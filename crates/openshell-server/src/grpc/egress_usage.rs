// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Egress usage reports, recent windows, and drift baselines.
//!
//! Supervisors report one usage window at a time. The gateway adds a report
//! only when its `window_sequence` is higher than the last accepted one for
//! its supervisor instance, keeps the last windows in memory, and keeps one
//! EWMA baseline per `(policy_key, endpoint_id)` in the store. The highest
//! sequences and the baselines are one object, so one write keeps them
//! consistent.
//!
//! Sandboxes of one cohort also share baselines: the sandboxes from one
//! workload template, or else the sandboxes with one base policy. A sandbox
//! compares against the cohort baseline until its own baseline is warm, so
//! short-lived sandboxes get drift findings too.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use openshell_core::egress_usage::{
    DEFAULT_DRIFT_MIN_BYTES, DEFAULT_DRIFT_MIN_REQUESTS, DEFAULT_DRIFT_RATIO,
};
use openshell_core::proto::{
    EgressFindingSeverity, EgressUsageFinding, EgressUsageSummary, EgressUsageUpdate,
    EgressUsageWindow, GetEgressUsageRequest, GetEgressUsageResponse, ReportEgressUsageRequest,
    ReportEgressUsageResponse, Sandbox, SandboxPolicy as ProtoSandboxPolicy, SandboxStreamEvent,
    UsageDrift, sandbox_stream_event,
};
use serde::{Deserialize, Serialize};
use tonic::{Request, Response, Status};

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::auth::workspace_authz::MinWorkspaceRole;
use crate::persistence::{
    ObjectCursor, ObjectId, ObjectName, ObjectWorkspace, PersistenceError, Store, WriteCondition,
};

/// Store object type for per-sandbox baselines and accepted sequences.
pub const EGRESS_USAGE_OBJECT_TYPE: &str = "egress_usage_state";
/// Store object type for cohort baselines, one per workspace and cohort.
pub const EGRESS_USAGE_COHORT_OBJECT_TYPE: &str = "egress_usage_cohort";

const RECENT_WINDOWS: usize = 60;
const RECENT_FINDINGS: usize = 200;
const MAX_BASELINES: usize = 256;
const MAX_TRACKED_INSTANCES: usize = 8;
const WARMUP_WINDOWS: u64 = 30;
const EWMA_WEIGHT: f64 = 0.1;
const CAS_ATTEMPTS: usize = 5;
/// Distinct sandboxes that must contribute before a cohort baseline is used.
const COHORT_MIN_CONTRIBUTORS: usize = 3;
const MAX_COHORT_CONTRIBUTORS: usize = 64;
/// Cohorts without a report for this long are removed.
pub const COHORT_IDLE_TTL: std::time::Duration = std::time::Duration::from_hours(24 * 7);

/// Recent windows and findings of every sandbox on this replica.
#[derive(Debug, Default)]
pub struct EgressUsageStore {
    recent: Mutex<HashMap<String, RecentUsage>>,
}

#[derive(Debug, Default)]
struct RecentUsage {
    windows: VecDeque<EgressUsageWindow>,
    findings: VecDeque<EgressUsageFinding>,
}

impl EgressUsageStore {
    fn record(&self, sandbox_id: &str, window: EgressUsageWindow, findings: &[EgressUsageFinding]) {
        let mut recent = self
            .recent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let usage = recent.entry(sandbox_id.to_string()).or_default();
        usage.windows.push_back(window);
        while usage.windows.len() > RECENT_WINDOWS {
            usage.windows.pop_front();
        }
        usage.findings.extend(findings.iter().cloned());
        while usage.findings.len() > RECENT_FINDINGS {
            usage.findings.pop_front();
        }
    }

    fn snapshot(&self, sandbox_id: &str) -> GetEgressUsageResponse {
        let recent = self
            .recent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        recent
            .get(sandbox_id)
            .map(|usage| GetEgressUsageResponse {
                windows: usage.windows.iter().cloned().collect(),
                findings: usage.findings.iter().cloned().collect(),
            })
            .unwrap_or_default()
    }

    /// Forget the recent windows of a deleted sandbox.
    pub fn remove(&self, sandbox_id: &str) {
        self.recent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(sandbox_id);
    }
}

/// EWMA baseline of one endpoint.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct Baseline {
    requests: f64,
    #[serde(default)]
    writes: f64,
    bytes_out: f64,
    bytes_in: f64,
    errors: f64,
    /// Windows seen, with or without traffic. Drift starts after the warmup.
    windows: u64,
    last_active_ms: i64,
    /// Counters above their drift threshold. A counter reports drift once
    /// and again only after it returns below the threshold.
    #[serde(default)]
    alerting: std::collections::BTreeSet<String>,
}

/// Persisted drift state of one sandbox.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct PersistedUsageState {
    /// Highest accepted `window_sequence` per supervisor instance.
    highest_sequence: BTreeMap<String, u64>,
    /// Baselines keyed by `policy_key|endpoint_id`.
    baselines: BTreeMap<String, Baseline>,
    /// Instance insertion order, oldest first, for bounded tracking.
    instances: Vec<String>,
}

/// Shared baselines of one cohort.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct CohortState {
    /// Baselines keyed by `policy_key|endpoint_id`. `windows` counts the
    /// active sandbox windows that updated the baseline.
    baselines: BTreeMap<String, Baseline>,
    /// Sandboxes that contributed, most recent last.
    contributors: Vec<String>,
}

/// Cohort baselines that a sandbox compares against before its own
/// baselines are warm.
struct CohortReference<'a> {
    label: &'static str,
    state: &'a CohortState,
}

impl CohortReference<'_> {
    fn baseline(&self, key: &str) -> Option<&Baseline> {
        if self.state.contributors.len() < COHORT_MIN_CONTRIBUTORS {
            return None;
        }
        self.state
            .baselines
            .get(key)
            .filter(|baseline| baseline.windows >= WARMUP_WINDOWS)
    }
}

/// Cohort of a sandbox: its workload template, or else its base policy.
fn cohort_of(sandbox: &Sandbox, policy: &ProtoSandboxPolicy) -> (String, &'static str) {
    sandbox
        .created_from_workload_template
        .as_ref()
        .filter(|template| !template.name.is_empty())
        .map_or_else(
            || {
                (
                    format!(
                        "policy:{}",
                        openshell_core::policy_identity::deterministic_policy_hash(policy)
                    ),
                    "policy baseline",
                )
            },
            |template| (format!("template:{}", template.name), "template baseline"),
        )
}

/// Drift settings resolved from the sandbox policy.
#[derive(Debug, Clone, Copy, PartialEq)]
struct DriftSettings {
    enabled: bool,
    ratio: f64,
    min_requests: u64,
    min_bytes: u64,
}

impl DriftSettings {
    fn from_policy(drift: Option<&UsageDrift>) -> Self {
        Self {
            enabled: drift.and_then(|drift| drift.enabled).unwrap_or(true),
            ratio: f64::from(
                drift
                    .and_then(|drift| drift.ratio)
                    .unwrap_or(DEFAULT_DRIFT_RATIO),
            ),
            min_requests: drift
                .and_then(|drift| drift.min_requests)
                .unwrap_or(DEFAULT_DRIFT_MIN_REQUESTS),
            min_bytes: drift
                .and_then(|drift| drift.min_bytes)
                .unwrap_or(DEFAULT_DRIFT_MIN_BYTES),
        }
    }
}

/// Endpoint totals of one window, summed across hosts and binaries.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct EndpointTotals {
    requests: u64,
    writes: u64,
    bytes_out: u64,
    bytes_in: u64,
    errors: u64,
}

fn endpoint_totals(
    summaries: &[EgressUsageSummary],
) -> BTreeMap<String, (String, String, EndpointTotals)> {
    let mut totals: BTreeMap<String, (String, String, EndpointTotals)> = BTreeMap::new();
    for summary in summaries {
        let key = format!("{}|{}", summary.policy_key, summary.endpoint_id);
        let entry = totals.entry(key).or_insert_with(|| {
            (
                summary.policy_key.clone(),
                summary.endpoint_id.clone(),
                EndpointTotals::default(),
            )
        });
        let responses = summary.responses.unwrap_or_default();
        entry.2.requests += summary.requests;
        entry.2.writes += summary.write_requests;
        entry.2.bytes_out += summary.bytes_out;
        entry.2.bytes_in += summary.bytes_in;
        entry.2.errors += responses.status_4xx + responses.status_5xx;
    }
    totals
}

#[allow(clippy::cast_precision_loss)]
fn as_f64(value: u64) -> f64 {
    value as f64
}

pub(super) fn human_bytes(bytes: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn drift_detail(counter: &str, value: u64, reference: f64, ratio: f64, label: &str) -> String {
    let (value, reference) = if counter.starts_with("bytes") {
        (human_bytes(as_f64(value)), human_bytes(reference))
    } else {
        (value.to_string(), format!("{reference:.1}"))
    };
    format!("{counter} {value} in one window is more than {ratio} times the {label} {reference}")
}

fn update_means(baseline: &mut Baseline, window: EndpointTotals) {
    let update = |mean: &mut f64, value: u64| {
        *mean = (1.0 - EWMA_WEIGHT).mul_add(*mean, EWMA_WEIGHT * as_f64(value));
    };
    update(&mut baseline.requests, window.requests);
    update(&mut baseline.writes, window.writes);
    update(&mut baseline.bytes_out, window.bytes_out);
    update(&mut baseline.bytes_in, window.bytes_in);
    update(&mut baseline.errors, window.errors);
}

fn first_baseline(window: EndpointTotals, now_ms: i64) -> Baseline {
    Baseline {
        requests: as_f64(window.requests),
        writes: as_f64(window.writes),
        bytes_out: as_f64(window.bytes_out),
        bytes_in: as_f64(window.bytes_in),
        errors: as_f64(window.errors),
        windows: 1,
        last_active_ms: now_ms,
        alerting: std::collections::BTreeSet::new(),
    }
}

fn evict_least_recent(baselines: &mut BTreeMap<String, Baseline>) {
    while baselines.len() > MAX_BASELINES {
        let Some(oldest) = baselines
            .iter()
            .min_by_key(|(_, baseline)| baseline.last_active_ms)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        baselines.remove(&oldest);
    }
}

/// Apply one accepted window to the baselines.
///
/// Only windows with traffic for an endpoint update its means, so idle time
/// does not pull a baseline down to zero. Every window counts toward the
/// warmup. Before the sandbox baseline of an endpoint is warm, the warm
/// cohort baseline is the reference. A counter drifts when its value is
/// more than `ratio` times the larger of the reference mean and its floor.
/// It reports once, and again only after a window below the threshold.
/// Windows that never arrived (dropped by the supervisor) are gaps and
/// update nothing. Returns drift findings.
fn apply_window(
    state: &mut PersistedUsageState,
    summaries: &[EgressUsageSummary],
    settings: DriftSettings,
    cohort: Option<&CohortReference<'_>>,
    now_ms: i64,
) -> Vec<EgressUsageFinding> {
    let totals = endpoint_totals(summaries);
    let mut findings = Vec::new();
    let keys: Vec<String> = state
        .baselines
        .keys()
        .cloned()
        .chain(totals.keys().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    for key in keys {
        let (policy_key, endpoint_id, window) = totals.get(&key).cloned().unwrap_or_else(|| {
            let mut parts = key.splitn(2, '|');
            (
                parts.next().unwrap_or_default().to_string(),
                parts.next().unwrap_or_default().to_string(),
                EndpointTotals::default(),
            )
        });
        let own = state.baselines.get(&key);
        let reference = match own {
            Some(baseline) if baseline.windows >= WARMUP_WINDOWS => {
                Some((baseline.clone(), "baseline"))
            }
            _ => cohort.and_then(|cohort| {
                cohort
                    .baseline(&key)
                    .map(|baseline| (baseline.clone(), cohort.label))
            }),
        };
        let is_new = own.is_none();
        let baseline = state
            .baselines
            .entry(key)
            .or_insert_with(|| first_baseline(window, now_ms));
        if settings.enabled
            && let Some((reference, label)) = reference
        {
            let checks = [
                (
                    "requests",
                    window.requests,
                    reference.requests,
                    settings.min_requests,
                ),
                (
                    "writes",
                    window.writes,
                    reference.writes,
                    settings.min_requests,
                ),
                (
                    "bytes_out",
                    window.bytes_out,
                    reference.bytes_out,
                    settings.min_bytes,
                ),
                (
                    "bytes_in",
                    window.bytes_in,
                    reference.bytes_in,
                    settings.min_bytes,
                ),
                (
                    "errors",
                    window.errors,
                    reference.errors,
                    settings.min_requests,
                ),
            ];
            for (counter, value, mean, floor) in checks {
                let threshold = mean.max(as_f64(floor));
                if as_f64(value) <= settings.ratio * threshold {
                    baseline.alerting.remove(counter);
                    continue;
                }
                if baseline.alerting.insert(counter.to_string()) {
                    findings.push(EgressUsageFinding {
                        finding_type: "egress.drift".to_string(),
                        severity: EgressFindingSeverity::Medium as i32,
                        policy_key: policy_key.clone(),
                        endpoint_id: endpoint_id.clone(),
                        counter: counter.to_string(),
                        detail: drift_detail(counter, value, threshold, settings.ratio, label),
                        ..Default::default()
                    });
                }
            }
        }
        if is_new {
            continue;
        }
        baseline.windows += 1;
        if window != EndpointTotals::default() {
            update_means(baseline, window);
            baseline.last_active_ms = now_ms;
        }
    }
    evict_least_recent(&mut state.baselines);
    findings
}

/// Add one sandbox window to the cohort baselines. Endpoints that drifted
/// in this window are left out, so a misbehaving sandbox does not raise the
/// shared baseline.
fn apply_cohort_window(
    cohort: &mut CohortState,
    summaries: &[EgressUsageSummary],
    drifted: &std::collections::BTreeSet<String>,
    sandbox_id: &str,
    now_ms: i64,
) {
    let mut contributed = false;
    for (key, (_, _, window)) in endpoint_totals(summaries) {
        if window == EndpointTotals::default() || drifted.contains(&key) {
            continue;
        }
        contributed = true;
        match cohort.baselines.get_mut(&key) {
            Some(baseline) => {
                update_means(baseline, window);
                baseline.windows += 1;
                baseline.last_active_ms = now_ms;
            }
            None => {
                cohort.baselines.insert(key, first_baseline(window, now_ms));
            }
        }
    }
    if contributed {
        cohort.contributors.retain(|id| id != sandbox_id);
        cohort.contributors.push(sandbox_id.to_string());
        if cohort.contributors.len() > MAX_COHORT_CONTRIBUTORS {
            cohort.contributors.remove(0);
        }
    }
    evict_least_recent(&mut cohort.baselines);
}

/// Accept a report only when its sequence is higher than the last accepted
/// one for its supervisor instance.
fn accept_sequence(state: &mut PersistedUsageState, instance: &str, sequence: u64) -> bool {
    match state.highest_sequence.get(instance) {
        Some(highest) if sequence <= *highest => return false,
        Some(_) => {}
        None => {
            state.instances.push(instance.to_string());
            while state.instances.len() > MAX_TRACKED_INSTANCES {
                let removed = state.instances.remove(0);
                state.highest_sequence.remove(&removed);
            }
        }
    }
    state
        .highest_sequence
        .insert(instance.to_string(), sequence);
    true
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

async fn load_state(
    store: &Store,
    workspace: &str,
    sandbox_id: &str,
) -> Result<(PersistedUsageState, Option<(String, u64)>), Status> {
    let record = store
        .get_by_name(EGRESS_USAGE_OBJECT_TYPE, workspace, sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("fetch egress usage state failed: {error}")))?;
    match record {
        Some(record) => {
            let state = serde_json::from_slice(&record.payload).map_err(|error| {
                Status::internal(format!("decode egress usage state failed: {error}"))
            })?;
            Ok((state, Some((record.id, record.resource_version))))
        }
        None => Ok((PersistedUsageState::default(), None)),
    }
}

async fn load_cohort(
    store: &Store,
    workspace: &str,
    cohort_id: &str,
) -> Result<Option<(CohortState, (String, u64))>, String> {
    let Some(record) = store
        .get_by_name(EGRESS_USAGE_COHORT_OBJECT_TYPE, workspace, cohort_id)
        .await
        .map_err(|error| error.to_string())?
    else {
        return Ok(None);
    };
    let cohort = serde_json::from_slice(&record.payload).map_err(|error| error.to_string())?;
    Ok(Some((cohort, (record.id, record.resource_version))))
}

/// Add a sandbox window to its cohort. The update is best effort: the
/// cohort is statistical, so a lost update never fails the report.
async fn update_cohort(
    store: &Store,
    workspace: &str,
    cohort_id: &str,
    summaries: &[EgressUsageSummary],
    drifted: &std::collections::BTreeSet<String>,
    sandbox_id: &str,
) {
    for _ in 0..CAS_ATTEMPTS {
        let (mut cohort, existing) = match load_cohort(store, workspace, cohort_id).await {
            Ok(Some((cohort, existing))) => (cohort, Some(existing)),
            Ok(None) => (CohortState::default(), None),
            Err(error) => {
                tracing::debug!(error = %error, cohort = %cohort_id, "egress usage cohort load failed");
                return;
            }
        };
        let before = cohort.clone();
        apply_cohort_window(&mut cohort, summaries, drifted, sandbox_id, now_ms());
        if cohort == before {
            return;
        }
        let Ok(payload) = serde_json::to_vec(&cohort) else {
            return;
        };
        let (id, condition) = existing.map_or_else(
            || (uuid::Uuid::new_v4().to_string(), WriteCondition::MustCreate),
            |(id, version)| (id, WriteCondition::MatchResourceVersion(version)),
        );
        match store
            .put_if(
                EGRESS_USAGE_COHORT_OBJECT_TYPE,
                &id,
                cohort_id,
                workspace,
                &payload,
                None,
                condition,
            )
            .await
        {
            Ok(_) => return,
            Err(PersistenceError::Conflict { .. } | PersistenceError::UniqueViolation { .. }) => {}
            Err(error) => {
                tracing::debug!(error = %error, cohort = %cohort_id, "egress usage cohort write failed");
                return;
            }
        }
    }
    tracing::debug!(cohort = %cohort_id, "egress usage cohort changed concurrently; update dropped");
}

/// Remove cohorts that received no report for [`COHORT_IDLE_TTL`], once per
/// `interval`.
pub fn spawn_cohort_reaper(store: Arc<Store>, interval: std::time::Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if let Err(error) = reap_idle_cohorts(&store, now_ms()).await {
                tracing::warn!(error = %error, "egress usage cohort reaper sweep failed");
            }
        }
    });
}

async fn reap_idle_cohorts(store: &Store, now_ms: i64) -> Result<u64, String> {
    let cutoff = now_ms - i64::try_from(COHORT_IDLE_TTL.as_millis()).unwrap_or(i64::MAX);
    let mut cursor = None;
    let mut idle = Vec::new();
    loop {
        let records = store
            .list_by_type_after(EGRESS_USAGE_COHORT_OBJECT_TYPE, cursor.as_ref(), 500)
            .await
            .map_err(|error| error.to_string())?;
        let Some(last) = records.last() else {
            break;
        };
        cursor = Some(ObjectCursor::from(last));
        idle.extend(
            records
                .iter()
                .filter(|record| record.updated_at_ms < cutoff)
                .map(|record| record.id.clone()),
        );
    }
    if idle.is_empty() {
        return Ok(0);
    }
    store
        .delete_many(EGRESS_USAGE_COHORT_OBJECT_TYPE, &idle)
        .await
        .map_err(|error| error.to_string())
}

/// Handle `ReportEgressUsage` from a sandbox supervisor.
pub(super) async fn handle_report_egress_usage(
    state: &Arc<ServerState>,
    request: Request<ReportEgressUsageRequest>,
) -> Result<Response<ReportEgressUsageResponse>, Status> {
    let principal = request
        .extensions()
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("missing principal"))?;
    let report = request.into_inner();
    if report.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if report.supervisor_instance_id.is_empty() {
        return Err(Status::invalid_argument(
            "supervisor_instance_id is required",
        ));
    }
    let workspace = super::workspace::resolve_workspace(
        state.store.as_ref(),
        crate::auth::workspace_authz::selected_workspace_name(report.workspace_scope.as_ref())?,
    )
    .await?
    .name;
    let sandbox = super::policy::resolve_sandbox_by_name_for_principal(
        state.store.as_ref(),
        &workspace,
        &principal,
        &report.name,
    )
    .await?;
    let sandbox_id = sandbox.object_id().to_string();
    if let Some(owner) =
        crate::supervisor_session::remote_supervisor_owner(state, &sandbox_id).await?
    {
        let forwarded = ReportEgressUsageRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector(workspace)),
            name: sandbox.object_name().to_string(),
            ..report
        };
        let response = crate::supervisor_session::forward_egress_usage_report_to_owner(
            state,
            &owner,
            &sandbox_id,
            forwarded,
        )
        .await?;
        return Ok(Response::new(response));
    }
    record_report(state, &workspace, &sandbox, report).await
}

/// Handle a report that another replica forwarded to this owner replica.
/// The forwarding replica authenticated the sandbox and resolved its name.
pub(super) async fn handle_peer_report_egress_usage(
    state: &Arc<ServerState>,
    request: Request<ReportEgressUsageRequest>,
) -> Result<Response<ReportEgressUsageResponse>, Status> {
    ensure_peer(&request)?;
    let report = request.into_inner();
    let (workspace, sandbox) =
        resolve_for_peer(state, report.workspace_scope.as_ref(), &report.name).await?;
    record_report(state, &workspace, &sandbox, report).await
}

fn ensure_peer<T>(request: &Request<T>) -> Result<(), Status> {
    if matches!(
        request.extensions().get::<Principal>(),
        Some(Principal::Peer(_))
    ) {
        Ok(())
    } else {
        Err(Status::permission_denied(
            "gateway peer principal is required",
        ))
    }
}

async fn resolve_for_peer(
    state: &Arc<ServerState>,
    workspace_scope: Option<&openshell_core::proto::WorkspaceSelector>,
    name: &str,
) -> Result<(String, Sandbox), Status> {
    let workspace = crate::auth::workspace_authz::selected_workspace_name(workspace_scope)?;
    if name.is_empty() {
        return Err(Status::invalid_argument("sandbox is required"));
    }
    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(workspace, name)
        .await
        .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    Ok((workspace.to_string(), sandbox))
}

/// Add one report to the persisted drift state, the recent windows, and the
/// watch stream of this replica.
async fn record_report(
    state: &Arc<ServerState>,
    workspace: &str,
    sandbox: &Sandbox,
    report: ReportEgressUsageRequest,
) -> Result<Response<ReportEgressUsageResponse>, Status> {
    let sandbox_id = sandbox.object_id().to_string();
    let policy =
        super::policy::current_base_policy_for_sandbox(state.store.as_ref(), sandbox).await?;
    let settings = DriftSettings::from_policy(
        policy
            .usage_monitoring
            .as_ref()
            .and_then(|monitoring| monitoring.drift.as_ref()),
    );

    let (cohort_id, cohort_label) = cohort_of(sandbox, &policy);
    let cohort = load_cohort(state.store.as_ref(), workspace, &cohort_id)
        .await
        .unwrap_or_else(|error| {
            tracing::debug!(error = %error, cohort = %cohort_id, "egress usage cohort unavailable");
            None
        })
        .map(|(cohort, _)| cohort);
    let cohort_reference = cohort.as_ref().map(|state| CohortReference {
        label: cohort_label,
        state,
    });

    let mut drift_findings = Vec::new();
    let mut accepted = false;
    for _ in 0..CAS_ATTEMPTS {
        let (mut persisted, existing) =
            load_state(state.store.as_ref(), workspace, &sandbox_id).await?;
        if !accept_sequence(
            &mut persisted,
            &report.supervisor_instance_id,
            report.window_sequence,
        ) {
            // A repeated report is acknowledged without being added again.
            return Ok(Response::new(ReportEgressUsageResponse {}));
        }
        drift_findings = apply_window(
            &mut persisted,
            &report.summaries,
            settings,
            cohort_reference.as_ref(),
            now_ms(),
        );
        let payload = serde_json::to_vec(&persisted).map_err(|error| {
            Status::internal(format!("encode egress usage state failed: {error}"))
        })?;
        let (id, condition) = existing.map_or_else(
            || (uuid::Uuid::new_v4().to_string(), WriteCondition::MustCreate),
            |(id, version)| (id, WriteCondition::MatchResourceVersion(version)),
        );
        match state
            .store
            .put_if(
                EGRESS_USAGE_OBJECT_TYPE,
                &id,
                &sandbox_id,
                workspace,
                &payload,
                None,
                condition,
            )
            .await
        {
            Ok(_) => {
                accepted = true;
                break;
            }
            Err(PersistenceError::Conflict { .. } | PersistenceError::UniqueViolation { .. }) => {}
            Err(other) => {
                return Err(super::persistence_error_to_status(
                    other,
                    "persist egress usage state",
                ));
            }
        }
    }
    if !accepted {
        return Err(Status::aborted(
            "egress usage state changed concurrently; retry",
        ));
    }

    state.egress_fleet.observe(
        workspace,
        &cohort_id,
        sandbox.object_name(),
        &report.summaries,
        now_ms(),
    );
    let drifted = drift_findings
        .iter()
        .map(|finding| format!("{}|{}", finding.policy_key, finding.endpoint_id))
        .collect();
    update_cohort(
        state.store.as_ref(),
        workspace,
        &cohort_id,
        &report.summaries,
        &drifted,
        &sandbox_id,
    )
    .await;

    let observed = prost_types::Timestamp::from(SystemTime::now());
    for finding in &mut drift_findings {
        finding.observed_time = Some(observed);
    }
    let mut findings = report.findings;
    findings.extend(drift_findings);
    let window = EgressUsageWindow {
        window_start: report.window_start,
        window_duration: report.window_duration,
        summaries: report.summaries,
        dropped_windows: report.dropped_windows,
    };
    state
        .egress_usage
        .record(&sandbox_id, window.clone(), &findings);
    state.tracing_log_bus.platform_event_bus.publish(
        &sandbox_id,
        SandboxStreamEvent {
            payload: Some(sandbox_stream_event::Payload::EgressUsage(
                EgressUsageUpdate {
                    window: Some(window),
                    findings,
                },
            )),
            cursor: String::new(),
        },
    );
    Ok(Response::new(ReportEgressUsageResponse {}))
}

/// Handle `GetEgressUsage` for a user with read access to the sandbox.
pub(super) async fn handle_get_egress_usage(
    state: &Arc<ServerState>,
    request: Request<GetEgressUsageRequest>,
) -> Result<Response<GetEgressUsageResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let sandbox = super::sandbox::resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &request.sandbox,
        crate::auth::workspace_authz::selected_workspace_name(request.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    let mut response = if let Some(owner) =
        crate::supervisor_session::remote_supervisor_owner(state, sandbox.object_id()).await?
    {
        crate::supervisor_session::forward_egress_usage_query_to_owner(
            state,
            &owner,
            sandbox.object_id(),
            request,
        )
        .await?
    } else {
        state.egress_usage.snapshot(sandbox.object_id())
    };
    // Fleet findings are in the store, so every replica can add them.
    match super::egress_fleet::fleet_findings_for_sandbox(
        state.store.as_ref(),
        sandbox.object_workspace(),
        sandbox.object_name(),
    )
    .await
    {
        Ok(fleet) => {
            response.findings.extend(fleet);
            response.findings.sort_by_key(|finding| {
                finding
                    .observed_time
                    .map_or((0, 0), |time| (time.seconds, time.nanos))
            });
        }
        Err(error) => {
            tracing::debug!(error = %error, "fleet findings unavailable for sandbox view");
        }
    }
    Ok(Response::new(response))
}

/// Serve recent usage kept by this owner replica to another replica.
pub(super) async fn handle_peer_get_egress_usage(
    state: &Arc<ServerState>,
    request: Request<GetEgressUsageRequest>,
) -> Result<Response<GetEgressUsageResponse>, Status> {
    ensure_peer(&request)?;
    let request = request.into_inner();
    let (_, sandbox) =
        resolve_for_peer(state, request.workspace_scope.as_ref(), &request.sandbox).await?;
    Ok(Response::new(
        state.egress_usage.snapshot(sandbox.object_id()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::EgressResponseCounts;

    fn summary(requests: u64, bytes_in: u64) -> EgressUsageSummary {
        EgressUsageSummary {
            policy_key: "api".into(),
            endpoint_id: "endpoint:v1:api".into(),
            host: "api.example.com".into(),
            requests,
            bytes_in,
            responses: Some(EgressResponseCounts::default()),
            ..Default::default()
        }
    }

    fn settings() -> DriftSettings {
        DriftSettings {
            enabled: true,
            ratio: 10.0,
            min_requests: 100,
            min_bytes: 1000,
        }
    }

    fn warm(state: &mut PersistedUsageState, requests: u64) {
        for _ in 0..WARMUP_WINDOWS {
            assert!(apply_window(state, &[summary(requests, 0)], settings(), None, 0).is_empty());
        }
    }

    #[test]
    fn no_drift_before_warmup() {
        let mut state = PersistedUsageState::default();
        apply_window(&mut state, &[summary(10, 0)], settings(), None, 0);
        let findings = apply_window(&mut state, &[summary(10_000, 0)], settings(), None, 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn jump_above_ratio_reports_once_while_it_lasts() {
        let mut state = PersistedUsageState::default();
        warm(&mut state, 200);
        let first = apply_window(&mut state, &[summary(20_000, 0)], settings(), None, 0);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].counter, "requests");
        for _ in 0..5 {
            assert!(
                apply_window(&mut state, &[summary(20_000, 0)], settings(), None, 0).is_empty()
            );
        }
    }

    #[test]
    fn drift_reports_again_after_returning_below_threshold() {
        let mut state = PersistedUsageState::default();
        warm(&mut state, 200);
        assert_eq!(
            apply_window(&mut state, &[summary(20_000, 0)], settings(), None, 0).len(),
            1
        );
        // An idle window clears the alert. The first jump raised the mean to
        // 2180, so the next jump must exceed 21 800 to drift again.
        apply_window(&mut state, &[], settings(), None, 0);
        assert!(apply_window(&mut state, &[summary(20_000, 0)], settings(), None, 0).is_empty());
        assert_eq!(
            apply_window(&mut state, &[summary(300_000, 0)], settings(), None, 0).len(),
            1
        );
    }

    #[test]
    fn idle_windows_do_not_decay_the_baseline() {
        let mut state = PersistedUsageState::default();
        apply_window(&mut state, &[summary(100, 0)], settings(), None, 0);
        for _ in 0..50 {
            apply_window(&mut state, &[], settings(), None, 0);
        }
        let baseline = &state.baselines["api|endpoint:v1:api"];
        assert_eq!(baseline.windows, 51);
        assert!((baseline.requests - 100.0).abs() < 1e-9);
    }

    #[test]
    fn floor_is_the_smallest_baseline_compared_against() {
        let mut state = PersistedUsageState::default();
        warm(&mut state, 1);
        // Ten times a tiny baseline, but below ratio times the floor of 100.
        assert!(apply_window(&mut state, &[summary(500, 0)], settings(), None, 0).is_empty());
        assert_eq!(
            apply_window(&mut state, &[summary(1001, 0)], settings(), None, 0).len(),
            1
        );
    }

    #[test]
    fn sustained_transfer_after_idle_time_reports_once() {
        // The playground case: idle windows, then one 4 GB download counted
        // over three 10 s windows.
        let mut state = PersistedUsageState::default();
        apply_window(&mut state, &[summary(1, 50_000)], settings(), None, 0);
        for _ in 0..WARMUP_WINDOWS {
            apply_window(&mut state, &[], settings(), None, 0);
        }
        let mut findings = Vec::new();
        for bytes in [143_501_034, 2_109_301_566, 2_048_000_240] {
            findings.extend(apply_window(
                &mut state,
                &[summary(1, bytes)],
                settings(),
                None,
                0,
            ));
        }
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].counter, "bytes_in");
        assert!(findings[0].detail.contains("MiB"), "{}", findings[0].detail);
    }

    #[test]
    fn writes_drift_on_a_read_mostly_endpoint() {
        let mut state = PersistedUsageState::default();
        warm(&mut state, 200);
        let mut window = summary(200, 0);
        window.write_requests = 1500;
        let findings = apply_window(&mut state, &[window], settings(), None, 0);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].counter, "writes");
    }

    #[test]
    fn persisted_baseline_without_writes_decodes() {
        let baseline: Baseline = serde_json::from_str(
            r#"{"requests":1.0,"bytes_out":0.0,"bytes_in":0.0,"errors":0.0,"windows":3,"last_active_ms":0}"#,
        )
        .unwrap();
        assert!(baseline.writes.abs() < f64::EPSILON);
        assert_eq!(baseline.windows, 3);
    }

    fn warm_cohort(contributors: usize, requests: u64) -> CohortState {
        let mut cohort = CohortState::default();
        let none = std::collections::BTreeSet::new();
        for window in 0..WARMUP_WINDOWS {
            let sandbox = format!("sandbox-{}", window % contributors as u64);
            apply_cohort_window(&mut cohort, &[summary(requests, 0)], &none, &sandbox, 0);
        }
        cohort
    }

    #[test]
    fn new_sandbox_drifts_against_a_warm_cohort_in_its_first_window() {
        let cohort = warm_cohort(3, 200);
        let reference = CohortReference {
            label: "policy baseline",
            state: &cohort,
        };
        let mut state = PersistedUsageState::default();
        let findings = apply_window(
            &mut state,
            &[summary(20_000, 0)],
            settings(),
            Some(&reference),
            0,
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].detail.contains("the policy baseline"),
            "{}",
            findings[0].detail
        );
        // The alert state is per sandbox, so the same level reports once.
        assert!(
            apply_window(
                &mut state,
                &[summary(20_000, 0)],
                settings(),
                Some(&reference),
                0
            )
            .is_empty()
        );
    }

    #[test]
    fn cohort_needs_three_contributors() {
        let cohort = warm_cohort(2, 200);
        let reference = CohortReference {
            label: "policy baseline",
            state: &cohort,
        };
        let mut state = PersistedUsageState::default();
        let findings = apply_window(
            &mut state,
            &[summary(20_000, 0)],
            settings(),
            Some(&reference),
            0,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn warm_sandbox_baseline_takes_over_from_the_cohort() {
        let cohort = warm_cohort(3, 200);
        let reference = CohortReference {
            label: "policy baseline",
            state: &cohort,
        };
        let mut state = PersistedUsageState::default();
        // This sandbox normally makes 20 000 requests per window.
        for _ in 0..=WARMUP_WINDOWS {
            apply_window(
                &mut state,
                &[summary(20_000, 0)],
                settings(),
                Some(&reference),
                0,
            );
        }
        assert!(
            apply_window(
                &mut state,
                &[summary(20_000, 0)],
                settings(),
                Some(&reference),
                0
            )
            .is_empty()
        );
    }

    #[test]
    fn drifted_endpoints_do_not_update_the_cohort() {
        let mut cohort = warm_cohort(3, 200);
        let before = cohort.baselines["api|endpoint:v1:api"].clone();
        let drifted = std::collections::BTreeSet::from(["api|endpoint:v1:api".to_string()]);
        apply_cohort_window(&mut cohort, &[summary(20_000, 0)], &drifted, "bad", 0);
        assert_eq!(cohort.baselines["api|endpoint:v1:api"], before);
        assert!(!cohort.contributors.contains(&"bad".to_string()));
    }

    #[test]
    fn cohort_contributors_are_bounded() {
        let none = std::collections::BTreeSet::new();
        let mut cohort = CohortState::default();
        for index in 0..(MAX_COHORT_CONTRIBUTORS + 5) {
            apply_cohort_window(
                &mut cohort,
                &[summary(1, 0)],
                &none,
                &format!("sandbox-{index}"),
                0,
            );
        }
        assert_eq!(cohort.contributors.len(), MAX_COHORT_CONTRIBUTORS);
        assert_eq!(cohort.contributors[0], "sandbox-5");
    }

    #[test]
    fn cohort_is_the_template_or_else_the_policy() {
        let policy = openshell_policy::restrictive_default_policy();
        let mut sandbox = Sandbox::default();
        let (policy_cohort, label) = cohort_of(&sandbox, &policy);
        assert!(policy_cohort.starts_with("policy:"), "{policy_cohort}");
        assert_eq!(label, "policy baseline");
        sandbox.created_from_workload_template =
            Some(openshell_core::proto::SandboxWorkloadTemplateProvenance {
                name: "eval".into(),
                resource_version: "1".into(),
            });
        assert_eq!(
            cohort_of(&sandbox, &policy),
            ("template:eval".to_string(), "template baseline")
        );
    }

    #[test]
    fn endpoint_totals_sum_hosts_and_binaries() {
        let mut other_host = summary(7, 0);
        other_host.host = "other.example.com".into();
        other_host.binary_sha256 = "sha-b".into();
        let totals = endpoint_totals(&[summary(3, 5), other_host]);
        assert_eq!(totals["api|endpoint:v1:api"].2.requests, 10);
    }

    #[test]
    fn sequence_is_accepted_once_per_instance() {
        let mut state = PersistedUsageState::default();
        assert!(accept_sequence(&mut state, "a", 1));
        assert!(!accept_sequence(&mut state, "a", 1));
        assert!(accept_sequence(&mut state, "a", 3), "gaps are legal");
        assert!(!accept_sequence(&mut state, "a", 2));
        assert!(accept_sequence(&mut state, "b", 1));
    }

    #[test]
    fn baselines_are_bounded_by_least_recent_activity() {
        let mut state = PersistedUsageState::default();
        for index in 0..(MAX_BASELINES + 3) {
            let mut item = summary(1, 0);
            item.endpoint_id = format!("endpoint:{index}");
            apply_window(
                &mut state,
                &[item],
                settings(),
                None,
                i64::try_from(index).unwrap(),
            );
        }
        assert_eq!(state.baselines.len(), MAX_BASELINES);
        assert!(!state.baselines.contains_key("api|endpoint:0"));
    }

    mod handlers {
        use super::super::*;
        use crate::auth::principal::{
            PeerPrincipal, Principal, SandboxIdentitySource, SandboxPrincipal,
        };
        use crate::grpc::test_support::test_server_state;
        use crate::supervisor_owner::{OWNER_TTL, SupervisorOwnerIndex};
        use openshell_core::proto::datamodel::v1::ObjectMeta;
        use openshell_core::proto::{SandboxPhase, SandboxSpec};

        const SANDBOX_ID: &str = "sandbox-usage";
        const SANDBOX_NAME: &str = "usage";

        async fn state_with_sandbox() -> Arc<ServerState> {
            let state = test_server_state().await;
            let mut sandbox = Sandbox {
                metadata: Some(ObjectMeta {
                    id: SANDBOX_ID.to_string(),
                    name: SANDBOX_NAME.to_string(),
                    workspace: "default".to_string(),
                    ..Default::default()
                }),
                spec: Some(SandboxSpec {
                    policy: Some(openshell_policy::restrictive_default_policy()),
                    ..Default::default()
                }),
                ..Default::default()
            };
            sandbox.set_phase(SandboxPhase::Ready as i32);
            state.store.put_message(&sandbox).await.unwrap();
            state
        }

        fn report(sequence: u64) -> ReportEgressUsageRequest {
            ReportEgressUsageRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                name: SANDBOX_NAME.to_string(),
                supervisor_instance_id: "instance-1".to_string(),
                window_sequence: sequence,
                summaries: vec![EgressUsageSummary {
                    policy_key: "api".to_string(),
                    endpoint_id: "endpoint:v1:api".to_string(),
                    requests: 3,
                    ..Default::default()
                }],
                ..Default::default()
            }
        }

        fn with_principal<T>(inner: T, principal: Principal) -> Request<T> {
            let mut request = Request::new(inner);
            request.extensions_mut().insert(principal);
            request
        }

        fn sandbox_principal() -> Principal {
            Principal::Sandbox(SandboxPrincipal {
                sandbox_id: SANDBOX_ID.to_string(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: "openshell-gateway:test-gateway".to_string(),
                },
                trust_domain: Some("openshell".to_string()),
            })
        }

        fn peer_principal() -> Principal {
            Principal::Peer(PeerPrincipal {
                replica_id: "replica-b".to_string(),
                pod_uid: "pod-b".to_string(),
            })
        }

        async fn put_sandbox(state: &ServerState, id: &str, template: Option<&str>) {
            let mut sandbox = Sandbox {
                metadata: Some(ObjectMeta {
                    id: id.to_string(),
                    name: id.to_string(),
                    workspace: "default".to_string(),
                    ..Default::default()
                }),
                spec: Some(SandboxSpec {
                    policy: Some(openshell_policy::restrictive_default_policy()),
                    ..Default::default()
                }),
                created_from_workload_template: template.map(|name| {
                    openshell_core::proto::SandboxWorkloadTemplateProvenance {
                        name: name.to_string(),
                        resource_version: "1".to_string(),
                    }
                }),
                ..Default::default()
            };
            sandbox.set_phase(SandboxPhase::Ready as i32);
            state.store.put_message(&sandbox).await.unwrap();
        }

        async fn send(state: &Arc<ServerState>, id: &str, sequence: u64, requests: u64) {
            let mut request = report(sequence);
            request.name = id.to_string();
            request.summaries[0].requests = requests;
            let principal = Principal::Sandbox(SandboxPrincipal {
                sandbox_id: id.to_string(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: "openshell-gateway:test-gateway".to_string(),
                },
                trust_domain: Some("openshell".to_string()),
            });
            handle_report_egress_usage(state, with_principal(request, principal))
                .await
                .unwrap();
        }

        fn drift_findings(state: &ServerState, id: &str) -> Vec<EgressUsageFinding> {
            state
                .egress_usage
                .snapshot(id)
                .findings
                .into_iter()
                .filter(|finding| finding.finding_type == "egress.drift")
                .collect()
        }

        #[tokio::test]
        async fn short_lived_sandbox_drifts_against_its_policy_cohort() {
            let state = test_server_state().await;
            for id in ["warm-a", "warm-b", "warm-c"] {
                put_sandbox(&state, id, None).await;
                for sequence in 1..=10 {
                    send(&state, id, sequence, 200).await;
                }
            }
            put_sandbox(&state, "fresh", None).await;
            send(&state, "fresh", 1, 20_000).await;
            let findings = drift_findings(&state, "fresh");
            assert_eq!(findings.len(), 1, "{findings:?}");
            assert!(findings[0].detail.contains("the policy baseline"));

            // A template sandbox is in another cohort, which is still cold.
            put_sandbox(&state, "templated", Some("eval")).await;
            send(&state, "templated", 1, 20_000).await;
            assert!(drift_findings(&state, "templated").is_empty());
        }

        #[tokio::test]
        async fn accepted_reports_reach_the_fleet_partials() {
            let state = test_server_state().await;
            put_sandbox(&state, "fleet-a", None).await;
            send(&state, "fleet-a", 1, 5).await;
            let later = now_ms() + 2 * 60_000;
            state
                .egress_fleet
                .tick_for_test(&state.store, "replica-a", later)
                .await;
            let partials = state
                .store
                .list(
                    super::super::super::egress_fleet::FLEET_PARTIAL_OBJECT_TYPE,
                    "default",
                    10,
                    0,
                )
                .await
                .unwrap();
            assert_eq!(partials.len(), 1);
        }

        #[tokio::test]
        async fn sandbox_view_includes_the_fleet_findings_that_list_it() {
            let state = test_server_state().await;
            put_sandbox(&state, "sb-01", None).await;
            put_sandbox(&state, "sb-99", None).await;
            state
                .store
                .put_if(
                    super::super::super::egress_fleet::FLEET_FINDING_OBJECT_TYPE,
                    "finding-id",
                    "001700000000000|policy:abc|proxy.internal:443|writer_sandboxes",
                    "default",
                    br#"{"finding_type":"egress.fleet_fan_in","counter":"writer_sandboxes","host":"proxy.internal","port":443,"detail":"20 sandboxes wrote to proxy.internal:443","observed_ms":1700000000000,"sandboxes":["sb-01","sb-02"]}"#,
                    None,
                    WriteCondition::MustCreate,
                )
                .await
                .unwrap();
            let usage = |name: &str| {
                crate::grpc::test_support::authed_request(GetEgressUsageRequest {
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
                    sandbox: name.to_string(),
                })
            };
            let listed = handle_get_egress_usage(&state, usage("sb-01"))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(listed.findings.len(), 1);
            assert_eq!(listed.findings[0].finding_type, "egress.fleet_fan_in");
            let other = handle_get_egress_usage(&state, usage("sb-99"))
                .await
                .unwrap()
                .into_inner();
            assert!(other.findings.is_empty());
        }

        #[tokio::test]
        async fn idle_cohorts_are_reaped() {
            let state = test_server_state().await;
            put_sandbox(&state, "warm-a", None).await;
            send(&state, "warm-a", 1, 5).await;
            let cohorts = || async {
                state
                    .store
                    .list(EGRESS_USAGE_COHORT_OBJECT_TYPE, "default", 10, 0)
                    .await
                    .unwrap()
                    .len()
            };
            assert_eq!(cohorts().await, 1);
            assert_eq!(reap_idle_cohorts(&state.store, now_ms()).await.unwrap(), 0);
            let later = now_ms() + i64::try_from(COHORT_IDLE_TTL.as_millis()).unwrap() + 1;
            assert_eq!(reap_idle_cohorts(&state.store, later).await.unwrap(), 1);
            assert_eq!(cohorts().await, 0);
        }

        #[tokio::test]
        async fn report_on_a_non_owner_replica_is_forwarded_not_recorded() {
            let state = state_with_sandbox().await;
            // Another replica owns the supervisor session. It advertises no
            // peer endpoint, so the forward fails instead of reaching a peer.
            SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
                .publish(
                    SANDBOX_ID,
                    "session-b",
                    "instance-b",
                    1,
                    "replica-b",
                    "local://replica-b",
                )
                .await
                .unwrap();
            let error =
                handle_report_egress_usage(&state, with_principal(report(1), sandbox_principal()))
                    .await
                    .unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{error}");
            assert!(error.message().contains("replica-b"), "{error}");
            assert!(state.egress_usage.snapshot(SANDBOX_ID).windows.is_empty());
        }

        #[tokio::test]
        async fn usage_query_on_a_non_owner_replica_is_forwarded() {
            let state = state_with_sandbox().await;
            SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
                .publish(
                    SANDBOX_ID,
                    "session-b",
                    "instance-b",
                    1,
                    "replica-b",
                    "local://replica-b",
                )
                .await
                .unwrap();
            let error = handle_get_egress_usage(
                &state,
                crate::grpc::test_support::authed_request(GetEgressUsageRequest {
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
                    sandbox: SANDBOX_NAME.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{error}");
        }

        #[tokio::test]
        async fn report_without_a_remote_owner_is_recorded_locally() {
            let state = state_with_sandbox().await;
            handle_report_egress_usage(&state, with_principal(report(1), sandbox_principal()))
                .await
                .unwrap();
            assert_eq!(state.egress_usage.snapshot(SANDBOX_ID).windows.len(), 1);
        }

        #[tokio::test]
        async fn peer_handlers_require_a_peer_principal() {
            let state = state_with_sandbox().await;
            let report_error = handle_peer_report_egress_usage(
                &state,
                with_principal(report(1), sandbox_principal()),
            )
            .await
            .unwrap_err();
            assert_eq!(report_error.code(), tonic::Code::PermissionDenied);
            let get_error = handle_peer_get_egress_usage(
                &state,
                Request::new(GetEgressUsageRequest {
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
                    sandbox: SANDBOX_NAME.to_string(),
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(get_error.code(), tonic::Code::PermissionDenied);
        }

        #[tokio::test]
        async fn forwarded_report_is_kept_by_the_owner_and_accepted_once() {
            let state = state_with_sandbox().await;
            for _ in 0..2 {
                handle_peer_report_egress_usage(
                    &state,
                    with_principal(report(7), peer_principal()),
                )
                .await
                .unwrap();
            }
            let usage = handle_peer_get_egress_usage(
                &state,
                with_principal(
                    GetEgressUsageRequest {
                        workspace_scope: Some(openshell_core::proto::workspace_selector(
                            "default".to_string(),
                        )),
                        sandbox: SANDBOX_NAME.to_string(),
                    },
                    peer_principal(),
                ),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(usage.windows.len(), 1, "a repeated report is added once");
            assert_eq!(usage.windows[0].summaries[0].requests, 3);
        }
    }
}
