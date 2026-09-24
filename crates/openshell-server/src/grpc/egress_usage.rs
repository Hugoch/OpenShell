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

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use openshell_core::egress_usage::{
    DEFAULT_DRIFT_MIN_BYTES, DEFAULT_DRIFT_MIN_REQUESTS, DEFAULT_DRIFT_RATIO,
};
use openshell_core::proto::{
    EgressFindingSeverity, EgressUsageFinding, EgressUsageSummary, EgressUsageUpdate,
    EgressUsageWindow, GetEgressUsageRequest, GetEgressUsageResponse, ReportEgressUsageRequest,
    ReportEgressUsageResponse, Sandbox, SandboxStreamEvent, UsageDrift, sandbox_stream_event,
};
use serde::{Deserialize, Serialize};
use tonic::{Request, Response, Status};

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::auth::workspace_authz::MinWorkspaceRole;
use crate::persistence::{ObjectId, ObjectName, PersistenceError, Store, WriteCondition};

/// Store object type for per-sandbox baselines and accepted sequences.
pub const EGRESS_USAGE_OBJECT_TYPE: &str = "egress_usage_state";

const RECENT_WINDOWS: usize = 60;
const RECENT_FINDINGS: usize = 200;
const MAX_BASELINES: usize = 256;
const MAX_TRACKED_INSTANCES: usize = 8;
const WARMUP_WINDOWS: u64 = 30;
const EWMA_WEIGHT: f64 = 0.1;
const CAS_ATTEMPTS: usize = 5;

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

fn human_bytes(bytes: f64) -> String {
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

fn drift_detail(counter: &str, value: u64, reference: f64, ratio: f64) -> String {
    let (value, reference) = if counter.starts_with("bytes") {
        (human_bytes(as_f64(value)), human_bytes(reference))
    } else {
        (value.to_string(), format!("{reference:.1}"))
    };
    format!("{counter} {value} in one window is more than {ratio} times the baseline {reference}")
}

/// Apply one accepted window to the baselines.
///
/// Only windows with traffic for an endpoint update its means, so idle time
/// does not pull a baseline down to zero. Every window counts toward the
/// warmup. A counter drifts when its value is more than `ratio` times the
/// larger of its mean and its floor. It reports once, and again only after
/// a window below the threshold. Windows that never arrived (dropped by the
/// supervisor) are gaps and update nothing. Returns drift findings.
fn apply_window(
    state: &mut PersistedUsageState,
    summaries: &[EgressUsageSummary],
    settings: DriftSettings,
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
        let Some(baseline) = state.baselines.get_mut(&key) else {
            state.baselines.insert(
                key,
                Baseline {
                    requests: as_f64(window.requests),
                    writes: as_f64(window.writes),
                    bytes_out: as_f64(window.bytes_out),
                    bytes_in: as_f64(window.bytes_in),
                    errors: as_f64(window.errors),
                    windows: 1,
                    last_active_ms: now_ms,
                    alerting: std::collections::BTreeSet::new(),
                },
            );
            continue;
        };
        if settings.enabled && baseline.windows >= WARMUP_WINDOWS {
            let checks = [
                (
                    "requests",
                    window.requests,
                    baseline.requests,
                    settings.min_requests,
                ),
                (
                    "writes",
                    window.writes,
                    baseline.writes,
                    settings.min_requests,
                ),
                (
                    "bytes_out",
                    window.bytes_out,
                    baseline.bytes_out,
                    settings.min_bytes,
                ),
                (
                    "bytes_in",
                    window.bytes_in,
                    baseline.bytes_in,
                    settings.min_bytes,
                ),
                (
                    "errors",
                    window.errors,
                    baseline.errors,
                    settings.min_requests,
                ),
            ];
            for (counter, value, mean, floor) in checks {
                let reference = mean.max(as_f64(floor));
                if as_f64(value) <= settings.ratio * reference {
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
                        detail: drift_detail(counter, value, reference, settings.ratio),
                        ..Default::default()
                    });
                }
            }
        }
        baseline.windows += 1;
        if window != EndpointTotals::default() {
            let update = |mean: &mut f64, value: u64| {
                *mean = (1.0 - EWMA_WEIGHT).mul_add(*mean, EWMA_WEIGHT * as_f64(value));
            };
            update(&mut baseline.requests, window.requests);
            update(&mut baseline.writes, window.writes);
            update(&mut baseline.bytes_out, window.bytes_out);
            update(&mut baseline.bytes_in, window.bytes_in);
            update(&mut baseline.errors, window.errors);
            baseline.last_active_ms = now_ms;
        }
    }
    while state.baselines.len() > MAX_BASELINES {
        let Some(oldest) = state
            .baselines
            .iter()
            .min_by_key(|(_, baseline)| baseline.last_active_ms)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        state.baselines.remove(&oldest);
    }
    findings
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
        drift_findings = apply_window(&mut persisted, &report.summaries, settings, now_ms());
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
    if let Some(owner) =
        crate::supervisor_session::remote_supervisor_owner(state, sandbox.object_id()).await?
    {
        let response = crate::supervisor_session::forward_egress_usage_query_to_owner(
            state,
            &owner,
            sandbox.object_id(),
            request,
        )
        .await?;
        return Ok(Response::new(response));
    }
    Ok(Response::new(
        state.egress_usage.snapshot(sandbox.object_id()),
    ))
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
            assert!(apply_window(state, &[summary(requests, 0)], settings(), 0).is_empty());
        }
    }

    #[test]
    fn no_drift_before_warmup() {
        let mut state = PersistedUsageState::default();
        apply_window(&mut state, &[summary(10, 0)], settings(), 0);
        let findings = apply_window(&mut state, &[summary(10_000, 0)], settings(), 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn jump_above_ratio_reports_once_while_it_lasts() {
        let mut state = PersistedUsageState::default();
        warm(&mut state, 200);
        let first = apply_window(&mut state, &[summary(20_000, 0)], settings(), 0);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].counter, "requests");
        for _ in 0..5 {
            assert!(apply_window(&mut state, &[summary(20_000, 0)], settings(), 0).is_empty());
        }
    }

    #[test]
    fn drift_reports_again_after_returning_below_threshold() {
        let mut state = PersistedUsageState::default();
        warm(&mut state, 200);
        assert_eq!(
            apply_window(&mut state, &[summary(20_000, 0)], settings(), 0).len(),
            1
        );
        // An idle window clears the alert. The first jump raised the mean to
        // 2180, so the next jump must exceed 21 800 to drift again.
        apply_window(&mut state, &[], settings(), 0);
        assert!(apply_window(&mut state, &[summary(20_000, 0)], settings(), 0).is_empty());
        assert_eq!(
            apply_window(&mut state, &[summary(300_000, 0)], settings(), 0).len(),
            1
        );
    }

    #[test]
    fn idle_windows_do_not_decay_the_baseline() {
        let mut state = PersistedUsageState::default();
        apply_window(&mut state, &[summary(100, 0)], settings(), 0);
        for _ in 0..50 {
            apply_window(&mut state, &[], settings(), 0);
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
        assert!(apply_window(&mut state, &[summary(500, 0)], settings(), 0).is_empty());
        assert_eq!(
            apply_window(&mut state, &[summary(1001, 0)], settings(), 0).len(),
            1
        );
    }

    #[test]
    fn sustained_transfer_after_idle_time_reports_once() {
        // The playground case: idle windows, then one 4 GB download counted
        // over three 10 s windows.
        let mut state = PersistedUsageState::default();
        apply_window(&mut state, &[summary(1, 50_000)], settings(), 0);
        for _ in 0..WARMUP_WINDOWS {
            apply_window(&mut state, &[], settings(), 0);
        }
        let mut findings = Vec::new();
        for bytes in [143_501_034, 2_109_301_566, 2_048_000_240] {
            findings.extend(apply_window(
                &mut state,
                &[summary(1, bytes)],
                settings(),
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
        let findings = apply_window(&mut state, &[window], settings(), 0);
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
