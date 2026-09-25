// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fleet egress usage: destinations per workspace and minute, across
//! sandboxes and gateway replicas.
//!
//! Each replica sums the reports that it accepts into one-minute buckets of
//! gateway time. When a bucket closes, the replica writes its share as one
//! partial record, so every partial has one writer. The first replica that
//! claims a bucket merges the partials of all replicas and evaluates fan-in:
//! a jump in the number of sandboxes that use, or write to, one destination.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openshell_core::proto::{
    EgressFindingSeverity, EgressUsageFinding, EgressUsageSummary, FleetEgressDestination,
    GetFleetEgressUsageRequest, GetFleetEgressUsageResponse,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use tonic::{Request, Response, Status};

use crate::ServerState;
use crate::auth::workspace_authz::{
    MinWorkspaceRole, authorize_workspace, selected_workspace_name,
};
use crate::persistence::{PersistenceError, Store, WriteCondition};

/// One replica's share of one workspace bucket.
pub const FLEET_PARTIAL_OBJECT_TYPE: &str = "egress_fleet_partial";
/// Claim of the evaluation of one workspace bucket.
pub const FLEET_EVAL_OBJECT_TYPE: &str = "egress_fleet_eval";
/// Fan-in baselines of one workspace.
pub const FLEET_BASELINE_OBJECT_TYPE: &str = "egress_fleet_baseline";
/// One fleet finding.
pub const FLEET_FINDING_OBJECT_TYPE: &str = "egress_fleet_finding";
/// Every fleet record type, for workspace deletion.
pub const FLEET_OBJECT_TYPES: [&str; 4] = [
    FLEET_PARTIAL_OBJECT_TYPE,
    FLEET_EVAL_OBJECT_TYPE,
    FLEET_BASELINE_OBJECT_TYPE,
    FLEET_FINDING_OBJECT_TYPE,
];

const BUCKET_MS: i64 = 60_000;
/// Time after a bucket ends before it is evaluated, so that other replicas
/// can write their partials.
const EVALUATION_DELAY_MS: i64 = 30_000;
const MAX_KEYS_PER_BUCKET: usize = 512;
const MAX_EXAMPLES: usize = 20;
const MAX_BASELINES: usize = 256;
const MAX_FINDINGS: usize = 200;
const DEFAULT_MINUTES: u32 = 10;
const MAX_MINUTES: u32 = 60;
const EWMA_WEIGHT: f64 = 0.1;
const DEFAULT_RATIO: f64 = 5.0;
const DEFAULT_MIN_SANDBOXES: u64 = 3;
const CAS_ATTEMPTS: usize = 5;
const LIST_PAGE: u32 = 500;
const BASELINE_NAME: &str = "fleet";
const OVERFLOW_HOST: &str = "other";
const PARTIAL_TTL: Duration = Duration::from_hours(1);
const FINDING_TTL: Duration = Duration::from_hours(24);
const BASELINE_TTL: Duration = Duration::from_hours(24 * 7);
const SWEEP_EVERY: Duration = Duration::from_hours(1);

/// Destination of fleet usage.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct DestinationKey {
    cohort: String,
    host: String,
    port: u32,
}

impl DestinationKey {
    fn name(&self) -> String {
        format!("{}|{}:{}", self.cohort, self.host, self.port)
    }
}

#[derive(Debug, Default)]
struct Accumulator {
    sandboxes: HashSet<String>,
    writers: HashSet<String>,
    requests: u64,
    write_requests: u64,
    bytes_out: u64,
    bytes_in: u64,
    errors: u64,
}

/// One destination in a partial or a merged bucket.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct BucketDestination {
    cohort: String,
    host: String,
    port: u32,
    sandboxes: u64,
    writer_sandboxes: u64,
    requests: u64,
    write_requests: u64,
    bytes_out: u64,
    bytes_in: u64,
    errors: u64,
    examples: Vec<String>,
}

impl BucketDestination {
    fn key(&self) -> DestinationKey {
        DestinationKey {
            cohort: self.cohort.clone(),
            host: self.host.clone(),
            port: self.port,
        }
    }

    /// Add another replica's share. Sandbox counts add up, because a
    /// sandbox has one owner replica at a time.
    fn merge(&mut self, other: &Self) {
        self.sandboxes += other.sandboxes;
        self.writer_sandboxes += other.writer_sandboxes;
        self.requests += other.requests;
        self.write_requests += other.write_requests;
        self.bytes_out += other.bytes_out;
        self.bytes_in += other.bytes_in;
        self.errors += other.errors;
        merge_examples(&mut self.examples, &other.examples);
    }
}

fn merge_examples(examples: &mut Vec<String>, other: &[String]) {
    for name in other {
        if examples.len() >= MAX_EXAMPLES {
            break;
        }
        if !examples.contains(name) {
            examples.push(name.clone());
        }
    }
}

/// Fan-in thresholds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FleetSettings {
    ratio: f64,
    min_sandboxes: u64,
}

impl Default for FleetSettings {
    fn default() -> Self {
        Self {
            ratio: DEFAULT_RATIO,
            min_sandboxes: DEFAULT_MIN_SANDBOXES,
        }
    }
}

impl FleetSettings {
    /// Defaults, with the proof-of-concept overrides
    /// `OPENSHELL_FLEET_FAN_IN_RATIO` and `OPENSHELL_FLEET_FAN_IN_MIN_SANDBOXES`.
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            ratio: std::env::var("OPENSHELL_FLEET_FAN_IN_RATIO")
                .ok()
                .and_then(|value| value.parse().ok())
                .filter(|ratio: &f64| *ratio >= 1.0)
                .unwrap_or(defaults.ratio),
            min_sandboxes: std::env::var("OPENSHELL_FLEET_FAN_IN_MIN_SANDBOXES")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(defaults.min_sandboxes),
        }
    }
}

type BucketMap = HashMap<DestinationKey, Accumulator>;

/// In-memory fleet buckets of this replica.
#[derive(Debug, Default)]
pub struct EgressFleet {
    buckets: Mutex<BTreeMap<(i64, String), BucketMap>>,
    pending: Mutex<BTreeSet<(i64, String)>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bucket_of(now_ms: i64) -> i64 {
    now_ms - now_ms.rem_euclid(BUCKET_MS)
}

/// Bucket start as a fixed-width name prefix, so names sort by time.
fn bucket_name(bucket: i64) -> String {
    format!("{bucket:015}")
}

impl EgressFleet {
    /// Add one accepted report to the bucket of `now_ms`.
    pub fn observe(
        &self,
        workspace: &str,
        cohort: &str,
        sandbox: &str,
        summaries: &[EgressUsageSummary],
        now_ms: i64,
    ) {
        let mut buckets = lock(&self.buckets);
        let bucket = buckets
            .entry((bucket_of(now_ms), workspace.to_string()))
            .or_default();
        for summary in summaries {
            let mut key = DestinationKey {
                cohort: cohort.to_string(),
                host: summary.host.clone(),
                port: summary.port,
            };
            if !bucket.contains_key(&key) && bucket.len() >= MAX_KEYS_PER_BUCKET {
                key.host = OVERFLOW_HOST.to_string();
                key.port = 0;
            }
            let entry = bucket.entry(key).or_default();
            let responses = summary.responses.unwrap_or_default();
            entry.sandboxes.insert(sandbox.to_string());
            if summary.write_requests > 0 {
                entry.writers.insert(sandbox.to_string());
            }
            entry.requests += summary.requests;
            entry.write_requests += summary.write_requests;
            entry.bytes_out += summary.bytes_out;
            entry.bytes_in += summary.bytes_in;
            entry.errors += responses.status_4xx + responses.status_5xx;
        }
    }

    /// Remove the buckets that ended before `now_ms` and return them as
    /// partials.
    fn take_closed(&self, now_ms: i64) -> Vec<(i64, String, Vec<BucketDestination>)> {
        let current = bucket_of(now_ms);
        let closed = {
            let mut buckets = lock(&self.buckets);
            let open = buckets.split_off(&(current, String::new()));
            std::mem::replace(&mut *buckets, open)
        };
        closed
            .into_iter()
            .map(|(key, map)| {
                let mut destinations: Vec<_> = map
                    .into_iter()
                    .map(|(key, accumulator)| {
                        let mut examples: Vec<_> = accumulator.sandboxes.iter().cloned().collect();
                        examples.sort();
                        examples.truncate(MAX_EXAMPLES);
                        BucketDestination {
                            cohort: key.cohort,
                            host: key.host,
                            port: key.port,
                            sandboxes: accumulator.sandboxes.len() as u64,
                            writer_sandboxes: accumulator.writers.len() as u64,
                            requests: accumulator.requests,
                            write_requests: accumulator.write_requests,
                            bytes_out: accumulator.bytes_out,
                            bytes_in: accumulator.bytes_in,
                            errors: accumulator.errors,
                            examples,
                        }
                    })
                    .collect();
                destinations.sort_by_key(BucketDestination::key);
                (key.0, key.1, destinations)
            })
            .collect()
    }

    /// Write closed buckets as partials, then evaluate the buckets that are
    /// due. Returns the new findings.
    async fn tick(
        &self,
        store: &Store,
        replica_id: &str,
        settings: FleetSettings,
        now_ms: i64,
    ) -> Vec<EgressUsageFinding> {
        for (bucket, workspace, destinations) in self.take_closed(now_ms) {
            match write_partial(store, &workspace, bucket, replica_id, &destinations).await {
                Ok(()) => {
                    lock(&self.pending).insert((bucket, workspace));
                }
                Err(error) => {
                    tracing::warn!(error = %error, workspace, "fleet usage partial write failed");
                }
            }
        }
        let due: Vec<_> = lock(&self.pending)
            .iter()
            .filter(|(bucket, _)| bucket + BUCKET_MS + EVALUATION_DELAY_MS <= now_ms)
            .cloned()
            .collect();
        let mut findings = Vec::new();
        for (bucket, workspace) in due {
            lock(&self.pending).remove(&(bucket, workspace.clone()));
            match evaluate_bucket(store, &workspace, bucket, settings, now_ms).await {
                Ok(new) => findings.extend(new),
                Err(error) => {
                    tracing::warn!(error = %error, workspace, "fleet usage evaluation failed");
                }
            }
        }
        findings
    }
}

async fn write_partial(
    store: &Store,
    workspace: &str,
    bucket: i64,
    replica_id: &str,
    destinations: &[BucketDestination],
) -> Result<(), String> {
    let payload = serde_json::to_vec(destinations).map_err(|error| error.to_string())?;
    match store
        .put_if(
            FLEET_PARTIAL_OBJECT_TYPE,
            &uuid::Uuid::new_v4().to_string(),
            &format!("{}|{replica_id}", bucket_name(bucket)),
            workspace,
            &payload,
            None,
            WriteCondition::MustCreate,
        )
        .await
    {
        Ok(_)
        | Err(PersistenceError::Conflict { .. } | PersistenceError::UniqueViolation { .. }) => {
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

/// List every record of a type in a workspace whose name starts with `prefix`.
async fn list_named(
    store: &Store,
    object_type: &str,
    workspace: &str,
    prefix: &str,
) -> Result<Vec<crate::persistence::ObjectRecord>, String> {
    let mut records = Vec::new();
    let mut offset = 0;
    loop {
        let page = store
            .list(object_type, workspace, LIST_PAGE, offset)
            .await
            .map_err(|error| error.to_string())?;
        let page_len = page.len();
        records.extend(
            page.into_iter()
                .filter(|record| record.name.starts_with(prefix)),
        );
        if page_len < LIST_PAGE as usize {
            return Ok(records);
        }
        offset += LIST_PAGE;
    }
}

/// Merge the partials of every replica for the buckets from `first` on.
async fn merged_buckets(
    store: &Store,
    workspace: &str,
    first: i64,
) -> Result<BTreeMap<i64, BTreeMap<DestinationKey, BucketDestination>>, String> {
    let mut buckets: BTreeMap<i64, BTreeMap<DestinationKey, BucketDestination>> = BTreeMap::new();
    for record in list_named(store, FLEET_PARTIAL_OBJECT_TYPE, workspace, "").await? {
        let Some(bucket) = record
            .name
            .split('|')
            .next()
            .and_then(|bucket| bucket.parse::<i64>().ok())
            .filter(|bucket| *bucket >= first)
        else {
            continue;
        };
        let Ok(destinations) = serde_json::from_slice::<Vec<BucketDestination>>(&record.payload)
        else {
            continue;
        };
        let merged = buckets.entry(bucket).or_default();
        for destination in destinations {
            merged
                .entry(destination.key())
                .and_modify(|existing| existing.merge(&destination))
                .or_insert(destination);
        }
    }
    Ok(buckets)
}

/// Fan-in baseline of one destination.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct FanInBaseline {
    sandboxes: f64,
    writer_sandboxes: f64,
    last_bucket: i64,
    /// Counters above their threshold. A counter reports once and again
    /// only after a bucket below the threshold.
    alerting: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct FleetBaselines {
    baselines: BTreeMap<String, FanInBaseline>,
}

#[allow(clippy::cast_precision_loss)]
fn as_f64(value: u64) -> f64 {
    value as f64
}

/// Apply one merged bucket to the baselines. The first bucket of a
/// destination sets its baseline. After it, a counter drifts when its value
/// is more than `ratio` times the larger of its mean and the floor.
fn apply_bucket(
    baselines: &mut FleetBaselines,
    bucket: i64,
    destinations: &BTreeMap<DestinationKey, BucketDestination>,
    settings: FleetSettings,
) -> Vec<EgressUsageFinding> {
    let mut findings = Vec::new();
    for (key, destination) in destinations {
        let Some(baseline) = baselines.baselines.get_mut(&key.name()) else {
            baselines.baselines.insert(
                key.name(),
                FanInBaseline {
                    sandboxes: as_f64(destination.sandboxes),
                    writer_sandboxes: as_f64(destination.writer_sandboxes),
                    last_bucket: bucket,
                    alerting: BTreeSet::new(),
                },
            );
            continue;
        };
        let checks = [
            (
                "sandboxes",
                destination.sandboxes,
                baseline.sandboxes,
                "used",
            ),
            (
                "writer_sandboxes",
                destination.writer_sandboxes,
                baseline.writer_sandboxes,
                "wrote to",
            ),
        ];
        for (counter, value, mean, verb) in checks {
            let reference = mean.max(as_f64(settings.min_sandboxes));
            if as_f64(value) <= settings.ratio * reference {
                baseline.alerting.remove(counter);
                continue;
            }
            if baseline.alerting.insert(counter.to_string()) {
                let others = destination
                    .sandboxes
                    .saturating_sub(destination.examples.len() as u64);
                let mut examples = destination.examples.join(", ");
                if others > 0 {
                    examples = format!("{examples} +{others}");
                }
                findings.push(EgressUsageFinding {
                    finding_type: "egress.fleet_fan_in".to_string(),
                    severity: EgressFindingSeverity::Medium as i32,
                    host: key.host.clone(),
                    port: key.port,
                    counter: counter.to_string(),
                    detail: format!(
                        "{value} sandboxes {verb} {}:{} in one minute, more than {} times the fleet baseline {reference:.1} (cohort {}: {examples})",
                        key.host, key.port, settings.ratio, key.cohort
                    ),
                    ..Default::default()
                });
            }
        }
        let update = |mean: &mut f64, value: u64| {
            *mean = (1.0 - EWMA_WEIGHT).mul_add(*mean, EWMA_WEIGHT * as_f64(value));
        };
        update(&mut baseline.sandboxes, destination.sandboxes);
        update(&mut baseline.writer_sandboxes, destination.writer_sandboxes);
        baseline.last_bucket = bucket;
    }
    while baselines.baselines.len() > MAX_BASELINES {
        let Some(oldest) = baselines
            .baselines
            .iter()
            .min_by_key(|(_, baseline)| baseline.last_bucket)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        baselines.baselines.remove(&oldest);
    }
    findings
}

/// Claim, merge, and evaluate one workspace bucket. Only the replica that
/// creates the claim evaluates the bucket, so each finding is created once.
async fn evaluate_bucket(
    store: &Store,
    workspace: &str,
    bucket: i64,
    settings: FleetSettings,
    now_ms: i64,
) -> Result<Vec<EgressUsageFinding>, String> {
    match store
        .put_if(
            FLEET_EVAL_OBJECT_TYPE,
            &uuid::Uuid::new_v4().to_string(),
            &bucket_name(bucket),
            workspace,
            b"{}",
            None,
            WriteCondition::MustCreate,
        )
        .await
    {
        Ok(_) => {}
        Err(PersistenceError::Conflict { .. } | PersistenceError::UniqueViolation { .. }) => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error.to_string()),
    }
    let merged = merged_buckets(store, workspace, bucket).await?;
    let Some(destinations) = merged.get(&bucket) else {
        return Ok(Vec::new());
    };

    let mut findings = Vec::new();
    let mut saved = false;
    for _ in 0..CAS_ATTEMPTS {
        let record = store
            .get_by_name(FLEET_BASELINE_OBJECT_TYPE, workspace, BASELINE_NAME)
            .await
            .map_err(|error| error.to_string())?;
        let (mut baselines, id, condition) = match record {
            Some(record) => (
                serde_json::from_slice(&record.payload).unwrap_or_default(),
                record.id,
                WriteCondition::MatchResourceVersion(record.resource_version),
            ),
            None => (
                FleetBaselines::default(),
                uuid::Uuid::new_v4().to_string(),
                WriteCondition::MustCreate,
            ),
        };
        findings = apply_bucket(&mut baselines, bucket, destinations, settings);
        let payload = serde_json::to_vec(&baselines).map_err(|error| error.to_string())?;
        match store
            .put_if(
                FLEET_BASELINE_OBJECT_TYPE,
                &id,
                BASELINE_NAME,
                workspace,
                &payload,
                None,
                condition,
            )
            .await
        {
            Ok(_) => {
                saved = true;
                break;
            }
            Err(PersistenceError::Conflict { .. } | PersistenceError::UniqueViolation { .. }) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    if !saved {
        return Err("fleet baselines changed concurrently".to_string());
    }

    let observed = prost_types::Timestamp::from(
        UNIX_EPOCH + Duration::from_millis(u64::try_from(now_ms).unwrap_or(0)),
    );
    for finding in &mut findings {
        finding.observed_time = Some(observed);
        let name = format!(
            "{}|{}:{}|{}",
            bucket_name(bucket),
            finding.host,
            finding.port,
            finding.counter
        );
        if let Err(error) = store
            .put_if(
                FLEET_FINDING_OBJECT_TYPE,
                &uuid::Uuid::new_v4().to_string(),
                &name,
                workspace,
                &finding.encode_to_vec(),
                None,
                WriteCondition::MustCreate,
            )
            .await
        {
            tracing::warn!(error = %error, workspace, "fleet finding write failed");
        }
        tracing::warn!(
            finding_type = %finding.finding_type,
            workspace,
            host = %finding.host,
            port = finding.port,
            counter = %finding.counter,
            "{}",
            finding.detail
        );
    }
    Ok(findings)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

fn ttl_ms(ttl: Duration) -> i64 {
    i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX)
}

/// Delete fleet records older than their retention.
async fn reap_fleet_records(store: &Store, now_ms: i64) -> Result<u64, String> {
    let mut deleted = 0;
    for (object_type, ttl) in [
        (FLEET_PARTIAL_OBJECT_TYPE, PARTIAL_TTL),
        (FLEET_EVAL_OBJECT_TYPE, PARTIAL_TTL),
        (FLEET_FINDING_OBJECT_TYPE, FINDING_TTL),
        (FLEET_BASELINE_OBJECT_TYPE, BASELINE_TTL),
    ] {
        let cutoff = now_ms - ttl_ms(ttl);
        let mut cursor = None;
        let mut old = Vec::new();
        loop {
            let records = store
                .list_by_type_after(object_type, cursor.as_ref(), LIST_PAGE)
                .await
                .map_err(|error| error.to_string())?;
            let Some(last) = records.last() else {
                break;
            };
            cursor = Some(crate::persistence::ObjectCursor::from(last));
            old.extend(
                records
                    .iter()
                    .filter(|record| record.updated_at_ms < cutoff)
                    .map(|record| record.id.clone()),
            );
        }
        if !old.is_empty() {
            deleted += store
                .delete_many(object_type, &old)
                .await
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(deleted)
}

/// Write partials, evaluate due buckets every 10 s, and sweep old records
/// every hour.
pub fn spawn_fleet_worker(state: Arc<ServerState>) {
    let settings = FleetSettings::from_env();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_sweep = std::time::Instant::now();
        loop {
            ticker.tick().await;
            state
                .egress_fleet
                .tick(&state.store, &state.replica_id, settings, now_ms())
                .await;
            if last_sweep.elapsed() >= SWEEP_EVERY {
                last_sweep = std::time::Instant::now();
                if let Err(error) = reap_fleet_records(&state.store, now_ms()).await {
                    tracing::warn!(error = %error, "fleet usage sweep failed");
                }
            }
        }
    });
}

/// Handle `GetFleetEgressUsage` for a workspace admin.
pub(super) async fn handle_get_fleet_egress_usage(
    state: &Arc<ServerState>,
    request: Request<GetFleetEgressUsageRequest>,
) -> Result<Response<GetFleetEgressUsageResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let workspace = selected_workspace_name(request.workspace_scope.as_ref())?;
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        workspace,
        MinWorkspaceRole::Admin,
    )
    .await?;
    let workspace = authz.workspace;
    let minutes = match request.minutes {
        0 => DEFAULT_MINUTES,
        minutes => minutes.min(MAX_MINUTES),
    };
    let first = bucket_of(now_ms()) - i64::from(minutes - 1) * BUCKET_MS;
    let buckets = merged_buckets(&state.store, &workspace, first)
        .await
        .map_err(|error| Status::internal(format!("read fleet usage failed: {error}")))?;
    Ok(Response::new(GetFleetEgressUsageResponse {
        destinations: fleet_destinations(&buckets),
        findings: fleet_findings(&state.store, &workspace)
            .await
            .map_err(|error| Status::internal(format!("read fleet findings failed: {error}")))?,
    }))
}

fn fleet_destinations(
    buckets: &BTreeMap<i64, BTreeMap<DestinationKey, BucketDestination>>,
) -> Vec<FleetEgressDestination> {
    let mut destinations: BTreeMap<DestinationKey, FleetEgressDestination> = BTreeMap::new();
    for destination in buckets.values().flat_map(BTreeMap::values) {
        let entry =
            destinations
                .entry(destination.key())
                .or_insert_with(|| FleetEgressDestination {
                    cohort: destination.cohort.clone(),
                    host: destination.host.clone(),
                    port: destination.port,
                    ..Default::default()
                });
        entry.max_sandboxes = entry.max_sandboxes.max(destination.sandboxes);
        entry.max_writer_sandboxes = entry.max_writer_sandboxes.max(destination.writer_sandboxes);
        entry.requests += destination.requests;
        entry.write_requests += destination.write_requests;
        entry.bytes_out += destination.bytes_out;
        entry.bytes_in += destination.bytes_in;
        entry.errors += destination.errors;
        merge_examples(&mut entry.example_sandboxes, &destination.examples);
    }
    let mut destinations: Vec<_> = destinations.into_values().collect();
    destinations.sort_by(|left, right| {
        right
            .max_sandboxes
            .cmp(&left.max_sandboxes)
            .then_with(|| right.bytes_in.cmp(&left.bytes_in))
    });
    destinations
}

async fn fleet_findings(store: &Store, workspace: &str) -> Result<Vec<EgressUsageFinding>, String> {
    let mut records = list_named(store, FLEET_FINDING_OBJECT_TYPE, workspace, "").await?;
    records.sort_by(|left, right| right.name.cmp(&left.name));
    Ok(records
        .iter()
        .take(MAX_FINDINGS)
        .filter_map(|record| EgressUsageFinding::decode(record.payload.as_slice()).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::test_support::{authed_request, test_server_state};

    const MINUTE: i64 = 1_700_000_040_000;

    fn summary(host: &str, requests: u64, writes: u64) -> EgressUsageSummary {
        EgressUsageSummary {
            policy_key: "api".into(),
            endpoint_id: "endpoint:v1:api".into(),
            host: host.into(),
            port: 443,
            requests,
            write_requests: writes,
            ..Default::default()
        }
    }

    fn settings() -> FleetSettings {
        FleetSettings::default()
    }

    /// Merged bucket with `sandboxes` sandboxes, `writers` of which write.
    fn bucket(
        host: &str,
        sandboxes: u64,
        writers: u64,
    ) -> BTreeMap<DestinationKey, BucketDestination> {
        let fleet = EgressFleet::default();
        for index in 0..sandboxes {
            let write_count = u64::from(index < writers);
            fleet.observe(
                "default",
                "policy:abc",
                &format!("sb-{index}"),
                &[summary(host, 1, write_count)],
                MINUTE,
            );
        }
        let (_, _, destinations) = fleet.take_closed(MINUTE + BUCKET_MS).remove(0);
        destinations
            .into_iter()
            .map(|destination| (destination.key(), destination))
            .collect()
    }

    #[test]
    fn readers_and_writers_are_counted_separately() {
        let merged = bucket("proxy.internal", 2, 1);
        let destination = merged.values().next().unwrap();
        assert_eq!(destination.sandboxes, 2);
        assert_eq!(destination.writer_sandboxes, 1);
        assert_eq!(destination.examples, ["sb-0", "sb-1"]);
    }

    #[test]
    fn writer_fan_in_reports_once_above_the_floor() {
        let mut baselines = FleetBaselines::default();
        // The first bucket of a destination sets its baseline.
        assert!(
            apply_bucket(
                &mut baselines,
                0,
                &bucket("proxy.internal", 16, 0),
                settings()
            )
            .is_empty()
        );
        let findings = apply_bucket(
            &mut baselines,
            1,
            &bucket("proxy.internal", 16, 16),
            settings(),
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].counter, "writer_sandboxes");
        assert!(
            findings[0]
                .detail
                .contains("16 sandboxes wrote to proxy.internal:443")
        );
        assert!(
            apply_bucket(
                &mut baselines,
                2,
                &bucket("proxy.internal", 16, 16),
                settings()
            )
            .is_empty(),
            "the same level reports once"
        );
    }

    #[test]
    fn fifteen_writers_stay_under_the_cold_threshold() {
        let mut baselines = FleetBaselines::default();
        apply_bucket(
            &mut baselines,
            0,
            &bucket("proxy.internal", 15, 0),
            settings(),
        );
        assert!(
            apply_bucket(
                &mut baselines,
                1,
                &bucket("proxy.internal", 15, 15),
                settings()
            )
            .is_empty()
        );
    }

    #[test]
    fn readers_report_only_against_a_low_baseline() {
        let mut baselines = FleetBaselines::default();
        // Every sandbox reads the package proxy from the start.
        for index in 0..5 {
            apply_bucket(
                &mut baselines,
                index,
                &bucket("proxy.internal", 40, 0),
                settings(),
            );
        }
        assert!(
            apply_bucket(
                &mut baselines,
                5,
                &bucket("proxy.internal", 40, 0),
                settings()
            )
            .is_empty()
        );
        // A paste site that one sandbox used suddenly draws 40.
        apply_bucket(
            &mut baselines,
            0,
            &bucket("paste.example", 1, 0),
            settings(),
        );
        let findings = apply_bucket(
            &mut baselines,
            1,
            &bucket("paste.example", 40, 0),
            settings(),
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].counter, "sandboxes");
    }

    #[test]
    fn keys_per_bucket_are_bounded() {
        let fleet = EgressFleet::default();
        for index in 0..(MAX_KEYS_PER_BUCKET + 10) {
            fleet.observe(
                "default",
                "policy:abc",
                "sb",
                &[summary(&format!("h{index}.example"), 1, 0)],
                MINUTE,
            );
        }
        let (_, _, destinations) = fleet.take_closed(MINUTE + BUCKET_MS).remove(0);
        assert_eq!(destinations.len(), MAX_KEYS_PER_BUCKET + 1);
        assert!(
            destinations
                .iter()
                .any(|destination| destination.host == OVERFLOW_HOST)
        );
    }

    #[tokio::test]
    async fn partials_of_two_replicas_add_up_and_one_evaluator_wins() {
        let state = test_server_state().await;
        let replica_a = EgressFleet::default();
        let replica_b = EgressFleet::default();
        for index in 0..10 {
            replica_a.observe(
                "default",
                "policy:abc",
                &format!("a-{index}"),
                &[summary("proxy.internal", 1, 1)],
                MINUTE,
            );
            replica_b.observe(
                "default",
                "policy:abc",
                &format!("b-{index}"),
                &[summary("proxy.internal", 1, 1)],
                MINUTE,
            );
        }
        let later = MINUTE + BUCKET_MS + EVALUATION_DELAY_MS;
        replica_a
            .tick(&state.store, "replica-a", settings(), MINUTE + BUCKET_MS)
            .await;
        replica_b
            .tick(&state.store, "replica-b", settings(), MINUTE + BUCKET_MS)
            .await;
        let merged = merged_buckets(&state.store, "default", 0).await.unwrap();
        let destination = merged[&bucket_of(MINUTE)].values().next().unwrap().clone();
        assert_eq!(destination.writer_sandboxes, 20);
        assert_eq!(destination.examples.len(), MAX_EXAMPLES);

        replica_a
            .tick(&state.store, "replica-a", settings(), later)
            .await;
        replica_b
            .tick(&state.store, "replica-b", settings(), later)
            .await;
        let claims = state
            .store
            .list(FLEET_EVAL_OBJECT_TYPE, "default", 10, 0)
            .await
            .unwrap();
        assert_eq!(claims.len(), 1, "one replica evaluates a bucket");
    }

    #[tokio::test]
    async fn report_to_fleet_view_end_to_end() {
        let state = test_server_state().await;
        // Minute 1: 16 sandboxes read the proxy. Minute 2: all of them write.
        for (minute, writes) in [(MINUTE, 0), (MINUTE + BUCKET_MS, 1)] {
            for index in 0..16 {
                state.egress_fleet.observe(
                    "default",
                    "template:eval",
                    &format!("sb-{index:02}"),
                    &[summary("proxy.internal", 2, writes)],
                    minute,
                );
            }
            let closes = minute + BUCKET_MS;
            state
                .egress_fleet
                .tick(&state.store, "replica-a", settings(), closes)
                .await;
            let findings = state
                .egress_fleet
                .tick(
                    &state.store,
                    "replica-a",
                    settings(),
                    closes + EVALUATION_DELAY_MS,
                )
                .await;
            assert_eq!(findings.len(), usize::from(writes == 1), "{findings:?}");
        }

        let usage = merged_buckets(&state.store, "default", 0).await.unwrap();
        let destinations = fleet_destinations(&usage);
        assert_eq!(destinations.len(), 1);
        assert_eq!(destinations[0].max_sandboxes, 16);
        assert_eq!(destinations[0].max_writer_sandboxes, 16);
        assert_eq!(destinations[0].requests, 64);

        let response = handle_get_fleet_egress_usage(
            &state,
            authed_request(GetFleetEgressUsageRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                minutes: 0,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(response.findings.len(), 1);
        assert_eq!(response.findings[0].finding_type, "egress.fleet_fan_in");
        assert_eq!(response.findings[0].counter, "writer_sandboxes");
    }

    #[tokio::test]
    async fn workspace_user_cannot_read_the_fleet_view() {
        use crate::auth::identity::{Identity, IdentityProvider};
        use crate::auth::principal::{Principal, UserPrincipal};
        use openshell_core::proto::datamodel::v1::ObjectMeta;
        use openshell_core::proto::{WorkspaceMember, WorkspaceRole};

        let mut state = test_server_state().await;
        Arc::get_mut(&mut state).unwrap().admin_role = "openshell-admin".to_string();
        state
            .store
            .put_message(&WorkspaceMember {
                metadata: Some(ObjectMeta {
                    id: "member-id".to_string(),
                    name: "test-user".to_string(),
                    workspace: "default".to_string(),
                    ..Default::default()
                }),
                principal_subject: "test-user".to_string(),
                role: WorkspaceRole::User.into(),
            })
            .await
            .unwrap();
        let mut request = Request::new(GetFleetEgressUsageRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
            minutes: 0,
        });
        request
            .extensions_mut()
            .insert(Principal::User(UserPrincipal {
                identity: Identity {
                    subject: "test-user".to_string(),
                    display_name: None,
                    roles: vec![],
                    scopes: vec![],
                    provider: IdentityProvider::Oidc,
                },
            }));
        let error = handle_get_fleet_egress_usage(&state, request)
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied, "{error}");
    }

    #[tokio::test]
    async fn sweep_removes_old_fleet_records() {
        let state = test_server_state().await;
        state.egress_fleet.observe(
            "default",
            "policy:abc",
            "sb",
            &[summary("h.example", 1, 0)],
            MINUTE,
        );
        state
            .egress_fleet
            .tick(&state.store, "replica-a", settings(), MINUTE + BUCKET_MS)
            .await;
        assert_eq!(reap_fleet_records(&state.store, now_ms()).await.unwrap(), 0);
        let later = now_ms() + ttl_ms(PARTIAL_TTL) + 1;
        assert_eq!(reap_fleet_records(&state.store, later).await.unwrap(), 1);
    }
}
