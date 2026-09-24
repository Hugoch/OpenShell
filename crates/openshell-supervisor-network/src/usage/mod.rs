// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Egress usage accounting, budgets, and novelty findings.
//!
//! Relays charge bytes through [`CountingStream`] into shared atomic
//! counters, so accounting never goes through a channel. Admission of a
//! connection or an L7 request selects budgets, takes tokens, evaluates
//! novelty, and returns the attribution that the relay charges.

mod counting;
mod ledger;
mod novelty;
mod table;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use openshell_core::egress_usage::{DEFAULT_LEARNING_PERIOD, MAX_FINDINGS_PER_REPORT};
use openshell_core::host_pattern::HostPattern;
use openshell_core::proto::{NetworkBudgetAction, SandboxPolicy};
use openshell_ocsf::{
    ActionId, ActivityId, DetectionFindingBuilder, DispositionId, Endpoint, FindingInfo,
    NetworkActivityBuilder, NetworkTraffic, SeverityId, StatusId, ocsf_emit,
};
use tokio::time::Instant;

pub use counting::{Attribution, AttributionCell, CountingStream};
pub use ledger::{BudgetSpec, Counter};
pub use table::{ResponseCounts, UsageKey, UsageSummary};

use ledger::{BudgetEntry, BudgetLedger};
use novelty::{Novelty, NoveltyKind, Observation};
use table::UsageTable;

/// Usage settings derived from one policy revision.
#[derive(Debug, Clone)]
pub struct UsageConfig {
    pub policy_hash: Arc<str>,
    pub budgets: Vec<BudgetSpec>,
    pub learning_period: Duration,
    pub endpoints_by_policy: BTreeMap<String, BTreeSet<String>>,
    endpoint_ids: HashMap<(String, usize), String>,
}

impl Default for UsageConfig {
    fn default() -> Self {
        Self {
            policy_hash: Arc::from(""),
            budgets: Vec::new(),
            learning_period: DEFAULT_LEARNING_PERIOD,
            endpoints_by_policy: BTreeMap::new(),
            endpoint_ids: HashMap::new(),
        }
    }
}

impl UsageConfig {
    /// Build the usage settings from a validated policy.
    pub fn from_proto(policy: &SandboxPolicy) -> Self {
        let mut endpoint_ids = HashMap::new();
        let mut endpoints_by_policy = BTreeMap::new();
        for (policy_key, rule) in &policy.network_policies {
            let mut ids = BTreeSet::new();
            for (index, endpoint) in rule.endpoints.iter().enumerate() {
                let id = openshell_core::endpoint_status::endpoint_id(endpoint);
                ids.insert(id.clone());
                endpoint_ids.insert((policy_key.clone(), index), id);
            }
            endpoints_by_policy.insert(policy_key.clone(), ids);
        }
        let budgets = policy
            .network_budgets
            .iter()
            .map(|(name, budget)| BudgetSpec {
                name: name.clone(),
                policies: budget.policies.clone(),
                // Validation rejects invalid patterns before this point.
                hosts: budget
                    .hosts
                    .iter()
                    .filter_map(|pattern| HostPattern::new(pattern).ok())
                    .collect(),
                deny: budget.on_exceed == NetworkBudgetAction::Deny as i32,
                requests_per_minute: budget.requests_per_minute,
                connections_per_minute: budget.connections_per_minute,
                bytes_out_per_hour: budget.bytes_out_per_hour,
                bytes_in_per_hour: budget.bytes_in_per_hour,
            })
            .collect();
        let learning_period = policy
            .usage_monitoring
            .as_ref()
            .and_then(|monitoring| monitoring.novelty.as_ref())
            .and_then(|novelty| novelty.learning_period.as_ref())
            .map_or(DEFAULT_LEARNING_PERIOD, |duration| {
                Duration::new(
                    u64::try_from(duration.seconds).unwrap_or(0),
                    u32::try_from(duration.nanos).unwrap_or(0),
                )
            });
        Self {
            policy_hash: Arc::from(
                openshell_core::policy_identity::deterministic_policy_hash(policy).as_str(),
            ),
            budgets,
            learning_period,
            endpoints_by_policy,
            endpoint_ids,
        }
    }

    /// Endpoint identity of one policy endpoint. Policies loaded from local
    /// files have no proto endpoint, so the position identifies them.
    pub fn endpoint_id(&self, policy_key: &str, endpoint_index: usize) -> String {
        self.endpoint_ids
            .get(&(policy_key.to_string(), endpoint_index))
            .cloned()
            .unwrap_or_else(|| format!("{policy_key}#{endpoint_index}"))
    }
}

/// Connection or L7 request admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionKind {
    Connection,
    Request,
}

/// Facts about one admission.
#[derive(Debug)]
pub struct Admission<'a> {
    pub kind: AdmissionKind,
    pub reported_policy: &'a str,
    pub authorizing_policies: &'a [String],
    pub endpoint_id: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub binary_path: &'a str,
    pub binary_sha256: &'a str,
    pub glob_host: bool,
    pub rule_ids: &'a [String],
}

/// A deny budget without balance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetDenial {
    pub budget: String,
    pub counter: Counter,
    pub retry_after: Duration,
}

/// Result of an admission.
#[derive(Debug)]
pub enum AdmissionOutcome {
    Admitted(Arc<Attribution>),
    Denied(BudgetDenial),
}

/// Finding severity. Budget denials are policy violations; the other
/// findings report a usage change, not a failed control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSeverity {
    Low,
    Medium,
}

/// One usage finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageFinding {
    pub finding_type: &'static str,
    pub severity: FindingSeverity,
    pub policy_key: String,
    pub endpoint_id: String,
    pub host: String,
    pub port: u16,
    pub binary_sha256: String,
    pub budget: String,
    pub counter: String,
    pub action: &'static str,
    pub detail: String,
}

#[derive(Debug, Default)]
struct FindingBuffer {
    findings: Vec<UsageFinding>,
    seen: HashSet<(String, &'static str)>,
    dropped: u64,
}

/// Summaries and findings of one window.
#[derive(Debug, Default)]
pub struct WindowSnapshot {
    pub summaries: Vec<UsageSummary>,
    pub findings: Vec<UsageFinding>,
    pub dropped_findings: u64,
    pub policy_hash: String,
}

/// Process-wide usage state. It survives policy reloads.
#[derive(Debug)]
pub struct UsageState {
    config: RwLock<Arc<UsageConfig>>,
    table: Mutex<UsageTable>,
    ledger: BudgetLedger,
    novelty: Mutex<Novelty>,
    findings: Mutex<FindingBuffer>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl UsageState {
    pub fn new(config: UsageConfig) -> Arc<Self> {
        let state = Arc::new(Self {
            config: RwLock::new(Arc::new(UsageConfig::default())),
            table: Mutex::new(UsageTable::default()),
            ledger: BudgetLedger::default(),
            novelty: Mutex::new(Novelty::new(config.learning_period)),
            findings: Mutex::new(FindingBuffer::default()),
        });
        state.reconfigure(config);
        state
    }

    /// Apply the usage settings of a new policy revision.
    pub fn reconfigure(&self, config: UsageConfig) {
        let now = Instant::now();
        self.ledger.reconcile(config.budgets.clone(), now);
        lock(&self.novelty).reconfigure(config.learning_period, &config.endpoints_by_policy, now);
        *self
            .config
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(config);
    }

    pub fn config(&self) -> Arc<UsageConfig> {
        self.config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Admit a connection or L7 request against the selected budgets.
    pub fn admit(&self, admission: &Admission<'_>) -> AdmissionOutcome {
        let now = Instant::now();
        let config = self.config();
        let budgets = self
            .ledger
            .selected(admission.authorizing_policies, admission.host);
        let count_counter = match admission.kind {
            AdmissionKind::Connection => Counter::Connections,
            AdmissionKind::Request => Counter::Requests,
        };
        let key = UsageKey {
            policy_key: admission.reported_policy.to_string(),
            endpoint_id: admission.endpoint_id.to_string(),
            host: admission.host.to_string(),
            port: admission.port,
            binary_path: admission.binary_path.to_string(),
            binary_sha256: admission.binary_sha256.to_string(),
        };
        let lookup = lock(&self.table).get_or_insert(&key, &config.policy_hash);
        if lookup.overflowed && lookup.inserted {
            self.record_finding(
                &key,
                UsageFinding {
                    finding_type: "egress.usage_overflow",
                    severity: FindingSeverity::Medium,
                    detail: "usage table is full; new keys share one entry per endpoint"
                        .to_string(),
                    ..finding_base(&key)
                },
            );
        }
        self.observe_novelty(admission, &key);
        let entry = lookup.entry;

        if let Some(denial) = take_deny_tokens(&budgets, count_counter, now) {
            entry.add_budget_denial();
            self.record_finding(
                &key,
                UsageFinding {
                    finding_type: "egress.budget_exceeded",
                    severity: FindingSeverity::Medium,
                    budget: denial.budget.clone(),
                    counter: denial.counter.name().to_string(),
                    action: "deny",
                    detail: format!(
                        "budget '{}' has no {} left",
                        denial.budget,
                        denial.counter.name()
                    ),
                    ..finding_base(&key)
                },
            );
            return AdmissionOutcome::Denied(denial);
        }

        for budget in budgets.iter().filter(|budget| !budget.spec.deny) {
            if let Some(counter) = alert_budget_exhausted(budget, count_counter, now) {
                self.record_finding(
                    &key,
                    UsageFinding {
                        finding_type: "egress.budget_exceeded",
                        severity: FindingSeverity::Low,
                        budget: budget.spec.name.clone(),
                        counter: counter.name().to_string(),
                        action: "alert",
                        detail: format!(
                            "budget '{}' has no {} left",
                            budget.spec.name,
                            counter.name()
                        ),
                        ..finding_base(&key)
                    },
                );
            }
        }

        match admission.kind {
            AdmissionKind::Connection => entry.add_connection(),
            AdmissionKind::Request => entry.add_request(admission.rule_ids),
        }
        let buckets = |counter: Counter| {
            budgets
                .iter()
                .filter_map(|budget| budget.bucket(counter).cloned())
                .collect::<Vec<_>>()
        };
        AdmissionOutcome::Admitted(Arc::new(Attribution {
            entry,
            bytes_out: buckets(Counter::BytesOut),
            bytes_in: buckets(Counter::BytesIn),
        }))
    }

    fn observe_novelty(&self, admission: &Admission<'_>, key: &UsageKey) {
        let now = Instant::now();
        let mut items: Vec<(NoveltyKind, &str)> = Vec::new();
        if admission.kind == AdmissionKind::Connection {
            if admission.glob_host {
                items.push((NoveltyKind::Host, admission.host));
            }
            items.push((NoveltyKind::Binary, admission.binary_sha256));
        }
        items.extend(
            admission
                .rule_ids
                .iter()
                .map(|rule| (NoveltyKind::Rule, rule.as_str())),
        );
        let observations: Vec<_> = {
            let mut novelty = lock(&self.novelty);
            items
                .into_iter()
                .map(|(kind, item)| {
                    (
                        kind,
                        item,
                        novelty.observe(admission.reported_policy, kind, item, now),
                    )
                })
                .collect()
        };
        for (kind, item, observation) in observations {
            match observation {
                Observation::Known => {}
                Observation::New => self.record_finding(
                    key,
                    UsageFinding {
                        finding_type: kind.finding_type(),
                        severity: FindingSeverity::Low,
                        detail: format!("first use of {item}"),
                        ..finding_base(key)
                    },
                ),
                Observation::Saturated => self.record_finding(
                    key,
                    UsageFinding {
                        finding_type: "egress.usage_overflow",
                        severity: FindingSeverity::Medium,
                        detail: format!("novelty set for {} is full", kind.finding_type()),
                        ..finding_base(key)
                    },
                ),
            }
        }
    }

    /// Keep at most one finding per usage key and type per window, and at
    /// most [`MAX_FINDINGS_PER_REPORT`] per window. Every recorded finding is
    /// also written to the local OCSF log.
    fn record_finding(&self, key: &UsageKey, finding: UsageFinding) {
        let dedup_key = format!(
            "{}|{}|{}|{}|{}|{}",
            key.policy_key, key.endpoint_id, key.host, key.port, key.binary_sha256, finding.detail
        );
        let mut buffer = lock(&self.findings);
        if !buffer.seen.insert((dedup_key, finding.finding_type)) {
            return;
        }
        emit_finding(&finding);
        if buffer.findings.len() >= MAX_FINDINGS_PER_REPORT {
            buffer.dropped += 1;
        } else {
            buffer.findings.push(finding);
        }
    }

    /// Read and reset the counters and findings of the current window.
    pub fn drain_window(&self) -> WindowSnapshot {
        let config = self.config();
        let summaries = lock(&self.table).drain(&config.policy_hash);
        let mut buffer = lock(&self.findings);
        let findings = std::mem::take(&mut buffer.findings);
        let dropped_findings = std::mem::take(&mut buffer.dropped);
        buffer.seen.clear();
        WindowSnapshot {
            summaries,
            findings,
            dropped_findings,
            policy_hash: config.policy_hash.to_string(),
        }
    }
}

fn finding_base(key: &UsageKey) -> UsageFinding {
    UsageFinding {
        finding_type: "",
        severity: FindingSeverity::Low,
        policy_key: key.policy_key.clone(),
        endpoint_id: key.endpoint_id.clone(),
        host: key.host.clone(),
        port: key.port,
        binary_sha256: key.binary_sha256.clone(),
        budget: String::new(),
        counter: String::new(),
        action: "",
        detail: String::new(),
    }
}

/// Take tokens from deny budgets in name order. If a budget cannot admit,
/// return the tokens taken from earlier budgets and report the denial.
fn take_deny_tokens(
    budgets: &[Arc<BudgetEntry>],
    count_counter: Counter,
    now: Instant,
) -> Option<BudgetDenial> {
    let mut taken = Vec::new();
    for budget in budgets.iter().filter(|budget| budget.spec.deny) {
        let denied_counter = budget.bucket(count_counter).and_then(|bucket| {
            if bucket.try_take_one(now) {
                taken.push(bucket.clone());
                None
            } else {
                Some((count_counter, bucket.clone()))
            }
        });
        let denied_counter = denied_counter.or_else(|| {
            [Counter::BytesOut, Counter::BytesIn]
                .into_iter()
                .find_map(|counter| {
                    let bucket = budget.bucket(counter)?;
                    (!bucket.has_balance(now)).then(|| (counter, bucket.clone()))
                })
        });
        if let Some((counter, bucket)) = denied_counter {
            // `taken` includes this budget's count token when a byte
            // counter denied the admission.
            for token in taken {
                token.return_one();
            }
            return Some(BudgetDenial {
                budget: budget.spec.name.clone(),
                counter,
                retry_after: bucket.retry_after(now),
            });
        }
    }
    None
}

/// Charge an alert budget. Returns the counter that has no balance left.
fn alert_budget_exhausted(
    budget: &BudgetEntry,
    count_counter: Counter,
    now: Instant,
) -> Option<Counter> {
    let mut exhausted = budget
        .bucket(count_counter)
        .filter(|bucket| !bucket.force_take_one(now))
        .map(|_| count_counter);
    for counter in [Counter::BytesOut, Counter::BytesIn] {
        if let Some(bucket) = budget.bucket(counter)
            && !bucket.has_balance(now)
        {
            exhausted.get_or_insert(counter);
        }
    }
    exhausted
}

fn emit_finding(finding: &UsageFinding) {
    let severity = match finding.severity {
        FindingSeverity::Low => SeverityId::Low,
        FindingSeverity::Medium => SeverityId::Medium,
    };
    let (action, disposition) = if finding.action == "deny" {
        (ActionId::Denied, DispositionId::Blocked)
    } else {
        (ActionId::Allowed, DispositionId::Allowed)
    };
    let port = finding.port.to_string();
    let event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Open)
        .action(action)
        .disposition(disposition)
        .severity(severity)
        .is_alert(finding.severity == FindingSeverity::Medium)
        .finding_info(FindingInfo::new(
            finding.finding_type,
            &format!("{}:{} {}", finding.host, finding.port, finding.detail),
        ))
        .evidence_pairs(&[
            ("policy", finding.policy_key.as_str()),
            ("endpoint_id", finding.endpoint_id.as_str()),
            ("host", finding.host.as_str()),
            ("port", port.as_str()),
            ("binary_sha256", finding.binary_sha256.as_str()),
            ("budget", finding.budget.as_str()),
            ("counter", finding.counter.as_str()),
            ("action", finding.action),
        ])
        .message(format!(
            "{} {}:{} {}",
            finding.finding_type, finding.host, finding.port, finding.detail
        ))
        .build();
    ocsf_emit!(event);
}

/// HTTP 429 response for a budget denial. The body uses the structured
/// form of policy denials. It gives no policy-advisor guidance, because a
/// policy change is not the correct response to a spent budget.
pub fn budget_exceeded_response(denial: &BudgetDenial) -> Vec<u8> {
    let retry_after = denial.retry_after.as_secs().max(1);
    let body = serde_json::json!({
        "error": "budget_exceeded",
        "budget": denial.budget,
        "counter": denial.counter.name(),
        "retry_after_seconds": retry_after,
        "detail": format!(
            "egress budget '{}' has no {} left; retry after {retry_after}s",
            denial.budget,
            denial.counter.name()
        ),
    })
    .to_string();
    format!(
        "HTTP/1.1 429 Too Many Requests\r\n\
         Content-Type: application/json\r\n\
         Retry-After: {retry_after}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len(),
    )
    .into_bytes()
}

/// Per-connection handle that relays use to admit L7 requests.
#[derive(Clone)]
pub struct ConnectionUsage {
    state: Arc<UsageState>,
    cell: Arc<AttributionCell>,
    meta: Arc<ConnectionMeta>,
}

/// Connection facts captured at admission.
#[derive(Debug)]
pub struct ConnectionMeta {
    pub host: String,
    pub port: u16,
    pub binary_path: String,
    pub binary_sha256: String,
    pub reported_policy: String,
    pub l4_policies: Vec<String>,
    pub endpoint_id: String,
    pub started: std::time::Instant,
}

impl std::fmt::Debug for ConnectionUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionUsage")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

impl ConnectionUsage {
    /// Admit a connection. On success, the returned handle charges the
    /// connection's bytes until an L7 request switches the attribution.
    pub fn admit_connection(
        state: &Arc<UsageState>,
        meta: ConnectionMeta,
        glob_host: bool,
    ) -> Result<Self, BudgetDenial> {
        let outcome = state.admit(&Admission {
            kind: AdmissionKind::Connection,
            reported_policy: &meta.reported_policy,
            authorizing_policies: &meta.l4_policies,
            endpoint_id: &meta.endpoint_id,
            host: &meta.host,
            port: meta.port,
            binary_path: &meta.binary_path,
            binary_sha256: &meta.binary_sha256,
            glob_host,
            rule_ids: &[],
        });
        match outcome {
            AdmissionOutcome::Admitted(attribution) => Ok(Self {
                state: state.clone(),
                cell: AttributionCell::new(attribution),
                meta: Arc::new(meta),
            }),
            AdmissionOutcome::Denied(denial) => Err(denial),
        }
    }

    pub fn cell(&self) -> Arc<AttributionCell> {
        self.cell.clone()
    }

    pub fn meta(&self) -> &ConnectionMeta {
        &self.meta
    }

    /// Admit an L7 request on this connection. Authorizing policies default
    /// to the L4 match when the request has no L7 authorizer, for example
    /// when audit mode forwards a request that no rule allows.
    pub fn admit_request(
        &self,
        authorizing_policies: &[String],
        endpoint_id: &str,
        rule_ids: &[String],
    ) -> Result<(), BudgetDenial> {
        let authorizing = if authorizing_policies.is_empty() {
            &self.meta.l4_policies[..]
        } else {
            authorizing_policies
        };
        let reported = authorizing
            .iter()
            .min()
            .map_or(self.meta.reported_policy.as_str(), String::as_str);
        let endpoint_id = if endpoint_id.is_empty() {
            &self.meta.endpoint_id
        } else {
            endpoint_id
        };
        match self.state.admit(&Admission {
            kind: AdmissionKind::Request,
            reported_policy: reported,
            authorizing_policies: authorizing,
            endpoint_id,
            host: &self.meta.host,
            port: self.meta.port,
            binary_path: &self.meta.binary_path,
            binary_sha256: &self.meta.binary_sha256,
            glob_host: false,
            rule_ids,
        }) {
            AdmissionOutcome::Admitted(attribution) => {
                self.cell.switch_to_request(attribution);
                Ok(())
            }
            AdmissionOutcome::Denied(denial) => Err(denial),
        }
    }

    /// OCSF close event with the connection totals and duration.
    pub fn close_event(&self) -> openshell_ocsf::OcsfEvent {
        let (bytes_out, bytes_in) = self.cell.totals();
        let duration_ms =
            i64::try_from(self.meta.started.elapsed().as_millis()).unwrap_or(i64::MAX);
        NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Close)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .dst_endpoint(Endpoint::from_domain(&self.meta.host, self.meta.port))
            .firewall_rule(&self.meta.reported_policy, "opa")
            .cumulative_traffic(NetworkTraffic::new(bytes_out, bytes_in), duration_ms)
            .message(format!("CLOSE {}:{}", self.meta.host, self.meta.port))
            .build()
    }
}

/// Emits the connection close event when the connection handler returns,
/// including on early returns and errors.
pub struct CloseEventGuard(pub Option<ConnectionUsage>);

impl Drop for CloseEventGuard {
    fn drop(&mut self) {
        if let Some(usage) = self.0.take() {
            ocsf_emit!(usage.close_event());
        }
    }
}

#[cfg(test)]
mod tests;
