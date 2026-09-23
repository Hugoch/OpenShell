// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Report egress usage windows to the gateway.
//!
//! Every window, the reporter reads and resets the usage counters and puts
//! one report into a bounded outbox. Reports leave in `window_sequence`
//! order with one report in flight, so the gateway can add each report
//! exactly once by keeping the highest accepted sequence per supervisor
//! instance. Empty windows are reported too: drift counts them as zero.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use openshell_core::egress_usage::{DEFAULT_WINDOW, MAX_OUTBOX_REPORTS};
use openshell_core::grpc_client::CachedOpenShellClient;
use openshell_core::proto::{
    EgressFindingSeverity, EgressResponseCounts, EgressRuleHit, EgressUsageFinding,
    EgressUsageSummary, ReportEgressUsageRequest,
};
use openshell_supervisor_network::usage::{
    FindingSeverity, UsageFinding, UsageState, UsageSummary, WindowSnapshot,
};
use tokio::sync::watch;
use tracing::{debug, warn};

const REPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// Window length from `OPENSHELL_USAGE_WINDOW_SECS`, or the default.
pub fn window_from_env(value: Option<&str>) -> Duration {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map_or(DEFAULT_WINDOW, Duration::from_secs)
}

pub struct UsageReporter {
    pub endpoint: String,
    pub sandbox_name: String,
    pub workspace: watch::Receiver<String>,
    pub supervisor_instance_id: String,
    pub window: Duration,
    pub usage: Arc<UsageState>,
}

impl UsageReporter {
    pub async fn run(self) {
        let mut ticker = tokio::time::interval(self.window);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        let mut outbox: VecDeque<ReportEgressUsageRequest> = VecDeque::new();
        let mut window_sequence = 0_u64;
        let mut dropped_windows = 0_u64;
        let mut window_start = SystemTime::now();
        let mut client: Option<CachedOpenShellClient> = None;
        loop {
            ticker.tick().await;
            let window_end = SystemTime::now();
            window_sequence += 1;
            let snapshot = self.usage.drain_window();
            if outbox.len() >= MAX_OUTBOX_REPORTS {
                outbox.pop_front();
                dropped_windows += 1;
            }
            outbox.push_back(build_report(
                &self.sandbox_name,
                &self.supervisor_instance_id,
                window_sequence,
                window_start,
                window_end,
                snapshot,
                std::mem::take(&mut dropped_windows),
            ));
            window_start = window_end;
            self.flush(&mut outbox, &mut client).await;
        }
    }

    /// Send queued reports in order until one fails. A failed report stays
    /// at the front and keeps its identity for the next attempt.
    async fn flush(
        &self,
        outbox: &mut VecDeque<ReportEgressUsageRequest>,
        client: &mut Option<CachedOpenShellClient>,
    ) {
        let workspace = self.workspace.borrow().clone();
        if workspace.is_empty() {
            return;
        }
        while let Some(report) = outbox.front() {
            if client.is_none() {
                match CachedOpenShellClient::connect(&self.endpoint).await {
                    Ok(connected) => {
                        connected.set_workspace(workspace.clone());
                        *client = Some(connected);
                    }
                    Err(error) => {
                        debug!(error = %error, "egress usage reporter cannot connect to gateway");
                        return;
                    }
                }
            }
            let Some(connected) = client.as_ref() else {
                return;
            };
            match tokio::time::timeout(
                REPORT_TIMEOUT,
                connected.report_egress_usage(report.clone()),
            )
            .await
            {
                Ok(Ok(())) => {
                    outbox.pop_front();
                }
                Ok(Err(error)) => {
                    warn!(error = %error, "failed to report egress usage; retrying next window");
                    *client = None;
                    return;
                }
                Err(_) => {
                    warn!("egress usage report timed out; retrying next window");
                    *client = None;
                    return;
                }
            }
        }
    }
}

fn timestamp(time: SystemTime) -> prost_types::Timestamp {
    prost_types::Timestamp::from(time)
}

fn build_report(
    sandbox_name: &str,
    supervisor_instance_id: &str,
    window_sequence: u64,
    window_start: SystemTime,
    window_end: SystemTime,
    snapshot: WindowSnapshot,
    dropped_windows: u64,
) -> ReportEgressUsageRequest {
    let duration = window_end.duration_since(window_start).unwrap_or_default();
    ReportEgressUsageRequest {
        workspace_scope: None,
        name: sandbox_name.to_string(),
        supervisor_instance_id: supervisor_instance_id.to_string(),
        window_sequence,
        window_start: Some(timestamp(window_start)),
        window_duration: prost_types::Duration::try_from(duration).ok(),
        summaries: snapshot
            .summaries
            .into_iter()
            .map(summary_to_proto)
            .collect(),
        findings: snapshot
            .findings
            .into_iter()
            .map(|finding| finding_to_proto(finding, window_end))
            .collect(),
        dropped_windows,
        dropped_findings: snapshot.dropped_findings,
    }
}

fn summary_to_proto(summary: UsageSummary) -> EgressUsageSummary {
    EgressUsageSummary {
        policy_key: summary.key.policy_key,
        endpoint_id: summary.key.endpoint_id,
        host: summary.key.host,
        port: u32::from(summary.key.port),
        binary_path: summary.key.binary_path,
        binary_sha256: summary.key.binary_sha256,
        // The policy hash identifies the revision; the supervisor does not know its number.
        config_revision: 0,
        policy_hash: summary.policy_hash,
        connections: summary.connections,
        requests: summary.requests,
        bytes_out: summary.bytes_out,
        bytes_in: summary.bytes_in,
        responses: Some(EgressResponseCounts {
            status_2xx: summary.responses.status_2xx,
            status_3xx: summary.responses.status_3xx,
            status_4xx: summary.responses.status_4xx,
            status_5xx: summary.responses.status_5xx,
            status_429: summary.responses.status_429,
        }),
        rule_hits: summary
            .rule_hits
            .into_iter()
            .map(|(rule_id, count)| EgressRuleHit { rule_id, count })
            .collect(),
        budget_denials: summary.budget_denials,
        overflow: summary.overflow,
    }
}

fn finding_to_proto(finding: UsageFinding, observed: SystemTime) -> EgressUsageFinding {
    let severity = match finding.severity {
        FindingSeverity::Low => EgressFindingSeverity::Low,
        FindingSeverity::Medium => EgressFindingSeverity::Medium,
    };
    EgressUsageFinding {
        finding_type: finding.finding_type.to_string(),
        severity: severity as i32,
        policy_key: finding.policy_key,
        endpoint_id: finding.endpoint_id,
        host: finding.host,
        port: u32::from(finding.port),
        binary_sha256: finding.binary_sha256,
        budget: finding.budget,
        counter: finding.counter,
        action: finding.action.to_string(),
        detail: finding.detail,
        observed_time: Some(timestamp(observed)),
    }
}

/// Keep windows moving for a supervisor without a gateway connection, for
/// example the standalone network proxy. Budgets, findings, and close
/// events still reach the local OCSF log.
pub async fn run_local_windows(usage: Arc<UsageState>, window: Duration) {
    let mut ticker = tokio::time::interval(window);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let snapshot = usage.drain_window();
        debug!(
            summaries = snapshot.summaries.len(),
            findings = snapshot.findings.len(),
            "egress usage window closed without a gateway"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_supervisor_network::usage::{ConnectionMeta, ConnectionUsage, UsageConfig};

    #[test]
    fn window_env_falls_back_to_default() {
        assert_eq!(window_from_env(None), DEFAULT_WINDOW);
        assert_eq!(window_from_env(Some("0")), DEFAULT_WINDOW);
        assert_eq!(window_from_env(Some("bad")), DEFAULT_WINDOW);
        assert_eq!(window_from_env(Some("5")), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn report_carries_summaries_findings_and_identity() {
        let usage = UsageState::new(UsageConfig::default());
        let connection = ConnectionUsage::admit_connection(
            &usage,
            ConnectionMeta {
                host: "api.example.com".into(),
                port: 443,
                binary_path: "/usr/bin/curl".into(),
                binary_sha256: "sha".into(),
                reported_policy: "api".into(),
                l4_policies: vec!["api".into()],
                endpoint_id: "endpoint:v1:api".into(),
                started: std::time::Instant::now(),
            },
            false,
        )
        .unwrap();
        connection
            .admit_request(&[], "", &["rule:v1:a".into()])
            .unwrap();
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let end = start + Duration::from_mins(1);
        let report = build_report("sb", "instance-1", 7, start, end, usage.drain_window(), 2);
        assert_eq!(report.window_sequence, 7);
        assert_eq!(report.supervisor_instance_id, "instance-1");
        assert_eq!(report.dropped_windows, 2);
        assert_eq!(report.window_duration.unwrap().seconds, 60);
        let summary = report
            .summaries
            .iter()
            .find(|summary| summary.requests == 1)
            .unwrap();
        assert_eq!(summary.port, 443);
        assert_eq!(summary.rule_hits[0].rule_id, "rule:v1:a");
    }
}
