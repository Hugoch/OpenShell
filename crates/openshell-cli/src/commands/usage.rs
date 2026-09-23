// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell sandbox usage`: recent egress usage of one sandbox.

use std::collections::BTreeMap;
use std::io::Write;

use miette::{IntoDiagnostic, Result};
use openshell_core::proto::{
    EgressFindingSeverity, EgressUsageFinding, GetEgressUsageRequest, GetEgressUsageResponse,
};
use serde_json::json;

use crate::tls::{TlsOptions, grpc_client};

/// Usage of one key summed over the recent windows.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct UsageRow {
    policy: String,
    host: String,
    port: u32,
    binary: String,
    connections: u64,
    requests: u64,
    bytes_out: u64,
    bytes_in: u64,
    status_2xx: u64,
    status_4xx: u64,
    status_5xx: u64,
    status_429: u64,
    budget_denials: u64,
}

fn aggregate(response: &GetEgressUsageResponse) -> Vec<UsageRow> {
    let mut rows: BTreeMap<(String, String, u32, String), UsageRow> = BTreeMap::new();
    for window in &response.windows {
        for summary in &window.summaries {
            let key = (
                summary.policy_key.clone(),
                summary.host.clone(),
                summary.port,
                summary.binary_path.clone(),
            );
            let row = rows.entry(key).or_insert_with(|| UsageRow {
                policy: summary.policy_key.clone(),
                host: summary.host.clone(),
                port: summary.port,
                binary: summary.binary_path.clone(),
                ..UsageRow::default()
            });
            let responses = summary.responses.unwrap_or_default();
            row.connections += summary.connections;
            row.requests += summary.requests;
            row.bytes_out += summary.bytes_out;
            row.bytes_in += summary.bytes_in;
            row.status_2xx += responses.status_2xx;
            row.status_4xx += responses.status_4xx;
            row.status_5xx += responses.status_5xx;
            row.status_429 += responses.status_429;
            row.budget_denials += summary.budget_denials;
        }
    }
    rows.into_values().collect()
}

#[allow(clippy::cast_precision_loss)]
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn severity(finding: &EgressUsageFinding) -> &'static str {
    match EgressFindingSeverity::try_from(finding.severity) {
        Ok(EgressFindingSeverity::Medium) => "MEDIUM",
        Ok(EgressFindingSeverity::Low) => "LOW",
        _ => "-",
    }
}

fn to_json(response: &GetEgressUsageResponse) -> serde_json::Value {
    let rows: Vec<_> = aggregate(response)
        .into_iter()
        .map(|row| {
            json!({
                "policy": row.policy,
                "host": row.host,
                "port": row.port,
                "binary": row.binary,
                "connections": row.connections,
                "requests": row.requests,
                "bytes_out": row.bytes_out,
                "bytes_in": row.bytes_in,
                "responses": {
                    "status_2xx": row.status_2xx,
                    "status_4xx": row.status_4xx,
                    "status_5xx": row.status_5xx,
                    "status_429": row.status_429,
                },
                "budget_denials": row.budget_denials,
            })
        })
        .collect();
    let findings: Vec<_> = response
        .findings
        .iter()
        .map(|finding| {
            json!({
                "type": finding.finding_type,
                "severity": severity(finding),
                "policy": finding.policy_key,
                "endpoint_id": finding.endpoint_id,
                "host": finding.host,
                "port": finding.port,
                "budget": finding.budget,
                "counter": finding.counter,
                "action": finding.action,
                "detail": finding.detail,
                "observed_time": finding.observed_time.as_ref().map(ToString::to_string),
            })
        })
        .collect();
    json!({
        "windows": response.windows.len(),
        "usage": rows,
        "findings": findings,
    })
}

fn render_table<W: Write>(response: &GetEgressUsageResponse, out: &mut W) -> Result<()> {
    let rows = aggregate(response);
    writeln!(
        out,
        "Egress usage over the last {} windows",
        response.windows.len()
    )
    .into_diagnostic()?;
    writeln!(
        out,
        "{:<16} {:<32} {:<18} {:>6} {:>7} {:>10} {:>10} {:>5} {:>5} {:>5} {:>5} {:>7}",
        "POLICY",
        "HOST",
        "BINARY",
        "CONNS",
        "REQS",
        "OUT",
        "IN",
        "2XX",
        "4XX",
        "5XX",
        "429",
        "DENIED"
    )
    .into_diagnostic()?;
    for row in &rows {
        let binary = row.binary.rsplit('/').next().unwrap_or("-");
        writeln!(
            out,
            "{:<16} {:<32} {:<18} {:>6} {:>7} {:>10} {:>10} {:>5} {:>5} {:>5} {:>5} {:>7}",
            row.policy,
            format!("{}:{}", row.host, row.port),
            if binary.is_empty() { "-" } else { binary },
            row.connections,
            row.requests,
            human_bytes(row.bytes_out),
            human_bytes(row.bytes_in),
            row.status_2xx,
            row.status_4xx,
            row.status_5xx,
            row.status_429,
            row.budget_denials,
        )
        .into_diagnostic()?;
    }
    if !response.findings.is_empty() {
        writeln!(out, "\nFindings").into_diagnostic()?;
        for finding in response.findings.iter().rev().take(20) {
            writeln!(
                out,
                "  {:<6} {:<24} {}:{} {}",
                severity(finding),
                finding.finding_type,
                finding.host,
                finding.port,
                finding.detail
            )
            .into_diagnostic()?;
        }
    }
    Ok(())
}

/// Print recent egress usage and findings of one sandbox.
pub async fn sandbox_usage(
    server: &str,
    name: &str,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_egress_usage(GetEgressUsageRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                workspace.to_string(),
            )),
            sandbox: name.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();
    if crate::output::print_output_single(output, &response, to_json)? {
        return Ok(());
    }
    render_table(&response, &mut std::io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{EgressResponseCounts, EgressUsageSummary, EgressUsageWindow};

    fn response() -> GetEgressUsageResponse {
        let summary = |requests, bytes_in| EgressUsageSummary {
            policy_key: "hub".into(),
            host: "huggingface.co".into(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            requests,
            bytes_in,
            responses: Some(EgressResponseCounts {
                status_2xx: requests,
                ..Default::default()
            }),
            ..Default::default()
        };
        GetEgressUsageResponse {
            windows: vec![
                EgressUsageWindow {
                    summaries: vec![summary(2, 100)],
                    ..Default::default()
                },
                EgressUsageWindow {
                    summaries: vec![summary(3, 2048)],
                    ..Default::default()
                },
            ],
            findings: vec![EgressUsageFinding {
                finding_type: "egress.budget_exceeded".into(),
                severity: EgressFindingSeverity::Medium as i32,
                host: "huggingface.co".into(),
                port: 443,
                detail: "budget 'hub' has no requests_per_minute left".into(),
                ..Default::default()
            }],
        }
    }

    #[test]
    fn aggregate_sums_windows_per_key() {
        let rows = aggregate(&response());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].requests, 5);
        assert_eq!(rows[0].bytes_in, 2148);
        assert_eq!(rows[0].status_2xx, 5);
    }

    #[test]
    fn table_shows_usage_and_findings() {
        let mut out = Vec::new();
        render_table(&response(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("huggingface.co:443"), "{text}");
        assert!(text.contains("2.1 KiB"), "{text}");
        assert!(text.contains("egress.budget_exceeded"), "{text}");
    }

    #[test]
    fn json_reports_rows_and_findings() {
        let value = to_json(&response());
        assert_eq!(value["windows"], 2);
        assert_eq!(value["usage"][0]["requests"], 5);
        assert_eq!(value["findings"][0]["severity"], "MEDIUM");
    }
}
