// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell workspace usage`: egress usage of all sandboxes in a workspace.

use std::io::Write;

use miette::{IntoDiagnostic, Result};
use openshell_core::proto::{GetFleetEgressUsageRequest, GetFleetEgressUsageResponse};
use serde_json::json;

use super::usage::{human_bytes, severity};
use crate::tls::{TlsOptions, grpc_client};

const TABLE_ROWS: usize = 30;

fn to_json(response: &GetFleetEgressUsageResponse) -> serde_json::Value {
    let destinations: Vec<_> = response
        .destinations
        .iter()
        .map(|destination| {
            json!({
                "cohort": destination.cohort,
                "host": destination.host,
                "port": destination.port,
                "max_sandboxes": destination.max_sandboxes,
                "max_writer_sandboxes": destination.max_writer_sandboxes,
                "requests": destination.requests,
                "write_requests": destination.write_requests,
                "bytes_out": destination.bytes_out,
                "bytes_in": destination.bytes_in,
                "errors": destination.errors,
                "example_sandboxes": destination.example_sandboxes,
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
                "host": finding.host,
                "port": finding.port,
                "counter": finding.counter,
                "detail": finding.detail,
                "observed_time": finding.observed_time.as_ref().map(ToString::to_string),
            })
        })
        .collect();
    json!({ "destinations": destinations, "findings": findings })
}

/// Cohort IDs of base policies are long hashes; keep a short prefix.
fn short_cohort(cohort: &str) -> String {
    cohort.strip_prefix("policy:").map_or_else(
        || cohort.to_string(),
        |hash| format!("policy:{}", &hash[..hash.len().min(12)]),
    )
}

fn render_table<W: Write>(response: &GetFleetEgressUsageResponse, out: &mut W) -> Result<()> {
    if response.destinations.is_empty() {
        writeln!(out, "No fleet egress usage in the selected minutes.").into_diagnostic()?;
    } else {
        writeln!(
            out,
            "{:<20} {:<32} {:>9} {:>8} {:>8} {:>7} {:>10} {:>10} {:>6}",
            "COHORT", "HOST", "SANDBOXES", "WRITERS", "REQS", "WRITES", "OUT", "IN", "ERRORS"
        )
        .into_diagnostic()?;
        for destination in response.destinations.iter().take(TABLE_ROWS) {
            writeln!(
                out,
                "{:<20} {:<32} {:>9} {:>8} {:>8} {:>7} {:>10} {:>10} {:>6}",
                short_cohort(&destination.cohort),
                format!("{}:{}", destination.host, destination.port),
                destination.max_sandboxes,
                destination.max_writer_sandboxes,
                destination.requests,
                destination.write_requests,
                human_bytes(destination.bytes_out),
                human_bytes(destination.bytes_in),
                destination.errors,
            )
            .into_diagnostic()?;
        }
        writeln!(
            out,
            "SANDBOXES and WRITERS are the largest counts in one minute."
        )
        .into_diagnostic()?;
    }
    if !response.findings.is_empty() {
        writeln!(out, "\nFindings").into_diagnostic()?;
        for finding in response.findings.iter().take(20) {
            writeln!(
                out,
                "  {:<6} {:<20} {}",
                severity(finding),
                finding.finding_type,
                finding.detail
            )
            .into_diagnostic()?;
        }
    }
    Ok(())
}

/// Print fleet egress usage and fleet findings of one workspace.
pub async fn workspace_usage(
    server: &str,
    workspace: &str,
    minutes: u32,
    output: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_fleet_egress_usage(GetFleetEgressUsageRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                workspace.to_string(),
            )),
            minutes,
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
    use openshell_core::proto::{
        EgressFindingSeverity, EgressUsageFinding, FleetEgressDestination,
    };

    fn response() -> GetFleetEgressUsageResponse {
        GetFleetEgressUsageResponse {
            destinations: vec![FleetEgressDestination {
                cohort: "policy:0123456789abcdef0123".into(),
                host: "proxy.internal".into(),
                port: 443,
                max_sandboxes: 16,
                max_writer_sandboxes: 12,
                requests: 64,
                write_requests: 20,
                bytes_in: 2048,
                example_sandboxes: vec!["sb-01".into()],
                ..Default::default()
            }],
            findings: vec![EgressUsageFinding {
                finding_type: "egress.fleet_fan_in".into(),
                severity: EgressFindingSeverity::Medium as i32,
                host: "proxy.internal".into(),
                port: 443,
                counter: "writer_sandboxes".into(),
                detail: "12 sandboxes wrote to proxy.internal:443 in one minute".into(),
                ..Default::default()
            }],
        }
    }

    #[test]
    fn table_shows_destinations_and_findings() {
        let mut out = Vec::new();
        render_table(&response(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("policy:0123456789ab "), "{text}");
        assert!(text.contains("proxy.internal:443"), "{text}");
        assert!(text.contains("MEDIUM egress.fleet_fan_in"), "{text}");
    }

    #[test]
    fn json_keeps_the_full_cohort_and_examples() {
        let value = to_json(&response());
        assert_eq!(
            value["destinations"][0]["cohort"],
            "policy:0123456789abcdef0123"
        );
        assert_eq!(value["destinations"][0]["max_writer_sandboxes"], 12);
        assert_eq!(value["destinations"][0]["example_sandboxes"][0], "sb-01");
        assert_eq!(value["findings"][0]["counter"], "writer_sandboxes");
    }
}
