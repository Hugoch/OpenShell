// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

fn budget(name: &str, deny: bool) -> BudgetSpec {
    BudgetSpec {
        name: name.to_string(),
        policies: vec![],
        hosts: vec![],
        deny,
        requests_per_minute: None,
        connections_per_minute: None,
        bytes_out_per_hour: None,
        bytes_in_per_hour: None,
    }
}

fn state(budgets: Vec<BudgetSpec>, learning_period: Duration) -> Arc<UsageState> {
    UsageState::new(UsageConfig {
        policy_hash: Arc::from("hash-1"),
        budgets,
        learning_period,
        ..UsageConfig::default()
    })
}

fn meta(host: &str) -> ConnectionMeta {
    ConnectionMeta {
        host: host.to_string(),
        port: 443,
        binary_path: "/usr/bin/curl".to_string(),
        binary_sha256: "sha-curl".to_string(),
        reported_policy: "api".to_string(),
        l4_policies: vec!["api".to_string()],
        endpoint_id: "endpoint:v1:api".to_string(),
        started: std::time::Instant::now(),
    }
}

#[tokio::test(start_paused = true)]
async fn deny_budget_denies_requests_after_its_capacity() {
    let mut hub = budget("hub", true);
    hub.requests_per_minute = Some(5);
    let state = state(vec![hub], Duration::ZERO);
    let connection = ConnectionUsage::admit_connection(&state, meta("api.example.com"), false)
        .expect("no connection budget");

    let results: Vec<_> = (0..10)
        .map(|_| connection.admit_request(&[], "", &[]))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 5);
    let denial = results[5].as_ref().unwrap_err();
    assert_eq!(denial.budget, "hub");
    assert_eq!(denial.counter, Counter::Requests);
    assert!(denial.retry_after > Duration::ZERO && denial.retry_after <= Duration::from_secs(12));

    let snapshot = state.drain_window();
    let summary = &snapshot.summaries[0];
    assert_eq!(summary.requests, 5);
    assert_eq!(summary.budget_denials, 5);
    let exceeded: Vec<_> = snapshot
        .findings
        .iter()
        .filter(|finding| finding.finding_type == "egress.budget_exceeded")
        .collect();
    assert_eq!(exceeded.len(), 1, "one finding per key and type per window");
    assert_eq!(exceeded[0].action, "deny");
}

#[tokio::test(start_paused = true)]
async fn alert_budget_never_denies_and_reports_once() {
    let mut watch = budget("watch", false);
    watch.requests_per_minute = Some(2);
    let state = state(vec![watch], Duration::ZERO);
    let connection = ConnectionUsage::admit_connection(&state, meta("api.example.com"), false)
        .expect("admitted");
    for _ in 0..6 {
        connection
            .admit_request(&[], "", &[])
            .expect("alert budgets never deny");
    }
    let snapshot = state.drain_window();
    assert_eq!(snapshot.summaries[0].requests, 6);
    assert_eq!(snapshot.summaries[0].budget_denials, 0);
    let alerts: Vec<_> = snapshot
        .findings
        .iter()
        .filter(|finding| finding.finding_type == "egress.budget_exceeded")
        .collect();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].action, "alert");
}

#[tokio::test(start_paused = true)]
async fn later_deny_returns_tokens_taken_by_earlier_budgets() {
    let mut first = budget("a-first", true);
    first.requests_per_minute = Some(10);
    let mut second = budget("b-second", true);
    second.requests_per_minute = Some(1);
    let state = state(vec![first, second], Duration::ZERO);
    let connection = ConnectionUsage::admit_connection(&state, meta("api.example.com"), false)
        .expect("admitted");
    connection
        .admit_request(&[], "", &[])
        .expect("both budgets have tokens");
    for _ in 0..5 {
        let denial = connection.admit_request(&[], "", &[]).unwrap_err();
        assert_eq!(denial.budget, "b-second");
    }
    let first_bucket = state.ledger.selected(&[], "api.example.com")[0]
        .bucket(Counter::Requests)
        .unwrap()
        .clone();
    assert!((first_bucket.balance(Instant::now()) - 9.0).abs() < 1e-9);
}

#[tokio::test(start_paused = true)]
async fn budget_selects_on_any_authorizing_policy() {
    let mut scoped = budget("scoped", true);
    scoped.policies = vec!["z_policy".to_string()];
    scoped.requests_per_minute = Some(1);
    let state = state(vec![scoped], Duration::ZERO);
    let connection = ConnectionUsage::admit_connection(&state, meta("api.example.com"), false)
        .expect("admitted");
    let authorizing = vec!["a_policy".to_string(), "z_policy".to_string()];
    connection
        .admit_request(&authorizing, "", &[])
        .expect("first token");
    let denial = connection.admit_request(&authorizing, "", &[]).unwrap_err();
    assert_eq!(denial.budget, "scoped");
    // The reported key is the smallest authorizing policy.
    let snapshot = state.drain_window();
    assert!(
        snapshot
            .summaries
            .iter()
            .any(|summary| summary.key.policy_key == "a_policy" && summary.requests == 1)
    );
}

#[tokio::test(start_paused = true)]
async fn byte_debt_denies_the_next_request() {
    let mut bytes = budget("bytes", true);
    bytes.bytes_in_per_hour = Some(100);
    let state = state(vec![bytes], Duration::ZERO);
    let connection = ConnectionUsage::admit_connection(&state, meta("api.example.com"), false)
        .expect("admitted");
    connection
        .admit_request(&[], "", &[])
        .expect("balance available");

    let (mut remote, local) = tokio::io::duplex(4096);
    let mut upstream = CountingStream::new(local, connection.cell());
    remote.write_all(&[0u8; 500]).await.unwrap();
    let mut buffer = vec![0u8; 500];
    upstream.read_exact(&mut buffer).await.unwrap();

    let denial = connection.admit_request(&[], "", &[]).unwrap_err();
    assert_eq!(denial.counter, Counter::BytesIn);
    assert_eq!(connection.cell().totals(), (0, 500));
}

#[tokio::test(start_paused = true)]
async fn counting_stream_charges_each_request_exactly_once() {
    let state = state(vec![], Duration::ZERO);
    let connection = ConnectionUsage::admit_connection(&state, meta("api.example.com"), false)
        .expect("admitted");
    let (mut remote, local) = tokio::io::duplex(4096);
    let mut upstream = CountingStream::new(local, connection.cell());

    connection
        .admit_request(&["first".to_string()], "endpoint:v1:first", &[])
        .unwrap();
    upstream
        .write_all(b"GET /a HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    remote.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
    let mut response = [0u8; 19];
    upstream.read_exact(&mut response).await.unwrap();

    connection
        .admit_request(&["second".to_string()], "endpoint:v1:second", &[])
        .unwrap();
    upstream
        .write_all(b"POST /b HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    remote.write_all(b"HTTP/1.1 503 No\r\n\r\n").await.unwrap();
    let mut response = [0u8; 19];
    upstream.read_exact(&mut response).await.unwrap();

    let snapshot = state.drain_window();
    let by_endpoint = |endpoint: &str| {
        snapshot
            .summaries
            .iter()
            .find(|summary| summary.key.endpoint_id == endpoint)
            .unwrap()
            .clone()
    };
    let first = by_endpoint("endpoint:v1:first");
    let second = by_endpoint("endpoint:v1:second");
    assert_eq!((first.bytes_out, first.bytes_in), (19, 19));
    assert_eq!((second.bytes_out, second.bytes_in), (20, 19));
    assert_eq!(first.responses.status_2xx, 1);
    assert_eq!(second.responses.status_5xx, 1);
    assert_eq!(connection.cell().totals(), (39, 38));
}

#[tokio::test(start_paused = true)]
async fn charges_are_kept_when_a_relay_stops_early() {
    let state = state(vec![], Duration::ZERO);
    let connection = ConnectionUsage::admit_connection(&state, meta("api.example.com"), false)
        .expect("admitted");
    let (mut remote, local) = tokio::io::duplex(4096);
    let mut upstream = CountingStream::new(local, connection.cell());
    remote.write_all(&[1u8; 64]).await.unwrap();
    let mut partial = [0u8; 32];
    upstream.read_exact(&mut partial).await.unwrap();
    // The relay task is cancelled here: dropping the stream mid-transfer.
    drop(upstream);
    let snapshot = state.drain_window();
    assert_eq!(snapshot.summaries[0].bytes_in, 32);
}

#[tokio::test(start_paused = true)]
async fn novelty_reports_new_host_after_learning_period() {
    let state = state(vec![], Duration::from_mins(1));
    ConnectionUsage::admit_connection(&state, meta("a.example.com"), true).unwrap();
    tokio::time::advance(Duration::from_secs(61)).await;
    ConnectionUsage::admit_connection(&state, meta("a.example.com"), true).unwrap();
    ConnectionUsage::admit_connection(&state, meta("b.example.com"), true).unwrap();
    let findings: Vec<_> = state
        .drain_window()
        .findings
        .into_iter()
        .filter(|finding| finding.finding_type == "egress.new_host")
        .collect();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].host, "b.example.com");
}

#[tokio::test(start_paused = true)]
async fn findings_per_window_are_capped() {
    let state = state(vec![], Duration::ZERO);
    for index in 0..(MAX_FINDINGS_PER_REPORT + 10) {
        ConnectionUsage::admit_connection(&state, meta(&format!("h{index}.example.com")), true)
            .unwrap();
    }
    let snapshot = state.drain_window();
    assert_eq!(snapshot.findings.len(), MAX_FINDINGS_PER_REPORT);
    assert!(snapshot.dropped_findings > 0);
}

#[tokio::test(start_paused = true)]
async fn reconfigure_keeps_balance_of_unchanged_budget() {
    let mut hub = budget("hub", true);
    hub.requests_per_minute = Some(2);
    let state = state(vec![hub.clone()], Duration::ZERO);
    let connection =
        ConnectionUsage::admit_connection(&state, meta("api.example.com"), false).unwrap();
    connection.admit_request(&[], "", &[]).unwrap();
    connection.admit_request(&[], "", &[]).unwrap();
    state.reconfigure(UsageConfig {
        policy_hash: Arc::from("hash-2"),
        budgets: vec![hub],
        learning_period: Duration::ZERO,
        ..UsageConfig::default()
    });
    assert!(connection.admit_request(&[], "", &[]).is_err());
}
