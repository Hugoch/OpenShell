// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hot-path benchmarks for egress usage accounting.
//!
//! Ignored by default. Run with:
//!
//! ```text
//! cargo test --release -p openshell-supervisor-network --lib usage::bench -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Each benchmark measures the same work with and without accounting and
//! prints the median of several rounds.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::l7::relay::{L7EvalContext, evaluate_l7_request, l7_usage_facts, relay_with_inspection};
use crate::opa::{NetworkInput, OpaEngine};

const ROUNDS: usize = 5;

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

fn overhead(base: Duration, with: Duration) -> f64 {
    (with.as_secs_f64() / base.as_secs_f64() - 1.0) * 100.0
}

fn meta() -> ConnectionMeta {
    ConnectionMeta {
        host: "api.example.test".into(),
        port: 8080,
        binary_path: "/usr/bin/curl".into(),
        binary_sha256: "sha".into(),
        reported_policy: "api".into(),
        l4_policies: vec!["api".into()],
        endpoint_id: "api#0".into(),
        started: Instant::now(),
    }
}

fn budget(
    name: &str,
    requests_per_minute: Option<u64>,
    bytes_in_per_hour: Option<u64>,
) -> BudgetSpec {
    BudgetSpec {
        name: name.into(),
        policies: vec![],
        hosts: vec![],
        deny: true,
        requests_per_minute,
        connections_per_minute: None,
        bytes_out_per_hour: None,
        bytes_in_per_hour,
    }
}

/// Copy `total` bytes from a remote writer through an optional counting
/// wrapper, like the raw relay reads an upstream.
async fn copy_through(total: usize, cell: Option<Arc<AttributionCell>>) -> Duration {
    let (mut remote, local) = tokio::io::duplex(256 * 1024);
    let writer = tokio::spawn(async move {
        let chunk = vec![0u8; 64 * 1024];
        let mut left = total;
        while left > 0 {
            let n = left.min(chunk.len());
            remote.write_all(&chunk[..n]).await.unwrap();
            left -= n;
        }
    });
    let mut buffer = vec![0u8; 64 * 1024];
    let start = Instant::now();
    let mut read = 0;
    if let Some(cell) = cell {
        let mut upstream = CountingStream::new(local, cell);
        while read < total {
            read += upstream.read(&mut buffer).await.unwrap();
        }
    } else {
        let mut upstream = local;
        while read < total {
            read += upstream.read(&mut buffer).await.unwrap();
        }
    }
    let elapsed = start.elapsed();
    writer.await.unwrap();
    elapsed
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark"]
async fn bench_raw_relay_throughput() {
    const TOTAL: usize = 1024 * 1024 * 1024;
    let state = UsageState::new(UsageConfig {
        budgets: vec![budget("bytes", None, Some(u64::MAX / 2))],
        ..UsageConfig::default()
    });
    let mut base = Vec::new();
    let mut with = Vec::new();
    for _ in 0..ROUNDS {
        base.push(copy_through(TOTAL, None).await);
        let connection = ConnectionUsage::admit_connection(&state, meta(), false).unwrap();
        with.push(copy_through(TOTAL, Some(connection.cell())).await);
    }
    let (base, with) = (median(base), median(with));
    #[allow(clippy::cast_precision_loss)]
    let gib = TOTAL as f64 / f64::from(1 << 30);
    println!(
        "raw relay 1 GiB: without {:.2} GiB/s, with accounting and a byte budget {:.2} GiB/s, overhead {:+.1}%",
        gib / base.as_secs_f64(),
        gib / with.as_secs_f64(),
        overhead(base, with)
    );
}

#[test]
#[ignore = "benchmark"]
fn bench_request_admission() {
    const REQUESTS: u32 = 200_000;
    for budgets in [0usize, 3] {
        let specs = (0..budgets)
            .map(|index| budget(&format!("b{index}"), Some(u64::MAX / 2), Some(u64::MAX / 2)))
            .collect();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let per_request = runtime.block_on(async {
            let state = UsageState::new(UsageConfig {
                budgets: specs,
                ..UsageConfig::default()
            });
            let connection = ConnectionUsage::admit_connection(&state, meta(), false).unwrap();
            let rule = vec!["rule:v1:a".to_string()];
            let mut samples = Vec::new();
            for _ in 0..ROUNDS {
                let start = Instant::now();
                for _ in 0..REQUESTS {
                    connection.admit_request(&[], "", &rule).unwrap();
                }
                samples.push(start.elapsed() / REQUESTS);
            }
            median(samples)
        });
        println!("request admission with {budgets} budgets: {per_request:?} per request");
    }
}

const POLICY: &str = r#"
version: 1
network_policies:
  api:
    name: api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: "/v1/**" }
          - allow: { method: POST, path: "/v1/items" }
    binaries:
      - { path: /usr/bin/curl }
network_budgets:
  requests:
    policies: [api]
    requests_per_minute: 1000000000
    bytes_in_per_hour: 1000000000000
    on_exceed: deny
"#;

fn engine_and_config() -> (
    OpaEngine,
    crate::l7::L7EndpointConfig,
    crate::opa::TunnelPolicyEngine,
) {
    let engine =
        OpaEngine::from_strings(include_str!("../../data/sandbox-policy.rego"), POLICY).unwrap();
    let input = NetworkInput {
        host: "api.example.test".into(),
        port: 8080,
        binary_path: PathBuf::from("/usr/bin/curl"),
        binary_sha256: "sha".into(),
        ancestors: vec![],
        cmdline_paths: vec![],
    };
    let (endpoint_config, generation) = engine
        .query_endpoint_config_with_generation(&input)
        .unwrap();
    let config = crate::l7::parse_l7_config(&endpoint_config.unwrap()).unwrap();
    let tunnel = engine.clone_engine_for_tunnel(generation).unwrap();
    (engine, config, tunnel)
}

fn context(usage: Option<ConnectionUsage>) -> L7EvalContext {
    L7EvalContext {
        host: "api.example.test".into(),
        port: 8080,
        request_default_port: Some(8080),
        policy_name: "api".into(),
        binary_path: "/usr/bin/curl".into(),
        usage,
        ..Default::default()
    }
}

/// Send `requests` keep-alive requests through the REST relay and return the
/// time per request.
async fn rest_relay(requests: u32, accounting: bool) -> Duration {
    const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let (engine, config, tunnel) = engine_and_config();
    let usage = accounting
        .then(|| ConnectionUsage::admit_connection(engine.usage(), meta(), false).unwrap());
    let ctx = context(usage.clone());
    let (mut app, mut relay_client) = tokio::io::duplex(64 * 1024);
    let (relay_upstream, mut upstream) = tokio::io::duplex(64 * 1024);
    let relay = tokio::spawn(async move {
        if let Some(usage) = usage {
            let mut counted = CountingStream::new(relay_upstream, usage.cell());
            relay_with_inspection(&config, tunnel, &mut relay_client, &mut counted, &ctx).await
        } else {
            let mut plain = relay_upstream;
            relay_with_inspection(&config, tunnel, &mut relay_client, &mut plain, &ctx).await
        }
    });
    let server = tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        let mut pending = Vec::new();
        loop {
            let n = upstream.read(&mut buffer).await.unwrap();
            if n == 0 {
                return;
            }
            pending.extend_from_slice(&buffer[..n]);
            while let Some(end) = pending.windows(4).position(|window| window == b"\r\n\r\n") {
                pending.drain(..end + 4);
                upstream.write_all(RESPONSE).await.unwrap();
            }
        }
    });
    let request = b"GET /v1/items HTTP/1.1\r\nHost: api.example.test\r\n\r\n";
    let mut response = vec![0u8; RESPONSE.len()];
    let start = Instant::now();
    for _ in 0..requests {
        app.write_all(request).await.unwrap();
        app.read_exact(&mut response).await.unwrap();
    }
    let elapsed = start.elapsed();
    drop(app);
    let _ = relay.await;
    server.abort();
    elapsed / requests
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark"]
async fn bench_rest_relay_per_request() {
    const REQUESTS: u32 = 5_000;
    rest_relay(500, false).await;
    rest_relay(500, true).await;
    let mut base = Vec::new();
    let mut with = Vec::new();
    for _ in 0..ROUNDS {
        base.push(rest_relay(REQUESTS, false).await);
        with.push(rest_relay(REQUESTS, true).await);
    }
    let (base, with) = (median(base), median(with));
    println!(
        "REST relay keep-alive request: without {base:?}, with accounting and a budget {with:?}, overhead {:+.1}% ({:?} per request)",
        overhead(base, with),
        with.saturating_sub(base)
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark"]
async fn bench_rego_usage_evaluation() {
    const CALLS: u32 = 5_000;
    let (_engine, _config, tunnel) = engine_and_config();
    let ctx = context(None);
    let request = crate::l7::L7RequestInfo {
        action: "GET".into(),
        target: "/v1/items".into(),
        query_params: HashMap::new(),
        graphql: None,
        jsonrpc: None,
    };
    let mut decision = Vec::new();
    let mut usage = Vec::new();
    for _ in 0..ROUNDS {
        let start = Instant::now();
        for _ in 0..CALLS {
            evaluate_l7_request(&tunnel, &ctx, &request).unwrap();
        }
        decision.push(start.elapsed() / CALLS);
        let start = Instant::now();
        for _ in 0..CALLS {
            l7_usage_facts(&tunnel, &ctx, &request).unwrap();
        }
        usage.push(start.elapsed() / CALLS);
    }
    println!(
        "Rego per L7 request: allow decision {:?}, usage attribution {:?}",
        median(decision),
        median(usage)
    );
}
