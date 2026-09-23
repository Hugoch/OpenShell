// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E coverage for egress usage accounting and budgets.
//!
//! A deny budget of 5 requests per minute admits the first 5 requests to an
//! allowed endpoint and refuses the rest with HTTP 429. The supervisor
//! reports exact byte counts to the gateway, and `openshell sandbox usage`
//! shows them.

use std::io::Write;
use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const TEST_SERVER_HOST: &str = "host.openshell.internal";
const BODY_BYTES: usize = 4096;

fn response_bytes() -> Vec<u8> {
    let mut response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY_BYTES}\r\nConnection: close\r\n\r\n")
            .into_bytes();
    response.extend(std::iter::repeat_n(b'x', BODY_BYTES));
    response
}

struct FixedResponseServer {
    port: u16,
    task: JoinHandle<()>,
}

impl FixedResponseServer {
    async fn start() -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|error| format!("bind HTTP server: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("read HTTP server address: {error}"))?
            .port();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 4096];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => request.extend_from_slice(&buffer[..read]),
                        }
                    }
                    let _ = stream.write_all(&response_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Ok(Self { port, task })
    }
}

impl Drop for FixedResponseServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn write_policy(port: u16) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create policy file");
    let policy = format!(
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  usage_api:
    name: usage_api
    endpoints:
      - host: {TEST_SERVER_HOST}
        port: {port}
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/data"
        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7"
    binaries:
      - path: "/**"

network_budgets:
  usage-api-requests:
    policies: [usage_api]
    requests_per_minute: 5
    on_exceed: deny
"#
    );
    file.write_all(policy.as_bytes()).expect("write policy");
    file.flush().expect("flush policy");
    file
}

async fn run_cli(args: &[&str]) -> Result<String, String> {
    let mut cmd = openshell_cmd();
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd
        .output()
        .await
        .map_err(|error| format!("spawn openshell {}: {error}", args.join(" ")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.status.success() {
        return Err(format!(
            "openshell {} failed:\n{stdout}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(stdout)
}

/// Wait for the first usage report. The default window is 60 seconds.
async fn wait_for_usage(sandbox: &str) -> Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(150);
    loop {
        let usage = run_cli(&["sandbox", "usage", sandbox, "-o", "json"])
            .await
            .expect("read sandbox usage");
        let value: Value = serde_json::from_str(&usage).expect("usage JSON");
        let requests: u64 = value["usage"]
            .as_array()
            .map(|rows| rows.iter().filter_map(|row| row["requests"].as_u64()).sum())
            .unwrap_or(0);
        if requests > 0 {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for egress usage:\n{usage}"
        );
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

#[tokio::test]
async fn budget_denies_requests_over_its_rate_and_usage_reports_exact_bytes() {
    let server = FixedResponseServer::start().await.expect("start server");
    let policy = write_policy(server.port);
    let policy_path = policy.path().to_str().expect("utf-8 path").to_string();
    let script = format!(
        r#"
import socket

allowed = 0
denied = 0
for _ in range(10):
    with socket.create_connection(({host:?}, {port}), timeout=10) as sock:
        sock.sendall(b"GET /data HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n")
        response = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response += chunk
    status = response.split(b"\r\n", 1)[0]
    if b" 200 " in status:
        allowed += 1
    elif b" 429 " in status and b"budget_exceeded" in response and b"Retry-After:" in response:
        denied += 1
    else:
        raise RuntimeError(f"unexpected response: {{response[:300]!r}}")
print(f"ALLOWED={{allowed}} DENIED={{denied}}")
"#,
        host = TEST_SERVER_HOST,
        port = server.port,
    );

    let mut guard = SandboxGuard::create_keep_with_args(
        &["--policy", &policy_path],
        &["sh", "-c", "echo Ready; sleep infinity"],
        "Ready",
    )
    .await
    .expect("create keep sandbox");
    let output = guard
        .exec(&["python3", "-c", &script])
        .await
        .expect("run budget script");
    assert!(
        output.contains("ALLOWED=5 DENIED=5"),
        "budget did not admit exactly 5 requests:\n{output}"
    );

    let logs = run_cli(&[
        "logs",
        &guard.name,
        "-n",
        "500",
        "--since",
        "5m",
        "--source",
        "sandbox",
    ])
    .await
    .expect("read sandbox logs");
    assert!(
        logs.contains("egress.budget_exceeded"),
        "budget finding missing from logs:\n{logs}"
    );
    assert!(
        logs.contains("NET:CLOSE") && logs.contains("bytes_in:"),
        "close event with traffic totals missing from logs:\n{logs}"
    );

    let usage = wait_for_usage(&guard.name).await;
    let row = usage["usage"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["requests"].as_u64().unwrap_or(0) > 0)
        })
        .cloned()
        .unwrap_or_else(|| panic!("no usage row with requests:\n{usage}"));
    assert_eq!(row["policy"], "usage_api", "{usage}");
    assert_eq!(row["requests"], 5, "{usage}");
    assert_eq!(row["budget_denials"], 5, "{usage}");
    assert_eq!(row["responses"]["status_2xx"], 5, "{usage}");
    assert_eq!(
        row["bytes_in"].as_u64(),
        Some(5 * response_bytes().len() as u64),
        "bytes_in must equal the upstream response bytes:\n{usage}"
    );
    assert!(row["bytes_out"].as_u64().unwrap_or(0) > 0, "{usage}");
    assert!(
        usage["findings"].as_array().is_some_and(|findings| findings
            .iter()
            .any(|finding| finding["type"] == "egress.budget_exceeded")),
        "budget finding missing from usage:\n{usage}"
    );

    guard.cleanup().await;
}
