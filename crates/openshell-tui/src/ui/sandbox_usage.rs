// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Egress usage panel for the sandbox screen: usage per policy, host, and
//! binary over the recent windows, and the newest findings.

use std::collections::BTreeMap;

use crate::app::App;
use openshell_core::proto::{EgressFindingSeverity, EgressUsageFinding, GetEgressUsageResponse};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Padding, Paragraph, Row, Table};

/// Usage of one key summed over the recent windows.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct UsageRow {
    policy: String,
    host: String,
    port: u32,
    binary: String,
    connections: u64,
    requests: u64,
    write_requests: u64,
    bytes_out: u64,
    bytes_in: u64,
    status_2xx: u64,
    status_4xx: u64,
    status_5xx: u64,
    status_429: u64,
    budget_denials: u64,
}

fn usage_rows(response: &GetEgressUsageResponse) -> Vec<UsageRow> {
    let mut rows: BTreeMap<(String, String, u32, String), UsageRow> = BTreeMap::new();
    for summary in response.windows.iter().flat_map(|window| &window.summaries) {
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
        row.write_requests += summary.write_requests;
        row.bytes_out += summary.bytes_out;
        row.bytes_in += summary.bytes_in;
        row.status_2xx += responses.status_2xx;
        row.status_4xx += responses.status_4xx;
        row.status_5xx += responses.status_5xx;
        row.status_429 += responses.status_429;
        row.budget_denials += summary.budget_denials;
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

/// Host and port for findings about one host; policy and endpoint for
/// drift findings, which sum every host of an endpoint.
fn finding_target(finding: &EgressUsageFinding) -> String {
    if finding.host.is_empty() {
        let endpoint = finding
            .endpoint_id
            .strip_prefix("endpoint:v1:")
            .map_or(finding.endpoint_id.as_str(), |hash| {
                &hash[..hash.len().min(12)]
            });
        format!("{} endpoint {endpoint}", finding.policy_key)
    } else {
        format!("{}:{}", finding.host, finding.port)
    }
}

fn severity(finding: &EgressUsageFinding, app: &App) -> (&'static str, Style) {
    match EgressFindingSeverity::try_from(finding.severity) {
        Ok(EgressFindingSeverity::Medium) => ("MEDIUM", app.theme.status_err),
        Ok(EgressFindingSeverity::Low) => ("LOW", app.theme.status_warn),
        _ => ("-", app.theme.muted),
    }
}

fn observed_time(finding: &EgressUsageFinding) -> String {
    finding
        .observed_time
        .as_ref()
        .and_then(|time| {
            let seconds = u64::try_from(time.seconds).ok()?;
            let of_day = seconds % 86_400;
            Some(format!(
                "{:02}:{:02}:{:02}",
                of_day / 3600,
                (of_day / 60) % 60,
                of_day % 60
            ))
        })
        .unwrap_or_else(|| "--:--:--".to_string())
}

/// Draw the usage panel.
pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let findings_height = u16::try_from(app.egress_usage.findings.len().min(10))
        .unwrap_or(10)
        .saturating_add(2)
        .max(3);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(findings_height)])
        .split(area);
    draw_usage_table(frame, app, chunks[0]);
    draw_findings(frame, app, chunks[1]);
}

fn draw_usage_table(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let t = &app.theme;
    let windows = app.egress_usage.windows.len();
    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" Egress Usage ", t.heading),
            Span::styled(format!(" last {windows} windows "), t.muted),
        ]))
        .borders(Borders::ALL)
        .border_style(t.border_focused)
        .padding(Padding::horizontal(1));

    let rows = usage_rows(&app.egress_usage);
    if rows.is_empty() {
        let message = if windows == 0 {
            "No usage report yet. Supervisors report one window at a time."
        } else {
            "No egress traffic in the recent windows."
        };
        frame.render_widget(Paragraph::new(message).block(block).style(t.muted), area);
        return;
    }

    let header = Row::new(
        [
            "POLICY", "HOST", "BINARY", "CONNS", "REQS", "WRITES", "OUT", "IN", "2XX", "4XX",
            "5XX", "429", "DENIED",
        ]
        .map(|label| Cell::from(label).style(t.heading)),
    );
    let body = rows.iter().map(|row| {
        let binary = row.binary.rsplit('/').next().unwrap_or_default();
        let denied_style = if row.budget_denials > 0 {
            t.status_err
        } else {
            t.text
        };
        Row::new(vec![
            Cell::from(row.policy.clone()),
            Cell::from(format!("{}:{}", row.host, row.port)),
            Cell::from(if binary.is_empty() { "-" } else { binary }.to_string()),
            Cell::from(row.connections.to_string()),
            Cell::from(row.requests.to_string()),
            Cell::from(row.write_requests.to_string()),
            Cell::from(human_bytes(row.bytes_out)),
            Cell::from(human_bytes(row.bytes_in)),
            Cell::from(row.status_2xx.to_string()),
            Cell::from(row.status_4xx.to_string()),
            Cell::from(row.status_5xx.to_string()),
            Cell::from(row.status_429.to_string()),
            Cell::from(row.budget_denials.to_string()).style(denied_style),
        ])
        .style(t.text)
    });
    let widths = [
        Constraint::Length(16),
        Constraint::Min(24),
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(6),
    ];
    frame.render_widget(Table::new(body, widths).header(header).block(block), area);
}

fn draw_findings(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let t = &app.theme;
    let findings = &app.egress_usage.findings;
    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" Findings ", t.heading),
            Span::styled(format!(" {} ", findings.len()), t.badge),
            Span::raw(" "),
        ]))
        .borders(Borders::ALL)
        .border_style(t.border)
        .padding(Padding::horizontal(1));
    if findings.is_empty() {
        frame.render_widget(
            Paragraph::new("No findings.").block(block).style(t.muted),
            area,
        );
        return;
    }
    let lines: Vec<Line<'_>> = findings
        .iter()
        .rev()
        .skip(app.usage_findings_scroll)
        .map(|finding| {
            let (label, style) = severity(finding, app);
            Line::from(vec![
                Span::styled(format!("{} ", observed_time(finding)), t.muted),
                Span::styled(format!("{label:<6} "), style),
                Span::styled(format!("{:<24} ", finding.finding_type), t.accent),
                Span::styled(format!("{} ", finding_target(finding)), t.text),
                Span::styled(finding.detail.clone(), t.muted),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{Focus, Screen};
    use crate::theme::Theme;
    use openshell_core::auth::EdgeAuthInterceptor;
    use openshell_core::proto::open_shell_client::OpenShellClient;
    use openshell_core::proto::{EgressResponseCounts, EgressUsageSummary, EgressUsageWindow};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn response() -> GetEgressUsageResponse {
        let summary = |requests, bytes_in, denials| EgressUsageSummary {
            policy_key: "local_api".into(),
            host: "host.openshell.internal".into(),
            port: 8000,
            binary_path: "/usr/bin/curl".into(),
            connections: requests,
            requests,
            bytes_in,
            budget_denials: denials,
            responses: Some(EgressResponseCounts {
                status_2xx: requests,
                ..Default::default()
            }),
            ..Default::default()
        };
        GetEgressUsageResponse {
            windows: vec![
                EgressUsageWindow {
                    summaries: vec![summary(15, 1024, 0)],
                    ..Default::default()
                },
                EgressUsageWindow {
                    summaries: vec![summary(5, 1024 * 1024, 5)],
                    ..Default::default()
                },
            ],
            findings: vec![
                EgressUsageFinding {
                    finding_type: "egress.budget_exceeded".into(),
                    severity: EgressFindingSeverity::Medium as i32,
                    host: "host.openshell.internal".into(),
                    port: 8000,
                    detail: "budget 'local-requests' has no requests_per_minute left".into(),
                    ..Default::default()
                },
                EgressUsageFinding {
                    finding_type: "egress.drift".into(),
                    severity: EgressFindingSeverity::Medium as i32,
                    policy_key: "local_api".into(),
                    endpoint_id: "endpoint:v1:110937c24f048d365ee1".into(),
                    detail: "bytes_in 100.6 MiB in one window".into(),
                    ..Default::default()
                },
            ],
        }
    }

    fn render(app: &App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(170, 16)).unwrap();
        terminal
            .draw(|frame| draw(frame, app, frame.size()))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.get(x, y).symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn test_app() -> App {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let client = OpenShellClient::with_interceptor(channel, EdgeAuthInterceptor::noop());
        let mut app = App::new(
            client,
            "test".to_string(),
            "http://127.0.0.1:1".to_string(),
            "default".to_string(),
            Theme::dark(),
        );
        app.screen = Screen::Sandbox;
        app.focus = Focus::SandboxUsage;
        app
    }

    #[test]
    fn rows_sum_windows_per_key() {
        let rows = usage_rows(&response());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].requests, 20);
        assert_eq!(rows[0].bytes_in, 1024 + 1024 * 1024);
        assert_eq!(rows[0].budget_denials, 5);
    }

    #[tokio::test]
    async fn panel_shows_usage_and_newest_finding_first() {
        let mut app = test_app();
        app.egress_usage = response();
        let text = render(&app);
        assert!(text.contains("Egress Usage"), "{text}");
        assert!(text.contains("host.openshell.internal:8000"), "{text}");
        assert!(text.contains("1.0 MiB"), "{text}");
        let drift = text.find("egress.drift").expect("drift finding shown");
        let budget = text
            .find("egress.budget_exceeded")
            .expect("budget finding shown");
        assert!(drift < budget, "newest finding first:\n{text}");
        assert!(text.contains("local_api endpoint 110937c24f04"), "{text}");
    }

    #[tokio::test]
    async fn panel_explains_missing_reports() {
        let app = test_app();
        let text = render(&app);
        assert!(text.contains("No usage report yet"), "{text}");
        assert!(text.contains("No findings."), "{text}");
    }
}
