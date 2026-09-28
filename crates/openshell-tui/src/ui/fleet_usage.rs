// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fleet tab of the dashboard: egress destinations of all sandboxes in the
//! current workspace, and the newest fleet findings.

use crate::app::App;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Padding, Paragraph, Row, Table};

use super::sandbox_usage::{human_bytes, observed_time, severity};

/// Cohort IDs of base policies are long hashes; keep a short prefix.
fn short_cohort(cohort: &str) -> String {
    cohort.strip_prefix("policy:").map_or_else(
        || cohort.to_string(),
        |hash| format!("policy:{}", &hash[..hash.len().min(12)]),
    )
}

/// Draw the Fleet tab.
pub fn draw(frame: &mut Frame<'_>, app: &App, area: Rect, focused: bool) {
    let t = &app.theme;
    let block = Block::default()
        .title(super::global_settings::draw_tab_title(app, focused))
        .borders(Borders::ALL)
        .border_style(if focused { t.border_focused } else { t.border })
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if let Some(error) = &app.fleet_usage_error {
        frame.render_widget(Paragraph::new(error.as_str()).style(t.muted), inner);
        return;
    }
    let findings = &app.fleet_usage.findings;
    let findings_height = u16::try_from(findings.len().min(4)).unwrap_or(4) + 1;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(findings_height)])
        .split(inner);
    draw_destinations(frame, app, chunks[0]);
    draw_findings(frame, app, chunks[1]);
}

fn draw_destinations(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let t = &app.theme;
    let destinations = &app.fleet_usage.destinations;
    if destinations.is_empty() {
        frame.render_widget(
            Paragraph::new("No fleet egress usage in the last 10 minutes.").style(t.muted),
            area,
        );
        return;
    }
    let header = Row::new(
        [
            "COHORT",
            "HOST",
            "SANDBOXES",
            "WRITERS",
            "REQS",
            "WRITES",
            "IN",
        ]
        .map(|label| Cell::from(label).style(t.heading)),
    );
    let body = destinations.iter().map(|destination| {
        Row::new(vec![
            Cell::from(short_cohort(&destination.cohort)),
            Cell::from(format!("{}:{}", destination.host, destination.port)),
            Cell::from(destination.max_sandboxes.to_string()),
            Cell::from(destination.max_writer_sandboxes.to_string()),
            Cell::from(destination.requests.to_string()),
            Cell::from(destination.write_requests.to_string()),
            Cell::from(human_bytes(destination.bytes_in)),
        ])
        .style(t.text)
    });
    let widths = [
        Constraint::Length(20),
        Constraint::Min(24),
        Constraint::Length(9),
        Constraint::Length(7),
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Length(10),
    ];
    frame.render_widget(Table::new(body, widths).header(header), area);
}

fn draw_findings(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let t = &app.theme;
    let findings = &app.fleet_usage.findings;
    let mut lines = vec![Line::from(Span::styled(
        format!("Fleet findings: {}", findings.len()),
        t.heading,
    ))];
    lines.extend(findings.iter().map(|finding| {
        let (label, style) = severity(finding, app);
        Line::from(vec![
            Span::styled(format!("{} ", observed_time(finding)), t.muted),
            Span::styled(format!("{label:<6} "), style),
            Span::styled(format!("{:<20} ", finding.finding_type), t.accent),
            Span::styled(finding.detail.clone(), t.muted),
        ])
    }));
    frame.render_widget(Paragraph::new(lines), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{Focus, MiddlePaneTab, Screen};
    use crate::theme::Theme;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use openshell_core::auth::EdgeAuthInterceptor;
    use openshell_core::proto::open_shell_client::OpenShellClient;
    use openshell_core::proto::{
        EgressFindingSeverity, EgressUsageFinding, FleetEgressDestination,
        GetFleetEgressUsageResponse,
    };
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render(app: &App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(170, 12)).unwrap();
        terminal
            .draw(|frame| draw(frame, app, frame.size(), true))
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
        app.screen = Screen::Dashboard;
        app.focus = Focus::Providers;
        app.middle_pane_tab = MiddlePaneTab::Fleet;
        app
    }

    #[tokio::test]
    async fn fleet_tab_shows_destinations_and_findings() {
        let mut app = test_app();
        app.fleet_usage = GetFleetEgressUsageResponse {
            destinations: vec![FleetEgressDestination {
                cohort: "policy:b1358bca69f0b76f89b2".into(),
                host: "host.openshell.internal".into(),
                port: 8000,
                max_sandboxes: 5,
                max_writer_sandboxes: 5,
                requests: 10,
                write_requests: 5,
                bytes_in: 2048,
                ..Default::default()
            }],
            findings: vec![EgressUsageFinding {
                finding_type: "egress.fleet_fan_in".into(),
                severity: EgressFindingSeverity::Medium as i32,
                detail: "5 sandboxes wrote to host.openshell.internal:8000 in one minute".into(),
                ..Default::default()
            }],
        };
        let text = render(&app);
        assert!(text.contains("Fleet"), "{text}");
        assert!(text.contains("policy:b1358bca69f0 "), "{text}");
        assert!(text.contains("host.openshell.internal:8000"), "{text}");
        assert!(text.contains("2.0 KiB"), "{text}");
        assert!(text.contains("MEDIUM egress.fleet_fan_in"), "{text}");
    }

    #[tokio::test]
    async fn fleet_tab_shows_why_it_has_no_data() {
        let mut app = test_app();
        app.fleet_usage_error = Some("Fleet usage unavailable: permission denied".into());
        let text = render(&app);
        assert!(text.contains("permission denied"), "{text}");
    }

    #[tokio::test]
    async fn tab_keys_cycle_to_the_fleet_tab_and_back() {
        let mut app = test_app();
        app.middle_pane_tab = MiddlePaneTab::Providers;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.handle_key(key(KeyCode::Char('l')));
        app.handle_key(key(KeyCode::Char('l')));
        assert_eq!(app.middle_pane_tab, MiddlePaneTab::Fleet);
        app.handle_key(key(KeyCode::Char('d')));
        assert_eq!(
            app.middle_pane_tab,
            MiddlePaneTab::Fleet,
            "the tab is read-only"
        );
        app.handle_key(key(KeyCode::Char('l')));
        assert_eq!(app.middle_pane_tab, MiddlePaneTab::Providers);
    }
}
