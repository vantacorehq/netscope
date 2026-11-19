//! Terminal view of a collector snapshot. Drawing is pure: tests use
//! `ratatui`'s `TestBackend` and never open a tty.

use netscope_collector::{Flow, Snapshot, format_addr, service_label};
use netscope_common::proto_name;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

pub fn draw(frame: &mut Frame, snapshot: &Snapshot) {
    let area = frame.area();
    let cols = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(8),
        ])
        .split(area);

    let title = Paragraph::new(Line::from("NETSCOPE  cgroup/skb  ·  real packets only"))
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, cols[0]);

    let stats = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(cols[1]);
    let active = snapshot
        .flows
        .iter()
        .filter(|flow| flow.tx + flow.rx > 0)
        .count();
    let pids = distinct_pids(snapshot);
    stat(frame, stats[0], "FLOWS", &snapshot.flows.len().to_string());
    stat(frame, stats[1], "ACTIVE", &active.to_string());
    stat(frame, stats[2], "BYTES", &grouped(snapshot.bytes));
    stat(frame, stats[3], "PIDS", &pids.to_string());

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(72), Constraint::Percentage(28)])
        .split(cols[2]);

    let rows = snapshot.flows.iter().take(40).map(flow_row);
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(22),
            Constraint::Length(22),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(16),
        ],
    )
    .header(
        Row::new(["PROTO", "LOCAL", "REMOTE", "TX", "RX", "PROC"]).style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(Block::default().title("CONNECTIONS").borders(Borders::ALL));
    frame.render_widget(table, body[0]);

    let mut services: Vec<(String, u64)> = Vec::new();
    for flow in &snapshot.flows {
        let label = service_label(flow);
        let bytes = flow.tx + flow.rx;
        if let Some(found) = services.iter_mut().find(|(name, _)| name == &label) {
            found.1 = found.1.saturating_add(bytes);
        } else {
            services.push((label, bytes));
        }
    }
    services.sort_by(|a, b| b.1.cmp(&a.1));
    let lines: Vec<Line> = services
        .iter()
        .take(12)
        .map(|(name, bytes)| Line::from(format!("{name:<12} {:>10}", grouped(*bytes))))
        .collect();
    let side = Paragraph::new(lines).block(
        Block::default()
            .title("TOP SERVICES")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Green)),
    );
    frame.render_widget(side, body[1]);
}

fn stat(frame: &mut Frame, area: ratatui::layout::Rect, label: &str, value: &str) {
    let text = Paragraph::new(format!("{value}\n{label}")).style(Style::default().fg(Color::Green));
    frame.render_widget(
        text.block(Block::default().borders(Borders::ALL).style(Style::default().fg(Color::DarkGray))),
        area,
    );
}

fn flow_row(flow: &Flow) -> Row<'_> {
    let local = format!(
        "{}:{}",
        format_addr(flow.key.family, &flow.key.local),
        flow.key.lport
    );
    let remote = format!(
        "{}:{}",
        format_addr(flow.key.family, &flow.key.remote),
        flow.key.rport
    );
    let proc = if flow.pid == 0 {
        "-".to_string()
    } else if flow.container.is_empty() {
        format!("{} {}", flow.pid, flow.comm)
    } else {
        format!("{} {}", flow.pid, &flow.container[..flow.container.len().min(8)])
    };
    Row::new([
        Cell::from(proto_name(flow.key.proto).to_string()),
        Cell::from(local),
        Cell::from(remote),
        Cell::from(grouped(flow.tx)),
        Cell::from(grouped(flow.rx)),
        Cell::from(proc),
    ])
}

fn distinct_pids(snapshot: &Snapshot) -> usize {
    let mut pids: Vec<u32> = snapshot
        .flows
        .iter()
        .map(|flow| flow.pid)
        .filter(|pid| *pid != 0)
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids.len()
}

fn grouped(n: u64) -> String {
    let raw = n.to_string();
    let mut out = String::new();
    for (i, ch) in raw.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_collector::Table;
    use netscope_common::{DIR_TX, FAMILY_V4, NetEvent, PROTO_UDP};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn draws_the_connection_it_was_given() {
        let mut table = Table::default();
        let mut ev = NetEvent::zero();
        ev.saddr[..4].copy_from_slice(&[10, 8, 0, 4]);
        ev.daddr[..4].copy_from_slice(&[10, 8, 0, 9]);
        ev.sport = 5353;
        ev.dport = 53;
        ev.bytes = 70;
        ev.proto = PROTO_UDP;
        ev.dir = DIR_TX;
        ev.family = FAMILY_V4;
        table.ingest(&ev, 1);
        let snap = table.snapshot();
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &snap)).unwrap();
        let text = buffer_text(terminal.backend().buffer());
        assert!(text.contains("NETSCOPE"), "{text}");
        assert!(text.contains("CONNECTIONS"), "{text}");
        assert!(text.contains("UDP/53"), "{text}");
        assert!(text.contains("10.8.0.4:5353"), "{text}");
    }

    fn buffer_text(buffer: &ratatui::buffer::Buffer) -> String {
        let mut lines = Vec::new();
        for y in 0..buffer.area.height {
            let mut line = String::new();
            for x in 0..buffer.area.width {
                line.push_str(buffer[(x, y)].symbol());
            }
            lines.push(line);
        }
        lines.join("\n")
    }
}
