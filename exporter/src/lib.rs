//! Prometheus text exposition. No client library: the format is the contract.

use netscope_collector::{Flow, Snapshot, format_addr};
use netscope_common::proto_name;

pub fn render(snapshot: &Snapshot) -> String {
    let mut out = String::with_capacity(snapshot.flows.len() * 160 + 512);
    push_counter(
        &mut out,
        "netscope_events_total",
        "Packets parsed by the cgroup/skb programs.",
        &[],
        snapshot.events,
    );
    push_counter(
        &mut out,
        "netscope_ringbuf_drops_total",
        "Packets parsed but not delivered because the ring buffer was full.",
        &[],
        snapshot.drops,
    );
    out.push_str("# HELP netscope_flow_bytes_total Bytes observed at the cgroup/skb hook, IP header included.\n");
    out.push_str("# TYPE netscope_flow_bytes_total counter\n");
    for flow in &snapshot.flows {
        push_flow(&mut out, flow, "tx", flow.tx);
        push_flow(&mut out, flow, "rx", flow.rx);
    }
    out
}

fn push_flow(out: &mut String, flow: &Flow, dir: &str, bytes: u64) {
    if bytes == 0 {
        return;
    }
    let labels = format!(
        "dir=\"{dir}\",proto=\"{}\",laddr=\"{}\",lport=\"{}\",raddr=\"{}\",rport=\"{}\",pid=\"{}\",comm=\"{}\",container=\"{}\"",
        proto_name(flow.key.proto),
        esc(&format_addr(flow.key.family, &flow.key.local)),
        flow.key.lport,
        esc(&format_addr(flow.key.family, &flow.key.remote)),
        flow.key.rport,
        flow.pid,
        esc(&flow.comm),
        esc(&flow.container),
    );
    out.push_str("netscope_flow_bytes_total{");
    out.push_str(&labels);
    out.push_str("} ");
    out.push_str(&bytes.to_string());
    out.push('\n');
}

fn push_counter(out: &mut String, name: &str, help: &str, _labels: &[&str], value: u64) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" counter\n");
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

fn esc(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_collector::Table;
    use netscope_common::{DIR_TX, FAMILY_V4, NetEvent, PROTO_TCP};

    #[test]
    fn renders_counters_and_a_flow() {
        let mut table = Table::default();
        let mut ev = NetEvent::zero();
        ev.saddr[..4].copy_from_slice(&[10, 0, 0, 8]);
        ev.daddr[..4].copy_from_slice(&[1, 1, 1, 1]);
        ev.sport = 40000;
        ev.dport = 443;
        ev.bytes = 120;
        ev.proto = PROTO_TCP;
        ev.dir = DIR_TX;
        ev.family = FAMILY_V4;
        table.ingest(&ev, 1);
        table.set_drops(3);
        let text = render(&table.snapshot());
        assert!(text.contains("netscope_events_total 1\n"));
        assert!(text.contains("netscope_ringbuf_drops_total 3\n"));
        assert!(text.contains("dir=\"tx\""));
        assert!(text.contains("proto=\"tcp\""));
        assert!(text.contains("laddr=\"10.0.0.8\""));
        assert!(text.contains("rport=\"443\""));
        assert!(text.contains("} 120\n"));
    }
}
