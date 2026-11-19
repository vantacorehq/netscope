//! Turns packet events into flows and attaches pid, comm and container id
//! from `/proc`. The proc data is read from the kernel, not invented.

use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use netscope_common::{DIR_TX, FAMILY_V4, FlowKey, NetEvent, proto_name};

#[derive(Clone, Debug)]
pub struct Flow {
    pub key: FlowKey,
    pub tx: u64,
    pub rx: u64,
    pub last_ms: u64,
    pub pid: u32,
    pub comm: String,
    pub container: String,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub flows: Vec<Flow>,
    pub events: u64,
    pub drops: u64,
    pub bytes: u64,
}

#[derive(Default)]
pub struct Table {
    flows: HashMap<FlowKey, Flow>,
    pub events: u64,
    pub drops: u64,
}

impl Table {
    pub fn ingest(&mut self, event: &NetEvent, now_ms: u64) {
        self.events = self.events.saturating_add(1);
        let key = FlowKey::from_event(event);
        let flow = self.flows.entry(key).or_insert_with(|| Flow {
            key,
            tx: 0,
            rx: 0,
            last_ms: now_ms,
            pid: 0,
            comm: String::new(),
            container: String::new(),
        });
        if event.dir == DIR_TX {
            flow.tx = flow.tx.saturating_add(u64::from(event.bytes));
        } else {
            flow.rx = flow.rx.saturating_add(u64::from(event.bytes));
        }
        flow.last_ms = now_ms;
    }

    pub fn set_drops(&mut self, drops: u64) {
        self.drops = drops;
    }

    pub fn enrich(&mut self, owners: &[SocketOwner]) {
        for flow in self.flows.values_mut() {
            if let Some(owner) = owners.iter().find(|owner| owner.matches(&flow.key)) {
                flow.pid = owner.pid;
                if !owner.comm.is_empty() {
                    flow.comm.clone_from(&owner.comm);
                }
                if !owner.container.is_empty() {
                    flow.container.clone_from(&owner.container);
                }
            }
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut flows: Vec<Flow> = self.flows.values().cloned().collect();
        flows.sort_by(|a, b| {
            (b.tx + b.rx)
                .cmp(&(a.tx + a.rx))
                .then(a.key.lport.cmp(&b.key.lport))
        });
        let bytes = flows.iter().fold(0u64, |acc, flow| {
            acc.saturating_add(flow.tx).saturating_add(flow.rx)
        });
        Snapshot {
            flows,
            events: self.events,
            drops: self.drops,
            bytes,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SocketOwner {
    pub key: FlowKey,
    pub pid: u32,
    pub comm: String,
    pub container: String,
}

impl SocketOwner {
    fn matches(&self, key: &FlowKey) -> bool {
        self.key == *key
            || (self.key.proto == key.proto
                && self.key.family == key.family
                && self.key.local == key.local
                && self.key.lport == key.lport
                && self.key.remote == [0; 16]
                && self.key.rport == 0)
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Read `/proc/net/tcp`, `/proc/net/udp` and the v6 files, then join them to
/// `/proc/<pid>/fd` socket inodes and `/proc/<pid>/cgroup`.
pub fn read_socket_owners(proc_root: &Path) -> Vec<SocketOwner> {
    let mut inodes: HashMap<u64, FlowKey> = HashMap::new();
    for (name, proto, family) in [
        ("tcp", netscope_common::PROTO_TCP, FAMILY_V4),
        ("udp", netscope_common::PROTO_UDP, FAMILY_V4),
        ("tcp6", netscope_common::PROTO_TCP, netscope_common::FAMILY_V6),
        ("udp6", netscope_common::PROTO_UDP, netscope_common::FAMILY_V6),
    ] {
        let path = proc_root.join("net").join(name);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        inodes.extend(parse_proc_net(&text, proto, family));
    }

    let mut owners = Vec::new();
    let Ok(entries) = fs::read_dir(proc_root) else {
        return owners;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        let comm = fs::read_to_string(entry.path().join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let cgroup = fs::read_to_string(entry.path().join("cgroup")).unwrap_or_default();
        let container = container_id(&cgroup).unwrap_or_default();
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };
            let link = link.to_string_lossy();
            let Some(inode) = socket_inode(&link) else {
                continue;
            };
            let Some(key) = inodes.get(&inode).copied() else {
                continue;
            };
            owners.push(SocketOwner {
                key,
                pid,
                comm: comm.clone(),
                container: container.clone(),
            });
        }
    }
    owners
}

pub fn parse_proc_net(text: &str, proto: u8, family: u8) -> HashMap<u64, FlowKey> {
    let mut out = HashMap::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let Some((local, lport)) = parse_proc_addr(cols[1], family) else {
            continue;
        };
        let Some((remote, rport)) = parse_proc_addr(cols[2], family) else {
            continue;
        };
        let Ok(inode) = cols[9].parse::<u64>() else {
            continue;
        };
        if inode == 0 {
            continue;
        }
        out.insert(
            inode,
            FlowKey {
                local,
                remote,
                lport,
                rport,
                proto,
                family,
            },
        );
    }
    out
}

fn parse_proc_addr(field: &str, family: u8) -> Option<([u8; 16], u16)> {
    let (addr, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let mut out = [0u8; 16];
    if family == FAMILY_V4 {
        if addr.len() != 8 {
            return None;
        }
        let raw = u32::from_str_radix(addr, 16).ok()?;
        // The kernel prints the address little-endian.
        out[..4].copy_from_slice(&raw.to_le_bytes());
    } else {
        if addr.len() != 32 {
            return None;
        }
        let bytes = hex_decode(addr)?;
        // Four little-endian words.
        for word in 0..4 {
            let chunk = &bytes[word * 4..word * 4 + 4];
            let value = u32::from_le_bytes(chunk.try_into().ok()?);
            out[word * 4..word * 4 + 4].copy_from_slice(&value.to_be_bytes());
        }
    }
    Some((out, port))
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn socket_inode(link: &str) -> Option<u64> {
    let rest = link.strip_prefix("socket:[")?.strip_suffix(']')?;
    rest.parse().ok()
}

/// Docker and containerd put a hex id in the cgroup path.
pub fn container_id(cgroup: &str) -> Option<String> {
    for token in cgroup.split(|c: char| !c.is_ascii_hexdigit() && c != '-') {
        let id = token.trim_start_matches('-');
        if id.len() >= 12 && id.chars().all(|c| c.is_ascii_hexdigit()) {
            // systemd unit names look like docker-<id>.scope, which splits
            // into "docker" and the id. A bare long hex run is the id.
            if id.len() == 12 || id.len() == 64 {
                return Some(id.to_string());
            }
        }
    }
    // Also accept docker-<64hex> when the dash stayed attached.
    for token in cgroup.split(|c: char| c == '/' || c.is_whitespace()) {
        if let Some(id) = token.strip_prefix("docker-") {
            let id = id.trim_end_matches(".scope");
            if (id.len() == 12 || id.len() == 64) && id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(id.to_string());
            }
        }
    }
    None
}

pub fn format_addr(family: u8, addr: &[u8; 16]) -> String {
    if family == FAMILY_V4 {
        Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string()
    } else {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(addr);
        Ipv6Addr::from(octets).to_string()
    }
}

pub fn service_label(flow: &Flow) -> String {
    format!(
        "{}/{}",
        proto_name(flow.key.proto).to_ascii_uppercase(),
        flow.key.rport
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use netscope_common::{DIR_RX, DIR_TX, FAMILY_V4, PROTO_TCP};
    use std::time::Instant;

    fn v4_event(dir: u8, sip: [u8; 4], sport: u16, dip: [u8; 4], dport: u16, bytes: u32) -> NetEvent {
        let mut ev = NetEvent::zero();
        ev.saddr[..4].copy_from_slice(&sip);
        ev.daddr[..4].copy_from_slice(&dip);
        ev.sport = sport;
        ev.dport = dport;
        ev.bytes = bytes;
        ev.proto = PROTO_TCP;
        ev.dir = dir;
        ev.family = FAMILY_V4;
        ev
    }

    #[test]
    fn tx_and_rx_share_one_flow() {
        let mut table = Table::default();
        table.ingest(
            &v4_event(DIR_TX, [10, 0, 0, 2], 40000, [1, 2, 3, 4], 443, 100),
            1,
        );
        table.ingest(
            &v4_event(DIR_RX, [1, 2, 3, 4], 443, [10, 0, 0, 2], 40000, 40),
            2,
        );
        let snap = table.snapshot();
        assert_eq!(snap.flows.len(), 1);
        assert_eq!(snap.flows[0].tx, 100);
        assert_eq!(snap.flows[0].rx, 40);
        assert_eq!(snap.bytes, 140);
        assert_eq!(snap.flows[0].key.lport, 40000);
        assert_eq!(snap.flows[0].key.rport, 443);
    }

    #[test]
    fn proc_net_tcp_little_endian_address() {
        let text = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 04030201:01BB 01 00000000:00000000 00:00000000 00000000     0        0 42 1 0000000000000000 20 4 30 10 -1
";
        let map = parse_proc_net(text, PROTO_TCP, FAMILY_V4);
        let key = map.get(&42).unwrap();
        assert_eq!(&key.local[..4], &[127, 0, 0, 1]);
        assert_eq!(key.lport, 0x1F90);
        assert_eq!(&key.remote[..4], &[1, 2, 3, 4]);
        assert_eq!(key.rport, 443);
    }

    #[test]
    fn listening_socket_matches_established_flow() {
        let mut table = Table::default();
        table.ingest(
            &v4_event(DIR_RX, [1, 2, 3, 4], 50000, [127, 0, 0, 1], 8080, 20),
            1,
        );
        let mut local = [0u8; 16];
        local[..4].copy_from_slice(&[127, 0, 0, 1]);
        table.enrich(&[SocketOwner {
            key: FlowKey {
                local,
                remote: [0; 16],
                lport: 8080,
                rport: 0,
                proto: PROTO_TCP,
                family: FAMILY_V4,
            },
            pid: 7,
            comm: "app".into(),
            container: String::new(),
        }]);
        let snap = table.snapshot();
        assert_eq!(snap.flows[0].pid, 7);
        assert_eq!(snap.flows[0].comm, "app");
    }

    #[test]
    fn container_id_from_docker_cgroup() {
        let text = "0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n";
        assert_eq!(
            container_id(text).as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(container_id("0::/\n"), None);
    }

    #[test]
    fn socket_inode_link() {
        assert_eq!(socket_inode("socket:[99]"), Some(99));
        assert_eq!(socket_inode("anon_inode:[eventfd]"), None);
    }

    #[test]
    fn ingest_200k_events_stays_under_two_seconds() {
        let mut table = Table::default();
        let started = Instant::now();
        for i in 0..200_000u32 {
            let mut ev = v4_event(
                if i % 2 == 0 { DIR_TX } else { DIR_RX },
                [10, 0, 0, 1],
                1000 + (i % 64) as u16,
                [10, 1, 0, (i % 32) as u8],
                80,
                64,
            );
            if i % 2 == 1 {
                ev = v4_event(DIR_RX, [10, 1, 0, (i % 32) as u8], 80, [10, 0, 0, 1], 1000 + (i % 64) as u16, 64);
            }
            table.ingest(&ev, i as u64);
        }
        let elapsed = started.elapsed();
        let snap = table.snapshot();
        assert!(snap.events == 200_000);
        assert!(
            elapsed.as_secs_f64() < 2.0,
            "userspace ingest took {elapsed:?}"
        );
        eprintln!(
            "collector ingest {:.0} events/s",
            200_000.0 / elapsed.as_secs_f64()
        );
    }

    #[test]
    fn proc_net_tcp6_loopback() {
        // Kernel layout: four little-endian u32 words. ::1 is word3 = 0x00000001
        // printed as 01000000 in the last eight hex digits.
        let text = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7 1 0000000000000000 100 0 0 10 0
";
        let map = parse_proc_net(text, PROTO_TCP, netscope_common::FAMILY_V6);
        let key = map.get(&7).unwrap();
        assert_eq!(key.lport, 80);
        assert_eq!(key.rport, 0);
        assert_eq!(format_addr(key.family, &key.local), "::1");
    }

    #[test]
    fn live_proc_net_parses() {
        let map = parse_proc_net(
            &fs::read_to_string("/proc/net/tcp").unwrap(),
            PROTO_TCP,
            FAMILY_V4,
        );
        assert!(map.len() > 0, "this kernel published no tcp table");
    }
}
