//! Packet event shared by the eBPF program and the userspace collector.
//!
//! This crate does not talk to the kernel. Address formatting lives in the
//! collector, where `std` is available.

#![no_std]

/// Packet arrived at the cgroup.
pub const DIR_RX: u8 = 0;
/// Packet left the cgroup.
pub const DIR_TX: u8 = 1;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const FAMILY_V4: u8 = 4;
pub const FAMILY_V6: u8 = 6;

/// One packet observed at the cgroup/skb hook.
///
/// Addresses are network byte order. IPv4 uses the first four bytes and
/// leaves the rest zero. `bytes` is the IP packet length at the hook
/// (header included), not a syscall return value.
///
/// `cgroup_skb` cannot call `bpf_get_current_pid_tgid`. Pid, comm and the
/// container id are attached later from `/proc`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetEvent {
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub bytes: u32,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub dir: u8,
    pub family: u8,
    pub _pad: u8,
}

impl NetEvent {
    pub const fn zero() -> Self {
        Self {
            saddr: [0; 16],
            daddr: [0; 16],
            bytes: 0,
            sport: 0,
            dport: 0,
            proto: 0,
            dir: 0,
            family: 0,
            _pad: 0,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetEvent {}

/// Flow identity with the local socket on the left.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    pub local: [u8; 16],
    pub remote: [u8; 16],
    pub lport: u16,
    pub rport: u16,
    pub proto: u8,
    pub family: u8,
}

impl FlowKey {
    pub fn from_event(ev: &NetEvent) -> Self {
        if ev.dir == DIR_TX {
            Self {
                local: ev.saddr,
                remote: ev.daddr,
                lport: ev.sport,
                rport: ev.dport,
                proto: ev.proto,
                family: ev.family,
            }
        } else {
            Self {
                local: ev.daddr,
                remote: ev.saddr,
                lport: ev.dport,
                rport: ev.sport,
                proto: ev.proto,
                family: ev.family,
            }
        }
    }
}

pub fn proto_name(proto: u8) -> &'static str {
    match proto {
        PROTO_TCP => "tcp",
        PROTO_UDP => "udp",
        _ => "other",
    }
}
