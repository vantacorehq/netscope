//! cgroup/skb programs. They see the IP header, not a syscall.
//!
//! Returning anything other than 1 would drop the packet. Parse failures
//! are ignored and the packet is always allowed.
//!
//! The entry points are written by hand, not via `#[cgroup_skb]`. That macro
//! emits a BPF-to-BPF call into `.text`, and this kernel refuses those calls
//! unless the loader has `CAP_BPF` in the initial user namespace
//! (`BPF_PROG_LOAD` returns EPERM). Helper calls are allowed, so every
//! function below is `#[inline(always)]` and the section itself contains only
//! helpers (`bpf_skb_load_bytes`, `bpf_ringbuf_output`, `bpf_map_lookup_elem`).
//!
//! Only fixed header offsets are read. IPv4 options and IPv6 extension
//! headers are skipped.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::__sk_buff,
    macros::map,
    maps::{Array, RingBuf},
    programs::SkBuffContext,
};
use netscope_common::{
    DIR_RX, DIR_TX, FAMILY_V4, FAMILY_V6, NetEvent, PROTO_TCP, PROTO_UDP,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[map]
static DROPS: Array<u64> = Array::with_max_entries(1, 0);

#[no_mangle]
#[link_section = "cgroup_skb/ingress"]
pub fn netscope_ingress(ctx: *mut __sk_buff) -> i32 {
    let ctx = SkBuffContext::new(ctx);
    observe(&ctx, DIR_RX);
    1
}

#[no_mangle]
#[link_section = "cgroup_skb/egress"]
pub fn netscope_egress(ctx: *mut __sk_buff) -> i32 {
    let ctx = SkBuffContext::new(ctx);
    observe(&ctx, DIR_TX);
    1
}

#[inline(always)]
fn observe(ctx: &SkBuffContext, dir: u8) {
    let Some(event) = parse(ctx, dir) else {
        return;
    };
    if EVENTS.output::<NetEvent>(&event, 0).is_err() {
        if let Some(slot) = DROPS.get_ptr_mut(0) {
            unsafe {
                *slot = (*slot).saturating_add(1);
            }
        }
    }
}

#[inline(always)]
fn parse(ctx: &SkBuffContext, dir: u8) -> Option<NetEvent> {
    let first: u8 = ctx.load(0).ok()?;
    let version = first >> 4;
    if version == 4 {
        parse_v4(ctx, dir, first)
    } else if version == 6 {
        parse_v6(ctx, dir)
    } else {
        None
    }
}

#[inline(always)]
fn parse_v4(ctx: &SkBuffContext, dir: u8, ver_ihl: u8) -> Option<NetEvent> {
    // IHL is in 32-bit words. 5 means a 20-byte header and no options.
    if ver_ihl & 0x0f != 5 {
        return None;
    }
    let proto: u8 = ctx.load(9).ok()?;
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return None;
    }
    let total: u16 = u16::from_be(ctx.load(2).ok()?);
    if total < 20 {
        return None;
    }
    let mut event = NetEvent::zero();
    event.saddr[0] = ctx.load(12).ok()?;
    event.saddr[1] = ctx.load(13).ok()?;
    event.saddr[2] = ctx.load(14).ok()?;
    event.saddr[3] = ctx.load(15).ok()?;
    event.daddr[0] = ctx.load(16).ok()?;
    event.daddr[1] = ctx.load(17).ok()?;
    event.daddr[2] = ctx.load(18).ok()?;
    event.daddr[3] = ctx.load(19).ok()?;
    event.sport = u16::from_be(ctx.load(20).ok()?);
    event.dport = u16::from_be(ctx.load(22).ok()?);
    event.proto = proto;
    event.dir = dir;
    event.family = FAMILY_V4;
    event.bytes = u32::from(total);
    Some(event)
}

#[inline(always)]
fn parse_v6(ctx: &SkBuffContext, dir: u8) -> Option<NetEvent> {
    let next: u8 = ctx.load(6).ok()?;
    if next != PROTO_TCP && next != PROTO_UDP {
        return None;
    }
    let payload: u16 = u16::from_be(ctx.load(4).ok()?);
    let mut event = NetEvent::zero();
    event.saddr = load16(ctx, 8)?;
    event.daddr = load16(ctx, 24)?;
    event.sport = u16::from_be(ctx.load(40).ok()?);
    event.dport = u16::from_be(ctx.load(42).ok()?);
    event.proto = next;
    event.dir = dir;
    event.family = FAMILY_V6;
    event.bytes = u32::from(payload).saturating_add(40);
    Some(event)
}

#[inline(always)]
fn load16(ctx: &SkBuffContext, off: usize) -> Option<[u8; 16]> {
    let hi: u64 = ctx.load(off).ok()?;
    let lo: u64 = ctx.load(off + 8).ok()?;
    let mut out = [0u8; 16];
    let hb = hi.to_ne_bytes();
    let lb = lo.to_ne_bytes();
    out[0] = hb[0];
    out[1] = hb[1];
    out[2] = hb[2];
    out[3] = hb[3];
    out[4] = hb[4];
    out[5] = hb[5];
    out[6] = hb[6];
    out[7] = hb[7];
    out[8] = lb[0];
    out[9] = lb[1];
    out[10] = lb[2];
    out[11] = lb[3];
    out[12] = lb[4];
    out[13] = lb[5];
    out[14] = lb[6];
    out[15] = lb[7];
    Some(out)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
