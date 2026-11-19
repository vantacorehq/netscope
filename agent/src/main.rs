//! Userspace half of NetScope.
//!
//! Loads the cgroup/skb programs, reads the ring buffer, joins flows to
//! `/proc`, draws the TUI and serves Prometheus text.

use std::fs::File;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use aya::maps::{Array, RingBuf};
use aya::programs::cgroup_skb::CgroupSkbLinkId;
use aya::programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType};
use aya::{Ebpf, include_bytes_aligned};
use anyhow::{Context, anyhow};
use clap::Parser;
use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use netscope_collector::{Table, now_ms, read_socket_owners};
use netscope_common::NetEvent;
use netscope_exporter::render;
use netscope_tui::draw;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Parser)]
#[command(
    name = "netscope",
    version,
    about = "Linux cgroup/skb network observer"
)]
struct Opt {
    /// cgroup v2 directory the programs attach to.
    #[arg(long, default_value = "/sys/fs/cgroup")]
    cgroup: PathBuf,
    /// Prometheus listen address. Defaults to localhost.
    #[arg(long, default_value = "127.0.0.1:9108")]
    metrics: String,
    /// Serve metrics only. Do not open a terminal UI.
    #[arg(long)]
    headless: bool,
    /// Exit after this many milliseconds.
    #[arg(long)]
    duration_ms: Option<u64>,
}

enum Fail {
    Env(String),
    Bug(anyhow::Error),
}

fn main() -> ExitCode {
    match run(Opt::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Env(msg)) => {
            eprintln!("netscope: environment: {msg}");
            ExitCode::from(2)
        }
        Err(Fail::Bug(err)) => {
            eprintln!("netscope: error: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn run(opt: Opt) -> Result<(), Fail> {
    probe(&opt)?;
    let mut ebpf = load_ebpf()?;
    let events = ebpf
        .take_map("EVENTS")
        .context("EVENTS map missing from the object")
        .map_err(Fail::Bug)?;
    let drops_map = ebpf
        .take_map("DROPS")
        .context("DROPS map missing from the object")
        .map_err(Fail::Bug)?;
    let mut ring = RingBuf::try_from(events).map_err(|err| Fail::Bug(anyhow!("{err}")))?;
    let drops: Array<_, u64> =
        Array::try_from(drops_map).map_err(|err| Fail::Bug(anyhow!("{err}")))?;
    let links = attach(&mut ebpf, &opt.cgroup)?;

    let table = Arc::new(Mutex::new(Table::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let reader_table = Arc::clone(&table);
    let reader_stop = Arc::clone(&stop);
    let reader = thread::spawn(move || {
        while !reader_stop.load(Ordering::Relaxed) {
            let mut saw = false;
            while let Some(item) = ring.next() {
                saw = true;
                if item.len() < std::mem::size_of::<NetEvent>() {
                    continue;
                }
                let mut event = NetEvent::zero();
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        item.as_ptr(),
                        &mut event as *mut NetEvent as *mut u8,
                        std::mem::size_of::<NetEvent>(),
                    );
                }
                reader_table.lock().expect("table").ingest(&event, now_ms());
            }
            if let Ok(value) = drops.get(&0, 0) {
                reader_table.lock().expect("table").set_drops(value);
            }
            if !saw {
                thread::sleep(Duration::from_millis(20));
            }
        }
    });

    let addr: SocketAddr = opt
        .metrics
        .parse()
        .with_context(|| format!("metrics address {}", opt.metrics))
        .map_err(Fail::Bug)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| Fail::Bug(err.into()))?;
    let bound = rt.block_on(serve_metrics(addr, Arc::clone(&table), Arc::clone(&stop)))?;
    eprintln!("netscope: metrics http://{bound}/metrics");

    let enrich_table = Arc::clone(&table);
    let enrich_stop = Arc::clone(&stop);
    rt.spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tick.tick().await;
            if enrich_stop.load(Ordering::Relaxed) {
                break;
            }
            let Ok(owners) =
                tokio::task::spawn_blocking(|| read_socket_owners(Path::new("/proc"))).await
            else {
                continue;
            };
            enrich_table.lock().expect("table").enrich(&owners);
        }
    });

    let ui = if opt.headless {
        rt.block_on(wait_headless(opt.duration_ms));
        Ok(())
    } else {
        let deadline = opt.duration_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        run_tui(&table, &stop, deadline)
    };

    stop.store(true, Ordering::Relaxed);
    let _ = reader.join();
    detach(&mut ebpf, links);
    drop(ebpf);
    let snap = table.lock().expect("table").snapshot();
    eprintln!(
        "netscope: stopped events={} drops={} flows={} bytes={}",
        snap.events, snap.drops, snap.flows.len(), snap.bytes
    );
    ui
}

fn probe(opt: &Opt) -> Result<(), Fail> {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default();
    let kernel = kernel.trim();
    let btf = Path::new("/sys/kernel/btf/vmlinux").exists();
    let jit = std::fs::read_to_string("/proc/sys/net/core/bpf_jit_enable").ok();
    let tracefs = Path::new("/sys/kernel/tracing/events").exists()
        || Path::new("/sys/kernel/debug/tracing/events").exists();
    eprintln!(
        "netscope: kernel={kernel} btf={btf} bpf_jit={} tracefs={tracefs} cgroup={}",
        jit.as_deref().map(str::trim).unwrap_or("absent"),
        opt.cgroup.display()
    );
    if !opt.cgroup.is_dir() {
        return Err(Fail::Env(format!(
            "{} is not a cgroup directory",
            opt.cgroup.display()
        )));
    }
    if std::fs::read_to_string(opt.cgroup.join("cgroup.procs")).is_err() {
        return Err(Fail::Env(format!(
            "{} does not look like cgroup v2 (no cgroup.procs)",
            opt.cgroup.display()
        )));
    }
    Ok(())
}

fn load_ebpf() -> Result<Ebpf, Fail> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim);
    }
    let bytes = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/netscope"));
    Ebpf::load(bytes).map_err(|err| classify(err.into()))
}

struct Links {
    ingress: CgroupSkbLinkId,
    egress: CgroupSkbLinkId,
}

fn attach(ebpf: &mut Ebpf, cgroup: &Path) -> Result<Links, Fail> {
    let file = File::open(cgroup).map_err(|err| {
        if err.kind() == std::io::ErrorKind::PermissionDenied
            || err.kind() == std::io::ErrorKind::NotFound
        {
            Fail::Env(format!("open {}: {err}", cgroup.display()))
        } else {
            Fail::Bug(err.into())
        }
    })?;

    let ingress_id = {
        let ingress: &mut CgroupSkb = ebpf
            .program_mut("netscope_ingress")
            .context("program netscope_ingress missing")
            .map_err(Fail::Bug)?
            .try_into()
            .map_err(|err: aya::programs::ProgramError| classify(err.into()))?;
        ingress.load().map_err(|err| classify(err.into()))?;
        ingress
            .attach(&file, CgroupSkbAttachType::Ingress, CgroupAttachMode::Single)
            .map_err(|err| classify(err.into()))?
    };
    let egress_id = {
        let egress: &mut CgroupSkb = ebpf
            .program_mut("netscope_egress")
            .context("program netscope_egress missing")
            .map_err(Fail::Bug)?
            .try_into()
            .map_err(|err: aya::programs::ProgramError| classify(err.into()))?;
        egress.load().map_err(|err| classify(err.into()))?;
        egress
            .attach(&file, CgroupSkbAttachType::Egress, CgroupAttachMode::Single)
            .map_err(|err| classify(err.into()))?
    };
    eprintln!("netscope: attached cgroup_skb ingress+egress");
    Ok(Links {
        ingress: ingress_id,
        egress: egress_id,
    })
}

fn detach(ebpf: &mut Ebpf, links: Links) {
    if let Some(program) = ebpf.program_mut("netscope_ingress") {
        if let Ok(program) = <&mut CgroupSkb>::try_from(program) {
            let _ = program.detach(links.ingress);
        }
    }
    if let Some(program) = ebpf.program_mut("netscope_egress") {
        if let Ok(program) = <&mut CgroupSkb>::try_from(program) {
            let _ = program.detach(links.egress);
        }
    }
}

fn classify(err: anyhow::Error) -> Fail {
    let text = format!("{err:#}");
    let lower = text.to_ascii_lowercase();
    if lower.contains("operation not permitted")
        || lower.contains("permission denied")
        || lower.contains("eperm")
        || lower.contains("eacces")
    {
        let extra = if lower.contains("bpf_link_create") {
            " The program loaded. Attach was refused. On a nested cgroup this is what the kernel returns when a parent already has a non-overridable cgroup-bpf program, or when this namespace cannot create bpf links. No packets were counted."
        } else {
            ""
        };
        Fail::Env(format!("{text}{extra}"))
    } else {
        Fail::Bug(err)
    }
}

async fn serve_metrics(
    addr: SocketAddr,
    table: Arc<Mutex<Table>>,
    stop: Arc<AtomicBool>,
) -> Result<SocketAddr, Fail> {
    let listener = TcpListener::bind(addr).await.map_err(|err| {
        if err.kind() == std::io::ErrorKind::PermissionDenied {
            Fail::Env(format!("bind {addr}: {err}"))
        } else {
            Fail::Bug(err.into())
        }
    })?;
    let bound = listener.local_addr().map_err(|err| Fail::Bug(err.into()))?;
    tokio::spawn(async move {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let accept = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
            let Ok(Ok((mut socket, _))) = accept else {
                continue;
            };
            let table = Arc::clone(&table);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = tokio::time::timeout(Duration::from_millis(500), socket.read(&mut buf)).await;
                let body = {
                    let snap = table.lock().expect("table").snapshot();
                    render(&snap)
                };
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(body.as_bytes()).await;
            });
        }
    });
    Ok(bound)
}

async fn wait_headless(duration_ms: Option<u64>) {
    match duration_ms {
        Some(ms) => {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(ms)) => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        None => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

fn run_tui(
    table: &Mutex<Table>,
    stop: &AtomicBool,
    deadline: Option<Instant>,
) -> Result<(), Fail> {
    if !std::io::stdout().is_terminal() {
        return Err(Fail::Env(
            "stdout is not a terminal; pass --headless".into(),
        ));
    }
    enable_raw_mode().map_err(|err| Fail::Bug(err.into()))?;
    let mut stdout = std::io::stdout();
    stdout
        .execute(EnterAlternateScreen)
        .map_err(|err| Fail::Bug(err.into()))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|err| Fail::Bug(err.into()))?;
    let result = (|| -> Result<(), Fail> {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                break;
            }
            let snap = table.lock().expect("table").snapshot();
            terminal
                .draw(|frame| draw(frame, &snap))
                .map_err(|err| Fail::Bug(err.into()))?;
            if event::poll(Duration::from_millis(200)).map_err(|err| Fail::Bug(err.into()))? {
                if let Event::Key(key) = event::read().map_err(|err| Fail::Bug(err.into()))? {
                    let quit = matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                        || (key.modifiers.contains(KeyModifiers::CONTROL)
                            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C')));
                    if quit {
                        break;
                    }
                }
            }
        }
        Ok(())
    })();
    disable_raw_mode().ok();
    let _ = terminal.backend_mut().execute(LeaveAlternateScreen);
    let _ = terminal.show_cursor();
    result
}
