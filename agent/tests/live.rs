//! Attaches the real cgroup/skb programs and checks that a localhost TCP
//! exchange shows up in the Prometheus output.
//!
//! Exit code 2 from the agent means this kernel or this user cannot load
//! eBPF. That skips the test. A verifier rejection or a silent hook is a
//! failure: we do not invent packets to paper over it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn observes_live_tcp() {
    let metrics = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_netscope"))
        .args([
            "--headless",
            "--duration-ms",
            "3500",
            "--metrics",
            &format!("127.0.0.1:{metrics}"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn netscope");

    let stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match std::io::BufRead::read_line(&mut reader, &mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if tx.send(line.clone()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut log = String::new();
    let started = Instant::now();
    let mut ready = false;
    while started.elapsed() < Duration::from_secs(60) {
        while let Ok(line) = rx.try_recv() {
            eprint!("{line}");
            log.push_str(&line);
            if line.contains("metrics http://") {
                ready = true;
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                thread::sleep(Duration::from_millis(50));
                while let Ok(line) = rx.try_recv() {
                    eprint!("{line}");
                    log.push_str(&line);
                }
                if status.code() == Some(2) {
                    eprintln!("skipping live eBPF test, agent reported an environment limit:\n{log}");
                    return;
                }
                panic!("agent exited early ({status}) before metrics were up:\n{log}");
            }
            Ok(None) => {}
            Err(err) => panic!("try_wait: {err}"),
        }
        if ready {
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    assert!(ready, "agent never announced metrics:\n{log}");

    let (listen_port, payload) = exchange();
    let needle_local = format!("lport=\"{listen_port}\"");
    let needle_remote = format!("rport=\"{listen_port}\"");

    let mut body = String::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Some(text) = http_get(metrics) {
            body = text;
            if body.contains(&needle_local) || body.contains(&needle_remote) {
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    let status = wait_child(&mut child, Duration::from_secs(20));
    while let Ok(line) = rx.try_recv() {
        eprint!("{line}");
        log.push_str(&line);
    }
    assert!(
        status.code() == Some(0),
        "agent exit {status}, log:\n{log}"
    );
    assert!(
        body.contains("netscope_events_total") && !body.contains("netscope_events_total 0\n"),
        "no packets counted. payload={payload} body:\n{body}\nlog:\n{log}"
    );
    assert!(
        body.contains(&needle_local) || body.contains(&needle_remote),
        "live TCP port {listen_port} missing from metrics. body:\n{body}\nlog:\n{log}"
    );
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn exchange() -> (u16, usize) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 128];
        let n = sock.read(&mut buf).unwrap_or(0);
        let _ = sock.write_all(b"netscope-pong");
        n
    });
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let payload = b"netscope-live-tcp-payload";
    client.write_all(payload).unwrap();
    let mut buf = [0u8; 32];
    let _ = client.read(&mut buf);
    drop(client);
    let n = server.join().unwrap();
    (port, n)
}

fn http_get(port: u16) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or(&text);
    Some(body.to_string())
}

fn wait_child(child: &mut std::process::Child, limit: Duration) -> std::process::ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            return child.wait().unwrap();
        }
        thread::sleep(Duration::from_millis(50));
    }
}
