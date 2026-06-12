//! ttystorm — diagnostic reproducer for the OpenVMM hybrid-vsock TTY stream
//! wedge (vim hang during interactive exec on Windows) and the vsock-churn
//! assert crash (`virtio_vsock connections.rs:1093`).
//!
//! Drives a real `tty: true` exec session over a single bidirectional stream
//! connection — exactly the shape `izba exec -it` uses — but with no console
//! involved, so a hang here convicts the VMM-side relay, not izba's terminal
//! code.
//!
//! By default connections go through izbad (GuestRpc + OpenStream splice),
//! the production datapath: round teardown is abrupt on the client side by
//! design, and the daemon must launder it into a graceful vsock teardown
//! (the churn drain). `--direct` dials `run/vsock.sock` itself — the
//! pre-daemon shape that reproduces the raw OpenVMM assert; expect it to
//! KILL the VM on an unpatched openvmm.exe. Requires a running daemon
//! unless `--direct` (it never auto-starts one: `current_exe` here is
//! ttystorm, not izba).
//!
//! Usage: ttystorm <sandbox> <burst|bidi|mixed|inonly> [rounds] [kib] [--direct]
//!   burst:  guest blasts `kib` KiB at the pty; host only reads
//!   bidi:   guest runs raw-mode `cat`; host writes `kib` KiB while reading
//!           the loopback (sustained two-way pressure, same connection)
//!   mixed:  guest blasts `kib` KiB while host trickles tiny writes in —
//!           vim's exact shape (redraw burst out, terminal replies in)
//!   inonly: raw-mode no-echo guest sink reads `kib` KiB; host only writes
//!           (unidirectional host->guest control)
//!   chop:   guest blasts a burst; host reads once, stops reading, then
//!           drops the connection with the relay write wedged — the
//!           connections.rs:1093 assert reproducer (see fn doc)
//!
//! All progress is reported on stderr (unbuffered). A watchdog thread kills
//! the run with exit 2 if neither direction moves for 15 s — socket read
//! timeouts are silently ignored on Windows AF_UNIX, so blocking reads can
//! never be trusted to wake up on their own.

use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use izba_core::sandbox;
use izba_proto::{
    read_frame, write_frame, ExecRequest, Request, Response, StreamAttach, StreamKind, StreamOpen,
};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const STALL: Duration = Duration::from_secs(15);

struct Progress {
    rx: AtomicU64,
    tx: AtomicU64,
}

/// How ttystorm reaches the guest: through izbad (production shape, default)
/// or dialing `run/vsock.sock` directly (`--direct`, the raw-VMM stressor).
struct Target {
    paths: Paths,
    name: String,
    direct: bool,
}

impl Target {
    /// One control RPC. Daemon path opens a fresh guest connection per call
    /// (exactly what `izba exec` does via GuestRpc).
    fn rpc(&self, req: &Request) -> anyhow::Result<Response> {
        if self.direct {
            let connector = sandbox::default_connector();
            let mut control = sandbox::control(&self.paths, &self.name, &connector)?;
            write_frame(&mut control, req)?;
            Ok(read_frame(&mut control)?)
        } else {
            self.daemon()?.guest_rpc(&self.name, req)
        }
    }

    fn stream(&self) -> anyhow::Result<izba_core::vmm::UdsStream> {
        if self.direct {
            sandbox::default_stream_connector()(&self.paths, &self.name)
        } else {
            self.daemon()?.open_stream_on_self(&self.name)
        }
    }

    fn daemon(&self) -> anyhow::Result<DaemonClient> {
        DaemonClient::connect_existing(&self.paths)?.ok_or_else(|| {
            anyhow::anyhow!(
                "no izbad running (ttystorm never auto-starts one) — \
                 run the sandbox via the izba CLI first, or pass --direct"
            )
        })
    }
}

fn main() -> anyhow::Result<()> {
    let (mut pos, mut direct) = (Vec::new(), false);
    for a in std::env::args().skip(1) {
        if a == "--direct" {
            direct = true;
        } else {
            pos.push(a);
        }
    }
    let mut args = pos.into_iter();
    let name = args.next().unwrap_or_else(|| "ws-validate".into());
    let mode = args.next().unwrap_or_else(|| "burst".into());
    let rounds: u32 = args.next().map(|s| s.parse().unwrap()).unwrap_or(3);
    let kib: usize = args.next().map(|s| s.parse().unwrap()).unwrap_or(1024);
    let t = Target {
        paths: Paths::from_env_or_default(None),
        name,
        direct,
    };
    eprintln!(
        "path: {}",
        if direct { "DIRECT vsock" } else { "via izbad" }
    );

    let progress = Arc::new(Progress {
        rx: AtomicU64::new(0),
        tx: AtomicU64::new(0),
    });
    spawn_watchdog(Arc::clone(&progress), mode.clone());

    for round in 1..=rounds {
        let start = Instant::now();
        match mode.as_str() {
            "burst" => burst(&t, kib, &progress)?,
            "bidi" => bidi(&t, kib, &progress)?,
            "mixed" => mixed(&t, kib, &progress)?,
            "inonly" => inonly(&t, kib, &progress)?,
            "bidiecho" => bidiecho(&t, kib, &progress)?,
            "floodfast" => floodfast(&t, kib, &progress)?,
            "chop" => chop(&t, kib, &progress)?,
            "reactive" => reactive(&t, kib, &progress)?,
            "vim" => vim_probe(&t, &progress)?,
            other => anyhow::bail!("unknown mode {other:?}"),
        }
        eprintln!("round {round}: PASS ({:?})", start.elapsed());
    }
    eprintln!("ALL ROUNDS PASS");
    Ok(())
}

/// Exit 2 with a stats line if no byte moves in either direction for STALL.
fn spawn_watchdog(progress: Arc<Progress>, mode: String) {
    std::thread::spawn(move || {
        let mut last = (0u64, 0u64);
        let mut since = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let now = (
                progress.rx.load(Ordering::Relaxed),
                progress.tx.load(Ordering::Relaxed),
            );
            if now != last {
                last = now;
                since = Instant::now();
            } else if since.elapsed() >= STALL {
                eprintln!(
                    "WEDGED ({mode}): no progress for {STALL:?} at rx={} tx={}",
                    now.0, now.1
                );
                std::process::exit(2);
            }
        }
    });
}

fn exec_tty(t: &Target, argv: &[&str]) -> anyhow::Result<u32> {
    let req = Request::Exec(ExecRequest {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env: vec![("TERM".into(), "xterm-256color".into())],
        cwd: "/workspace".into(),
        tty: true,
        uid: 0,
        gid: 0,
    });
    match t.rpc(&req)? {
        Response::ExecStarted { exec_id } => Ok(exec_id),
        other => anyhow::bail!("unexpected exec reply: {other:?}"),
    }
}

fn attach_tty(t: &Target, exec_id: u32) -> anyhow::Result<izba_core::vmm::UdsStream> {
    let mut conn = t.stream()?;
    write_frame(
        &mut conn,
        &StreamOpen::Attach(StreamAttach {
            exec_id,
            kind: StreamKind::Tty,
        }),
    )?;
    Ok(conn)
}

/// Read until guest half-closes (child exit); count into progress.rx.
fn drain_to_eof(stream: &izba_core::vmm::UdsStream, progress: &Progress) -> anyhow::Result<u64> {
    let mut got = 0u64;
    let mut buf = [0u8; 8192];
    let mut s = stream;
    loop {
        match s.read(&mut buf) {
            Ok(0) => return Ok(got),
            Ok(n) => {
                got += n as u64;
                progress.rx.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn burst(t: &Target, kib: usize, progress: &Progress) -> anyhow::Result<()> {
    let cmd = format!("dd if=/dev/zero bs=1024 count={kib} 2>/dev/null | base64");
    let exec_id = exec_tty(t, &["sh", "-c", &cmd])?;
    let stream = attach_tty(t, exec_id)?;
    let got = drain_to_eof(&stream, progress)?;
    eprintln!("  burst: read {got} bytes to EOF");
    Ok(())
}

/// Read until `marker` shows up (the guest's signal that raw mode is set, so
/// nothing we write afterwards can be eaten by canonical-mode buffering).
/// Returns any payload bytes that arrived after the marker.
fn await_marker(
    stream: &izba_core::vmm::UdsStream,
    marker: &[u8],
    progress: &Progress,
) -> anyhow::Result<Vec<u8>> {
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    let mut s = stream;
    loop {
        match s.read(&mut buf) {
            Ok(0) => anyhow::bail!("EOF while waiting for {marker:?}"),
            Ok(n) => {
                seen.extend_from_slice(&buf[..n]);
                progress.rx.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => return Err(e.into()),
        }
        if let Some(pos) = seen.windows(marker.len()).position(|w| w == marker) {
            return Ok(seen[pos + marker.len()..].to_vec());
        }
    }
}

fn bidi(t: &Target, kib: usize, progress: &Progress) -> anyhow::Result<()> {
    // Raw mode, no echo: the only loopback is cat itself, so expect exactly
    // `total` bytes back, then EOF cannot happen (cat stays open) — we stop
    // once the loopback is complete.
    let exec_id = exec_tty(t, &["sh", "-c", "stty raw -echo && echo READY && cat"])?;
    let stream = attach_tty(t, exec_id)?;
    let leftover = await_marker(&stream, b"READY", progress)?;
    let writer_stream = stream.try_clone()?;

    let total = (kib * 1024) as u64;
    let wprog = Arc::new(AtomicU64::new(0));
    let wprog2 = Arc::clone(&wprog);
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        let chunk = [b'x'; 4096];
        let mut s = &writer_stream;
        let mut sent = 0u64;
        while sent < total {
            let n = (total - sent).min(chunk.len() as u64) as usize;
            s.write_all(&chunk[..n])?;
            sent += n as u64;
            wprog2.store(sent, Ordering::Relaxed);
        }
        Ok(())
    });

    let mut got = leftover.len() as u64; // stray newline after READY, if any
    let mut buf = [0u8; 8192];
    let mut s = &stream;
    while got < total {
        match s.read(&mut buf) {
            Ok(0) => anyhow::bail!("unexpected EOF in bidi after {got} bytes"),
            Ok(n) => {
                got += n as u64;
                progress.rx.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => return Err(e.into()),
        }
        progress
            .tx
            .store(wprog.load(Ordering::Relaxed), Ordering::Relaxed);
    }
    writer.join().expect("writer panicked")?;
    eprintln!("  bidi: {total} bytes looped back");
    Ok(())
}

/// vim's shape: heavy guest->host burst while the host trickles tiny writes
/// (terminal query responses) into the same connection.
fn mixed(t: &Target, kib: usize, progress: &Progress) -> anyhow::Result<()> {
    let cmd = format!("stty raw -echo && dd if=/dev/zero bs=1024 count={kib} 2>/dev/null | base64");
    let exec_id = exec_tty(t, &["sh", "-c", &cmd])?;
    let stream = attach_tty(t, exec_id)?;
    let writer_stream = stream.try_clone()?;

    let done = Arc::new(AtomicU64::new(0));
    let done2 = Arc::clone(&done);
    let wprog = Arc::new(AtomicU64::new(0));
    let wprog2 = Arc::clone(&wprog);
    let writer = std::thread::spawn(move || {
        // ~20 tiny writes/s, like a terminal answering DA/DSR queries.
        let mut s = &writer_stream;
        let mut sent = 0u64;
        while done2.load(Ordering::Relaxed) == 0 {
            if s.write_all(b"\x1b[1;1R").is_err() {
                return sent; // guest side already gone
            }
            sent += 6;
            wprog2.store(sent, Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(50));
        }
        sent
    });

    let mut got = 0u64;
    let mut buf = [0u8; 8192];
    let mut s = &stream;
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                got += n as u64;
                progress.rx.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => return Err(e.into()),
        }
        progress
            .tx
            .store(wprog.load(Ordering::Relaxed), Ordering::Relaxed);
    }
    done.store(1, Ordering::Relaxed);
    let sent = writer.join().expect("writer panicked");
    eprintln!("  mixed: read {got} bytes to EOF, trickled {sent} bytes in");
    Ok(())
}

/// v1's exact shape, isolated to the echo factor: canonical mode, ECHO on,
/// newline-terminated lines, but READY-gated so there is no attach race.
/// Every line we send comes back twice (pty echo + cat), so expect ~2x.
fn bidiecho(t: &Target, kib: usize, progress: &Progress) -> anyhow::Result<()> {
    let exec_id = exec_tty(t, &["sh", "-c", "echo READY && cat"])?;
    let stream = attach_tty(t, exec_id)?;
    let leftover = await_marker(&stream, b"READY", progress)?;
    let writer_stream = stream.try_clone()?;

    let total = (kib * 1024) as u64;
    let wprog = Arc::new(AtomicU64::new(0));
    let wprog2 = Arc::clone(&wprog);
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        let line = [b"x".repeat(63), b"\n".to_vec()].concat();
        let mut s = &writer_stream;
        let mut sent = 0u64;
        while sent < total {
            s.write_all(&line)?;
            sent += line.len() as u64;
            wprog2.store(sent, Ordering::Relaxed);
        }
        Ok(())
    });

    let mut got = leftover.len() as u64;
    let mut buf = [0u8; 8192];
    let mut s = &stream;
    while got < total * 2 {
        match s.read(&mut buf) {
            Ok(0) => anyhow::bail!("unexpected EOF in bidiecho after {got} bytes"),
            Ok(n) => {
                got += n as u64;
                progress.rx.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => return Err(e.into()),
        }
        progress
            .tx
            .store(wprog.load(Ordering::Relaxed), Ordering::Relaxed);
    }
    writer.join().expect("writer panicked")?;
    eprintln!("  bidiecho: sent {total}, read {got} bytes (echo + cat)");
    Ok(())
}

/// v1's exact shape, isolated to the attach race: raw-mode cat, but the host
/// flood starts the instant the StreamAttach frame is written — racing the
/// relay's connection establishment and the guest-side attach plumbing.
fn floodfast(t: &Target, kib: usize, progress: &Progress) -> anyhow::Result<()> {
    let exec_id = exec_tty(t, &["sh", "-c", "stty raw -echo && cat"])?;
    let stream = attach_tty(t, exec_id)?;
    let writer_stream = stream.try_clone()?;

    let total = (kib * 1024) as u64;
    let wprog = Arc::new(AtomicU64::new(0));
    let wprog2 = Arc::clone(&wprog);
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        let chunk = [b'x'; 4096];
        let mut s = &writer_stream;
        let mut sent = 0u64;
        while sent < total {
            let n = (total - sent).min(chunk.len() as u64) as usize;
            s.write_all(&chunk[..n])?;
            sent += n as u64;
            wprog2.store(sent, Ordering::Relaxed);
        }
        Ok(())
    });

    // Pre-raw canonical buffering may eat a prefix (sh hasn't run stty yet
    // when the flood lands), so don't demand exact loopback — demand
    // continuous progress until the writer finishes and at least half the
    // flood comes back. Keep reading until BOTH hold: stopping reads while
    // the writer still has bytes to push deadlocks on loopback backpressure
    // once the in-flight remainder exceeds the path's buffering (cat blocks
    // writing the echo, so it stops reading our flood). The watchdog
    // converts a true stall into exit 2. The round still ENDS with an
    // abrupt drop while cat holds unread echo — the churn stressor.
    // (`wprog == total` is stored before the final chunk's echo can arrive
    // back, so the loop can't block on a read with nothing left in flight.)
    let mut got = 0u64;
    let mut buf = [0u8; 8192];
    let mut s = &stream;
    while got < total / 2 || wprog.load(Ordering::Relaxed) < total {
        match s.read(&mut buf) {
            Ok(0) => anyhow::bail!("unexpected EOF in floodfast after {got} bytes"),
            Ok(n) => {
                got += n as u64;
                progress.rx.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => return Err(e.into()),
        }
        progress
            .tx
            .store(wprog.load(Ordering::Relaxed), Ordering::Relaxed);
    }
    writer.join().expect("writer panicked")?;
    eprintln!("  floodfast: flood survived, {got} bytes back");
    Ok(())
}

/// The churn killer: attach to a guest blasting a bounded burst, read one
/// chunk to prove flow, then STOP reading so every buffer between the guest
/// and us fills and the VMM's relay write to our socket blocks — then drop
/// the connection abruptly with that write pending. With `--direct` on an
/// unpatched openvmm.exe this is the surgical reproducer for the
/// `virtio_vsock connections.rs:1093` assert (the write-ready flush fails,
/// SendReset is queued WITHOUT removing the connection, the next poll
/// panic-aborts the VM). Through izbad the splice drains the leg to EOF
/// instead, and the VM must survive.
fn chop(t: &Target, kib: usize, progress: &Progress) -> anyhow::Result<()> {
    let cmd = format!("dd if=/dev/zero bs=1024 count={kib} 2>/dev/null | base64");
    let exec_id = exec_tty(t, &["sh", "-c", &cmd])?;
    let stream = attach_tty(t, exec_id)?;
    let mut buf = [0u8; 8192];
    let mut s = &stream;
    let n = s.read(&mut buf)?;
    anyhow::ensure!(n > 0, "no burst bytes before chop");
    progress.rx.fetch_add(n as u64, Ordering::Relaxed);
    // Let the unread burst wedge the relay: guest -> vsock -> VMM -> (full
    // socket buffer) before the abrupt close.
    std::thread::sleep(Duration::from_millis(300));
    progress.tx.fetch_add(1, Ordering::Relaxed); // keep the watchdog fed
    drop(stream);
    Ok(())
}

/// vim's established-connection shape, maximally tightened: the guest blasts
/// a burst and the host answers EVERY read with an immediate tiny write —
/// the way a terminal answers DA/DSR queries — so reverse writes land while
/// forward data is in flight on the same connection.
fn reactive(t: &Target, kib: usize, progress: &Progress) -> anyhow::Result<()> {
    let cmd = format!("stty raw -echo && dd if=/dev/zero bs=1024 count={kib} 2>/dev/null | base64");
    let exec_id = exec_tty(t, &["sh", "-c", &cmd])?;
    let stream = attach_tty(t, exec_id)?;
    let mut writer_stream = stream.try_clone()?;

    let mut got = 0u64;
    let mut answered = 0u64;
    let mut buf = [0u8; 8192];
    let mut s = &stream;
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                got += n as u64;
                progress.rx.fetch_add(n as u64, Ordering::Relaxed);
                // Answer every chunk like a terminal answering a query.
                if writer_stream.write_all(b"\x1b[1;1R").is_ok() {
                    answered += 6;
                    progress.tx.store(answered, Ordering::Relaxed);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    eprintln!("  reactive: read {got} bytes to EOF, answered {answered} bytes");
    Ok(())
}

/// Drive a real `vim` over a tty stream exactly like the CLI would, but with
/// the host side fully scripted, so we can see what vim emits and whether it
/// goes silent waiting for a terminal reply. Sets a 24x80 winsize first (the
/// CLI resizes before the program looks), opens vim on a file, then dumps
/// every byte vim sends with inter-chunk timing. Quits vim after 6 s.
fn vim_probe(t: &Target, progress: &Progress) -> anyhow::Result<()> {
    use izba_proto::Request;

    // Make a file with enough lines that vim must paint a full screen.
    let exec_setup = exec_tty(
        t,
        &["sh", "-c", "seq 1 441 > /tmp/probe.txt; echo SETUP_DONE"],
    )?;
    let setup_stream = attach_tty(t, exec_setup)?;
    let _ = await_marker(&setup_stream, b"SETUP_DONE", progress)?;
    drop(setup_stream);

    // Start vim under a tty. Default config (NOT -u NONE) so vim runs its
    // startup terminal-capability probes (u7 cursor-position request, DA1,
    // etc.) — the thing minimal vim skips and the suspected hang trigger.
    let exec_id = exec_tty(t, &["vim", "/tmp/probe.txt"])?;

    // Size the pty to 80x24 BEFORE attaching the stream — same order the CLI
    // uses (resize() runs before the program looks at the winsize).
    match t.rpc(&Request::Resize {
        exec_id,
        cols: 80,
        rows: 24,
    })? {
        Response::Ok => {}
        other => eprintln!("  (resize reply: {other:?})"),
    }

    let stream = attach_tty(t, exec_id)?;
    let mut writer = stream.try_clone()?;

    // Reader thread: log every chunk vim emits with a timestamp, so a silent
    // gap (vim blocked on a terminal-reply it never gets) is obvious. Reports
    // bytes seen through a shared counter the main thread relays to the
    // watchdog.
    let rx_seen = Arc::new(AtomicU64::new(0));
    let reader = std::thread::spawn({
        let stream = stream.try_clone()?;
        let rx_seen = Arc::clone(&rx_seen);
        move || {
            let mut s = &stream;
            let mut buf = [0u8; 8192];
            let t0 = Instant::now();
            let mut total = 0u64;
            loop {
                match s.read(&mut buf) {
                    Ok(0) => {
                        eprintln!("  [{:?}] vim stream EOF after {total} bytes", t0.elapsed());
                        return;
                    }
                    Ok(n) => {
                        total += n as u64;
                        rx_seen.store(total, Ordering::Relaxed);
                        eprintln!(
                            "  [{:?}] +{n} bytes (total {total}); head={}",
                            t0.elapsed(),
                            escape_prefix(&buf[..n], 48)
                        );
                    }
                    Err(e) => {
                        eprintln!("  [{:?}] vim stream read error: {e}", t0.elapsed());
                        return;
                    }
                }
            }
        }
    });

    // Let vim paint, watching for the silent gap. Relay reader progress to the
    // watchdog so it doesn't false-trip while we deliberately wait.
    for _ in 0..60 {
        std::thread::sleep(Duration::from_millis(100));
        progress
            .rx
            .store(rx_seen.load(Ordering::Relaxed), Ordering::Relaxed);
        progress.tx.fetch_add(1, Ordering::Relaxed);
    }

    // Try answering common terminal queries vim/xterm-256color may send:
    // primary device attributes and cursor position report. If vim was
    // blocked waiting for these, output should resume right after.
    eprintln!("  --- injecting DA1 + DSR replies ---");
    let _ = writer.write_all(b"\x1b[?62;c"); // DA1 response
    let _ = writer.write_all(b"\x1b[24;1R"); // cursor position report
    std::thread::sleep(Duration::from_secs(3));

    // Quit vim: ESC, then :q!<CR>
    eprintln!("  --- sending :q! ---");
    let _ = writer.write_all(b"\x1b:q!\r");
    std::thread::sleep(Duration::from_secs(2));

    let _ = stream.shutdown(std::net::Shutdown::Both);
    let _ = reader.join();
    eprintln!("  vim_probe done");
    Ok(())
}

fn escape_prefix(b: &[u8], n: usize) -> String {
    let mut out = String::new();
    for &c in b.iter().take(n) {
        match c {
            0x1b => out.push_str("\\e"),
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            0x20..=0x7e => out.push(c as char),
            _ => out.push_str(&format!("\\x{c:02x}")),
        }
    }
    if b.len() > n {
        out.push_str("...");
    }
    out
}

/// Pure host->guest on the tty connection: raw, no echo, guest just counts.
fn inonly(t: &Target, kib: usize, progress: &Progress) -> anyhow::Result<()> {
    let total = kib * 1024;
    let cmd = format!("stty raw -echo && echo READY && head -c {total} > /dev/null && echo DONE");
    let exec_id = exec_tty(t, &["sh", "-c", &cmd])?;
    let stream = attach_tty(t, exec_id)?;
    let _ = await_marker(&stream, b"READY", progress)?;
    let writer_stream = stream.try_clone()?;

    let wprog = Arc::new(AtomicU64::new(0));
    let wprog2 = Arc::clone(&wprog);
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        let chunk = [b'x'; 4096];
        let mut s = &writer_stream;
        let mut sent = 0usize;
        while sent < total {
            let n = (total - sent).min(chunk.len());
            s.write_all(&chunk[..n])?;
            sent += n;
            wprog2.store(sent as u64, Ordering::Relaxed);
        }
        Ok(())
    });

    // Expect "DONE" + EOF once the guest has swallowed every byte.
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    let mut s = &stream;
    loop {
        // Keep the watchdog fed with writer progress while we wait.
        progress
            .tx
            .store(wprog.load(Ordering::Relaxed), Ordering::Relaxed);
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                progress.rx.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => return Err(e.into()),
        }
        if out.windows(4).any(|w| w == b"DONE") {
            break;
        }
    }
    writer.join().expect("writer panicked")?;
    anyhow::ensure!(
        out.windows(4).any(|w| w == b"DONE"),
        "guest sink exited without DONE marker"
    );
    eprintln!("  inonly: guest swallowed {total} bytes and answered DONE");
    Ok(())
}
