//! End-to-end daemon lifecycle against the real `izba` binary and a real
//! microVM. Gated behind `IZBA_INTEGRATION=1` (same convention as the core
//! suite; see docs/testing.md). Run serially:
//!
//! ```text
//! IZBA_INTEGRATION=1 IZBA_KERNEL=... IZBA_INITRAMFS=... \
//! cargo test -p izba-cli --test daemon_e2e -- --test-threads=1 --nocapture
//! ```

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

use izba_core::state::{load_json, RunState, STATE_FILE};
use serde_json::Value;

const IMAGE: &str = "alpine:3.20";

fn want() -> bool {
    if std::env::var("IZBA_INTEGRATION").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set IZBA_INTEGRATION=1 to run the daemon e2e");
        return false;
    }
    true
}

fn izba(data: &Path, envs: &[(&str, &str)], args: &[&str]) -> Output {
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_izba"));
    c.env("IZBA_DATA_DIR", data);
    for (k, v) in envs {
        c.env(k, v);
    }
    c.args(args);
    c.output().expect("run izba")
}

fn stdout_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn assert_ok(o: &Output, what: &str) {
    assert!(
        o.status.success(),
        "{what} failed (exit {:?})\nstdout: {}\nstderr: {}",
        o.status.code(),
        stdout_of(o),
        String::from_utf8_lossy(&o.stderr)
    );
}

/// Parse "daemon: running (pid 12345, version 0.1.0, uptime 3s)".
fn daemon_pid(data: &Path, envs: &[(&str, &str)]) -> Option<u32> {
    let o = izba(data, envs, &["daemon", "status"]);
    let out = stdout_of(&o);
    let rest = out.split("(pid ").nth(1)?;
    rest.split(',').next()?.trim().parse().ok()
}

fn daemon_version_of(data: &Path, envs: &[(&str, &str)]) -> Option<String> {
    let o = izba(data, envs, &["daemon", "status"]);
    let out = stdout_of(&o);
    let rest = out.split("version ").nth(1)?;
    Some(rest.split(',').next()?.trim().to_string())
}

/// Minimal HTTP GET with retries (relay/server may need a moment).
fn http_get(port: u16) -> anyhow::Result<String> {
    let mut last: Option<std::io::Error> = None;
    for _ in 0..50 {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(mut s) => {
                s.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
                let mut buf = String::new();
                s.read_to_string(&mut buf)?;
                if let Some(idx) = buf.find("\r\n\r\n") {
                    return Ok(buf[idx + 4..].to_string());
                }
                return Ok(buf);
            }
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("http_get({port}) never connected: {last:?}")
}

/// Standard base64 (RFC 4648 §4) — hand-rolled so the e2e suite gains no
/// dev-dependency for the ~30 bytes of `Authorization: Basic` it needs.
fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for c in input.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// One-shot HTTP GET returning `(status_code, body)`, with optional HTTP Basic
/// credentials — the auth matrix `http_get` (which only ever expected a 200)
/// cannot express.
///
/// Deliberately does NOT retry: callers poll it inside their own deadline loop
/// so a "connection refused" and a "401 arrived" are distinguishable. The read
/// tolerates a server that keeps the socket open despite `Connection: close`
/// (KasmVNC's websockify answers HTTP/1.1) by treating a read timeout as
/// end-of-response rather than an error.
fn http_get_status(
    port: u16,
    path: &str,
    basic_auth: Option<(&str, &str)>,
) -> anyhow::Result<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut req = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    if let Some((user, pass)) = basic_auth {
        let token = base64_encode(format!("{user}:{pass}").as_bytes());
        req.push_str(&format!("Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())?;

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                // The KasmVNC index page is ~10 KB; a megabyte is plenty and
                // bounds a server that streams forever.
                if buf.len() > 1 << 20 {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(e) => return Err(e.into()),
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let code: u16 = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("no HTTP status line in reply: {text:?}"))?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((code, body))
}

/// What a real VNC client does that a plain HTTP GET never does: upgrade the
/// same port to a WebSocket and run the first two RFB steps through it.
///
/// Returns `(upgrade_status, rfb_greeting, security_types)`. The greeting is
/// the server's `RFB 003.00x\n`; the types are the bytes of the
/// `SecurityTypes` list it offers after the client echoes the version back
/// (`1 = None`, `2 = VncAuth`). Everything before this — bind, relay, HTTP,
/// BasicAuth, even the websocket upgrade itself — can be perfectly healthy
/// while the session still dead-ends here, which is exactly the bug this
/// probe exists to catch, so the types are returned rather than merely
/// counted.
///
/// Hand-rolled over `TcpStream`: masking a couple of ≤125-byte client frames
/// and reading two server frames is less code than a websocket dependency,
/// and it keeps the probe honest about the wire.
fn ws_rfb_probe(
    port: u16,
    basic_auth: Option<(&str, &str)>,
) -> anyhow::Result<(u16, Vec<u8>, Vec<u8>)> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;

    // `/websockify` is the path the shipped KasmVNC web client dials, and
    // `Origin` is NOT optional: without it the server answers 404 ("request
    // failed websocket checks"), which would make a broken probe look like a
    // broken server.
    let mut req = format!(
        "GET /websockify HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         Upgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Protocol: binary\r\nOrigin: http://127.0.0.1:{port}\r\n",
        base64_encode(b"izba-e2e-probe16"),
    );
    if let Some((user, pass)) = basic_auth {
        req.push_str(&format!(
            "Authorization: Basic {}\r\n",
            base64_encode(format!("{user}:{pass}").as_bytes())
        ));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())?;

    // Read just past the response headers; anything after them is already
    // websocket framing and must not be consumed by the header parse.
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match s.read(&mut chunk) {
            Ok(0) => anyhow::bail!(
                "connection closed before the websocket response completed: {:?}",
                String::from_utf8_lossy(&buf)
            ),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(e.into()),
        }
        anyhow::ensure!(buf.len() < 1 << 16, "websocket response headers too large");
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let code: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("no HTTP status line in the upgrade reply: {head:?}"))?;
    if code != 101 {
        return Ok((code, Vec::new(), Vec::new()));
    }

    let mut pending: Vec<u8> = buf[head_end..].to_vec();
    let greeting = ws_read_frame(&mut s, &mut pending)?;
    // Echo the server's version back (RFB 3.x step 2) so it proceeds to the
    // security-type list.
    anyhow::ensure!(
        greeting.len() >= 12,
        "short RFB greeting: {:?}",
        String::from_utf8_lossy(&greeting)
    );
    ws_write_frame(&mut s, &greeting[..12])?;
    let security = ws_read_frame(&mut s, &mut pending)?;
    // `<count> <type>…`, or a `0` count meaning the handshake failed outright.
    let types = match security.split_first() {
        Some((&n, rest)) if n as usize <= rest.len() => rest[..n as usize].to_vec(),
        _ => Vec::new(),
    };
    Ok((code, greeting, types))
}

/// One masked client→server binary frame (payload ≤ 125 bytes — every frame
/// this probe sends is a handshake token).
fn ws_write_frame(s: &mut TcpStream, payload: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(payload.len() <= 125, "probe frames stay short");
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    let mut frame = vec![0x82, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    s.write_all(&frame)?;
    Ok(())
}

/// One server→client frame's payload (server frames are never masked; the
/// 7-bit and 16-bit length forms both appear in an RFB stream).
fn ws_read_frame(s: &mut TcpStream, pending: &mut Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let mut fill = |pending: &mut Vec<u8>, want: usize| -> anyhow::Result<()> {
        let mut chunk = [0u8; 4096];
        while pending.len() < want {
            match s.read(&mut chunk) {
                Ok(0) => anyhow::bail!("connection closed mid-frame"),
                Ok(n) => pending.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    };
    fill(pending, 2)?;
    let (mut len, mut off) = ((pending[1] & 0x7f) as usize, 2usize);
    if len == 126 {
        fill(pending, 4)?;
        len = u16::from_be_bytes([pending[2], pending[3]]) as usize;
        off = 4;
    }
    anyhow::ensure!(len < 1 << 20, "unexpectedly large websocket frame: {len}");
    fill(pending, off + len)?;
    let payload = pending[off..off + len].to_vec();
    pending.drain(..off + len);
    Ok(payload)
}

/// Listeners (`st == 0A`) from a `/proc/net/tcp[6]` dump, as
/// `(port, local-address-in-the-kernel's-hex-form)`.
///
/// The ADDRESS is kept, not discarded: `00000000` (wildcard) and `0100007F`
/// (loopback, little-endian 127.0.0.1) are very different security postures,
/// and the VNC listener's `-interface 127.0.0.1` is only actually pinned if a
/// test looks at it.
///
/// `/proc/net/tcp` is kernel-provided, so this works on ANY workload image —
/// unlike `netstat`, which needs the image to ship busybox/net-tools.
fn parse_listeners(proc_net_tcp: &str) -> BTreeSet<(u16, String)> {
    proc_net_tcp
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 || f[3] != "0A" {
                return None;
            }
            let (addr, port) = f[1].rsplit_once(':')?;
            Some((u16::from_str_radix(port, 16).ok()?, addr.to_string()))
        })
        .collect()
}

#[test]
fn daemon_full_lifecycle() {
    if !want() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let no_env: &[(&str, &str)] = &[];

    // [1] First command auto-starts the daemon and runs a workload.
    let o = izba(
        &data,
        no_env,
        &[
            "run",
            "--image",
            IMAGE,
            "--name",
            "e2e",
            &ws_s,
            "--",
            "/bin/true",
        ],
    );
    assert_ok(&o, "run /bin/true");
    assert!(
        data.join("daemon/izbad.sock").exists(),
        "daemon socket exists"
    );
    let pid1 = daemon_pid(&data, no_env).expect("daemon status shows a pid");

    // [2] Lifecycle through the daemon: exec exit codes + cp roundtrip.
    let o = izba(&data, no_env, &["exec", "e2e", "--", "/bin/false"]);
    assert_eq!(o.status.code(), Some(1), "exec false -> 1");
    // Stance B: crun resolves the command inside the container; a missing
    // executable surfaces as crun's stderr diagnostic + crun's exit code (1 on
    // crun 1.28), passed straight through — not the pre-crun 127/CommandNotFound.
    let o = izba(&data, no_env, &["exec", "e2e", "--", "/no/such/cmd"]);
    assert_eq!(o.status.code(), Some(1), "exec missing -> crun rc 1");
    std::fs::write(root.path().join("hello.txt"), b"roundtrip").unwrap();
    let src = root.path().join("hello.txt").to_string_lossy().into_owned();
    assert_ok(
        &izba(&data, no_env, &["cp", &src, "e2e:/tmp/hello.txt"]),
        "cp in",
    );
    let back = root.path().join("back.txt").to_string_lossy().into_owned();
    assert_ok(
        &izba(&data, no_env, &["cp", "e2e:/tmp/hello.txt", &back]),
        "cp out",
    );
    assert_eq!(
        std::fs::read(root.path().join("back.txt")).unwrap(),
        b"roundtrip"
    );

    // [3] Port publish through the daemon (relay = daemon thread).
    // alpine's busybox has no httpd (that's busybox-extras), but its `nc`
    // supports `-l -p -e` — same trick as the core suite's
    // start_guest_httpd. The serve script is written host-side (the
    // workspace is shared into the guest at /workspace).
    std::fs::write(
        ws.join("serve.sh"),
        b"printf 'HTTP/1.0 200 OK\\r\\n\\r\\ndaemon-port-body'\n",
    )
    .unwrap();
    assert_ok(
        &izba(
            &data,
            no_env,
            &[
                "exec",
                "e2e",
                "--",
                "sh",
                "-c",
                "setsid sh -c 'while true; do nc -l -p 8000 -e sh /workspace/serve.sh; done' \
               >/dev/null 2>&1 & sleep 1",
            ],
        ),
        "start guest nc server",
    );
    assert_ok(
        &izba(&data, no_env, &["port", "publish", "e2e", "18091:8000"]),
        "publish",
    );
    let body = http_get(18091).expect("GET through daemon relay");
    assert!(body.contains("daemon-port-body"), "got: {body}");

    // [4] kill -9 the daemon: next CLI adopts; sandbox unharmed; relay back.
    let o = std::process::Command::new("kill")
        .args(["-9", &pid1.to_string()])
        .output()
        .unwrap();
    assert!(o.status.success(), "kill -9 daemon");
    std::thread::sleep(Duration::from_millis(300));
    let o = izba(&data, no_env, &["ls"]);
    assert_ok(&o, "ls after daemon kill");
    assert!(
        stdout_of(&o).contains("running"),
        "sandbox survived daemon kill"
    );
    let pid2 = daemon_pid(&data, no_env).expect("fresh daemon pid");
    assert_ne!(pid1, pid2, "a new daemon was auto-started");
    let body = http_get(18091).expect("relay respawned after adoption");
    assert!(body.contains("daemon-port-body"), "got: {body}");

    // [5] Same-proto rebuild does NOT churn-restart the daemon. Compatibility
    // is gated on DAEMON_PROTO_VERSION, not the display string (commit
    // 14efddb): a client carrying a *different display version* (e.g. a rebuild
    // /redeploy at the same wire proto) connects to the healthy daemon and
    // leaves it — and its live sandbox — untouched. The respawn-on-proto-
    // mismatch path is the unit test `connect_with_restarts_on_proto_mismatch`
    // in client.rs; the proto version is a compile-time constant with no env
    // override, so a real proto mismatch cannot be driven through the binary
    // here. This phase is the e2e mirror of `connect_with_keeps_daemon_on_
    // build_only_diff` against a real daemon carrying a live VM.
    let va: &[(&str, &str)] = &[("IZBA_DAEMON_VERSION", "e2e-A")];
    let vb: &[(&str, &str)] = &[("IZBA_DAEMON_VERSION", "e2e-B")];
    assert_ok(
        &izba(&data, no_env, &["daemon", "stop"]),
        "daemon stop pre-dance",
    );
    assert_ok(&izba(&data, va, &["ls"]), "start daemon as version A");
    assert_eq!(daemon_version_of(&data, va).as_deref(), Some("e2e-A"));
    let pid_a = daemon_pid(&data, va).expect("daemon A pid");
    let o = izba(&data, vb, &["ls"]);
    assert_ok(&o, "client B against same-proto daemon A succeeds");
    assert_eq!(
        daemon_version_of(&data, vb).as_deref(),
        Some("e2e-A"),
        "a display-version-only change must NOT replace a same-proto daemon"
    );
    assert_eq!(
        daemon_pid(&data, vb),
        Some(pid_a),
        "the daemon process is unchanged (no churn-restart on a build-only diff)"
    );
    assert!(
        stdout_of(&o).contains("running"),
        "sandbox untouched by the client's version difference"
    );

    // [6] daemon stop leaves the sandbox running; next command revives.
    assert_ok(&izba(&data, no_env, &["daemon", "stop"]), "daemon stop");
    let o = izba(&data, no_env, &["daemon", "status"]);
    assert!(stdout_of(&o).contains("not running"), "status after stop");
    let o = izba(&data, no_env, &["ls"]);
    assert_ok(&o, "ls revives daemon");
    assert!(stdout_of(&o).contains("running"), "sandbox kept running");

    // [7] Idle-exit: stop the sandbox, restart the daemon with a 1 s idle
    // budget, watch it leave on its own.
    assert_ok(&izba(&data, no_env, &["stop", "e2e"]), "stop sandbox");
    assert_ok(
        &izba(&data, no_env, &["daemon", "stop"]),
        "daemon stop pre-idle",
    );
    let idle: &[(&str, &str)] = &[("IZBA_DAEMON_IDLE_SECS", "1")];
    assert_ok(&izba(&data, idle, &["ls"]), "start daemon with 1s idle");
    // Watch the socket FILE, not `daemon status`: every status probe opens a
    // connection, and connections reset the idle timer — polling via the API
    // would keep the daemon alive forever. The exiting daemon unlinks its
    // socket, so the file vanishing is the exit signal.
    let sock = data.join("daemon/izbad.sock");
    let deadline = Instant::now() + Duration::from_secs(10);
    while sock.exists() {
        assert!(Instant::now() < deadline, "daemon never idle-exited");
        std::thread::sleep(Duration::from_millis(300));
    }
    let o = izba(&data, no_env, &["daemon", "status"]);
    assert!(
        stdout_of(&o).contains("not running"),
        "status agrees the daemon is gone"
    );

    // [8] Cleanup.
    assert_ok(&izba(&data, no_env, &["rm", "--force", "e2e"]), "rm");
    let _ = izba(&data, no_env, &["daemon", "stop"]);
}

/// SSH access against a real microVM: `izba ssh <name> -- <cmd>` round-trip +
/// chroot-isolation proofs + native in-container SFTP.
///
/// Gated behind `IZBA_INTEGRATION=1` (same as the other daemon e2e tests).
/// The initramfs must be built WITH `IZBA_SSHD` embedded — CI does this via the
/// `initramfs` job in `e2e.yml` which passes `IZBA_SSHD=dist/sshd` (which also
/// embeds the vendored static `sftp-server` used by step 6).
///
/// Assertions:
/// 1. `/bin/true` exit-0 via `izba ssh`  — proxy channel is live.
/// 2. Round-trip: `echo ssh-marker-42` stdout is recovered.
/// 3. Container isolation (positive): `cat /etc/alpine-release` works (the
///    session entered the alpine crun container via `crun exec`).
/// 4. Container isolation (negative): `cat /run/izba/ssh/ssh_host_ed25519_key`
///    fails — the host key lives in init-root, outside the container's mount
///    namespace, so it is invisible to the session.
/// 6. Native SFTP (`Subsystem sftp`): a `sftp` put/get byte round-trip through
///    the in-container `sftp-server`, cross-checked against the host workspace
///    share — exercised on this same (already-proven-alive) VM to avoid a
///    separate, CI-flaky microVM boot.
#[test]
fn ssh_access_e2e() {
    if !want() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let no_env: &[(&str, &str)] = &[];

    // [1] Boot a sandbox (the microVM persists after the workload exits).
    let o = izba(
        &data,
        no_env,
        &[
            "run",
            "--image",
            IMAGE,
            "--name",
            "sshe2e",
            &ws_s,
            "--",
            "/bin/true",
        ],
    );
    assert_ok(&o, "run /bin/true (boot)");

    // [2] Core: `izba ssh sshe2e -- /bin/true` exits 0.
    let o = izba(&data, no_env, &["ssh", "sshe2e", "--", "/bin/true"]);
    assert_ok(&o, "ssh /bin/true -> 0");

    // [3] Round-trip: stdout from a remote command is delivered.
    let o = izba(
        &data,
        no_env,
        &["ssh", "sshe2e", "--", "echo", "ssh-marker-42"],
    );
    assert_ok(&o, "ssh echo exits 0");
    assert!(
        stdout_of(&o).contains("ssh-marker-42"),
        "ssh stdout round-trip missing marker; got: {}",
        stdout_of(&o)
    );

    // [4] Container isolation (positive): inside the alpine image via crun exec.
    let o = izba(
        &data,
        no_env,
        &["ssh", "sshe2e", "--", "cat", "/etc/alpine-release"],
    );
    assert_ok(
        &o,
        "ssh cat /etc/alpine-release (proves the session entered the container)",
    );
    assert!(
        !stdout_of(&o).is_empty(),
        "alpine-release must be non-empty"
    );

    // [5] Container isolation (negative): the sshd host key lives in init-root,
    // outside the container's mount namespace.
    let o = izba(
        &data,
        no_env,
        &[
            "ssh",
            "sshe2e",
            "--",
            "cat",
            "/run/izba/ssh/ssh_host_ed25519_key",
        ],
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        !o.status.success(),
        "host key outside the container must be unreadable from the session"
    );
    assert!(
        err.contains("No such file") || err.contains("can't open"),
        "expected a not-found error proving the ssh session connected but the path is absent \
        (chroot isolation), got stderr: {err}"
    );

    // [6] Native in-container SFTP over the SAME sandbox (no extra VM boot — a
    // separate microVM boot is the flakiest thing on constrained CI runners, so
    // we exercise sftp on the VM the ssh checks above just proved alive). The
    // system `sftp` client connects through the same `izba __ssh-proxy`
    // ProxyCommand `izba ssh` uses, requesting the `Subsystem sftp` declared in
    // `hack/sshd_config`. sshd runs that subsystem through root's login shell
    // (`/init -c "<path>"`), which izba-init routes into
    // `crun exec /bin/sh -c "<path>"` → the vendored `sftp-server` INSIDE the
    // container (oci.rs `SFTP_SERVER_GUEST_PATH`). The ssh identity + host-key
    // trust were already warmed by the `izba ssh` calls above.
    //
    // cwd inside the session is /workspace (SSH_SESSION_CWD), so the relative
    // remote paths land in `ws` — which is the host side of that virtiofs share.
    let payload = b"sftp-roundtrip-payload-1337\n";
    let up = root.path().join("up.txt");
    std::fs::write(&up, payload).unwrap();
    let down = root.path().join("down.txt");
    let batch = root.path().join("batch.sftp");
    std::fs::write(
        &batch,
        format!(
            "put {} sftp-uploaded.txt\nget sftp-uploaded.txt {}\n",
            up.display(),
            down.display()
        ),
    )
    .unwrap();
    let o = sftp(&data, "sshe2e", &batch);
    assert!(
        o.status.success(),
        "sftp batch failed (exit {:?})\nstdout: {}\nstderr: {}",
        o.status.code(),
        stdout_of(&o),
        String::from_utf8_lossy(&o.stderr)
    );
    // Downloaded bytes must equal what we uploaded (protocol round-trip through
    // the in-container sftp-server).
    let got = std::fs::read(&down).expect("sftp get must have written down.txt");
    assert_eq!(
        got, payload,
        "sftp get round-trip mismatch: in-container sftp-server did not serve the file"
    );
    // The upload also appears in the host `ws` virtiofs share, confirming the
    // server operated on the CONTAINER filesystem (not sshd's initramfs).
    let host_side = ws.join("sftp-uploaded.txt");
    assert_eq!(
        std::fs::read(&host_side).ok().as_deref(),
        Some(payload.as_slice()),
        "uploaded file must appear in the host workspace share at {}",
        host_side.display()
    );

    // [7] Cleanup.
    assert_ok(
        &izba(&data, no_env, &["rm", "--force", "sshe2e"]),
        "rm sshe2e",
    );
    let _ = izba(&data, no_env, &["daemon", "stop"]);
}

/// Run the system `sftp` client against `izba-<name>` over the `izba
/// __ssh-proxy` ProxyCommand, executing the commands in `batch` (`sftp -b`).
/// Mirrors `izba ssh`'s inline `-o` connection knobs (see
/// `commands::ssh::build_ssh_args`) so it works without a managed ~/.ssh/config.
///
/// CRITICAL: `IZBA_DATA_DIR` must be set on the `sftp` process so the
/// `izba __ssh-proxy` child it spawns (via ProxyCommand) inherits it and talks
/// to *this test's* daemon/sandbox — without it the proxy falls back to the
/// default data dir, finds no such sandbox, and fails with "sandbox … is not
/// running". `izba ssh` works because the `izba()` helper sets it on the parent.
fn sftp(data: &Path, name: &str, batch: &Path) -> Output {
    let exe = env!("CARGO_BIN_EXE_izba");
    let ssh_dir = data.join("ssh");
    let identity = ssh_dir.join("id_ed25519");
    let known_hosts = ssh_dir.join("known_hosts");
    let args: Vec<String> = vec![
        "-o".into(),
        format!("ProxyCommand=\"{exe}\" __ssh-proxy %h"),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("IdentityFile={}", identity.display()),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "User=root".into(),
        "-b".into(),
        batch.to_string_lossy().into_owned(),
        format!("izba-{name}"),
    ];
    std::process::Command::new("sftp")
        .env("IZBA_DATA_DIR", data)
        .args(&args)
        .output()
        .expect("run sftp client")
}

/// Build a Dockerfile inside a throwaway builder VM, ingest the result, tag it,
/// then run the built image and assert the marker file written by the `RUN` layer
/// is readable inside a fresh workload sandbox.
///
/// Exercises the full Track E / `izba build` pipeline end-to-end:
///   lazy-pull of the BuildKit builder image → build in VM → OCI-archive ingest
///   → tag → `izba run --image <tag>` → verify marker.
///
/// Gated behind `IZBA_INTEGRATION=1` — self-skips otherwise.
///
/// Note: this test requires host-side internet egress on the runner (builder
/// image pull from docker.io/moby/buildkit, plus the in-VM `FROM alpine:3.20`
/// pull through the enforcing build-network policy that allow-lists Docker Hub).
/// GitHub Actions hosted runners have internet access; this test is always run
/// in that environment.
#[test]
fn build_in_vm_dockerfile_to_running_sandbox() {
    if !want() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let no_env: &[(&str, &str)] = &[];

    // Resolve the fixture directory relative to this crate's manifest.
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/build");
    let fixture_s = fixture_dir.to_string_lossy().into_owned();

    // [1] Build the Dockerfile inside a throwaway builder VM.
    //     On failure, dump all sandbox console.logs to aid diagnosis.
    //     Note: buildkitd.log lives inside the VM and is NOT readable from the
    //     host; it surfaces here because the build script tails it to stderr on
    //     buildctl failure, and stderr is captured into console.log.
    let o = izba(
        &data,
        no_env,
        &["build", "-t", "izba-e2e-built", &fixture_s],
    );
    if !o.status.success() {
        // Best-effort: dump all sandbox console.logs (builder name is time-based).
        let sandboxes_dir = data.join("sandboxes");
        if let Ok(rd) = std::fs::read_dir(&sandboxes_dir) {
            for entry in rd.flatten() {
                let console = entry.path().join("logs/console.log");
                if console.exists() {
                    eprintln!(
                        "--- builder console.log ({}) ---",
                        entry.file_name().to_string_lossy()
                    );
                    if let Ok(txt) = std::fs::read_to_string(&console) {
                        for line in txt
                            .lines()
                            .rev()
                            .take(60)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                        {
                            eprintln!("{line}");
                        }
                    }
                }
            }
        }
    }
    assert_ok(&o, "izba build -t izba-e2e-built");

    // [2] Run the built image and confirm the marker the RUN layer wrote is
    //     visible inside the container.
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let o = izba(
        &data,
        no_env,
        &[
            "run",
            "--image",
            "izba-e2e-built",
            "--name",
            "e2e-built-run",
            &ws_s,
            "--",
            "cat",
            "/izba-build-marker",
        ],
    );
    assert_ok(
        &o,
        "izba run --image izba-e2e-built -- cat /izba-build-marker",
    );
    let marker = stdout_of(&o);
    assert!(
        marker.contains("izba-build-ok"),
        "marker file content from built image must contain 'izba-build-ok'; got: {marker:?}"
    );

    // [3] Cleanup.
    let _ = izba(&data, no_env, &["rm", "--force", "e2e-built-run"]);
    // Note: the tag + image store live inside the tempdir and are cleaned up
    // automatically when `root` is dropped; no explicit `izba image rm` is
    // needed (and there is no such subcommand in the CLI surface).
    let _ = izba(&data, no_env, &["daemon", "stop"]);
}

/// Manifest live-apply path: create → `izba diff` → `izba promote` against a
/// RUNNING sandbox proves egress policy and port relays change without restart.
///
/// Steps:
/// 1. Boot a sandbox with an initial enforcing policy (example.com only).
/// 2. Start a guest TCP nc server on port 8000 for the relay assertion.
/// 3. Write `izba.yml` adding a second egress host + a published port.
/// 4. `izba diff` — assert deltas contain the new host and the port change.
/// 5. `izba promote` (no `--restart`) — live-apply the egress+port deltas.
/// 6. Assert `izba policy show` reflects the new host.
/// 7. Assert `izba port ls` shows the new relay rule.
/// 8. Assert `http_get` through the promoted port relay returns the expected body.
#[test]
fn manifest_diff_promote_live_path() {
    if !want() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let no_env: &[(&str, &str)] = &[];
    let name = "manifest";

    // [1] Write the initial policy (enforcing, one host) and boot the sandbox.
    let policy_path = root.path().join("initial-policy.yaml");
    std::fs::write(&policy_path, b"enforce: true\nallow:\n  - example.com\n").unwrap();
    let policy_s = policy_path.to_string_lossy().into_owned();
    let o = izba(
        &data,
        no_env,
        &[
            "run", "-d", "--image", IMAGE, "--name", name, "--policy", &policy_s, &ws_s,
        ],
    );
    assert_ok(&o, "run -d (boot detached with policy)");
    assert!(
        stdout_of(&o).contains(name),
        "run -d prints sandbox name: {}",
        stdout_of(&o)
    );

    // [2] Start a guest TCP server so the promoted port relay can be tested.
    std::fs::write(
        ws.join("serve.sh"),
        b"printf 'HTTP/1.0 200 OK\\r\\n\\r\\npromote-port-body'\n",
    )
    .unwrap();
    assert_ok(
        &izba(
            &data,
            no_env,
            &[
                "exec",
                name,
                "--",
                "sh",
                "-c",
                "setsid sh -c 'while true; do nc -l -p 8000 -e sh /workspace/serve.sh; done' \
               >/dev/null 2>&1 & sleep 1",
            ],
        ),
        "start guest nc server on :8000",
    );

    // [3] Write izba.yml: same image/cpus/memory (no restart-class delta),
    //     + add api.anthropic.com to the egress allow-list, + a published port.
    //     rootDisk is ignored in the managed↔repo diff (rw_size_gb = 0 on
    //     managed side; diff.rs never compares it), but must parse validly.
    std::fs::write(
        ws.join("izba.yml"),
        concat!(
            "apiVersion: izba.dev/v1alpha1\n",
            "kind: Sandbox\n",
            "metadata:\n",
            "  name: manifest\n",
            "spec:\n",
            "  image: alpine:3.20\n",
            "  resources:\n",
            "    cpus: 2\n",
            "    memory: 4Gi\n",
            "  rootDisk:\n",
            "    size: 8Gi\n",
            "  egress:\n",
            "    enforce: true\n",
            "    allow:\n",
            "      - example.com\n",
            "      - api.anthropic.com\n",
            "  ports:\n",
            "    - guest: 8000\n",
            "      host: 18131\n",
        ),
    )
    .unwrap();

    // [4] `izba diff <ws>` — must exit 0 and show the two live deltas.
    let o = izba(&data, no_env, &["diff", &ws_s]);
    assert_ok(&o, "izba diff");
    let diff_out = stdout_of(&o);
    assert!(
        diff_out.contains("api.anthropic.com"),
        "diff must list the new egress host; got:\n{diff_out}"
    );
    assert!(
        diff_out.contains("ports"),
        "diff must list the port change; got:\n{diff_out}"
    );

    // [5] `izba promote <ws>` (no --restart — only live-class deltas).
    let o = izba(&data, no_env, &["promote", &ws_s]);
    assert_ok(&o, "izba promote");

    // [6] Verify the live egress policy was reloaded: new host must appear.
    let o = izba(&data, no_env, &["policy", "show", name]);
    assert_ok(&o, "izba policy show");
    let policy_out = stdout_of(&o);
    assert!(
        policy_out.contains("api.anthropic.com"),
        "promoted policy must list api.anthropic.com; got:\n{policy_out}"
    );

    // [7] Verify the port relay was published.
    let o = izba(&data, no_env, &["port", "ls", name]);
    assert_ok(&o, "izba port ls");
    let pls = stdout_of(&o);
    assert!(
        pls.contains("18131") && pls.contains("8000"),
        "promoted port relay must appear in port ls; got:\n{pls}"
    );

    // [8] Verify the relay is actually live by making an HTTP request through it.
    let body = http_get(18131).expect("GET through promoted port relay");
    assert!(
        body.contains("promote-port-body"),
        "port relay must deliver guest response; got: {body}"
    );

    // [9] Graduation (dogfood 2026-07-09): an egress-ONLY promote must
    // hot-reload the policy WITHOUT restarting the VM — vmm pid constant.
    let state_path = data.join("sandboxes").join(name).join(STATE_FILE);
    let st: RunState = load_json(&state_path)
        .expect("read state.json")
        .expect("state.json present while running");
    let pid_before = st.vmm_pid.clone();
    std::fs::write(
        ws.join("izba.yml"),
        concat!(
            "apiVersion: izba.dev/v1alpha1\n",
            "kind: Sandbox\n",
            "metadata:\n",
            "  name: manifest\n",
            "spec:\n",
            "  image: alpine:3.20\n",
            "  resources:\n",
            "    cpus: 2\n",
            "    memory: 4Gi\n",
            "  rootDisk:\n",
            "    size: 8Gi\n",
            "  egress:\n",
            "    enforce: true\n",
            "    allow:\n",
            "      - example.com\n",
            "      - api.anthropic.com\n",
            "      - crates.io\n",
            "  ports:\n",
            "    - guest: 8000\n",
            "      host: 18131\n",
        ),
    )
    .unwrap();
    // #123: use the BARE NAME form — exercises the sandbox_ref Name-form
    // resolver end-to-end (name -> config.json's recorded workspace).
    assert_ok(
        &izba(&data, no_env, &["diff", name]),
        "diff (egress-only, by name)",
    );
    assert_ok(
        &izba(&data, no_env, &["promote", name]),
        "promote (egress-only, by name)",
    );
    let st: RunState = load_json(&state_path)
        .expect("read state.json after promote")
        .expect("state.json still present");
    assert_eq!(
        st.vmm_pid, pid_before,
        "egress-only promote must hot-reload, not restart the VM"
    );
    let o = izba(&data, no_env, &["policy", "show", name]);
    assert_ok(&o, "policy show after hot-reload");
    assert!(
        stdout_of(&o).contains("crates.io"),
        "hot-reloaded policy must list crates.io; got:\n{}",
        stdout_of(&o)
    );

    // [10] Promote against a STOPPED sandbox skips live RPCs with the honest
    // "changes apply on next start" note (promote.rs:198) and exits 0.
    assert_ok(
        &izba(&data, no_env, &["stop", name]),
        "stop before offline promote",
    );
    std::fs::write(
        ws.join("izba.yml"),
        concat!(
            "apiVersion: izba.dev/v1alpha1\n",
            "kind: Sandbox\n",
            "metadata:\n",
            "  name: manifest\n",
            "spec:\n",
            "  image: alpine:3.20\n",
            "  resources:\n",
            "    cpus: 2\n",
            "    memory: 4Gi\n",
            "  rootDisk:\n",
            "    size: 8Gi\n",
            "  egress:\n",
            "    enforce: true\n",
            "    allow:\n",
            "      - example.com\n",
        ),
    )
    .unwrap();
    assert_ok(&izba(&data, no_env, &["diff", &ws_s]), "diff (stopped)");
    let o = izba(&data, no_env, &["promote", &ws_s]);
    assert_ok(&o, "promote against a stopped sandbox");
    let err = String::from_utf8_lossy(&o.stderr);
    let out = stdout_of(&o);
    assert!(
        err.contains("changes apply on next start") || out.contains("changes apply on next start"),
        "offline promote must print the next-start note; stdout:\n{out}\nstderr:\n{err}"
    );

    // [11] A divergent agent-writable metadata.name must NOT redirect the
    // promote target: `izba diff NAME` writes the review token under NAME's
    // sandbox dir, and `izba promote NAME` must read it from the same place
    // (pre-fix it consulted metadata.name and bailed "no reviewed diff").
    std::fs::write(
        ws.join("izba.yml"),
        concat!(
            "apiVersion: izba.dev/v1alpha1\n",
            "kind: Sandbox\n",
            "metadata:\n",
            "  name: manifest-alias\n",
            "spec:\n",
            "  image: alpine:3.20\n",
            "  resources:\n",
            "    cpus: 2\n",
            "    memory: 4Gi\n",
            "  rootDisk:\n",
            "    size: 8Gi\n",
            "  egress:\n",
            "    enforce: true\n",
            "    allow:\n",
            "      - example.com\n",
        ),
    )
    .unwrap();
    assert_ok(
        &izba(&data, no_env, &["diff", name]),
        "diff by name with divergent metadata.name",
    );
    let o = izba(&data, no_env, &["promote", name]);
    assert_ok(&o, "promote by name must target the resolved sandbox");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        !err.contains("no reviewed diff"),
        "promote must read the review token from the RESOLVED sandbox: {err}"
    );
    assert!(
        !data.join("sandboxes").join("manifest-alias").exists(),
        "metadata.name must not create/redirect to a different sandbox dir"
    );

    // Cleanup.
    let _ = izba(&data, no_env, &["rm", "--force", name]);
    let _ = izba(&data, no_env, &["daemon", "stop"]);
}

/// CLI-surface lifecycle: drives the thin verbs `daemon_full_lifecycle` does
/// NOT reach end-to-end against a real daemon + microVM — `create` (vs `run`),
/// `netlog`, `port ls`/`unpublish`, `stop`, and non-force `rm`. These verbs read
/// 0% in the merged coverage report precisely because the monolithic lifecycle
/// test uses `run` (never standalone `create`) and aborts at its upgrade-dance
/// phase before reaching its own `stop`/`rm` steps. A standalone test is also
/// more robust: one verb's regression can't mask the rest.
#[test]
fn cli_surface_lifecycle() {
    if !want() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let no_env: &[(&str, &str)] = &[];

    // [1] `create` (not `run`): provisions a STOPPED sandbox and prints its name
    // (create does not boot the VM — only `run`/Start does).
    let o = izba(
        &data,
        no_env,
        &["create", "--image", IMAGE, "--name", "cli", &ws_s],
    );
    assert_ok(&o, "create");
    assert!(stdout_of(&o).contains("cli"), "create prints the name");
    assert!(
        data.join("daemon/izbad.sock").exists(),
        "create auto-started the daemon"
    );

    // [2] `ls` lists it as stopped.
    let o = izba(&data, no_env, &["ls"]);
    assert_ok(&o, "ls after create");
    let ls = stdout_of(&o);
    assert!(ls.contains("cli"), "ls lists the sandbox: {ls}");
    assert!(ls.contains("stopped"), "created-not-run is stopped: {ls}");

    // [3] `netlog` on a never-run sandbox: no egress recorded yet, clean exit 0.
    assert_ok(&izba(&data, no_env, &["netlog", "cli"]), "netlog (empty)");
    // [3b] `netlog` on a missing sandbox is an honest error (nonzero exit).
    let o = izba(&data, no_env, &["netlog", "no-such-sandbox"]);
    assert!(!o.status.success(), "netlog on missing sandbox must error");

    // [4] `run` an EXISTING sandbox by name: starts it (no re-create) + execs.
    assert_ok(
        &izba(&data, no_env, &["run", "cli", "--", "/bin/true"]),
        "run existing sandbox",
    );
    let o = izba(&data, no_env, &["ls"]);
    assert!(
        stdout_of(&o).contains("running"),
        "sandbox running after run: {}",
        stdout_of(&o)
    );

    // [5] `port` verbs the lifecycle monolith never reaches: publish/ls/unpublish.
    assert_ok(
        &izba(&data, no_env, &["port", "publish", "cli", "18093:8000"]),
        "port publish",
    );
    let o = izba(&data, no_env, &["port", "ls", "cli"]);
    assert_ok(&o, "port ls");
    let pls = stdout_of(&o);
    assert!(
        pls.contains("18093") && pls.contains("8000"),
        "port ls shows the rule: {pls}"
    );
    assert_ok(
        &izba(&data, no_env, &["port", "unpublish", "cli", "18093"]),
        "port unpublish",
    );
    assert!(
        !stdout_of(&izba(&data, no_env, &["port", "ls", "cli"])).contains("18093"),
        "rule is gone after unpublish"
    );

    // [6] `stop` the running sandbox; `ls` reflects stopped.
    assert_ok(&izba(&data, no_env, &["stop", "cli"]), "stop");
    let o = izba(&data, no_env, &["ls"]);
    assert!(
        stdout_of(&o).contains("stopped"),
        "stopped after stop: {}",
        stdout_of(&o)
    );

    // [6b] `start` re-boots the stopped sandbox WITHOUT exec'ing (symmetric with
    // `stop`); `ls` reflects running again. Then stop once more so the rm step
    // below operates on a stopped sandbox.
    assert_ok(&izba(&data, no_env, &["start", "cli"]), "start");
    let o = izba(&data, no_env, &["ls"]);
    assert!(
        stdout_of(&o).contains("running"),
        "running after start: {}",
        stdout_of(&o)
    );
    assert_ok(&izba(&data, no_env, &["stop", "cli"]), "stop after start");

    // [6c] `start` on a sandbox that does not exist is an honest error.
    let o = izba(&data, no_env, &["start", "no-such-sandbox"]);
    assert!(!o.status.success(), "start on missing sandbox must error");

    // [7] non-force `rm` on a stopped sandbox removes it; `ls` no longer lists it.
    assert_ok(&izba(&data, no_env, &["rm", "cli"]), "rm (non-force)");
    let o = izba(&data, no_env, &["ls"]);
    assert!(
        !stdout_of(&o).contains("cli"),
        "removed sandbox is gone: {}",
        stdout_of(&o)
    );

    // [8] `run --rm`: a throwaway run creates + starts + execs, then tears the
    // sandbox down on exit — it must NOT linger in `ls`. Uses its own workspace
    // so it does not collide with the (now-removed) `cli` sandbox's relabel.
    let ws2 = root.path().join("ws-rm");
    std::fs::create_dir_all(&ws2).unwrap();
    let ws2_s = ws2.to_string_lossy().into_owned();
    assert_ok(
        &izba(
            &data,
            no_env,
            &[
                "run",
                "--rm",
                "--image",
                IMAGE,
                "--name",
                "rmtest",
                &ws2_s,
                "--",
                "/bin/true",
            ],
        ),
        "run --rm throwaway",
    );
    assert!(
        !stdout_of(&izba(&data, no_env, &["ls"])).contains("rmtest"),
        "run --rm removed the sandbox: {}",
        stdout_of(&izba(&data, no_env, &["ls"]))
    );

    // [9] `run --rm` against a PRE-EXISTING sandbox must NOT destroy it: `run`
    // can attach to an existing sandbox by name, so `--rm` only reaps what this
    // invocation freshly created. Create `keep`, then `run --rm keep` — it must
    // survive (otherwise `--rm` would silently delete user data).
    let ws3 = root.path().join("ws-keep");
    std::fs::create_dir_all(&ws3).unwrap();
    let ws3_s = ws3.to_string_lossy().into_owned();
    assert_ok(
        &izba(
            &data,
            no_env,
            &["create", "--image", IMAGE, "--name", "keep", &ws3_s],
        ),
        "create keep",
    );
    assert_ok(
        &izba(&data, no_env, &["run", "--rm", "keep", "--", "/bin/true"]),
        "run --rm against existing",
    );
    assert!(
        stdout_of(&izba(&data, no_env, &["ls"])).contains("keep"),
        "run --rm must NOT remove a pre-existing sandbox: {}",
        stdout_of(&izba(&data, no_env, &["ls"]))
    );
    assert_ok(&izba(&data, no_env, &["rm", "--force", "keep"]), "rm keep");

    // [10] `run -d`/`--detach`: create + start in one step and return
    // immediately, leaving the sandbox RUNNING (no exec). This is the
    // docker-parity bring-up path (#109). It must print the name and the
    // sandbox must show as running in `ls` without any foreground shell.
    let ws4 = root.path().join("ws-detach");
    std::fs::create_dir_all(&ws4).unwrap();
    let ws4_s = ws4.to_string_lossy().into_owned();
    let o = izba(
        &data,
        no_env,
        &["run", "-d", "--image", IMAGE, "--name", "detached", &ws4_s],
    );
    assert_ok(&o, "run -d");
    assert!(
        stdout_of(&o).contains("detached"),
        "run -d prints the sandbox name: {}",
        stdout_of(&o)
    );
    let ls_out = stdout_of(&izba(&data, no_env, &["ls"]));
    assert!(
        ls_out.contains("detached") && ls_out.contains("running"),
        "run -d leaves the sandbox running: {}",
        ls_out
    );
    // [10b] `run -d` with a trailing command is contradictory and rejected
    // (before any VM work) — the sandbox is still up from the call above.
    let o = izba(&data, no_env, &["run", "-d", "detached", "--", "/bin/true"]);
    assert!(
        !o.status.success(),
        "run -d -- CMD must be rejected (detach runs no command)"
    );
    assert_ok(
        &izba(&data, no_env, &["rm", "--force", "detached"]),
        "rm detached",
    );

    let _ = izba(&data, no_env, &["daemon", "stop"]);
}

/// #67 regression: right after `izba run`, the reconciler must see a
/// consistent daemon-vs-disk view (the settle re-sample absorbs the
/// supervisor tick's cache lag; the Start heal covers the idempotent path).
#[test]
fn reconcile_is_clean_right_after_run() {
    if !want() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let no_env: &[(&str, &str)] = &[];
    let name = "reconcile-e2e";

    let o = izba(
        &data,
        no_env,
        &["run", "-d", "--image", IMAGE, "--name", name, &ws_s],
    );
    assert_ok(&o, "run -d");

    let o = izba(&data, no_env, &["__reconcile", "--json"]);
    assert_ok(&o, "__reconcile --json");
    let out = stdout_of(&o);
    let report: Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("reconcile output not JSON: {e}\n{out}"));
    let violations = report["violations"]
        .as_array()
        .expect("violations is an array");
    assert!(
        violations.is_empty(),
        "reconcile must be clean right after run: {out}"
    );

    let _ = izba(&data, no_env, &["rm", "--force", name]);
    let _ = izba(&data, no_env, &["daemon", "stop"]);
}

/// Docker mode, pinned by digest (resolved 2026-08-08 from `docker:28-dind`).
const DIND_IMAGE: &str =
    "docker@sha256:2a232a42256f70d78e3cc5d2b5d6b3276710a0de0596c145f627ecfae90282ac";
/// The inner workload the nested engine publishes (resolved 2026-08-08 from
/// `nginx:alpine`) — a tiny image that serves HTTP on :80 with no config.
const NGINX_IMAGE: &str =
    "nginx@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752";

/// Dump the guest console tail for a docker-mode sandbox, mirroring the
/// build-in-VM test's dump-on-failure pattern, plus the in-container engine
/// log (the only place a dockerd that died leaves its reason).
fn docker_diag(data: &Path, name: &str) -> String {
    let mut out = String::new();
    let console = data.join("sandboxes").join(name).join("logs/console.log");
    out.push_str(&format!("--- console.log ({}) ---\n", console.display()));
    if let Ok(txt) = std::fs::read_to_string(&console) {
        let lines: Vec<&str> = txt.lines().collect();
        let start = lines.len().saturating_sub(60);
        out.push_str(&lines[start..].join("\n"));
    }
    out.push_str("\n--- /var/log/izba-dockerd.log ---\n");
    let o = izba(
        data,
        &[],
        &["exec", name, "--", "cat", "/var/log/izba-dockerd.log"],
    );
    out.push_str(&stdout_of(&o));
    out.push_str(&String::from_utf8_lossy(&o.stderr));
    out
}

/// Tear the sandbox and its daemon down even when an assertion panics.
///
/// Every other test in this file cleans up on the happy path only, which is
/// fine for CI (fresh runner per job) but leaks a live microVM AND a daemon
/// still holding the published host port on a developer box — the next local
/// run then fails with a misleading "host port … is unavailable" instead of
/// the real regression. A docker-mode sandbox is the most expensive thing this
/// suite boots, so it is the one that earns the guard.
struct SandboxGuard {
    data: PathBuf,
    name: &'static str,
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        let _ = izba(&self.data, &[], &["rm", "--force", self.name]);
        let _ = izba(&self.data, &[], &["daemon", "stop"]);
    }
}

/// Docker mode (#198) through the FULL daemon path: a port published against
/// a container the nested Docker Engine started must be reachable from the
/// host. Every hop is real — host TcpStream → izbad relay → `StreamOpen::
/// TcpDial{8080}` over vsock 1026 → izba-init's loopback dial MISS →
/// docker-mode veth fallback to `192.168.127.2` → docker-proxy in the
/// workload's own netns → nginx in the nested container.
///
/// The veth fallback (Task 6) is the piece this test exists for: in docker
/// mode the published port lives in the container's netns, never on init's
/// loopback, so without the fallback this GET can only ever fail.
#[test]
fn docker_publish_reaches_inner_container() {
    if !want() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let no_env: &[(&str, &str)] = &[];
    let name = "dind-port";
    let _guard = SandboxGuard {
        data: data.clone(),
        name,
    };

    // [1] Create + start a docker-mode sandbox via the real CLI flag.
    let o = izba(
        &data,
        no_env,
        &[
            "create", "--docker", "--image", DIND_IMAGE, "--cpus", "2", "--mem", "2048", "--name",
            name, &ws_s,
        ],
    );
    assert_ok(&o, "create --docker");
    let o = izba(&data, no_env, &["start", name]);
    assert_ok(&o, "start");

    // [2] Wait for the auto-started engine. Generous ceiling: dockerd starts
    // containerd, its bridge + iptables, and probes storage first.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut ready = false;
    while Instant::now() < deadline {
        if izba(
            &data,
            no_env,
            &["exec", name, "--", "docker", "info", "--format", "{{.ID}}"],
        )
        .status
        .success()
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert!(
        ready,
        "dockerd never became ready within 120s\n{}",
        docker_diag(&data, name)
    );

    // [2b] Task 10: `izba status` must show docker mode plus a running
    // engine line, sourced from the same guest Stats round-trip the port
    // reach-through below exercises transitively.
    let o = izba(&data, no_env, &["status", name]);
    assert_ok(&o, "status");
    let status_out = stdout_of(&o);
    assert!(
        status_out.contains("mode:        docker"),
        "status must show docker mode, got:\n{status_out}"
    );
    assert!(
        status_out.contains("engine:      running"),
        "status must show a running engine, got:\n{status_out}"
    );

    // [3] Run nginx in the nested engine with a published port. `-p 8080:80`
    // makes docker-proxy listen on 8080 in the WORKLOAD's netns.
    let o = izba(
        &data,
        no_env,
        &[
            "exec",
            name,
            "--",
            "docker",
            "run",
            "-d",
            "-p",
            "8080:80",
            NGINX_IMAGE,
        ],
    );
    assert!(
        o.status.success(),
        "nested `docker run -d -p 8080:80 nginx` failed: {}\n{}\n{}",
        stdout_of(&o),
        String::from_utf8_lossy(&o.stderr),
        docker_diag(&data, name)
    );

    // [4] Publish it host-side and GET through the whole chain.
    assert_ok(
        &izba(&data, no_env, &["port", "publish", name, "18080:8080"]),
        "port publish 18080:8080",
    );
    let body = http_get(18080).unwrap_or_else(|e| {
        panic!(
            "GET 127.0.0.1:18080 never reached the nested container: {e:#}\n{}",
            docker_diag(&data, name)
        )
    });
    assert!(
        body.contains("nginx"),
        "expected nginx's default page through the relay, got: {body:?}\n{}",
        docker_diag(&data, name)
    );
    // Teardown is the SandboxGuard's job (it also runs on panic).
}

// ── VNC desktop (spec 2026-08-09) ────────────────────────────────────────────

/// Is the KasmVNC bundle staged where PRODUCTION discovery looks for it?
///
/// Deliberately the exe-relative `<exe-dir>/../artifacts/kasmvnc.erofs` path
/// and NOTHING else: the test never sets `IZBA_KASMVNC_EROFS`, so a green run
/// proves the shipped discovery path works (the USB post-mortem's lesson —
/// an e2e that hands itself an env override can pass while every installer
/// is broken). `CARGO_BIN_EXE_izba` is `<target>/debug/izba`, so the parent
/// hop lands on `<target>/artifacts`.
fn vnc_bundle_path() -> Option<PathBuf> {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_izba"));
    exe.parent()
        .and_then(Path::parent)
        .map(|d| d.join("artifacts/kasmvnc.erofs"))
}

/// Guest + host diagnostics for a VNC sandbox: the console tail (boot/mount
/// failures) plus the in-container desktop log, which is the only place a
/// dead `Xkasmvnc` leaves its reason. Mirrors `docker_diag`.
fn vnc_diag(data: &Path, name: &str) -> String {
    let mut out = String::new();
    let console = data.join("sandboxes").join(name).join("logs/console.log");
    out.push_str(&format!("--- console.log ({}) ---\n", console.display()));
    if let Ok(txt) = std::fs::read_to_string(&console) {
        let lines: Vec<&str> = txt.lines().collect();
        let start = lines.len().saturating_sub(60);
        out.push_str(&lines[start..].join("\n"));
    }
    out.push_str("\n--- /var/log/izba-vnc.log (in guest) ---\n");
    let o = izba(
        data,
        &[],
        &["exec", name, "--", "cat", "/var/log/izba-vnc.log"],
    );
    out.push_str(&stdout_of(&o));
    out.push_str(&String::from_utf8_lossy(&o.stderr));
    out
}

/// Split `http://izba:<password>@127.0.0.1:<port>/` into its two variable
/// parts, asserting the whole shape on the way (the URL contract `izba vnc
/// url` promises: fixed user, loopback host, trailing slash).
fn parse_vnc_url(url: &str) -> (String, u16) {
    let rest = url
        .strip_prefix("http://izba:")
        .unwrap_or_else(|| panic!("vnc url must carry the izba userinfo, got: {url:?}"));
    let (password, hostpart) = rest
        .split_once('@')
        .unwrap_or_else(|| panic!("vnc url must carry a password, got: {url:?}"));
    let hostport = hostpart.trim_end_matches('/');
    let port: u16 = hostport
        .strip_prefix("127.0.0.1:")
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("vnc url must target a loopback port, got: {url:?}"));
    assert!(!password.is_empty(), "vnc url password must not be empty");
    (password.to_string(), port)
}

/// Prove a REAL browser-equivalent session against the desktop on `port`:
/// wait for the server to bind behind the relay, authenticate, and carry an
/// RFB stream over the websocket whose offered security type is `None`.
///
/// Factored out because the second `start` of a sandbox has to be held to the
/// exact same bar as the first (see the restart step of [`vnc_desktop_e2e`]);
/// the first pass keeps its extra negative probes inline.
fn prove_desktop_session(data: &Path, name: &str, port: u16, password: &str, phase: &str) {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut last_status = None;
    let mut last_err = None;
    while Instant::now() < deadline {
        match http_get_status(port, "/", None) {
            Ok((code, _)) => {
                last_status = Some(code);
                if code == 401 {
                    break;
                }
            }
            Err(e) => last_err = Some(format!("{e:#}")),
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert_eq!(
        last_status,
        Some(401),
        "[{phase}] the desktop never answered with an auth challenge within \
         120s (last status: {last_status:?}, last error: {last_err:?})\n{}",
        vnc_diag(data, name)
    );

    let (code, body) = http_get_status(port, "/", Some(("izba", password))).unwrap_or_else(|e| {
        panic!(
            "[{phase}] authenticated GET failed: {e:#}\n{}",
            vnc_diag(data, name)
        )
    });
    assert_eq!(
        code,
        200,
        "[{phase}] correct credentials must be accepted\n{}",
        vnc_diag(data, name)
    );
    assert!(
        body.to_lowercase().contains("kasm"),
        "[{phase}] expected the KasmVNC client page, got: {:.400}\n{}",
        body,
        vnc_diag(data, name)
    );

    let (code, greeting, types) =
        ws_rfb_probe(port, Some(("izba", password))).unwrap_or_else(|e| {
            panic!(
                "[{phase}] websocket upgrade failed: {e:#}\n{}",
                vnc_diag(data, name)
            )
        });
    assert_eq!(
        code,
        101,
        "[{phase}] the credentialed websocket upgrade must succeed\n{}",
        vnc_diag(data, name)
    );
    assert!(
        greeting.starts_with(b"RFB "),
        "[{phase}] the websocket must carry the RFB stream, got: {:?}\n{}",
        String::from_utf8_lossy(&greeting),
        vnc_diag(data, name)
    );
    assert!(
        types.contains(&1) && !types.contains(&2),
        "[{phase}] the server must offer RFB security type None (1) and not \
         VncAuth (2), got: {types:?}\n{}",
        vnc_diag(data, name)
    );
}

/// The Applications menu's *content*, read as a separate `izba exec` from
/// [`assert_desktop_procs`]'s process listing.
///
/// **Two things must stay true here, and the second one bit us already.**
///
/// 1. Liveness is a LYING oracle for this menu. `menu-cached` (the daemon)
///    can be running and answering while `menu-cache-gen` (the generator it
///    spawns from a second hardcoded path) is missing, in which case the
///    menu opens with nothing in it — no cache file, no warning, no error,
///    nothing in `/var/log/izba-vnc.log`. That shipped once and was caught
///    only by a human opening the menu in a browser. The generated cache
///    under `$HOME/.cache/menus/` is the one host-visible artifact that
///    proves the generator ran, and lxpanel triggers it at startup, so no
///    interaction is needed to observe it.
/// 2. **The probe must not be able to satisfy itself.** The first version of
///    this check appended the `ls` to the *same* `sh -c` as the process
///    listing and grepped the combined stdout for a marker string — but that
///    listing dumps every `/proc/<pid>/cmdline`, including the probe's OWN
///    argv, which contains the marker as literal script text. It therefore
///    passed whether or not a cache existed: a vacuous assertion that looked
///    like a strengthened one. Keeping this in its own exec, and asserting on
///    that exec's stdout alone, is what makes it real. Any future "just fold
///    it into the other command" must not be taken.
fn menu_cache_entries(data: &Path, name: &str) -> String {
    let o = izba(
        data,
        &[],
        // HOME is /tmp for the desktop (izba-init's vnc_env), so menu-cache
        // writes its generated cache to /tmp/.cache/menus. `ls` of a missing
        // directory is an error, hence the tolerant `2>/dev/null; true` —
        // the exec ITSELF is still asserted, so a broken `izba exec` cannot
        // masquerade as an empty cache.
        &[
            "exec",
            name,
            "--",
            "sh",
            "-c",
            "ls /tmp/.cache/menus 2>/dev/null; true",
        ],
    );
    assert_ok(&o, "read the generated Applications-menu cache");
    stdout_of(&o)
}

/// Assert every desktop component is a live process inside the container
/// **and** that the Applications menu actually has content, polling
/// briefly: pcmanfm/lxpanel start alongside openbox, and menu-cached is
/// spawned lazily by lxpanel's menu plugin, so a single snapshot right
/// after the RFB proof can race their startup.
fn assert_desktop_procs(data: &Path, name: &str, phase: &str) {
    let wants = ["Xkasmvnc", "openbox", "lxpanel", "pcmanfm", "menu-cached"];
    let no_env: &[(&str, &str)] = &[];
    let deadline = Instant::now() + Duration::from_secs(60);
    let (procs, menu) = loop {
        let o = izba(
            data,
            no_env,
            &[
                "exec",
                name,
                "--",
                "sh",
                "-c",
                // pgrep is not in busybox-alpine's default applet set.
                "for p in /proc/[0-9]*; do tr '\\0' ' ' < \"$p/cmdline\"; echo; done",
            ],
        );
        assert_ok(&o, "list container processes");
        let procs = stdout_of(&o);
        let menu = menu_cache_entries(data, name);
        if wants.iter().all(|w| procs.contains(w)) && !menu.trim().is_empty() {
            return;
        }
        if Instant::now() >= deadline {
            break (procs, menu);
        }
        std::thread::sleep(Duration::from_secs(2));
    };
    for want in wants {
        assert!(
            procs.contains(want),
            "[{phase}] {want} must be running inside the container, got:\n{procs}\n{}",
            vnc_diag(data, name)
        );
    }
    assert!(
        !menu.trim().is_empty(),
        "[{phase}] the Applications menu is EMPTY: nothing under \
         /tmp/.cache/menus, so menu-cache-gen never ran. The panel and \
         menu-cached can both look healthy in this state.\n{}",
        vnc_diag(data, name)
    );
}

/// The guest's listeners, read from the kernel inside the workload container
/// (which shares init's netns for every non-docker sandbox, so this is the
/// whole guest).
///
/// Each file is `cat`'d separately and its absence tolerated (`; true`): a
/// kernel built without IPv6 has no `/proc/net/tcp6`, and a single `cat a b`
/// would fail the whole read — turning "the guest listens on nothing extra"
/// into an unrelated exec failure. The exec ITSELF is still asserted, so a
/// broken `izba exec` cannot masquerade as an empty listener set.
fn guest_listeners(data: &Path, name: &str) -> BTreeSet<(u16, String)> {
    let o = izba(
        data,
        &[],
        &[
            "exec",
            name,
            "--",
            "sh",
            "-c",
            "cat /proc/net/tcp 2>/dev/null; cat /proc/net/tcp6 2>/dev/null; true",
        ],
    );
    assert_ok(&o, "read the guest's /proc/net/tcp");
    parse_listeners(&stdout_of(&o))
}

/// The full VNC display feature against a real microVM: bundle discovery
/// through the PRODUCTION path, credentialed web client through the daemon's
/// ephemeral relay, the desktop actually running inside the container, the
/// guest's listening surface, and the honest `vnc off`/plain-sandbox
/// renderings.
///
/// Everything here is a real hop: host `TcpStream` → izbad's VNC relay →
/// `StreamOpen::TcpDial{6901}` over vsock 1026 → izba-init's loopback dial →
/// `Xkasmvnc`'s websockify inside the crun container, authenticating against
/// the `kasmpasswd` hash the host generated at `start` and delivered over the
/// `izba-vnc` virtiofs share.
///
/// Assertions, in order:
/// 1. `izba vnc url` prints `http://izba:<pw>@127.0.0.1:<port>/`.
/// 2. Auth matrix: no creds → 401; correct creds → 200 + a KasmVNC page;
///    wrong password → 401 (the hash really is checked, not merely present).
/// 3. A REAL client session, not just static content: the websocket upgrade
///    on the same port (401 unauthenticated, 101 with credentials — even
///    after more unauthenticated requests than KasmVNC's default brute-force
///    threshold) carrying an RFB stream whose offered security type is
///    `None`, not `VncAuth`. Every probe in the first cut stopped at an HTTP
///    GET, and static content served perfectly while the desktop never
///    appeared.
/// 4. The desktop is functional: the X socket is at `/tmp/.X11-unix/X1` and
///    `Xkasmvnc`, `openbox`, `lxpanel`, `pcmanfm`, and `menu-cached` are all
///    live processes inside the container.
/// 5. The guest listens on NOTHING beyond izba's own set — in particular no
///    X11 TCP port (`-ac` grants root-on-display to anything in the netns, so
///    an open 6001 would be a real hole).
/// 6. A RESTARTED sandbox serves a working desktop too — `stop`/`start`,
///    then the whole real-client proof again against the new URL, plus the
///    full component set from item 4 alive again. The first cut only ever
///    booted a fresh sandbox, and the X server's lock file lives in the
///    persistent overlay, so every second boot was dead.
/// 7. `izba vnc off` on a RUNNING sandbox: "restart required" guidance, a
///    status line that admits the desktop is still up, and a `vnc url` that
///    still hands back the live URL with the disabled warning on stderr.
/// 8. A sandbox created WITHOUT `--vnc`: `izba vnc url` fails, pointing at
///    `vnc on`.
#[test]
fn vnc_desktop_e2e() {
    if !want() {
        return;
    }
    // The whole point of this test is that PRODUCTION discovery finds the
    // bundle. `izba()` inherits the parent environment, so an ambient
    // IZBA_KASMVNC_EROFS exported in the shell (or by a CI step) would hand
    // the daemon an override and the test would silently prove the wrong
    // path — the exact mode the USB post-mortem calls out. Refuse to run
    // rather than run a lie.
    assert!(
        std::env::var_os("IZBA_KASMVNC_EROFS").is_none(),
        "this e2e must prove production discovery — unset IZBA_KASMVNC_EROFS"
    );
    let bundle = vnc_bundle_path();
    if !bundle.as_deref().map(Path::exists).unwrap_or(false) {
        eprintln!(
            "SKIP vnc_desktop_e2e: kasmvnc.erofs not staged at {} — run \
             hack/build-kasmvnc-erofs.sh and copy dist/kasmvnc.erofs there",
            bundle
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<exe-relative artifacts dir>".into())
        );
        return;
    }

    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let no_env: &[(&str, &str)] = &[];
    let name = "vnc-e2e";
    let plain = "vnc-e2e-plain";
    // Guards drop in REVERSE declaration order, so the plain sandbox's guard
    // is declared FIRST to make the VNC sandbox's guard run first: the live
    // microVM is then torn down while the daemon this test has been using is
    // still up, and only the cheap `rm` of a never-started sandbox lands
    // after it. (Each guard also stops the daemon, so the second one
    // re-spawns it for its `rm` — harmless, and not worth changing the
    // shared `SandboxGuard` the docker e2e also relies on.) The plain
    // sandbox does not exist until step [9]; `rm --force` on a missing
    // sandbox is a no-op the guard already ignores.
    let _plain_guard = SandboxGuard {
        data: data.clone(),
        name: plain,
    };
    let _guard = SandboxGuard {
        data: data.clone(),
        name,
    };

    // [1] create --vnc + start. No IZBA_KASMVNC_EROFS: the daemon must find
    // the bundle by itself or `start` fails closed.
    let o = izba(
        &data,
        no_env,
        &["create", "--vnc", "--image", IMAGE, "--name", name, &ws_s],
    );
    assert_ok(&o, "create --vnc");
    let o = izba(&data, no_env, &["start", name]);
    assert_ok(&o, "start (vnc)");

    // [2] The credentialed URL.
    let o = izba(&data, no_env, &["vnc", "url", name]);
    assert_ok(&o, "vnc url");
    let url = stdout_of(&o).trim().to_string();
    let (password, port) = parse_vnc_url(&url);

    // [3] Poll for the desktop: the relay is up the instant `start` returns,
    // but Xkasmvnc needs a few seconds to bind :6901 behind it. An
    // unauthenticated 401 is the first honest proof the whole chain is live.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut last_status = None;
    let mut last_err = None;
    while Instant::now() < deadline {
        match http_get_status(port, "/", None) {
            Ok((code, _)) => {
                last_status = Some(code);
                if code == 401 {
                    break;
                }
            }
            // Keep the reason: "relay refused the connection" and "the guest
            // answered 500" are different failures, and `last_status: None`
            // alone says nothing about which one happened.
            Err(e) => last_err = Some(format!("{e:#}")),
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert_eq!(
        last_status,
        Some(401),
        "the desktop never answered with an auth challenge within 120s \
         (last status: {last_status:?}, last error: {last_err:?})\n{}",
        vnc_diag(&data, name)
    );

    // [4] Correct credentials get the KasmVNC web client.
    let (code, body) = http_get_status(port, "/", Some(("izba", &password)))
        .unwrap_or_else(|e| panic!("authenticated GET failed: {e:#}\n{}", vnc_diag(&data, name)));
    assert_eq!(
        code,
        200,
        "correct credentials must be accepted (the host-generated kasmpasswd \
         hash must match byte-for-byte what KasmVNC recomputes)\n{}",
        vnc_diag(&data, name)
    );
    assert!(
        body.to_lowercase().contains("kasm"),
        "expected the KasmVNC client page, got: {:.400}\n{}",
        body,
        vnc_diag(&data, name)
    );

    // [5] A wrong password is rejected — proves [4] passed because of the
    // credentials, not because auth is effectively disabled.
    let (code, _) = http_get_status(port, "/", Some(("izba", "definitely-not-the-password")))
        .unwrap_or_else(|e| {
            panic!(
                "wrong-password GET never completed: {e:#}\n{}",
                vnc_diag(&data, name)
            )
        });
    assert_eq!(
        code,
        401,
        "a wrong password must not be accepted\n{}",
        vnc_diag(&data, name)
    );

    // [5b] The step every earlier probe skipped: what a REAL client does.
    // Static GETs can all succeed while the session is dead, which is
    // precisely how the "page loads, desktop never appears, endless spinner"
    // bug shipped. Upgrade the same port to a websocket and run the first two
    // RFB steps through it.
    //
    // First unauthenticated — the auth gate has to hold on the websocket
    // path, not merely on `/`.
    let (code, _, _) = ws_rfb_probe(port, None).unwrap_or_else(|e| {
        panic!(
            "unauthenticated websocket upgrade never completed: {e:#}\n{}",
            vnc_diag(&data, name)
        )
    });
    assert_eq!(
        code,
        401,
        "the websocket must demand BasicAuth too\n{}",
        vnc_diag(&data, name)
    );

    // Then hammer the server with MORE unauthenticated requests than
    // KasmVNC's default brute-force threshold (5) before the real attempt.
    // A browser generates exactly this pattern by itself — basic auth is
    // 401-then-retry and the client page fetches ~30 subresources in
    // parallel — and every request arrives from the same guest-loopback
    // address, so the default lockout blacklists the only client there is.
    // With the lockout left on, the authenticated probe below fails.
    for _ in 0..6 {
        let _ = http_get_status(port, "/", None);
    }

    let (code, greeting, types) = ws_rfb_probe(port, Some(("izba", &password)))
        .unwrap_or_else(|e| panic!("websocket upgrade failed: {e:#}\n{}", vnc_diag(&data, name)));
    assert_eq!(
        code,
        101,
        "the credentialed websocket upgrade must succeed (a blacklisted \
         loopback answers 401 forever)\n{}",
        vnc_diag(&data, name)
    );
    assert!(
        greeting.starts_with(b"RFB "),
        "the websocket must carry the RFB stream, got: {:?}\n{}",
        String::from_utf8_lossy(&greeting),
        vnc_diag(&data, name)
    );
    // `1 = None`, `2 = VncAuth`. VncAuth authenticates against a separate
    // legacy `-rfbauth` file that izba never writes, so offering it strands
    // the web client at a password prompt it can never satisfy — the RFB
    // stream must be gated by the BasicAuth already proven above instead.
    assert!(
        types.contains(&1) && !types.contains(&2),
        "the server must offer RFB security type None (1) and not VncAuth \
         (2), got: {types:?}\n{}",
        vnc_diag(&data, name)
    );

    // [6] The desktop is really running inside the container: the X server's
    // socket is where izba-init's window-manager wait expects it, and both
    // processes are alive.
    let o = izba(
        &data,
        no_env,
        &["exec", name, "--", "sh", "-c", "ls /tmp/.X11-unix/"],
    );
    assert_ok(&o, "ls /tmp/.X11-unix/");
    assert!(
        stdout_of(&o).contains("X1"),
        "the X server must own display :1 at /tmp/.X11-unix/X1, got: {:?}\n{}",
        stdout_of(&o),
        vnc_diag(&data, name)
    );
    assert_desktop_procs(&data, name, "first boot");

    // [7] Listening surface. `Xkasmvnc` runs with `-ac` (access control off),
    // so an X11 TCP listener would hand root-on-display to anything that can
    // reach the guest netns — the whole point of KasmVNC's unix-socket-only
    // default. Assert the LISTEN set is exactly izba's own: sshd (22), the
    // egress DNS/TCP stub (53), the egress relay (15001) and the desktop's
    // websocket (6901).
    let listeners = guest_listeners(&data, name);
    let ports: BTreeSet<u16> = listeners.iter().map(|(p, _)| *p).collect();
    let expected: BTreeSet<u16> = [22, 53, 6901, 15001].into_iter().collect();
    // The desktop must be listening AND on loopback specifically: `0100007F`
    // is the kernel's little-endian hex for 127.0.0.1, so this pins
    // `-interface 127.0.0.1` end to end. A regression to a wildcard bind
    // would satisfy a port-only assertion while exposing the display to
    // anything that reaches the guest's netns.
    assert!(
        listeners.contains(&(6901, "0100007F".to_string())),
        "the desktop's websocket must be listening on loopback (0100007F), got: {listeners:?}"
    );
    assert!(
        !ports.contains(&6001),
        "an X11 TCP listener (6000+display) must NOT exist — with -ac it would \
         be root-on-display for anything in the guest netns; got: {listeners:?}"
    );
    assert!(
        ports.is_subset(&expected),
        "the guest must listen on nothing beyond izba's own set {expected:?}, got: {listeners:?}"
    );

    // [7b] RESTART — the class every assertion above is blind to, and the one
    // that reached a user: everything so far only ever exercised the FIRST
    // boot of a fresh sandbox, which is also all CI ever booted.
    //
    // The container's `/tmp` is not a tmpfs; it lives in the sandbox's
    // persistent overlay. So the X server's `/tmp/.X1-lock` and
    // `/tmp/.X11-unix/X1` survive `stop`, and on the next `start` `Xkasmvnc`
    // finds the lock, concludes the display is taken and dies with "Server is
    // already active for display 1" — while `izba vnc url` still cheerfully
    // prints a URL that now serves nothing. Every upgrade (the installer
    // quiesces sandboxes) and every plain `izba stop`/`izba start` hits it.
    let o = izba(&data, no_env, &["stop", name]);
    assert_ok(&o, "stop (vnc restart)");
    let o = izba(&data, no_env, &["start", name]);
    assert_ok(&o, "start (vnc restart)");

    // The password is regenerated per `start` and the relay port is
    // ephemeral, so the URL must be re-read — using the stale one would
    // prove nothing.
    let o = izba(&data, no_env, &["vnc", "url", name]);
    assert_ok(&o, "vnc url (after restart)");
    let url2 = stdout_of(&o).trim().to_string();
    let (password2, port2) = parse_vnc_url(&url2);
    assert_ne!(
        password2, password,
        "each start must mint a fresh VNC password"
    );
    prove_desktop_session(&data, name, port2, &password2, "after restart");

    // …and the desktop processes really came back, not just the websocket.
    assert_desktop_procs(&data, name, "after restart");

    // The precise failure mode, named: even if some future change made the
    // probes above pass by luck, a stale lock leaves this in the log.
    let o = izba(
        &data,
        no_env,
        &["exec", name, "--", "cat", "/var/log/izba-vnc.log"],
    );
    assert_ok(&o, "read the guest vnc log after restart");
    assert!(
        !stdout_of(&o).contains("already active for display"),
        "a restarted sandbox must not trip X's stale display lock:\n{}",
        stdout_of(&o)
    );

    // [8] `vnc off` against a RUNNING sandbox: config flips now, the booted
    // desktop cannot be unmade, and every surface has to say so honestly.
    let o = izba(&data, no_env, &["vnc", "off", name]);
    assert_ok(&o, "vnc off");
    let off_out = format!("{}{}", stdout_of(&o), String::from_utf8_lossy(&o.stderr));
    assert!(
        off_out.contains("restart required"),
        "vnc off on a running sandbox must ask for a restart, got: {off_out}"
    );
    let o = izba(&data, no_env, &["status", name]);
    assert_ok(&o, "status after vnc off");
    let status_out = stdout_of(&o);
    assert!(
        status_out.contains("vnc:         disabled (desktop still running until restart)"),
        "status must admit the desktop is still up, got:\n{status_out}"
    );
    // The URL still works — the relay and the desktop behind it are live.
    let o = izba(&data, no_env, &["vnc", "url", name]);
    assert_ok(&o, "vnc url after vnc off");
    assert_eq!(
        stdout_of(&o).trim(),
        // The URL of the CURRENT run — the restart in [7b] minted a new
        // password and relay port, and `vnc off` must not disturb either.
        url2,
        "the live relay's URL must be unchanged by a config-only flip"
    );
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("disabled in config"),
        "vnc url must warn that the desktop is on borrowed time, got stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    // [9] A sandbox created WITHOUT --vnc has no URL to give. It never needs
    // to boot for that answer, so this costs no second microVM.
    let ws2 = root.path().join("ws-plain");
    std::fs::create_dir_all(&ws2).unwrap();
    let ws2_s = ws2.to_string_lossy().into_owned();
    assert_ok(
        &izba(
            &data,
            no_env,
            &["create", "--image", IMAGE, "--name", plain, &ws2_s],
        ),
        "create (plain)",
    );
    let o = izba(&data, no_env, &["vnc", "url", plain]);
    assert!(
        !o.status.success(),
        "vnc url on a sandbox without --vnc must fail"
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("vnc on"),
        "the refusal must point at `izba vnc on`, got: {err}"
    );

    // Teardown is the SandboxGuards' job (they also run on panic).
}

/// The two hand-rolled parsers `vnc_desktop_e2e` leans on are pure, so they
/// are gated in EVERY CI run — not only under `IZBA_INTEGRATION=1`. A silent
/// base64 bug would turn "the password was rejected" into "the header was
/// malformed", and a `/proc/net/tcp` misparse would turn the listening-surface
/// assertion into a no-op.
#[test]
fn base64_encode_matches_rfc4648_vectors() {
    assert_eq!(base64_encode(b""), "");
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
    assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    // The shape the test actually sends, plus the high-bit/padding edges.
    assert_eq!(base64_encode(b"izba:pw"), "aXpiYTpwdw==");
    assert_eq!(base64_encode(&[0xff, 0xef, 0xfe]), "/+/+");
}

#[test]
fn parse_listeners_reads_only_listeners_and_keeps_the_address() {
    // Verbatim from a real `--vnc` guest (alpine:3.20, 2026-08-09): sshd,
    // the egress DNS stub, the egress relay, the desktop websocket, and one
    // ESTABLISHED (st 01) connection that must NOT be counted.
    let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 538 1
   1: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 545 1
   2: 00000000:3A99 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 539 1
   3: 0100007F:1AF5 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 647 1
   4: 0100007F:E5CA 0100007F:1AF5 01 00000000:00000000 00:00000000 00000000     0        0 0 3
";
    let got = parse_listeners(sample);
    assert_eq!(
        got,
        [
            // Loopback-bound (0100007F) vs wildcard (00000000) is preserved:
            // it is the difference the VNC assertion turns on.
            (22u16, "0100007F".to_string()),
            (53, "00000000".to_string()),
            (6901, "0100007F".to_string()),
            (15001, "00000000".to_string()),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    );
    // An IPv6-shaped row (32-hex address) parses the same way.
    let v6 = "   0: 00000000000000000000000000000000:1F90 \
              00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1\n";
    assert_eq!(
        parse_listeners(v6),
        [(8080u16, "00000000000000000000000000000000".to_string())]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    assert!(parse_listeners("").is_empty());
}
