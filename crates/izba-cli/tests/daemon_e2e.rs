//! End-to-end daemon lifecycle against the real `izba` binary and a real
//! microVM. Gated behind `IZBA_INTEGRATION=1` (same convention as the core
//! suite; see docs/testing.md). Run serially:
//!
//! ```text
//! IZBA_INTEGRATION=1 IZBA_KERNEL=... IZBA_INITRAMFS=... \
//! cargo test -p izba-cli --test daemon_e2e -- --test-threads=1 --nocapture
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

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
    let o = izba(&data, no_env, &["exec", "e2e", "--", "/no/such/cmd"]);
    assert_eq!(o.status.code(), Some(127), "exec missing -> 127");
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

    // [5] Version upgrade dance: daemon at version A, client at version B.
    let va: &[(&str, &str)] = &[("IZBA_DAEMON_VERSION", "e2e-A")];
    let vb: &[(&str, &str)] = &[("IZBA_DAEMON_VERSION", "e2e-B")];
    assert_ok(
        &izba(&data, no_env, &["daemon", "stop"]),
        "daemon stop pre-dance",
    );
    assert_ok(&izba(&data, va, &["ls"]), "start daemon as version A");
    assert_eq!(daemon_version_of(&data, va).as_deref(), Some("e2e-A"));
    let o = izba(&data, vb, &["ls"]);
    assert_ok(&o, "client B against daemon A succeeds via upgrade dance");
    assert_eq!(
        daemon_version_of(&data, vb).as_deref(),
        Some("e2e-B"),
        "daemon was replaced by the new version"
    );
    assert!(
        stdout_of(&o).contains("running"),
        "sandbox survived the upgrade"
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
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let o = izba(&data, no_env, &["daemon", "status"]);
        if stdout_of(&o).contains("not running") {
            break;
        }
        assert!(Instant::now() < deadline, "daemon never idle-exited");
        std::thread::sleep(Duration::from_millis(300));
    }

    // [8] Cleanup.
    assert_ok(&izba(&data, no_env, &["rm", "--force", "e2e"]), "rm");
    let _ = izba(&data, no_env, &["daemon", "stop"]);
}
