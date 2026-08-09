//! `izba vnc` end-to-end against the real binary, backed by a hand-rolled
//! FAKE daemon (a plain `DaemonHello`/`DaemonRequest`/`DaemonResponse` script
//! over a real Unix socket bound at the exact path `DaemonClient::connect`
//! resolves) rather than a real `izbad` — modeled on `usb_cli.rs`'s
//! subprocess-driven shape, but the daemon side is scripted so `Inspect` can
//! report states (a live relay + credentialed `vnc_url`, a desktop that's
//! stopped answering, `vnc off` against an already-running desktop) that no
//! VM-free real daemon could ever produce.
//!
//! Task 11 review (I2): this is what actually reaches `vnc_set`/`inspect` —
//! the daemon-driving `run()` itself is `#[mutants::skip]`, but these two
//! helper functions are not, and their `Ok(0)`-shaped mutants only die when
//! something asserts on the real subprocess's exit code and output, which is
//! exactly what these tests do.

use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use izba_core::build_info::BuildInfoOwned;
use izba_core::daemon::proto::{
    DaemonHello, DaemonRequest, DaemonResponse, SandboxDetail, DAEMON_PROTO_VERSION,
};
use izba_core::daemon::transport;
use izba_core::paths::Paths;
use izba_core::vmm::UdsStream;
use izba_proto::{read_frame, write_frame};

fn izba(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_izba"))
        .args(args)
        .env("IZBA_DATA_DIR", data)
        // Defensive: if a real daemon ever does get spawned instead of our
        // fake one reaching the socket first, let it self-exit fast.
        .env("IZBA_DAEMON_IDLE_SECS", "2")
        .output()
        .expect("run izba")
}

fn base_detail(name: &str) -> SandboxDetail {
    SandboxDetail {
        name: name.into(),
        image_ref: "ubuntu:24.04".into(),
        image_digest: "sha256:abc".into(),
        cpus: 1,
        mem_mb: 256,
        workspace: "/ws".into(),
        status: "stopped".into(),
        ports: vec![],
        volumes: vec![],
        confinement: None,
        container: None,
        user_fallback: None,
        docker: false,
        vnc: false,
        vnc_running: false,
        vnc_url: None,
        vnc_restart_required: false,
    }
}

/// Fake-daemon state: `detail` is what `Inspect` reports (a `VncSet` request
/// flips `.vnc` on it, mirroring the real handler's persist-then-you-can-
/// re-Inspect-it shape); `error`, when set, makes EVERY request — regardless
/// of type — answer with that `DaemonResponse::Error` instead, standing in
/// for a daemon-side refusal (e.g. "no such sandbox").
struct FakeState {
    detail: SandboxDetail,
    error: Option<String>,
}

/// Bind a fake daemon at `paths.daemon_socket()` (the exact path
/// `DaemonClient::connect` dials) and serve `state` for the rest of the
/// test. Returns `None` (the test should skip, not fail) where the sandbox
/// denies binding a Unix socket — the house convention, see `vsock.rs`'s
/// `full_connect_via_listener`.
fn fake_daemon(paths: &Paths, state: Arc<Mutex<FakeState>>) -> Option<()> {
    let listener = match transport::bind_socket(paths) {
        Ok(l) => l,
        Err(e) => {
            let msg = format!("{e:#}");
            if msg.contains("Permission denied") || msg.contains("Operation not permitted") {
                return None;
            }
            panic!("binding fake daemon socket: {e:#}");
        }
    };
    std::thread::spawn(move || loop {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || serve_one(stream, state));
            }
            Err(_) => return,
        }
    });
    Some(())
}

/// One connection: hello, then answer every request off `state` until the
/// client closes the socket (a plain EOF, not an error — each `izba vnc …`
/// subcommand makes a fresh connection per RPC and drops it when done).
fn serve_one(mut s: UdsStream, state: Arc<Mutex<FakeState>>) {
    let _hello: DaemonHello = match read_frame(&mut s) {
        Ok(h) => h,
        Err(_) => return,
    };
    let hello_ok = DaemonResponse::HelloOk {
        version: "fake".into(),
        proto: DAEMON_PROTO_VERSION,
        build: BuildInfoOwned::default(),
    };
    if write_frame(&mut s, &hello_ok).is_err() {
        return;
    }
    loop {
        let req: DaemonRequest = match read_frame(&mut s) {
            Ok(r) => r,
            Err(_) => return,
        };
        let resp = {
            let mut st = state.lock().unwrap();
            if let Some(message) = st.error.clone() {
                DaemonResponse::Error { message }
            } else {
                match req {
                    DaemonRequest::VncSet { enabled, .. } => {
                        st.detail.vnc = enabled;
                        DaemonResponse::Ok
                    }
                    DaemonRequest::Inspect { .. } => DaemonResponse::Inspect(st.detail.clone()),
                    _ => DaemonResponse::Error {
                        message: "fake daemon: unsupported request".into(),
                    },
                }
            }
        };
        if write_frame(&mut s, &resp).is_err() {
            return;
        }
    }
}

/// Set up a temp data dir + fake daemon serving `detail`. Returns `None`
/// (the caller should skip, not fail) when the sandbox denies the bind.
fn setup(detail: SandboxDetail) -> Option<(tempfile::TempDir, Arc<Mutex<FakeState>>)> {
    let data = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(data.path().to_path_buf());
    let state = Arc::new(Mutex::new(FakeState {
        detail,
        error: None,
    }));
    fake_daemon(&paths, Arc::clone(&state))?;
    Some((data, state))
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// on / off
// ---------------------------------------------------------------------------

#[test]
fn vnc_on_flips_config_and_confirms_without_restart_guidance_when_stopped() {
    let Some((data, state)) = setup(base_detail("web")) else {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    };
    let out = izba(data.path(), &["vnc", "on", "web"]);
    assert!(out.status.success(), "{out:?}");
    assert!(
        stdout_of(&out).contains("vnc enabled for 'web'"),
        "{}",
        stdout_of(&out)
    );
    assert!(
        stderr_of(&out).is_empty(),
        "a stopped sandbox needs no restart guidance: {}",
        stderr_of(&out)
    );
    assert!(state.lock().unwrap().detail.vnc, "config must flip");
}

#[test]
fn vnc_off_flips_config_and_confirms() {
    let mut det = base_detail("web");
    det.vnc = true;
    let Some((data, state)) = setup(det) else {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    };
    let out = izba(data.path(), &["vnc", "off", "web"]);
    assert!(out.status.success(), "{out:?}");
    assert!(
        stdout_of(&out).contains("vnc disabled for 'web'"),
        "{}",
        stdout_of(&out)
    );
    assert!(!state.lock().unwrap().detail.vnc, "config must flip");
}

#[test]
fn vnc_on_a_running_sandbox_prints_restart_guidance_on_stderr() {
    let mut det = base_detail("web");
    det.status = "running".into();
    det.vnc_restart_required = true; // what the post-flip Inspect will report
    let Some((data, _state)) = setup(det) else {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    };
    let out = izba(data.path(), &["vnc", "on", "web"]);
    assert!(
        out.status.success(),
        "restart guidance is a warning, not a failure: {out:?}"
    );
    assert!(
        stderr_of(&out).contains("vnc: restart required — stop and start 'web' to apply"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn vnc_on_of_an_unknown_sandbox_reports_the_daemons_error() {
    let Some((data, state)) = setup(base_detail("ghost")) else {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    };
    state.lock().unwrap().error = Some("no such sandbox 'ghost'".into());
    let out = izba(data.path(), &["vnc", "on", "ghost"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr_of(&out).contains("no such sandbox"),
        "{}",
        stderr_of(&out)
    );
}

// ---------------------------------------------------------------------------
// url — the credentialed-URL discipline surface
// ---------------------------------------------------------------------------

#[test]
fn vnc_url_when_not_enabled_refuses_without_leaking_anything_on_stdout() {
    let Some((data, _state)) = setup(base_detail("web")) else {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    };
    let out = izba(data.path(), &["vnc", "url", "web"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr_of(&out).contains("vnc not enabled"),
        "{}",
        stderr_of(&out)
    );
    assert!(stdout_of(&out).is_empty(), "{}", stdout_of(&out));
}

#[test]
fn vnc_url_when_enabled_but_stopped_refuses() {
    let mut det = base_detail("web");
    det.vnc = true;
    let Some((data, _state)) = setup(det) else {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    };
    let out = izba(data.path(), &["vnc", "url", "web"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr_of(&out).contains("sandbox not running"),
        "{}",
        stderr_of(&out)
    );
    assert!(stdout_of(&out).is_empty(), "{}", stdout_of(&out));
}

#[test]
fn vnc_url_prints_exactly_the_url_when_relayed_and_answering() {
    let mut det = base_detail("web");
    det.vnc = true;
    det.status = "running".into();
    det.vnc_running = true;
    det.vnc_url = Some("http://izba:s3cr3t@127.0.0.1:4444/".into());
    let Some((data, _state)) = setup(det) else {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    };
    let out = izba(data.path(), &["vnc", "url", "web"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(stdout_of(&out), "http://izba:s3cr3t@127.0.0.1:4444/\n");
    assert!(stderr_of(&out).is_empty(), "{}", stderr_of(&out));
}

#[test]
fn vnc_url_warns_but_still_prints_the_url_when_the_desktop_is_dead() {
    let mut det = base_detail("web");
    det.vnc = true;
    det.status = "running".into();
    det.vnc_running = false; // relay is up, desktop process isn't answering
    det.vnc_url = Some("http://izba:s3cr3t@127.0.0.1:4444/".into());
    let Some((data, _state)) = setup(det) else {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    };
    let out = izba(data.path(), &["vnc", "url", "web"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(stdout_of(&out), "http://izba:s3cr3t@127.0.0.1:4444/\n");
    assert!(
        stderr_of(&out).contains("the desktop is not answering"),
        "{}",
        stderr_of(&out)
    );
    assert!(
        stderr_of(&out).contains("izba exec web -- cat /var/log/izba-vnc.log"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn vnc_url_after_a_live_off_still_returns_the_url_with_a_warning() {
    // Task 11 review I4: `vnc off` against an already-running sandbox flips
    // config immediately, but `vnc_url` is keyed on the live relay, not on
    // config — the desktop is still real and reachable until a restart.
    let mut det = base_detail("web");
    det.vnc = false;
    det.status = "running".into();
    det.vnc_running = true;
    det.vnc_url = Some("http://izba:s3cr3t@127.0.0.1:4444/".into());
    let Some((data, _state)) = setup(det) else {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    };
    let out = izba(data.path(), &["vnc", "url", "web"]);
    assert!(out.status.success(), "{out:?}");
    assert_eq!(stdout_of(&out), "http://izba:s3cr3t@127.0.0.1:4444/\n");
    assert!(
        stderr_of(&out).contains("vnc is disabled in config"),
        "{}",
        stderr_of(&out)
    );
    assert!(
        stderr_of(&out).contains("next restart"),
        "{}",
        stderr_of(&out)
    );
}

// ---------------------------------------------------------------------------
// open — must never leak the URL on the refusal path
// ---------------------------------------------------------------------------

#[test]
fn vnc_open_of_a_not_enabled_sandbox_never_prints_a_url() {
    let Some((data, _state)) = setup(base_detail("web")) else {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    };
    let out = izba(data.path(), &["vnc", "open", "web"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr_of(&out).contains("vnc not enabled"),
        "{}",
        stderr_of(&out)
    );
    assert!(
        stdout_of(&out).is_empty(),
        "the refusal path must never print anything URL-shaped: {}",
        stdout_of(&out)
    );
    assert!(!stderr_of(&out).contains("http://"), "{}", stderr_of(&out));
}

#[test]
fn vnc_help_lists_every_verb() {
    let data = tempfile::tempdir().unwrap();
    let out = izba(data.path(), &["vnc", "--help"]);
    assert!(out.status.success());
    let text = stdout_of(&out);
    for sub in ["on", "off", "url", "open"] {
        assert!(text.contains(sub), "missing subcommand {sub}: {text}");
    }
}
