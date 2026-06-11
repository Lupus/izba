//! Tier 1: drive the real `izba exec -it` binary through a PTY/ConPTY against a
//! scripted fake guest — no VM. Self-skips where a PTY cannot be allocated.

use izba_ttytest::harness::TerminalSession;
use izba_ttytest::scenarios::{self, Scenario};
use izba_ttytest::scripted_guest::ScriptedGuest;
use portable_pty::CommandBuilder;
use std::time::Duration;

/// Build `izba exec -it <name> -- <argv...>` pointed at the guest's data root.
fn izba_exec_cmd(guest: &ScriptedGuest, argv: &[String]) -> CommandBuilder {
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_izba"));
    cmd.arg("exec");
    cmd.arg("-it");
    cmd.arg(guest.sandbox_name());
    cmd.arg("--");
    for a in argv {
        cmd.arg(a);
    }
    cmd.env("IZBA_DATA_DIR", guest.data_dir());
    // The daemon-first CLI auto-starts izbad per data root; keep test
    // daemons short-lived so nothing lingers after the suite.
    cmd.env("IZBA_DAEMON_IDLE_SECS", "2");
    cmd.env("TERM", "xterm-256color");
    cmd
}

/// Best-effort: stop the per-data-root daemon the CLI auto-started.
/// Leaked daemons also self-exit via IZBA_DAEMON_IDLE_SECS=2.
fn stop_daemon(data_dir: &std::path::Path) {
    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_izba"))
        .env("IZBA_DATA_DIR", data_dir)
        .args(["daemon", "stop"])
        .output();
}

/// Spawn the session, self-skipping if no PTY is available here.
fn session_or_skip(guest: &ScriptedGuest, sc: &Scenario) -> Option<TerminalSession> {
    let cmd = izba_exec_cmd(guest, &sc.argv);
    match TerminalSession::spawn(cmd, 80, 24) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("SKIP {}: cannot allocate a PTY here: {e:#}", sc.name);
            None
        }
    }
}

const T: Duration = Duration::from_secs(10);

#[test]
fn vim_renders_through_the_probe_byte() {
    let sc = scenarios::vim_redraw();
    let Some(guest) = ScriptedGuest::start_or_skip(scenarios::vim_redraw().script) else {
        return;
    };
    let Some(mut sess) = session_or_skip(&guest, &sc) else {
        return;
    };

    // The line AFTER the 0xbd probe must render — this is the bug we fixed.
    sess.wait_for_text("line-AFTER-probe", T)
        .expect("post-probe line");

    // Resize and confirm the guest saw it and repainted.
    sess.resize(90, 20).unwrap();
    sess.wait_for_text("resized to 90x20", T).expect("repaint");

    sess.send_keys("q").unwrap();
    let out = sess.wait_exit(T).expect("exit");
    assert_eq!(out.code, Some(0));
    assert_eq!(guest.last_resize(), Some((90, 20)));
    stop_daemon(guest.data_dir());
}

#[test]
fn arrow_keys_reach_the_guest() {
    let sc = scenarios::arrow_keys();
    let Some(guest) = ScriptedGuest::start_or_skip(scenarios::arrow_keys().script) else {
        return;
    };
    let Some(mut sess) = session_or_skip(&guest, &sc) else {
        return;
    };

    sess.wait_for_text("sh-prompt$", T).expect("prompt");
    sess.send_bytes(b"\x1b[A\x1b[B").unwrap(); // up, down
    sess.send_keys("q").unwrap();
    sess.wait_exit(T).expect("exit");

    let got = guest.received_input();
    assert!(
        got.windows(3).any(|w| w == b"\x1b[A"),
        "up-arrow not delivered: {got:?}"
    );
    stop_daemon(guest.data_dir());
}

#[test]
fn ctrl_c_ends_exec_without_killing_izba() {
    let sc = scenarios::ctrl_c();
    let Some(guest) = ScriptedGuest::start_or_skip(scenarios::ctrl_c().script) else {
        return;
    };
    let Some(mut sess) = session_or_skip(&guest, &sc) else {
        return;
    };

    sess.wait_for_text("sleeping...", T).expect("running");
    assert!(
        sess.is_child_alive(),
        "izba must still be alive before Ctrl-C"
    );
    sess.send_bytes(&[0x03]).unwrap(); // Ctrl-C

    let out = sess.wait_exit(T).expect("exit");
    // ExitStatus::Signal(2) -> CLI exit 128 + 2 = 130.
    assert_eq!(out.code, Some(130));
    assert!(guest.received_input().contains(&0x03));
    stop_daemon(guest.data_dir());
}

#[test]
fn exit_code_passthrough() {
    let sc = scenarios::exit_code(42);
    let Some(guest) = ScriptedGuest::start_or_skip(scenarios::exit_code(42).script) else {
        return;
    };
    let Some(mut sess) = session_or_skip(&guest, &sc) else {
        return;
    };
    let out = sess.wait_exit(T).expect("exit");
    assert_eq!(out.code, Some(42));
    stop_daemon(guest.data_dir());
}

#[test]
fn command_not_found_is_127() {
    let sc = scenarios::command_not_found();
    let Some(guest) = ScriptedGuest::start_or_skip(scenarios::command_not_found().script) else {
        return;
    };
    let Some(mut sess) = session_or_skip(&guest, &sc) else {
        return;
    };
    let out = sess.wait_exit(T).expect("exit");
    assert_eq!(out.code, Some(127));
    stop_daemon(guest.data_dir());
}
