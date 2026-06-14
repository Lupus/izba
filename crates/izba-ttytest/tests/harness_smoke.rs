use izba_ttytest::harness::TerminalSession;
use portable_pty::CommandBuilder;
use std::time::Duration;

/// Self-skip when this environment cannot allocate a PTY/ConPTY.
fn pty_or_skip(cmd: CommandBuilder) -> Option<TerminalSession> {
    match TerminalSession::spawn(cmd, 80, 24) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("SKIP: cannot allocate a PTY here: {e:#}");
            None
        }
    }
}

#[test]
fn fixture_banner_echo_and_exit() {
    let cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_ttyfixture"));
    let Some(mut sess) = pty_or_skip(cmd) else {
        return;
    };

    sess.wait_for_text("TTYFIXTURE-READY", Duration::from_secs(5))
        .expect("banner");
    sess.send_keys("hi").expect("send hi");
    sess.wait_for_text("GOT:hi", Duration::from_secs(5))
        .expect("echo");
    sess.send_keys("q").expect("send q");
    let outcome = sess.wait_exit(Duration::from_secs(5)).expect("exit");
    assert_eq!(outcome.code, Some(0));
}

/// Always-pass diagnostic that emits structured `CONPTY-DIAG` evidence via the
/// *real* portable-pty path (the code that actually fails on hosted Windows
/// runners). Run with `--nocapture`: it never asserts, so the evidence is
/// captured even when ConPTY output is lost. Discriminates the two root-cause
/// hypotheses — `bytes=0 eof=true` with a clean child exit points at ConPTY
/// output loss, not a crashed child.
#[test]
fn conpty_diagnostic_dump() {
    println!(
        "CONPTY-DIAG begin os={} arch={}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_ttyfixture"));
    let mut sess = match TerminalSession::spawn(cmd, 80, 24) {
        Ok(s) => {
            println!("CONPTY-DIAG child_spawned=true");
            s
        }
        Err(e) => {
            println!("CONPTY-DIAG child_spawned=false err={e:#}");
            return;
        }
    };

    let banner = sess.wait_for_text("TTYFIXTURE-READY", Duration::from_secs(5));
    println!("CONPTY-DIAG banner_seen={}", banner.is_ok());
    println!("CONPTY-DIAG {}", sess.read_report());
    println!("CONPTY-DIAG child_alive={}", sess.is_child_alive());

    // Nudge the child to exit so we can report its code without hanging.
    let _ = sess.send_keys("q");
    match sess.wait_exit(Duration::from_secs(5)) {
        Ok(o) => println!("CONPTY-DIAG child_exit_code={:?}", o.code),
        Err(e) => println!("CONPTY-DIAG child_exit=unknown ({e:#})"),
    }
    println!("CONPTY-DIAG {}", sess.read_report());
    println!(
        "CONPTY-DIAG screen_nonblank_chars={}",
        sess.screen_text()
            .chars()
            .filter(|c| !c.is_whitespace())
            .count()
    );
    println!("CONPTY-DIAG end");
}

#[test]
fn resize_updates_grid_dimensions() {
    let cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_ttyfixture"));
    let Some(sess) = pty_or_skip(cmd) else { return };
    // Resizing must not error; the fixture ignores SIGWINCH, so we only assert
    // the call succeeds and the parser tracks the new size.
    sess.resize(100, 30).expect("resize");
    assert_eq!(sess.size(), (100, 30));
}
