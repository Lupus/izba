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

#[test]
fn resize_updates_grid_dimensions() {
    let cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_ttyfixture"));
    let Some(sess) = pty_or_skip(cmd) else { return };
    // Resizing must not error; the fixture ignores SIGWINCH, so we only assert
    // the call succeeds and the parser tracks the new size.
    sess.resize(100, 30).expect("resize");
    assert_eq!(sess.size(), (100, 30));
}
