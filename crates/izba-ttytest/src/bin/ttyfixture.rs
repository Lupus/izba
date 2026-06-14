//! Tiny cross-platform fixture for the TerminalSession smoke test: print a
//! banner, echo each input chunk back prefixed with `GOT:`, and exit on `q`.
use std::io::{Read, Write};

/// Put stdin into raw mode so reads return immediately (byte-by-byte) rather
/// than waiting for a newline in the PTY line discipline.
#[cfg(unix)]
fn enter_raw_mode() {
    use std::os::unix::io::AsRawFd;
    let fd = std::io::stdin().as_raw_fd();
    // SAFETY: stdin fd is valid; only enable raw mode if tcgetattr succeeds.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) == 0 {
            libc::cfmakeraw(&mut t);
            libc::tcsetattr(fd, libc::TCSANOW, &t);
        }
    }
}

#[cfg(windows)]
fn enter_raw_mode() {
    // A ConPTY child's stdin defaults to cooked console mode (ENABLE_LINE_INPUT
    // | ENABLE_ECHO_INPUT), so reads block until Enter and the pty echoes input
    // locally — the Windows analogue of cfmakeraw. Clear those so reads return
    // per-keystroke, matching the unix fixture (and how real TUI apps behave).
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
        ENABLE_PROCESSED_INPUT, STD_INPUT_HANDLE,
    };
    // SAFETY: STD_INPUT_HANDLE is a valid console handle under ConPTY; we only
    // mutate the input mode if GetConsoleMode succeeds.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0u32;
        if GetConsoleMode(h, &mut mode) != 0 {
            mode &= !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
            SetConsoleMode(h, mode);
        }
    }
}

fn main() {
    enter_raw_mode();

    let mut out = std::io::stdout();
    let _ = out.write_all(b"TTYFIXTURE-READY\r\n");
    let _ = out.flush();

    let mut stdin = std::io::stdin();
    let mut buf = [0u8; 64];
    loop {
        match stdin.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let _ = out.write_all(b"GOT:");
                let _ = out.write_all(&buf[..n]);
                let _ = out.write_all(b"\r\n");
                let _ = out.flush();
                if buf[..n].contains(&b'q') {
                    break;
                }
            }
        }
    }
    let _ = out.write_all(b"TTYFIXTURE-BYE\r\n");
    let _ = out.flush();
}
