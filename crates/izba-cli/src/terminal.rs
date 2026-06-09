//! Host terminal handling: raw mode, window size, tty detection.

use anyhow::Context;
use nix::sys::termios::{self, SetArg, Termios};
use std::io;

/// Puts stdin into raw mode; restores the saved settings on drop, so the
/// terminal recovers even on early returns and panics that unwind.
pub struct RawGuard {
    saved: Termios,
}

impl RawGuard {
    pub fn new() -> anyhow::Result<Self> {
        let saved = termios::tcgetattr(io::stdin()).context("reading terminal attributes")?;
        let mut raw = saved.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(io::stdin(), SetArg::TCSANOW, &raw)
            .context("setting terminal raw mode")?;
        Ok(Self { saved })
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(io::stdin(), SetArg::TCSANOW, &self.saved);
    }
}

/// Current terminal size as `(cols, rows)`; falls back to 80x24 when stdout
/// is not a terminal (or the ioctl fails).
pub fn winsize() -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if rc == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
        (ws.ws_col, ws.ws_row)
    } else {
        (80, 24)
    }
}

/// Is the given fd a terminal?
pub fn is_tty(fd: std::os::fd::RawFd) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn winsize_has_fallback() {
        // Under `cargo test` stdout is a pipe, so this exercises the fallback;
        // on a real terminal it returns the actual size. Either way: nonzero.
        let (cols, rows) = winsize();
        assert!(cols > 0 && rows > 0);
    }

    #[test]
    fn devnull_is_not_a_tty() {
        use std::os::fd::AsRawFd;
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(!is_tty(f.as_raw_fd()));
    }
}
