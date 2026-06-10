//! Host terminal handling: raw mode, window size, tty detection.

use std::io::IsTerminal;

/// Is stdin a terminal? (Cross-platform via std's `IsTerminal`.)
pub fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

pub use imp::{winsize, RawGuard};

#[cfg(unix)]
mod imp {
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

    /// Current terminal size as `(cols, rows)`; falls back to 80x24 when
    /// stdout is not a terminal (or the ioctl fails).
    pub fn winsize() -> (u16, u16) {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
        if rc == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            (ws.ws_col, ws.ws_row)
        } else {
            (80, 24)
        }
    }
}

#[cfg(windows)]
mod imp {
    use anyhow::bail;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetConsoleScreenBufferInfo, SetConsoleMode, CONSOLE_SCREEN_BUFFER_INFO,
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
        ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    };

    /// Puts the console into raw VT mode; restores both saved modes on drop.
    ///
    /// stdin drops line/echo/Ctrl-C processing and turns on VT input (so
    /// arrow keys etc. arrive as escape sequences, matching the guest PTY);
    /// stdout turns on VT processing (so guest escape sequences render).
    pub struct RawGuard {
        stdin: HANDLE,
        stdout: HANDLE,
        saved_in: u32,
        saved_out: u32,
    }

    impl RawGuard {
        pub fn new() -> anyhow::Result<Self> {
            let stdin = io::stdin().as_raw_handle() as HANDLE;
            let stdout = io::stdout().as_raw_handle() as HANDLE;
            let mut saved_in: u32 = 0;
            let mut saved_out: u32 = 0;
            // SAFETY: plain FFI on the process's own std handles.
            unsafe {
                if GetConsoleMode(stdin, &mut saved_in) == 0 {
                    bail!("stdin is not a console");
                }
                if GetConsoleMode(stdout, &mut saved_out) == 0 {
                    bail!("stdout is not a console");
                }
                let raw_in = (saved_in
                    & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
                    | ENABLE_VIRTUAL_TERMINAL_INPUT;
                if SetConsoleMode(stdin, raw_in) == 0 {
                    bail!(
                        "setting console raw input mode: {}",
                        io::Error::last_os_error()
                    );
                }
                let raw_out = saved_out | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                if SetConsoleMode(stdout, raw_out) == 0 {
                    let _ = SetConsoleMode(stdin, saved_in);
                    bail!("enabling console VT output: {}", io::Error::last_os_error());
                }
            }
            Ok(Self {
                stdin,
                stdout,
                saved_in,
                saved_out,
            })
        }
    }

    impl Drop for RawGuard {
        fn drop(&mut self) {
            // SAFETY: restoring the modes we saved on the same handles.
            unsafe {
                let _ = SetConsoleMode(self.stdin, self.saved_in);
                let _ = SetConsoleMode(self.stdout, self.saved_out);
            }
        }
    }

    /// Current console window size as `(cols, rows)`; 80x24 fallback when
    /// stdout is not a console.
    pub fn winsize() -> (u16, u16) {
        let h = io::stdout().as_raw_handle() as HANDLE;
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: valid handle and out-pointer.
        let ok = unsafe { GetConsoleScreenBufferInfo(h, &mut info) };
        if ok != 0 {
            let cols = (info.srWindow.Right - info.srWindow.Left + 1).max(0) as u16;
            let rows = (info.srWindow.Bottom - info.srWindow.Top + 1).max(0) as u16;
            if cols > 0 && rows > 0 {
                return (cols, rows);
            }
        }
        (80, 24)
    }
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
}
