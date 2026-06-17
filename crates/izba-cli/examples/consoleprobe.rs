//! consoleprobe — reproduce-and-confirm harness for the Windows `vim` hang.
//!
//! Root cause: izba's tty/stdout relay pump wrote guest bytes to
//! `std::io::stdout()`, whose Windows console backend transcodes to UTF-16 for
//! `WriteConsoleW` and therefore REJECTS any chunk that isn't valid UTF-8 with
//! `ErrorKind::InvalidData`. Guest programs legitimately emit non-UTF-8 bytes —
//! vim writes a lone `0xbd` during its `t_u7` ambiguous-width probe, right
//! before painting the file — so the pump errored on that chunk and exited,
//! dropping the whole screen redraw and wedging the editor (it also stops
//! reading input, hence "unresponsive to keys and resize"). `less` emits only
//! clean UTF-8, which is why it was unaffected.
//!
//! This probe writes the exact byte sequence vim emits (a redraw containing a
//! raw `0xbd`) two ways and reports the outcome of each:
//!   1. via `std::io::stdout().write_all` — the OLD path; expected to FAIL.
//!   2. via a raw `WriteFile` to the console handle — the FIX; expected to PASS
//!      and to leave the screen fully painted.
//!
//! Run from a REAL Windows Terminal / conhost (NOT WSL interop, which has no
//! console): `consoleprobe.exe`

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

#[cfg(windows)]
const CP_UTF8: u32 = 65001;

/// vim's startup redraw, abbreviated: clear, paint two lines, then the
/// t_u7 ambiguous-width probe (a raw 0xbd byte) followed by more content.
/// The 0xbd is what kills the UTF-8-enforcing path mid-stream.
#[cfg(windows)]
fn vim_like_redraw() -> Vec<u8> {
    let mut vim_like: Vec<u8> = Vec::new();
    vim_like.extend_from_slice(b"\x1b[2J\x1b[1;1Hline-before-probe: ASCII renders fine\r\n");
    vim_like.extend_from_slice(b"\x1b[2;1Hsecond line, then the width probe -> ");
    vim_like.push(0xbd); // the offending non-UTF-8 byte (vim's t_u7 char)
    vim_like.extend_from_slice(b"\x1b[3;1Hline-AFTER-probe: this is the part that vanished\r\n");
    vim_like
}

/// Saved console state, restored by `Drop`.
#[cfg(windows)]
struct ConsoleGuard {
    stdin_h: HANDLE,
    stdout_h: HANDLE,
    in_mode: u32,
    out_mode: u32,
    out_cp: u32,
}

#[cfg(windows)]
impl ConsoleGuard {
    /// Capture the current console state and apply izba's RawGuard setup
    /// (plus the codepage fix). Returns `None` if stdout is not a console.
    fn setup() -> Option<Self> {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetConsoleOutputCP, SetConsoleMode, SetConsoleOutputCP,
            ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
            ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        };

        let stdin_h = std::io::stdin().as_raw_handle() as HANDLE;
        let stdout_h = std::io::stdout().as_raw_handle() as HANDLE;
        let mut in_mode: u32 = 0;
        let mut out_mode: u32 = 0;
        unsafe {
            if GetConsoleMode(stdout_h, &mut out_mode) == 0 {
                return None;
            }
            GetConsoleMode(stdin_h, &mut in_mode);
            let out_cp = GetConsoleOutputCP();
            let raw_in = (in_mode
                & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
                | ENABLE_VIRTUAL_TERMINAL_INPUT;
            SetConsoleMode(stdin_h, raw_in);
            SetConsoleMode(stdout_h, out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            SetConsoleOutputCP(CP_UTF8);
            Some(Self {
                stdin_h,
                stdout_h,
                in_mode,
                out_mode,
                out_cp,
            })
        }
    }
}

#[cfg(windows)]
impl Drop for ConsoleGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::{SetConsoleMode, SetConsoleOutputCP};
        unsafe {
            SetConsoleMode(self.stdin_h, self.in_mode);
            SetConsoleMode(self.stdout_h, self.out_mode);
            SetConsoleOutputCP(self.out_cp);
        }
    }
}

/// Test 1 — the OLD pump path: `std::io::stdout().write_all`, expected to fail.
#[cfg(windows)]
fn run_test1_write_all(vim_like: &[u8]) {
    use std::io::Write;
    print!("\r\n=== Test 1: std::io::stdout().write_all (the OLD pump path) ===\r\n");
    let _ = std::io::stdout().flush();
    let old = std::io::stdout().write_all(vim_like);
    // Move somewhere clean to print the verdict regardless of where the
    // partial write left the cursor.
    print!("\x1b[6;1H");
    match &old {
        Ok(()) => print!("Test 1 result: write_all returned Ok (unexpected on a console)\r\n"),
        Err(e) => print!(
            "Test 1 result: write_all FAILED -> {:?}: {}\r\n   (note 'line-AFTER-probe' above is MISSING — exactly the vim hang)\r\n",
            e.kind(),
            e
        ),
    }
    let _ = std::io::stdout().flush();
}

/// Test 2 — the FIX path: a raw `WriteFile` to the console handle.
#[cfg(windows)]
fn run_test2_writefile(stdout_h: HANDLE, vim_like: &[u8]) {
    use std::io::Write;
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    print!("\r\n=== Test 2: raw WriteFile to the console handle (the FIX) ===\r\n");
    let _ = std::io::stdout().flush();
    let mut written: u32 = 0;
    let ok = unsafe {
        WriteFile(
            stdout_h,
            vim_like.as_ptr(),
            vim_like.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    print!("\x1b[14;1H");
    if ok != 0 {
        print!(
            "Test 2 result: WriteFile wrote {written}/{} bytes OK\r\n   (note 'line-AFTER-probe' IS present above — fix verified)\r\n",
            vim_like.len()
        );
    } else {
        print!(
            "Test 2 result: WriteFile FAILED -> {}\r\n",
            std::io::Error::last_os_error()
        );
    }
    let _ = std::io::stdout().flush();
}

/// Render a chunk of raw input bytes as a human-readable escape string.
#[cfg(windows)]
fn render_key_bytes(chunk: &[u8]) -> String {
    let mut s = String::new();
    for &c in chunk {
        match c {
            0x1b => s.push_str("\\e"),
            b'\r' => s.push_str("\\r"),
            b'\n' => s.push_str("\\n"),
            0x20..=0x7e => s.push(c as char),
            _ => s.push_str(&format!("\\x{c:02x}")),
        }
    }
    s
}

/// Test 3 — input sanity: echo raw key bytes until 'q' or a 15s idle timeout.
#[cfg(windows)]
fn run_test3_input_echo() {
    use std::io::{Read, Write};
    use std::sync::mpsc;
    use std::time::Duration;

    print!("\r\n=== Test 3: press a few keys (arrows/letters), 'q' to quit ===\r\n");
    let _ = std::io::stdout().flush();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        let mut stdin = std::io::stdin();
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                return;
            }
        }
    });
    while let Ok(chunk) = rx.recv_timeout(Duration::from_secs(15)) {
        print!("  key bytes: {}\r\n", render_key_bytes(&chunk));
        let _ = std::io::stdout().flush();
        if chunk.contains(&b'q') {
            return;
        }
    }
    print!("  (no input for 15s, exiting)\r\n");
}

#[cfg(windows)]
fn main() {
    let vim_like = vim_like_redraw();

    let Some(guard) = ConsoleGuard::setup() else {
        eprintln!("ERROR: stdout is not a console — run this from a real Windows Terminal, not WSL interop.");
        std::process::exit(1);
    };
    let stdout_h = guard.stdout_h;

    run_test1_write_all(&vim_like);
    run_test2_writefile(stdout_h, &vim_like);
    run_test3_input_echo();

    drop(guard);
    println!("consoleprobe done.");
}

#[cfg(not(windows))]
fn main() {
    eprintln!("consoleprobe is Windows-only; run it on the Windows spike host.");
}
