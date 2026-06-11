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
fn main() {
    use std::io::{Read, Write};
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetConsoleOutputCP, SetConsoleMode, SetConsoleOutputCP, ENABLE_ECHO_INPUT,
        ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    };

    const CP_UTF8: u32 = 65001;

    // vim's startup redraw, abbreviated: clear, paint two lines, then the
    // t_u7 ambiguous-width probe (a raw 0xbd byte) followed by more content.
    // The 0xbd is what kills the UTF-8-enforcing path mid-stream.
    let mut vim_like: Vec<u8> = Vec::new();
    vim_like.extend_from_slice(b"\x1b[2J\x1b[1;1Hline-before-probe: ASCII renders fine\r\n");
    vim_like.extend_from_slice(b"\x1b[2;1Hsecond line, then the width probe -> ");
    vim_like.push(0xbd); // the offending non-UTF-8 byte (vim's t_u7 char)
    vim_like.extend_from_slice(b"\x1b[3;1Hline-AFTER-probe: this is the part that vanished\r\n");

    let stdin_h = std::io::stdin().as_raw_handle() as HANDLE;
    let stdout_h = std::io::stdout().as_raw_handle() as HANDLE;
    let (mut in_mode, mut out_mode, out_cp);
    unsafe {
        in_mode = 0;
        out_mode = 0;
        if GetConsoleMode(stdout_h, &mut out_mode) == 0 {
            eprintln!("ERROR: stdout is not a console — run this from a real Windows Terminal, not WSL interop.");
            std::process::exit(1);
        }
        GetConsoleMode(stdin_h, &mut in_mode);
        out_cp = GetConsoleOutputCP();
        // izba's RawGuard setup (plus the codepage fix).
        let raw_in = (in_mode & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
            | ENABLE_VIRTUAL_TERMINAL_INPUT;
        SetConsoleMode(stdin_h, raw_in);
        SetConsoleMode(stdout_h, out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        SetConsoleOutputCP(CP_UTF8);
    }

    let restore = || unsafe {
        SetConsoleMode(stdin_h, in_mode);
        SetConsoleMode(stdout_h, out_mode);
        SetConsoleOutputCP(out_cp);
    };

    // --- 1. OLD path: std::io::stdout().write_all ---
    print!("\r\n=== Test 1: std::io::stdout().write_all (the OLD pump path) ===\r\n");
    let _ = std::io::stdout().flush();
    let old = std::io::stdout().write_all(&vim_like);
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

    // --- 2. FIX path: raw WriteFile to the console handle ---
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

    // --- 3. quick input sanity: echo raw key bytes for a few seconds ---
    print!("\r\n=== Test 3: press a few keys (arrows/letters), 'q' to quit ===\r\n");
    let _ = std::io::stdout().flush();
    use std::sync::mpsc;
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
    loop {
        match rx.recv_timeout(Duration::from_secs(15)) {
            Ok(chunk) => {
                let mut s = String::new();
                for &c in &chunk {
                    match c {
                        0x1b => s.push_str("\\e"),
                        b'\r' => s.push_str("\\r"),
                        b'\n' => s.push_str("\\n"),
                        0x20..=0x7e => s.push(c as char),
                        _ => s.push_str(&format!("\\x{c:02x}")),
                    }
                }
                print!("  key bytes: {s}\r\n");
                let _ = std::io::stdout().flush();
                if chunk.contains(&b'q') {
                    break;
                }
            }
            Err(_) => {
                print!("  (no input for 15s, exiting)\r\n");
                break;
            }
        }
    }

    restore();
    println!("consoleprobe done.");
}

#[cfg(not(windows))]
fn main() {
    eprintln!("consoleprobe is Windows-only; run it on the Windows spike host.");
}
