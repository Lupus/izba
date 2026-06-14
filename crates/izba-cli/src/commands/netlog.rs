//! `izba netlog <sandbox> [--follow]` — the egress audit view ("see every
//! connection"). Reads the per-sandbox `logs/egress-audit.jsonl` that izbad's
//! audit sink appends to and pretty-prints each decision. Read-only: no daemon
//! round-trip, no policy logic — just the file under the sandbox dir.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};
use izba_core::daemon::egress::audit;
use izba_core::paths::Paths;

const AUDIT_FILE: &str = "egress-audit.jsonl";

pub fn run(paths: &Paths, sandbox: &str, follow: bool) -> anyhow::Result<i32> {
    if !paths.sandbox_dir(sandbox).exists() {
        bail!("no such sandbox: {sandbox}");
    }
    let path = paths.logs_dir(sandbox).join(AUDIT_FILE);

    // Print whatever exists so far.
    let mut offset = match std::fs::read_to_string(&path) {
        Ok(text) => {
            print_complete_lines(&text);
            // Resume the follow from the end of the last complete line.
            byte_len_through_last_newline(&text)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !follow {
                eprintln!("izba: no egress recorded yet for '{sandbox}'");
            }
            0
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };

    if !follow {
        return Ok(0);
    }

    // Tail: poll for appended bytes, print only complete (newline-terminated)
    // lines so a half-written record is never shown. Ends on Ctrl-C.
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let appended = match read_from(&path, offset) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("tailing {}", path.display())),
        };
        if appended.is_empty() {
            continue;
        }
        let consumed = byte_len_through_last_newline(&appended);
        if consumed == 0 {
            continue; // only a partial line so far; wait for its newline
        }
        print_complete_lines(&appended[..consumed as usize]);
        offset += consumed;
    }
}

/// Format and print every complete line in `text` (a trailing partial line,
/// if any, is ignored by the caller via the offset bookkeeping).
fn print_complete_lines(text: &str) {
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match audit::parse_line(line) {
            Some(rec) => println!("{}", audit::format_record(&rec)),
            None => eprintln!("izba netlog: skipping malformed line"),
        }
    }
}

/// Byte length of `text` up to and including its last `\n` (0 if none).
fn byte_len_through_last_newline(text: &str) -> u64 {
    match text.rfind('\n') {
        Some(idx) => (idx + 1) as u64,
        None => 0,
    }
}

fn read_from(path: &Path, offset: u64) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_newline_offset() {
        assert_eq!(byte_len_through_last_newline("a\nb\n"), 4);
        assert_eq!(
            byte_len_through_last_newline("a\nb"),
            2,
            "partial tail excluded"
        );
        assert_eq!(byte_len_through_last_newline("no newline"), 0);
        assert_eq!(byte_len_through_last_newline(""), 0);
    }
}
