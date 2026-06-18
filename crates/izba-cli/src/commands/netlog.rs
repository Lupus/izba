//! `izba netlog <sandbox> [--follow]` — the egress audit view ("see every
//! connection"). Reads the per-sandbox `logs/egress-audit.jsonl` that izbad's
//! audit sink appends to and pretty-prints each decision. Read-only: no daemon
//! round-trip, no policy logic — just the file under the sandbox dir.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};
use izba_core::daemon::egress::audit;
use izba_core::daemon::egress::audit::git_op_label;
use izba_core::paths::Paths;

const AUDIT_FILE: &str = "egress-audit.jsonl";

pub fn run(paths: &Paths, sandbox: &str, summary: bool, follow: bool) -> anyhow::Result<i32> {
    if !paths.sandbox_dir(sandbox).exists() {
        bail!("no such sandbox: {sandbox}");
    }
    let path = paths.logs_dir(sandbox).join(AUDIT_FILE);

    if summary {
        return print_summary(&path, sandbox);
    }

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

fn print_summary(path: &Path, sandbox: &str) -> anyhow::Result<i32> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("izba: no egress recorded yet for '{sandbox}'");
            return Ok(0);
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let records = text.lines().filter_map(audit::parse_line);
    for s in audit::aggregate(records) {
        println!("{}", format_summary_row(&s));
    }
    Ok(0)
}

/// `<utc>  ALLOW/DENY l7  host|ip:port  a<allow>/d<deny>  [METHOD path]`
fn format_summary_row(s: &izba_core::daemon::egress::audit::EndpointSummary) -> String {
    use izba_core::daemon::egress::policy::Verdict;
    let ts = izba_core::daemon::egress::audit::format_ts_ms(s.last_seen_ms);
    let verdict = match s.verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY ",
    };
    let tier = match s.tier {
        izba_core::daemon::egress::audit::Tier::L7 => "l7",
        izba_core::daemon::egress::audit::Tier::L3 => "l3",
    };
    let target = s.host.clone().unwrap_or_else(|| s.dest_ip.to_string());
    let req = match git_op_label(s.last_method.as_deref(), s.last_path.as_deref()) {
        Some(label) => format!("  {label}"),
        None => match (&s.last_method, &s.last_path) {
            (Some(m), Some(p)) => format!("  {m} {p}"),
            _ => String::new(),
        },
    };
    format!(
        "{ts}  {verdict} {tier}  {target}:{port}  a{a}/d{d}{req}",
        port = s.port,
        a = s.allow_count,
        d = s.deny_count,
    )
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

    #[test]
    fn summary_row_renders_endpoint_counts_and_verdict() {
        use izba_core::daemon::egress::audit::{aggregate, AuditRecord, Tier};
        use izba_core::daemon::egress::policy::Verdict;
        let mut a = AuditRecord::allow(
            "web",
            "1.1.1.1".parse().unwrap(),
            443,
            Some("api.x.com"),
            Tier::L7,
            "ok",
        );
        a.ts_ms = 1_700_000_000_000;
        let mut d = AuditRecord::deny(
            "web",
            "1.1.1.1".parse().unwrap(),
            443,
            Some("api.x.com"),
            Tier::L7,
            "no",
        );
        d.ts_ms = 1_700_000_001_000;
        let summaries = aggregate(vec![a, d]);
        let line = format_summary_row(&summaries[0]);
        assert!(line.contains("api.x.com:443"), "{line}");
        assert!(line.contains("DENY"), "latest verdict: {line}");
        assert!(
            line.contains("a1/d1") || (line.contains("allow=1") && line.contains("deny=1")),
            "{line}"
        );
        let _ = Verdict::Allow; // import used
    }
}
