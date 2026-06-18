//! `izba-jail-helper` — elevated helper binary for per-sandbox Windows account
//! management.
//!
//! This binary is designed to be run ELEVATED (UAC prompt or Task Scheduler) and
//! performs account/firewall operations that require administrator rights on behalf
//! of the un-elevated `izbad` daemon. It receives a sub-command verb on the
//! command line and writes a JSON result to stdout before exiting.
//!
//! # Verbs
//!
//! - `provision --sandbox <name> --grant <path>… --sid-out <file> --cred-out <file>`
//! - `deprovision --sandbox <name>`
//! - `gc --live <name>…`
//!
//! # Platform
//!
//! The binary is Windows-only. On non-Windows it prints a diagnostic to stderr
//! and exits with code 2 (mirrors the `confine_probe` example pattern).

pub mod account;
pub mod dacl;
pub mod userlist;

// ── Verb definition (all platforms) ─────────────────────────────────────────

/// A parsed command-line verb, ready for dispatch.
#[derive(Debug, PartialEq)]
pub enum Verb {
    Provision {
        sandbox: String,
        grants: Vec<String>,
        sid_out: String,
        cred_out: String,
    },
    Deprovision {
        sandbox: String,
    },
    Gc {
        live: Vec<String>,
    },
}

// ── Pure arg parser (all platforms, fully unit-tested) ───────────────────────

/// Parse an `argv` slice (excluding `argv[0]`) into a [`Verb`].
///
/// The flag names here MUST match the argv builders in
/// `izba-core/src/jail_account/builders.rs` exactly:
///
/// - `provision --sandbox <name> --grant <path>… --sid-out <file> --cred-out <file>`
/// - `deprovision --sandbox <name>`
/// - `gc --live <name>…`
pub fn parse_args(argv: &[String]) -> Result<Verb, String> {
    let mut it = argv.iter();
    let verb_str = it
        .next()
        .ok_or_else(|| "usage: izba-jail-helper <provision|deprovision|gc> [flags]".to_string())?;

    match verb_str.as_str() {
        "provision" => parse_provision(it.as_slice()),
        "deprovision" => parse_deprovision(it.as_slice()),
        "gc" => parse_gc(it.as_slice()),
        other => Err(format!(
            "unknown verb {other:?}: expected one of provision, deprovision, gc"
        )),
    }
}

fn parse_provision(args: &[String]) -> Result<Verb, String> {
    let mut sandbox: Option<String> = None;
    let mut grants: Vec<String> = Vec::new();
    let mut sid_out: Option<String> = None;
    let mut cred_out: Option<String> = None;

    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--sandbox" => {
                sandbox = Some(it.next().ok_or("--sandbox requires a value")?.clone());
            }
            "--grant" => {
                grants.push(it.next().ok_or("--grant requires a value")?.clone());
            }
            "--sid-out" => {
                sid_out = Some(it.next().ok_or("--sid-out requires a value")?.clone());
            }
            "--cred-out" => {
                cred_out = Some(it.next().ok_or("--cred-out requires a value")?.clone());
            }
            other => return Err(format!("provision: unexpected flag {other:?}")),
        }
    }

    Ok(Verb::Provision {
        sandbox: sandbox.ok_or("provision: --sandbox is required")?,
        grants,
        sid_out: sid_out.ok_or("provision: --sid-out is required")?,
        cred_out: cred_out.ok_or("provision: --cred-out is required")?,
    })
}

fn parse_deprovision(args: &[String]) -> Result<Verb, String> {
    let mut sandbox: Option<String> = None;

    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--sandbox" => {
                sandbox = Some(it.next().ok_or("--sandbox requires a value")?.clone());
            }
            other => return Err(format!("deprovision: unexpected flag {other:?}")),
        }
    }

    Ok(Verb::Deprovision {
        sandbox: sandbox.ok_or("deprovision: --sandbox is required")?,
    })
}

fn parse_gc(args: &[String]) -> Result<Verb, String> {
    let mut live: Vec<String> = Vec::new();

    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--live" => {
                live.push(it.next().ok_or("--live requires a value")?.clone());
            }
            other => return Err(format!("gc: unexpected flag {other:?}")),
        }
    }

    Ok(Verb::Gc { live })
}

// ── Non-Windows stub ─────────────────────────────────────────────────────────

#[cfg(not(windows))]
fn main() {
    eprintln!("izba-jail-helper: windows-only");
    std::process::exit(2);
}

// ── Windows entry point ──────────────────────────────────────────────────────

#[cfg(windows)]
fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&argv) {
        Ok(verb) => {
            if let Err(e) = dispatch(verb) {
                eprintln!("izba-jail-helper: {e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("izba-jail-helper: {e}");
            std::process::exit(1);
        }
    }
}

/// Dispatch a parsed verb to its handler. On Windows, each handler is a stub
/// that will be filled in by subsequent tasks (Tasks 4–6 add FFI).
#[cfg(windows)]
fn dispatch(verb: Verb) -> Result<(), String> {
    match verb {
        Verb::Provision {
            sandbox,
            grants,
            sid_out,
            cred_out,
        } => handle_provision(sandbox, grants, sid_out, cred_out),
        Verb::Deprovision { sandbox } => handle_deprovision(sandbox),
        Verb::Gc { live } => handle_gc(live),
    }
}

#[cfg(windows)]
fn handle_provision(
    sandbox: String,
    grants: Vec<String>,
    sid_out: String,
    cred_out: String,
) -> Result<(), String> {
    // Stub: print the parsed args as JSON and exit 0.
    // Tasks 4–6 will replace this with real account/registry/firewall FFI.
    let out = serde_json::json!({
        "verb": "provision",
        "sandbox": sandbox,
        "grants": grants,
        "sid_out": sid_out,
        "cred_out": cred_out,
    });
    println!("{out}");
    Ok(())
}

#[cfg(windows)]
fn handle_deprovision(sandbox: String) -> Result<(), String> {
    let out = serde_json::json!({
        "verb": "deprovision",
        "sandbox": sandbox,
    });
    println!("{out}");
    Ok(())
}

#[cfg(windows)]
fn handle_gc(live: Vec<String>) -> Result<(), String> {
    let out = serde_json::json!({
        "verb": "gc",
        "live": live,
    });
    println!("{out}");
    Ok(())
}

// ── Unit tests (all platforms, pure parser) ──────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    // ── provision ────────────────────────────────────────────────────────────

    #[test]
    fn provision_single_grant() {
        let v = parse_args(&argv(&[
            "provision",
            "--sandbox",
            "my-sandbox",
            "--grant",
            "/run/vm/my-sandbox",
            "--sid-out",
            "/tmp/sid.txt",
            "--cred-out",
            "/tmp/cred.json",
        ]))
        .unwrap();
        assert_eq!(
            v,
            Verb::Provision {
                sandbox: "my-sandbox".into(),
                grants: vec!["/run/vm/my-sandbox".into()],
                sid_out: "/tmp/sid.txt".into(),
                cred_out: "/tmp/cred.json".into(),
            }
        );
    }

    #[test]
    fn provision_multiple_grants() {
        let v = parse_args(&argv(&[
            "provision",
            "--sandbox",
            "sb",
            "--grant",
            "/a",
            "--grant",
            "/b",
            "--grant",
            "/c",
            "--sid-out",
            "/x/sid",
            "--cred-out",
            "/x/cred",
        ]))
        .unwrap();
        match v {
            Verb::Provision { grants, .. } => {
                assert_eq!(grants, vec!["/a", "/b", "/c"]);
            }
            _ => panic!("expected Provision"),
        }
    }

    #[test]
    fn provision_no_grants() {
        let v = parse_args(&argv(&[
            "provision",
            "--sandbox",
            "sb",
            "--sid-out",
            "/sid",
            "--cred-out",
            "/cred",
        ]))
        .unwrap();
        match v {
            Verb::Provision { grants, .. } => {
                assert!(grants.is_empty());
            }
            _ => panic!("expected Provision"),
        }
    }

    #[test]
    fn provision_missing_sandbox() {
        let err = parse_args(&argv(&[
            "provision",
            "--sid-out",
            "/sid",
            "--cred-out",
            "/cred",
        ]))
        .unwrap_err();
        assert!(
            err.contains("--sandbox"),
            "error should mention --sandbox: {err}"
        );
    }

    #[test]
    fn provision_missing_sid_out() {
        let err = parse_args(&argv(&[
            "provision",
            "--sandbox",
            "sb",
            "--cred-out",
            "/cred",
        ]))
        .unwrap_err();
        assert!(
            err.contains("--sid-out"),
            "error should mention --sid-out: {err}"
        );
    }

    #[test]
    fn provision_missing_cred_out() {
        let err = parse_args(&argv(&[
            "provision",
            "--sandbox",
            "sb",
            "--sid-out",
            "/sid",
        ]))
        .unwrap_err();
        assert!(
            err.contains("--cred-out"),
            "error should mention --cred-out: {err}"
        );
    }

    #[test]
    fn provision_unknown_flag() {
        let err = parse_args(&argv(&[
            "provision",
            "--sandbox",
            "sb",
            "--sid-out",
            "/sid",
            "--cred-out",
            "/cred",
            "--unknown",
            "x",
        ]))
        .unwrap_err();
        assert!(
            err.contains("--unknown"),
            "error should mention the bad flag: {err}"
        );
    }

    // ── deprovision ──────────────────────────────────────────────────────────

    #[test]
    fn deprovision_basic() {
        let v = parse_args(&argv(&["deprovision", "--sandbox", "my-sandbox"])).unwrap();
        assert_eq!(
            v,
            Verb::Deprovision {
                sandbox: "my-sandbox".into()
            }
        );
    }

    #[test]
    fn deprovision_missing_sandbox() {
        let err = parse_args(&argv(&["deprovision"])).unwrap_err();
        assert!(
            err.contains("--sandbox"),
            "error should mention --sandbox: {err}"
        );
    }

    #[test]
    fn deprovision_unknown_flag() {
        let err =
            parse_args(&argv(&["deprovision", "--sandbox", "sb", "--nope", "x"])).unwrap_err();
        assert!(
            err.contains("--nope"),
            "error should mention the bad flag: {err}"
        );
    }

    // ── gc ───────────────────────────────────────────────────────────────────

    #[test]
    fn gc_multiple_live() {
        let v = parse_args(&argv(&["gc", "--live", "a", "--live", "b", "--live", "c"])).unwrap();
        assert_eq!(
            v,
            Verb::Gc {
                live: vec!["a".into(), "b".into(), "c".into()]
            }
        );
    }

    #[test]
    fn gc_empty_live() {
        let v = parse_args(&argv(&["gc"])).unwrap();
        assert_eq!(v, Verb::Gc { live: vec![] });
    }

    #[test]
    fn gc_single_live() {
        let v = parse_args(&argv(&["gc", "--live", "only"])).unwrap();
        assert_eq!(
            v,
            Verb::Gc {
                live: vec!["only".into()]
            }
        );
    }

    #[test]
    fn gc_unknown_flag() {
        let err = parse_args(&argv(&["gc", "--dead", "x"])).unwrap_err();
        assert!(
            err.contains("--dead"),
            "error should mention the bad flag: {err}"
        );
    }

    // ── top-level dispatch ────────────────────────────────────────────────────

    #[test]
    fn unknown_verb() {
        let err = parse_args(&argv(&["frobnicate"])).unwrap_err();
        assert!(
            err.contains("frobnicate"),
            "error should mention the unknown verb: {err}"
        );
    }

    #[test]
    fn empty_argv() {
        let err = parse_args(&[]).unwrap_err();
        assert!(!err.is_empty());
    }
}
