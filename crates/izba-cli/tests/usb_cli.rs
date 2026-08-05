//! `izba usb` end-to-end against the real binary.
//!
//! These cover the two properties no unit test can reach: that the subcommands
//! are actually wired into the CLI, and that a grant cannot be made from a
//! script without the confirmation flag. The refusal paths need no daemon and
//! no VM — they fail before any connection is attempted.

use std::path::Path;
use std::process::{Command, Output};

fn izba(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_izba"))
        .args(args)
        .env("IZBA_DATA_DIR", data)
        // Defensive: if a daemon ever does get spawned, let it self-exit fast.
        .env("IZBA_DAEMON_IDLE_SECS", "2")
        .output()
        .expect("run izba")
}

#[test]
fn a_scripted_grant_without_confirmation_is_refused_and_names_the_flag() {
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data.path().join("sandboxes/web")).unwrap();

    let out = izba(
        data.path(),
        &["usb", "allow", "web", "--device", "0403:6001"],
    );
    assert!(!out.status.success(), "must not grant unconfirmed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--confirm"), "{stderr}");
    assert!(stderr.contains("0403:6001"), "{stderr}");
}

#[test]
fn a_scripted_grant_whose_confirmation_names_a_different_device_is_refused() {
    let data = tempfile::tempdir().unwrap();
    let out = izba(
        data.path(),
        &[
            "usb",
            "allow",
            "web",
            "--device",
            "0403:6001",
            "--confirm",
            "1a86:7523",
        ],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("does not match"), "{stderr}");
}

#[test]
fn a_malformed_device_id_is_rejected_before_anything_else_happens() {
    // No daemon runs here, so reaching the daemon would surface a connection
    // error instead — the id must be refused first, on its own terms.
    let data = tempfile::tempdir().unwrap();
    let out = izba(
        data.path(),
        &["usb", "allow", "web", "--device", "403:6001"],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("vid:pid"), "{stderr}");
}

#[test]
fn usb_help_lists_every_verb() {
    let data = tempfile::tempdir().unwrap();
    let out = izba(data.path(), &["usb", "--help"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for sub in ["upstream", "list", "allow", "revoke", "status"] {
        assert!(text.contains(sub), "missing subcommand {sub}: {text}");
    }
}

#[test]
fn a_malformed_upstream_target_is_refused_without_contacting_a_daemon() {
    let data = tempfile::tempdir().unwrap();
    let out = izba(data.path(), &["usb", "upstream", "set", "host:99999"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("port"), "{stderr}");
}
