//! `izba policy allow <host>:3240` must be HONORED and must WARN.
//!
//! An explicit rule opening a USB/IP port is a deliberate decision — a bare
//! host entry authorizes only [80, 443], so the port was typed on purpose — and
//! izba does not veto it. It does tell the user what they just granted, and
//! points at the narrower per-device alternative.
//!
//! These drive the real binary and need no daemon or VM: policy edits are
//! daemon-free, and the reload is skipped when no daemon is running.

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

/// `policy allow` only requires the sandbox dir to exist, so a bare mkdir is
/// enough to exercise the command without creating a VM.
fn sandbox(data: &Path, name: &str) {
    std::fs::create_dir_all(data.join("sandboxes").join(name)).unwrap();
}

#[test]
fn allowing_the_usbip_port_warns_and_recommends_the_device_allowlist() {
    let data = tempfile::tempdir().unwrap();
    sandbox(data.path(), "usbtest");

    let out = izba(
        data.path(),
        &["policy", "allow", "usbtest", "10.1.0.124:3240"],
    );
    assert!(
        out.status.success(),
        "the rule must be honored, not rejected"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("10.1.0.124:3240"),
        "the offending rule must be named: {stderr}"
    );
    assert!(
        stderr.contains("izba usb allow"),
        "must point at the per-device alternative: {stderr}"
    );
    assert!(
        stderr.contains("EVERY"),
        "must state that the rule grants every exported device: {stderr}"
    );

    // Honored means persisted: the port is really in the policy file.
    let yaml = std::fs::read_to_string(data.path().join("sandboxes/usbtest/policy.yaml")).unwrap();
    assert!(yaml.contains("3240"), "rule must be persisted: {yaml}");
}

#[test]
fn an_ordinary_allow_prints_no_usbip_notice() {
    let data = tempfile::tempdir().unwrap();
    sandbox(data.path(), "webtest");

    let out = izba(data.path(), &["policy", "allow", "webtest", "github.com"]);
    assert!(out.status.success());

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("USB/IP"),
        "a bare host opens only [80, 443] and must not warn: {stderr}"
    );
}
