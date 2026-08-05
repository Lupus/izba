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

// ---------------------------------------------------------------------------
// Daemon-backed round trips.
//
// These auto-start a real izbad but never create a VM, so unlike `daemon_e2e`
// they need no KVM and run on every host. They cover the wiring nothing else
// can: that each verb actually reaches the daemon and reports its answer.
// ---------------------------------------------------------------------------

/// Skip (rather than fail) where the sandbox forbids binding the daemon socket
/// — the house convention for tests that need a real listener.
fn daemon_unavailable(out: &Output) -> bool {
    let stderr = String::from_utf8_lossy(&out.stderr);
    stderr.contains("Permission denied") || stderr.contains("Operation not permitted")
}

/// `usb allow` needs the sandbox to exist and hold a readable config; seeding it
/// by hand keeps this test VM-free.
fn seed_sandbox(data: &Path, name: &str) {
    let dir = data.join("sandboxes").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.json"),
        r#"{"image_digest":"sha256:x","image_ref":"img","cpus":1,"mem_mb":512,
            "workspace":"/ws","ports":[],"volumes":[],"builder":false,"rw_size_gb":0}"#,
    )
    .unwrap();
}

#[test]
fn every_usb_verb_refuses_clearly_while_no_upstream_is_configured() {
    let data = tempfile::tempdir().unwrap();
    seed_sandbox(data.path(), "web");

    let show = izba(data.path(), &["usb", "upstream", "show"]);
    if daemon_unavailable(&show) {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    }
    assert!(show.status.success(), "show must answer with USB off");
    assert!(
        String::from_utf8_lossy(&show.stdout).contains("no usbip upstream configured"),
        "{}",
        String::from_utf8_lossy(&show.stdout)
    );

    // The rest must refuse, and say why rather than failing obscurely.
    for args in [
        vec!["usb", "list"],
        vec!["usb", "status", "web"],
        vec!["usb", "revoke", "web", "--device", "0403:6001"],
    ] {
        let out = izba(data.path(), &args);
        assert!(!out.status.success(), "{args:?} must refuse: {out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("not configured"),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn setting_a_loopback_upstream_is_reported_back_without_a_warning() {
    let data = tempfile::tempdir().unwrap();
    let set = izba(data.path(), &["usb", "upstream", "set", "127.0.0.1"]);
    if daemon_unavailable(&set) {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    }
    assert!(set.status.success(), "{set:?}");
    let stdout = String::from_utf8_lossy(&set.stdout);
    assert!(stdout.contains("127.0.0.1:3240"), "{stdout}");
    assert!(stdout.contains("own-host-loopback"), "{stdout}");
    assert!(
        !String::from_utf8_lossy(&set.stderr).contains("⚠"),
        "loopback is the recommended setup and must not warn: {}",
        String::from_utf8_lossy(&set.stderr)
    );
}

#[test]
fn a_named_upstream_reports_what_it_actually_resolves_to() {
    // Trust is decided on the resolved address, so when the user typed a name
    // they must be able to see which machine that name currently points at —
    // otherwise the trust class is an unexplained verdict.
    let data = tempfile::tempdir().unwrap();
    let set = izba(data.path(), &["usb", "upstream", "set", "localhost"]);
    if daemon_unavailable(&set) {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    }
    assert!(set.status.success(), "{set:?}");
    let stdout = String::from_utf8_lossy(&set.stdout);
    assert!(stdout.contains("upstream: localhost:3240"), "{stdout}");
    assert!(
        stdout.contains("resolves to:"),
        "a name must report its address: {stdout}"
    );
}

#[test]
fn an_ip_literal_upstream_does_not_repeat_itself() {
    // "127.0.0.1 resolves to 127.0.0.1" is noise; the line exists only to
    // explain a name.
    let data = tempfile::tempdir().unwrap();
    let set = izba(data.path(), &["usb", "upstream", "set", "127.0.0.1"]);
    if daemon_unavailable(&set) {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    }
    assert!(set.status.success(), "{set:?}");
    let stdout = String::from_utf8_lossy(&set.stdout);
    assert!(
        !stdout.contains("resolves to:"),
        "an address is not worth restating: {stdout}"
    );
}

#[test]
fn a_public_upstream_is_refused_end_to_end() {
    let data = tempfile::tempdir().unwrap();
    let out = izba(data.path(), &["usb", "upstream", "set", "203.0.113.7"]);
    if daemon_unavailable(&out) {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    }
    assert!(!out.status.success(), "a public upstream must be refused");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--allow-remote"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_grant_round_trips_through_allow_status_and_revoke() {
    let data = tempfile::tempdir().unwrap();
    seed_sandbox(data.path(), "web");

    let set = izba(data.path(), &["usb", "upstream", "set", "127.0.0.1"]);
    if daemon_unavailable(&set) {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    }
    assert!(set.status.success(), "{set:?}");

    // No grants yet.
    let empty = izba(data.path(), &["usb", "status", "web"]);
    assert!(empty.status.success(), "{empty:?}");
    assert!(
        String::from_utf8_lossy(&empty.stdout).contains("no USB device grants"),
        "{}",
        String::from_utf8_lossy(&empty.stdout)
    );

    // Grant, confirmed non-interactively.
    let allow = izba(
        data.path(),
        &[
            "usb",
            "allow",
            "web",
            "--device",
            "0403:6001",
            "--busid",
            "3-2",
            "--confirm",
            "0403:6001",
        ],
    );
    assert!(allow.status.success(), "{allow:?}");
    assert!(
        String::from_utf8_lossy(&allow.stdout).contains("granted 0403:6001"),
        "{}",
        String::from_utf8_lossy(&allow.stdout)
    );

    let status = izba(data.path(), &["usb", "status", "web"]);
    assert!(status.status.success(), "{status:?}");
    let text = String::from_utf8_lossy(&status.stdout);
    assert!(text.contains("0403:6001"), "{text}");
    assert!(text.contains("3-2"), "the pin is reported: {text}");

    // The grant really is the sandbox's managed truth on disk.
    let cfg = std::fs::read_to_string(data.path().join("sandboxes/web/config.json")).unwrap();
    assert!(cfg.contains("\"usb\""), "{cfg}");

    let revoke = izba(
        data.path(),
        &["usb", "revoke", "web", "--device", "0403:6001"],
    );
    assert!(revoke.status.success(), "{revoke:?}");
    let after = izba(data.path(), &["usb", "status", "web"]);
    assert!(
        String::from_utf8_lossy(&after.stdout).contains("no USB device grants"),
        "{}",
        String::from_utf8_lossy(&after.stdout)
    );
}

#[test]
fn listing_devices_reports_the_dial_failure_rather_than_an_empty_list() {
    // Port 1 has nothing on it. "no devices" here would be a lie that reads as
    // "your hardware isn't shared" instead of "izba could not reach the server".
    let data = tempfile::tempdir().unwrap();
    let set = izba(data.path(), &["usb", "upstream", "set", "127.0.0.1:1"]);
    if daemon_unavailable(&set) {
        eprintln!("SKIP: daemon socket unavailable in this environment");
        return;
    }
    assert!(set.status.success(), "{set:?}");

    let out = izba(data.path(), &["usb", "list"]);
    assert!(!out.status.success(), "a failed dial must not exit 0");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("connecting to the usbip upstream"),
        "{stderr}"
    );
}
