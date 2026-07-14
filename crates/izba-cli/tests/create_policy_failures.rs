//! `izba create --policy` failure paths: a missing or invalid policy file
//! must fail the invocation BEFORE any sandbox state exists (#139) and
//! unknown policy keys must be rejected loudly (#138). Validation happens
//! before the daemon is contacted, so these run without a daemon/VM.

use std::path::Path;
use std::process::{Command, Output};

fn izba(data: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_izba"))
        .args(args)
        .current_dir(cwd)
        .env("IZBA_DATA_DIR", data)
        // Defensive: if a daemon ever does get spawned, let it self-exit fast.
        .env("IZBA_DAEMON_IDLE_SECS", "2")
        .output()
        .expect("run izba")
}

fn no_sandbox_registered(data: &Path, name: &str) {
    let dir = data.join("sandboxes").join(name);
    assert!(
        !dir.exists(),
        "stub sandbox left behind at {}",
        dir.display()
    );
}

#[test]
fn create_with_missing_policy_file_leaves_no_stub() {
    let data = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let out = izba(
        data.path(),
        ws.path(),
        &[
            "create",
            "--name",
            "stubtest",
            "--policy",
            "/nonexistent-policy.yaml",
        ],
    );
    assert!(!out.status.success(), "create must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("reading egress policy"), "stderr: {err}");
    no_sandbox_registered(data.path(), "stubtest");
}

#[test]
fn create_with_unknown_policy_key_fails_loud_and_leaves_no_stub() {
    let data = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let policy = ws.path().join("policy.yaml");
    std::fs::write(&policy, "allow:\n  - host: example.com\n    portz: [80]\n").unwrap();
    let out = izba(
        data.path(),
        ws.path(),
        &[
            "create",
            "--name",
            "stubtest",
            "--policy",
            policy.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success(), "create must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("portz"),
        "must name the offending key; stderr: {err}"
    );
    assert!(
        err.contains("valid keys"),
        "must list valid keys; stderr: {err}"
    );
    no_sandbox_registered(data.path(), "stubtest");
}

#[test]
fn failing_create_leaves_preexisting_sandbox_untouched() {
    let data = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    // Seed a fake pre-existing sandbox of the same name.
    let dir = data.path().join("sandboxes").join("stubtest");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.json"), "{}").unwrap();
    std::fs::write(dir.join("marker"), "precious").unwrap();
    let out = izba(
        data.path(),
        ws.path(),
        &[
            "create",
            "--name",
            "stubtest",
            "--policy",
            "/nonexistent-policy.yaml",
        ],
    );
    assert!(!out.status.success(), "create must fail");
    // The pre-existing sandbox must be completely untouched by the failure.
    assert_eq!(
        std::fs::read_to_string(dir.join("marker")).unwrap(),
        "precious"
    );
    assert!(dir.join("config.json").exists());
}
