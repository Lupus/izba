//! Binary-level: a too-deep IZBA_DATA_DIR fails `create` EARLY (before any
//! daemon RPC), with an actionable message and no stub sandbox dir (#71).

use std::process::Command;

#[test]
fn create_on_deep_data_dir_fails_early_and_leaves_no_stub() {
    let tmp = tempfile::tempdir().unwrap();
    let deep = tmp.path().join("d".repeat(100));
    let ws = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_izba"))
        .args(["create", "web", "--image", "docker.io/library/alpine:3.20"])
        .current_dir(ws.path())
        .env("IZBA_DATA_DIR", &deep)
        .env("IZBA_DAEMON_IDLE_SECS", "2")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("IZBA_DATA_DIR"), "stderr: {stderr}");
    assert!(stderr.contains("108"), "stderr: {stderr}");
    assert!(
        !stderr.contains("SUN_LEN"),
        "raw kernel error leaked: {stderr}"
    );
    assert!(!deep.join("sandboxes").join("web").exists());
}
