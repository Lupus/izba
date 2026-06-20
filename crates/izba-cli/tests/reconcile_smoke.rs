use std::process::Command;

#[test]
fn reconcile_json_on_empty_data_dir_is_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_izba"))
        .args(["__reconcile", "--json"])
        .env("IZBA_DATA_DIR", tmp.path())
        .env("IZBA_DAEMON_IDLE_SECS", "2")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["violations"].as_array().unwrap().len(), 0);
}
