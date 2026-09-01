//! Binary-level: `run`/`create`'s positional NAME_OR_DIR never silently
//! materialises a workspace directory for a bare word (#242).
//!
//! Before this rule, a bare word that named no sandbox fell through to
//! `create_dir_all`, so a typo quietly became a new empty workspace — and,
//! when the cwd held an `izba.yml`, that empty workspace silently discarded
//! the manifest's `enforce:`/`protocol:` posture.

use std::process::Command;

/// Keep any daemon this test does spawn short-lived and isolated.
fn izba(args: &[&str], cwd: &std::path::Path, data: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_izba"))
        .args(args)
        .current_dir(cwd)
        .env("IZBA_DATA_DIR", data)
        .env("IZBA_DAEMON_IDLE_SECS", "2")
        .output()
        .unwrap()
}

#[test]
fn create_bare_word_matching_nothing_errors_and_leaves_no_directory() {
    let data = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let out = izba(&["create", "ghost"], ws.path(), data.path());
    assert!(!out.status.success(), "a bare-word miss must not succeed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no sandbox named 'ghost'"),
        "stderr: {stderr}"
    );
    assert!(
        !ws.path().join("ghost").exists(),
        "izba create wrote ./ghost/ into the user's directory on a typo"
    );
}

#[test]
fn run_bare_word_matching_nothing_errors_and_leaves_no_directory() {
    let data = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let out = izba(&["run", "-d", "ghost"], ws.path(), data.path());
    assert!(!out.status.success(), "a bare-word miss must not succeed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no sandbox named 'ghost'"),
        "stderr: {stderr}"
    );
    assert!(
        !ws.path().join("ghost").exists(),
        "izba run wrote ./ghost/ into the user's directory on a typo"
    );
}

/// The rejection is a pure local decision, so it must land BEFORE the daemon
/// connect — a typo should never pay for spawning `izbad` (same property
/// `run_on_deep_data_dir_fails_early_and_leaves_no_daemon` pins for #71).
#[test]
fn bare_word_miss_is_rejected_before_the_daemon_is_spawned() {
    let data = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let out = izba(&["run", "-d", "ghost"], ws.path(), data.path());
    assert!(!out.status.success());
    assert!(
        !data.path().join("daemon").exists(),
        "izbad was spawned for an argument that could never resolve"
    );
}

/// The error must name both interpretations the user might have meant, so the
/// fix is a pointer rather than a wall.
#[test]
fn bare_word_miss_hints_the_directory_and_name_spellings() {
    let data = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    let out = izba(&["create", "ghost"], ws.path(), data.path());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("./ghost"), "hint the dir form: {stderr}");
    assert!(
        stderr.contains("--name ghost ."),
        "hint the current-directory form: {stderr}"
    );
}

/// The ignored-manifest warning's CALL SITE, not just its decision (#242).
/// `create` emits it BEFORE the daemon connect, so this is reachable without a
/// daemon — which is precisely why the assertion lives here: the pure decision
/// is unit-tested in `sandbox_ref`, and a rule with a test but a call site
/// without one is this repo's recurring defect class.
#[test]
fn create_warns_when_the_cwd_manifest_is_not_the_one_applied() {
    let data = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    std::fs::write(
        ws.path().join("izba.yml"),
        "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nmetadata: { name: declared }\nspec:\n  image: alpine:3\n",
    )
    .unwrap();
    // A sibling directory with no manifest of its own: the cwd's izba.yml is
    // therefore NOT the manifest governing the sandbox being created.
    std::fs::create_dir_all(ws.path().join("sub")).unwrap();
    let out = izba(&["create", "./sub"], ws.path(), data.path());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("./izba.yml declares sandbox 'declared'"),
        "must name the manifest it ignored: {stderr}"
    );
    assert!(
        stderr.contains("NOT applied"),
        "must say the manifest was not applied: {stderr}"
    );
}

/// The mirror case: applying the cwd's own manifest must stay quiet, or the
/// warning becomes noise users learn to skip.
#[test]
fn create_is_quiet_when_the_cwd_manifest_is_the_one_applied() {
    let data = tempfile::tempdir().unwrap();
    let ws = tempfile::tempdir().unwrap();
    std::fs::write(
        ws.path().join("izba.yml"),
        "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nmetadata: { name: declared }\nspec:\n  image: alpine:3\n",
    )
    .unwrap();
    let out = izba(&["create", "."], ws.path(), data.path());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("NOT applied"),
        "applying the cwd manifest must not warn about it: {stderr}"
    );
}
