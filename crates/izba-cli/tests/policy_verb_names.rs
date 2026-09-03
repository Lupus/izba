//! `izba policy` verbs must name what they do (#150), through the real binary.
//!
//! `block` never created a deny rule and `enable` never turned the firewall
//! on. The canonical spellings are `revoke` and `seed`; the old ones keep
//! working for one release as hidden, deprecated subcommands that announce
//! themselves on STDERR and then do the identical thing.
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

/// Policy edits only require the sandbox dir to exist.
fn sandbox(data: &Path, name: &str) {
    std::fs::create_dir_all(data.join("sandboxes").join(name)).unwrap();
}

fn out(o: &Output) -> (String, String, i32) {
    (
        String::from_utf8_lossy(&o.stdout).to_string(),
        String::from_utf8_lossy(&o.stderr).to_string(),
        o.status.code().expect("exited normally"),
    )
}

/// The note must not land on stdout: the command still does its work, and a
/// script parsing izba's stdout must not start seeing an extra line.
#[test]
fn the_deprecated_spellings_warn_on_stderr_and_still_work() {
    let data = tempfile::tempdir().unwrap();
    sandbox(data.path(), "web");
    assert!(izba(data.path(), &["policy", "allow", "web", "api.x.com"])
        .status
        .success());
    assert!(izba(
        data.path(),
        &["policy", "git", "allow", "web", "github.com/o/a"]
    )
    .status
    .success());

    let (stdout, stderr, code) = out(&izba(data.path(), &["policy", "block", "web", "api.x.com"]));
    assert_eq!(code, 0, "the deprecated verb still does the work: {stderr}");
    assert!(
        stderr.contains("izba policy block") && stderr.contains("izba policy revoke"),
        "the note must name both spellings: {stderr}"
    );
    assert!(
        !stdout.contains("deprecated"),
        "the note belongs on stderr, not stdout: {stdout}"
    );
    // ...and the work really happened.
    let yaml = std::fs::read_to_string(data.path().join("sandboxes/web/policy.yaml")).unwrap();
    assert!(!yaml.contains("api.x.com"), "{yaml}");

    let (stdout, stderr, code) = out(&izba(data.path(), &["policy", "enable", "web"]));
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains("izba policy enable") && stderr.contains("izba policy seed"),
        "{stderr}"
    );
    assert!(!stdout.contains("deprecated"), "{stdout}");

    let (stdout, stderr, code) = out(&izba(
        data.path(),
        &["policy", "git", "block", "web", "github.com/o/a"],
    ));
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains("izba policy git block") && stderr.contains("izba policy git revoke"),
        "{stderr}"
    );
    assert!(!stdout.contains("deprecated"), "{stdout}");
}

/// Dogfood C6: a removal that removes nothing must say so and fail. Before
/// #150 it printed exactly what a successful withdrawal printed, so a typo'd
/// host read as revoked access the sandbox still had.
#[test]
fn revoking_nothing_fails_loudly_and_claims_no_success() {
    let data = tempfile::tempdir().unwrap();
    sandbox(data.path(), "web");
    assert!(izba(data.path(), &["policy", "allow", "web", "api.x.com"])
        .status
        .success());

    let (stdout, stderr, code) = out(&izba(
        data.path(),
        &["policy", "revoke", "web", "typo.example"],
    ));
    assert_eq!(
        code, 1,
        "a no-op removal must exit non-zero: {stdout}{stderr}"
    );
    assert!(
        stderr.contains("typo.example"),
        "name the host it looked for: {stderr}"
    );
    assert!(
        stderr.contains("80") && stderr.contains("443"),
        "name the ports it looked for: {stderr}"
    );
    assert!(
        !stdout.contains("policy updated") && !stdout.contains("reloaded egress policy"),
        "a no-op must not print the success line: {stdout}"
    );
    // The real grant is untouched.
    let yaml = std::fs::read_to_string(data.path().join("sandboxes/web/policy.yaml")).unwrap();
    assert!(yaml.contains("api.x.com"), "{yaml}");

    // The deprecated alias is identical apart from its own note.
    let (stdout, stderr2, code) = out(&izba(
        data.path(),
        &["policy", "block", "web", "typo.example"],
    ));
    assert_eq!(code, 1, "{stderr2}");
    assert!(
        stderr2.contains(stderr.trim()),
        "the alias must print the same no-op message: {stderr2}"
    );
    assert!(!stdout.contains("policy updated"), "{stdout}");

    // A removal that DOES remove something succeeds and reports the update.
    let (stdout, stderr, code) = out(&izba(
        data.path(),
        &["policy", "revoke", "web", "api.x.com"],
    ));
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.contains("policy updated"),
        "a real removal still reports the update: {stdout}"
    );
}

/// The git half of the same contract.
#[test]
fn revoking_a_git_rule_that_does_not_exist_fails_loudly() {
    let data = tempfile::tempdir().unwrap();
    sandbox(data.path(), "web");
    assert!(izba(
        data.path(),
        &["policy", "git", "allow", "web", "github.com/o/a"]
    )
    .status
    .success());

    let (stdout, stderr, code) = out(&izba(
        data.path(),
        &["policy", "git", "revoke", "web", "github.com/o/b"],
    ));
    assert_eq!(code, 1, "{stdout}{stderr}");
    assert!(
        stderr.contains("github.com/o/b"),
        "name the target it looked for: {stderr}"
    );
    assert!(
        !stdout.contains("policy updated"),
        "a no-op must not print the success line: {stdout}"
    );

    let (stdout, stderr, code) = out(&izba(
        data.path(),
        &["policy", "git", "revoke", "web", "github.com/o/a"],
    ));
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains("policy updated"), "{stdout}");
}
