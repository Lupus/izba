//! Tier 2: drive the real `izba exec -it` against a real sandbox end-to-end.
//! Env-gated (`IZBA_TTY_E2E=1` plus a working izba host with KVM/OpenVMM +
//! artifacts); self-skips otherwise. Full runs happen on a KVM host or the
//! OpenVMM spike host. In CI/sandbox without the env var, this compiles and
//! self-skips (no-op pass).
//!
//! Lifecycle used here:
//!   `izba create --image IMG --name NAME WORKSPACE_DIR`   → creates config, returns
//!   `izba run NAME -- true`                               → starts the VM + runs `true`
//!                                                           (leaves VM running)
//!   `izba exec -it NAME -- CMD`                          → drive via real guest PTY
//!   `izba rm --force NAME`                               → stop + remove

use izba_ttytest::harness::TerminalSession;
use portable_pty::CommandBuilder;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

struct E2eEnv {
    data_dir: PathBuf,
    image: String,
    workspace: PathBuf,
}

/// Returns `Some(env)` only when explicitly enabled; prints SKIP and returns
/// `None` otherwise. Full setup (KVM/OpenVMM + artifacts) is the operator's
/// responsibility, same as the existing `IZBA_INTEGRATION` suite.
fn want() -> Option<E2eEnv> {
    if std::env::var("IZBA_TTY_E2E").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set IZBA_TTY_E2E=1 (with a working izba host) to run Tier 2");
        return None;
    }
    let data_dir = std::env::var_os("IZBA_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("izba-tty-e2e-data"));
    let image = std::env::var("IZBA_TTY_E2E_IMAGE").unwrap_or_else(|_| "alpine:3.20".to_string());
    let workspace = std::env::temp_dir().join("izba-tty-e2e-ws");
    Some(E2eEnv {
        data_dir,
        image,
        workspace,
    })
}

/// A `Command` for the izba binary with the shared data dir pre-set.
fn izba(env: &E2eEnv) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_izba"));
    c.env("IZBA_DATA_DIR", &env.data_dir);
    c
}

/// Bring up a sandbox: create its config then start the VM via `run NAME --
/// true`. Returns once the VM is live and responsive (the `run` call to `true`
/// has returned).
fn bring_up(env: &E2eEnv, name: &str) {
    std::fs::create_dir_all(&env.workspace).unwrap();

    // Step 1: create the sandbox config (does not start the VM).
    let status = izba(env)
        .args([
            "create",
            "--image",
            &env.image,
            "--name",
            name,
            env.workspace.to_str().unwrap(),
        ])
        .status()
        .expect("izba create failed to spawn");
    assert!(
        status.success(),
        "izba create --image {} --name {} ... exited with {status}",
        env.image,
        name
    );

    // Step 2: start the VM and run `true` to confirm liveness, leaving the VM
    // running. `izba run NAME -- CMD` is idempotent: if it's already running it
    // stays running; it blocks only until the CMD exits.
    let status = izba(env)
        .args(["run", name, "--", "true"])
        .status()
        .expect("izba run ... -- true failed to spawn");
    assert!(
        status.success(),
        "izba run {name} -- true exited with {status} (VM failed to start or `true` failed)"
    );
}

/// Tear down a sandbox; best-effort (failures are not fatal so test output
/// stays clean even when the VM is already dead).
fn tear_down(env: &E2eEnv, name: &str) {
    let _ = izba(env).args(["rm", "--force", name]).status();
}

const TIMEOUT: Duration = Duration::from_secs(30);

#[test]
fn exit_code_passthrough_end_to_end() {
    let Some(env) = want() else {
        return;
    };
    let name = "ttye2e-exitcode";

    tear_down(&env, name); // clean any prior crashed instance
    bring_up(&env, name);

    // Drive exit 42 through a real guest PTY and confirm the code passes
    // through the full chain: guest shell → vsock stream → izba exec.
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_izba"));
    cmd.args(["exec", "-it", name, "--", "sh", "-c", "exit 42"]);
    cmd.env("IZBA_DATA_DIR", &env.data_dir);
    cmd.env("TERM", "xterm-256color");
    let mut sess = TerminalSession::spawn(cmd, 80, 24).expect("spawn pty session");
    let outcome = sess.wait_exit(TIMEOUT).expect("wait for izba exec to exit");
    assert_eq!(
        outcome.code,
        Some(42),
        "expected exit code 42 from `sh -c 'exit 42'`"
    );

    tear_down(&env, name);
}

#[test]
fn vim_renders_on_real_guest() {
    let Some(env) = want() else {
        return;
    };
    let name = "ttye2e-vim";

    tear_down(&env, name); // clean any prior crashed instance
    std::fs::create_dir_all(&env.workspace).unwrap();
    std::fs::write(env.workspace.join("x"), b"hello e2e\n").unwrap();
    bring_up(&env, name);

    // Open the workspace file in vi via a real guest PTY.
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_izba"));
    cmd.args(["exec", "-it", name, "--", "vi", "/workspace/x"]);
    cmd.env("IZBA_DATA_DIR", &env.data_dir);
    cmd.env("TERM", "xterm-256color");
    let mut sess = TerminalSession::spawn(cmd, 80, 24).expect("spawn pty session");

    // The file content must appear in the rendered screen.
    sess.wait_for_text("hello e2e", TIMEOUT)
        .expect("vi should render the workspace file");

    // Exercise resize: the guest pty must handle a SIGWINCH equivalent.
    sess.resize(100, 30).unwrap();
    let _ = sess.wait_stable(Duration::from_millis(300), TIMEOUT);

    // Quit vi cleanly.
    sess.send_keys("\x1b").unwrap(); // ESC — ensure normal mode
    sess.send_keys(":q!\r").unwrap();
    let _ = sess.wait_exit(TIMEOUT);

    tear_down(&env, name);
}
