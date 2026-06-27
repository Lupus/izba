//! End-to-end daemon lifecycle against the real `izba` binary and a real
//! microVM. Gated behind `IZBA_INTEGRATION=1` (same convention as the core
//! suite; see docs/testing.md). Run serially:
//!
//! ```text
//! IZBA_INTEGRATION=1 IZBA_KERNEL=... IZBA_INITRAMFS=... \
//! cargo test -p izba-cli --test daemon_e2e -- --test-threads=1 --nocapture
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

const IMAGE: &str = "alpine:3.20";

fn want() -> bool {
    if std::env::var("IZBA_INTEGRATION").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set IZBA_INTEGRATION=1 to run the daemon e2e");
        return false;
    }
    true
}

fn izba(data: &Path, envs: &[(&str, &str)], args: &[&str]) -> Output {
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_izba"));
    c.env("IZBA_DATA_DIR", data);
    for (k, v) in envs {
        c.env(k, v);
    }
    c.args(args);
    c.output().expect("run izba")
}

fn stdout_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn assert_ok(o: &Output, what: &str) {
    assert!(
        o.status.success(),
        "{what} failed (exit {:?})\nstdout: {}\nstderr: {}",
        o.status.code(),
        stdout_of(o),
        String::from_utf8_lossy(&o.stderr)
    );
}

/// Parse "daemon: running (pid 12345, version 0.1.0, uptime 3s)".
fn daemon_pid(data: &Path, envs: &[(&str, &str)]) -> Option<u32> {
    let o = izba(data, envs, &["daemon", "status"]);
    let out = stdout_of(&o);
    let rest = out.split("(pid ").nth(1)?;
    rest.split(',').next()?.trim().parse().ok()
}

fn daemon_version_of(data: &Path, envs: &[(&str, &str)]) -> Option<String> {
    let o = izba(data, envs, &["daemon", "status"]);
    let out = stdout_of(&o);
    let rest = out.split("version ").nth(1)?;
    Some(rest.split(',').next()?.trim().to_string())
}

/// Minimal HTTP GET with retries (relay/server may need a moment).
fn http_get(port: u16) -> anyhow::Result<String> {
    let mut last: Option<std::io::Error> = None;
    for _ in 0..50 {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(mut s) => {
                s.write_all(b"GET / HTTP/1.0\r\n\r\n")?;
                let mut buf = String::new();
                s.read_to_string(&mut buf)?;
                if let Some(idx) = buf.find("\r\n\r\n") {
                    return Ok(buf[idx + 4..].to_string());
                }
                return Ok(buf);
            }
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("http_get({port}) never connected: {last:?}")
}

#[test]
fn daemon_full_lifecycle() {
    if !want() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let no_env: &[(&str, &str)] = &[];

    // [1] First command auto-starts the daemon and runs a workload.
    let o = izba(
        &data,
        no_env,
        &[
            "run",
            "--image",
            IMAGE,
            "--name",
            "e2e",
            &ws_s,
            "--",
            "/bin/true",
        ],
    );
    assert_ok(&o, "run /bin/true");
    assert!(
        data.join("daemon/izbad.sock").exists(),
        "daemon socket exists"
    );
    let pid1 = daemon_pid(&data, no_env).expect("daemon status shows a pid");

    // [2] Lifecycle through the daemon: exec exit codes + cp roundtrip.
    let o = izba(&data, no_env, &["exec", "e2e", "--", "/bin/false"]);
    assert_eq!(o.status.code(), Some(1), "exec false -> 1");
    // Stance B: crun resolves the command inside the container; a missing
    // executable surfaces as crun's stderr diagnostic + crun's exit code (1 on
    // crun 1.28), passed straight through — not the pre-crun 127/CommandNotFound.
    let o = izba(&data, no_env, &["exec", "e2e", "--", "/no/such/cmd"]);
    assert_eq!(o.status.code(), Some(1), "exec missing -> crun rc 1");
    std::fs::write(root.path().join("hello.txt"), b"roundtrip").unwrap();
    let src = root.path().join("hello.txt").to_string_lossy().into_owned();
    assert_ok(
        &izba(&data, no_env, &["cp", &src, "e2e:/tmp/hello.txt"]),
        "cp in",
    );
    let back = root.path().join("back.txt").to_string_lossy().into_owned();
    assert_ok(
        &izba(&data, no_env, &["cp", "e2e:/tmp/hello.txt", &back]),
        "cp out",
    );
    assert_eq!(
        std::fs::read(root.path().join("back.txt")).unwrap(),
        b"roundtrip"
    );

    // [3] Port publish through the daemon (relay = daemon thread).
    // alpine's busybox has no httpd (that's busybox-extras), but its `nc`
    // supports `-l -p -e` — same trick as the core suite's
    // start_guest_httpd. The serve script is written host-side (the
    // workspace is shared into the guest at /workspace).
    std::fs::write(
        ws.join("serve.sh"),
        b"printf 'HTTP/1.0 200 OK\\r\\n\\r\\ndaemon-port-body'\n",
    )
    .unwrap();
    assert_ok(
        &izba(
            &data,
            no_env,
            &[
                "exec",
                "e2e",
                "--",
                "sh",
                "-c",
                "setsid sh -c 'while true; do nc -l -p 8000 -e sh /workspace/serve.sh; done' \
               >/dev/null 2>&1 & sleep 1",
            ],
        ),
        "start guest nc server",
    );
    assert_ok(
        &izba(&data, no_env, &["port", "publish", "e2e", "18091:8000"]),
        "publish",
    );
    let body = http_get(18091).expect("GET through daemon relay");
    assert!(body.contains("daemon-port-body"), "got: {body}");

    // [4] kill -9 the daemon: next CLI adopts; sandbox unharmed; relay back.
    let o = std::process::Command::new("kill")
        .args(["-9", &pid1.to_string()])
        .output()
        .unwrap();
    assert!(o.status.success(), "kill -9 daemon");
    std::thread::sleep(Duration::from_millis(300));
    let o = izba(&data, no_env, &["ls"]);
    assert_ok(&o, "ls after daemon kill");
    assert!(
        stdout_of(&o).contains("running"),
        "sandbox survived daemon kill"
    );
    let pid2 = daemon_pid(&data, no_env).expect("fresh daemon pid");
    assert_ne!(pid1, pid2, "a new daemon was auto-started");
    let body = http_get(18091).expect("relay respawned after adoption");
    assert!(body.contains("daemon-port-body"), "got: {body}");

    // [5] Same-proto rebuild does NOT churn-restart the daemon. Compatibility
    // is gated on DAEMON_PROTO_VERSION, not the display string (commit
    // 14efddb): a client carrying a *different display version* (e.g. a rebuild
    // /redeploy at the same wire proto) connects to the healthy daemon and
    // leaves it — and its live sandbox — untouched. The respawn-on-proto-
    // mismatch path is the unit test `connect_with_restarts_on_proto_mismatch`
    // in client.rs; the proto version is a compile-time constant with no env
    // override, so a real proto mismatch cannot be driven through the binary
    // here. This phase is the e2e mirror of `connect_with_keeps_daemon_on_
    // build_only_diff` against a real daemon carrying a live VM.
    let va: &[(&str, &str)] = &[("IZBA_DAEMON_VERSION", "e2e-A")];
    let vb: &[(&str, &str)] = &[("IZBA_DAEMON_VERSION", "e2e-B")];
    assert_ok(
        &izba(&data, no_env, &["daemon", "stop"]),
        "daemon stop pre-dance",
    );
    assert_ok(&izba(&data, va, &["ls"]), "start daemon as version A");
    assert_eq!(daemon_version_of(&data, va).as_deref(), Some("e2e-A"));
    let pid_a = daemon_pid(&data, va).expect("daemon A pid");
    let o = izba(&data, vb, &["ls"]);
    assert_ok(&o, "client B against same-proto daemon A succeeds");
    assert_eq!(
        daemon_version_of(&data, vb).as_deref(),
        Some("e2e-A"),
        "a display-version-only change must NOT replace a same-proto daemon"
    );
    assert_eq!(
        daemon_pid(&data, vb),
        Some(pid_a),
        "the daemon process is unchanged (no churn-restart on a build-only diff)"
    );
    assert!(
        stdout_of(&o).contains("running"),
        "sandbox untouched by the client's version difference"
    );

    // [6] daemon stop leaves the sandbox running; next command revives.
    assert_ok(&izba(&data, no_env, &["daemon", "stop"]), "daemon stop");
    let o = izba(&data, no_env, &["daemon", "status"]);
    assert!(stdout_of(&o).contains("not running"), "status after stop");
    let o = izba(&data, no_env, &["ls"]);
    assert_ok(&o, "ls revives daemon");
    assert!(stdout_of(&o).contains("running"), "sandbox kept running");

    // [7] Idle-exit: stop the sandbox, restart the daemon with a 1 s idle
    // budget, watch it leave on its own.
    assert_ok(&izba(&data, no_env, &["stop", "e2e"]), "stop sandbox");
    assert_ok(
        &izba(&data, no_env, &["daemon", "stop"]),
        "daemon stop pre-idle",
    );
    let idle: &[(&str, &str)] = &[("IZBA_DAEMON_IDLE_SECS", "1")];
    assert_ok(&izba(&data, idle, &["ls"]), "start daemon with 1s idle");
    // Watch the socket FILE, not `daemon status`: every status probe opens a
    // connection, and connections reset the idle timer — polling via the API
    // would keep the daemon alive forever. The exiting daemon unlinks its
    // socket, so the file vanishing is the exit signal.
    let sock = data.join("daemon/izbad.sock");
    let deadline = Instant::now() + Duration::from_secs(10);
    while sock.exists() {
        assert!(Instant::now() < deadline, "daemon never idle-exited");
        std::thread::sleep(Duration::from_millis(300));
    }
    let o = izba(&data, no_env, &["daemon", "status"]);
    assert!(
        stdout_of(&o).contains("not running"),
        "status agrees the daemon is gone"
    );

    // [8] Cleanup.
    assert_ok(&izba(&data, no_env, &["rm", "--force", "e2e"]), "rm");
    let _ = izba(&data, no_env, &["daemon", "stop"]);
}

/// SSH access against a real microVM: `izba ssh <name> -- <cmd>` round-trip +
/// chroot-isolation proofs + native in-container SFTP.
///
/// Gated behind `IZBA_INTEGRATION=1` (same as the other daemon e2e tests).
/// The initramfs must be built WITH `IZBA_SSHD` embedded — CI does this via the
/// `initramfs` job in `e2e.yml` which passes `IZBA_SSHD=dist/sshd` (which also
/// embeds the vendored static `sftp-server` used by step 6).
///
/// Assertions:
/// 1. `/bin/true` exit-0 via `izba ssh`  — proxy channel is live.
/// 2. Round-trip: `echo ssh-marker-42` stdout is recovered.
/// 3. Container isolation (positive): `cat /etc/alpine-release` works (the
///    session entered the alpine crun container via `crun exec`).
/// 4. Container isolation (negative): `cat /run/izba/ssh/ssh_host_ed25519_key`
///    fails — the host key lives in init-root, outside the container's mount
///    namespace, so it is invisible to the session.
/// 6. Native SFTP (`Subsystem sftp`): a `sftp` put/get byte round-trip through
///    the in-container `sftp-server`, cross-checked against the host workspace
///    share — exercised on this same (already-proven-alive) VM to avoid a
///    separate, CI-flaky microVM boot.
#[test]
fn ssh_access_e2e() {
    if !want() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let no_env: &[(&str, &str)] = &[];

    // [1] Boot a sandbox (the microVM persists after the workload exits).
    let o = izba(
        &data,
        no_env,
        &[
            "run",
            "--image",
            IMAGE,
            "--name",
            "sshe2e",
            &ws_s,
            "--",
            "/bin/true",
        ],
    );
    assert_ok(&o, "run /bin/true (boot)");

    // [2] Core: `izba ssh sshe2e -- /bin/true` exits 0.
    let o = izba(&data, no_env, &["ssh", "sshe2e", "--", "/bin/true"]);
    assert_ok(&o, "ssh /bin/true -> 0");

    // [3] Round-trip: stdout from a remote command is delivered.
    let o = izba(
        &data,
        no_env,
        &["ssh", "sshe2e", "--", "echo", "ssh-marker-42"],
    );
    assert_ok(&o, "ssh echo exits 0");
    assert!(
        stdout_of(&o).contains("ssh-marker-42"),
        "ssh stdout round-trip missing marker; got: {}",
        stdout_of(&o)
    );

    // [4] Container isolation (positive): inside the alpine image via crun exec.
    let o = izba(
        &data,
        no_env,
        &["ssh", "sshe2e", "--", "cat", "/etc/alpine-release"],
    );
    assert_ok(
        &o,
        "ssh cat /etc/alpine-release (proves the session entered the container)",
    );
    assert!(
        !stdout_of(&o).is_empty(),
        "alpine-release must be non-empty"
    );

    // [5] Container isolation (negative): the sshd host key lives in init-root,
    // outside the container's mount namespace.
    let o = izba(
        &data,
        no_env,
        &[
            "ssh",
            "sshe2e",
            "--",
            "cat",
            "/run/izba/ssh/ssh_host_ed25519_key",
        ],
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        !o.status.success(),
        "host key outside the container must be unreadable from the session"
    );
    assert!(
        err.contains("No such file") || err.contains("can't open"),
        "expected a not-found error proving the ssh session connected but the path is absent \
        (chroot isolation), got stderr: {err}"
    );

    // [6] Native in-container SFTP over the SAME sandbox (no extra VM boot — a
    // separate microVM boot is the flakiest thing on constrained CI runners, so
    // we exercise sftp on the VM the ssh checks above just proved alive). The
    // system `sftp` client connects through the same `izba __ssh-proxy`
    // ProxyCommand `izba ssh` uses, requesting the `Subsystem sftp` declared in
    // `hack/sshd_config`. sshd runs that subsystem through root's login shell
    // (`/init -c "<path>"`), which izba-init routes into
    // `crun exec /bin/sh -c "<path>"` → the vendored `sftp-server` INSIDE the
    // container (oci.rs `SFTP_SERVER_GUEST_PATH`). The ssh identity + host-key
    // trust were already warmed by the `izba ssh` calls above.
    //
    // cwd inside the session is /workspace (SSH_SESSION_CWD), so the relative
    // remote paths land in `ws` — which is the host side of that virtiofs share.
    let payload = b"sftp-roundtrip-payload-1337\n";
    let up = root.path().join("up.txt");
    std::fs::write(&up, payload).unwrap();
    let down = root.path().join("down.txt");
    let batch = root.path().join("batch.sftp");
    std::fs::write(
        &batch,
        format!(
            "put {} sftp-uploaded.txt\nget sftp-uploaded.txt {}\n",
            up.display(),
            down.display()
        ),
    )
    .unwrap();
    let o = sftp(&data, "sshe2e", &batch);
    assert!(
        o.status.success(),
        "sftp batch failed (exit {:?})\nstdout: {}\nstderr: {}",
        o.status.code(),
        stdout_of(&o),
        String::from_utf8_lossy(&o.stderr)
    );
    // Downloaded bytes must equal what we uploaded (protocol round-trip through
    // the in-container sftp-server).
    let got = std::fs::read(&down).expect("sftp get must have written down.txt");
    assert_eq!(
        got, payload,
        "sftp get round-trip mismatch: in-container sftp-server did not serve the file"
    );
    // The upload also appears in the host `ws` virtiofs share, confirming the
    // server operated on the CONTAINER filesystem (not sshd's initramfs).
    let host_side = ws.join("sftp-uploaded.txt");
    assert_eq!(
        std::fs::read(&host_side).ok().as_deref(),
        Some(payload.as_slice()),
        "uploaded file must appear in the host workspace share at {}",
        host_side.display()
    );

    // [7] Cleanup.
    assert_ok(
        &izba(&data, no_env, &["rm", "--force", "sshe2e"]),
        "rm sshe2e",
    );
    let _ = izba(&data, no_env, &["daemon", "stop"]);
}

/// Run the system `sftp` client against `izba-<name>` over the `izba
/// __ssh-proxy` ProxyCommand, executing the commands in `batch` (`sftp -b`).
/// Mirrors `izba ssh`'s inline `-o` connection knobs (see
/// `commands::ssh::build_ssh_args`) so it works without a managed ~/.ssh/config.
///
/// CRITICAL: `IZBA_DATA_DIR` must be set on the `sftp` process so the
/// `izba __ssh-proxy` child it spawns (via ProxyCommand) inherits it and talks
/// to *this test's* daemon/sandbox — without it the proxy falls back to the
/// default data dir, finds no such sandbox, and fails with "sandbox … is not
/// running". `izba ssh` works because the `izba()` helper sets it on the parent.
fn sftp(data: &Path, name: &str, batch: &Path) -> Output {
    let exe = env!("CARGO_BIN_EXE_izba");
    let ssh_dir = data.join("ssh");
    let identity = ssh_dir.join("id_ed25519");
    let known_hosts = ssh_dir.join("known_hosts");
    let args: Vec<String> = vec![
        "-o".into(),
        format!("ProxyCommand=\"{exe}\" __ssh-proxy %h"),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("IdentityFile={}", identity.display()),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "User=root".into(),
        "-b".into(),
        batch.to_string_lossy().into_owned(),
        format!("izba-{name}"),
    ];
    std::process::Command::new("sftp")
        .env("IZBA_DATA_DIR", data)
        .args(&args)
        .output()
        .expect("run sftp client")
}

/// Build a Dockerfile inside a throwaway builder VM, ingest the result, tag it,
/// then run the built image and assert the marker file written by the `RUN` layer
/// is readable inside a fresh workload sandbox.
///
/// Exercises the full Track E / `izba build` pipeline end-to-end:
///   lazy-pull of the BuildKit builder image → build in VM → OCI-archive ingest
///   → tag → `izba run --image <tag>` → verify marker.
///
/// Gated behind `IZBA_INTEGRATION=1` — self-skips otherwise.
///
/// Note: this test requires host-side internet egress on the runner (builder
/// image pull from docker.io/moby/buildkit, plus the in-VM `FROM alpine:3.20`
/// pull through the enforcing build-network policy that allow-lists Docker Hub).
/// GitHub Actions hosted runners have internet access; this test is always run
/// in that environment.
#[test]
fn build_in_vm_dockerfile_to_running_sandbox() {
    if !want() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let no_env: &[(&str, &str)] = &[];

    // Resolve the fixture directory relative to this crate's manifest.
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/build");
    let fixture_s = fixture_dir.to_string_lossy().into_owned();

    // [1] Build the Dockerfile inside a throwaway builder VM.
    //     On failure, dump all sandbox console.logs to aid diagnosis.
    //     Note: buildkitd.log lives inside the VM and is NOT readable from the
    //     host; it surfaces here because the build script tails it to stderr on
    //     buildctl failure, and stderr is captured into console.log.
    let o = izba(
        &data,
        no_env,
        &["build", "-t", "izba-e2e-built", &fixture_s],
    );
    if !o.status.success() {
        // Best-effort: dump all sandbox console.logs (builder name is time-based).
        let sandboxes_dir = data.join("sandboxes");
        if let Ok(rd) = std::fs::read_dir(&sandboxes_dir) {
            for entry in rd.flatten() {
                let console = entry.path().join("logs/console.log");
                if console.exists() {
                    eprintln!(
                        "--- builder console.log ({}) ---",
                        entry.file_name().to_string_lossy()
                    );
                    if let Ok(txt) = std::fs::read_to_string(&console) {
                        for line in txt
                            .lines()
                            .rev()
                            .take(60)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                        {
                            eprintln!("{line}");
                        }
                    }
                }
            }
        }
    }
    assert_ok(&o, "izba build -t izba-e2e-built");

    // [2] Run the built image and confirm the marker the RUN layer wrote is
    //     visible inside the container.
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let o = izba(
        &data,
        no_env,
        &[
            "run",
            "--image",
            "izba-e2e-built",
            "--name",
            "e2e-built-run",
            &ws_s,
            "--",
            "cat",
            "/izba-build-marker",
        ],
    );
    assert_ok(
        &o,
        "izba run --image izba-e2e-built -- cat /izba-build-marker",
    );
    let marker = stdout_of(&o);
    assert!(
        marker.contains("izba-build-ok"),
        "marker file content from built image must contain 'izba-build-ok'; got: {marker:?}"
    );

    // [3] Cleanup.
    let _ = izba(&data, no_env, &["rm", "--force", "e2e-built-run"]);
    // Note: the tag + image store live inside the tempdir and are cleaned up
    // automatically when `root` is dropped; no explicit `izba image rm` is
    // needed (and there is no such subcommand in the CLI surface).
    let _ = izba(&data, no_env, &["daemon", "stop"]);
}

/// CLI-surface lifecycle: drives the thin verbs `daemon_full_lifecycle` does
/// NOT reach end-to-end against a real daemon + microVM — `create` (vs `run`),
/// `netlog`, `port ls`/`unpublish`, `stop`, and non-force `rm`. These verbs read
/// 0% in the merged coverage report precisely because the monolithic lifecycle
/// test uses `run` (never standalone `create`) and aborts at its upgrade-dance
/// phase before reaching its own `stop`/`rm` steps. A standalone test is also
/// more robust: one verb's regression can't mask the rest.
#[test]
fn cli_surface_lifecycle() {
    if !want() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let no_env: &[(&str, &str)] = &[];

    // [1] `create` (not `run`): provisions a STOPPED sandbox and prints its name
    // (create does not boot the VM — only `run`/Start does).
    let o = izba(
        &data,
        no_env,
        &["create", "--image", IMAGE, "--name", "cli", &ws_s],
    );
    assert_ok(&o, "create");
    assert!(stdout_of(&o).contains("cli"), "create prints the name");
    assert!(
        data.join("daemon/izbad.sock").exists(),
        "create auto-started the daemon"
    );

    // [2] `ls` lists it as stopped.
    let o = izba(&data, no_env, &["ls"]);
    assert_ok(&o, "ls after create");
    let ls = stdout_of(&o);
    assert!(ls.contains("cli"), "ls lists the sandbox: {ls}");
    assert!(ls.contains("stopped"), "created-not-run is stopped: {ls}");

    // [3] `netlog` on a never-run sandbox: no egress recorded yet, clean exit 0.
    assert_ok(&izba(&data, no_env, &["netlog", "cli"]), "netlog (empty)");
    // [3b] `netlog` on a missing sandbox is an honest error (nonzero exit).
    let o = izba(&data, no_env, &["netlog", "no-such-sandbox"]);
    assert!(!o.status.success(), "netlog on missing sandbox must error");

    // [4] `run` an EXISTING sandbox by name: starts it (no re-create) + execs.
    assert_ok(
        &izba(&data, no_env, &["run", "cli", "--", "/bin/true"]),
        "run existing sandbox",
    );
    let o = izba(&data, no_env, &["ls"]);
    assert!(
        stdout_of(&o).contains("running"),
        "sandbox running after run: {}",
        stdout_of(&o)
    );

    // [5] `port` verbs the lifecycle monolith never reaches: publish/ls/unpublish.
    assert_ok(
        &izba(&data, no_env, &["port", "publish", "cli", "18093:8000"]),
        "port publish",
    );
    let o = izba(&data, no_env, &["port", "ls", "cli"]);
    assert_ok(&o, "port ls");
    let pls = stdout_of(&o);
    assert!(
        pls.contains("18093") && pls.contains("8000"),
        "port ls shows the rule: {pls}"
    );
    assert_ok(
        &izba(&data, no_env, &["port", "unpublish", "cli", "18093"]),
        "port unpublish",
    );
    assert!(
        !stdout_of(&izba(&data, no_env, &["port", "ls", "cli"])).contains("18093"),
        "rule is gone after unpublish"
    );

    // [6] `stop` the running sandbox; `ls` reflects stopped.
    assert_ok(&izba(&data, no_env, &["stop", "cli"]), "stop");
    assert!(
        stdout_of(&izba(&data, no_env, &["ls"])).contains("stopped"),
        "stopped after stop"
    );

    // [6b] `start` re-boots the stopped sandbox WITHOUT exec'ing (symmetric with
    // `stop`); `ls` reflects running again. Then stop once more so the rm step
    // below operates on a stopped sandbox.
    assert_ok(&izba(&data, no_env, &["start", "cli"]), "start");
    assert!(
        stdout_of(&izba(&data, no_env, &["ls"])).contains("running"),
        "running after start"
    );
    assert_ok(&izba(&data, no_env, &["stop", "cli"]), "stop after start");

    // [6c] `start` on a sandbox that does not exist is an honest error.
    let o = izba(&data, no_env, &["start", "no-such-sandbox"]);
    assert!(!o.status.success(), "start on missing sandbox must error");

    // [7] non-force `rm` on a stopped sandbox removes it; `ls` no longer lists it.
    assert_ok(&izba(&data, no_env, &["rm", "cli"]), "rm (non-force)");
    assert!(
        !stdout_of(&izba(&data, no_env, &["ls"])).contains("cli"),
        "removed sandbox is gone"
    );

    // [8] `run --rm`: a throwaway run creates + starts + execs, then tears the
    // sandbox down on exit — it must NOT linger in `ls`. Uses its own workspace
    // so it does not collide with the (now-removed) `cli` sandbox's relabel.
    let ws2 = root.path().join("ws-rm");
    std::fs::create_dir_all(&ws2).unwrap();
    let ws2_s = ws2.to_string_lossy().into_owned();
    assert_ok(
        &izba(
            &data,
            no_env,
            &[
                "run",
                "--rm",
                "--image",
                IMAGE,
                "--name",
                "rmtest",
                &ws2_s,
                "--",
                "/bin/true",
            ],
        ),
        "run --rm throwaway",
    );
    assert!(
        !stdout_of(&izba(&data, no_env, &["ls"])).contains("rmtest"),
        "run --rm removed the sandbox: {}",
        stdout_of(&izba(&data, no_env, &["ls"]))
    );

    // [9] `run --rm` against a PRE-EXISTING sandbox must NOT destroy it: `run`
    // can attach to an existing sandbox by name, so `--rm` only reaps what this
    // invocation freshly created. Create `keep`, then `run --rm keep` — it must
    // survive (otherwise `--rm` would silently delete user data).
    let ws3 = root.path().join("ws-keep");
    std::fs::create_dir_all(&ws3).unwrap();
    let ws3_s = ws3.to_string_lossy().into_owned();
    assert_ok(
        &izba(
            &data,
            no_env,
            &["create", "--image", IMAGE, "--name", "keep", &ws3_s],
        ),
        "create keep",
    );
    assert_ok(
        &izba(&data, no_env, &["run", "--rm", "keep", "--", "/bin/true"]),
        "run --rm against existing",
    );
    assert!(
        stdout_of(&izba(&data, no_env, &["ls"])).contains("keep"),
        "run --rm must NOT remove a pre-existing sandbox: {}",
        stdout_of(&izba(&data, no_env, &["ls"]))
    );
    assert_ok(&izba(&data, no_env, &["rm", "--force", "keep"]), "rm keep");

    let _ = izba(&data, no_env, &["daemon", "stop"]);
}
