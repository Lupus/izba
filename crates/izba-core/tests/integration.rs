//! End-to-end integration suite: boots real microVMs with cloud-hypervisor.
//!
//! Gated behind `IZBA_INTEGRATION=1` — without it every test prints a SKIP
//! note and passes, so the suite is safe to run in environments without
//! /dev/kvm or the VMM binaries. See `docs/testing.md` for the full runbook:
//!
//! ```text
//! IZBA_INTEGRATION=1 \
//! IZBA_KERNEL=~/.local/share/izba/artifacts/vmlinux \
//! IZBA_INITRAMFS=~/.local/share/izba/artifacts/initramfs.cpio.gz \
//! cargo test -p izba-core --test integration -- --test-threads=1 --nocapture
//! ```
//!
//! Layout per test: a fresh `Paths` root in a tempdir (own sandboxes,
//! workspace), sharing one image cache across the whole process so the OCI
//! image is pulled and converted to erofs exactly once.

use anyhow::Context;
use std::fs::{self, File};
use std::io::Write as _;
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use izba_core::daemon::relays::RelayManager;
use izba_core::image::ensure_image;
use izba_core::liveness::Liveness;
use izba_core::paths::Paths;
use izba_core::procmgr;
use izba_core::sandbox::{self, Artifacts, CreateOpts};
use izba_core::state::{load_json, PortRule, RunState, STATE_FILE};
use izba_core::vmm::cloud_hypervisor::CloudHypervisorDriver;
use izba_core::vmm::UdsStream;
use izba_proto::{
    read_frame, write_frame, ErrorKind, ExecRequest, ExitStatus, Request, Response, StreamAttach,
    StreamKind, StreamOpen,
};

const BOOT_TIMEOUT: Duration = Duration::from_secs(60);
const BOOT_POLL: Duration = Duration::from_millis(200);
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_IMAGE: &str = "alpine:3.20";
/// Same default PATH izba-init would apply; passed explicitly because the
/// control protocol requires the caller to provide the environment.
const STD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

// ---------------------------------------------------------------------------
// Harness: gate, requirements, shared image cache
// ---------------------------------------------------------------------------

struct TestEnv {
    kernel: PathBuf,
    initramfs: PathBuf,
    image_ref: String,
}

/// The env gate. Returns `None` (test passes as a skip) unless
/// `IZBA_INTEGRATION=1`. When gated in, every host requirement is checked and
/// ALL missing pieces are reported in a single panic message.
fn want() -> Option<TestEnv> {
    if std::env::var("IZBA_INTEGRATION").ok().as_deref() != Some("1") {
        eprintln!(
            "SKIP: set IZBA_INTEGRATION=1 (plus IZBA_KERNEL/IZBA_INITRAMFS) to run \
             the end-to-end suite; see docs/testing.md"
        );
        return None;
    }

    let mut missing: Vec<String> = Vec::new();

    if let Err(e) = File::options().read(true).write(true).open("/dev/kvm") {
        missing.push(format!(
            "/dev/kvm is not read-write accessible ({e}); enable nested virtualization \
             and fix permissions (see docs/testing.md §1)"
        ));
    }
    for bin in ["cloud-hypervisor", "virtiofsd", "mkfs.erofs"] {
        if which::which(bin).is_err() {
            missing.push(format!(
                "`{bin}` not found on PATH (run hack/fetch-artifacts.sh / apt install; \
                 see docs/testing.md §2)"
            ));
        }
    }
    let kernel = require_env_file("IZBA_KERNEL", &mut missing);
    let initramfs = require_env_file("IZBA_INITRAMFS", &mut missing);

    if !missing.is_empty() {
        panic!(
            "IZBA_INTEGRATION=1 but the host is not ready:\n  - {}\n\
             see docs/testing.md for setup instructions",
            missing.join("\n  - ")
        );
    }

    Some(TestEnv {
        kernel: kernel.expect("checked above"),
        initramfs: initramfs.expect("checked above"),
        image_ref: std::env::var("IZBA_TEST_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string()),
    })
}

fn require_env_file(var: &str, missing: &mut Vec<String>) -> Option<PathBuf> {
    match std::env::var_os(var).map(PathBuf::from) {
        None => {
            missing.push(format!("env {var} is not set"));
            None
        }
        Some(p) if !p.is_file() => {
            missing.push(format!("env {var}={} is not an existing file", p.display()));
            None
        }
        Some(p) => Some(p),
    }
}

/// Image cache shared by every test in this process: `(rootfs.erofs path,
/// digest)`. The pull + erofs conversion runs at most once per process.
static CACHED_IMAGE: OnceLock<(PathBuf, String)> = OnceLock::new();
/// Backing tempdir for the default cache location. Held in a static so it
/// lives for the whole test process (never dropped; the OS tmp reaper cleans
/// it up — set IZBA_TEST_CACHE to reuse a persistent cache across runs).
static CACHE_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();

fn cached_image(env: &TestEnv) -> &'static (PathBuf, String) {
    CACHED_IMAGE.get_or_init(|| {
        let cache_root = match std::env::var_os("IZBA_TEST_CACHE") {
            Some(d) => PathBuf::from(d),
            None => CACHE_DIR
                .get_or_init(|| tempfile::tempdir().expect("creating image cache tempdir"))
                .path()
                .to_path_buf(),
        };
        let cache_paths = Paths::with_root(cache_root);
        eprintln!("pulling {} into the shared test cache...", env.image_ref);
        let digest = ensure_image(&cache_paths, &env.image_ref)
            .with_context(|| format!("pulling test image {}", env.image_ref))
            .unwrap();
        let rootfs = cache_paths.image_dir(&digest).join("rootfs.erofs");
        assert!(rootfs.is_file(), "ensure_image must produce {rootfs:?}");
        (rootfs, digest)
    })
}

/// Make the shared cached image available under this test's own `Paths` root
/// (hardlink, falling back to copy across filesystems) and return its digest.
///
/// Copies BOTH `rootfs.erofs` and the cached `config.json` (when present) so the
/// per-sandbox OCI bundle reflects the image's real `User`/`Env`/`WorkingDir`,
/// not a bare-root default — load-bearing for the userns USER-mapping tests.
fn provision_image(env: &TestEnv, paths: &Paths) -> String {
    let (cached_rootfs, digest) = cached_image(env);
    let dir = paths.image_dir(digest);
    fs::create_dir_all(&dir).expect("creating image dir");
    let dst = dir.join("rootfs.erofs");
    if !dst.exists() {
        if fs::hard_link(cached_rootfs, &dst).is_err() {
            fs::copy(cached_rootfs, &dst).expect("copying cached rootfs.erofs");
        }
        fs::write(dir.join("ref.txt"), &env.image_ref).expect("writing ref.txt");
        // The config blob lives next to rootfs.erofs in the shared cache.
        let cached_cfg = cached_rootfs.with_file_name("config.json");
        if cached_cfg.is_file() {
            let cfg_dst = dir.join("config.json");
            if fs::hard_link(&cached_cfg, &cfg_dst).is_err() {
                fs::copy(&cached_cfg, &cfg_dst).expect("copying cached config.json");
            }
        }
    }
    digest.clone()
}

// ---------------------------------------------------------------------------
// Per-test fixture with panic-safe cleanup
// ---------------------------------------------------------------------------

/// Per-test root: own `Paths`, own workspace dirs, and a Drop guard that
/// force-removes every tracked sandbox even when the test panics.
struct TestBox {
    /// Kept alive for the fixture's lifetime; deleted after sandbox cleanup
    /// (named fields drop after `Drop::drop` runs).
    root: tempfile::TempDir,
    paths: Paths,
    names: Vec<String>,
}

impl TestBox {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("creating test root");
        let paths = Paths::with_root(root.path().join("izba"));
        Self {
            root,
            paths,
            names: Vec::new(),
        }
    }

    /// Create (and return) a fresh workspace directory named `ws-<sub>`.
    fn workspace(&self, sub: &str) -> PathBuf {
        let ws = self.root.path().join(format!("ws-{sub}"));
        fs::create_dir_all(&ws).expect("creating workspace");
        ws
    }
}

impl Drop for TestBox {
    fn drop(&mut self) {
        let connector = sandbox::default_connector();
        for name in &self.names {
            let _ = sandbox::remove(&self.paths, name, &connector, true);
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle helpers
// ---------------------------------------------------------------------------

/// `create` only — registers the name for cleanup before anything can fail
/// to boot. Egress is always the izbad-owned vsock_1027 plane now.
fn create_sandbox(env: &TestEnv, tb: &mut TestBox, name: &str, ws: &Path) {
    let digest = provision_image(env, &tb.paths);
    sandbox::create(
        &tb.paths,
        name,
        &CreateOpts {
            image_digest: digest,
            image_ref: env.image_ref.clone(),
            cpus: 1,
            mem_mb: 1024,
            workspace: ws.to_path_buf(),
            rw_size_gb: 2,
            ports: Vec::new(),
            volumes: Vec::new(),
            builder: false,
            docker: false,
            vnc: false,
        },
    )
    .expect("create");
    tb.names.push(name.to_string());
}

/// `create` with user volumes; registers the name for cleanup.
fn create_sandbox_with_volumes(
    env: &TestEnv,
    tb: &mut TestBox,
    name: &str,
    ws: &Path,
    volumes: Vec<izba_core::volume::VolumeSpec>,
) {
    let digest = provision_image(env, &tb.paths);
    sandbox::create(
        &tb.paths,
        name,
        &CreateOpts {
            image_digest: digest,
            image_ref: env.image_ref.clone(),
            cpus: 1,
            mem_mb: 1024,
            workspace: ws.to_path_buf(),
            rw_size_gb: 2,
            ports: Vec::new(),
            volumes,
            builder: false,
            docker: false,
            vnc: false,
        },
    )
    .expect("create");
    tb.names.push(name.to_string());
}

fn start_sandbox(env: &TestEnv, tb: &TestBox, name: &str) -> anyhow::Result<()> {
    // Opt out of confinement automatically on any host that cannot meet the
    // full fail-closed floor (seccomp AND Landlock AND a virtiofsd sandbox —
    // the last needs unprivileged userns or CAP_SYS_CHROOT). Deriving this from
    // a single leg (e.g. Landlock alone) would still fail closed on a
    // Landlock-present-but-no-userns-non-root runner and panic every boot test;
    // probing the real `plan()` covers all three legs.
    let caps = izba_core::procmgr::jail_linux::Capabilities::probe();
    let allow_unconfined = izba_core::procmgr::jail_linux::plan(&caps, false, 0).is_err();
    sandbox::start_with_timeouts(
        &tb.paths,
        name,
        &CloudHypervisorDriver,
        &Artifacts {
            variant: izba_core::artifacts::KernelVariant::Base,
            kernel: env.kernel.clone(),
            initramfs: env.initramfs.clone(),
            kasmvnc_erofs: None,
        },
        allow_unconfined,
        BOOT_TIMEOUT,
        BOOT_POLL,
    )
}

/// create + start, panicking on failure (the common path).
fn boot(env: &TestEnv, tb: &mut TestBox, name: &str, ws: &Path) {
    create_sandbox(env, tb, name, ws);
    if let Err(e) = start_sandbox(env, tb, name) {
        panic!(
            "boot of '{name}' failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, name)
        );
    }
}

fn stop_sandbox(tb: &TestBox, name: &str) {
    let connector = sandbox::default_connector();
    sandbox::stop(&tb.paths, name, &connector, STOP_TIMEOUT).expect("stop");
}

/// Last ~2 KiB of the guest serial console, for failure diagnostics.
fn console_tail(paths: &Paths, name: &str) -> String {
    let log = paths.logs_dir(name).join("console.log");
    let text =
        fs::read_to_string(&log).unwrap_or_else(|e| format!("<unreadable {}: {e}>", log.display()));
    let tail_start = text.len().saturating_sub(2048);
    // Avoid splitting a UTF-8 code point mid-sequence.
    let mut start = tail_start;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_string()
}

/// Last ~30 lines of a sidecar log, or `(missing)` when absent/unreadable.
fn log_tail(path: &Path) -> String {
    let Ok(text) = fs::read_to_string(path) else {
        return "(missing)".to_string();
    };
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(30);
    lines[start..].join("\n")
}

/// Full boot-failure diagnostics: the console tail first, then the last lines
/// of each sidecar log from the same `logs/` directory (the console can be
/// empty when the VMM itself fails before the guest prints anything).
fn boot_diag(paths: &Paths, name: &str) -> String {
    let logs = paths.logs_dir(name);
    let mut out = console_tail(paths, name);
    for log in ["vmm.log", "virtiofsd-workspace.log"] {
        out.push_str(&format!("\n--- {log} tail ---\n"));
        out.push_str(&log_tail(&logs.join(log)));
    }
    out
}

// ---------------------------------------------------------------------------
// Exec helpers (mirror the CLI's exec.rs, simplified for tests)
// ---------------------------------------------------------------------------

/// Run `argv` non-interactively in the sandbox and collect both output
/// streams. `Err` carries the guest's `Response::Error` to the Exec request
/// (e.g. `CommandNotFound`); transport failures panic.
fn exec_collect(
    paths: &Paths,
    name: &str,
    argv: &[&str],
    stdin: Option<&[u8]>,
) -> Result<(ExitStatus, String, String), (ErrorKind, String)> {
    exec_collect_env(
        paths,
        name,
        argv,
        stdin,
        vec![("PATH".to_string(), STD_PATH.to_string())],
    )
}

/// `exec_collect` with caller-controlled environment.
///
/// `exec_collect` always supplies `PATH=STD_PATH`, which makes the whole
/// integration suite blind to #222: it would pass even if the guest delivered
/// a container with no `PATH` at all. Passing an EMPTY env here is what the
/// real CLI does (`izba-cli/src/commands/exec.rs` sends `vec![]`), so a test
/// that wants to observe the container's own `PATH` must use this.
fn exec_collect_env(
    paths: &Paths,
    name: &str,
    argv: &[&str],
    stdin: Option<&[u8]>,
    env: Vec<(String, String)>,
) -> Result<(ExitStatus, String, String), (ErrorKind, String)> {
    let connector = sandbox::default_connector();
    let mut control = sandbox::control(paths, name, &connector).expect("control connection");

    let req = Request::Exec(ExecRequest {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env,
        cwd: "/workspace".to_string(),
        tty: false,
        uid: 0,
        gid: 0,
    });
    write_frame(&mut control, &req).expect("sending exec");
    let exec_id = match read_frame::<_, Response>(&mut control).expect("exec reply") {
        Response::ExecStarted { exec_id } => exec_id,
        Response::Error { kind, message } => return Err((kind, message)),
        other => panic!("unexpected reply to exec: {other:?}"),
    };

    let out = attach(paths, name, exec_id, StreamKind::Stdout);
    let err = attach(paths, name, exec_id, StreamKind::Stderr);
    // Pumps must run BEFORE the stdin write: a guest producing more output
    // than the socket buffers hold would block, never read stdin, and
    // deadlock against our synchronous write below.
    let out_t = std::thread::spawn(move || slurp(out));
    let err_t = std::thread::spawn(move || slurp(err));
    if let Some(data) = stdin {
        let mut sin = attach(paths, name, exec_id, StreamKind::Stdin);
        sin.write_all(data).expect("writing stdin");
        // Half-close → guest pump sees EOF → child's stdin sees EOF.
        sin.shutdown(Shutdown::Write).expect("half-closing stdin");
    }

    // Wait gets its own control connection: the guest serves one request at
    // a time per connection and Wait blocks until the workload exits.
    let mut wait_conn = connector(paths, name).expect("wait connection");
    let status = wait(&mut wait_conn, exec_id)?;
    let stdout = out_t.join().expect("stdout pump");
    let stderr = err_t.join().expect("stderr pump");
    Ok((status, stdout, stderr))
}

fn wait(
    conn: &mut Box<dyn izba_core::vmm::IoStream>,
    exec_id: u32,
) -> Result<ExitStatus, (ErrorKind, String)> {
    write_frame(conn, &Request::Wait { exec_id }).expect("sending wait");
    match read_frame::<_, Response>(conn).expect("wait reply") {
        Response::Wait { status } => Ok(status),
        Response::Error { kind, message } => Err((kind, message)),
        other => panic!("unexpected reply to wait: {other:?}"),
    }
}

/// Open a stream-port connection bound to `exec_id`'s `kind` stream.
fn attach(paths: &Paths, name: &str, exec_id: u32, kind: StreamKind) -> UdsStream {
    let mut conn = sandbox::default_stream_connector()(paths, name)
        .unwrap_or_else(|e| panic!("opening {kind:?} stream: {e:#}"));
    write_frame(
        &mut conn,
        &StreamOpen::Attach(StreamAttach { exec_id, kind }),
    )
    .expect("sending stream attach");
    conn
}

/// Read a stream to EOF, lossily decoded.
fn slurp(mut s: UdsStream) -> String {
    let mut buf = Vec::new();
    let _ = std::io::Read::read_to_end(&mut s, &mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// `exec_collect` + assert exit code 0, returning stdout.
fn exec_ok(paths: &Paths, name: &str, argv: &[&str]) -> String {
    let (status, stdout, stderr) = exec_collect(paths, name, argv, None)
        .unwrap_or_else(|(kind, msg)| panic!("exec {argv:?} rejected ({kind:?}): {msg}"));
    assert_eq!(
        status,
        ExitStatus::Code(0),
        "exec {argv:?} failed: status {status:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
    stdout
}

/// Start a tiny HTTP responder in the guest, detached, so it keeps running
/// after the exec returns. alpine's base busybox has NO `httpd` applet (that
/// lives in busybox-extras), but its `nc` supports `-l -p` and `-e PROG`
/// (verified on a live alpine:3.20 guest) — so serve with an nc accept loop
/// that reads the request line first, then answers from `index.html`.
fn start_guest_httpd(paths: &Paths, name: &str, body: &str, guest_port: u16) {
    exec_ok(
        paths,
        name,
        &[
            "sh",
            "-c",
            &format!("printf '%s' '{body}' > /workspace/index.html"),
        ],
    );
    // The per-connection handler script: consume the request line, reply.
    // `printf '%s\n' ARGS...` writes the args verbatim (no escape processing),
    // so the script's own `printf "...\r\n\r\n"` reaches the file intact and
    // is interpreted by the guest shell at serve time.
    exec_ok(
        paths,
        name,
        &[
            "sh",
            "-c",
            concat!(
                r#"printf '%s\n' 'read -r _' 'printf "HTTP/1.0 200 OK\r\n\r\n"' "#,
                r#"'cat /workspace/index.html' > /workspace/serve.sh"#
            ),
        ],
    );
    // Accept loop, disowned via setsid so it survives the exec's teardown.
    let cmd = format!(
        "setsid sh -c 'while true; do nc -l -p {guest_port} -e sh /workspace/serve.sh; done' \
         >/dev/null 2>&1 &"
    );
    exec_ok(paths, name, &["sh", "-c", &cmd]);
    // Give the listener a moment to bind.
    std::thread::sleep(Duration::from_millis(300));
}

/// Minimal HTTP/1.0 GET against a host TCP port; returns the response body
/// (everything after the blank line). Retries briefly while the relay warms up.
fn http_get(host_port: u16) -> anyhow::Result<String> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let last_err = match (|| -> anyhow::Result<String> {
            let mut s = TcpStream::connect(("127.0.0.1", host_port))?;
            s.set_read_timeout(Some(Duration::from_secs(3)))?;
            s.write_all(b"GET /index.html HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
            let mut resp = String::new();
            s.read_to_string(&mut resp)?;
            let body = resp
                .split_once("\r\n\r\n")
                .map(|(_, b)| b.to_string())
                .unwrap_or_default();
            Ok(body)
        })() {
            Ok(body) if !body.is_empty() => return Ok(body),
            Ok(_) => "empty body".to_string(),
            Err(e) => e.to_string(),
        };
        if Instant::now() >= deadline {
            anyhow::bail!("http_get({host_port}) never succeeded: {last_err}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn boot_to_healthy_under_5s() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("boot");
    create_sandbox(&env, &mut tb, "bench", &ws);

    let t0 = Instant::now();
    if let Err(e) = start_sandbox(&env, &tb, "bench") {
        panic!(
            "boot failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "bench")
        );
    }
    let elapsed = t0.elapsed();
    if elapsed > Duration::from_secs(5) {
        eprintln!("note: boot took {elapsed:?} — over the 5s soft budget (hard budget is 10s)");
    }
    assert!(
        elapsed <= Duration::from_secs(10),
        "boot took {elapsed:?}, over the 10s hard budget"
    );

    stop_sandbox(&tb, "bench");
}

#[test]
fn exit_codes() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("exit");
    boot(&env, &mut tb, "exit", &ws);

    let (status, _, _) = exec_collect(&tb.paths, "exit", &["true"], None).expect("exec true");
    assert_eq!(status, ExitStatus::Code(0));

    let (status, _, _) = exec_collect(&tb.paths, "exit", &["false"], None).expect("exec false");
    assert_eq!(status, ExitStatus::Code(1));

    // Stance B: the workload runs inside the crun container, so command
    // resolution happens in crun — a missing executable is no longer a
    // spawn-time CommandNotFound frame. crun prints its own "executable file
    // ... not found" diagnostic to stderr and exits non-zero (rc 1 on the
    // pinned crun 1.28), which izba passes straight through (honest
    // container-runtime behavior, like `docker exec`).
    let (status, out, err) = exec_collect(&tb.paths, "exit", &["/nonexistent"], None)
        .expect("exec of /nonexistent returns a status, not a transport error");
    assert_eq!(status, ExitStatus::Code(1), "missing command -> crun rc 1");
    assert!(
        out.is_empty(),
        "no stdout for a missing command, got {out:?}"
    );
    assert!(
        err.contains("not found"),
        "stderr should carry crun's not-found diagnostic, got {err:?}"
    );

    // Non-docker sandboxes report no engine at all (the field is `Some` only
    // when the guest booted with `izba.docker=1` — see docker_mode_engine_
    // runs_containers for the docker-mode counterpart).
    let connector = sandbox::default_connector();
    let mut stats_conn = connector(&tb.paths, "exit").expect("stats control connection");
    write_frame(&mut stats_conn, &Request::Stats).expect("sending stats request");
    match read_frame::<_, Response>(&mut stats_conn).expect("stats reply") {
        Response::Stats(g) => assert!(
            g.docker.is_none(),
            "non-docker sandbox must report no engine status, got {:?}",
            g.docker
        ),
        other => panic!("expected Stats, got {other:?}"),
    }
}

#[test]
fn stdin_echo() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("stdin");
    boot(&env, &mut tb, "stdin", &ws);

    let payload = b"hello izba\n";
    let (status, stdout, stderr) =
        exec_collect(&tb.paths, "stdin", &["cat"], Some(payload)).expect("exec cat");
    assert_eq!(status, ExitStatus::Code(0), "cat failed; stderr: {stderr}");
    assert_eq!(stdout.as_bytes(), payload, "stdout must echo stdin exactly");
}

#[test]
fn tty_resize() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("tty");
    boot(&env, &mut tb, "tty", &ws);

    let connector = sandbox::default_connector();
    let mut control = sandbox::control(&tb.paths, "tty", &connector).expect("control connection");

    // The guest pre-sizes the pty to 24x80 at openpty; the sleep gives the
    // Resize below time to land before stty queries the size.
    let req = Request::Exec(ExecRequest {
        argv: vec![
            "sh".to_string(),
            "-c".to_string(),
            "sleep 0.3; stty size".to_string(),
        ],
        env: vec![("PATH".to_string(), STD_PATH.to_string())],
        cwd: "/workspace".to_string(),
        tty: true,
        uid: 0,
        gid: 0,
    });
    write_frame(&mut control, &req).expect("sending exec");
    let exec_id = match read_frame::<_, Response>(&mut control).expect("exec reply") {
        Response::ExecStarted { exec_id } => exec_id,
        other => panic!("unexpected reply to tty exec: {other:?}"),
    };

    // Resize immediately on the same control connection (still free; Wait
    // goes to a second connection).
    write_frame(
        &mut control,
        &Request::Resize {
            exec_id,
            cols: 99,
            rows: 31,
        },
    )
    .expect("sending resize");
    match read_frame::<_, Response>(&mut control).expect("resize reply") {
        Response::Ok => {}
        other => panic!("unexpected reply to resize: {other:?}"),
    }

    let tty = attach(&tb.paths, "tty", exec_id, StreamKind::Tty);
    let out_t = std::thread::spawn(move || slurp(tty));

    let mut wait_conn = connector(&tb.paths, "tty").expect("wait connection");
    let status = wait(&mut wait_conn, exec_id).expect("wait");
    let output = out_t.join().expect("tty pump");

    assert_eq!(status, ExitStatus::Code(0), "stty size failed: {output}");
    assert!(
        output.contains("31 99"),
        "pty must report the resized 31x99 geometry, got: {output:?}"
    );
}

#[test]
fn workspace_roundtrip() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("rt");
    fs::write(ws.join("hello.txt"), "from-host").unwrap();
    boot(&env, &mut tb, "rt", &ws);

    // host → guest
    let stdout = exec_ok(&tb.paths, "rt", &["cat", "/workspace/hello.txt"]);
    assert_eq!(stdout, "from-host");

    // guest → host (virtiofs writeback may lag a moment; poll briefly)
    exec_ok(
        &tb.paths,
        "rt",
        &["sh", "-c", "echo from-guest > /workspace/back.txt"],
    );
    let back = ws.join("back.txt");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(content) = fs::read_to_string(&back) {
            if content == "from-guest\n" {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "host never saw back.txt == \"from-guest\\n\" (got: {:?})",
            fs::read_to_string(&back).ok()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Option A container user-namespace mapping, end-to-end on a real boot.
///
/// The default image (alpine) runs as root, and the test process's euid (the
/// workspace owner) is non-zero, so `generate_spec` emits a NON-identity,
/// MULTI-EXTENT transposition map (swap container-0 <-> host-euid). This is
/// exactly the shape the crun-userns spike flagged as unproven on the real
/// overlay-root boot (it `EINVAL`'d / hit `readlink ''` on the minimal
/// initramfs harness). Booting + exec'ing here proves crun accepts the
/// multi-extent map and the round-trip is correct:
///
/// - container-root (uid 0) owns the host-owned `/workspace` (the transposition
///   maps host-euid -> container-0), so an in-guest `stat` reports owner 0;
/// - a file the container writes to `/workspace` lands on the host owned by the
///   workspace owner (the test euid) — virtiofsd squashes to the host user.
///
/// `#[cfg(unix)]`: asserts on POSIX file ownership (`MetadataExt::uid`), which
/// only exists on unix; the KVM suite runs on Linux only anyway.
/// Shared assertions for the Option A userns round-trip tests:
/// 1. the workload runs as `expect_uid` (the image USER);
/// 2. the host-seeded `/workspace/seed.txt` appears owned by `expect_uid`
///    inside the guest (transposition: host owner -> the workload USER);
/// 3. a file the workload writes to `/workspace` lands on the host owned by the
///    workspace directory's owner (virtiofsd squashes to the host user,
///    whatever the in-guest uid).
#[cfg(unix)]
fn assert_userns_workspace_roundtrip(paths: &Paths, name: &str, ws: &Path, expect_uid: &str) {
    use std::os::unix::fs::MetadataExt;

    let uid = exec_ok(paths, name, &["id", "-u"]);
    assert_eq!(
        uid.trim(),
        expect_uid,
        "workload must run as the image USER {expect_uid}"
    );

    let owner = exec_ok(paths, name, &["stat", "-c", "%u", "/workspace/seed.txt"]);
    assert_eq!(
        owner.trim(),
        expect_uid,
        "the image USER {expect_uid} must own the host workspace under the userns map"
    );

    // guest -> host: the workload-created file lands owned by the workspace
    // owner regardless of the in-guest uid.
    let want_uid = fs::metadata(ws).unwrap().uid();
    exec_ok(
        paths,
        name,
        &["sh", "-c", "echo from-guest > /workspace/out.txt"],
    );
    let out = ws.join("out.txt");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if fs::metadata(&out)
            .map(|m| m.uid())
            .is_ok_and(|u| u == want_uid)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "host never saw out.txt owned by workspace owner {want_uid} (got {:?})",
            fs::metadata(&out).map(|m| m.uid())
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(unix)]
#[test]
fn userns_root_owns_workspace_roundtrip() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("userns");
    fs::write(ws.join("seed.txt"), "from-host").unwrap();
    boot(&env, &mut tb, "userns", &ws);

    // alpine's USER is root; the transposition swaps host-euid <-> container-0,
    // so container-root owns the host-owned /workspace and the write round-trips.
    assert_userns_workspace_roundtrip(&tb.paths, "userns", &ws, "0");
    stop_sandbox(&tb, "userns");
}

/// Option A with a REAL multi-uid image whose `USER` is numeric and non-root.
///
/// Uses `nginxinc/nginx-unprivileged` (pinned by digest) — `USER 101`, alpine
/// base (busybox `id`/`stat`/`sh`). This is the case the spike called out
/// (recommendation #4: "real multi-uid images use a uid range — does Option A
/// run them?"). The transposition swaps container-101 with the host workspace
/// owner, so default exec runs as USER 101, that USER owns `/workspace`, and its
/// writes round-trip to the host owner.
///
/// Pulled directly into the test's own store (not the shared alpine cache) so
/// the image's real `config.json` (carrying `USER 101`) drives the mapping.
///
/// `#[cfg(unix)]`: asserts on POSIX file ownership; KVM suite is Linux-only.
#[cfg(unix)]
#[test]
fn userns_numeric_user_owns_workspace() {
    let Some(env) = want() else { return };
    // Pinned digest of nginxinc/nginx-unprivileged:alpine (USER 101). Pinning by
    // digest keeps the test reproducible even if the floating tag is re-pushed.
    const IMAGE: &str = "nginxinc/nginx-unprivileged@sha256:054e14f543eb688809d59ec2ad1644d1a61678e247c87a318ad605977eb37eaf";

    let mut tb = TestBox::new();
    let ws = tb.workspace("uns-user");
    fs::write(ws.join("seed.txt"), "from-host").unwrap();

    // Pull the multi-uid image into this test's own store; its config.json
    // carries the numeric USER 101 that drives the transposition.
    let digest = ensure_image(&tb.paths, IMAGE).expect("pull multi-uid image");
    sandbox::create(
        &tb.paths,
        "uns-user",
        &CreateOpts {
            image_digest: digest,
            image_ref: IMAGE.to_string(),
            cpus: 1,
            mem_mb: 1024,
            workspace: ws.clone(),
            rw_size_gb: 2,
            ports: Vec::new(),
            volumes: Vec::new(),
            builder: false,
            docker: false,
            vnc: false,
        },
    )
    .expect("create");
    tb.names.push("uns-user".to_string());
    if let Err(e) = start_sandbox(&env, &tb, "uns-user") {
        panic!(
            "boot failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "uns-user")
        );
    }

    assert_userns_workspace_roundtrip(&tb.paths, "uns-user", &ws, "101");

    // --- the sudo-enabling property of the transposition ---
    // For a non-root USER, image-root-owned files (guest uid 0) map to
    // container-root (uid 0) inside the userns. That is the exact kernel
    // precondition for setuid-root binaries (sudo, su) owned by image-root to be
    // honored: the file is owned by the namespace's root, so the setuid bit
    // elevates to container-0. We assert the precondition directly (a root-owned
    // image file reads as uid 0 inside) plus that USER 101 is GENUINELY
    // unprivileged (cannot read a root-only file). A full in-container `sudo`
    // round-trip needs an image fixture with sudo+NOPASSWD and a numeric USER —
    // tracked as a follow-up.
    let passwd_owner = exec_ok(&tb.paths, "uns-user", &["stat", "-c", "%u", "/etc/passwd"]);
    assert_eq!(
        passwd_owner.trim(),
        "0",
        "image-root files must map to container-root (uid 0) — the precondition \
         for setuid sudo-to-root under a non-root USER"
    );
    let (shadow_status, _, _) = exec_collect(&tb.paths, "uns-user", &["cat", "/etc/shadow"], None)
        .expect("exec cat shadow");
    assert_ne!(
        shadow_status,
        ExitStatus::Code(0),
        "USER 101 must NOT read root-only /etc/shadow (640 root:shadow) — proves it \
         is genuinely unprivileged, not silently mapped to root"
    );

    stop_sandbox(&tb, "uns-user");
}

/// Symbolic image `USER` (`nobody`) is resolved host-side to its numeric uid
/// (65534 on alpine) and baked into the OCI `process.user`.  Distinct from the
/// numeric-`USER` test: the image config carries a *name*, not a number.  The
/// host reads the captured `/etc/passwd` (`nobody:x:65534:65534:…`) produced by
/// Task 4's flatten step and maps "nobody" → 65534, then transposes the userns
/// workspace accordingly.
///
/// Fixture: `alpine:3.20` (the suite's `DEFAULT_IMAGE`) pulled into a private
/// per-test store so the shared cache is unaffected.  After the pull the test
/// patches the image's `config.json` in-place — setting `["config"]["User"] =
/// "nobody"` — before handing the digest to `sandbox::create`.
///
/// `#[cfg(unix)]`: asserts on POSIX file ownership; KVM suite is Linux-only.
#[cfg(unix)]
#[test]
fn userns_resolves_symbolic_image_user() {
    use izba_core::image::ImageStore;

    let Some(env) = want() else { return };

    let mut tb = TestBox::new();
    let ws = tb.workspace("uns-sym");
    fs::write(ws.join("seed.txt"), "from-host").unwrap();

    // Pull alpine into this test's own private store so we can patch its
    // config.json without poisoning the shared image cache used by other tests.
    let digest =
        ensure_image(&tb.paths, DEFAULT_IMAGE).expect("pull alpine for symbolic-user test");

    // Patch config.json: set ["config"]["User"] = "nobody".
    // Alpine ships `nobody:x:65534:65534:…` in /etc/passwd; the flatten step
    // captures that file, so the host-side resolver maps "nobody" → 65534.
    let cfg_path = ImageStore::new(&tb.paths).config_path(&digest);
    let raw = fs::read_to_string(&cfg_path).expect("config.json must be present after pull");
    let mut cfg_value: serde_json::Value =
        serde_json::from_str(&raw).expect("config.json must be valid JSON");
    cfg_value["config"]["User"] = serde_json::Value::String("nobody".to_string());
    let patched = serde_json::to_vec(&cfg_value).expect("re-serialise patched config");
    ImageStore::new(&tb.paths)
        .persist_config(&digest, &patched)
        .expect("atomically write patched config.json");

    // Create and start the sandbox with the patched image config.
    sandbox::create(
        &tb.paths,
        "uns-sym",
        &CreateOpts {
            image_digest: digest,
            image_ref: DEFAULT_IMAGE.to_string(),
            cpus: 1,
            mem_mb: 1024,
            workspace: ws.clone(),
            rw_size_gb: 2,
            ports: Vec::new(),
            volumes: Vec::new(),
            builder: false,
            docker: false,
            vnc: false,
        },
    )
    .expect("create");
    tb.names.push("uns-sym".to_string());
    if let Err(e) = start_sandbox(&env, &tb, "uns-sym") {
        panic!(
            "boot failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "uns-sym")
        );
    }

    // Symbolic USER "nobody" must resolve to uid 65534 (alpine's nobody uid).
    assert_userns_workspace_roundtrip(&tb.paths, "uns-sym", &ws, "65534");

    stop_sandbox(&tb, "uns-sym");
}

/// #222, end-to-end on a **glibc, non-Alpine** image.
///
/// Every other sandbox this suite boots is Alpine/musl-family or scratch, which
/// is precisely why a fully green board shipped a bug where bare commands could
/// not be resolved. This is the capability-not-environment gap again.
///
/// Two things are asserted, and neither hardcodes a `PATH`:
///
/// 1. **Bare commands resolve.** `cat`/`sh`/`ls` with NO caller-supplied env —
///    exactly what the real CLI sends (`commands/exec.rs` sends `vec![]`). This
///    is the literal reproduction from the issue.
/// 2. **The observed `PATH` is the image's DECLARED `PATH`**, compared against
///    the image's own OCI config read back from the image store — not against a
///    constant. If izba ever injected a default, this fails even though (1)
///    would still pass.
///
/// `exec_collect_env` is used rather than `exec_ok`, because the suite's normal
/// exec helper supplies `PATH=STD_PATH` and would mask the whole bug.
#[test]
fn non_alpine_image_bare_commands_resolve_via_the_images_declared_path() {
    use izba_core::image::ImageStore;

    // The image from the issue itself, so AC1 is asserted literally.
    const GLIBC_IMAGE: &str = "ubuntu:24.04";

    let Some(env) = want() else { return };

    let mut tb = TestBox::new();
    let ws = tb.workspace("glibc");

    let digest = ensure_image(&tb.paths, GLIBC_IMAGE).expect("pull the glibc test image");

    // The oracle: what does the image itself declare? Read it from the cached
    // OCI config, so the assertion tracks the image and not our expectations.
    let declared_path: String = ImageStore::new(&tb.paths)
        .load_config(&digest)
        .expect("load image config")
        .and_then(|f| f.config)
        .and_then(|c| c.env)
        .unwrap_or_default()
        .iter()
        .find_map(|e| e.strip_prefix("PATH=").map(str::to_string))
        .expect("the test image must declare a PATH in its OCI config");

    sandbox::create(
        &tb.paths,
        "glibc",
        &CreateOpts {
            image_digest: digest,
            image_ref: GLIBC_IMAGE.to_string(),
            cpus: 1,
            mem_mb: 1024,
            workspace: ws.clone(),
            rw_size_gb: 2,
            ports: Vec::new(),
            volumes: Vec::new(),
            builder: false,
            docker: false,
            vnc: false,
        },
    )
    .expect("create");
    tb.names.push("glibc".to_string());
    if let Err(e) = start_sandbox(&env, &tb, "glibc") {
        panic!(
            "boot failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "glibc")
        );
    }

    // (1) Bare commands, no caller env — the exact failure from the issue.
    for argv in [
        vec!["cat", "/etc/os-release"],
        vec!["sh", "-c", "exit 0"],
        vec!["ls", "/"],
    ] {
        let (status, stdout, stderr) =
            exec_collect_env(&tb.paths, "glibc", &argv, None, Vec::new())
                .unwrap_or_else(|(k, m)| panic!("exec {argv:?} failed to start: {k:?}: {m}"));
        assert_eq!(
            status,
            ExitStatus::Code(0),
            "bare `{}` must resolve via the image's PATH\nstdout: {stdout}\nstderr: {stderr}",
            argv.join(" ")
        );
    }

    // Sanity: this really is the non-Alpine image we asked for.
    let (_, os_release, _) = exec_collect_env(
        &tb.paths,
        "glibc",
        &["cat", "/etc/os-release"],
        None,
        Vec::new(),
    )
    .expect("cat /etc/os-release");
    assert!(
        os_release.to_lowercase().contains("ubuntu"),
        "expected an ubuntu rootfs, got: {os_release}"
    );

    // (2) The PATH the process sees IS the image's declared PATH.
    let (status, observed, stderr) =
        exec_collect_env(&tb.paths, "glibc", &["printenv", "PATH"], None, Vec::new())
            .expect("printenv PATH");
    assert_eq!(
        status,
        ExitStatus::Code(0),
        "printenv PATH failed: {stderr}"
    );
    assert_eq!(
        observed.trim(),
        declared_path,
        "the process must see the image's DECLARED PATH, not an izba-invented default"
    );

    stop_sandbox(&tb, "glibc");
}

#[test]
fn rw_persistence_across_restart() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("rw");
    boot(&env, &mut tb, "rw", &ws);

    // Writes to / land in the overlay upper layer, i.e. on rw.img.
    exec_ok(
        &tb.paths,
        "rw",
        &["sh", "-c", "echo keep > /marker && sync"],
    );
    stop_sandbox(&tb, "rw");

    if let Err(e) = start_sandbox(&env, &tb, "rw") {
        panic!(
            "second boot failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "rw")
        );
    }
    let stdout = exec_ok(&tb.paths, "rw", &["cat", "/marker"]);
    assert_eq!(stdout, "keep\n", "/marker must survive a restart");
}

#[test]
fn volumes_persist_reattach_and_prune() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("vol");
    let vols = vec![
        izba_core::volume::VolumeSpec {
            name: None,
            guest_path: "/eph".into(),
            size_bytes: 64 << 20,
            eph_id: None,
        },
        izba_core::volume::VolumeSpec {
            name: Some("data".into()),
            guest_path: "/data".into(),
            size_bytes: 64 << 20,
            eph_id: None,
        },
    ];
    create_sandbox_with_volumes(&env, &mut tb, "vol", &ws, vols);
    if let Err(e) = start_sandbox(&env, &tb, "vol") {
        panic!(
            "boot of 'vol' failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "vol")
        );
    }

    // Both volumes are mounted ext4 at their declared paths; write a sentinel
    // to each (these land on the volume disks, NOT the overlay/rw.img).
    exec_ok(
        &tb.paths,
        "vol",
        &[
            "sh",
            "-c",
            "echo eph > /eph/s && echo data > /data/s && sync",
        ],
    );

    // Survive a stop/start (the M3 exit criterion).
    stop_sandbox(&tb, "vol");
    if let Err(e) = start_sandbox(&env, &tb, "vol") {
        panic!(
            "restart of 'vol' failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "vol")
        );
    }
    assert_eq!(exec_ok(&tb.paths, "vol", &["cat", "/eph/s"]), "eph\n");
    assert_eq!(exec_ok(&tb.paths, "vol", &["cat", "/data/s"]), "data\n");

    // Remove the sandbox: ephemeral image goes with the sandbox dir, the named
    // persistent image survives under <data>/volumes.
    stop_sandbox(&tb, "vol");
    let connector = sandbox::default_connector();
    sandbox::remove(&tb.paths, "vol", &connector, true).expect("remove vol");
    tb.names.retain(|n| n != "vol");
    assert!(
        tb.paths.volume_image("data").exists(),
        "persistent volume must survive rm"
    );
    assert!(
        !tb.paths.sandbox_dir("vol").exists(),
        "ephemeral volume goes with the sandbox dir"
    );

    // A new sandbox re-attaches the named volume by name — data is intact and
    // the image is NOT reformatted.
    let ws2 = tb.workspace("vol2");
    create_sandbox_with_volumes(
        &env,
        &mut tb,
        "vol2",
        &ws2,
        vec![izba_core::volume::VolumeSpec {
            name: Some("data".into()),
            guest_path: "/data".into(),
            size_bytes: 64 << 20,
            eph_id: None,
        }],
    );
    if let Err(e) = start_sandbox(&env, &tb, "vol2") {
        panic!(
            "boot of 'vol2' failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "vol2")
        );
    }
    assert_eq!(
        exec_ok(&tb.paths, "vol2", &["cat", "/data/s"]),
        "data\n",
        "re-attached persistent volume keeps prior data"
    );

    // Prune while "data" is still referenced by vol2: it must be kept.
    let kept = sandbox::prune_volumes(&tb.paths).expect("prune (referenced)");
    assert!(
        kept.removed.is_empty(),
        "referenced volume must not be pruned"
    );
    assert!(tb.paths.volume_image("data").exists());

    // Remove vol2, then prune: now "data" is unreferenced and gets reaped.
    stop_sandbox(&tb, "vol2");
    sandbox::remove(&tb.paths, "vol2", &connector, true).expect("remove vol2");
    tb.names.retain(|n| n != "vol2");
    let pruned = sandbox::prune_volumes(&tb.paths).expect("prune (unreferenced)");
    assert_eq!(pruned.removed, vec!["data".to_string()]);
    assert!(!tb.paths.volume_image("data").exists());
}

#[test]
fn volume_survives_force_rm_of_running_sandbox() {
    // #78 regression: rm --force of a RUNNING sandbox must not lose unsynced
    // persistent-volume writes. The force path now sends the guest Shutdown
    // (init syncs the page cache before power-off) under a bounded grace.
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("fvol");
    create_sandbox_with_volumes(
        &env,
        &mut tb,
        "fvol",
        &ws,
        vec![izba_core::volume::VolumeSpec {
            name: Some("fdata".into()),
            guest_path: "/data".into(),
            size_bytes: 64 << 20,
            eph_id: None,
        }],
    );
    if let Err(e) = start_sandbox(&env, &tb, "fvol") {
        panic!(
            "boot of 'fvol' failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "fvol")
        );
    }

    // Write WITHOUT an explicit sync: the sentinel sits in the guest page
    // cache, exactly the state the old abrupt kill lost.
    exec_ok(&tb.paths, "fvol", &["sh", "-c", "echo forced > /data/s"]);

    // Force-remove while still running.
    let connector = sandbox::default_connector();
    sandbox::remove(&tb.paths, "fvol", &connector, true).expect("force rm running fvol");
    tb.names.retain(|n| n != "fvol");
    assert!(
        tb.paths.volume_image("fdata").exists(),
        "persistent volume must survive force rm"
    );

    // Re-attach in a fresh sandbox: the unsynced write must have survived.
    let ws2 = tb.workspace("fvol2");
    create_sandbox_with_volumes(
        &env,
        &mut tb,
        "fvol2",
        &ws2,
        vec![izba_core::volume::VolumeSpec {
            name: Some("fdata".into()),
            guest_path: "/data".into(),
            size_bytes: 64 << 20,
            eph_id: None,
        }],
    );
    if let Err(e) = start_sandbox(&env, &tb, "fvol2") {
        panic!(
            "boot of 'fvol2' failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "fvol2")
        );
    }
    assert_eq!(
        exec_ok(&tb.paths, "fvol2", &["cat", "/data/s"]),
        "forced\n",
        "write made just before rm --force of the running sandbox must survive"
    );
}

#[test]
fn first_boot_formats_blank_rw() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("blank");
    create_sandbox(&env, &mut tb, "blank", &ws);

    // create() pre-formats rw.img when mkfs.ext4 exists on the host; defeat
    // that by re-creating it as a blank sparse file of the same size, so the
    // guest-side mke2fs path (if the initramfs embeds one) is exercised.
    let rw = tb.paths.sandbox_dir("blank").join("rw.img");
    let size = fs::metadata(&rw).expect("rw.img metadata").len();
    let f = File::create(&rw).expect("re-creating rw.img");
    f.set_len(size).expect("sizing blank rw.img");
    drop(f);

    match start_sandbox(&env, &tb, "blank") {
        Ok(()) => {
            // Boot succeeded → the guest must have formatted the disk.
            let stdout = exec_ok(&tb.paths, "blank", &["sh", "-c", "touch /x && echo ok"]);
            assert_eq!(stdout, "ok\n");
        }
        Err(e) => {
            let console = console_tail(&tb.paths, "blank");
            if console.contains("no mke2fs") {
                eprintln!(
                    "SKIP first_boot_formats_blank_rw: initramfs has no embedded mke2fs \
                     (rebuild with IZBA_MKE2FS=... to cover this path)"
                );
                return;
            }
            panic!(
                "boot with blank rw.img failed unexpectedly: {e:#}\nconsole tail:\n{}",
                boot_diag(&tb.paths, "blank")
            );
        }
    }
}

/// Real-internet reachability through the only egress path there is now: the
/// izbad-owned vsock_1027 stub (nft REDIRECT + DNS stub -> izbad dial-out).
/// The guest is NIC-less, so this fails outright without the EgressManager
/// stand-in bound before boot.
#[test]
fn guest_networking() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("net");
    create_sandbox(&env, &mut tb, "net", &ws);

    // Daemonless suite: stand in for izbad's listener ourselves. The listener
    // must exist on run/vsock.sock_1027 BEFORE the guest boots and dials it.
    use izba_core::daemon::egress::EgressManager;
    let mgr = EgressManager::new(
        izba_core::daemon::egress::sys_resolver::SystemResolver::new().expect("system resolver"),
        None,
        izba_core::daemon::egress::audit::AuditSink::new(tb.paths.clone()),
    );
    mgr.ensure_listening(&tb.paths, "net", &tb.paths.run_dir("net"))
        .expect("bind vsock_1027 listener");

    if let Err(e) = start_sandbox(&env, &tb, "net") {
        mgr.stop("net", &tb.paths.run_dir("net"));
        panic!(
            "boot of 'net' failed: {e:#}\nconsole tail:\n{}",
            console_tail(&tb.paths, "net")
        );
    }

    // busybox wget (alpine) or curl (debian/ubuntu images), with in-guest
    // retries — the DNS stub + first egress dial can take a moment to settle
    // right after boot.
    let script = "for i in 1 2 3 4 5; do \
         if wget -qO- http://detectportal.firefox.com/success.txt 2>/dev/null \
            || curl -fsS http://detectportal.firefox.com/success.txt 2>/dev/null; \
         then exit 0; fi; sleep 2; done; \
         echo 'network unreachable after retries' >&2; exit 1";
    let (status, stdout, stderr) =
        exec_collect(&tb.paths, "net", &["sh", "-c", script], None).expect("exec network check");
    assert_eq!(
        status,
        ExitStatus::Code(0),
        "guest networking failed; stderr: {stderr}"
    );
    assert!(
        stdout.contains("success"),
        "expected captive-portal 'success' body, got: {stdout:?}"
    );

    stop_sandbox(&tb, "net");
    mgr.stop("net", &tb.paths.run_dir("net"));
}

/// Boot `name` with a stand-in izbad egress listener (the daemonless suite
/// plays izbad). The listener must exist on `run/vsock.sock_1027` BEFORE the
/// guest boots and dials it. Panics with the console tail on boot failure;
/// returns the manager so the caller stops it at the end. Shared by the
/// `egress_dns_*` tests so their setup isn't copy-pasted (CPD gate).
///
/// `policy_yaml`, when `Some`, is installed as the sandbox's egress policy
/// (via the same `EgressPolicyConfig::write_to` the CLI's
/// `persist_policy_config` uses) BEFORE `ensure_listening` — which resolves
/// the sandbox's policy once, at arm time — so an enforcing policy is live
/// for the whole boot. `None` keeps the bare/non-enforcing AllowAll default.
fn start_with_egress(
    env: &TestEnv,
    tb: &mut TestBox,
    name: &str,
    ws: &Path,
    policy_yaml: Option<&str>,
) -> izba_core::daemon::egress::EgressManager {
    use izba_core::daemon::egress::config::EgressPolicyConfig;
    create_sandbox(env, tb, name, ws);
    if let Some(yaml) = policy_yaml {
        let cfg = EgressPolicyConfig::from_yaml(yaml).expect("parsing egress policy yaml");
        cfg.write_to(&tb.paths.sandbox_dir(name))
            .expect("writing egress policy.yaml");
    }
    arm_egress_and_start(env, tb, name)
}

/// Arm the stand-in izbad egress listener for an ALREADY-CREATED sandbox and
/// boot it. Split out of [`start_with_egress`] so tests that need a bespoke
/// `create` (docker mode, a dedicated image, bigger cpu/mem) reuse the exact
/// same arm-then-boot ordering — the listener MUST exist on
/// `run/vsock.sock_1027` before the guest boots and dials it.
fn arm_egress_and_start(
    env: &TestEnv,
    tb: &TestBox,
    name: &str,
) -> izba_core::daemon::egress::EgressManager {
    use izba_core::daemon::egress::{
        audit::AuditSink, sys_resolver::SystemResolver, EgressManager,
    };
    let mgr = EgressManager::new(
        SystemResolver::new().expect("system resolver"),
        None,
        AuditSink::new(tb.paths.clone()),
    );
    mgr.ensure_listening(&tb.paths, name, &tb.paths.run_dir(name))
        .expect("bind vsock_1027 listener");
    if let Err(e) = start_sandbox(env, tb, name) {
        mgr.stop(name, &tb.paths.run_dir(name));
        panic!(
            "boot of '{name}' failed: {e:#}\nconsole tail:\n{}",
            console_tail(&tb.paths, name)
        );
    }
    mgr
}

/// M1 phase A exit: an egress=izbad sandbox resolves DNS through izbad.
/// This is ALSO the runtime validation of guest-initiated hybrid vsock
/// (guest dials CID 2:1027 -> CH bridges to run/vsock.sock_1027).
#[test]
fn egress_dns_via_izbad() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("egress-dns");
    let mgr = start_with_egress(&env, &mut tb, "egress-dns", &ws, None);

    // getent uses the guest resolv.conf (nameserver 127.0.0.1 -> the izba-init
    // DNS stub on 0.0.0.0:53 -> vsock Dns stream -> izbad SystemResolver ->
    // host upstream). The reply rides loopback; a non-loopback resolver address
    // would be REDIRECTed by nft and its reply dropped (wildcard-socket
    // source-address mismatch; see NFT_RULESET's doc in egress.rs).
    let out = exec_ok(
        &tb.paths,
        "egress-dns",
        &["sh", "-lc", "getent hosts example.com"],
    );
    assert!(
        out.contains("example.com"),
        "expected a resolved address for example.com, got: {out:?}"
    );

    stop_sandbox(&tb, "egress-dns");
    mgr.stop("egress-dns", &tb.paths.run_dir("egress-dns"));
}

/// #148 e2e: an ENFORCING policy that allow-lists only `example.com` denies
/// DNS for an unlisted name (`example.org`), NXDOMAIN'd by the host-side gate
/// in `dns_loop` (`daemon/egress/router.rs`) and never forwarded upstream.
/// Both names are real, live domains that resolve fine with no izba involved
/// at all — so any observed difference between them is proof of izba's own
/// enforcement, not network happenstance.
#[test]
fn egress_dns_enforce_denies_unlisted() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("egress-dns-enforce");
    let name = "egress-dns-enforce";
    let mgr = start_with_egress(
        &env,
        &mut tb,
        name,
        &ws,
        Some("enforce: true\nallow:\n  - example.com\n"),
    );

    // Allowed: example.com is on the allow-list, forwarded upstream as usual.
    let out = exec_ok(&tb.paths, name, &["sh", "-lc", "getent hosts example.com"]);
    assert!(
        out.contains("example.com"),
        "expected the allow-listed example.com to resolve, got: {out:?}"
    );

    // Denied: example.org is NOT on the allow-list, so the enforcing gate
    // must answer NXDOMAIN instead of forwarding upstream. `getent` exits
    // non-zero on NXDOMAIN, so `exec_collect` (not `exec_ok`) is required.
    let (status, stdout, stderr) = exec_collect(
        &tb.paths,
        name,
        &["sh", "-lc", "getent hosts example.org"],
        None,
    )
    .expect("exec getent example.org");
    assert_ne!(
        status,
        ExitStatus::Code(0),
        "expected getent to fail (NXDOMAIN) for the unlisted example.org, \
         stdout: {stdout:?} stderr: {stderr:?}"
    );
    assert!(
        !stdout.contains("example.org"),
        "expected NO resolved address for the denied example.org, got: {stdout:?}"
    );

    // The denial must be audit-logged: one JSONL line with a deny verdict, a
    // DNS-tier rule, for the denied host.
    let audit_path = tb.paths.logs_dir(name).join("egress-audit.jsonl");
    let audit_text = fs::read_to_string(&audit_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", audit_path.display()));
    let denied = audit_text.lines().any(|line| {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        v.get("verdict").and_then(|x| x.as_str()) == Some("deny")
            && v.get("rule")
                .and_then(|x| x.as_str())
                .is_some_and(|r| r.starts_with("DNS:"))
            && v.get("host").and_then(|x| x.as_str()) == Some("example.org")
    });
    assert!(
        denied,
        "expected a deny audit record for example.org (a 'DNS:' rule), got:\n{audit_text}"
    );

    stop_sandbox(&tb, name);
    mgr.stop(name, &tb.paths.run_dir(name));
}

/// Transparent-reply fix (M4 prereq for docker/build-in-VM): a client that
/// hardcodes an external UDP resolver (e.g. dockerd/buildkit falling back to
/// 8.8.8.8:53 after stripping the loopback resolv.conf) resolves names. The
/// nft `udp dport 53 redirect` pulls the query to the stub; the stub answers
/// FROM the REDIRECT's original destination (IP_ORIGDSTADDR/IP_PKTINFO) so
/// conntrack un-NATs the reply. Before the fix this path was dead (wildcard
/// source mismatch). busybox `nslookup <name> <server>` queries ONLY the given
/// server over UDP, so it exercises exactly the hardcoded-resolver path,
/// bypassing the loopback resolv.conf the `egress_dns_via_izbad` test covers.
#[test]
fn egress_dns_hardcoded_external_resolver() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("egress-dns-hard");
    let mgr = start_with_egress(&env, &mut tb, "egress-dns-hard", &ws, None);

    // Query 8.8.8.8 explicitly: the datagram leaves for 8.8.8.8:53, nft
    // REDIRECTs it to the guest stub, izbad resolves via the host upstream,
    // and the transparent reply (sourced from the REDIRECT's 127.0.0.1 dst)
    // is un-NAT'd by conntrack back to 8.8.8.8:53 so nslookup accepts it.
    let out = exec_ok(
        &tb.paths,
        "egress-dns-hard",
        &["sh", "-lc", "nslookup example.com 8.8.8.8"],
    );
    assert!(
        out.contains("example.com") && out.to_lowercase().contains("address"),
        "expected nslookup against hardcoded 8.8.8.8 to resolve example.com, got: {out:?}"
    );

    stop_sandbox(&tb, "egress-dns-hard");
    mgr.stop("egress-dns-hard", &tb.paths.run_dir("egress-dns-hard"));
}

/// Completeness companion to `egress_dns_hardcoded_external_resolver`: DNS over
/// *TCP* to a hardcoded external resolver is ALSO intercepted by the in-guest
/// resolver, not raw-dialed to that IP. We target `192.0.2.1` (RFC 5737
/// TEST-NET-1, guaranteed to host no real DNS server), so a non-empty answer
/// can ONLY come from izba's resolver — the pre-`tcp dport 53 redirect` behaviour
/// (general TCP REDIRECT → `TcpConnect` dial-out to 192.0.2.1:53) would connect
/// nowhere and return nothing. busybox has no TCP-capable resolver, so we craft
/// a minimal DNS/TCP query for `example.com` (2-byte length prefix + message,
/// id 0xABCD) and send it with `nc`; the response echoes the question, whose
/// `example` label is `65 78 61 6d 70 6c 65` in the hexdump. `sleep` keeps nc's
/// stdin open long enough to read the reply before half-closing.
#[test]
fn egress_dns_tcp_hardcoded_external_resolver() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("egress-dns-tcp");
    let mgr = start_with_egress(&env, &mut tb, "egress-dns-tcp", &ws, None);

    // DNS/TCP query for example.com A IN (id 0xABCD), 2-byte length-prefixed;
    // octal escapes keep printf busybox-portable. The pipeline's exit status is
    // `tr`'s (always 0), so `exec_ok` won't trip on nc's exit code.
    let q = r"\000\035\253\315\001\000\000\001\000\000\000\000\000\000\007example\003com\000\000\001\000\001";
    let cmd = format!(
        "{{ printf '{q}'; sleep 2; }} | nc -w 5 192.0.2.1 53 | od -A n -t x1 | tr -d '\\n'"
    );
    let out = exec_ok(&tb.paths, "egress-dns-tcp", &["sh", "-lc", &cmd]);
    assert!(
        out.contains("65 78 61 6d 70 6c 65"),
        "expected a DNS/TCP answer echoing example.com from the in-guest resolver \
         (a raw dial to TEST-NET 192.0.2.1:53 would return nothing), got: {out:?}"
    );

    stop_sandbox(&tb, "egress-dns-tcp");
    mgr.stop("egress-dns-tcp", &tb.paths.run_dir("egress-dns-tcp"));
}

/// M1 phase B exit: guest TCP egress rides the stub. The guest wgets a
/// host-served one-shot HTTP page addressed by a routable host IP; the nft
/// REDIRECT intercepts, izbad dials back to the host listener.
#[test]
fn egress_http_via_stub() {
    use std::io::{Read as _, Write as _};
    let Some(env) = want() else { return };
    // A host IP the guest can name and izbad can dial (NOT loopback —
    // 127/8 is excluded from REDIRECT by design).
    let probe = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    probe.connect(("8.8.8.8", 80)).unwrap();
    let host_ip = probe.local_addr().unwrap().ip();

    let listener = std::net::TcpListener::bind((host_ip, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf);
        s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nizba-m1ok")
            .unwrap();
    });

    let mut tb = TestBox::new();
    let ws = tb.workspace("egress-http");
    create_sandbox(&env, &mut tb, "egress-http", &ws);

    // Daemonless suite: stand in for izbad's listener ourselves. The listener
    // must exist on run/vsock.sock_1027 BEFORE the guest boots and dials it.
    use izba_core::daemon::egress::EgressManager;
    let mgr = EgressManager::new(
        izba_core::daemon::egress::sys_resolver::SystemResolver::new().expect("system resolver"),
        None,
        izba_core::daemon::egress::audit::AuditSink::new(tb.paths.clone()),
    );
    mgr.ensure_listening(&tb.paths, "egress-http", &tb.paths.run_dir("egress-http"))
        .expect("bind vsock_1027 listener");

    if let Err(e) = start_sandbox(&env, &tb, "egress-http") {
        mgr.stop("egress-http", &tb.paths.run_dir("egress-http"));
        panic!(
            "boot of 'egress-http' failed: {e:#}\nconsole tail:\n{}",
            console_tail(&tb.paths, "egress-http")
        );
    }

    // The guest's nft REDIRECT intercepts this connect to the host's real IP;
    // the izba-init stub carries it over vsock as StreamOpen::TcpConnect, and
    // our EgressManager stand-in dials host_ip:port from the host netns.
    let out = exec_ok(
        &tb.paths,
        "egress-http",
        &["sh", "-lc", &format!("wget -qO- http://{host_ip}:{port}/")],
    );
    assert_eq!(out.trim(), "izba-m1ok");

    srv.join().unwrap();
    stop_sandbox(&tb, "egress-http");
    mgr.stop("egress-http", &tb.paths.run_dir("egress-http"));
}

/// M2 exit: the agent firewall MITMs guest HTTP(S) under a declared policy. A
/// sandbox with `--policy` allowing `example.com` gets the izba CA baked in, and
/// the MITM is exercised over BOTH tier-1 transports:
///   * HTTPS (:443) — the guest's TLS handshake to an allowed host completes
///     ONLY because it trusts the baked per-SNI leaf; the MITM decrypts the Host
///     and records an L7 ALLOW (non-allowed host → L7 DENY via a synthesized
///     403).
///   * Plaintext HTTP (:80) — apt's default. Classified as cleartext by
///     `OrigDst.port` (not TLS-handshaked), so this exercises `serve_mitm`'s
///     cleartext-ingress branch (hyper h1 server → per-request policy → h1
///     upstream over a raw TCP connection).
///
/// The host-side audit log is the robust, image-agnostic proof: an `l7` record
/// on :443 appears only if the guest trusted the baked CA AND the MITM read the
/// decrypted Host; an `l7` record on :80 appears only if the cleartext MITM read
/// the Host without a TLS handshake. Guest exit codes are secondary (busybox
/// TLS quirks vary by image).
///
/// Reaching the MITM at all requires the denied host to RESOLVE: the #148 DNS
/// gate NXDOMAINs any QNAME outside the allow-list, so the policy lists the
/// denied host on an unused port to keep it resolvable while :443/:80 stay
/// denied (see the policy comment in the test body). A fully-unlisted host is
/// asserted separately as an l3 :53 DENY — the DNS-gate quadrant.
#[test]
fn mitm_firewall_allows_and_denies_real_vm() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("mitm");
    // Declare the per-sandbox egress policy. Persisting it makes
    // `resolve_policy` arm an enforcing RegoPolicy at listen time, so tier-1
    // HTTPS is routed through the MITM.
    //
    // Since the #148 DNS gate, an enforcing sandbox NXDOMAINs any QNAME no
    // allow rule could match — a host absent from the policy is now denied at
    // DNS (tier l3) and never opens a TCP connection, so it can never produce
    // the L7 MITM records this test asserts. To keep exercising the L7 deny
    // path, www.iana.org is listed on a port it will never dial (9): the
    // port-agnostic `resolvable` rule lets its DNS through, while
    // `check(host, 443/80)` still denies — the MITM terminates and answers 403.
    let (mgr, _audit) = setup_mitm_sandbox(
        &env,
        &mut tb,
        "mitm",
        &ws,
        "allow:\n  - example.com\n  - host: www.iana.org\n    ports: [9]\n",
    );
    // Two datapaths, both routed through the MITM for an enforcing sandbox:
    //
    //   * HTTPS on :443 — a clean TLS handshake to the allowed host (validation
    //     ON, no --no-check-certificate) proves the guest trusts the baked CA;
    //     the denied host's handshake also completes so the MITM can read the
    //     Host and answer 403.
    //   * Plaintext HTTP on :80 — apt's default (archive.ubuntu.com). The :80
    //     records below are the regression guard for the cleartext-ingress path —
    //     they appear only if `serve_mitm`'s cleartext branch read the request
    //     head and ran policy (rather than force-handshaking TLS on the request
    //     line, which silently broke plaintext egress in an earlier design).
    //
    // Exit codes are informational; the audit log is the assertion. Retry the
    // allowed fetches — DNS + first egress dial can settle a beat after boot.
    let script = "\
        for i in 1 2 3 4 5; do \
          wget -qO- https://example.com/ >/dev/null 2>&1 && break; \
          curl -fsS https://example.com/ >/dev/null 2>&1 && break; \
          sleep 2; \
        done; echo allowed-https-rc=$?; \
        wget -qO- https://www.iana.org/ >/dev/null 2>&1; echo denied-https-wget-rc=$?; \
        curl -fsS https://www.iana.org/ >/dev/null 2>&1; echo denied-https-curl-rc=$?; \
        for i in 1 2 3 4 5; do \
          wget -qO- http://example.com/ >/dev/null 2>&1 && break; \
          curl -fsS http://example.com/ >/dev/null 2>&1 && break; \
          sleep 2; \
        done; echo allowed-http-rc=$?; \
        wget -qO- http://www.iana.org/ >/dev/null 2>&1; echo denied-http-wget-rc=$?; \
        curl -fsS http://www.iana.org/ >/dev/null 2>&1; echo denied-http-curl-rc=$?; \
        wget -qO- https://www.wikipedia.org/ >/dev/null 2>&1; echo dns-denied-rc=$?";
    let (_status, stdout, stderr) = exec_collect(&tb.paths, "mitm", &["sh", "-lc", script], None)
        .unwrap_or_else(|(k, m)| panic!("exec rejected ({k:?}): {m}"));
    eprintln!("guest output:\n{stdout}\n{stderr}");

    // The MITM records each decision synchronously before replying, so by the
    // time the guest commands return the lines are on disk. Read with a short
    // retry to absorb filesystem lag.
    let records = read_audit_with_retry(&tb.paths, "mitm");
    let l7 = |verdict: &str, host: &str, port: u16| {
        records.iter().any(|r| {
            r.tier == izba_core::daemon::egress::audit::Tier::L7
                && r.port == port
                && format!("{:?}", r.verdict).to_lowercase().contains(verdict)
                && r.host.as_deref() == Some(host)
        })
    };

    let dump = || {
        let lines: Vec<String> = records.iter().map(|r| r.to_json()).collect();
        format!(
            "audit records:\n{}\nconsole tail:\n{}",
            lines.join("\n"),
            console_tail(&tb.paths, "mitm")
        )
    };
    // HTTPS (:443) — TLS-terminated MITM path.
    assert!(
        l7("allow", "example.com", 443),
        "expected an L7 ALLOW for example.com:443 (guest trusted the baked CA + MITM saw the Host).\n{}",
        dump()
    );
    assert!(
        l7("deny", "www.iana.org", 443),
        "expected an L7 DENY for www.iana.org:443 (MITM terminated + policy denied).\n{}",
        dump()
    );
    // Plaintext HTTP (:80) — the apt-over-http path. These records exist only if
    // `serve_mitm`'s cleartext-ingress branch read the Host and ran policy instead
    // of force-handshaking TLS on the request line.
    assert!(
        l7("allow", "example.com", 80),
        "expected an L7 ALLOW for example.com:80 (plaintext HTTP MITM read the Host + allowed).\n{}",
        dump()
    );
    assert!(
        l7("deny", "www.iana.org", 80),
        "expected an L7 DENY for www.iana.org:80 (plaintext HTTP MITM terminated + policy denied).\n{}",
        dump()
    );
    // DNS gate (#148) — a host NO allow rule could match is refused at
    // resolution: NXDOMAIN + an l3 :53 deny record, and no TCP/L7 record ever
    // appears for it.
    let dns_denied = records.iter().any(|r| {
        r.tier == izba_core::daemon::egress::audit::Tier::L3
            && r.port == 53
            && format!("{:?}", r.verdict).to_lowercase().contains("deny")
            && r.host.as_deref() == Some("www.wikipedia.org")
    });
    assert!(
        dns_denied,
        "expected an L3 DNS DENY for www.wikipedia.org:53 (enforcing DNS gate refused the QNAME).\n{}",
        dump()
    );
    assert!(
        !records
            .iter()
            .any(|r| r.host.as_deref() == Some("www.wikipedia.org") && r.port != 53),
        "a DNS-refused host must never reach the TCP/MITM datapath.\n{}",
        dump()
    );

    stop_sandbox(&tb, "mitm");
    mgr.stop("mitm", &tb.paths.run_dir("mitm"));
}

/// Create a sandbox, write an egress `policy_yaml`, build a MITM-enabled
/// [`EgressManager`], bind it to the per-sandbox vsock_1027 listener, and
/// boot the VM.  The MITM runtime uses the same persistent izba CA that
/// `sandbox::start` bakes into the guest, so the guest trusts the per-SNI
/// leaves the MITM presents.
///
/// Extracted to avoid verbatim repetition across MITM integration tests
/// (SonarCloud duplication gate).
///
/// Returns `(mgr, audit)` — the caller drives assertions against `audit`
/// records and calls `mgr.stop(name, run_dir)` after the test.
fn setup_mitm_sandbox(
    env: &TestEnv,
    tb: &mut TestBox,
    name: &str,
    ws: &std::path::Path,
    policy_yaml: &str,
) -> (
    izba_core::daemon::egress::EgressManager,
    izba_core::daemon::egress::audit::AuditSink,
) {
    use izba_core::daemon::egress::audit::AuditSink;
    use izba_core::daemon::egress::config::EgressPolicyConfig;
    use izba_core::daemon::egress::mitm::{upstream_client_config_webpki, CertCache};
    use izba_core::daemon::egress::mitm_runtime::MitmRuntime;
    use izba_core::daemon::egress::EgressManager;

    create_sandbox(env, tb, name, ws);

    // Persist the policy before ensure_listening reads it (resolve_policy arms
    // an enforcing RegoPolicy at listen time when the file is present).
    std::fs::write(
        EgressPolicyConfig::path_in(&tb.paths.sandbox_dir(name)),
        policy_yaml,
    )
    .expect("write policy.yaml");

    // Build the MITM runtime from the SAME persistent CA that
    // `sandbox::start` bakes into the guest (both read `tb.paths.ca_dir()`),
    // so the guest trusts the per-SNI leaf the MITM presents.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = izba_core::ca::load_or_create(&tb.paths.ca_dir()).expect("izba CA");
    let certs = std::sync::Arc::new(CertCache::new(ca));
    let audit = AuditSink::new(tb.paths.clone());
    let mitm = std::sync::Arc::new(
        MitmRuntime::start(certs, upstream_client_config_webpki(), audit.clone())
            .expect("start MITM runtime"),
    );

    let mgr = EgressManager::new(
        izba_core::daemon::egress::sys_resolver::SystemResolver::new().expect("system resolver"),
        Some(mitm),
        audit.clone(),
    );
    mgr.ensure_listening(&tb.paths, name, &tb.paths.run_dir(name))
        .expect("bind vsock_1027 listener");

    if let Err(e) = start_sandbox(env, tb, name) {
        mgr.stop(name, &tb.paths.run_dir(name));
        panic!(
            "boot of {name:?} failed: {e:#}\nconsole tail:\n{}",
            console_tail(&tb.paths, name)
        );
    }

    (mgr, audit)
}

/// Read + parse the per-sandbox egress audit log, retrying briefly so a record
/// the MITM just wrote is observed.
fn read_audit_with_retry(
    paths: &Paths,
    name: &str,
) -> Vec<izba_core::daemon::egress::audit::AuditRecord> {
    use izba_core::daemon::egress::audit::parse_line;
    let path = paths.logs_dir(name).join("egress-audit.jsonl");
    for _ in 0..10 {
        if let Ok(body) = fs::read_to_string(&path) {
            let recs: Vec<_> = body.lines().filter_map(parse_line).collect();
            if !recs.is_empty() {
                return recs;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Vec::new()
}

/// M1 throughput baseline: bulk transfer through the egress stub.
/// MEASURED, NOT GATED (roadmap decision) — the number is printed for
/// trend-watching; the only assertion is that the transfer completes.
#[test]
fn egress_throughput_baseline() {
    use std::io::{Read as _, Write as _};
    let Some(env) = want() else { return };
    const PAYLOAD: usize = 64 * 1024 * 1024;
    let probe = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    probe.connect(("8.8.8.8", 80)).unwrap();
    let host_ip = probe.local_addr().unwrap().ip();
    let listener = std::net::TcpListener::bind((host_ip, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf);
        s.write_all(format!("HTTP/1.0 200 OK\r\nContent-Length: {PAYLOAD}\r\n\r\n").as_bytes())
            .unwrap();
        let chunk = vec![0u8; 64 * 1024];
        let mut sent = 0;
        while sent < PAYLOAD {
            let n = (PAYLOAD - sent).min(chunk.len());
            s.write_all(&chunk[..n]).unwrap();
            sent += n;
        }
    });

    let mut tb = TestBox::new();
    let ws = tb.workspace("egress-tput");
    create_sandbox(&env, &mut tb, "egress-tput", &ws);
    use izba_core::daemon::egress::EgressManager;
    let mgr = EgressManager::new(
        izba_core::daemon::egress::sys_resolver::SystemResolver::new().expect("system resolver"),
        None,
        izba_core::daemon::egress::audit::AuditSink::new(tb.paths.clone()),
    );
    mgr.ensure_listening(&tb.paths, "egress-tput", &tb.paths.run_dir("egress-tput"))
        .unwrap();
    if let Err(e) = start_sandbox(&env, &tb, "egress-tput") {
        mgr.stop("egress-tput", &tb.paths.run_dir("egress-tput"));
        panic!(
            "boot of 'egress-tput' failed: {e:#}\nconsole tail:\n{}",
            console_tail(&tb.paths, "egress-tput")
        );
    }

    let t0 = std::time::Instant::now();
    exec_ok(
        &tb.paths,
        "egress-tput",
        &[
            "sh",
            "-lc",
            &format!("wget -qO /dev/null http://{host_ip}:{port}/"),
        ],
    );
    let dt = t0.elapsed();
    eprintln!(
        "EGRESS THROUGHPUT BASELINE: {:.1} MiB/s ({PAYLOAD} bytes in {dt:?})",
        PAYLOAD as f64 / 1024.0 / 1024.0 / dt.as_secs_f64()
    );

    srv.join().unwrap();
    stop_sandbox(&tb, "egress-tput");
    mgr.stop("egress-tput", &tb.paths.run_dir("egress-tput"));
}

#[test]
fn concurrent_two_sandboxes() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws_a = tb.workspace("left");
    let ws_b = tb.workspace("right");
    boot(&env, &mut tb, "left", &ws_a);
    boot(&env, &mut tb, "right", &ws_b);

    for name in ["left", "right"] {
        let stdout = exec_ok(&tb.paths, name, &["sh", "-c", "echo $((6*7))"]);
        assert_eq!(stdout, "42\n", "sandbox '{name}' exec output");
    }

    stop_sandbox(&tb, "left");
    stop_sandbox(&tb, "right");
}

#[test]
fn stop_while_running() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("stop");
    boot(&env, &mut tb, "stop", &ws);

    // Launch a long-running exec and deliberately never wait on it.
    let connector = sandbox::default_connector();
    let mut control = sandbox::control(&tb.paths, "stop", &connector).expect("control connection");
    write_frame(
        &mut control,
        &Request::Exec(ExecRequest {
            argv: vec!["sleep".to_string(), "300".to_string()],
            env: vec![("PATH".to_string(), STD_PATH.to_string())],
            cwd: "/workspace".to_string(),
            tty: false,
            uid: 0,
            gid: 0,
        }),
    )
    .expect("sending exec");
    match read_frame::<_, Response>(&mut control).expect("exec reply") {
        Response::ExecStarted { .. } => {}
        other => panic!("unexpected reply to exec: {other:?}"),
    }
    drop(control);

    sandbox::stop(&tb.paths, "stop", &connector, STOP_TIMEOUT)
        .expect("stop must succeed while a workload is running");

    let infos = sandbox::list(&tb.paths, &connector).expect("list");
    let info = infos
        .iter()
        .find(|i| i.name == "stop")
        .expect("sandbox listed");
    assert_eq!(info.liveness, Liveness::Stopped);
}

#[test]
fn kill_vmm_then_ls_reports_stopped() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("kill");
    boot(&env, &mut tb, "kill", &ws);

    let state_path = tb.paths.sandbox_dir("kill").join(STATE_FILE);
    let state: RunState = load_json(&state_path)
        .expect("reading state.json")
        .expect("state.json present after start");

    // Simulate a VMM crash: SIGKILL it directly, bypassing izba.
    procmgr::kill_pid(&state.vmm_pid).expect("killing vmm");
    let deadline = Instant::now() + Duration::from_secs(2);
    while procmgr::pid_alive(&state.vmm_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !procmgr::pid_alive(&state.vmm_pid),
        "vmm must be dead after SIGKILL"
    );

    let connector = sandbox::default_connector();
    let infos = sandbox::list(&tb.paths, &connector).expect("list");
    let info = infos
        .iter()
        .find(|i| i.name == "kill")
        .expect("sandbox listed");
    assert_eq!(
        info.liveness,
        Liveness::Stopped,
        "a killed VMM must be reported as stopped"
    );
    assert!(
        !state_path.exists(),
        "list must clean up the stale state.json of a dead VMM"
    );

    // The crash simulation orphaned the sidecars (virtiofsd usually exits on
    // its own when the vhost-user peer dies, but don't rely on it).
    for (_, id) in &state.sidecar_pids {
        let _ = procmgr::kill_pid(id);
    }
}

// Uses Unix-only fs APIs (exec-bit + symlink assertions); the integration
// suite only ever boots on Linux/KVM. Gated so the windows-gnu --all-targets
// clippy gate (gate 6) still compiles this test target.
#[cfg(unix)]
#[test]
fn cp_round_trip_tree() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("cp");
    boot(&env, &mut tb, "cpbox", &ws);

    // Build a small tree on the host.
    let src = tb.root.path().join("cp-src");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a.txt"), b"alpha").unwrap();
    fs::write(src.join("sub/run.sh"), b"#!/bin/sh\necho hi\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(src.join("sub/run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink("a.txt", src.join("link")).unwrap();

    // Host -> guest: dest /etc/izba-cp-test does NOT exist and /etc does, so
    // the guest applies the RENAME rule (the tree source becomes the new tree
    // root named izba-cp-test). The host sends the dest verbatim + an archive
    // rooted at basename(src); tarfs::extract arbitrates this guest-side.
    let conn = sandbox::default_stream_connector()(&tb.paths, "cpbox")
        .expect("stream conn for cp to-guest");
    izba_core::cp::copy_to_guest(conn, &src, "/etc/izba-cp-test").expect("copy_to_guest");

    // Verify inside the guest via exec.
    let cat = exec_ok(&tb.paths, "cpbox", &["cat", "/etc/izba-cp-test/a.txt"]);
    assert_eq!(cat, "alpha");
    let mode = exec_ok(
        &tb.paths,
        "cpbox",
        &["sh", "-c", "stat -c %a /etc/izba-cp-test/sub/run.sh"],
    );
    assert_eq!(mode.trim(), "755", "exec bit must survive host->guest");
    let link = exec_ok(&tb.paths, "cpbox", &["readlink", "/etc/izba-cp-test/link"]);
    assert_eq!(link.trim(), "a.txt", "symlink must survive host->guest");

    // Host -> guest INTO-DIR rule: /etc/izba-cp-test now EXISTS and is a
    // directory, so copying a single file there lands it at
    // /etc/izba-cp-test/<basename>, NOT overwriting the directory.
    let extra = tb.root.path().join("extra.txt");
    fs::write(&extra, b"into-dir").unwrap();
    let conn = sandbox::default_stream_connector()(&tb.paths, "cpbox")
        .expect("stream conn for cp into-dir");
    izba_core::cp::copy_to_guest(conn, &extra, "/etc/izba-cp-test")
        .expect("copy_to_guest into existing dir");
    let into = exec_ok(&tb.paths, "cpbox", &["cat", "/etc/izba-cp-test/extra.txt"]);
    assert_eq!(into, "into-dir", "file must land inside the existing dir");

    // Guest -> host: copy it back out and assert byte-equality + bits.
    let out = tb.root.path().join("cp-out");
    fs::create_dir_all(&out).unwrap();
    let conn = sandbox::default_stream_connector()(&tb.paths, "cpbox")
        .expect("stream conn for cp from-guest");
    izba_core::cp::copy_from_guest(conn, "/etc/izba-cp-test", &out).expect("copy_from_guest");

    assert_eq!(fs::read(out.join("izba-cp-test/a.txt")).unwrap(), b"alpha");
    let back_mode = fs::metadata(out.join("izba-cp-test/sub/run.sh"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(back_mode, 0o755, "exec bit must survive guest->host");
    let back_link = fs::read_link(out.join("izba-cp-test/link")).unwrap();
    assert_eq!(back_link, std::path::Path::new("a.txt"));

    stop_sandbox(&tb, "cpbox");
}

#[test]
fn cp_missing_guest_src_errors() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("cpmiss");
    boot(&env, &mut tb, "cpmiss", &ws);

    let out = tb.root.path().join("cp-miss-out");
    fs::create_dir_all(&out).unwrap();
    let conn = sandbox::default_stream_connector()(&tb.paths, "cpmiss").expect("stream conn");
    let err = izba_core::cp::copy_from_guest(conn, "/no/such/path", &out)
        .expect_err("missing guest src must error");
    assert!(
        err.to_string().contains("no such file or directory"),
        "got: {err:#}"
    );

    stop_sandbox(&tb, "cpmiss");
}

#[test]
fn port_publish_create_time() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("port-create");

    // create with -p 18080:8000 (persisted), then boot.
    let digest = provision_image(&env, &tb.paths);
    sandbox::create(
        &tb.paths,
        "portc",
        &CreateOpts {
            image_digest: digest,
            image_ref: env.image_ref.clone(),
            cpus: 1,
            mem_mb: 1024,
            workspace: ws.to_path_buf(),
            rw_size_gb: 2,
            ports: vec![PortRule {
                bind: "127.0.0.1".parse().unwrap(),
                host_port: 18080,
                guest_port: 8000,
            }],
            volumes: Vec::new(),
            builder: false,
            docker: false,
            vnc: false,
        },
    )
    .expect("create");
    tb.names.push("portc".to_string());
    if let Err(e) = start_sandbox(&env, &tb, "portc") {
        panic!(
            "boot failed: {e:#}\nconsole:\n{}",
            boot_diag(&tb.paths, "portc")
        );
    }

    // `start` no longer auto-spawns the config rules — that responsibility
    // moved to the daemon's Start handler. Apply them here via a RelayManager
    // exactly as that handler does.
    let relays = RelayManager::new();
    let config: izba_core::state::SandboxConfig =
        load_json(&tb.paths.sandbox_dir("portc").join("config.json"))
            .expect("read config.json")
            .expect("config.json present");
    for rule in &config.ports {
        relays
            .publish(&tb.paths, "portc", rule.clone())
            .expect("publish config rule");
    }

    start_guest_httpd(&tb.paths, "portc", "hello-from-guest", 8000);
    let body = http_get(18080).expect("curl published port");
    assert_eq!(body, "hello-from-guest");

    relays.stop_all("portc");
    stop_sandbox(&tb, "portc");
}

#[test]
fn port_publish_runtime_and_unpublish() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("port-runtime");
    boot(&env, &mut tb, "portr", &ws);

    start_guest_httpd(&tb.paths, "portr", "runtime-body", 8000);

    let relays = RelayManager::new();
    relays
        .publish(
            &tb.paths,
            "portr",
            PortRule {
                bind: "127.0.0.1".parse().unwrap(),
                host_port: 18081,
                guest_port: 8000,
            },
        )
        .expect("runtime publish");

    let body = http_get(18081).expect("curl runtime-published port");
    assert_eq!(body, "runtime-body");

    // The manager reports exactly the one active rule.
    let listed = relays.active("portr");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].host_port, 18081);

    // unpublish (synchronous join) → the host port stops accepting.
    relays
        .unpublish("portr", "127.0.0.1".parse().unwrap(), 18081)
        .expect("unpublish");
    assert!(
        http_get(18081).is_err(),
        "port must be unreachable after unpublish"
    );
    assert!(relays.active("portr").is_empty(), "no rules should remain");

    stop_sandbox(&tb, "portr");
}

/// Confinement boot test: on a host that has the Landlock LSM, the sandbox
/// must boot with `ConfinementMode::Restricted` recorded in its `state.json`.
///
/// The negative (fail-closed) path is already covered by unit tests in
/// `crates/izba-core/src/procmgr/jail_linux.rs` — this test proves only the
/// positive "Landlock present → Restricted actually applied" path with a real
/// microVM boot.
#[test]
fn confined_boot_records_restricted_when_landlock_present() {
    let Some(env) = want() else { return };
    // This test asserts the VMM actually reaches Restricted, so the host must
    // meet the FULL confinement floor (seccomp AND Landlock AND a virtiofsd
    // sandbox). If any leg is missing, `start_sandbox` opts out to
    // `--allow-unconfined` (mode None) and the assertion below could not hold —
    // skip with a clear reason rather than fail. (`plan` Ok ⇔ full floor met.)
    let caps = izba_core::procmgr::jail_linux::Capabilities::probe();
    if izba_core::procmgr::jail_linux::plan(&caps, false, 0).is_err() {
        eprintln!(
            "SKIP: host cannot meet the confinement floor \
             (need seccomp + Landlock LSM + unprivileged userns/CAP_SYS_CHROOT; \
             enable CONFIG_SECURITY_LANDLOCK + lsm=...,landlock and userns)"
        );
        return;
    }
    let mut tb = TestBox::new();
    let ws = tb.workspace("confined");
    create_sandbox(&env, &mut tb, "confined", &ws);
    if let Err(e) = start_sandbox(&env, &tb, "confined") {
        panic!(
            "confined boot failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "confined")
        );
    }

    // The recorded confinement must be Restricted (the fail-closed default
    // reached it — Landlock is present so no degradation path applies).
    let state_path = tb.paths.sandbox_dir("confined").join(STATE_FILE);
    let st: RunState = load_json(&state_path)
        .expect("reading state.json")
        .expect("state.json present after start");
    let conf = st
        .confinement
        .expect("confinement must be recorded at launch");
    assert_eq!(
        conf.mode,
        izba_core::procmgr::ConfinementMode::Restricted,
        "expected Restricted, got {conf:?} (summary: {})",
        conf.summary()
    );
    assert!(
        conf.reason.contains("landlock"),
        "reason should name landlock: {}",
        conf.reason
    );

    stop_sandbox(&tb, "confined");
}

/// M2 git-egress exit: a sandbox with `enforce: true` +
/// `git: [{repo: "github.com/octocat/Hello-World", access: read}]` must
/// (a) allow `git clone` of that repo (exit 0, L7 ALLOW record) and
/// (b) deny a `git push` attempt (non-zero exit, L7 DENY record).
///
/// This exercises the full end-to-end git egress path through a booted
/// microVM: izba-init's nft REDIRECT → vsock 1027 → izbad MITM → Rego
/// git rules → audit log.
///
/// ## Assertion strategy
///
/// [`AuditRecord`] stores `path` but not the query string, so both the
/// clone leg (`GET /info/refs?service=git-upload-pack`) and the push leg
/// (`GET /info/refs?service=git-receive-pack`) produce `path = "/info/refs"`.
/// This means the audit assertions alone cannot tie a verdict to a specific
/// git operation — a swapped-logic regression (rego allows receive-pack but
/// denies upload-pack) would still produce one ALLOW + one DENY at `/info/refs`
/// and satisfy both audit checks.
///
/// The per-leg HTTP outcome IS distinguishable via the `?service=` URL, and
/// wget's exit code reflects it:
///   - clone leg (`git-upload-pack`) → MITM ALLOW → 200 → wget exits 0
///   - push leg  (`git-receive-pack`) → MITM DENY  → 403 → wget exits non-zero
///
/// Therefore the **primary** discriminators are the per-leg exit codes
/// (`clone_rc == 0`, `push_rc != 0`), which together catch swapped-logic,
/// deny-all, and allow-all regressions. The audit ALLOW+DENY presence at
/// `/info/refs` is kept as corroboration that the policy layer evaluated
/// both legs.
///
/// Network note: the test dials real github.com. If the host has no internet
/// (air-gapped CI), the test will fail in the exec step — not in the policy
/// check. The e2e.yml job runs on hosted runners with internet access.
#[test]
fn git_read_only_repo_allows_clone_denies_push() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("git-ro");
    // Write a per-sandbox policy: enforce=true, one git rule granting read-only
    // access to octocat/Hello-World. No host_rules → all non-git HTTPS is
    // denied; only git smart-HTTP to this repo is allowed (clone OK, push denied).
    let (mgr, _audit) = setup_mitm_sandbox(
        &env,
        &mut tb,
        "git-ro",
        &ws,
        "enforce: true\ngit:\n  - repo: github.com/octocat/Hello-World\n    access: read\n",
    );
    // Use busybox wget (always present in alpine) to exercise the git smart-HTTP
    // discovery endpoints via HTTPS. The MITM terminates TLS, reads the Host +
    // query string, and the Rego git rules decide:
    //
    //   clone leg: GET .../info/refs?service=git-upload-pack
    //     → git_kind = "read", rule.access = "read" → ALLOW → MITM proxies to
    //       github.com → 200 → wget exits 0
    //   push leg:  GET .../info/refs?service=git-receive-pack
    //     → git_kind = "write", rule.access = "read" (≠ "read-write") → DENY
    //       → MITM returns synthetic 403 → wget exits non-zero
    //
    // We need no git binary — the smart-HTTP wire protocol is just HTTP GET with
    // a query string, so wget covers both legs. busybox wget uses
    // SSL_CERT_FILE=/etc/izba/ca-bundle.pem (set by izba-init's configure_env_defaults
    // when the izba-trust virtiofs share is mounted) to trust the MITM's izba-CA-signed
    // certificate. The retry loop absorbs DNS + first egress settle time after boot.
    // We redirect stderr to /dev/null so wget's error output does not clutter
    // the exec_collect stdout; the exit codes are the primary signal.
    let script = "\
        for i in 1 2 3 4 5; do \
          rc=0; \
          wget -qO /dev/null -T 15 \
            'https://github.com/octocat/Hello-World/info/refs?service=git-upload-pack' \
            2>/dev/null || rc=$?; \
          if [ $rc -eq 0 ]; then break; fi; \
          sleep 3; \
        done; \
        echo clone-discovery-rc=$rc; \
        wget -qO /dev/null -T 15 \
          'https://github.com/octocat/Hello-World/info/refs?service=git-receive-pack' \
          2>/dev/null; echo push-discovery-rc=$?";
    let (_status, stdout, stderr) = exec_collect(&tb.paths, "git-ro", &["sh", "-lc", script], None)
        .unwrap_or_else(|(k, m)| panic!("exec rejected ({k:?}): {m}"));
    eprintln!("guest output:\n{stdout}\n{stderr}");

    // The MITM records synchronously, so by the time exec returns the records
    // are on disk. Read with a short retry to absorb any filesystem lag.
    let records = read_audit_with_retry(&tb.paths, "git-ro");
    let l7_git = |verdict: &str, path_suffix: &str| {
        records.iter().any(|r| {
            r.tier == izba_core::daemon::egress::audit::Tier::L7
                && r.host.as_deref() == Some("github.com")
                && r.port == 443
                && format!("{:?}", r.verdict).to_lowercase().contains(verdict)
                && r.path.as_deref().is_some_and(|p| p.ends_with(path_suffix))
        })
    };

    let dump = || {
        let lines: Vec<String> = records.iter().map(|r| r.to_json()).collect();
        format!(
            "audit records:\n{}\nguest stdout:\n{stdout}\nguest stderr:\n{stderr}\nconsole tail:\n{}",
            lines.join("\n"),
            console_tail(&tb.paths, "git-ro")
        )
    };

    // Primary discriminators: per-leg wget exit codes.
    //
    // AuditRecord carries `path` but not the query string, so both legs share
    // `path = "/info/refs"`.  The exit codes are the only assertions that tie
    // a specific git operation to its verdict and catch swapped-logic,
    // deny-all, and allow-all regressions.
    let clone_rc = stdout
        .lines()
        .find(|l| l.starts_with("clone-discovery-rc="))
        .and_then(|l| l.split('=').nth(1))
        .and_then(|v| v.trim().parse::<i32>().ok())
        .unwrap_or(1); // missing marker → treat as failure
    assert_eq!(
        clone_rc,
        0,
        "git clone discovery (upload-pack) must succeed (got {clone_rc} — \
         the MITM may have denied upload-pack or network is down).\n{}",
        dump()
    );

    let push_rc = stdout
        .lines()
        .find(|l| l.starts_with("push-discovery-rc="))
        .and_then(|l| l.split('=').nth(1))
        .and_then(|v| v.trim().parse::<i32>().ok())
        .unwrap_or(0); // missing marker → treat as success (should fail)
    assert_ne!(
        push_rc,
        0,
        "git push discovery (receive-pack) must return non-zero (got 0 — \
         the MITM 403 may not have reached wget or policy is too permissive).\n{}",
        dump()
    );

    // Corroboration: audit layer must have evaluated both legs and recorded
    // one ALLOW (clone) and one DENY (push) at /info/refs.  These cannot
    // distinguish which operation got which verdict on their own (no query
    // string in AuditRecord), but together with the exit codes above they
    // confirm the policy layer ran end-to-end.

    // Clone discovery (upload-pack): Rego git read → ALLOW.
    assert!(
        l7_git("allow", "/info/refs"),
        "expected an L7 ALLOW for github.com:443 git-upload-pack discovery \
         (clone permitted under read access).\n{}",
        dump()
    );

    // Push discovery (receive-pack): Rego git write denied for read-only rule.
    assert!(
        l7_git("deny", "/info/refs"),
        "expected an L7 DENY for github.com:443 git-receive-pack discovery \
         (push forbidden under read-only access).\n{}",
        dump()
    );

    stop_sandbox(&tb, "git-ro");
    mgr.stop("git-ro", &tb.paths.run_dir("git-ro"));
}

// ---------------------------------------------------------------------------
// Docker mode (#198): the Docker-in-Docker journey
// ---------------------------------------------------------------------------

/// The docker-mode fixture: Docker's own `dind` image, which ships a full
/// Docker Engine (dockerd + containerd + runc + iptables). Pinned by DIGEST —
/// resolved 2026-08-08 from the floating tag `docker:28-dind` — so a re-push of
/// that tag can never silently change what this test boots.
const DIND_IMAGE: &str =
    "docker@sha256:2a232a42256f70d78e3cc5d2b5d6b3276710a0de0596c145f627ecfae90282ac";

/// The image the NESTED engine pulls — pinned by DIGEST for the same reason as
/// [`DIND_IMAGE`] (resolved 2026-08-08 from the floating tag
/// `hello-world:latest`). The journey greps this container's stdout, so a
/// re-push of the tag would change both what the test runs AND whether it
/// passes, and the failure would read as a docker-mode product regression.
const HELLO_WORLD_IMAGE: &str =
    "hello-world@sha256:7f4da0fc94bcece205a8c0b6f4d11c8196924654ffe5c4d1aa439b7f632048b2";

/// Adversarial escape probe run AS CONTAINER ROOT inside a docker-mode sandbox.
/// It first UNDOES the read-only `/proc/sys` binds every way a workload holding
/// userns `CAP_SYS_ADMIN` (which docker mode grants, seccomp off) can — plain
/// `remount,rw`, the `remount,rw,bind` spelling, a fresh bind elsewhere, and a
/// brand-new `procfs` — then attempts to write `/proc/sys/kernel/core_pattern`
/// through each. `core_pattern` is the classic container→host-root escalation
/// primitive (a `|/path` value makes the kernel run that program as real root
/// on the next crash), so a landed write here would be guest-init-root code
/// execution — able to flush izba's nft egress rules.
///
/// The point of the probe is to prove the remounts SUCCEED (they do — the binds
/// are defeatable) yet the WRITE is still denied, because the durable barrier is
/// the container-0 ≠ guest-0 uid map, not the bind. `core_pattern`'s original
/// value is restored-by-identity (we only ever try to write the value already
/// there), and the escape payload is only attempted against the copies, so a
/// success would be observable without actually arming a real host `core_pattern`.
///
/// Machine-readable lines the assertions parse: `remount_rc`, `bindremount_rc`,
/// `write_after_remount_rc` (the load-bearing one — MUST be non-zero) with its
/// `write_after_remount_err`, plus `core_before`/`core_after` (MUST be equal)
/// and the `uid_map` that explains why (container-0 maps to a non-zero guest id).
const PROC_SYS_ESCAPE_PROBE: &str = r#"
CORE=/proc/sys/kernel/core_pattern
BEFORE=$(cat "$CORE" 2>/dev/null)
echo "core_before=$BEFORE"
mount -o remount,rw /proc/sys/kernel 2>&1; echo "remount_rc=$?"
mount -o remount,rw,bind /proc/sys/kernel 2>&1; echo "bindremount_rc=$?"
printf '%s' "$BEFORE" > "$CORE" 2>/tmp/e1; echo "write_after_remount_rc=$?"
echo "write_after_remount_err=$(cat /tmp/e1)"
mkdir -p /tmp/k && mount --bind /proc/sys/kernel /tmp/k 2>&1; echo "rebind_rc=$?"
printf '%s' "$BEFORE" > /tmp/k/core_pattern 2>/tmp/e2; echo "rebind_write_rc=$?"
echo "rebind_write_err=$(cat /tmp/e2)"
mkdir -p /tmp/p && mount -t proc proc /tmp/p 2>&1; echo "freshproc_rc=$?"
printf '%s' "$BEFORE" > /tmp/p/sys/kernel/core_pattern 2>/tmp/e3; echo "freshproc_write_rc=$?"
echo "freshproc_write_err=$(cat /tmp/e3)"
echo "core_after=$(cat "$CORE" 2>/dev/null)"
echo "euid=$(id -u)"
echo "uid_map=$(cat /proc/self/uid_map | tr '\n' ';')"
exit 0
"#;

/// Pull `key=<value>` out of the [`PROC_SYS_ESCAPE_PROBE`] output.
fn probe_field<'a>(out: &'a str, key: &str) -> Option<&'a str> {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .map(str::trim)
}

/// `create` a docker-mode sandbox on the dind fixture, sized for a real engine
/// (dockerd + containerd + a nested container are hungry compared to the 1
/// cpu / 1 GiB the alpine tests use). Registers the name for cleanup.
fn create_docker_sandbox(tb: &mut TestBox, name: &str, ws: &Path) {
    let digest = ensure_image(&tb.paths, DIND_IMAGE).expect("pulling the dind fixture image");
    sandbox::create(
        &tb.paths,
        name,
        &CreateOpts {
            image_digest: digest,
            image_ref: DIND_IMAGE.to_string(),
            cpus: 2,
            mem_mb: 2048,
            workspace: ws.to_path_buf(),
            rw_size_gb: 4,
            ports: Vec::new(),
            volumes: Vec::new(),
            builder: false,
            // The whole point: own netns + veth, userns-scoped admin caps,
            // rw cgroupfs, the auto /var/lib/docker volume, izba.docker=1.
            docker: true,
            vnc: false,
        },
    )
    .expect("create docker-mode sandbox");
    tb.names.push(name.to_string());
}

/// The whole guest serial console (not just [`console_tail`]'s last 2 KiB):
/// the docker-mode banners this test asserts on are printed during boot and
/// scroll far out of the tail once dockerd starts logging.
fn console_full(paths: &Paths, name: &str) -> String {
    let log = paths.logs_dir(name).join("console.log");
    fs::read_to_string(&log).unwrap_or_else(|e| format!("<unreadable {}: {e}>", log.display()))
}

/// Docker-mode failure diagnostics, per the Task 7 brief: the guest console
/// tail PLUS the in-container engine log — the two places a dockerd that never
/// came up leaves its reason.
fn docker_diag(paths: &Paths, name: &str) -> String {
    let mut out = format!("--- console tail ---\n{}", console_tail(paths, name));
    out.push_str("\n--- /var/log/izba-dockerd.log (in container) ---\n");
    match exec_collect(paths, name, &["cat", "/var/log/izba-dockerd.log"], None) {
        Ok((status, stdout, stderr)) => {
            out.push_str(&format!("(exit {status:?})\n{stdout}\n{stderr}"))
        }
        Err((kind, msg)) => out.push_str(&format!("<exec rejected ({kind:?}): {msg}>")),
    }
    out
}

/// Re-run `argv` in the guest until it exits 0 or `timeout` elapses, returning
/// the successful stdout (`None` on timeout, so the caller can dump
/// diagnostics). dockerd needs a generous ceiling: it starts containerd, sets
/// up its bridge + iptables, and probes storage before it answers `docker info`.
fn poll_exec_ok(paths: &Paths, name: &str, argv: &[&str], timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok((ExitStatus::Code(0), stdout, _)) = exec_collect(paths, name, argv, None) {
            return Some(stdout);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// The #198 docker-mode journey against a REAL microVM: engine auto-start,
/// the veth datapath, cgroup delegation, a nested container pulled through
/// izba's egress plane, and netlog honesty for that nested pull.
///
/// This is the honest gate for Tasks 4-6 — every piece below is something the
/// host-side unit tests structurally cannot observe (a real netns, a real
/// cgroup2 hierarchy, a real dockerd):
///
/// * **Task 4 (a)** `veth::apply`'s `create_dir_all("/var/run/netns")` +
///   `ip netns attach izba <pid>` round-trip actually succeeds as root in the
///   guest — proven by the absence of the loud failure banner AND by (b).
/// * **Task 4 (b)** the pair carries `.1` (init side) ↔ `.2` (container side)
///   with the default route back through `.1`.
/// * **Task 4 (c)** the nat-**prerouting** chain intercepts traffic that
///   originates in the workload's own netns (it never traverses init's
///   `output` hook) — proven by inner-container-pull records in the audit log.
/// * **Task 4 (d)** docker-mode resolv.conf points at `192.168.127.1` (the
///   veth gateway, NOT loopback) and names actually resolve through it.
/// * **Task 5 (a)** `cgroup.controllers` inside the container lists the
///   delegated controllers post-boot.
/// * **Task 5 (c)** `parse_cgroup_path` matched crun's REAL `0::<path>`
///   naming — proven by the absence of the "delegation skipped" banner.
/// * **Task 5 (d)** `start_engine` end-to-end: the engine log exists, dockerd
///   is really there, and a nested container runs.
#[test]
fn docker_mode_engine_runs_containers() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let name = "dind";
    let ws = tb.workspace(name);
    create_docker_sandbox(&mut tb, name, &ws);
    // Stand in for izbad's vsock-1027 listener: the nested image pull below
    // travels this plane, so it must be armed before the guest boots.
    let mgr = arm_egress_and_start(&env, &tb, name);

    // --- [1] The veth datapath (Task 4 a/b) ---------------------------------
    // The container is in its OWN netns; its only link to the world is the
    // pair veth::apply wired up after crun reported `running`.
    let (st, addrs, aerr) = exec_collect(
        &tb.paths,
        name,
        &["ip", "-o", "addr", "show", "veth1"],
        None,
    )
    .expect("exec ip addr show veth1");
    assert_eq!(
        st,
        ExitStatus::Code(0),
        "the container netns must hold the veth1 end: {aerr}\n--- console ---\n{}",
        console_full(&tb.paths, name)
    );
    assert!(
        addrs.contains("192.168.127.2/24"),
        "container side of the veth must carry GUEST_IP, got: {addrs:?}\n{}",
        console_full(&tb.paths, name)
    );
    let routes = exec_ok(&tb.paths, name, &["ip", "route"]);
    assert!(
        routes.contains("default via 192.168.127.1"),
        "container's default route must go via the init-side veth address, got: {routes:?}"
    );
    // The loud failure banners must be absent: their presence would mean the
    // netns attach or the cgroup delegation silently degraded this boot.
    let console = console_full(&tb.paths, name);
    assert!(
        !console.contains("DOCKER-MODE VETH SETUP FAILED")
            && !console.contains("DOCKER-MODE VETH SETUP SKIPPED"),
        "veth setup reported failure on the console:\n{console}"
    );
    assert!(
        !console.contains("cgroup delegation skipped")
            && !console.contains("cgroup delegation incomplete"),
        "cgroup delegation reported a problem on the console:\n{console}"
    );

    // --- [2] Docker-mode DNS (Task 4 d) -------------------------------------
    // resolv.conf points at the veth gateway (loopback would be wrong here:
    // the container's own netns has no DNS stub on 127.0.0.1).
    let resolv = exec_ok(&tb.paths, name, &["cat", "/etc/resolv.conf"]);
    assert!(
        resolv.contains("192.168.127.1"),
        "docker-mode resolv.conf must name the veth gateway, got: {resolv:?}"
    );
    let resolved = exec_ok(
        &tb.paths,
        name,
        &["sh", "-lc", "getent hosts registry-1.docker.io"],
    );
    assert!(
        resolved.contains("registry-1.docker.io"),
        "a name must resolve through the veth-gateway resolver, got: {resolved:?}"
    );

    // --- [3] The auto /var/lib/docker volume --------------------------------
    // The engine's graph root must sit on the dedicated virtio-blk volume, not
    // on the overlay upper (overlay2-on-overlayfs does not work).
    let mounts = exec_ok(
        &tb.paths,
        name,
        &["sh", "-lc", "grep ' /var/lib/docker ' /proc/mounts"],
    );
    assert!(
        mounts.contains("/dev/vd"),
        "/var/lib/docker must be a virtio-blk volume mount, got: {mounts:?}"
    );

    // --- [4] Cgroup delegation (Task 5 a) -----------------------------------
    // The container's own cgroup can only create controller-bearing children
    // if init wrote `+<controller>` into every ancestor's subtree_control.
    let controllers = exec_ok(
        &tb.paths,
        name,
        &["cat", "/sys/fs/cgroup/cgroup.controllers"],
    );
    for want in ["cpu", "memory", "pids", "io"] {
        assert!(
            controllers.split_whitespace().any(|c| c == want),
            "delegated controllers must include {want}, got: {controllers:?}"
        );
    }

    // --- [5] Engine auto-start (Task 5 d) -----------------------------------
    let version = poll_exec_ok(
        &tb.paths,
        name,
        &["docker", "info", "--format", "{{.ServerVersion}}"],
        Duration::from_secs(120),
    )
    .unwrap_or_else(|| {
        panic!(
            "dockerd never answered `docker info` within 120s\n{}",
            docker_diag(&tb.paths, name)
        )
    });
    assert!(
        !version.trim().is_empty(),
        "docker info reported an empty server version"
    );
    let driver = exec_ok(
        &tb.paths,
        name,
        &["docker", "info", "--format", "{{.Driver}}"],
    );
    assert_eq!(
        driver.trim(),
        "overlay2",
        "engine must run overlay2 on the dedicated volume (a non-overlay2 \
         driver means /var/lib/docker landed on the overlay upper)"
    );
    // The engine log is the honest record; "ships no dockerd" is what
    // start_engine writes when the image has no engine at all.
    let engine_log = exec_ok(&tb.paths, name, &["cat", "/var/log/izba-dockerd.log"]);
    assert!(
        !engine_log.contains("ships no dockerd"),
        "the dind image must ship dockerd; engine log said: {engine_log:?}"
    );

    // --- [5a] Stats: Request::Stats round-trip, guest-reported and sane -----
    // The engine is known up (phase [5] just confirmed `docker info`), so
    // this is the honest real-VM proof that izba-init's stats collector sees
    // a live process tree, real meminfo, the overlay statfs, AND detects the
    // running dockerd by comm scan (Task 2/3).
    let connector = sandbox::default_connector();
    let mut stats_conn = connector(&tb.paths, name).expect("stats control connection");
    write_frame(&mut stats_conn, &Request::Stats).expect("sending stats request");
    match read_frame::<_, Response>(&mut stats_conn).expect("stats reply") {
        Response::Stats(g) => {
            assert!(
                g.process_count >= 3,
                "at least init+crun+dockerd: {}",
                g.process_count
            );
            assert!(
                g.mem_total_kb > 100_000,
                "meminfo parsed: {}",
                g.mem_total_kb
            );
            assert!(!g.mounts.is_empty(), "overlay statfs reported");
            let e = g
                .docker
                .expect("docker engine status present in docker mode");
            assert!(e.running, "dockerd detected by comm scan: {:?}", e.detail);
            assert!(g.container.is_some());
        }
        other => panic!("expected Stats, got {other:?}"),
    }

    // --- [5b] The /proc/sys narrowing (defense-in-depth) is real ------------
    // Docker mode unlocks the `net` sysctl subtree (dockerd needs
    // net.ipv4.ip_forward) and read-only-remounts every OTHER child. These
    // binds are defense-in-depth, NOT the durable barrier — phase [5c] proves a
    // CAP_SYS_ADMIN workload can remove them — but they still narrow the attack
    // surface, so pin that they are actually installed.
    //
    // Enumerating the REAL /proc/sys is the point: the host-side list in
    // runtime_config.rs could miss a subtree this kernel registers, and that
    // subtree would then lack even the defense-in-depth bind. crun bind-remounts
    // every readonlyPath, so a protected child has its own /proc/mounts line and
    // an unprotected one does not. Any output at all is a failure, and it names
    // the offender (this is what caught /proc/sys/sunrpc, CONFIG_SUNRPC).
    let unprotected = exec_ok(
        &tb.paths,
        name,
        &[
            "sh",
            "-c",
            "for d in /proc/sys/*; do [ -d \"$d\" ] || continue; \
             [ \"$d\" = /proc/sys/net ] && continue; \
             grep -q \" $d \" /proc/mounts || echo \"$d\"; done",
        ],
    );
    assert!(
        unprotected.trim().is_empty(),
        "every non-net /proc/sys subtree must be remounted read-only; \
         these are NOT: {unprotected:?}\n{}",
        docker_diag(&tb.paths, name)
    );
    // The subtree dockerd needs really is writable — proven by the value dockerd
    // itself wrote during the startup that phase [5] just confirmed.
    let forwarding = exec_ok(&tb.paths, name, &["cat", "/proc/sys/net/ipv4/ip_forward"]);
    assert_eq!(
        forwarding.trim(),
        "1",
        "dockerd must have been able to set net.ipv4.ip_forward"
    );

    // --- [5c] ADVERSARIAL: the DURABLE barrier holds under CAP_SYS_ADMIN ----
    // Run as container root, remove the read-only /proc/sys/kernel bind (which a
    // CAP_SYS_ADMIN workload CAN do — the bind is not MNT_LOCKED), then try to
    // write kernel.core_pattern (the classic container→host-root escalation).
    // The remount is ALLOWED; the WRITE must be DENIED — not by the bind, but by
    // the rootless container-0 ≠ guest-0 uid invariant: the sysctl's plain
    // `test_perm` euid check denies a non-guest-0 writer, and `CAP_DAC_OVERRIDE`
    // cannot bypass it because the file's guest-0 owner is unmapped
    // (`capable_wrt_inode_uidgid`). This is the property PART 1 enforces at start.
    let probe = exec_ok(&tb.paths, name, &["sh", "-c", PROC_SYS_ESCAPE_PROBE]);
    eprintln!("---- [5c] escape probe ----\n{probe}\n---- end probe ----");
    // The remount MUST succeed (rc 0): the whole point is that the read-only
    // bind is defeatable and the WRITE is nonetheless denied by the uid map. A
    // silently-failed remount (non-zero rc, bind still in place) would deny the
    // write for the WRONG reason — the defense-in-depth layer, not the durable
    // barrier — and mask a uid-invariant regression behind a green test.
    let remount_rc = probe_field(&probe, "remount_rc")
        .unwrap_or_else(|| panic!("probe missing remount_rc:\n{probe}"));
    assert_eq!(
        remount_rc, "0",
        "probe premise broken: the CAP_SYS_ADMIN remount of /proc/sys/kernel did \
         NOT succeed, so a denied write proves nothing about the uid barrier. \
         Probe:\n{probe}"
    );
    let write_rc = probe_field(&probe, "write_after_remount_rc")
        .unwrap_or_else(|| panic!("probe missing write_after_remount_rc:\n{probe}"));
    assert_ne!(
        write_rc, "0",
        "SECURITY: kernel.core_pattern write LANDED after remount — the durable \
         container-0 ≠ guest-0 barrier failed. Probe:\n{probe}"
    );
    let core_before = probe_field(&probe, "core_before").unwrap_or("");
    let core_after = probe_field(&probe, "core_after").unwrap_or("");
    assert_eq!(
        core_before, core_after,
        "SECURITY: kernel.core_pattern CHANGED — a container→guest-root escape \
         landed. Probe:\n{probe}"
    );
    // And the same for every alternative vector the probe tried.
    for rc in ["rebind_write_rc", "freshproc_write_rc"] {
        assert_ne!(
            probe_field(&probe, rc),
            Some("0"),
            "SECURITY: {rc} write LANDED — an alternative escape vector worked. \
             Probe:\n{probe}"
        );
    }
    // Sanity on WHY it held: the uid map must isolate container-root.
    let uid_map = probe_field(&probe, "uid_map").unwrap_or("");
    assert!(
        !uid_map.is_empty() && uid_map.starts_with('0'),
        "expected a container-root uid_map line, got: {uid_map:?}"
    );

    // --- [5d] The common flow still WORKS: a user-owned /workspace is writable
    // by the container root (the transposition maps the host workspace owner to
    // container-0), so the rootless invariant does not break the product.
    let ws_probe = exec_ok(
        &tb.paths,
        name,
        &[
            "sh",
            "-c",
            "touch /workspace/izba-docker-probe && echo ok && rm -f /workspace/izba-docker-probe",
        ],
    );
    assert!(
        ws_probe.contains("ok"),
        "container root must be able to write the user-owned /workspace, got: {ws_probe:?}"
    );

    // --- [5e] uid FIDELITY through the idmapped layers ----------------------
    // The shifted userns map (container-0 → guest-BASE) composed with the
    // layer idmap (disk-0 → guest-BASE) must present image files with their
    // ORIGINAL image uids inside the container. Under the old transpose,
    // /etc/passwd (image uid 0) presented as uid 1000 here — the exact
    // scrambling that broke sudo/settings in the claude-code-docker template.
    let fid = exec_ok(&tb.paths, name, &["stat", "-c", "%u:%g", "/etc/passwd"]);
    assert_eq!(
        fid.trim(),
        "0:0",
        "image-root files must present as container-root (idmap fidelity)"
    );
    // The auto /var/lib/docker volume rides the same idmap: its freshly
    // formatted ext4 root (disk-uid 0) must be container-root-owned — that is
    // what lets dockerd own its graph root with no chown pass.
    let vld = exec_ok(&tb.paths, name, &["stat", "-c", "%u:%g", "/var/lib/docker"]);
    assert_eq!(
        vld.trim(),
        "0:0",
        "the /var/lib/docker volume root must present as container-root"
    );
    // init's own writes through the idmapped rootfs (the setfsuid guard) must
    // land as container-root-owned too, not on the fsuid-0 anchor (`nobody`).
    let resolv_owner = exec_ok(
        &tb.paths,
        name,
        &["stat", "-c", "%u:%g", "/etc/resolv.conf"],
    );
    assert_eq!(
        resolv_owner.trim(),
        "0:0",
        "init-written files (resolv.conf) must present as container-root"
    );

    // --- [6] A nested container, pulled through izba's egress plane ---------
    // Proves: inner pull over the veth + prerouting REDIRECT, nested runc
    // under the delegated cgroups, and that the userns-scoped admin caps are
    // enough (no --privileged).
    let (status, stdout, stderr) = exec_collect(
        &tb.paths,
        name,
        &["docker", "run", "--rm", HELLO_WORLD_IMAGE],
        None,
    )
    .expect("exec docker run");
    assert_eq!(
        status,
        ExitStatus::Code(0),
        "nested `docker run` failed: stdout {stdout:?} stderr {stderr:?}\n{}",
        docker_diag(&tb.paths, name)
    );
    assert!(
        stdout.contains("Hello from Docker!"),
        "expected the hello-world greeting from the nested container, got: {stdout:?}"
    );

    // --- [7] Netlog honesty (Task 4 c) --------------------------------------
    // The inner pull is POLICY-VISIBLE: it reached the registry through
    // izbad, so izba's audit log names the registry host. This is the
    // structural payoff of moving interception to the prerouting hook — the
    // workload's own netns cannot route anywhere else.
    let records = read_audit_with_retry(&tb.paths, name);
    let hosts: Vec<String> = records.iter().filter_map(|r| r.host.clone()).collect();
    assert!(
        hosts.iter().any(|h| h.ends_with("docker.io")),
        "expected an audit record for the nested pull's registry host \
         (registry-1.docker.io / auth.docker.io); saw hosts: {hosts:?}"
    );

    stop_sandbox(&tb, name);
    mgr.stop(name, &tb.paths.run_dir(name));
}

/// A NON-ROOT-`USER` image, pinned by digest (resolved 2026-08-09 from
/// `nginxinc/nginx-unprivileged:alpine`; `USER 101`, chowns /var/cache/nginx
/// to 101). The uid-shape of `docker/sandbox-templates:claude-code-docker`
/// (`USER agent`=1000 on a uid-1000 workspace) in a CI-sized image.
const NON_ROOT_USER_IMAGE: &str = "nginxinc/nginx-unprivileged@sha256:a6c3ec0c0d249d68b0682df854d4a9e222b90fb607dc3fcf2f1d2fcbc85d347e";

/// REGRESSION GATE for the claude-code-docker breakage (uid-fidelity design):
/// a docker-mode sandbox from a non-root-`USER` image must (a) START — the
/// old transpose map degenerated to identity for owner==USER and the F-32
/// gate then failed the boot closed — and (b) present FAITHFUL ownership:
/// image-root files as container-root (the old Windows scramble showed them
/// as the USER's uid, breaking sudo and $HOME), image-USER files as the USER,
/// and /workspace owned + writable by the USER.
#[test]
fn docker_mode_non_root_user_image_boots_with_faithful_ownership() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let name = "nonroot-docker";
    let ws = tb.workspace(name);
    let digest =
        ensure_image(&tb.paths, NON_ROOT_USER_IMAGE).expect("pulling the non-root fixture image");
    sandbox::create(
        &tb.paths,
        name,
        &CreateOpts {
            image_digest: digest,
            image_ref: NON_ROOT_USER_IMAGE.to_string(),
            cpus: 1,
            mem_mb: 1024,
            workspace: ws.to_path_buf(),
            rw_size_gb: 4,
            ports: Vec::new(),
            volumes: Vec::new(),
            builder: false,
            docker: true,
            vnc: false,
        },
    )
    .expect("create non-root docker-mode sandbox");
    tb.names.push(name.to_string());
    // (a) The boot itself is the first assertion: the pre-fix code refused
    // this shape at generate_spec time ("use a non-root-owned workspace").
    let mgr = arm_egress_and_start(&env, &tb, name);

    // Default exec runs as the image USER (ExecRequest uid==gid==0 ⇒ crun
    // applies the configured USER) — the identity the claude template's shell
    // lands on.
    let uid = exec_ok(&tb.paths, name, &["id", "-u"]);
    assert_eq!(uid.trim(), "101", "exec must run as the image USER");

    // (b) Ownership fidelity, all three directions of the old scramble:
    // image-root files present as container-root…
    let passwd = exec_ok(&tb.paths, name, &["stat", "-c", "%u:%g", "/etc/passwd"]);
    assert_eq!(
        passwd.trim(),
        "0:0",
        "image-root files must present as container-root, not the USER's uid"
    );
    // …image-USER-owned files keep the USER's uid (the claude analogue was
    // /home/agent presenting as root, EACCES on its own settings)…
    let cache = exec_ok(&tb.paths, name, &["stat", "-c", "%u", "/var/cache/nginx"]);
    assert_eq!(
        cache.trim(),
        "101",
        "image files chowned to the USER must present as the USER"
    );
    // …and init-written files land as container-root (the setfsuid guard),
    // readable by the USER.
    let resolv = exec_ok(
        &tb.paths,
        name,
        &["stat", "-c", "%u:%g", "/etc/resolv.conf"],
    );
    assert_eq!(
        resolv.trim(),
        "0:0",
        "resolv.conf must be container-root-owned"
    );
    let trust = exec_ok(
        &tb.paths,
        name,
        &["stat", "-c", "%u:%g", "/etc/izba/ca.pem"],
    );
    assert_eq!(
        trust.trim(),
        "0:0",
        "trust anchor must be container-root-owned"
    );

    // The workspace carve-out: the USER owns and can write /workspace.
    let ws_owner = exec_ok(&tb.paths, name, &["stat", "-c", "%u", "/workspace"]);
    assert_eq!(
        ws_owner.trim(),
        "101",
        "the image USER must own the virtiofs /workspace"
    );
    let ws_probe = exec_ok(
        &tb.paths,
        name,
        &[
            "sh",
            "-c",
            "touch /workspace/izba-nonroot-probe && echo ok && rm -f /workspace/izba-nonroot-probe",
        ],
    );
    assert!(
        ws_probe.contains("ok"),
        "the image USER must be able to write /workspace, got: {ws_probe:?}"
    );

    stop_sandbox(&tb, name);
    mgr.stop(name, &tb.paths.run_dir(name));
}
