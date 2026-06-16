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
        },
    )
    .expect("create");
    tb.names.push(name.to_string());
}

fn start_sandbox(env: &TestEnv, tb: &TestBox, name: &str) -> anyhow::Result<()> {
    sandbox::start_with_timeouts(
        &tb.paths,
        name,
        &CloudHypervisorDriver,
        &Artifacts {
            kernel: env.kernel.clone(),
            initramfs: env.initramfs.clone(),
        },
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
    for log in ["vmm.log", "passt.log", "virtiofsd-workspace.log"] {
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
    let connector = sandbox::default_connector();
    let mut control = sandbox::control(paths, name, &connector).expect("control connection");

    let req = Request::Exec(ExecRequest {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env: vec![("PATH".to_string(), STD_PATH.to_string())],
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

    let err = exec_collect(&tb.paths, "exit", &["/nonexistent"], None)
        .expect_err("exec of /nonexistent must be rejected");
    assert_eq!(
        err.0,
        ErrorKind::CommandNotFound,
        "expected CommandNotFound, got {err:?}"
    );
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
        },
        izba_core::volume::VolumeSpec {
            name: Some("data".into()),
            guest_path: "/data".into(),
            size_bytes: 64 << 20,
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
    use izba_core::daemon::egress::{dns::UdpForwarder, policy::AllowAll, EgressManager};
    let mgr = EgressManager::new(
        std::sync::Arc::new(AllowAll),
        std::sync::Arc::new(UdpForwarder::new("127.0.0.1:53".parse().unwrap())),
        None,
        izba_core::daemon::egress::audit::AuditSink::new(tb.paths.clone()),
    );
    mgr.ensure_listening(&tb.paths, "net")
        .expect("bind vsock_1027 listener");

    if let Err(e) = start_sandbox(&env, &tb, "net") {
        mgr.stop(&tb.paths, "net");
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
    mgr.stop(&tb.paths, "net");
}

/// M1 phase A exit: an egress=izbad sandbox resolves DNS through izbad.
/// This is ALSO the runtime validation of guest-initiated hybrid vsock
/// (guest dials CID 2:1027 -> CH bridges to run/vsock.sock_1027).
#[test]
fn egress_dns_via_izbad() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("egress-dns");
    create_sandbox(&env, &mut tb, "egress-dns", &ws);

    // Daemonless suite: stand in for izbad's listener ourselves. The listener
    // must exist on run/vsock.sock_1027 BEFORE the guest boots and dials it.
    use izba_core::daemon::egress::{dns::UdpForwarder, policy::AllowAll, EgressManager};
    let mgr = EgressManager::new(
        std::sync::Arc::new(AllowAll),
        std::sync::Arc::new(UdpForwarder::new("127.0.0.1:53".parse().unwrap())),
        None,
        izba_core::daemon::egress::audit::AuditSink::new(tb.paths.clone()),
    );
    mgr.ensure_listening(&tb.paths, "egress-dns")
        .expect("bind vsock_1027 listener");

    if let Err(e) = start_sandbox(&env, &tb, "egress-dns") {
        mgr.stop(&tb.paths, "egress-dns");
        panic!(
            "boot of 'egress-dns' failed: {e:#}\nconsole tail:\n{}",
            console_tail(&tb.paths, "egress-dns")
        );
    }

    // getent uses the guest resolv.conf (nameserver 127.0.0.1 -> the izba-init
    // DNS stub on 0.0.0.0:53 -> vsock Dns stream -> izbad UdpForwarder -> host
    // upstream). The reply rides loopback; a non-loopback resolver address
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
    mgr.stop(&tb.paths, "egress-dns");
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
    use izba_core::daemon::egress::{dns::UdpForwarder, policy::AllowAll, EgressManager};
    let mgr = EgressManager::new(
        std::sync::Arc::new(AllowAll),
        std::sync::Arc::new(UdpForwarder::new("127.0.0.1:53".parse().unwrap())),
        None,
        izba_core::daemon::egress::audit::AuditSink::new(tb.paths.clone()),
    );
    mgr.ensure_listening(&tb.paths, "egress-http")
        .expect("bind vsock_1027 listener");

    if let Err(e) = start_sandbox(&env, &tb, "egress-http") {
        mgr.stop(&tb.paths, "egress-http");
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
    mgr.stop(&tb.paths, "egress-http");
}

/// M2 exit: the agent firewall MITMs guest HTTP(S) under a declared policy. A
/// sandbox with `--policy` allowing `example.com` gets the izba CA baked in, and
/// the MITM is exercised over BOTH tier-1 transports:
///   * HTTPS (:443) — the guest's TLS handshake to an allowed host completes
///     ONLY because it trusts the baked per-SNI leaf; the MITM decrypts the Host
///     and records an L7 ALLOW (non-allowed host → L7 DENY via a synthesized
///     403).
///   * Plaintext HTTP (:80) — apt's default. The cleartext request line is NOT
///     a TLS ClientHello, so this exercises the `mitm_terminate_http` path
///     (sniff → read head → policy) that shipped broken when every tier-1 flow
///     was force-handshaked as TLS.
///
/// The host-side audit log is the robust, image-agnostic proof: an `l7` record
/// on :443 appears only if the guest trusted the baked CA AND the MITM read the
/// decrypted Host; an `l7` record on :80 appears only if the cleartext MITM read
/// the Host without a TLS handshake. Guest exit codes are secondary (busybox
/// TLS quirks vary by image).
#[test]
fn mitm_firewall_allows_and_denies_real_vm() {
    use izba_core::daemon::egress::audit::AuditSink;
    use izba_core::daemon::egress::config::EgressPolicyConfig;
    use izba_core::daemon::egress::mitm::{upstream_client_config_webpki, CertCache};
    use izba_core::daemon::egress::mitm_runtime::MitmRuntime;
    use izba_core::daemon::egress::{dns::UdpForwarder, policy::AllowAll, EgressManager};

    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("mitm");
    create_sandbox(&env, &mut tb, "mitm", &ws);

    // Declare the per-sandbox egress policy (allow example.com only). Persisting
    // it makes `resolve_policy` arm an enforcing RegoPolicy at listen time, so
    // tier-1 HTTPS is routed through the MITM.
    std::fs::write(
        EgressPolicyConfig::path_in(&tb.paths.sandbox_dir("mitm")),
        "allow:\n  - example.com\n",
    )
    .expect("write policy.yaml");

    // Build the shared MITM runtime from the SAME persistent CA that
    // sandbox::start bakes into the guest (both read tb.paths.ca_dir()).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = izba_core::ca::load_or_create(&tb.paths.ca_dir()).expect("izba CA");
    let certs = std::sync::Arc::new(CertCache::new(ca));
    let audit = AuditSink::new(tb.paths.clone());
    let mitm = std::sync::Arc::new(
        MitmRuntime::start(certs, upstream_client_config_webpki(), audit.clone())
            .expect("start MITM runtime"),
    );

    let mgr = EgressManager::new(
        std::sync::Arc::new(AllowAll),
        std::sync::Arc::new(UdpForwarder::new("127.0.0.1:53".parse().unwrap())),
        Some(mitm),
        audit,
    );
    mgr.ensure_listening(&tb.paths, "mitm")
        .expect("bind vsock_1027 listener");

    if let Err(e) = start_sandbox(&env, &tb, "mitm") {
        mgr.stop(&tb.paths, "mitm");
        panic!(
            "boot of 'mitm' failed: {e:#}\nconsole tail:\n{}",
            console_tail(&tb.paths, "mitm")
        );
    }

    // Two datapaths, both routed through the MITM for an enforcing sandbox:
    //
    //   * HTTPS on :443 — a clean TLS handshake to the allowed host (validation
    //     ON, no --no-check-certificate) proves the guest trusts the baked CA;
    //     the denied host's handshake also completes so the MITM can read the
    //     Host and answer 403.
    //   * Plaintext HTTP on :80 — apt's default (archive.ubuntu.com). This path
    //     shipped BROKEN: the MITM force-handshaked TLS on every tier-1 flow, so
    //     cleartext failed before any Host was parsed and NOTHING was audited.
    //     The :80 records below are the regression guard — they appear only if
    //     `mitm_terminate_http` read the cleartext request head and ran policy.
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
        curl -fsS http://www.iana.org/ >/dev/null 2>&1; echo denied-http-curl-rc=$?";
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
    // Plaintext HTTP (:80) — the apt-over-http path that shipped broken. These
    // records exist only if the cleartext MITM (`mitm_terminate_http`) read the
    // Host and ran policy instead of force-handshaking TLS on the request line.
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

    stop_sandbox(&tb, "mitm");
    mgr.stop(&tb.paths, "mitm");
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
    use izba_core::daemon::egress::{dns::UdpForwarder, policy::AllowAll, EgressManager};
    let mgr = EgressManager::new(
        std::sync::Arc::new(AllowAll),
        std::sync::Arc::new(UdpForwarder::new("127.0.0.1:53".parse().unwrap())),
        None,
        izba_core::daemon::egress::audit::AuditSink::new(tb.paths.clone()),
    );
    mgr.ensure_listening(&tb.paths, "egress-tput").unwrap();
    if let Err(e) = start_sandbox(&env, &tb, "egress-tput") {
        mgr.stop(&tb.paths, "egress-tput");
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
    mgr.stop(&tb.paths, "egress-tput");
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
