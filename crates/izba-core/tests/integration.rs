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

use izba_core::image::ensure_image;
use izba_core::liveness::Liveness;
use izba_core::paths::Paths;
use izba_core::procmgr;
use izba_core::sandbox::{self, Artifacts, CreateOpts};
use izba_core::state::{load_json, RunState, STATE_FILE};
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
    for bin in ["cloud-hypervisor", "virtiofsd", "passt", "mkfs.erofs"] {
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
/// to boot.
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
            console_tail(&tb.paths, name)
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
            console_tail(&tb.paths, "bench")
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
            console_tail(&tb.paths, "rw")
        );
    }
    let stdout = exec_ok(&tb.paths, "rw", &["cat", "/marker"]);
    assert_eq!(stdout, "keep\n", "/marker must survive a restart");
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
            panic!("boot with blank rw.img failed unexpectedly: {e:#}\nconsole tail:\n{console}");
        }
    }
}

#[test]
fn guest_networking() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("net");
    boot(&env, &mut tb, "net", &ws);

    // busybox wget (alpine) or curl (debian/ubuntu images), with in-guest
    // retries — DHCP/DNS through passt can take a few seconds to settle.
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

    // The crash simulation orphaned the sidecars (virtiofsd, passt usually
    // exit on their own when the vhost-user peer dies, but don't rely on it).
    for (_, id) in &state.sidecar_pids {
        let _ = procmgr::kill_pid(id);
    }
}
