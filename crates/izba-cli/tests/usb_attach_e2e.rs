//! The USB datapath against a real microVM, a real `vhci-hcd`, and a real
//! usbip server.
//!
//! Everything below the surface is unit-tested against byte-level fakes. This
//! suite exists for the one claim those cannot make: that a granted device
//! actually reaches the agent. The central assertion is therefore behavioural
//! rather than a log scrape — bytes written inside the sandbox come back — and
//! it can only pass if URBs really travelled guest `vhci` → vsock 1028 → izbad
//! → TCP → the server, and all the way back.
//!
//! Gated on `IZBA_INTEGRATION=1` plus the two artifacts this needs beyond the
//! usual set: `IZBA_KERNEL_USB` (the USB-capable kernel) and `IZBA_FAKE_USBIPD`
//! (the server from `hack/fake-usbipd`, an excluded crate — `usbip` links
//! libusb and must never enter a workspace gate).
//!
//! ```text
//! IZBA_INTEGRATION=1 IZBA_KERNEL=... IZBA_KERNEL_USB=... IZBA_INITRAMFS=... \
//! IZBA_FAKE_USBIPD=hack/fake-usbipd/target/release/fake-usbipd \
//! cargo test -p izba-cli --test usb_attach_e2e -- --test-threads=1 --nocapture
//! ```
//!
//! One case, `a_granted_device_attaches_on_the_kernel_an_installed_build_resolves`,
//! runs with every one of those overrides REMOVED and needs the artifacts staged
//! where an installer puts them, next to the binary:
//!
//! ```text
//! mkdir -p target/artifacts
//! cp dist/vmlinux dist/vmlinux-usb dist/initramfs.cpio.gz target/artifacts/
//! ```

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// The device the fake server exports, and the only one any test grants.
const DEVICE: &str = "0403:6001";
/// A device the fake server does NOT export — used to prove a grant izba
/// cannot satisfy fails honestly rather than attaching something else.
const OTHER_DEVICE: &str = "1a86:7523";
const IMAGE: &str = "alpine:3.20";

struct Env {
    fake: PathBuf,
}

/// Skip unless everything this suite needs is present, naming what is missing.
/// A USB e2e that quietly passes because it never ran is worse than no test.
fn want() -> Option<Env> {
    if std::env::var("IZBA_INTEGRATION").ok().as_deref() != Some("1") {
        eprintln!("SKIP: set IZBA_INTEGRATION=1 to run the USB e2e");
        return None;
    }
    let mut missing = Vec::new();
    for var in ["IZBA_KERNEL", "IZBA_KERNEL_USB", "IZBA_INITRAMFS"] {
        match std::env::var(var) {
            Ok(v) if Path::new(&v).is_file() => {}
            _ => missing.push(format!("{var} must point at an existing file")),
        }
    }
    let fake = match std::env::var("IZBA_FAKE_USBIPD") {
        Ok(v) if Path::new(&v).is_file() => PathBuf::from(v),
        _ => {
            missing.push(
                "IZBA_FAKE_USBIPD must point at the built hack/fake-usbipd binary \
                 (cargo build --release --manifest-path hack/fake-usbipd/Cargo.toml)"
                    .into(),
            );
            PathBuf::new()
        }
    };
    if !missing.is_empty() {
        panic!(
            "IZBA_INTEGRATION=1 but the USB e2e cannot run:\n  {}",
            missing.join("\n  ")
        );
    }
    Some(Env { fake })
}

/// A running fake usbip server, killed when the test drops it.
struct FakeUsbipd {
    child: Child,
    addr: String,
}

impl FakeUsbipd {
    fn start(env: &Env) -> Self {
        let mut child = Command::new(&env.fake)
            .arg("127.0.0.1:0")
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn fake-usbipd");
        // It prints the address it bound before serving; an ephemeral port
        // keeps parallel runs (and a real usbipd on 3240) out of the way.
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("stdout"))
            .read_line(&mut line)
            .expect("fake-usbipd must announce its address");
        Self {
            child,
            addr: line.trim().to_string(),
        }
    }
}

impl Drop for FakeUsbipd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Where a run gets its boot artifacts from.
#[derive(Clone, Copy)]
enum Artifacts {
    /// Whatever the environment says — in CI, the `IZBA_KERNEL*` overrides.
    Injected,
    /// The way an installed build finds them: no overrides at all, so the
    /// kernel can only come from `<exe-dir>/../artifacts`.
    Installed,
}

/// Every environment variable that hands izba a boot artifact directly.
const ARTIFACT_OVERRIDES: [&str; 3] = ["IZBA_KERNEL", "IZBA_KERNEL_USB", "IZBA_INITRAMFS"];

/// The directory an installed build keeps its boot artifacts in, relative to
/// the binary under test: `<exe-dir>/../artifacts` (`/usr/lib/izba/artifacts`
/// for the .deb, `{app}\artifacts` for the Windows installer, and
/// `target/artifacts` here).
fn installed_artifacts_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_izba"))
        .parent()
        .and_then(Path::parent)
        .expect("the izba binary has a grandparent dir")
        .join("artifacts")
}

fn izba_as<S: AsRef<std::ffi::OsStr>>(how: Artifacts, data: &Path, args: &[S]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_izba"));
    cmd.env("IZBA_DATA_DIR", data).args(args);
    if matches!(how, Artifacts::Installed) {
        for var in ARTIFACT_OVERRIDES {
            cmd.env_remove(var);
        }
    }
    cmd.output().expect("run izba")
}

fn izba<S: AsRef<std::ffi::OsStr>>(data: &Path, args: &[S]) -> Output {
    izba_as(Artifacts::Injected, data, args)
}

fn out(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ok(o: &Output, what: &str) {
    assert!(o.status.success(), "{what} failed:\n{}", out(o));
}

/// Create a sandbox, grant it the device, and start it. Returns its name.
///
/// Order matters and is the product's, not the test's: the grant must exist
/// BEFORE the start, because that is what selects the USB kernel.
fn granted_sandbox(data: &Path, fake: &FakeUsbipd, name: &str) -> String {
    ok(
        &izba(data, &["usb", "upstream", "set", &fake.addr]),
        "usb upstream set",
    );
    ok(&izba(data, &create_args(data, name)), "create");
    ok(
        &izba(
            data,
            &[
                "usb",
                "allow",
                name,
                "--device",
                DEVICE,
                "--confirm",
                DEVICE,
            ],
        ),
        "usb allow",
    );
    ok(&izba(data, &["start", name]), "start");
    name.to_string()
}

/// `izba create` for a sandbox whose workspace lives under the test's own temp
/// dir.
///
/// The positional argument is the WORKSPACE DIRECTORY, not the name — passing a
/// bare name creates a directory of that name in the process's cwd, which for
/// `cargo test` is the crate root. That litters the source tree with sandbox
/// workspaces, so the name is given explicitly and the workspace is placed where
/// the rest of the test's state already lives.
fn create_args(data: &Path, name: &str) -> Vec<String> {
    let ws = data.join("ws").join(name);
    std::fs::create_dir_all(&ws).expect("workspace dir");
    vec![
        "create".into(),
        ws.to_string_lossy().into_owned(),
        "--name".into(),
        name.into(),
        "--image".into(),
        IMAGE.into(),
    ]
}

/// Run a shell command inside the sandbox's workload container.
fn exec(data: &Path, name: &str, script: &str) -> Output {
    izba(data, &["exec", name, "--", "sh", "-c", script])
}

/// Poll until `script` succeeds inside the sandbox, or give up.
fn exec_until_ok(data: &Path, name: &str, script: &str, what: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let o = exec(data, name, script);
        if o.status.success() {
            return String::from_utf8_lossy(&o.stdout).into_owned();
        }
        if Instant::now() >= deadline {
            panic!("{what} never succeeded; last attempt:\n{}", out(&o));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The runtime dirs of every sandbox in this data root.
///
/// Returns a non-empty vec or panics: an assertion looping over an empty list
/// passes without checking anything, which is the failure mode a socket-absence
/// test is most likely to have.
fn run_dirs(data: &Path) -> Vec<PathBuf> {
    let dirs: Vec<PathBuf> = std::fs::read_dir(data.join("run"))
        .expect("run dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    assert!(
        !dirs.is_empty(),
        "expected at least one runtime dir under {}",
        data.join("run").display()
    );
    dirs
}

fn teardown(data: &Path, name: &str) {
    let _ = izba(data, &["rm", "-f", name]);
}

#[test]
fn a_granted_device_reaches_the_workload_and_carries_bytes_both_ways() {
    let Some(env) = want() else { return };
    let fake = FakeUsbipd::start(&env);
    let data = tempfile::tempdir().unwrap();
    let name = granted_sandbox(data.path(), &fake, "usbecho");

    let attach = izba(data.path(), &["usb", "attach", &name, "--device", DEVICE]);
    ok(&attach, "usb attach");

    // The node must appear inside the CONTAINER, not merely in the guest: that
    // is the whole point of the /dev/izba bind and the device-cgroup rules.
    let listing = exec_until_ok(
        data.path(),
        &name,
        "ls /dev/izba/",
        "the device node appearing inside the container",
    );
    assert!(
        listing.contains("ttyACM"),
        "expected a ttyACM node in /dev/izba, got: {listing}"
    );

    // The behavioural assertion. Raw mode first: a tty in its default canonical
    // mode does not deliver input until a line ends, so a byte-count read would
    // block forever on data that had in fact arrived — and raw is what a real
    // serial tool (esptool, picocom) sets anyway. `head -c` then blocks until
    // the bytes come back, so a reply that never arrives fails as a timeout
    // rather than passing on an empty read.
    let echoed = exec(
        data.path(),
        &name,
        "stty -F /dev/izba/ttyACM0 raw -echo; exec 3<>/dev/izba/ttyACM0; \
         printf hello >&3; timeout 10 head -c5 <&3",
    );
    ok(&echoed, "serial echo");
    assert_eq!(
        String::from_utf8_lossy(&echoed.stdout).trim(),
        "hello",
        "the bytes written must come back: {}",
        out(&echoed)
    );

    teardown(data.path(), &name);
}

#[test]
fn a_granted_device_attaches_on_the_kernel_an_installed_build_resolves() {
    // #191. Every other case here is handed its kernel through IZBA_KERNEL_USB
    // — precisely the path an installed user never takes, and the reason a
    // build that shipped no USB kernel at all (#189) passed a fully green
    // board. This case takes the overrides away: the data root is a fresh
    // tempdir with no `artifacts/`, so the ONLY place left to find a kernel is
    // next to the binary, where an installer puts it.
    //
    // EVERY izba invocation below goes through `Artifacts::Installed`. izbad is
    // spawned by the first one and inherits its environment; one stray call
    // with the overrides intact could hand the daemon a kernel and this would
    // prove nothing.
    let Some(env) = want() else { return };
    let staged = installed_artifacts_dir();
    for f in ["vmlinux-usb", "initramfs.cpio.gz"] {
        assert!(
            staged.join(f).is_file(),
            "IZBA_INTEGRATION=1 but {} is not staged — this case boots from the \
             installed layout, never from an override. Stage it with:\n  \
             mkdir -p {dir} && cp dist/vmlinux dist/vmlinux-usb dist/initramfs.cpio.gz {dir}/",
            staged.join(f).display(),
            dir = staged.display(),
        );
    }
    let fake = FakeUsbipd::start(&env);
    let data = tempfile::tempdir().unwrap();
    let how = Artifacts::Installed;
    let name = "usbinstalled";

    ok(
        &izba_as(how, data.path(), &["usb", "upstream", "set", &fake.addr]),
        "usb upstream set",
    );
    assert!(
        !data.path().join("artifacts").exists(),
        "the data root must hold no artifacts, or the lookup could be satisfied there"
    );
    ok(
        &izba_as(how, data.path(), &create_args(data.path(), name)),
        "create",
    );
    ok(
        &izba_as(
            how,
            data.path(),
            &[
                "usb",
                "allow",
                name,
                "--device",
                DEVICE,
                "--confirm",
                DEVICE,
            ],
        ),
        "usb allow",
    );
    ok(
        &izba_as(how, data.path(), &["start", name]),
        "start on the installed-layout USB kernel",
    );
    ok(
        &izba_as(
            how,
            data.path(),
            &["usb", "attach", name, "--device", DEVICE],
        ),
        "usb attach",
    );

    // Behavioural, like the central case: the node exists in the container and
    // bytes come back, which only a kernel with vhci-hcd + cdc-acm can do.
    let echoed = {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let o = izba_as(
                how,
                data.path(),
                &[
                    "exec",
                    name,
                    "--",
                    "sh",
                    "-c",
                    "stty -F /dev/izba/ttyACM0 raw -echo && exec 3<>/dev/izba/ttyACM0 && \
                     printf hello >&3 && timeout 10 head -c5 <&3",
                ],
            );
            if o.status.success() || Instant::now() >= deadline {
                break o;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    ok(&echoed, "serial echo on the installed-layout kernel");
    assert_eq!(
        String::from_utf8_lossy(&echoed.stdout).trim(),
        "hello",
        "the bytes written must come back: {}",
        out(&echoed)
    );

    let _ = izba_as(how, data.path(), &["rm", "-f", name]);
}

#[test]
fn a_device_that_was_never_granted_cannot_be_attached() {
    let Some(env) = want() else { return };
    let fake = FakeUsbipd::start(&env);
    let data = tempfile::tempdir().unwrap();
    let name = granted_sandbox(data.path(), &fake, "usbnogrant");

    let attach = izba(
        data.path(),
        &["usb", "attach", &name, "--device", OTHER_DEVICE],
    );
    assert!(
        !attach.status.success(),
        "an ungranted device must not attach:\n{}",
        out(&attach)
    );
    assert!(out(&attach).contains("not granted"), "{}", out(&attach));

    // And nothing appeared for it.
    let listing = exec(data.path(), &name, "ls /dev/izba/ 2>&1 || true");
    assert!(
        !String::from_utf8_lossy(&listing.stdout).contains("tty"),
        "no device may appear for a refused attach: {}",
        out(&listing)
    );

    teardown(data.path(), &name);
}

#[test]
fn a_sandbox_without_grants_has_no_usb_plane_and_no_usb_kernel() {
    // The structural claim behind "disabled USB adds no attack surface",
    // checked on a running sandbox rather than argued: no socket to dial, and
    // no vhci to attach to even if something did.
    let Some(_env) = want() else { return };
    let data = tempfile::tempdir().unwrap();
    ok(
        &izba(data.path(), &create_args(data.path(), "plain")),
        "create",
    );
    ok(&izba(data.path(), &["start", "plain"]), "start");

    let run_dirs = run_dirs(data.path());
    for dir in &run_dirs {
        assert!(
            !dir.join("vsock.sock_1028").exists(),
            "a sandbox without grants must have no USB listener: {}",
            dir.display()
        );
        assert!(
            dir.join("vsock.sock_1027").exists(),
            "...while the egress plane is still there: {}",
            dir.display()
        );
    }

    // Defence in depth behind the grant check: no virtual host controller.
    let sysfs = exec(
        data.path(),
        "plain",
        "ls /sys/devices/platform/ 2>&1 || true",
    );
    assert!(
        !String::from_utf8_lossy(&sysfs.stdout).contains("vhci"),
        "the default kernel must have no vhci: {}",
        out(&sysfs)
    );
    // And no device directory was bound into the container.
    let dev = exec(data.path(), "plain", "ls -d /dev/izba 2>&1 || true");
    assert!(
        !dev.status.success() || String::from_utf8_lossy(&dev.stdout).contains("No such"),
        "no grants must mean no /dev/izba: {}",
        out(&dev)
    );

    teardown(data.path(), "plain");
}

#[test]
fn detaching_removes_the_device_and_it_can_be_attached_again() {
    let Some(env) = want() else { return };
    let fake = FakeUsbipd::start(&env);
    let data = tempfile::tempdir().unwrap();
    let name = granted_sandbox(data.path(), &fake, "usbcycle");

    ok(
        &izba(data.path(), &["usb", "attach", &name, "--device", DEVICE]),
        "first attach",
    );
    exec_until_ok(
        data.path(),
        &name,
        "ls /dev/izba/ttyACM0",
        "the node appearing",
    );

    ok(
        &izba(data.path(), &["usb", "detach", &name, "--device", DEVICE]),
        "detach",
    );
    let gone = exec(data.path(), &name, "ls /dev/izba/ttyACM0");
    assert!(
        !gone.status.success(),
        "the node must be gone after detach: {}",
        out(&gone)
    );

    // The vhci port went back to the pool, so the same device attaches again.
    ok(
        &izba(data.path(), &["usb", "attach", &name, "--device", DEVICE]),
        "re-attach",
    );
    exec_until_ok(
        data.path(),
        &name,
        "ls /dev/izba/ttyACM0",
        "the node reappearing",
    );

    teardown(data.path(), &name);
}

#[test]
fn revoking_a_grant_closes_the_plane_on_a_running_sandbox() {
    // A revoke must take effect on the next attempt, not the next restart —
    // the reason the broker's lifecycle call is `refresh` rather than
    // `ensure_listening`.
    let Some(env) = want() else { return };
    let fake = FakeUsbipd::start(&env);
    let data = tempfile::tempdir().unwrap();
    let name = granted_sandbox(data.path(), &fake, "usbrevoke");

    ok(
        &izba(data.path(), &["usb", "revoke", &name, "--device", DEVICE]),
        "revoke",
    );
    let run_dirs = run_dirs(data.path());
    for dir in &run_dirs {
        assert!(
            !dir.join("vsock.sock_1028").exists(),
            "revoking the last grant must close the plane: {}",
            dir.display()
        );
    }
    let attach = izba(data.path(), &["usb", "attach", &name, "--device", DEVICE]);
    assert!(
        !attach.status.success() && out(&attach).contains("not granted"),
        "a revoked device must not attach: {}",
        out(&attach)
    );

    teardown(data.path(), &name);
}

#[test]
fn revoking_while_attached_releases_the_device_rather_than_stranding_it() {
    // Withdrawing consent has to reach the hardware, not just the record. A
    // revoke that left the device bound to the guest's vhci would keep it
    // unavailable to the host indefinitely — and, when detach was gated on the
    // grant, would tell the user to re-grant the device in order to release it.
    let Some(env) = want() else { return };
    let fake = FakeUsbipd::start(&env);
    let data = tempfile::tempdir().unwrap();
    let name = granted_sandbox(data.path(), &fake, "usbstrand");

    ok(
        &izba(data.path(), &["usb", "attach", &name, "--device", DEVICE]),
        "attach",
    );
    exec_until_ok(
        data.path(),
        &name,
        "ls /dev/izba/ttyACM0",
        "the node appearing",
    );

    ok(
        &izba(data.path(), &["usb", "revoke", &name, "--device", DEVICE]),
        "revoke",
    );
    // The device is gone from the workload, without anyone having to detach it.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if !exec(data.path(), &name, "ls /dev/izba/ttyACM0")
            .status
            .success()
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "revoke must release an attached device, not strand it"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    teardown(data.path(), &name);
}

#[test]
fn an_attach_is_visible_in_netlog() {
    // A device the sandbox reached is exactly what `izba netlog` is for.
    let Some(env) = want() else { return };
    let fake = FakeUsbipd::start(&env);
    let data = tempfile::tempdir().unwrap();
    let name = granted_sandbox(data.path(), &fake, "usbnetlog");
    ok(
        &izba(data.path(), &["usb", "attach", &name, "--device", DEVICE]),
        "attach",
    );

    let log = izba(data.path(), &["netlog", &name]);
    ok(&log, "netlog");
    let text = out(&log);
    assert!(text.contains("usb"), "the tier must be visible: {text}");
    assert!(text.contains(DEVICE), "name the device: {text}");

    teardown(data.path(), &name);
}
