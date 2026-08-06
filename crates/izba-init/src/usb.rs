//! Guest-side USB attach: hand `vhci-hcd` a socket that izbad is holding open
//! to a real device.
//!
//! The guest never speaks USB/IP. It dials the USB plane (vsock 1028), names
//! the device it was told to attach, and receives back the two numbers the
//! kernel needs — `devid` and `speed` — plus a connection that is, from that
//! moment on, a raw URB stream. Writing `"<port> <fd> <devid> <speed>"` to
//! `vhci_hcd`'s `attach` file transfers ownership of that socket to the kernel:
//! `vhci` accepts any `SOCK_STREAM` fd, with no address-family check, which is
//! why a vsock connection works here with no loopback-TCP shim and no VMM
//! change on either driver.
//!
//! Whether this guest may do any of it is decided by the **host**, via
//! `izba.usb=1` on the kernel cmdline. Without it every verb here refuses:
//! nothing inside the guest can talk itself into USB support.

use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use izba_proto::{read_frame, write_frame, ErrorKind, Response, StreamOpen};

/// The virtual host controller's sysfs directory. Fixed: `vhci_hcd` is a
/// platform driver with a single instance, built into izba's USB kernel.
pub const VHCI_DIR: &str = "/sys/devices/platform/vhci_hcd.0";

/// Where attached device nodes are mirrored for the workload. Lives in
/// init-root `/run` — OUTSIDE the `/rootfs` overlay, mirroring how the ssh
/// material is kept out of the OCI image — and is bind-mounted into the
/// container at `/dev/izba`.
pub const SHARED_DEV_DIR: &str = "/run/izba/usb";

/// `USB_SPEED_SUPER` in the kernel's `usb_device_speed` enum. SuperSpeed
/// devices must land on a `ss` vhci port; everything else on an `hs` one.
const USB_SPEED_SUPER: u32 = 5;

/// `VDEV_ST_NULL` — the status a free vhci port reports.
const VDEV_ST_NULL: &str = "004";

/// How long to wait for the kernel to enumerate the device and create its node
/// after a successful attach. Enumeration is several control transfers over the
/// vsock link, so it is not instant; past this the attach is reported as having
/// produced no usable device rather than silently succeeding.
const NODE_TIMEOUT: Duration = Duration::from_secs(5);

/// How often to re-check `/dev` while waiting for enumeration.
const NODE_POLL: Duration = Duration::from_millis(100);

type InitError = (ErrorKind, String);

/// The kernel-facing operations an attach performs after izbad has replied.
///
/// A trait because the ordering around them is the delicate part — the socket
/// is surrendered to the kernel at one exact moment, and a later failure has to
/// undo the attach — and that ordering deserves a test rather than a comment.
/// The real implementation writes sysfs; tests substitute a recorder.
pub trait Vhci {
    /// A free port for a device of this speed, or an error explaining why not.
    fn free_port(&self, speed: u32) -> Result<u32, InitError>;
    /// Hand `fd` to the kernel on `port`. After this returns `Ok` the kernel
    /// owns the socket.
    fn attach(&self, port: u32, fd: RawFd, devid: u32, speed: u32) -> Result<(), InitError>;
    /// Release `port`.
    fn detach(&self, port: u32) -> Result<(), InitError>;
    /// Close a descriptor the kernel is finished with.
    fn close_fd(&self, fd: RawFd);
    /// Snapshot the device names currently present.
    fn devices(&self) -> BTreeSet<String>;
    /// Expose the newly-appeared node `name` to the workload, returning where
    /// it put it.
    fn expose(&self, name: &str) -> Result<PathBuf, InitError>;
    /// Withdraw a previously exposed node.
    fn unexpose(&self, node: &Path);
}

/// The real thing: sysfs writes plus a devtmpfs mirror.
pub struct SysfsVhci;

/// One device this guest currently holds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Attached {
    port: u32,
    node: PathBuf,
    /// The socket the kernel took ownership of. `vhci` shuts the connection
    /// down on detach, but nothing closes the descriptor — so init keeps the
    /// number in order to close it itself. Without this every attach/detach
    /// cycle leaks one fd in PID 1, and enough cycles exhaust the table for
    /// every other plane too (exec, cp, relays, ssh).
    fd: RawFd,
}

/// The guest's USB state: whether it may attach at all, and what it holds.
pub struct UsbState {
    enabled: bool,
    attached: Mutex<HashMap<String, Attached>>,
    /// Serializes whole attach and detach operations.
    ///
    /// A per-device claim is NOT enough, because the resources an attach
    /// consumes are global: the vhci port pool, and the `/dev` snapshot the new
    /// node is identified by. Two attaches of *different* devices, overlapping,
    /// can pick the same free port and can each attribute the other's node to
    /// itself — leaving a detach that removes the wrong node, or an attachment
    /// with no map entry that only the VM's death releases.
    ///
    /// Held across I/O, which is normally worth avoiding. It is right here:
    /// attach is a human-driven action taking a second or two, this lock guards
    /// only USB operations (exec, cp, relays and ssh are untouched), and the
    /// alternative is a corrupt port table.
    op: Mutex<()>,
    /// How long to wait for enumeration. A field rather than a constant so a
    /// test for the "never becomes a serial port" path does not have to spend
    /// the real timeout on every CI run.
    node_timeout: Duration,
}

impl UsbState {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            attached: Mutex::new(HashMap::new()),
            op: Mutex::new(()),
            node_timeout: NODE_TIMEOUT,
        }
    }

    /// Attach `device` over the real vsock plane and the real vhci.
    pub fn attach_with<S, D>(&self, device: &str, dial: D) -> Result<(), InitError>
    where
        S: Read + Write + AsRawFd,
        D: FnOnce() -> std::io::Result<S>,
    {
        self.attach_on(device, dial, &SysfsVhci)
    }

    /// Attach `device`, dialing through `dial` and driving `vhci`.
    ///
    /// Both are seams so the whole sequence is host-testable: the dialer stands
    /// in for the vsock (the pattern `egress.rs` uses), and `vhci` for a kernel
    /// that is not there.
    ///
    /// The ordering is the substance of this function:
    ///
    /// 1. The host's gate, then the duplicate check — before anything is dialed.
    /// 2. One frame out, one frame back. izbad's refusal is passed through.
    /// 3. `/dev` is snapshotted BEFORE the attach, so the node diff afterwards
    ///    sees only what this attach produced.
    /// 4. The socket is surrendered to the kernel — and only then leaked, so a
    ///    failed attach closes it instead of stranding a connection to izbad
    ///    for the life of the guest.
    /// 5. If the device never becomes usable, the attach is rolled back: a port
    ///    holding a device nothing can open still keeps that device away from
    ///    the host.
    pub fn attach_on<S, D, V>(&self, device: &str, dial: D, vhci: &V) -> Result<(), InitError>
    where
        S: Read + Write + AsRawFd,
        D: FnOnce() -> std::io::Result<S>,
        V: Vhci + ?Sized,
    {
        self.gate()?;
        // Everything below shares the vhci port pool and the /dev snapshot, so
        // it runs as one operation.
        let _op = self.op.lock().unwrap_or_else(|e| e.into_inner());
        if self.attached.lock().unwrap().contains_key(device) {
            return Err((
                ErrorKind::BadRequest,
                format!("{device} is already attached"),
            ));
        }

        let mut conn = dial().map_err(|e| {
            (
                ErrorKind::ConnectFailed,
                format!("dialing the USB plane: {e}"),
            )
        })?;
        write_frame(
            &mut conn,
            &StreamOpen::UsbAttach {
                device: device.to_string(),
            },
        )
        .map_err(|e| (ErrorKind::Internal, format!("sending the attach: {e}")))?;

        let (devid, speed) = match read_frame::<_, Response>(&mut conn) {
            Ok(Response::UsbAttached { devid, speed }) => (devid, speed),
            // izbad's refusal is the useful one — it knows about grants,
            // upstreams and hardware. Pass it through rather than restating it.
            Ok(Response::Error { kind, message }) => return Err((kind, message)),
            Ok(other) => {
                return Err((
                    ErrorKind::Internal,
                    format!("unexpected reply on the USB plane: {other:?}"),
                ))
            }
            Err(e) => return Err((ErrorKind::Internal, format!("reading the reply: {e}"))),
        };

        let before = vhci.devices();
        let port = vhci.free_port(speed)?;
        let fd = conn.as_raw_fd();
        vhci.attach(port, fd, devid, speed)?;
        // The kernel owns this socket now. Leak the handle deliberately:
        // dropping `conn` would close the socket out from under `vhci` and kill
        // the device the line above just created. Only after a successful
        // attach — on any earlier failure `conn` is dropped normally, so a
        // refused attach never strands a connection to izbad for the life of
        // the guest. The raw number is kept so `detach` can close it.
        std::mem::forget(conn);

        let node = match self.wait_for_node(&before, vhci) {
            Ok(node) => node,
            Err(e) => {
                let _ = vhci.detach(port);
                vhci.close_fd(fd);
                return Err(e);
            }
        };
        self.attached
            .lock()
            .unwrap()
            .insert(device.to_string(), Attached { port, node, fd });
        Ok(())
    }

    /// Detach a device this guest holds, returning its vhci port to the pool.
    pub fn detach(&self, device: &str) -> Result<(), InitError> {
        self.detach_on(device, &SysfsVhci)
    }

    pub fn detach_on<V: Vhci + ?Sized>(&self, device: &str, vhci: &V) -> Result<(), InitError> {
        self.gate()?;
        // Same operation lock as attach: detach frees a vhci port and removes a
        // node, both of which an in-flight attach is reading.
        let _op = self.op.lock().unwrap_or_else(|e| e.into_inner());
        let Some(a) = self.attached.lock().unwrap().remove(device) else {
            return Err((
                ErrorKind::BadRequest,
                format!("{device} is not attached to this sandbox"),
            ));
        };
        // The node goes first: once the port is released its major/minor may be
        // reused, and a stale node would then point at someone else's device.
        vhci.unexpose(&a.node);
        let released = vhci.detach(a.port);
        // vhci shuts the connection down, but the descriptor is still ours.
        // Closed even when the detach failed: the alternative is leaking it
        // with nothing left holding a record of it.
        vhci.close_fd(a.fd);
        released
    }

    /// The host's decision, enforced before anything else happens.
    fn gate(&self) -> Result<(), InitError> {
        if self.enabled {
            return Ok(());
        }
        Err((
            ErrorKind::UsbUnavailable,
            "this guest did not boot with USB support (izba.usb=1); \
             grant a device and restart the sandbox"
                .into(),
        ))
    }

    /// Wait for the kernel to enumerate the device, then expose its node.
    ///
    /// The kernel picks the minor, so izba must not guess a name: the new node
    /// is found by diffing `/dev`. Enumeration is several control transfers over
    /// the vsock link, so it is not instant — but a device that never produces a
    /// serial node is a failure, not a slow success.
    fn wait_for_node<V: Vhci + ?Sized>(
        &self,
        before: &BTreeSet<String>,
        vhci: &V,
    ) -> Result<PathBuf, InitError> {
        let deadline = Instant::now() + self.node_timeout;
        loop {
            if let Some(name) = new_serial_nodes(before, &vhci.devices()).first() {
                return vhci.expose(name);
            }
            if Instant::now() >= deadline {
                return Err((
                    ErrorKind::Internal,
                    "the device attached but no serial node appeared — izba supports \
                     serial-class devices only (CDC-ACM and the common USB bridges)"
                        .into(),
                ));
            }
            std::thread::sleep(NODE_POLL.min(self.node_timeout));
        }
    }
}

impl Vhci for SysfsVhci {
    // reason: one sysfs read feeding the unit-tested `parse_free_port`.
    #[mutants::skip]
    fn free_port(&self, speed: u32) -> Result<u32, InitError> {
        let status = std::fs::read_to_string(Path::new(VHCI_DIR).join("status")).map_err(|e| {
            (
                ErrorKind::Internal,
                format!("reading {VHCI_DIR}/status: {e} — is this a USB-capable kernel?"),
            )
        })?;
        parse_free_port(&status, speed).ok_or((
            ErrorKind::Internal,
            "no free vhci port — detach a device first".into(),
        ))
    }

    // reason: a one-line sysfs write; its content comes from the unit-tested
    // `attach_line`.
    #[mutants::skip]
    fn attach(&self, port: u32, fd: RawFd, devid: u32, speed: u32) -> Result<(), InitError> {
        write_sysfs(
            &Path::new(VHCI_DIR).join("attach"),
            &attach_line(port, fd, devid, speed),
        )
        .map_err(|e| {
            (
                ErrorKind::Internal,
                format!("handing the socket to vhci: {e}"),
            )
        })
    }

    // reason: a one-line sysfs write.
    #[mutants::skip]
    fn detach(&self, port: u32) -> Result<(), InitError> {
        write_sysfs(&Path::new(VHCI_DIR).join("detach"), &port.to_string())
            .map_err(|e| (ErrorKind::Internal, format!("detaching port {port}: {e}")))
    }

    // reason: a single close(2).
    #[mutants::skip]
    fn close_fd(&self, fd: RawFd) {
        // Safety: `fd` came from a socket this module leaked with
        // `mem::forget` after the kernel took it over, and is closed exactly
        // once — the `Attached` entry holding it is removed under the lock
        // before this runs, so no other path can reach the same number.
        unsafe {
            libc::close(fd);
        }
    }

    // reason: reads the guest's devtmpfs; the diff it feeds is unit-tested.
    #[mutants::skip]
    fn devices(&self) -> BTreeSet<String> {
        std::fs::read_dir("/dev")
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    // reason: needs a real device node and CAP_MKNOD.
    #[mutants::skip]
    fn expose(&self, name: &str) -> Result<PathBuf, InitError> {
        let src = Path::new("/dev").join(name);
        let dst = Path::new(SHARED_DEV_DIR).join(name);
        mirror(&src, &dst).map(|()| dst).map_err(|e| {
            (
                ErrorKind::Internal,
                format!("exposing {name} to the workload: {e}"),
            )
        })
    }

    #[mutants::skip]
    fn unexpose(&self, node: &Path) {
        let _ = std::fs::remove_file(node);
    }
}

/// Dial izbad's USB plane (host CID 2, port 1028).
///
/// The production dialer for [`UsbState::attach_with`], separated so tests can
/// substitute a `UnixStream` pair — the same seam `egress.rs` uses.
// reason: one vsock connect; the handshake it feeds is fully unit-tested
// through the dialer seam, and a vsock connect cannot run on a host runner.
#[mutants::skip]
pub fn dial_host() -> std::io::Result<vsock::VsockStream> {
    vsock::VsockStream::connect_with_cid_port(libc::VMADDR_CID_HOST, izba_proto::USB_PORT)
}

/// Read the vhci status file and pick a free port for this speed.

// reason: a one-line sysfs write; the value written is built by the unit-tested
// `attach_line`.
#[mutants::skip]
fn write_sysfs(path: &Path, value: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.write_all(value.as_bytes())
}

/// Re-create `src`'s device node at `dst`, world-readable and world-writable.
///
/// Mode 0666 rather than an ownership dance: the workload runs in its own user
/// namespace, so a uid-based grant would depend on the mapping, and the node
/// would be unusable by any image whose USER is not root. What actually gates
/// reachability is the bind mount (the node exists nowhere else the container
/// can see) and the cgroup device filter (only the serial majors may be opened
/// at all).
///
/// The mode is set explicitly AFTER `mknod`, because mknod's mode argument is
/// masked by the process umask — inherited as 022 here, which would silently
/// produce 0644 and lock out exactly the non-root workloads this is for.
// reason: needs a real device node and CAP_MKNOD.
#[mutants::skip]
fn mirror(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(src)?;
    if !meta.file_type().is_char_device() {
        return Err(std::io::Error::other(format!(
            "{} is not a character device",
            src.display()
        )));
    }
    let _ = std::fs::remove_file(dst);
    nix::sys::stat::mknod(
        dst,
        nix::sys::stat::SFlag::S_IFCHR,
        nix::sys::stat::Mode::from_bits_truncate(0o666),
        meta.rdev(),
    )
    .map_err(std::io::Error::from)?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o666))
}

/// Find a free vhci port for a device of this speed.
///
/// The status file has one header line and then one line per port:
/// `hub port sta spd dev sockfd local_busid`, where `sta == VDEV_ST_NULL` means
/// free. The hub column matters rather than being decoration: `vhci` keeps
/// separate USB2 (`hs`) and USB3 (`ss`) port ranges and refuses a mismatched
/// attach, so the speed selects the hub as well as travelling on the attach
/// line.
pub fn parse_free_port(status: &str, speed: u32) -> Option<u32> {
    let want_hub = if speed == USB_SPEED_SUPER { "ss" } else { "hs" };
    status.lines().find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || f[0] != want_hub || f[2] != VDEV_ST_NULL {
            return None;
        }
        f[1].parse::<u32>().ok()
    })
}

/// The exact line `vhci_hcd`'s `attach` file expects.
pub fn attach_line(port: u32, fd: i32, devid: u32, speed: u32) -> String {
    format!("{port} {fd} {devid} {speed}")
}

/// Which serial device nodes appeared between two snapshots of `/dev`.
///
/// Filtering to the serial families is izba's v1 scope (design D5) expressed
/// where it can be seen: a device that enumerated as something else is not
/// handed to the workload merely because it showed up. The container's cgroup
/// device filter enforces the same rule independently.
pub fn new_serial_nodes(before: &BTreeSet<String>, after: &BTreeSet<String>) -> Vec<String> {
    after
        .difference(before)
        .filter(|n| n.starts_with("ttyACM") || n.starts_with("ttyUSB"))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    const STATUS: &str = "\
hub port sta spd dev      sockfd local_busid
hs  0000 006 003 00030002 000005 3-2
hs  0001 004 000 00000000 000000 0-0
ss  0008 004 000 00000000 000000 0-0
";

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_high_speed_device_takes_a_free_hs_port_skipping_the_busy_one() {
        assert_eq!(parse_free_port(STATUS, 3), Some(1));
    }

    #[test]
    fn a_super_speed_device_needs_an_ss_port() {
        // vhci refuses a SuperSpeed device on a USB2 port, which would surface
        // as an unexplained EINVAL from the attach write.
        assert_eq!(parse_free_port(STATUS, 5), Some(8));
    }

    #[test]
    fn no_free_port_of_the_right_kind_is_none_not_a_guess() {
        let only_hs = "\
hub port sta spd dev      sockfd local_busid
hs  0001 004 000 00000000 000000 0-0
";
        assert_eq!(parse_free_port(only_hs, 5), None, "no ss port exists");
        assert_eq!(parse_free_port(only_hs, 3), Some(1));

        let all_busy = "\
hub port sta spd dev      sockfd local_busid
hs  0000 006 003 00030002 000005 3-2
";
        assert_eq!(parse_free_port(all_busy, 3), None);
    }

    #[test]
    fn a_header_only_or_garbled_status_yields_no_port() {
        for s in [
            "",
            "hub port sta spd dev sockfd local_busid\n",
            "nonsense\n",
            "hs\n",
            "hs  xxxx 004 000\n",
        ] {
            assert_eq!(parse_free_port(s, 3), None, "{s:?}");
        }
    }

    #[test]
    fn the_shared_directory_matches_the_path_the_host_binds_into_the_container() {
        // izba-core binds this exact path to /dev/izba in the OCI spec
        // (image/runtime_config.rs::USB_SHARED_DIR). The two crates cannot share
        // a constant — izba-core does not depend on izba-init — so each pins the
        // literal. Asserting it on only one side leaves the other free to drift,
        // which would silently bind an empty directory and the device would
        // simply never appear.
        assert_eq!(SHARED_DEV_DIR, "/run/izba/usb");
    }

    #[test]
    fn the_attach_line_is_the_four_fields_the_kernel_expects() {
        assert_eq!(attach_line(1, 7, 196_610, 3), "1 7 196610 3");
    }

    #[test]
    fn only_newly_appeared_serial_nodes_are_reported() {
        // The kernel picks the minor, so the node is identified by diffing
        // /dev rather than by predicting a name.
        assert_eq!(
            new_serial_nodes(
                &set(&["ttyS0", "ttyACM0"]),
                &set(&["ttyS0", "ttyACM0", "ttyACM1"])
            ),
            vec!["ttyACM1".to_string()]
        );
    }

    #[test]
    fn a_pre_existing_node_is_never_reported_as_new() {
        assert!(new_serial_nodes(&set(&["ttyACM0"]), &set(&["ttyACM0"])).is_empty());
    }

    #[test]
    fn a_non_serial_node_is_never_mirrored_into_the_container() {
        // v1 is serial-class only (D5): a device that enumerated as something
        // else is not handed to the workload just because it appeared.
        assert!(
            new_serial_nodes(&set(&[]), &set(&["sdb", "hidraw0", "video0", "ttyS1"])).is_empty()
        );
    }

    #[test]
    fn both_serial_families_are_recognised() {
        assert_eq!(
            new_serial_nodes(&set(&[]), &set(&["ttyUSB0", "ttyACM0"])).len(),
            2
        );
    }

    #[test]
    fn every_usb_request_is_refused_when_the_guest_did_not_boot_with_usb() {
        // The host decides, via izba.usb=1. A guest that reasons its way to
        // this call gets nothing — and the dialer is never even invoked.
        let usb = UsbState::new(false);
        let (kind, msg) = usb
            .attach_with("0403:6001", || -> std::io::Result<UnixStream> {
                panic!("must not dial when USB is off")
            })
            .unwrap_err();
        assert_eq!(kind, ErrorKind::UsbUnavailable);
        assert!(msg.contains("izba.usb"), "{msg}");
        assert_eq!(
            usb.detach("0403:6001").unwrap_err().0,
            ErrorKind::UsbUnavailable
        );
    }

    #[test]
    fn attach_sends_exactly_one_frame_naming_the_device_and_nothing_else() {
        // D1: the guest may say WHICH device; it may never say where from.
        let (mine, theirs) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || {
            let mut peer = theirs;
            let open: StreamOpen = read_frame(&mut peer).unwrap();
            let StreamOpen::UsbAttach { device } = open else {
                panic!("expected usb_attach, got {open:?}")
            };
            assert_eq!(device, "0403:6001");
            write_frame(
                &mut peer,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: "no".into(),
                },
            )
            .unwrap();
        });
        let usb = UsbState::new(true);
        let _ = usb.attach_with("0403:6001", || Ok(mine));
        h.join().unwrap();
    }

    #[test]
    fn a_refusal_from_izbad_is_reported_verbatim_rather_than_restated() {
        // izbad knows about grants, upstreams and hardware; init knows none of
        // that, so paraphrasing its refusal could only lose information.
        let (mine, theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut peer = theirs;
            let _: StreamOpen = read_frame(&mut peer).unwrap();
            write_frame(
                &mut peer,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: "0403:6001 is not granted to 'web'".into(),
                },
            )
            .unwrap();
        });
        let usb = UsbState::new(true);
        let (kind, msg) = usb.attach_with("0403:6001", || Ok(mine)).unwrap_err();
        assert_eq!(kind, ErrorKind::BadRequest);
        assert_eq!(msg, "0403:6001 is not granted to 'web'");
    }

    #[test]
    fn a_dial_failure_is_reported_as_one() {
        let usb = UsbState::new(true);
        let (kind, msg) = usb
            .attach_with("0403:6001", || -> std::io::Result<UnixStream> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "no izbad",
                ))
            })
            .unwrap_err();
        assert_eq!(kind, ErrorKind::ConnectFailed);
        assert!(msg.contains("USB plane"), "{msg}");
    }

    #[test]
    fn a_reply_that_is_not_an_attach_answer_is_refused() {
        let (mine, theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut peer = theirs;
            let _: StreamOpen = read_frame(&mut peer).unwrap();
            write_frame(&mut peer, &Response::Ok).unwrap();
        });
        let usb = UsbState::new(true);
        let (kind, _) = usb.attach_with("0403:6001", || Ok(mine)).unwrap_err();
        assert_eq!(kind, ErrorKind::Internal);
    }

    #[test]
    fn a_hung_up_plane_is_an_error_not_a_wedge() {
        let (mine, theirs) = UnixStream::pair().unwrap();
        drop(theirs);
        let usb = UsbState::new(true);
        assert!(usb.attach_with("0403:6001", || Ok(mine)).is_err());
    }

    impl UsbState {
        /// Same as `new(true)`, but gives up on enumeration quickly — the
        /// timeout's duration is not what these tests are about.
        fn impatient() -> Self {
            Self {
                node_timeout: Duration::from_millis(150),
                ..Self::new(true)
            }
        }
    }

    /// A recording `Vhci` over a modelled `/dev`: no kernel, but every call and
    /// its order is visible, which is what the attach sequence's guarantees are
    /// actually about. The node appears BECAUSE of the attach, the way devtmpfs
    /// behaves, so the node-diff logic is genuinely exercised rather than fed a
    /// scripted answer.
    struct FakeVhci {
        present: Mutex<BTreeSet<String>>,
        calls: Mutex<Vec<String>>,
        /// The descriptor handed to `attach`, so a test can ask whether the
        /// socket is still open afterwards. That is the ONLY way to observe the
        /// `mem::forget` — without it, deleting the forget (or moving it before
        /// the attach) leaves every unit test green.
        attached_fd: Mutex<Option<RawFd>>,
        closed: Mutex<Vec<RawFd>>,
        /// What enumerating produces; `None` models a device that attaches but
        /// never becomes a serial port.
        node_on_attach: Option<String>,
        free_port: Option<u32>,
        attach_ok: bool,
        expose_ok: bool,
    }

    impl FakeVhci {
        fn working() -> Self {
            Self {
                present: Mutex::new(["ttyS0".to_string()].into_iter().collect()),
                calls: Mutex::new(Vec::new()),
                attached_fd: Mutex::new(None),
                closed: Mutex::new(Vec::new()),
                node_on_attach: Some("ttyACM0".into()),
                free_port: Some(1),
                attach_ok: true,
                expose_ok: true,
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        /// Whether the descriptor handed to `attach` is still a live fd.
        ///
        /// `F_GETFD` succeeds on an open descriptor and fails with `EBADF` on a
        /// closed one, which is exactly the distinction between "the kernel
        /// kept the socket" and "init dropped it out from under vhci". Only
        /// sound as a POSITIVE check while izba still owns the descriptor: once
        /// it is closed the number can be reissued to any other thread in this
        /// process, so absence must be asserted from `closed_fds` instead.
        fn attached_fd_is_open(&self) -> bool {
            let Some(fd) = *self.attached_fd.lock().unwrap() else {
                return false;
            };
            nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).is_ok()
        }

        fn closed_fds(&self) -> Vec<RawFd> {
            self.closed.lock().unwrap().clone()
        }
    }

    impl Vhci for FakeVhci {
        fn free_port(&self, _speed: u32) -> Result<u32, InitError> {
            self.calls.lock().unwrap().push("free_port".into());
            self.free_port
                .ok_or((ErrorKind::Internal, "no free vhci port".into()))
        }
        fn attach(&self, port: u32, fd: RawFd, _devid: u32, _speed: u32) -> Result<(), InitError> {
            self.calls.lock().unwrap().push(format!("attach({port})"));
            // The kernel would take the socket here; record the number so the
            // test can check init did not close it afterwards.
            assert!(
                nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD).is_ok(),
                "vhci must be handed a LIVE socket, got a closed fd {fd}"
            );
            if !self.attach_ok {
                return Err((ErrorKind::Internal, "vhci refused".into()));
            }
            *self.attached_fd.lock().unwrap() = Some(fd);
            if let Some(node) = &self.node_on_attach {
                self.present.lock().unwrap().insert(node.clone());
            }
            Ok(())
        }
        fn detach(&self, port: u32) -> Result<(), InitError> {
            self.calls.lock().unwrap().push(format!("detach({port})"));
            if let Some(node) = &self.node_on_attach {
                self.present.lock().unwrap().remove(node);
            }
            Ok(())
        }
        fn devices(&self) -> BTreeSet<String> {
            self.present.lock().unwrap().clone()
        }
        fn expose(&self, name: &str) -> Result<PathBuf, InitError> {
            self.calls.lock().unwrap().push(format!("expose({name})"));
            if self.expose_ok {
                Ok(PathBuf::from(SHARED_DEV_DIR).join(name))
            } else {
                Err((ErrorKind::Internal, "mknod failed".into()))
            }
        }
        fn unexpose(&self, node: &Path) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("unexpose({})", node.display()));
        }
        fn close_fd(&self, fd: RawFd) {
            self.closed.lock().unwrap().push(fd);
            // Really close it: the tests assert on liveness, so a fake that
            // only recorded the intent would report an fd as open forever.
            unsafe { libc::close(fd) };
        }
    }

    /// A fake izbad that answers one attach with `reply`.
    fn izbad(reply: Response) -> std::os::unix::net::UnixStream {
        let (mine, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut peer = theirs;
            let _: StreamOpen = read_frame(&mut peer).unwrap();
            let _ = write_frame(&mut peer, &reply);
            // Hold the connection until the test drops us: closing here would
            // race the fd the attach is about to hand to the kernel.
            std::thread::sleep(Duration::from_millis(200));
        });
        mine
    }

    fn attached_reply() -> Response {
        Response::UsbAttached {
            devid: 196_610,
            speed: 3,
        }
    }

    #[test]
    fn a_successful_attach_runs_the_sequence_in_order() {
        let vhci = FakeVhci::working();
        let usb = UsbState::new(true);
        usb.attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .unwrap();
        assert_eq!(
            vhci.calls(),
            vec!["free_port", "attach(1)", "expose(ttyACM0)"],
            "port, then the socket, then the node"
        );
    }

    #[test]
    fn the_socket_survives_the_attach_because_the_kernel_now_owns_it() {
        // Without `mem::forget`, dropping the stream would close the socket out
        // from under vhci and kill the device that was just created. This is
        // the only assertion that can see the difference.
        let vhci = FakeVhci::working();
        let usb = UsbState::new(true);
        usb.attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .unwrap();
        assert!(
            vhci.attached_fd_is_open(),
            "the socket handed to vhci must still be open after the attach"
        );
        // And detaching hands it back: vhci ends the connection, but the
        // descriptor is init's to close, and nothing else ever will.
        let fd = vhci.attached_fd.lock().unwrap().expect("attached fd");
        usb.detach_on("0403:6001", &vhci).unwrap();
        // Asserted on the RECORD of the close, not by re-probing the number:
        // the harness runs tests in parallel threads, so a freed descriptor can
        // be handed straight to another test's open() and would then look alive
        // again. The record is deterministic; the probe is a race.
        assert_eq!(
            vhci.closed_fds(),
            vec![fd],
            "detach must close exactly the fd it attached"
        );
    }

    #[test]
    fn a_rolled_back_attach_closes_the_socket_rather_than_leaking_it() {
        // The kernel took the fd and then gave it back via detach. Leaving it
        // open would leak one descriptor per failed attach, with nothing left
        // holding a record of it.
        let vhci = FakeVhci {
            node_on_attach: None,
            ..FakeVhci::working()
        };
        let usb = UsbState::impatient();
        assert!(usb
            .attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .is_err());
        assert_eq!(vhci.closed_fds().len(), 1, "{:?}", vhci.calls());
    }

    #[test]
    fn a_device_that_never_produces_a_node_rolls_the_attach_back() {
        // A vhci port holding a device nothing can open is worse than a clean
        // failure: the device also stays unavailable to the host, and nothing
        // in the guest would ever release it.
        let vhci = FakeVhci {
            node_on_attach: None,
            ..FakeVhci::working()
        };
        let usb = UsbState::impatient();
        let (kind, msg) = usb
            .attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .unwrap_err();
        assert_eq!(kind, ErrorKind::Internal);
        assert!(msg.contains("serial-class"), "{msg}");
        assert!(
            vhci.calls().contains(&"detach(1)".to_string()),
            "the port must be released again: {:?}",
            vhci.calls()
        );
    }

    #[test]
    fn a_failure_to_expose_the_node_also_rolls_back() {
        let vhci = FakeVhci {
            expose_ok: false,
            ..FakeVhci::working()
        };
        let usb = UsbState::new(true);
        assert!(usb
            .attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .is_err());
        assert!(vhci.calls().contains(&"detach(1)".to_string()));
    }

    #[test]
    fn a_vhci_that_refuses_the_attach_is_not_rolled_back() {
        // Nothing was attached, so there is no port to release — and detaching
        // one izba does not hold could unplug somebody else's device.
        let vhci = FakeVhci {
            attach_ok: false,
            ..FakeVhci::working()
        };
        let usb = UsbState::new(true);
        assert!(usb
            .attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .is_err());
        assert!(
            !vhci.calls().iter().any(|c| c.starts_with("detach")),
            "{:?}",
            vhci.calls()
        );
    }

    #[test]
    fn no_free_port_fails_before_the_socket_is_surrendered() {
        let vhci = FakeVhci {
            free_port: None,
            ..FakeVhci::working()
        };
        let usb = UsbState::new(true);
        let (_, msg) = usb
            .attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .unwrap_err();
        assert!(msg.contains("no free vhci port"), "{msg}");
        assert_eq!(vhci.calls(), vec!["free_port"], "nothing else was touched");
    }

    #[test]
    fn a_refused_attach_leaves_nothing_attached_so_it_can_be_retried() {
        // The duplicate check must reflect what is actually held: a failed
        // attach that recorded itself would make the retry impossible.
        let vhci = FakeVhci {
            attach_ok: false,
            ..FakeVhci::working()
        };
        let usb = UsbState::new(true);
        assert!(usb
            .attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .is_err());
        let again = usb.attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci);
        assert!(
            !format!("{again:?}").contains("already attached"),
            "a failed attach must not block a retry: {again:?}"
        );
    }

    #[test]
    fn overlapping_attaches_are_serialized_rather_than_racing_the_port_pool() {
        // Two attaches of DIFFERENT devices are the dangerous case: they share
        // the vhci port pool and the /dev snapshot the new node is identified
        // by, so without one operation lock they can pick the same port and
        // each attribute the other's node to itself.
        let vhci = std::sync::Arc::new(SlowVhci::default());
        let usb = std::sync::Arc::new(UsbState::new(true));

        let handles: Vec<_> = ["0403:6001", "1a86:7523"]
            .into_iter()
            .map(|dev| {
                let (usb, vhci) = (usb.clone(), vhci.clone());
                std::thread::spawn(move || {
                    usb.attach_on(dev, || Ok(izbad(attached_reply())), &*vhci)
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap().expect("both attaches succeed");
        }
        assert!(
            !vhci.overlapped.load(std::sync::atomic::Ordering::SeqCst),
            "two attach sequences ran concurrently; they share the port pool"
        );
        assert_eq!(
            vhci.ports.lock().unwrap().len(),
            2,
            "each attach must get its own vhci port"
        );
    }

    /// A vhci whose attach dwells, and which notices if two operations are ever
    /// inside it at once. Ports are handed out in order, so a race shows up as
    /// a duplicate.
    #[derive(Default)]
    struct SlowVhci {
        inside: std::sync::atomic::AtomicUsize,
        overlapped: std::sync::atomic::AtomicBool,
        ports: Mutex<Vec<u32>>,
        next_port: std::sync::atomic::AtomicU32,
        present: Mutex<BTreeSet<String>>,
    }

    impl SlowVhci {
        fn enter(&self) {
            use std::sync::atomic::Ordering::SeqCst;
            if self.inside.fetch_add(1, SeqCst) > 0 {
                self.overlapped.store(true, SeqCst);
            }
            std::thread::sleep(Duration::from_millis(30));
            self.inside.fetch_sub(1, SeqCst);
        }
    }

    impl Vhci for SlowVhci {
        fn free_port(&self, _speed: u32) -> Result<u32, InitError> {
            self.enter();
            let p = self
                .next_port
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(p)
        }
        fn attach(&self, port: u32, _fd: RawFd, _devid: u32, _speed: u32) -> Result<(), InitError> {
            self.enter();
            self.ports.lock().unwrap().push(port);
            self.present.lock().unwrap().insert(format!("ttyACM{port}"));
            Ok(())
        }
        fn detach(&self, _port: u32) -> Result<(), InitError> {
            Ok(())
        }
        fn close_fd(&self, fd: RawFd) {
            unsafe { libc::close(fd) };
        }
        fn devices(&self) -> BTreeSet<String> {
            self.present.lock().unwrap().clone()
        }
        fn expose(&self, name: &str) -> Result<PathBuf, InitError> {
            Ok(PathBuf::from(SHARED_DEV_DIR).join(name))
        }
        fn unexpose(&self, _node: &Path) {}
    }

    #[test]
    fn attaching_the_same_device_twice_is_refused() {
        let vhci = FakeVhci::working();
        let usb = UsbState::new(true);
        usb.attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .unwrap();
        let (kind, msg) = usb
            .attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .unwrap_err();
        assert_eq!(kind, ErrorKind::BadRequest);
        assert!(msg.contains("already attached"), "{msg}");
    }

    #[test]
    fn detach_releases_the_node_before_the_port() {
        // Once the port is released its major/minor may be reused, so a node
        // left behind would point at whatever lands there next.
        let vhci = FakeVhci::working();
        let usb = UsbState::new(true);
        usb.attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .unwrap();
        usb.detach_on("0403:6001", &vhci).unwrap();
        let calls = vhci.calls();
        let unexpose = calls
            .iter()
            .position(|c| c.starts_with("unexpose"))
            .unwrap();
        let detach = calls.iter().position(|c| c == "detach(1)").unwrap();
        assert!(unexpose < detach, "{calls:?}");
    }

    #[test]
    fn a_detached_device_can_be_attached_again() {
        let vhci = FakeVhci::working();
        let usb = UsbState::new(true);
        usb.attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .unwrap();
        usb.detach_on("0403:6001", &vhci).unwrap();
        assert!(usb
            .attach_on("0403:6001", || Ok(izbad(attached_reply())), &vhci)
            .is_ok());
    }

    #[test]
    fn detaching_a_device_that_was_never_attached_says_so() {
        let usb = UsbState::new(true);
        let (kind, msg) = usb.detach("0403:6001").unwrap_err();
        assert_eq!(kind, ErrorKind::BadRequest);
        assert!(msg.contains("not attached"), "{msg}");
    }
}
