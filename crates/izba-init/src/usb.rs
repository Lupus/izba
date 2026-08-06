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
use std::os::fd::AsRawFd;
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

type InitError = (ErrorKind, String);

/// One device this guest currently holds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Attached {
    port: u32,
    node: PathBuf,
}

/// The guest's USB state: whether it may attach at all, and what it holds.
pub struct UsbState {
    enabled: bool,
    attached: Mutex<HashMap<String, Attached>>,
}

impl UsbState {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            attached: Mutex::new(HashMap::new()),
        }
    }

    /// Attach `device`, dialing the USB plane through `dial`.
    ///
    /// The dialer is a seam so the whole handshake is host-testable without a
    /// vsock (the pattern `egress.rs` uses). Everything after the reply touches
    /// sysfs and is exercised only in the guest.
    pub fn attach_with<S, D>(&self, device: &str, dial: D) -> Result<(), InitError>
    where
        S: Read + Write + AsRawFd,
        D: FnOnce() -> std::io::Result<S>,
    {
        self.gate()?;
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

        let before = dev_entries();
        let port = free_port(speed)?;
        write_sysfs(
            &Path::new(VHCI_DIR).join("attach"),
            &attach_line(port, conn.as_raw_fd(), devid, speed),
        )
        .map_err(|e| {
            (
                ErrorKind::Internal,
                format!("handing the socket to vhci: {e}"),
            )
        })?;
        // The kernel owns this fd now. Leak it deliberately: dropping `conn`
        // would close the socket out from under `vhci`, killing the device the
        // line above just created. This happens ONLY after the write succeeded
        // — on any earlier failure `conn` is dropped normally, so a refused
        // attach never leaves a connection open to izbad for the guest's life.
        std::mem::forget(conn);

        let node = match self.mirror_node(&before) {
            Ok(node) => node,
            Err(e) => {
                // Undo the attach: a port holding a device nothing can open is
                // worse than a clean failure, because the device also stays
                // unavailable to the host.
                let _ = write_sysfs(&Path::new(VHCI_DIR).join("detach"), &port.to_string());
                return Err(e);
            }
        };
        self.attached
            .lock()
            .unwrap()
            .insert(device.to_string(), Attached { port, node });
        Ok(())
    }

    /// Detach a device this guest holds, returning its vhci port to the pool.
    pub fn detach(&self, device: &str) -> Result<(), InitError> {
        self.gate()?;
        let Some(a) = self.attached.lock().unwrap().remove(device) else {
            return Err((
                ErrorKind::BadRequest,
                format!("{device} is not attached to this sandbox"),
            ));
        };
        // The node goes first: once the port is released the major/minor may be
        // reused, and a stale node would then point at someone else's device.
        let _ = std::fs::remove_file(&a.node);
        write_sysfs(&Path::new(VHCI_DIR).join("detach"), &a.port.to_string()).map_err(|e| {
            (
                ErrorKind::Internal,
                format!("detaching port {}: {e}", a.port),
            )
        })
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

    /// Copy whichever serial node the kernel just created into the shared
    /// directory the workload can see.
    ///
    /// The kernel picks the minor, so izba must not guess a name: the new node
    /// is found by diffing `/dev`. The mirror is a fresh `mknod` with the same
    /// device numbers rather than a link, because the container sees the shared
    /// directory through a bind mount and `/dev` itself is not in it.
    // reason: devtmpfs polling + mknod; `new_serial_nodes` and `dev_entries`
    // carry the logic and are unit-tested, and there is no device node to
    // create on a host test runner.
    #[mutants::skip]
    fn mirror_node(&self, before: &BTreeSet<String>) -> Result<PathBuf, InitError> {
        let deadline = Instant::now() + NODE_TIMEOUT;
        loop {
            let fresh = new_serial_nodes(before, &dev_entries());
            if let Some(name) = fresh.first() {
                let src = Path::new("/dev").join(name);
                let dst = Path::new(SHARED_DEV_DIR).join(name);
                return mirror(&src, &dst).map(|()| dst).map_err(|e| {
                    (
                        ErrorKind::Internal,
                        format!("exposing {name} to the workload: {e}"),
                    )
                });
            }
            if Instant::now() >= deadline {
                return Err((
                    ErrorKind::Internal,
                    "the device attached but no serial node appeared — izba supports \
                     serial-class devices only (CDC-ACM and the common USB bridges)"
                        .into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
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
// reason: one sysfs read feeding the unit-tested `parse_free_port`.
#[mutants::skip]
fn free_port(speed: u32) -> Result<u32, InitError> {
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

// reason: a one-line sysfs write; the value written is built by the unit-tested
// `attach_line`.
#[mutants::skip]
fn write_sysfs(path: &Path, value: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.write_all(value.as_bytes())
}

// reason: reads the guest's devtmpfs; the diff it feeds is unit-tested.
#[mutants::skip]
fn dev_entries() -> BTreeSet<String> {
    std::fs::read_dir("/dev")
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Re-create `src`'s device node at `dst`, world-readable and world-writable.
///
/// Mode 0666 rather than an ownership dance: the workload runs in its own user
/// namespace, so a uid-based grant would depend on the mapping. What actually
/// gates reachability is the bind mount (the node exists nowhere else the
/// container can see) and the cgroup device filter (only the serial majors may
/// be opened at all).
// reason: needs a real device node and CAP_MKNOD.
#[mutants::skip]
fn mirror(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::MetadataExt;
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
    .map_err(std::io::Error::from)
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

    #[test]
    fn detaching_a_device_that_was_never_attached_says_so() {
        let usb = UsbState::new(true);
        let (kind, msg) = usb.detach("0403:6001").unwrap_err();
        assert_eq!(kind, ErrorKind::BadRequest);
        assert!(msg.contains("not attached"), "{msg}");
    }
}
