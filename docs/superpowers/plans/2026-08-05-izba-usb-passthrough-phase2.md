# USB passthrough — Phase 2 (host-side control plane) implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a human configure a usbip upstream, see what it exports, and grant
a specific `vid:pid` to a specific sandbox — with the egress floor from Phase 1
now driven by the real grants and the real upstream.

**Architecture:** Everything in this phase is host-side. A new `crate::usb`
module holds the device-id type, the persisted settings, the upstream-trust
classifier, the per-sandbox grant model, and the host-side inventory (an
`OP_REQ_DEVLIST` exchange against the upstream, using the Phase-1 codec). The
daemon gains control-plane RPCs over these, the CLI gains `izba usb`, and the
`UsbGuard` that Phase 1 left `default()` is populated from the grants and the
configured upstream — and kept live across grant/revoke the same way
`apply_policy` keeps the egress policy live.

**Tech Stack:** Rust (izba-core, izba-cli, izba-proto), serde/serde_json, clap,
`std::net::TcpStream` (blocking, with explicit timeouts — no tokio on this path).

## Scope: what this phase deliberately does NOT build

The design spec (§5.2) put the vsock-1028 broker (`session.rs`) in Phase 2. This
plan moves it to Phase 3, next to the guest client that is its only caller.
Reasons, both worth stating in the PR:

1. A listener nothing dials cannot be tested against a real datapath. Pairing it
   with `izba-init`'s client means the splice, the D6 URB validation, and the
   attach handshake are proven end-to-end in one KVM e2e rather than shipped on
   in-process faith.
2. Phase 2 therefore adds **zero new guest-reachable surface**. Constraint #2
   ("disabled USB must add zero attack surface to izbad") holds trivially here:
   there is no new listener, no new guest frame variant, and no guest-reachable
   parser anywhere in this phase. The only new I/O is host-initiated, outbound,
   and only when a human configured an upstream.

Consequently `DAEMON_PROTO_VERSION` goes 2 → 3 in this phase (control-plane
variants) and will go 3 → 4 in Phase 3 (`UsbAttach`/`UsbDetach`, guest RPC).
Two cheap bumps beat shipping dead wire variants that answer "not implemented".

## Global Constraints

- Six workspace gates must be green before every commit: `cargo test
  --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo
  fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl
  --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p
  izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu
  --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
- `source .cargo-env` first if the file exists.
- Conventional commits (`feat(core): ...`). TDD: the failing test comes first.
- **Unit tests never bind unix/vsock/TCP listeners.** Use in-memory streams
  (`std::io::Cursor`, a paired `Read`+`Write` fake) or runtime-skip on
  `PermissionDenied`.
- **The out-of-workspace app gate** must be run on this change (it embeds
  `izba-core` by path and the six gates do not compile it): `cd app && npm ci &&
  npm run build && (cd src-tauri && cargo fmt --check && cargo clippy
  --all-targets -- -D warnings && cargo test)`.
- Fail closed and loud: no permissive fallback on a corrupt config, no silent
  security downgrade. A missing/corrupt `usb/settings.json` means the feature is
  **off**, never "on with defaults".
- Every persisted string that reaches a log, a path, or a format argument comes
  from the Phase-1 codec, which already refuses non-printable-ASCII.
- New mutants must be killed by tests, not by `#[mutants::skip]`, unless the
  skip carries a justification comment in the house style.

---

## File structure

**New — `crates/izba-core/src/usb/`** (host-side model; Phase 3 adds
`usb/broker.rs` for the vsock plane, keeping one module tree):

| File | Responsibility |
| --- | --- |
| `mod.rs` | Module docs + re-exports; the "feature is off unless an upstream is configured" predicate. |
| `ids.rs` | `DeviceId` (`vid:pid`) — parse, display, equality. Nothing else. |
| `settings.rs` | `<data>/usb/settings.json`: upstream endpoint + `allow_remote_upstream`. Load never fails; a bad file reads as "off". |
| `trust.rs` | `UpstreamTrust` classification and its human-facing warnings; pure, with host detection injected. |
| `grants.rs` | `UsbConfig`/`UsbGrant` (persisted on `SandboxConfig.usb`) + add/revoke/lookup, including the ambiguity rules. |
| `inventory.rs` | Host-side `OP_REQ_DEVLIST` exchange: framed socket read → Phase-1 decoder → `UpstreamDevice` list. |
| `usbipd_state.rs` | Pure parser for `usbipd.exe state --json`, plus the guarded invoker (Windows/WSL convenience only). |

**Modified:**

- `crates/izba-proto/src/usbip/op.rs` — publish the framing constants a socket
  reader needs (`OP_COMMON_LEN`, `DEVICE_RECORD_LEN`, `INTERFACE_LEN`,
  `MAX_DEVICES`).
- `crates/izba-core/src/paths.rs` — `usb_dir()`.
- `crates/izba-core/src/state.rs` — `SandboxConfig.usb`.
- `crates/izba-core/src/lib.rs` — `pub mod usb;`.
- `crates/izba-core/src/daemon/proto.rs` — version bump + variants.
- `crates/izba-core/src/daemon/server.rs` — handlers + the fail-closed gate.
- `crates/izba-core/src/daemon/egress/mod.rs` — populate + hot-swap `UsbGuard`.
- `crates/izba-cli/src/commands/mod.rs`, `usb.rs` (new), `main.rs` — the CLI.
- `crates/izba-cli/src/commands/policy.rs` — pass the real upstream to
  `usbip_exposure_warning`.
- `docs/`, `README.md`, `docs/security/findings-2026-06-15.md`.

---

### Task 1: `DeviceId` and the USB settings file

**Files:**
- Create: `crates/izba-core/src/usb/mod.rs`, `crates/izba-core/src/usb/ids.rs`,
  `crates/izba-core/src/usb/settings.rs`
- Modify: `crates/izba-core/src/lib.rs`, `crates/izba-core/src/paths.rs`
- Test: inline `#[cfg(test)] mod tests` in each new file; `paths.rs` tests

**Interfaces:**
- Produces: `usb::DeviceId { vid: u16, pid: u16 }` with `FromStr` + `Display`;
  `usb::settings::{UsbSettings, Upstream, load, save}`;
  `usb::is_configured(&UsbSettings) -> bool`; `Paths::usb_dir()`.

- [ ] **Step 1: Write the failing tests for `DeviceId`**

Create `crates/izba-core/src/usb/ids.rs` containing only this test module for
now (the type comes in step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_vid_pid() {
        let id: DeviceId = "0403:6001".parse().unwrap();
        assert_eq!(id.vid, 0x0403);
        assert_eq!(id.pid, 0x6001);
        assert_eq!(id.to_string(), "0403:6001");
    }

    #[test]
    fn uppercase_input_is_accepted_and_normalises_to_lowercase() {
        // lsusb prints uppercase on some platforms; the canonical form is lower.
        let id: DeviceId = "1A86:7523".parse().unwrap();
        assert_eq!(id.to_string(), "1a86:7523");
    }

    #[test]
    fn rejects_anything_that_is_not_exactly_four_hex_colon_four_hex() {
        // Short forms are refused rather than zero-padded: "403:6001" is far too
        // easy to mistype for a different device, and a grant is a consent record.
        for bad in [
            "403:6001", "0403:601", "0403-6001", "04036001", "0403:6001:0",
            "", "0403:", ":6001", "zzzz:6001", "0403:600g", " 0403:6001",
            "0403:6001 ", "00403:6001",
        ] {
            assert!(bad.parse::<DeviceId>().is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn error_names_the_expected_shape() {
        let err = "nope".parse::<DeviceId>().unwrap_err().to_string();
        assert!(err.contains("vid:pid"), "{err}");
        assert!(err.contains("0403:6001"), "actionable example: {err}");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core usb::ids`
Expected: FAIL — `cannot find type DeviceId`.

- [ ] **Step 3: Implement `DeviceId`**

Prepend to `crates/izba-core/src/usb/ids.rs`:

```rust
//! USB device identity as a human types it: `vid:pid`.
//!
//! Deliberately strict — four hex digits each, no shorthand. A grant is a
//! consent record, and a typo that silently widened or narrowed it would be a
//! consent bug, not a usability one. See F-USB-3: this pair is *asserted* by
//! the device, so it expresses human intent, never provenance.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId {
    pub vid: u16,
    pub pid: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDeviceIdError;

impl fmt::Display for ParseDeviceIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a USB id in vid:pid form, four hex digits each (e.g. 0403:6001)")
    }
}

impl std::error::Error for ParseDeviceIdError {}

fn hex4(s: &str) -> Result<u16, ParseDeviceIdError> {
    if s.len() != 4 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ParseDeviceIdError);
    }
    u16::from_str_radix(s, 16).map_err(|_| ParseDeviceIdError)
}

impl FromStr for DeviceId {
    type Err = ParseDeviceIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (v, p) = s.split_once(':').ok_or(ParseDeviceIdError)?;
        Ok(Self {
            vid: hex4(v)?,
            pid: hex4(p)?,
        })
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04x}:{:04x}", self.vid, self.pid)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-core usb::ids`
Expected: PASS (4 tests) — after step 6 wires the module in. If the module is
not yet declared, the compiler will say so; do step 5 first in that case.

- [ ] **Step 5: Write the failing tests for settings**

Create `crates/izba-core/src/usb/settings.rs` with this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_off_with_no_upstream() {
        let s = UsbSettings::default();
        assert!(s.upstream.is_none(), "no upstream ⇒ the feature is off");
        assert!(!s.allow_remote_upstream, "remote upstreams are opt-in");
    }

    #[test]
    fn missing_file_reads_as_off() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load(tmp.path()).upstream.is_none());
    }

    #[test]
    fn corrupt_file_reads_as_off_not_as_permissive_defaults() {
        // Inverted from ssh::settings (default ON): an unreadable USB config must
        // never leave the feature enabled, because "enabled" is what arms the
        // grant plane and relaxes nothing else.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("settings.json"), b"{ not json").unwrap();
        let s = load(tmp.path());
        assert!(s.upstream.is_none());
        assert!(!s.allow_remote_upstream);
    }

    #[test]
    fn roundtrips_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let want = UsbSettings {
            upstream: Some(Upstream {
                host: "172.24.32.1".into(),
                port: 3240,
            }),
            allow_remote_upstream: true,
        };
        save(tmp.path(), &want).unwrap();
        let got = load(tmp.path());
        assert_eq!(got.upstream.as_ref().unwrap().host, "172.24.32.1");
        assert_eq!(got.upstream.as_ref().unwrap().port, 3240);
        assert!(got.allow_remote_upstream);
    }

    #[test]
    fn omitted_allow_remote_defaults_to_refusing_public_upstreams() {
        let s: UsbSettings =
            serde_json::from_str(r#"{"upstream":{"host":"127.0.0.1","port":3240}}"#).unwrap();
        assert!(!s.allow_remote_upstream);
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        save(tmp.path(), &UsbSettings::default()).unwrap();
        let mode = std::fs::metadata(tmp.path().join("settings.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "settings name the user's hardware host");
    }
}
```

- [ ] **Step 6: Run to verify failure**

Run: `cargo test -p izba-core usb::settings`
Expected: FAIL — unresolved `UsbSettings`.

- [ ] **Step 7: Implement settings, the module root, and `usb_dir`**

Prepend to `crates/izba-core/src/usb/settings.rs`:

```rust
//! Daemon-level USB settings: `<data>/usb/settings.json`.
//!
//! Absent or unreadable means the feature is OFF. This is the inverse of
//! `ssh::settings` (whose default is on) and it is deliberate: an upstream is
//! the address izbad will dial from the host's network position, so "I could
//! not read your intent" must never resolve to "dial something".

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The usbip server izbad talks to. `host` is stored as the user typed it so
/// `izba usb upstream show` can echo it back; resolution happens per use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
}

/// The IANA-registered usbip port; also usbipd-win's default.
pub const DEFAULT_UPSTREAM_PORT: u16 = 3240;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbSettings {
    /// `None` ⇒ USB passthrough is not configured; every USB RPC refuses.
    #[serde(default)]
    pub upstream: Option<Upstream>,
    /// Permit a globally-routable upstream. Off by default: an unauthenticated,
    /// unencrypted protocol over the open internet is refused, not warned about.
    #[serde(default)]
    pub allow_remote_upstream: bool,
}

const FILE: &str = "settings.json";

/// Never fails: an unreadable or malformed file reads as "not configured".
pub fn load(usb_dir: &Path) -> UsbSettings {
    match std::fs::read(usb_dir.join(FILE)) {
        Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
        Err(_) => UsbSettings::default(),
    }
}

pub fn save(usb_dir: &Path, s: &UsbSettings) -> anyhow::Result<()> {
    std::fs::create_dir_all(usb_dir)?;
    let path = usb_dir.join(FILE);
    crate::state::save_json(&path, s)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
```

Create `crates/izba-core/src/usb/mod.rs`:

```rust
//! Host-side USB passthrough: identity, consent, settings, and inventory.
//!
//! Everything here runs on the host and is reachable only from a human-driven
//! CLI/GUI action or from izbad's own outbound dial. The guest-facing broker
//! plane lands in Phase 3 as `usb::broker`.

pub mod ids;
pub mod inventory;
pub mod settings;
pub mod trust;
pub mod usbipd_state;

pub use ids::DeviceId;
pub use settings::{Upstream, UsbSettings};

/// The single "is this feature on?" predicate. USB is configured exactly when a
/// human set an upstream; nothing else turns it on.
pub fn is_configured(s: &UsbSettings) -> bool {
    s.upstream.is_some()
}
```

Add `pub mod usb;` to `crates/izba-core/src/lib.rs` (alphabetical among the
existing `pub mod` lines). Add to `crates/izba-core/src/paths.rs`, next to
`ssh_dir`:

```rust
    /// Daemon-level USB passthrough settings (`settings.json`).
    pub fn usb_dir(&self) -> PathBuf {
        self.root.join("usb")
    }
```

Note: `usb/mod.rs` declares `inventory`, `trust`, and `usbipd_state`, which
arrive in Tasks 2/4/5. Until then, create each as an empty file with just its
`//!` module doc so the crate compiles; each later task fills it in.

- [ ] **Step 8: Add the `usb_dir` test**

In the `paths.rs` test module, alongside `ssh_dirs_resolve_under_root`:

```rust
    #[test]
    fn usb_dir_resolves_under_root() {
        let p = Paths::with_root(PathBuf::from("/data/izba"));
        assert_eq!(p.usb_dir(), PathBuf::from("/data/izba/usb"));
    }
```

- [ ] **Step 9: Run the gates**

Run: `cargo test -p izba-core usb:: && cargo test -p izba-core paths:: && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add crates/izba-core/src/usb crates/izba-core/src/lib.rs crates/izba-core/src/paths.rs
git commit -m "feat(core): add the USB device id and the daemon USB settings file"
```

---

### Task 2: Upstream trust classification

**Files:**
- Modify: `crates/izba-core/src/usb/trust.rs`
- Test: inline `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: nothing from Task 1 except the module slot.
- Produces: `usb::trust::{UpstreamTrust, classify, describe, is_refused,
  default_gateway_from_proc_route, running_under_wsl}`.

Why this exists: warning on "not loopback" would fire on izba's primary
platform, because in WSL2 NAT mode the Windows host *is* an RFC1918 gateway.
The classifier separates "your own machine across the WSL boundary" from "some
other box on your LAN", so the loud warning stays meaningful.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_is_the_recommended_configuration() {
        for a in ["127.0.0.1", "127.5.5.5", "::1"] {
            assert_eq!(classify(ip(a), None, false), UpstreamTrust::OwnHostLoopback);
        }
        assert!(describe(UpstreamTrust::OwnHostLoopback, "127.0.0.1").is_none());
    }

    #[test]
    fn the_wsl_default_gateway_is_your_own_windows_host() {
        let gw = ip("172.24.32.1");
        assert_eq!(
            classify(gw, Some(gw), true),
            UpstreamTrust::OwnHostWslGateway
        );
        let msg = describe(UpstreamTrust::OwnHostWslGateway, "172.24.32.1").unwrap();
        assert!(msg.contains("Windows host"), "{msg}");
        // The honest caveat: usbipd-win serves every WSL distro on this machine.
        assert!(msg.contains("WSL"), "{msg}");
    }

    #[test]
    fn the_same_address_off_wsl_is_just_a_lan_host() {
        // Identical address, but izbad is not under WSL: it is someone's box.
        let gw = ip("172.24.32.1");
        assert_eq!(classify(gw, Some(gw), false), UpstreamTrust::PrivateLan);
    }

    #[test]
    fn a_private_address_that_is_not_the_gateway_is_lan_even_under_wsl() {
        assert_eq!(
            classify(ip("192.168.1.50"), Some(ip("172.24.32.1")), true),
            UpstreamTrust::PrivateLan
        );
    }

    #[test]
    fn private_ranges_are_recognised_including_ula() {
        for a in ["10.0.0.5", "172.16.0.1", "172.31.255.254", "192.168.0.9", "fd00::1"] {
            assert_eq!(classify(ip(a), None, false), UpstreamTrust::PrivateLan, "{a}");
        }
        // 172.32/12 is NOT private — a classic off-by-one in RFC1918 checks.
        assert_eq!(classify(ip("172.32.0.1"), None, false), UpstreamTrust::Public);
    }

    #[test]
    fn lan_warning_names_who_is_being_trusted() {
        let msg = describe(UpstreamTrust::PrivateLan, "192.168.1.50").unwrap();
        assert!(msg.contains("192.168.1.50"), "{msg}");
        assert!(msg.contains("no authentication"), "{msg}");
        // F-USB-5: the upstream can attack the guest USB stack, so say so.
        assert!(msg.contains("read or modify"), "{msg}");
    }

    #[test]
    fn public_upstreams_are_refused_unless_explicitly_allowed() {
        assert_eq!(classify(ip("93.184.216.34"), None, false), UpstreamTrust::Public);
        assert!(is_refused(UpstreamTrust::Public, false));
        assert!(!is_refused(UpstreamTrust::Public, true));
        for t in [
            UpstreamTrust::OwnHostLoopback,
            UpstreamTrust::OwnHostWslGateway,
            UpstreamTrust::PrivateLan,
        ] {
            assert!(!is_refused(t, false), "{t:?} must not need the opt-out");
        }
    }

    #[test]
    fn a_public_upstream_still_warns_after_being_allowed() {
        let msg = describe(UpstreamTrust::Public, "203.0.113.7").unwrap();
        assert!(msg.contains("internet"), "{msg}");
    }

    #[test]
    fn gateway_comes_from_proc_net_route_never_from_resolv_conf() {
        // Destination 00000000 = default route; Gateway is little-endian hex.
        // 0120CDAC -> ac cd 20 01 -> 172.205.32.1 read big-endian... the kernel
        // prints it host-endian, so the bytes reverse: 01 20 cd ac = 172.24.32.1.
        let table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
eth0\t0000E0AC\t00000000\t0001\t0\t0\t0\t0000F0FF\n\
eth0\t00000000\t0120CDAC\t0003\t0\t0\t0\t00000000\n";
        assert_eq!(
            default_gateway_from_proc_route(table),
            Some(ip("172.205.32.1"))
        );
    }

    #[test]
    fn a_route_table_with_no_default_route_yields_no_gateway() {
        let table = "Iface\tDestination\tGateway\n\
eth0\t0000E0AC\t00000000\t0001\t0\t0\t0\t0000F0FF\n";
        assert_eq!(default_gateway_from_proc_route(table), None);
        assert_eq!(default_gateway_from_proc_route(""), None);
        assert_eq!(default_gateway_from_proc_route("garbage\nlines\n"), None);
    }

    #[test]
    fn wsl_is_detected_from_the_kernel_release_string() {
        assert!(wsl_from_osrelease("5.15.167.4-microsoft-standard-WSL2"));
        assert!(wsl_from_osrelease("6.6.87.2-microsoft-standard-WSL2+"));
        assert!(!wsl_from_osrelease("6.8.0-45-generic"));
        assert!(!wsl_from_osrelease(""));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core usb::trust`
Expected: FAIL — `UpstreamTrust` not found.

- [ ] **Step 3: Implement the classifier**

Replace the contents of `crates/izba-core/src/usb/trust.rs` (keeping the tests):

```rust
//! How much to trust the configured usbip upstream, and what to tell the human.
//!
//! usbip has no authentication, no authorization and no encryption. The only
//! meaningful question is therefore *whose machine* is on the other end, and
//! "is it loopback?" answers that badly on izba's primary platform: under WSL2
//! NAT the user's own Windows host is an RFC1918 default gateway. So the
//! gateway case is classified separately and gets an informational note, while
//! a genuine third-party LAN box gets the loud one.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTrust {
    /// Same machine as izbad.
    OwnHostLoopback,
    /// The user's own Windows host, reached across the WSL2 NAT boundary.
    OwnHostWslGateway,
    /// A private-range address that is not this machine.
    PrivateLan,
    /// Globally routable.
    Public,
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            // Unique-local fc00::/7 and link-local fe80::/10.
            let seg = v6.segments();
            (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Classify `ip` given the host's default gateway (if known) and whether izbad
/// is running under WSL. Both inputs are injected so this stays pure.
pub fn classify(ip: IpAddr, gateway: Option<IpAddr>, under_wsl: bool) -> UpstreamTrust {
    if ip.is_loopback() {
        return UpstreamTrust::OwnHostLoopback;
    }
    if under_wsl && gateway == Some(ip) {
        return UpstreamTrust::OwnHostWslGateway;
    }
    if is_private(ip) {
        return UpstreamTrust::PrivateLan;
    }
    UpstreamTrust::Public
}

/// A public upstream is refused outright unless the user opted in; every other
/// class is allowed (with or without a warning).
pub fn is_refused(t: UpstreamTrust, allow_remote_upstream: bool) -> bool {
    matches!(t, UpstreamTrust::Public) && !allow_remote_upstream
}

/// The human-facing note for this class, or `None` when the configuration is
/// the recommended one and silence is correct.
pub fn describe(t: UpstreamTrust, host: &str) -> Option<String> {
    match t {
        UpstreamTrust::OwnHostLoopback => None,
        UpstreamTrust::OwnHostWslGateway => Some(format!(
            "note: {host} is your Windows host across the WSL boundary.\n\
             Any other WSL distro on this machine can attach the same devices."
        )),
        UpstreamTrust::PrivateLan => Some(format!(
            "⚠  {host} is another machine on your network.\n\
             USB/IP has no authentication and no encryption: anyone who can route\n\
             there can attach the same devices, and can read or modify everything\n\
             your sandbox sends to and receives from them."
        )),
        UpstreamTrust::Public => Some(format!(
            "⚠  {host} is reachable from the internet.\n\
             USB/IP has no authentication and no encryption. Anyone who can reach\n\
             this address can attach the same devices, and can read or modify the\n\
             traffic. This is not a supported configuration."
        )),
    }
}

/// Parse the default gateway out of `/proc/net/route` contents.
///
/// Deliberately NOT derived from `resolv.conf`: with izba's DNS tunnelling the
/// nameserver is a stub address, not the host.
pub fn default_gateway_from_proc_route(table: &str) -> Option<IpAddr> {
    for line in table.lines().skip(1) {
        let mut f = line.split_whitespace();
        let (_iface, dest, gw) = (f.next()?, f.next()?, f.next()?);
        if dest != "00000000" {
            continue;
        }
        let raw = u32::from_str_radix(gw, 16).ok()?;
        if raw == 0 {
            continue;
        }
        // The kernel prints the address in host byte order.
        let b = raw.to_le_bytes();
        return Some(IpAddr::from([b[0], b[1], b[2], b[3]]));
    }
    None
}

pub fn wsl_from_osrelease(release: &str) -> bool {
    let r = release.to_ascii_lowercase();
    r.contains("microsoft") || r.contains("wsl")
}

/// Read the host's default gateway. `None` on any platform or failure — the
/// caller then classifies without the WSL special case, which is the safe
/// direction (a gateway would only ever *downgrade* a warning).
// reason: thin /proc reader; the parsing is fully unit-tested through
// `default_gateway_from_proc_route`.
#[mutants::skip]
pub fn host_default_gateway() -> Option<IpAddr> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    default_gateway_from_proc_route(&table)
}

// reason: thin /proc reader; `wsl_from_osrelease` carries the logic.
#[mutants::skip]
pub fn running_under_wsl() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|r| wsl_from_osrelease(&r))
        .unwrap_or(false)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p izba-core usb::trust`
Expected: PASS (11 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/usb/trust.rs
git commit -m "feat(core): classify usbip upstream trust, WSL gateway aware"
```

---

### Task 3: Per-sandbox device grants

**Files:**
- Modify: `crates/izba-core/src/usb/grants.rs` (new file, declared in Task 1),
  `crates/izba-core/src/usb/mod.rs`, `crates/izba-core/src/state.rs`
- Test: inline `#[cfg(test)] mod tests` in `grants.rs`; back-compat test in
  `state.rs`

**Interfaces:**
- Consumes: `usb::DeviceId` (Task 1).
- Produces: `usb::grants::{UsbConfig, UsbGrant, grant, revoke, find}`;
  `SandboxConfig.usb: UsbConfig`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> DeviceId {
        s.parse().unwrap()
    }

    fn cfg_with(entries: &[(&str, Option<&str>)]) -> UsbConfig {
        let mut c = UsbConfig::default();
        for (d, pin) in entries {
            grant(
                &mut c,
                UsbGrant {
                    device: id(d),
                    busid_pin: pin.map(|s| s.to_string()),
                    description: String::new(),
                    granted_at_unix_ms: 1,
                },
            )
            .unwrap();
        }
        c
    }

    #[test]
    fn a_fresh_sandbox_holds_no_grants() {
        let c = UsbConfig::default();
        assert!(c.devices.is_empty());
        assert!(!c.is_enabled(), "no grants ⇒ USB is not enabled here");
    }

    #[test]
    fn granting_a_device_enables_usb_for_the_sandbox() {
        let c = cfg_with(&[("0403:6001", None)]);
        assert!(c.is_enabled());
        assert_eq!(c.devices.len(), 1);
        assert!(find(&c, id("0403:6001")).is_some());
        assert!(find(&c, id("1a86:7523")).is_none());
    }

    #[test]
    fn granting_the_same_device_twice_is_refused_not_duplicated() {
        // Silently deduplicating would hide that the second grant's busid_pin
        // never took effect; a grant is a consent record, so say so.
        let mut c = cfg_with(&[("0403:6001", None)]);
        let err = grant(
            &mut c,
            UsbGrant {
                device: id("0403:6001"),
                busid_pin: Some("3-2".into()),
                description: String::new(),
                granted_at_unix_ms: 2,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("0403:6001"), "{err}");
        assert!(err.contains("already"), "{err}");
        assert_eq!(c.devices.len(), 1);
        assert!(c.devices[0].busid_pin.is_none(), "the first grant stands");
    }

    #[test]
    fn revoking_removes_exactly_one_grant() {
        let mut c = cfg_with(&[("0403:6001", None), ("1a86:7523", None)]);
        revoke(&mut c, id("0403:6001")).unwrap();
        assert_eq!(c.devices.len(), 1);
        assert_eq!(c.devices[0].device, id("1a86:7523"));
        assert!(c.is_enabled(), "one grant remains");
    }

    #[test]
    fn revoking_the_last_grant_disables_usb_again() {
        let mut c = cfg_with(&[("0403:6001", None)]);
        revoke(&mut c, id("0403:6001")).unwrap();
        assert!(!c.is_enabled());
    }

    #[test]
    fn revoking_something_never_granted_is_an_error_not_a_silent_ok() {
        let mut c = UsbConfig::default();
        let err = revoke(&mut c, id("0403:6001")).unwrap_err().to_string();
        assert!(err.contains("0403:6001"), "{err}");
        assert!(err.contains("not granted"), "{err}");
    }

    #[test]
    fn a_busid_pin_must_look_like_a_busid() {
        let mut c = UsbConfig::default();
        for bad in ["", "3-2; rm -rf /", "../../etc", "3-2\n", &"9".repeat(64)] {
            let err = grant(
                &mut c,
                UsbGrant {
                    device: id("0403:6001"),
                    busid_pin: Some(bad.to_string()),
                    description: String::new(),
                    granted_at_unix_ms: 1,
                },
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("busid"), "{bad:?}: {err}");
        }
        assert!(c.devices.is_empty(), "nothing is persisted on rejection");
    }

    #[test]
    fn a_plausible_busid_pin_is_kept() {
        let c = cfg_with(&[("0403:6001", Some("3-2"))]);
        assert_eq!(c.devices[0].busid_pin.as_deref(), Some("3-2"));
        let c = cfg_with(&[("0403:6001", Some("1-1.4.2"))]);
        assert_eq!(c.devices[0].busid_pin.as_deref(), Some("1-1.4.2"));
    }

    #[test]
    fn grants_serialize_with_a_stable_shape() {
        let c = cfg_with(&[("0403:6001", Some("3-2"))]);
        let s = serde_json::to_string(&c).unwrap();
        assert!(s.contains(r#""device":{"vid":1027,"pid":24577}"#), "{s}");
        assert!(s.contains(r#""busid_pin":"3-2""#), "{s}");
        let back: UsbConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(back.devices[0].device, id("0403:6001"));
    }

    #[test]
    fn an_absent_usb_key_deserializes_to_no_grants() {
        let c: UsbConfig = serde_json::from_str("{}").unwrap();
        assert!(c.devices.is_empty());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core usb::grants`
Expected: FAIL — `UsbConfig` not found.

- [ ] **Step 3: Implement the grant model**

Write `crates/izba-core/src/usb/grants.rs` (above the tests):

```rust
//! Per-sandbox device grants — the consent record.
//!
//! Persisted on `SandboxConfig.usb`, i.e. inside the host-only managed truth
//! (`<data>/sandboxes/<name>/config.json`). Never in the overlay, never in a
//! virtiofs share, never in `izba.yml` (D8): hardware consent is
//! machine-specific and must not live in an agent-writable repo file. `izba rm`
//! removes the sandbox dir, so a reused name can never inherit hardware.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::DeviceId;

/// One standing grant (D7): it survives replug and re-attach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbGrant {
    pub device: DeviceId,
    /// Disambiguates two identical `vid:pid` devices (D9). `None` ⇒ the
    /// upstream must expose exactly one match or the attach is an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub busid_pin: Option<String>,
    /// Free text from the upstream's device record, for display only.
    #[serde(default)]
    pub description: String,
    pub granted_at_unix_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbConfig {
    #[serde(default)]
    pub devices: Vec<UsbGrant>,
}

impl UsbConfig {
    /// Whether this sandbox holds any hardware consent. This is the single
    /// input to the Phase-1 `UsbGuard`'s `sandbox_usb_enabled`.
    pub fn is_enabled(&self) -> bool {
        !self.devices.is_empty()
    }
}

/// A busid is a kernel-assigned port path like `3-2` or `1-1.4.2`. It is
/// upstream-supplied data that ends up in a protocol field and in logs, so it
/// is validated on the way in rather than sanitised on the way out.
fn valid_busid(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

pub fn find(cfg: &UsbConfig, device: DeviceId) -> Option<&UsbGrant> {
    cfg.devices.iter().find(|g| g.device == device)
}

pub fn grant(cfg: &mut UsbConfig, g: UsbGrant) -> Result<()> {
    if let Some(pin) = &g.busid_pin {
        if !valid_busid(pin) {
            bail!("'{pin}' is not a valid busid (expected e.g. 3-2 or 1-1.4.2)");
        }
    }
    if find(cfg, g.device).is_some() {
        bail!(
            "{} is already granted to this sandbox; revoke it first to change its pin",
            g.device
        );
    }
    cfg.devices.push(g);
    Ok(())
}

pub fn revoke(cfg: &mut UsbConfig, device: DeviceId) -> Result<()> {
    let before = cfg.devices.len();
    cfg.devices.retain(|g| g.device != device);
    if cfg.devices.len() == before {
        bail!("{device} is not granted to this sandbox");
    }
    Ok(())
}
```

Add `pub mod grants;` and `pub use grants::{UsbConfig, UsbGrant};` to
`usb/mod.rs`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p izba-core usb::grants`
Expected: PASS (10 tests).

- [ ] **Step 5: Write the failing `SandboxConfig` back-compat test**

Add to the `state.rs` test module (create one if absent, following the file's
existing conventions):

```rust
    #[test]
    fn a_config_written_before_usb_deserializes_with_no_grants() {
        // Disk-state back-compat: every sandbox on disk today predates the field.
        let json = r#"{"image_digest":"sha256:a","image_ref":"ubuntu:24.04",
            "cpus":2,"mem_mb":4096,"workspace":"/ws"}"#;
        let cfg: SandboxConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.usb.devices.is_empty());
        assert!(!cfg.usb.is_enabled());
    }
```

- [ ] **Step 6: Run to verify failure**

Run: `cargo test -p izba-core state::`
Expected: FAIL — no field `usb`.

- [ ] **Step 7: Add the field**

In `crates/izba-core/src/state.rs`, at the end of `SandboxConfig`:

```rust
    /// Standing USB device grants for this sandbox (host-only consent record).
    /// `serde(default)` keeps every `config.json` written before this feature
    /// deserializing — as no grants, i.e. USB disabled.
    #[serde(default)]
    pub usb: crate::usb::UsbConfig,
```

Then fix every `SandboxConfig { .. }` literal the compiler flags by adding
`usb: Default::default()`.

- [ ] **Step 8: Run the gates**

Run: `cargo test -p izba-core && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/izba-core/src/usb crates/izba-core/src/state.rs
git commit -m "feat(core): persist per-sandbox USB device grants"
```

---

### Task 4: Host-side device inventory

**Files:**
- Modify: `crates/izba-proto/src/usbip/op.rs` (publish framing constants),
  `crates/izba-core/src/usb/inventory.rs`
- Test: inline in both

**Interfaces:**
- Consumes: `izba_proto::usbip::{encode_op_req_devlist, decode_op_rep_devlist,
  UsbDeviceRecord, OP_COMMON_LEN, DEVICE_RECORD_LEN, INTERFACE_LEN, MAX_DEVICES}`;
  `usb::DeviceId`.
- Produces: `usb::inventory::{UpstreamDevice, read_devlist_reply, fetch}`.

The socket reader must learn the framing (a device count, and each record's
interface count) to know when the message ends — but it stays a *framer*: the
bytes it collects are handed to the Phase-1 decoder, which remains the only
validator whose output is used.

- [ ] **Step 1: Publish the framing constants**

In `crates/izba-proto/src/usbip/op.rs`, change these four `const` declarations to
`pub const`, and add to each a line of doc explaining it is a framing fact a
socket reader needs:

```rust
/// Length of the 8-byte `op_common` prefix. Public because a socket reader must
/// know how much to read before it can learn the message's real length.
pub const OP_COMMON_LEN: usize = 8;
/// Length of one device record — the framing stride for a devlist reply.
pub const DEVICE_RECORD_LEN: usize = 0x138;
/// Length of one interface descriptor that trails a devlist record.
pub const INTERFACE_LEN: usize = 4;
/// Maximum devices izba will accept in one devlist reply.
pub const MAX_DEVICES: u32 = 256;
```

Re-export them from `crates/izba-proto/src/usbip/mod.rs` alongside the existing
re-exports.

- [ ] **Step 2: Write the failing inventory tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use izba_proto::usbip::{DEVICE_RECORD_LEN, OP_COMMON_LEN, USBIP_VERSION};

    /// Build one 312-byte device record plus its interface descriptors.
    fn record(busid: &str, vid: u16, pid: u16, n_iface: u8) -> Vec<u8> {
        let mut b = vec![0u8; DEVICE_RECORD_LEN];
        let path = format!("/sys/devices/pci0000:00/usb{busid}");
        b[..path.len()].copy_from_slice(path.as_bytes());
        b[0x100..0x100 + busid.len()].copy_from_slice(busid.as_bytes());
        b[0x120..0x124].copy_from_slice(&3u32.to_be_bytes()); // busnum
        b[0x124..0x128].copy_from_slice(&2u32.to_be_bytes()); // devnum
        b[0x128..0x12C].copy_from_slice(&2u32.to_be_bytes()); // speed
        b[0x12C..0x12E].copy_from_slice(&vid.to_be_bytes());
        b[0x12E..0x130].copy_from_slice(&pid.to_be_bytes());
        b[0x137] = n_iface;
        b.extend(std::iter::repeat(0u8).take(n_iface as usize * 4));
        b
    }

    fn devlist_reply(records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        out.extend_from_slice(&0x0005u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // status
        out.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    #[test]
    fn parses_a_devlist_reply() {
        let reply = devlist_reply(&[
            record("3-2", 0x0403, 0x6001, 1),
            record("1-1.4", 0x1a86, 0x7523, 0),
        ]);
        let devices = read_devlist_reply(&mut std::io::Cursor::new(reply)).unwrap();

        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].busid, "3-2");
        assert_eq!(devices[0].id.to_string(), "0403:6001");
        assert_eq!(devices[1].id.to_string(), "1a86:7523");
    }

    #[test]
    fn an_empty_devlist_is_a_normal_answer_not_an_error() {
        // usbipd with nothing bound: the honest answer is "no devices", and the
        // CLI turns that into the `usbipd bind` hint.
        let devices =
            read_devlist_reply(&mut std::io::Cursor::new(devlist_reply(&[])))
                .unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn interface_descriptors_are_skipped_so_the_next_record_aligns() {
        // A record with the maximum interface count must not desynchronise the
        // reader — this is the framing bug that would silently mis-parse device 2.
        let reply = devlist_reply(&[record("3-2", 0x0403, 0x6001, 255), record("3-3", 0x1a86, 0x7523, 0)]);
        let devices = read_devlist_reply(&mut std::io::Cursor::new(reply)).unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[1].busid, "3-3");
    }

    #[test]
    fn a_claimed_device_count_beyond_the_cap_is_refused_before_reading_it() {
        // The count is attacker-controlled; it must bound the read, not be
        // trusted by it. 4 billion records must not become 4 billion reads.
        let mut reply = Vec::new();
        reply.extend_from_slice(&USBIP_VERSION.to_be_bytes());
        reply.extend_from_slice(&0x0005u16.to_be_bytes());
        reply.extend_from_slice(&0u32.to_be_bytes());
        reply.extend_from_slice(&u32::MAX.to_be_bytes());
        let err = read_devlist_reply(&mut std::io::Cursor::new(reply))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cap") || err.contains("too many"), "{err}");
    }

    #[test]
    fn a_truncated_reply_is_an_error_not_a_short_device_list() {
        let full = devlist_reply(&[record("3-2", 0x0403, 0x6001, 0)]);
        for cut in [0, 4, OP_COMMON_LEN, OP_COMMON_LEN + 4, full.len() - 1] {
            let err = read_devlist_reply(&mut std::io::Cursor::new(full[..cut].to_vec()));
            assert!(err.is_err(), "a reply cut at {cut} must not parse");
        }
    }

    #[test]
    fn a_wrong_version_reply_is_refused() {
        let mut reply = devlist_reply(&[]);
        reply[0..2].copy_from_slice(&0x0110u16.to_be_bytes());
        assert!(read_devlist_reply(&mut std::io::Cursor::new(reply)).is_err());
    }

    #[test]
    fn devices_matching_a_granted_id_are_identifiable() {
        let reply = devlist_reply(&[record("3-2", 0x0403, 0x6001, 0), record("3-3", 0x0403, 0x6001, 0)]);
        let devices = read_devlist_reply(&mut std::io::Cursor::new(reply)).unwrap();
        let id: crate::usb::DeviceId = "0403:6001".parse().unwrap();
        let matches: Vec<_> = devices.iter().filter(|d| d.id == id).collect();
        assert_eq!(matches.len(), 2, "two identical devices — D9's ambiguity case");
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p izba-core usb::inventory`
Expected: FAIL — `read_devlist_reply` not found.

- [ ] **Step 4: Implement the inventory**

Write `crates/izba-core/src/usb/inventory.rs` above its tests:

```rust
//! Host-side device inventory: one `OP_REQ_DEVLIST` exchange with the upstream.
//!
//! This is the ONLY thing izba asks an unconfigured-guest-free upstream for in
//! Phase 2, and it is always host-initiated. The guest never sees a device list
//! (D1/F-USB-9).
//!
//! Framing vs validation: a devlist reply is variable-length, so the reader must
//! read the device count and each record's interface count to know where the
//! message ends. It uses those two fields ONLY to bound its reads; every value
//! it returns comes from `izba_proto::usbip::decode_op_rep_devlist`, which
//! re-validates the whole buffer.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use izba_proto::usbip::{
    decode_op_rep_devlist, encode_op_req_devlist, UsbDeviceRecord, DEVICE_RECORD_LEN,
    INTERFACE_LEN, MAX_DEVICES, OP_COMMON_LEN,
};

use super::DeviceId;

/// One device the upstream currently exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamDevice {
    pub busid: String,
    pub id: DeviceId,
    pub description: String,
    pub speed: u32,
}

impl From<UsbDeviceRecord> for UpstreamDevice {
    fn from(r: UsbDeviceRecord) -> Self {
        Self {
            id: DeviceId {
                vid: r.id_vendor,
                pid: r.id_product,
            },
            description: r.path.clone(),
            busid: r.busid,
            speed: r.speed,
        }
    }
}

/// How long izbad waits on an upstream that accepted the connection but does
/// not answer. Short: this runs behind an interactive command.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Read one `OP_REP_DEVLIST` off `reply`.
///
/// The caller is responsible for having sent [`encode_op_req_devlist`] first;
/// this function never writes, which keeps the socket single-writer and lets
/// tests drive it from a plain `Cursor`.
pub fn read_devlist_reply<R: Read>(reply: &mut R) -> Result<Vec<UpstreamDevice>> {
    let mut buf = vec![0u8; OP_COMMON_LEN + 4];
    reply
        .read_exact(&mut buf)
        .context("reading the devlist reply header")?;

    let count = u32::from_be_bytes([
        buf[OP_COMMON_LEN],
        buf[OP_COMMON_LEN + 1],
        buf[OP_COMMON_LEN + 2],
        buf[OP_COMMON_LEN + 3],
    ]);
    if count > MAX_DEVICES {
        bail!("upstream claims {count} devices, above the {MAX_DEVICES} cap");
    }

    for _ in 0..count {
        let start = buf.len();
        buf.resize(start + DEVICE_RECORD_LEN, 0);
        reply
            .read_exact(&mut buf[start..])
            .context("reading a device record")?;
        // The interface count is the record's last byte; it is a u8, so the
        // trailing read self-bounds at 1020 bytes.
        let n_iface = buf[buf.len() - 1] as usize;
        let ifaces = start + DEVICE_RECORD_LEN;
        buf.resize(ifaces + n_iface * INTERFACE_LEN, 0);
        reply
            .read_exact(&mut buf[ifaces..])
            .context("reading interface descriptors")?;
    }

    let records = decode_op_rep_devlist(&buf).context("decoding the devlist reply")?;
    Ok(records.into_iter().map(UpstreamDevice::from).collect())
}

/// Dial `addr` and enumerate. Every phase is time-bounded so a wedged or
/// silently-accepting upstream cannot hang an interactive command.
// reason: real-socket glue — `read_devlist_reply` carries all the parsing, and
// exercising the dial/timeout wiring needs a bound listener, which the house
// unit-test constraint forbids.
#[mutants::skip]
pub fn fetch(addr: SocketAddr) -> Result<Vec<UpstreamDevice>> {
    let mut sock = TcpStream::connect_timeout(&addr, IO_TIMEOUT)
        .with_context(|| format!("connecting to the usbip upstream at {addr}"))?;
    sock.set_read_timeout(Some(IO_TIMEOUT))?;
    sock.set_write_timeout(Some(IO_TIMEOUT))?;
    sock.write_all(&encode_op_req_devlist())
        .context("sending OP_REQ_DEVLIST")?;
    sock.flush()?;
    read_devlist_reply(&mut sock)
}
```

**Watch the direction of the exchange.** The reader is named
`read_devlist_reply` and takes only a `Read` on purpose: it must never write to
the socket, so `fetch` owns sending the request and the socket stays
single-writer. An API where one function both writes the request and reads the
reply invites the read-before-write bug — and a test driving it from a
`Cursor` would not catch that, because a `Cursor` happily "replies" to a request
that was never sent.

writes to the socket.

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p izba-core usb::inventory && cargo test -p izba-proto usbip`
Expected: PASS.

- [ ] **Step 6: Run the gates and commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
git add crates/izba-proto/src/usbip crates/izba-core/src/usb/inventory.rs
git commit -m "feat(core): enumerate upstream USB devices over the usbip op phase"
```

---

### Task 5: `usbipd.exe state` enrichment

**Files:**
- Modify: `crates/izba-core/src/usb/usbipd_state.rs`
- Test: inline

**Interfaces:**
- Consumes: `usb::DeviceId`.
- Produces: `usb::usbipd_state::{UsbipdDevice, parse, bind_command, probe}`.

Why: `OP_REQ_DEVLIST` shows only devices already **bound**. The device the human
just plugged in is invisible until they run `usbipd bind` elevated — so without
this, izba's answer to "my ESP32 isn't listed" is silence. This reads
usbipd-win's own JSON to name the unbound device and print the exact command.
izba never elevates and never runs `bind` itself (constraint #5).

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "Devices": [
        {"BusId":"3-2","VendorId":"0403","ProductId":"6001",
         "Description":"USB Serial Converter","IsBound":false,"IsAttached":false},
        {"BusId":"1-4","VendorId":"1a86","ProductId":"7523",
         "Description":"USB-SERIAL CH340","IsBound":true,"IsAttached":false},
        {"BusId":"2-1","VendorId":"046d","ProductId":"c52b",
         "Description":"Unifying Receiver","IsBound":true,"IsAttached":true}
      ]
    }"#;

    #[test]
    fn parses_the_device_table() {
        let d = parse(SAMPLE).unwrap();
        assert_eq!(d.len(), 3);
        assert_eq!(d[0].busid, "3-2");
        assert_eq!(d[0].id.to_string(), "0403:6001");
        assert_eq!(d[0].description, "USB Serial Converter");
        assert!(!d[0].bound);
        assert!(d[1].bound && !d[1].attached);
        assert!(d[2].attached);
    }

    #[test]
    fn an_unbound_device_yields_the_exact_command_to_run() {
        let d = parse(SAMPLE).unwrap();
        let cmd = bind_command(&d[0]);
        assert_eq!(cmd, "usbipd bind --busid 3-2");
    }

    #[test]
    fn a_device_with_an_unparseable_id_is_dropped_not_fatal() {
        // One odd row must not blind the user to the rest of their hardware.
        let json = r#"{"Devices":[
            {"BusId":"3-2","VendorId":"zzzz","ProductId":"6001","Description":"x",
             "IsBound":false,"IsAttached":false},
            {"BusId":"1-4","VendorId":"1a86","ProductId":"7523","Description":"ok",
             "IsBound":true,"IsAttached":false}]}"#;
        let d = parse(json).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].description, "ok");
    }

    #[test]
    fn a_hostile_busid_is_dropped_so_it_can_never_reach_a_command_line() {
        let json = r#"{"Devices":[
            {"BusId":"3-2 & calc.exe","VendorId":"0403","ProductId":"6001",
             "Description":"x","IsBound":false,"IsAttached":false}]}"#;
        assert!(parse(json).unwrap().is_empty());
    }

    #[test]
    fn garbage_input_is_an_error_not_a_panic() {
        for bad in ["", "null", "[]", "{}", "{ not json", r#"{"Devices":3}"#] {
            let _ = parse(bad); // must not panic
        }
        assert!(parse("{ not json").is_err());
        assert!(parse("{}").unwrap().is_empty(), "no Devices key ⇒ nothing known");
    }

    #[test]
    fn output_beyond_the_cap_is_refused_before_parsing() {
        let big = "x".repeat(MAX_STATE_BYTES + 1);
        let err = parse(&big).unwrap_err().to_string();
        assert!(err.contains("too large"), "{err}");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core usb::usbipd_state`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
//! Read usbipd-win's own device table so izba can name a device the human has
//! plugged in but not yet shared.
//!
//! `OP_REQ_DEVLIST` only reports devices already bound, so without this the
//! answer to "why isn't my board listed?" is silence. This is a convenience
//! layer, never a control path: izba runs the read-only `state` verb, at a
//! fixed path, with a timeout and a size cap, and it NEVER runs `bind` (which
//! needs Administrator — constraint #5: izba prints the command, the human runs
//! it). Nothing here is reachable from a guest RPC.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use super::DeviceId;

/// Cap on the JSON izba will parse. A realistic table is a few KiB.
pub const MAX_STATE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbipdDevice {
    pub busid: String,
    pub id: DeviceId,
    pub description: String,
    pub bound: bool,
    pub attached: bool,
}

#[derive(Deserialize)]
struct StateFile {
    #[serde(default, rename = "Devices")]
    devices: Vec<StateRow>,
}

#[derive(Deserialize)]
struct StateRow {
    #[serde(rename = "BusId")]
    bus_id: String,
    #[serde(rename = "VendorId")]
    vendor_id: String,
    #[serde(rename = "ProductId")]
    product_id: String,
    #[serde(default, rename = "Description")]
    description: String,
    #[serde(default, rename = "IsBound")]
    is_bound: bool,
    #[serde(default, rename = "IsAttached")]
    is_attached: bool,
}

fn plausible_busid(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// Parse `usbipd state` JSON. Rows izba cannot make sense of are dropped rather
/// than failing the whole listing — one odd device must not hide the others.
pub fn parse(json: &str) -> Result<Vec<UsbipdDevice>> {
    if json.len() > MAX_STATE_BYTES {
        bail!("usbipd state output too large ({} bytes)", json.len());
    }
    let file: StateFile = serde_json::from_str(json).context("parsing usbipd state JSON")?;
    Ok(file
        .devices
        .into_iter()
        .filter_map(|r| {
            let id: DeviceId = format!("{}:{}", r.vendor_id, r.product_id).parse().ok()?;
            if !plausible_busid(&r.bus_id) {
                return None;
            }
            Some(UsbipdDevice {
                busid: r.bus_id,
                id,
                description: r.description,
                bound: r.is_bound,
                attached: r.is_attached,
            })
        })
        .collect())
}

/// The exact command the human must run elevated to share this device.
pub fn bind_command(d: &UsbipdDevice) -> String {
    format!("usbipd bind --busid {}", d.busid)
}

/// Run `usbipd.exe state` across the WSL interop boundary. Returns `None` on
/// any failure — this is decoration, and its absence must never fail a listing.
// reason: process-spawn glue across WSL interop; `parse`/`bind_command` carry
// the logic and are fully unit-tested.
#[mutants::skip]
pub fn probe() -> Option<Vec<UsbipdDevice>> {
    if !super::trust::running_under_wsl() {
        return None;
    }
    let out = std::process::Command::new("usbipd.exe")
        .args(["state"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    parse(&text).ok()
}
```

- [ ] **Step 4: Run to verify pass, then commit**

```bash
cargo test -p izba-core usb::usbipd_state
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
git add crates/izba-core/src/usb/usbipd_state.rs
git commit -m "feat(core): read usbipd state so izba can name unshared devices"
```

---

### Task 6: The daemon wire protocol

**Files:**
- Modify: `crates/izba-core/src/daemon/proto.rs`
- Test: extend `proto.rs`'s `tests` module

**Interfaces:**
- Consumes: `usb::{DeviceId, UsbGrant}`, `usb::inventory::UpstreamDevice`.
- Produces: `DaemonRequest::{UsbUpstreamShow, UsbUpstreamSet, UsbListDevices,
  UsbAllow, UsbRevoke, UsbStatus}`; `DaemonResponse::{UsbUpstream, UsbDevices,
  UsbStatus}`; `DAEMON_PROTO_VERSION = 3`.

- [ ] **Step 1: Write the failing tests**

Add to `proto.rs`'s test module:

```rust
    #[test]
    fn usb_requests_roundtrip() {
        for req in [
            DaemonRequest::UsbUpstreamShow,
            DaemonRequest::UsbUpstreamSet {
                host: "172.24.32.1".into(),
                port: 3240,
                allow_remote: false,
            },
            DaemonRequest::UsbListDevices,
            DaemonRequest::UsbAllow {
                name: "web".into(),
                device: "0403:6001".into(),
                busid_pin: Some("3-2".into()),
            },
            DaemonRequest::UsbRevoke {
                name: "web".into(),
                device: "0403:6001".into(),
            },
            DaemonRequest::UsbStatus { name: "web".into() },
        ] {
            let mut buf = Vec::new();
            write_frame(&mut buf, &req).unwrap();
            let back: DaemonRequest = read_frame(&mut std::io::Cursor::new(&buf)).unwrap();
            assert_eq!(format!("{req:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn usb_responses_roundtrip() {
        for resp in [
            DaemonResponse::UsbUpstream {
                upstream: Some(UsbUpstreamInfo {
                    host: "127.0.0.1".into(),
                    port: 3240,
                    resolved: Some("127.0.0.1".into()),
                    trust: "own-host-loopback".into(),
                    warning: None,
                }),
            },
            DaemonResponse::UsbUpstream { upstream: None },
            DaemonResponse::UsbDevices {
                devices: vec![UsbDeviceInfo {
                    busid: "3-2".into(),
                    device: "0403:6001".into(),
                    description: "USB Serial Converter".into(),
                    shared: true,
                    granted_to: vec!["web".into()],
                    bind_command: None,
                }],
            },
            DaemonResponse::UsbStatus {
                grants: vec![UsbGrantInfo {
                    device: "0403:6001".into(),
                    busid_pin: None,
                    description: "USB Serial Converter".into(),
                    granted_at_unix_ms: 1_700_000_000_000,
                }],
            },
        ] {
            let mut buf = Vec::new();
            write_frame(&mut buf, &resp).unwrap();
            let back: DaemonResponse = read_frame(&mut std::io::Cursor::new(&buf)).unwrap();
            assert_eq!(format!("{resp:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn usb_wire_tags_are_stable() {
        for (req, tag) in [
            (DaemonRequest::UsbUpstreamShow, r#""type":"usb_upstream_show""#),
            (DaemonRequest::UsbListDevices, r#""type":"usb_list_devices""#),
            (
                DaemonRequest::UsbStatus { name: "w".into() },
                r#""type":"usb_status""#,
            ),
        ] {
            let s = serde_json::to_string(&req).unwrap();
            assert!(s.contains(tag), "{s}");
        }
    }

    #[test]
    fn proto_version_is_bumped_for_the_new_request_variants() {
        // A same-version daemon predating these variants would fail the frame
        // read instead of self-healing, so the compatibility gate must move.
        assert_eq!(DAEMON_PROTO_VERSION, 3);
    }

    #[test]
    fn an_older_daemon_reads_a_usb_request_as_unknown_not_as_a_dropped_frame() {
        // The `#[serde(other)]` catch-all is what turns a version slip into an
        // honest error rather than a hung connection.
        let json = r#"{"type":"usb_list_devices"}"#;
        let back: DaemonRequest = serde_json::from_str(json).unwrap();
        assert!(matches!(back, DaemonRequest::UsbListDevices));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core daemon::proto`
Expected: FAIL — no variant `UsbUpstreamShow`.

- [ ] **Step 3: Implement the variants**

Bump the constant, extending its doc comment:

```rust
/// (v3 covers the `Usb*` control-plane requests; Phase 3's `UsbAttach`/
/// `UsbDetach` guest RPCs will take it to 4.)
pub const DAEMON_PROTO_VERSION: u32 = 3;
```

Add to `DaemonRequest`, **before** the `#[serde(other)] Unknown` arm:

```rust
    /// Report the configured usbip upstream and its trust classification.
    UsbUpstreamShow,
    /// Set (or replace) the usbip upstream. `allow_remote` opts into a
    /// globally-routable address, which is otherwise refused.
    UsbUpstreamSet {
        host: String,
        port: u16,
        #[serde(default)]
        allow_remote: bool,
    },
    /// Enumerate what the upstream exports, annotated with existing grants.
    UsbListDevices,
    /// Grant one `vid:pid` to one sandbox. The device is a string on the wire so
    /// a malformed id is a clean daemon-side error, not a frame-read failure.
    UsbAllow {
        name: String,
        device: String,
        #[serde(default)]
        busid_pin: Option<String>,
    },
    /// Withdraw a grant; tears down any live stream for it (Phase 3).
    UsbRevoke {
        name: String,
        device: String,
    },
    /// List a sandbox's grants.
    UsbStatus {
        name: String,
    },
```

Add the payload structs above `DaemonResponse`:

```rust
/// The configured upstream, as reported to a human.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbUpstreamInfo {
    pub host: String,
    pub port: u16,
    /// The address `host` currently resolves to, when it resolves.
    pub resolved: Option<String>,
    /// `UpstreamTrust` rendered as a stable kebab-case token.
    pub trust: String,
    /// The human-facing note for that trust class, when there is one.
    pub warning: Option<String>,
}

/// One device the upstream exports (or that usbipd knows but has not shared).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDeviceInfo {
    pub busid: String,
    /// Canonical `vid:pid`.
    pub device: String,
    pub description: String,
    /// Whether the upstream is currently exporting it (`OP_REP_DEVLIST`).
    pub shared: bool,
    /// Sandboxes already holding a grant for this `vid:pid`.
    #[serde(default)]
    pub granted_to: Vec<String>,
    /// For an unshared device: the exact command the human must run elevated.
    #[serde(default)]
    pub bind_command: Option<String>,
}

/// One standing grant, as reported to a human.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbGrantInfo {
    pub device: String,
    pub busid_pin: Option<String>,
    pub description: String,
    pub granted_at_unix_ms: u64,
}
```

Add to `DaemonResponse`:

```rust
    UsbUpstream {
        upstream: Option<UsbUpstreamInfo>,
    },
    UsbDevices {
        devices: Vec<UsbDeviceInfo>,
    },
    UsbStatus {
        grants: Vec<UsbGrantInfo>,
    },
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p izba-core daemon::proto`
Expected: PASS.

- [ ] **Step 5: Run the full gates (the app embeds these types)**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
```

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/daemon/proto.rs
git commit -m "feat(core): add the USB control-plane daemon RPCs (proto 3)"
```

---

### Task 7: Daemon handlers and the live `UsbGuard`

**Files:**
- Modify: `crates/izba-core/src/daemon/server.rs`,
  `crates/izba-core/src/daemon/egress/mod.rs`,
  `crates/izba-core/src/usb/mod.rs`
- Test: `server.rs` test module; `egress/mod.rs` test module

**Interfaces:**
- Consumes: everything from Tasks 1–6.
- Produces: `usb::resolve_upstream(&UsbSettings) -> Option<(IpAddr, u16)>`;
  `usb::guard_for(&Paths, &str) -> router::UsbGuard`;
  `EgressManager::apply_usb_guard(&str, UsbGuard)`.

Two security-load-bearing behaviours here, each with its own test:

1. **Fail-closed gate.** Every USB handler except `UsbUpstreamShow`/`Set`
   refuses with "usb passthrough is not configured" *before* it reads any
   address or label field.
2. **The guard is live.** `apply_usb_guard` mirrors `apply_policy`, so revoking
   the last grant reopens LAN access on the next connection instead of at the
   next VM restart, and granting the first one closes it immediately.

- [ ] **Step 1: Write the failing guard-population tests**

In `crates/izba-core/src/daemon/egress/mod.rs`'s test module:

```rust
    #[test]
    fn a_sandbox_with_no_grants_gets_a_disabled_guard() {
        let (_d, paths) = test_paths();
        let g = crate::usb::guard_for(&paths, "web");
        assert!(!g.sandbox_usb_enabled);
        assert!(g.upstream.is_none(), "no upstream is configured");
    }

    #[test]
    fn a_granted_sandbox_gets_an_enabled_guard_carrying_the_upstream() {
        let (_d, paths) = test_paths();
        crate::usb::settings::save(
            &paths.usb_dir(),
            &crate::usb::UsbSettings {
                upstream: Some(crate::usb::Upstream {
                    host: "127.0.0.1".into(),
                    port: 3240,
                }),
                allow_remote_upstream: false,
            },
        )
        .unwrap();
        let mut cfg = test_sandbox_config();
        crate::usb::grants::grant(
            &mut cfg.usb,
            crate::usb::UsbGrant {
                device: "0403:6001".parse().unwrap(),
                busid_pin: None,
                description: String::new(),
                granted_at_unix_ms: 1,
            },
        )
        .unwrap();
        crate::state::save_json(&paths.sandbox_dir("web").join("config.json"), &cfg).unwrap();

        let g = crate::usb::guard_for(&paths, "web");
        assert!(g.sandbox_usb_enabled);
        assert_eq!(
            g.upstream,
            Some(("127.0.0.1".parse().unwrap(), 3240)),
            "the guard denies the configured endpoint on its own port"
        );
    }

    #[test]
    fn apply_usb_guard_swaps_a_live_slot() {
        // Revoking the last grant must reopen LAN on the NEXT connection, not at
        // the next VM restart — the same liveness contract as apply_policy.
        let mgr = mgr();
        mgr.insert_for_test("web");
        assert_eq!(mgr.slot_usb_guard("web").map(|g| g.sandbox_usb_enabled), Some(false));
        mgr.apply_usb_guard(
            "web",
            router::UsbGuard {
                sandbox_usb_enabled: true,
                upstream: None,
            },
        );
        assert_eq!(mgr.slot_usb_guard("web").map(|g| g.sandbox_usb_enabled), Some(true));
    }

    #[test]
    fn apply_usb_guard_on_an_unknown_sandbox_is_a_noop() {
        let mgr = mgr();
        mgr.apply_usb_guard("ghost", router::UsbGuard::default());
        assert!(mgr.slot_usb_guard("ghost").is_none());
    }
```

Add a `test_sandbox_config()` helper to that module building a minimal
`SandboxConfig` (mirroring the one in `server.rs`'s tests).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core daemon::egress`
Expected: FAIL — `guard_for` / `apply_usb_guard` not found.

- [ ] **Step 3: Implement guard resolution and the live cell**

In `usb/mod.rs`:

```rust
/// Resolve the configured upstream to an address the egress guard can compare
/// against. `None` when USB is unconfigured or the host does not resolve — the
/// guard then falls back to the well-known port alone, which is the honest
/// answer rather than a guess.
pub fn resolve_upstream(s: &UsbSettings) -> Option<(std::net::IpAddr, u16)> {
    use std::net::ToSocketAddrs;
    let up = s.upstream.as_ref()?;
    if let Ok(ip) = up.host.parse::<std::net::IpAddr>() {
        return Some((ip, up.port));
    }
    (up.host.as_str(), up.port)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|sa| (sa.ip(), up.port))
}

/// Build the egress USB guard for one sandbox: enabled exactly when it holds a
/// grant, carrying the configured upstream endpoint so the guard can deny it by
/// address as well as by the well-known port (a usbipd is multi-homed).
pub fn guard_for(
    paths: &crate::paths::Paths,
    name: &str,
) -> crate::daemon::egress::router::UsbGuard {
    let enabled = crate::state::load_json::<crate::state::SandboxConfig>(
        &paths.sandbox_dir(name).join("config.json"),
    )
    .ok()
    .flatten()
    .map(|c| c.usb.is_enabled())
    .unwrap_or(false);
    crate::daemon::egress::router::UsbGuard {
        sandbox_usb_enabled: enabled,
        upstream: resolve_upstream(&settings::load(&paths.usb_dir())),
    }
}
```

In `egress/mod.rs`, add a `UsbGuardCell` next to `PolicyCell` (same shape: a
`Mutex<UsbGuard>` with `load`/`store`), store it on `EgressSlot`, hand a clone
to the accept thread, read it per connection, and replace the
`router::UsbGuard::default()` argument with `guard_cell.load()`. Add:

```rust
    /// Hot-swap `name`'s USB guard (grant/revoke). Takes effect on the next
    /// connection; no-op when `name` has no live slot.
    pub fn apply_usb_guard(&self, name: &str, guard: router::UsbGuard) {
        if let Some(slot) = self.inner.lock().unwrap().get(name) {
            slot.usb.store(guard);
        }
    }

    #[cfg(test)]
    fn slot_usb_guard(&self, name: &str) -> Option<router::UsbGuard> {
        self.inner.lock().unwrap().get(name).map(|s| s.usb.load())
    }
```

and initialise the slot's cell in `ensure_listening` from
`crate::usb::guard_for(paths, name)`, replacing the Phase-1 comment about the
defaulted guard with one naming the new source of truth.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p izba-core daemon::egress`
Expected: PASS.

- [ ] **Step 5: Write the failing handler tests**

In `server.rs`'s test module (using the existing `test_daemon`/`rpc` helpers):

```rust
    #[test]
    fn usb_requests_refuse_when_no_upstream_is_configured() {
        let (_tmp, d) = test_daemon();
        let mut c = client_conn(&d);
        for req in [
            DaemonRequest::UsbListDevices,
            DaemonRequest::UsbAllow {
                name: "web".into(),
                device: "0403:6001".into(),
                busid_pin: None,
            },
            DaemonRequest::UsbRevoke {
                name: "web".into(),
                device: "0403:6001".into(),
            },
            DaemonRequest::UsbStatus { name: "web".into() },
        ] {
            match rpc(&mut c, &req) {
                DaemonResponse::Error { message } => assert!(
                    message.contains("not configured"),
                    "{req:?} must refuse before touching its fields: {message}"
                ),
                other => panic!("{req:?} must refuse when USB is off, got {other:?}"),
            }
        }
    }

    #[test]
    fn usb_upstream_show_is_answerable_with_the_feature_off() {
        // The one thing a user must be able to ask before configuring anything.
        let (_tmp, d) = test_daemon();
        let mut c = client_conn(&d);
        match rpc(&mut c, &DaemonRequest::UsbUpstreamShow) {
            DaemonResponse::UsbUpstream { upstream } => assert!(upstream.is_none()),
            other => panic!("expected UsbUpstream, got {other:?}"),
        }
    }

    #[test]
    fn setting_a_loopback_upstream_persists_it_without_a_warning() {
        let (tmp, d) = test_daemon();
        let mut c = client_conn(&d);
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbUpstreamSet {
                host: "127.0.0.1".into(),
                port: 3240,
                allow_remote: false,
            },
        ));
        let s = crate::usb::settings::load(&d.paths.usb_dir());
        assert_eq!(s.upstream.as_ref().unwrap().host, "127.0.0.1");
        let _ = tmp;

        match rpc(&mut c, &DaemonRequest::UsbUpstreamShow) {
            DaemonResponse::UsbUpstream { upstream } => {
                let u = upstream.unwrap();
                assert_eq!(u.trust, "own-host-loopback");
                assert!(u.warning.is_none(), "loopback is the recommended setup");
            }
            other => panic!("expected UsbUpstream, got {other:?}"),
        }
    }

    #[test]
    fn a_public_upstream_is_refused_unless_explicitly_allowed() {
        let (_tmp, d) = test_daemon();
        let mut c = client_conn(&d);
        match rpc(
            &mut c,
            &DaemonRequest::UsbUpstreamSet {
                host: "203.0.113.7".into(),
                port: 3240,
                allow_remote: false,
            },
        ) {
            DaemonResponse::Error { message } => {
                assert!(message.contains("internet") || message.contains("public"), "{message}");
                assert!(message.contains("--allow-remote"), "name the opt-in: {message}");
            }
            other => panic!("a public upstream must be refused, got {other:?}"),
        }
        assert!(
            crate::usb::settings::load(&d.paths.usb_dir()).upstream.is_none(),
            "a refused upstream must not be persisted"
        );
    }

    #[test]
    fn allow_then_status_then_revoke_round_trips_through_disk() {
        let (tmp, d) = test_daemon();
        let mut c = client_conn(&d);
        rpc(&mut c, &create_req(&tmp, "web"));
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbUpstreamSet {
                host: "127.0.0.1".into(),
                port: 3240,
                allow_remote: false,
            },
        ));
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbAllow {
                name: "web".into(),
                device: "0403:6001".into(),
                busid_pin: None,
            },
        ));

        match rpc(&mut c, &DaemonRequest::UsbStatus { name: "web".into() }) {
            DaemonResponse::UsbStatus { grants } => {
                assert_eq!(grants.len(), 1);
                assert_eq!(grants[0].device, "0403:6001");
            }
            other => panic!("expected UsbStatus, got {other:?}"),
        }

        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbRevoke {
                name: "web".into(),
                device: "0403:6001".into(),
            },
        ));
        match rpc(&mut c, &DaemonRequest::UsbStatus { name: "web".into() }) {
            DaemonResponse::UsbStatus { grants } => assert!(grants.is_empty()),
            other => panic!("expected UsbStatus, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_device_id_is_a_clean_error_not_a_grant() {
        let (tmp, d) = test_daemon();
        let mut c = client_conn(&d);
        rpc(&mut c, &create_req(&tmp, "web"));
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbUpstreamSet {
                host: "127.0.0.1".into(),
                port: 3240,
                allow_remote: false,
            },
        ));
        match rpc(
            &mut c,
            &DaemonRequest::UsbAllow {
                name: "web".into(),
                device: "not-an-id".into(),
                busid_pin: None,
            },
        ) {
            DaemonResponse::Error { message } => assert!(message.contains("vid:pid"), "{message}"),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn granting_to_a_sandbox_that_does_not_exist_is_refused() {
        let (_tmp, d) = test_daemon();
        let mut c = client_conn(&d);
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::UsbUpstreamSet {
                host: "127.0.0.1".into(),
                port: 3240,
                allow_remote: false,
            },
        ));
        match rpc(
            &mut c,
            &DaemonRequest::UsbAllow {
                name: "ghost".into(),
                device: "0403:6001".into(),
                busid_pin: None,
            },
        ) {
            DaemonResponse::Error { .. } => {}
            other => panic!("expected an error, got {other:?}"),
        }
    }
```

Add a small `expect_ok_resp(resp)` helper to that module if one does not exist,
asserting `DaemonResponse::Ok` and panicking with the message otherwise.

- [ ] **Step 6: Run to verify failure**

Run: `cargo test -p izba-core daemon::server`
Expected: FAIL — non-exhaustive match in `dispatch_inner`.

- [ ] **Step 7: Implement the handlers**

Add arms to `dispatch_inner` (one line each, per the file's convention), placed
before the `Unknown` arm:

```rust
        DaemonRequest::UsbUpstreamShow => handle_usb_upstream_show(d),
        DaemonRequest::UsbUpstreamSet {
            host,
            port,
            allow_remote,
        } => handle_usb_upstream_set(d, host, port, allow_remote),
        DaemonRequest::UsbListDevices => handle_usb_list_devices(d),
        DaemonRequest::UsbAllow {
            name,
            device,
            busid_pin,
        } => handle_usb_allow(d, name, device, busid_pin),
        DaemonRequest::UsbRevoke { name, device } => handle_usb_revoke(d, name, device),
        DaemonRequest::UsbStatus { name } => handle_usb_status(d, name),
```

And the handlers:

```rust
/// The fail-closed gate. Called FIRST in every USB handler except the two
/// upstream verbs — before any address, label, or sandbox name is examined —
/// so that a daemon with USB unconfigured has no USB code path a caller can
/// drive at all.
fn usb_settings_or_refuse(d: &Arc<Daemon>) -> anyhow::Result<crate::usb::UsbSettings> {
    let s = crate::usb::settings::load(&d.paths.usb_dir());
    if !crate::usb::is_configured(&s) {
        bail!(
            "usb passthrough is not configured — run `izba usb upstream set <host>` \
             to point izba at a usbip server"
        );
    }
    Ok(s)
}

/// Classify an upstream host, resolving it if needed.
fn classify_upstream(host: &str, port: u16) -> (Option<std::net::IpAddr>, crate::usb::trust::UpstreamTrust) {
    let resolved = crate::usb::resolve_upstream(&crate::usb::UsbSettings {
        upstream: Some(crate::usb::Upstream {
            host: host.to_string(),
            port,
        }),
        allow_remote_upstream: false,
    })
    .map(|(ip, _)| ip);
    let trust = match resolved {
        Some(ip) => crate::usb::trust::classify(
            ip,
            crate::usb::trust::host_default_gateway(),
            crate::usb::trust::running_under_wsl(),
        ),
        // An unresolvable host is treated as the most dangerous class rather
        // than the safest: izba does not know whose machine it is.
        None => crate::usb::trust::UpstreamTrust::Public,
    };
    (resolved, trust)
}

fn trust_token(t: crate::usb::trust::UpstreamTrust) -> &'static str {
    use crate::usb::trust::UpstreamTrust as T;
    match t {
        T::OwnHostLoopback => "own-host-loopback",
        T::OwnHostWslGateway => "own-host-wsl-gateway",
        T::PrivateLan => "private-lan",
        T::Public => "public",
    }
}

fn handle_usb_upstream_show(d: &Arc<Daemon>) -> anyhow::Result<DaemonResponse> {
    let s = crate::usb::settings::load(&d.paths.usb_dir());
    let Some(up) = s.upstream.clone() else {
        return Ok(DaemonResponse::UsbUpstream { upstream: None });
    };
    let (resolved, trust) = classify_upstream(&up.host, up.port);
    Ok(DaemonResponse::UsbUpstream {
        upstream: Some(crate::daemon::proto::UsbUpstreamInfo {
            warning: crate::usb::trust::describe(trust, &up.host),
            trust: trust_token(trust).to_string(),
            resolved: resolved.map(|ip| ip.to_string()),
            host: up.host,
            port: up.port,
        }),
    })
}

fn handle_usb_upstream_set(
    d: &Arc<Daemon>,
    host: String,
    port: u16,
    allow_remote: bool,
) -> anyhow::Result<DaemonResponse> {
    let (_resolved, trust) = classify_upstream(&host, port);
    if crate::usb::trust::is_refused(trust, allow_remote) {
        bail!(
            "refusing to use '{host}' as a usbip upstream: it is reachable from the \
             internet, and USB/IP has no authentication or encryption. Pass \
             --allow-remote if you genuinely mean it."
        );
    }
    let mut s = crate::usb::settings::load(&d.paths.usb_dir());
    s.upstream = Some(crate::usb::Upstream { host, port });
    s.allow_remote_upstream = allow_remote;
    crate::usb::settings::save(&d.paths.usb_dir(), &s)?;
    Ok(DaemonResponse::Ok)
}

fn handle_usb_list_devices(d: &Arc<Daemon>) -> anyhow::Result<DaemonResponse> {
    let s = usb_settings_or_refuse(d)?;
    let (ip, port) = crate::usb::resolve_upstream(&s)
        .ok_or_else(|| anyhow::anyhow!("the configured usbip upstream does not resolve"))?;
    let shared = crate::usb::inventory::fetch(std::net::SocketAddr::new(ip, port))?;
    Ok(DaemonResponse::UsbDevices {
        devices: crate::usb::list_devices(&d.paths, &shared, crate::usb::usbipd_state::probe()),
    })
}

fn handle_usb_allow(
    d: &Arc<Daemon>,
    name: String,
    device: String,
    busid_pin: Option<String>,
) -> anyhow::Result<DaemonResponse> {
    let _ = usb_settings_or_refuse(d)?;
    let id: crate::usb::DeviceId = device.parse()?;
    sandbox_must_exist(&d.paths, &name)?;
    let path = d.paths.sandbox_dir(&name).join("config.json");
    let mut cfg: crate::state::SandboxConfig = crate::state::load_json(&path)?
        .ok_or_else(|| anyhow::anyhow!("sandbox '{name}' has no config"))?;
    crate::usb::grants::grant(
        &mut cfg.usb,
        crate::usb::UsbGrant {
            device: id,
            busid_pin,
            description: String::new(),
            granted_at_unix_ms: crate::state::now_unix_ms(),
        },
    )?;
    crate::state::save_json(&path, &cfg)?;
    d.egress.apply_usb_guard(&name, crate::usb::guard_for(&d.paths, &name));
    Ok(DaemonResponse::Ok)
}

fn handle_usb_revoke(
    d: &Arc<Daemon>,
    name: String,
    device: String,
) -> anyhow::Result<DaemonResponse> {
    let _ = usb_settings_or_refuse(d)?;
    let id: crate::usb::DeviceId = device.parse()?;
    sandbox_must_exist(&d.paths, &name)?;
    let path = d.paths.sandbox_dir(&name).join("config.json");
    let mut cfg: crate::state::SandboxConfig = crate::state::load_json(&path)?
        .ok_or_else(|| anyhow::anyhow!("sandbox '{name}' has no config"))?;
    crate::usb::grants::revoke(&mut cfg.usb, id)?;
    crate::state::save_json(&path, &cfg)?;
    d.egress.apply_usb_guard(&name, crate::usb::guard_for(&d.paths, &name));
    Ok(DaemonResponse::Ok)
}

fn handle_usb_status(d: &Arc<Daemon>, name: String) -> anyhow::Result<DaemonResponse> {
    let _ = usb_settings_or_refuse(d)?;
    sandbox_must_exist(&d.paths, &name)?;
    let cfg: crate::state::SandboxConfig =
        crate::state::load_json(&d.paths.sandbox_dir(&name).join("config.json"))?
            .ok_or_else(|| anyhow::anyhow!("sandbox '{name}' has no config"))?;
    Ok(DaemonResponse::UsbStatus {
        grants: cfg
            .usb
            .devices
            .iter()
            .map(|g| crate::daemon::proto::UsbGrantInfo {
                device: g.device.to_string(),
                busid_pin: g.busid_pin.clone(),
                description: g.description.clone(),
                granted_at_unix_ms: g.granted_at_unix_ms,
            })
            .collect(),
    })
}
```

Add to `usb/mod.rs` the pure annotation function (unit-tested there, so the
daemon handler stays glue):

```rust
/// Annotate the upstream's exported devices with existing grants, and append
/// the devices usbipd knows about but has not shared — each carrying the exact
/// command the human must run elevated to share it.
pub fn list_devices(
    paths: &crate::paths::Paths,
    shared: &[inventory::UpstreamDevice],
    known: Option<Vec<usbipd_state::UsbipdDevice>>,
) -> Vec<crate::daemon::proto::UsbDeviceInfo> {
    let grants = grants_by_device(paths);
    let mut out: Vec<_> = shared
        .iter()
        .map(|d| crate::daemon::proto::UsbDeviceInfo {
            busid: d.busid.clone(),
            device: d.id.to_string(),
            description: d.description.clone(),
            shared: true,
            granted_to: grants.get(&d.id).cloned().unwrap_or_default(),
            bind_command: None,
        })
        .collect();
    for k in known.unwrap_or_default().into_iter().filter(|k| !k.bound) {
        out.push(crate::daemon::proto::UsbDeviceInfo {
            bind_command: Some(usbipd_state::bind_command(&k)),
            granted_to: grants.get(&k.id).cloned().unwrap_or_default(),
            busid: k.busid,
            device: k.id.to_string(),
            description: k.description,
            shared: false,
        });
    }
    out
}
```

plus a `grants_by_device(paths) -> HashMap<DeviceId, Vec<String>>` that walks
`paths.sandboxes_dir()` reading each `config.json`. Write unit tests for
`list_devices` in `usb/mod.rs` covering: a shared device with two granting
sandboxes; an unshared device carrying a bind command; and a bound-but-unshared
device appearing exactly once.

If `crate::state::now_unix_ms()` does not exist, add it there next to
`save_json` (a thin `SystemTime::now()` reader with `#[mutants::skip]` and a
justification), or reuse whatever the codebase already uses for
`started_unix_ms`.

- [ ] **Step 8: Run the gates**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/izba-core/src/daemon crates/izba-core/src/usb crates/izba-core/src/state.rs
git commit -m "feat(core): serve the USB control plane and drive the egress guard from grants"
```

---

### Task 8: The `izba usb` CLI

**Files:**
- Create: `crates/izba-cli/src/commands/usb.rs`,
  `crates/izba-cli/tests/usb_cli.rs`
- Modify: `crates/izba-cli/src/commands/mod.rs`,
  `crates/izba-cli/src/main.rs`, `crates/izba-cli/src/commands/policy.rs`
- Test: inline in `usb.rs` (consent logic) + the ungated integration test

**Interfaces:**
- Consumes: the Task 6 RPCs.
- Produces: `commands::usb::{UsbCmd, run}`.

Surface (spec §6.3), advanced-user oriented per constraint #5:

```
izba usb upstream show
izba usb upstream set <HOST[:PORT]> [--allow-remote]
izba usb list
izba usb allow <SANDBOX> --device <VID:PID> [--busid <BUSID>] [--confirm <VID:PID>]
izba usb revoke <SANDBOX> --device <VID:PID>
izba usb status <SANDBOX>
```

- [ ] **Step 1: Write the failing consent tests**

In `crates/izba-cli/src/commands/usb.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_banner_states_every_consequence_of_a_grant() {
        let b = consent_banner("web", "0403:6001", "USB Serial Converter");
        for must in [
            "0403:6001",
            "web",
            "USB Serial Converter",
            // Raw transfer-level access: reflash, brick.
            "reflash",
            // The egress firewall cannot see USB traffic (F-USB-7).
            "egress firewall",
            // Exclusive while attached.
            "unavailable to the host",
            // F-USB-3: izba can only verify what the server reports.
            "cannot verify",
        ] {
            assert!(b.contains(must), "banner must mention {must:?}:\n{b}");
        }
    }

    #[test]
    fn confirmation_requires_the_exact_device_id_typed_back() {
        let id = "0403:6001";
        assert!(confirm_matches(id, "0403:6001"));
        assert!(confirm_matches(id, " 0403:6001\n"), "trims whitespace");
        assert!(confirm_matches(id, "0403:6001"), "already canonical");
        for wrong in ["", "y", "yes", "0403:6002", "1a86:7523", "0403", "6001"] {
            assert!(!confirm_matches(id, wrong), "must reject {wrong:?}");
        }
    }

    #[test]
    fn an_uppercase_confirmation_of_the_same_device_is_accepted() {
        // The human is retyping an id they read off a listing; case is not the
        // thing being confirmed, the device is.
        assert!(confirm_matches("1a86:7523", "1A86:7523"));
    }

    #[test]
    fn a_non_interactive_grant_needs_the_confirm_flag() {
        let err = resolve_confirmation("0403:6001", None, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--confirm"), "{err}");
        assert!(err.contains("not a terminal"), "{err}");
    }

    #[test]
    fn a_non_interactive_grant_with_a_matching_confirm_flag_proceeds() {
        assert!(resolve_confirmation("0403:6001", Some("0403:6001"), false).unwrap());
    }

    #[test]
    fn a_non_interactive_grant_with_a_mismatched_confirm_flag_is_refused() {
        let err = resolve_confirmation("0403:6001", Some("1a86:7523"), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn upstream_arg_parses_host_and_optional_port() {
        assert_eq!(parse_upstream_arg("127.0.0.1").unwrap(), ("127.0.0.1".to_string(), 3240));
        assert_eq!(parse_upstream_arg("host.local:1234").unwrap(), ("host.local".to_string(), 1234));
        assert_eq!(parse_upstream_arg("[::1]:9").unwrap(), ("::1".to_string(), 9));
        // A bare IPv6 literal has colons but no port.
        assert_eq!(parse_upstream_arg("fd00::1").unwrap(), ("fd00::1".to_string(), 3240));
        for bad in ["", ":", "host:", "host:0", "host:99999", "host:abc"] {
            assert!(parse_upstream_arg(bad).is_err(), "must reject {bad:?}");
        }
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-cli usb`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the command**

Write `crates/izba-cli/src/commands/usb.rs` following `volume.rs`'s shape
(clap `Subcommand`, `run(paths, cmd) -> anyhow::Result<i32>`, `DaemonClient`,
`super::expect_ok`). Key pieces:

```rust
//! `izba usb` — configure a usbip upstream and grant devices to sandboxes.
//!
//! Deliberately thin (constraint #5): izba never runs `usbipd bind` and never
//! elevates. When a device needs sharing, izba prints the exact command for the
//! human to run themselves.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{bail, Result};
use clap::Subcommand;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use izba_core::usb::settings::DEFAULT_UPSTREAM_PORT;

#[derive(Debug, Subcommand)]
pub enum UsbCmd {
    /// Show or set the usbip upstream izba dials
    #[command(subcommand)]
    Upstream(UpstreamCmd),
    /// List devices the upstream exports (and ones it knows but has not shared)
    List,
    /// Grant one device to one sandbox (requires typing the device id back)
    Allow {
        /// Sandbox name
        name: String,
        /// Device to grant, as VID:PID (e.g. 0403:6001)
        #[arg(short, long)]
        device: String,
        /// Pin the grant to one busid when two identical devices are present
        #[arg(long)]
        busid: Option<String>,
        /// Non-interactive confirmation: must equal --device
        #[arg(long)]
        confirm: Option<String>,
    },
    /// Withdraw a device grant from a sandbox
    Revoke {
        name: String,
        #[arg(short, long)]
        device: String,
    },
    /// Show a sandbox's device grants
    Status { name: String },
}

#[derive(Debug, Subcommand)]
pub enum UpstreamCmd {
    /// Print the configured upstream and how much izba trusts it
    Show,
    /// Point izba at a usbip server (HOST or HOST:PORT; default port 3240)
    Set {
        target: String,
        /// Permit a globally-routable upstream (NOT recommended)
        #[arg(long)]
        allow_remote: bool,
    },
}

/// Split `HOST` / `HOST:PORT` / `[V6]:PORT`, defaulting the port.
pub(crate) fn parse_upstream_arg(s: &str) -> Result<(String, u16)> { /* ... */ }

/// The loud consent banner (spec §6.1). Every clause here is a consequence the
/// human is accepting, not decoration.
pub(crate) fn consent_banner(sandbox: &str, device: &str, description: &str) -> String {
    format!(
        "\
⚠  Granting {device} ({description}) to sandbox '{sandbox}'.

The agent in that sandbox gets raw, transfer-level access to this device. It can
reflash it, change its firmware, or permanently damage it.

USB traffic is NOT visible to the egress firewall: `izba netlog` will not show
what crosses this link, and no allow-list applies to it.

While attached, the device is unavailable to the host and to every other sandbox.

izba cannot verify that this is the physical object in front of you — the USB/IP
protocol carries no serial number, and a device asserts its own {device}.

Type the device id to confirm: "
    )
}

/// Whether `typed` confirms `device`. Case-insensitive and whitespace-trimmed:
/// the human is retyping an id off a listing, and the device is what is being
/// confirmed, not the formatting.
pub(crate) fn confirm_matches(device: &str, typed: &str) -> bool {
    typed.trim().eq_ignore_ascii_case(device.trim())
}

/// Decide whether a grant may proceed. Interactive ⇒ the caller prompts;
/// non-interactive ⇒ `--confirm` must be present and match (a script cannot
/// answer a prompt, so name the flag instead of hanging or silently aborting).
pub(crate) fn resolve_confirmation(
    device: &str,
    confirm: Option<&str>,
    is_tty: bool,
) -> Result<bool> {
    match confirm {
        Some(c) if confirm_matches(device, c) => Ok(true),
        Some(c) => bail!("--confirm '{c}' does not match --device '{device}'"),
        None if is_tty => Ok(false), // caller prompts
        None => bail!(
            "refusing to grant {device} without confirmation: stdin is not a terminal \
             — re-run with --confirm {device}"
        ),
    }
}
```

The `allow` path: `resolve_confirmation` → if it returned `false`, print the
banner, read a line, and require `confirm_matches`; then send `UsbAllow`. Mark
the real-stdin wrapper `#[mutants::skip]` with a justification, exactly as
`volume.rs` does for `confirm_destructive`.

The `list` renderer must print the `bind_command` line for unshared devices —
that is the whole point of Task 5. Something like:

```
BUSID    DEVICE      SHARED  GRANTED TO   DESCRIPTION
3-2      0403:6001   yes     web          USB Serial Converter
1-4      1a86:7523   no      -            USB-SERIAL CH340
  ↳ not shared yet — run this elevated on the USB host:  usbipd bind --busid 1-4
```

Register the command: `pub mod usb;` in `commands/mod.rs`, `Usb(commands::usb::UsbCmd)`
in `main.rs`'s `Cmd` enum with a doc comment ("Pass a USB device through to a
sandbox"), and `Cmd::Usb(uc) => commands::usb::run(paths, &uc)` in the dispatch.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p izba-cli usb`
Expected: PASS.

- [ ] **Step 5: Feed the real upstream to the policy warning**

In `crates/izba-cli/src/commands/policy.rs`, replace the Phase-1 placeholder:

```rust
fn warn_usbip_exposure(paths: &Paths, cfg: &EgressPolicyConfig) {
    // Phase 2: the configured upstream is now known, so a rule naming that exact
    // endpoint on a non-3240 port is flagged too — not just the well-known port.
    let upstream = izba_core::usb::resolve_upstream(&izba_core::usb::settings::load(
        &paths.usb_dir(),
    ));
    if let Some(msg) = usbip_exposure_warning(cfg, upstream) {
        eprintln!("\n{msg}");
    }
}
```

and thread `paths` through from the `PolicyCmd::Allow` arm.

- [ ] **Step 6: Add the failing end-to-end test**

Create `crates/izba-cli/tests/usb_cli.rs`, following the
`policy_usbip_notice.rs` pattern (real binary, `IZBA_DATA_DIR`, no daemon
needed for the refusal paths):

```rust
//! `izba usb` end-to-end against the real binary.
//!
//! These cover the two properties no unit test can: that the subcommands are
//! actually wired into the CLI, and that a grant cannot be made from a script
//! without the confirmation flag.

use std::path::Path;
use std::process::{Command, Output};

fn izba(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_izba"))
        .args(args)
        .env("IZBA_DATA_DIR", data)
        .env("IZBA_DAEMON_IDLE_SECS", "2")
        .output()
        .expect("run izba")
}

#[test]
fn a_scripted_grant_without_confirmation_is_refused_and_names_the_flag() {
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data.path().join("sandboxes/web")).unwrap();
    let out = izba(
        data.path(),
        &["usb", "allow", "web", "--device", "0403:6001"],
    );
    assert!(!out.status.success(), "must not grant unconfirmed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--confirm"), "{stderr}");
}

#[test]
fn usb_help_documents_that_izba_never_runs_usbipd_bind() {
    let data = tempfile::tempdir().unwrap();
    let out = izba(data.path(), &["usb", "--help"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for sub in ["upstream", "list", "allow", "revoke", "status"] {
        assert!(text.contains(sub), "missing subcommand {sub}: {text}");
    }
}
```

- [ ] **Step 7: Run the gates**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check && cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/izba-cli/src/commands/usb.rs crates/izba-cli/src/commands/mod.rs \
        crates/izba-cli/src/commands/policy.rs crates/izba-cli/src/main.rs \
        crates/izba-cli/tests/usb_cli.rs
git commit -m "feat(cli): add izba usb with a per-device consent gate"
```

---

### Task 9: Documentation, security register, and the app gate

**Files:**
- Modify: `README.md`, `docs/security/findings-2026-06-15.md`,
  `docs/superpowers/specs/2026-08-04-izba-usb-passthrough-design.md`,
  `CLAUDE.md` (crate map line for `usb/`)

- [ ] **Step 1: Record the phase-2 scope change in the spec**

Add to the design doc a short subsection under §5.2 stating that the broker
(`session.rs`) ships in Phase 3 with the guest client, why (testability +
zero new guest surface in Phase 2), and that `DAEMON_PROTO_VERSION` therefore
moves 2→3 here and 3→4 there. Do not rewrite the approved decisions.

- [ ] **Step 2: Update the security register**

In `docs/security/findings-2026-06-15.md`:
- **F-USB-4** (unauthenticated upstream) → mitigation now implemented: the
  trust classifier refuses public upstreams unless `--allow-remote`, and warns
  on every other non-loopback class. Move to the mitigated/closed column with
  the implementing symbols named (`usb::trust::{classify,is_refused,describe}`).
- **F-USB-1** — amend the existing CLOSED entry: the guard is no longer
  enforcement-only; it is now driven by real grants and the real upstream, and
  it is live across grant/revoke via `apply_usb_guard`.
- **F-USB-9** (inventory disclosure) — note that Phase 2 keeps it resolved: the
  device listing is a host-only RPC with no guest-reachable path.
- Update the severity summary counts to match.

- [ ] **Step 3: Document the command surface**

Add a `USB passthrough` subsection to `README.md`'s command surface with the
six verbs, the loopback-is-recommended note, and an explicit sentence that izba
prints the `usbipd bind` command rather than running it (it needs
Administrator). State plainly that Phase 2 configures and consents; devices do
not yet appear inside the guest.

- [ ] **Step 4: Update the crate map**

In `CLAUDE.md`, extend the `izba-core` bullet with `usb/` — host-side USB
passthrough: device ids, grants (host-only consent), upstream settings + trust
classification, and the usbip inventory.

- [ ] **Step 5: Run the out-of-workspace app gate**

```bash
cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
```
Expected: PASS. The app embeds `izba-core` by path, and `SandboxConfig` gained
a field — this gate is the only thing that compiles it.

- [ ] **Step 6: Run every gate one final time**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```

- [ ] **Step 7: Commit and open the PR**

```bash
git add README.md CLAUDE.md docs/
git commit -m "docs: document the USB control plane and its security posture"
git push -u origin feat/usb-passthrough-phase2
gh pr create --title "feat(usb): phase 2 — host-side USB control plane" --body '...'
```

Open it **ready for review**, never `--draft` (repo rule: draft gates the
Greptile review app). Then iterate to CLEAN on all three fronts: Actions checks,
the SonarCloud quality gate, and Greptile.

---

## Self-review

**Spec coverage.** §5.1 codec — done in Phase 1, consumed here by Task 4. §5.2
`settings.rs`/`trust.rs`/`inventory.rs` — Tasks 1/2/4; `mod.rs`'s `UsbBroker`
and `session.rs` — deferred to Phase 3, recorded above and in Task 9 Step 1.
§5.3–§5.5 (guest client, container device visibility, kernel) — Phase 3. §5.6
control plane — Task 6, minus `UsbAttach`/`UsbDetach` (Phase 3, proto 4). §5.7
config surfaces — Tasks 1 and 3. §6.1 consent — Task 8. §6.2 trust — Task 2.
§6.3 CLI — Task 8; GUI — Phase 4. §7 error handling — the fail-closed gate in
Task 7; the audit `Tier::Usb` belongs with the datapath in Phase 3. §8 testing
— unit throughout; `jiegec/usbip` in-process and KVM e2e are Phase 3, since
there is no datapath to drive here.

**Placeholders.** Task 4 Step 4 gives `fetch` in its final form and names the
read-before-write bug the API shape invites, rather than leaving a reader to
rediscover it. Everything else carries concrete code. Task 8 Step 3 leaves
`parse_upstream_arg`'s body to the implementer, but pins its full behaviour with
seven assertions in Step 1, including the IPv6 and out-of-range cases.

**Type consistency.** `DeviceId` is the type everywhere in core; the daemon wire
carries it as a `String` (Task 6) so a malformed id is a clean daemon-side error
rather than a frame-read failure, and Task 7's handlers do the one `parse()`.
`UsbConfig::is_enabled()` is the single input to `UsbGuard.sandbox_usb_enabled`
(Tasks 3 and 7). `usb::resolve_upstream` is used by both `guard_for` (Task 7)
and the policy warning (Task 8), so the guard and the warning cannot disagree
about what the upstream is.
