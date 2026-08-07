//! Read usbipd-win's own device table so izba can name a device the human has
//! plugged in but not yet shared.
//!
//! `OP_REQ_DEVLIST` reports only devices already **bound**, so without this the
//! answer to "why isn't my board listed?" is silence. This is a convenience
//! layer, never a control path: izba runs the read-only `state` verb, with a
//! timeout and a size cap, and it NEVER runs `bind` — that needs Administrator,
//! and constraint #5 says izba prints the command for the human to run rather
//! than wrapping usbipd-win. Nothing here is reachable from a guest RPC.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use super::DeviceId;

/// Cap on the JSON izba will parse. A realistic table is a few KiB.
pub const MAX_STATE_BYTES: usize = 256 * 1024;

/// How long izba waits for `usbipd.exe state`. Sized for the WSL interop hop,
/// which is the slow case; a native Windows spawn returns far inside it. Past
/// this the listing proceeds without enrichment.
pub const PROBE_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbipdDevice {
    pub busid: String,
    pub id: DeviceId,
    pub description: String,
    /// Shared via `usbipd bind` — i.e. visible in an `OP_REP_DEVLIST`.
    pub bound: bool,
    /// Currently attached by some client (possibly not izba).
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
    bus_id: Option<String>,
    #[serde(rename = "VendorId")]
    vendor_id: Option<String>,
    #[serde(rename = "ProductId")]
    product_id: Option<String>,
    #[serde(default, rename = "Description")]
    description: String,
    #[serde(default, rename = "IsBound")]
    is_bound: bool,
    #[serde(default, rename = "IsAttached")]
    is_attached: bool,
}

/// A busid must look like a kernel port path before izba will ever render it
/// into a command line for a human to paste (`usbipd bind --busid <x>`).
fn plausible_busid(s: &str) -> bool {
    super::grants::valid_busid(s)
}

/// Parse `usbipd state` JSON. Rows izba cannot make sense of are dropped rather
/// than failing the whole listing — one odd device must not hide the others.
pub fn parse(json: &str) -> Result<Vec<UsbipdDevice>> {
    if json.len() > MAX_STATE_BYTES {
        bail!(
            "usbipd state output too large ({} bytes, cap {MAX_STATE_BYTES})",
            json.len()
        );
    }
    let file: StateFile = serde_json::from_str(json).context("parsing usbipd state JSON")?;
    Ok(file
        .devices
        .into_iter()
        .filter_map(|r| {
            let bus_id = r.bus_id?;
            if !plausible_busid(&bus_id) {
                return None;
            }
            let id: DeviceId = format!("{}:{}", r.vendor_id?, r.product_id?).parse().ok()?;
            Some(UsbipdDevice {
                busid: bus_id,
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

/// The human-readable product name usbipd knows for a device, if it can be
/// matched without guessing.
///
/// The USB/IP wire format carries no product string — `OP_REP_DEVLIST` gives a
/// sysfs path and nothing friendlier — so the only source of "USB JTAG/serial
/// debug unit" is usbipd's own state table, and getting it onto a shared row is
/// a join rather than a new field (#190).
///
/// Match rule, in order:
/// 1. busid AND id both equal — unambiguous.
/// 2. id equal and exactly one row carries it — the busid spellings need not
///    agree between usbipd and the upstream's export, and one device of that
///    model cannot be confused with another.
///
/// Never busid alone: a busid is host-local, so against a remote upstream that
/// would paste this machine's device name onto someone else's hardware.
pub fn describe<'a>(known: &'a [UsbipdDevice], busid: &str, id: DeviceId) -> Option<&'a str> {
    let non_empty = |d: &'a UsbipdDevice| Some(d.description.as_str()).filter(|s| !s.is_empty());
    if let Some(d) = known.iter().find(|d| d.busid == busid && d.id == id) {
        return non_empty(d);
    }
    let mut by_id = known.iter().filter(|d| d.id == id);
    let only = by_id.next()?;
    if by_id.next().is_some() {
        return None;
    }
    non_empty(only)
}

/// Run `usbipd.exe state` across the WSL interop boundary. Returns `None` on
/// any failure — this is decoration, and its absence must never fail a listing
/// or be mistaken for "you have no devices".
///
/// Time-bounded, because the WSL interop hop can wedge and this runs behind an
/// interactive command: a `usbipd.exe` that never exits must cost the user a few
/// seconds and an unadorned listing, not a hung terminal. The child is killed on
/// expiry.
///
/// The output is read only after the process exits, so a child that produced
/// more than one pipe buffer would block writing rather than be read — which the
/// deadline then resolves. That is the intended outcome: a `state` reply too big
/// to fit a pipe buffer is not one izba would parse anyway (see
/// [`MAX_STATE_BYTES`]).
// reason: process-spawn glue across WSL interop; `parse`/`bind_command` carry
// the logic and are fully unit-tested.
#[mutants::skip]
pub fn probe() -> Option<Vec<UsbipdDevice>> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    if !super::trust::can_probe_usbipd() {
        return None;
    }
    let mut child = Command::new("usbipd.exe")
        .arg("state")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .ok()?;

    let deadline = Instant::now() + Duration::from_secs(PROBE_TIMEOUT_SECS);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) => return None,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => return None,
        }
    }

    // Bound the read as well as the wait: `parse` refuses anything over the cap,
    // so reading past it only wastes memory.
    let mut buf = String::new();
    child
        .stdout
        .take()?
        .take(MAX_STATE_BYTES as u64 + 1)
        .read_to_string(&mut buf)
        .ok()?;
    parse(&buf).ok()
}

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
        assert!(d[2].bound && d[2].attached);
    }

    #[test]
    fn an_unbound_device_yields_the_exact_command_to_run() {
        let d = parse(SAMPLE).unwrap();
        assert_eq!(bind_command(&d[0]), "usbipd bind --busid 3-2");
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
    fn a_row_missing_a_required_field_is_dropped() {
        let json = r#"{"Devices":[
            {"VendorId":"0403","ProductId":"6001"},
            {"BusId":"3-2","ProductId":"6001"},
            {"BusId":"3-2","VendorId":"0403"}]}"#;
        assert!(parse(json).unwrap().is_empty());
    }

    #[test]
    fn a_hostile_busid_is_dropped_so_it_can_never_reach_a_command_line() {
        // `bind_command` renders the busid into text a human is invited to
        // paste into an elevated shell — so a shell metacharacter must never
        // survive parsing, rather than being escaped downstream.
        for bad in [
            "3-2 & calc.exe",
            "3-2; rm -rf /",
            "../../etc",
            "3-2\n",
            "$(id)",
        ] {
            let json = format!(
                r#"{{"Devices":[{{"BusId":{},"VendorId":"0403","ProductId":"6001",
                   "Description":"x","IsBound":false,"IsAttached":false}}]}}"#,
                serde_json::to_string(bad).unwrap()
            );
            assert!(parse(&json).unwrap().is_empty(), "must drop {bad:?}");
        }
    }

    #[test]
    fn garbage_input_is_an_error_or_an_empty_list_never_a_panic() {
        for bad in ["", "null", "[]", "{ not json", r#"{"Devices":3}"#] {
            let _ = parse(bad);
        }
        assert!(parse("{ not json").is_err());
        assert!(
            parse("{}").unwrap().is_empty(),
            "no Devices key ⇒ nothing known"
        );
    }

    #[test]
    fn output_beyond_the_cap_is_refused_before_parsing() {
        let big = "x".repeat(MAX_STATE_BYTES + 1);
        let err = parse(&big).unwrap_err().to_string();
        assert!(err.contains("too large"), "{err}");
        // Exactly at the cap is still attempted (it fails as bad JSON, not as
        // an oversize refusal) — the boundary must be inclusive.
        let at_cap = "x".repeat(MAX_STATE_BYTES);
        assert!(!parse(&at_cap)
            .unwrap_err()
            .to_string()
            .contains("too large"));
    }

    #[test]
    fn the_cap_is_roomy_enough_for_a_real_device_table() {
        // Asserted against a LITERAL, not against MAX_STATE_BYTES: a test
        // written in terms of the constant moves with it, and so cannot notice
        // the cap shrinking. A machine with many devices produces tens of KB of
        // JSON, and a cap that refused that would silently drop the enrichment
        // telling the user how to share a device.
        let realistic = "x".repeat(100_000);
        assert!(
            !parse(&realistic)
                .unwrap_err()
                .to_string()
                .contains("too large"),
            "100 KB of output must reach the parser, not the size refusal"
        );
    }

    fn known(busid: &str, vid: u16, pid: u16, desc: &str) -> UsbipdDevice {
        UsbipdDevice {
            busid: busid.to_string(),
            id: DeviceId { vid, pid },
            description: desc.to_string(),
            bound: true,
            attached: false,
        }
    }

    #[test]
    fn a_row_matching_on_both_busid_and_id_gets_the_product_name() {
        let table = [known("12-4", 0x303a, 0x1001, "USB JTAG/serial debug unit")];
        assert_eq!(
            describe(
                &table,
                "12-4",
                DeviceId {
                    vid: 0x303a,
                    pid: 0x1001
                }
            ),
            Some("USB JTAG/serial debug unit")
        );
    }

    #[test]
    fn a_busid_match_with_a_different_device_never_lends_its_name() {
        // A busid is host-local. Against a remote upstream the same string can
        // name entirely different hardware, and pasting a local product name
        // (worse: one carrying a local COM port) onto it would be a lie.
        let table = [known("12-4", 0x303a, 0x1001, "USB JTAG/serial debug unit")];
        assert_eq!(
            describe(
                &table,
                "12-4",
                DeviceId {
                    vid: 0x0403,
                    pid: 0x6001
                }
            ),
            None
        );
    }

    #[test]
    fn a_unique_id_still_matches_when_the_busids_differ() {
        // usbipd's busid and the upstream's exported busid need not be spelled
        // the same. One unambiguous device of that model is still safe to name.
        let table = [known("3-2", 0x303a, 0x1001, "USB JTAG/serial debug unit")];
        assert_eq!(
            describe(
                &table,
                "12-4",
                DeviceId {
                    vid: 0x303a,
                    pid: 0x1001
                }
            ),
            Some("USB JTAG/serial debug unit")
        );
    }

    #[test]
    fn two_identical_models_are_ambiguous_and_neither_name_is_borrowed() {
        let table = [
            known("3-2", 0x303a, 0x1001, "board on the left"),
            known("3-3", 0x303a, 0x1001, "board on the right"),
        ];
        // Neither busid matches, and the id alone cannot pick between them.
        assert_eq!(
            describe(
                &table,
                "12-4",
                DeviceId {
                    vid: 0x303a,
                    pid: 0x1001
                }
            ),
            None
        );
        // …but an exact busid match still resolves it.
        assert_eq!(
            describe(
                &table,
                "3-3",
                DeviceId {
                    vid: 0x303a,
                    pid: 0x1001
                }
            ),
            Some("board on the right")
        );
    }

    #[test]
    fn an_empty_usbipd_description_is_not_worth_borrowing() {
        let table = [known("12-4", 0x303a, 0x1001, "")];
        assert_eq!(
            describe(
                &table,
                "12-4",
                DeviceId {
                    vid: 0x303a,
                    pid: 0x1001
                }
            ),
            None
        );
    }
}
