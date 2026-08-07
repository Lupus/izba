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

/// One row of `usbipd.exe state`, as **captured from usbipd-win 5.3.0 against
/// real hardware**. Every row on that machine carried exactly these seven keys:
/// `BusId`, `ClientIPAddress`, `Description`, `InstanceId`, `IsForced`,
/// `PersistedGuid`, `StubInstanceId` — no more, no less.
///
/// This struct once asked for `VendorId`/`ProductId`/`IsBound`/`IsAttached`.
/// **No usbipd-win release has ever emitted those**, so every row failed to
/// yield an id and the whole table parsed to nothing. Do not "restore" them:
/// the ids come out of `InstanceId`, and bound/attached are derived below.
#[derive(Deserialize)]
struct StateRow {
    /// `null` for a persisted-but-disconnected device — the "Persisted"
    /// section of `usbipd list`. There is no port to bind or attach.
    #[serde(default, rename = "BusId")]
    bus_id: Option<String>,
    /// `USB\VID_303A&PID_1001\<tail>`; the tail is a serial, a MAC, a counter
    /// or a device path, and is never depended on.
    #[serde(default, rename = "InstanceId")]
    instance_id: String,
    #[serde(default, rename = "Description")]
    description: String,
    /// Non-null exactly for the devices `usbipd list` calls `Shared` — this is
    /// how usbipd records a `bind`, and so how izba reads it back.
    #[serde(default, rename = "PersistedGuid")]
    persisted_guid: Option<String>,
    /// Non-null while some client (not necessarily izba) holds the device.
    #[serde(default, rename = "ClientIPAddress")]
    client_ip_address: Option<String>,
}

/// Pull `vid:pid` out of a Windows device instance id
/// (`USB\VID_303A&PID_1001\<tail>`), case-insensitively.
///
/// Returns `None` rather than guessing: a hub or a composite child whose
/// instance id carries no `VID_`/`PID_`, or fields that are not four hex
/// digits, must drop the row. A grant is a consent record, so a truncated
/// field is never zero-padded into some other device's id.
fn ids_from_instance_id(s: &str) -> Option<DeviceId> {
    fn hex4_after<'a>(hay: &'a str, tag: &str) -> Option<&'a str> {
        let start = hay.find(tag)? + tag.len();
        hay.get(start..start + 4)
    }
    // Uppercased so the tags match either spelling; `DeviceId` parses hex in
    // either case, and `to_ascii_uppercase` preserves byte offsets.
    let up = s.to_ascii_uppercase();
    let vid = hex4_after(&up, "VID_")?;
    let pid = hex4_after(&up, "PID_")?;
    format!("{vid}:{pid}").parse().ok()
}

/// A busid must look like a kernel port path before izba will ever render it
/// into a command line for a human to paste (`usbipd bind --busid <x>`).
fn plausible_busid(s: &str) -> bool {
    super::grants::valid_busid(s)
}

/// Parse `usbipd state` JSON. Rows izba cannot make sense of are dropped rather
/// than failing the whole listing — one odd device must not hide the others.
///
/// The two booleans are **derived**, because usbipd-win reports neither
/// directly: a device is shared iff `usbipd bind` persisted a GUID for it
/// (`PersistedGuid` non-null), and attached iff some client holds it
/// (`ClientIPAddress` non-null).
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
            // A null BusId is a persisted-but-disconnected device: keeping it
            // would render `usbipd bind --busid` naming nothing.
            let bus_id = r.bus_id?;
            if !plausible_busid(&bus_id) {
                return None;
            }
            let id = ids_from_instance_id(&r.instance_id)?;
            Some(UsbipdDevice {
                busid: bus_id,
                id,
                description: r.description,
                bound: r.persisted_guid.is_some(),
                attached: r.client_ip_address.is_some(),
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

    /// A VERBATIM capture from `usbipd.exe state` on usbipd-win 5.3.0 against
    /// real hardware (three of the machine's eighteen rows: one shared, one
    /// unshared-but-connected, one persisted-but-disconnected). Do not
    /// "tidy" it into a prettier schema — the point of this constant is that
    /// it is what the tool actually prints.
    const SAMPLE: &str = r#"{
      "Devices": [
        {
          "BusId": "12-4",
          "ClientIPAddress": null,
          "Description": "USB Serial Device (COM8), USB JTAG/serial debug unit",
          "InstanceId": "USB\\VID_303A&PID_1001\\1C:DB:D4:7A:0A:38",
          "IsForced": false,
          "PersistedGuid": "6ce17084-0138-4ab2-a73b-cc465da477cc",
          "StubInstanceId": null
        },
        {
          "BusId": "1-8",
          "ClientIPAddress": null,
          "Description": "Integrated Camera, Integrated IR Camera, Camera DFU Device",
          "InstanceId": "USB\\VID_04F2&PID_B6CB\\0001",
          "IsForced": false,
          "PersistedGuid": null,
          "StubInstanceId": null
        },
        {
          "BusId": null,
          "ClientIPAddress": null,
          "Description": "USB Serial Device (COM8), USB Input Device",
          "InstanceId": "USB\\VID_04D9&PID_B534\\0000",
          "IsForced": false,
          "PersistedGuid": "d8406b90-e336-4b9e-9fba-35affd5d4892",
          "StubInstanceId": null
        }
      ]
    }"#;

    #[test]
    fn parses_the_real_device_table() {
        let d = parse(SAMPLE).unwrap();
        // The third row is persisted-but-disconnected and must not survive.
        assert_eq!(d.len(), 2, "{d:?}");
        assert_eq!(d[0].busid, "12-4");
        assert_eq!(d[0].id.to_string(), "303a:1001");
        assert_eq!(
            d[0].description,
            "USB Serial Device (COM8), USB JTAG/serial debug unit"
        );
        assert!(d[0].bound, "a non-null PersistedGuid means shared");
        assert!(!d[0].attached, "a null ClientIPAddress means unattached");
        assert_eq!(d[1].busid, "1-8");
        assert_eq!(d[1].id.to_string(), "04f2:b6cb");
        assert!(!d[1].bound, "a null PersistedGuid means not shared");
        assert!(!d[1].attached);
    }

    #[test]
    fn a_persisted_but_disconnected_row_is_dropped() {
        // `usbipd list` shows these under "Persisted": there is no port, so
        // `usbipd bind --busid <nothing>` would name nothing at all.
        let d = parse(SAMPLE).unwrap();
        assert!(
            d.iter().all(|d| d.id.to_string() != "04d9:b534"),
            "the BusId-less row must not reach a listing: {d:?}"
        );
    }

    #[test]
    fn an_attached_device_is_reported_attached() {
        let json = r#"{"Devices":[{"BusId":"12-4","ClientIPAddress":"172.24.0.1",
            "Description":"board","InstanceId":"USB\\VID_303A&PID_1001\\x",
            "IsForced":false,"PersistedGuid":"6ce17084-0138-4ab2-a73b-cc465da477cc",
            "StubInstanceId":null}]}"#;
        let d = parse(json).unwrap();
        assert_eq!(d.len(), 1);
        assert!(d[0].bound && d[0].attached);
    }

    #[test]
    fn an_unbound_device_yields_the_exact_command_to_run() {
        let d = parse(SAMPLE).unwrap();
        let unbound = d.iter().find(|d| !d.bound).expect("row 1-8 is unshared");
        assert_eq!(bind_command(unbound), "usbipd bind --busid 1-8");
    }

    #[test]
    fn ids_are_read_out_of_the_instance_id_whatever_its_tail() {
        // The tail after the ids is a serial, a MAC, a counter or a device
        // path — never something to depend on.
        for (instance, want) in [
            ("USB\\VID_303A&PID_1001\\1C:DB:D4:7A:0A:38", "303a:1001"),
            ("USB\\VID_04F2&PID_B6CB\\0001", "04f2:b6cb"),
            ("USB\\VID_8087&PID_0033\\E&1CB3952&0&4", "8087:0033"),
            // Case is not guaranteed by anything, so do not assume it.
            ("usb\\vid_1a86&pid_7523\\5&2f3c1b1&0&2", "1a86:7523"),
        ] {
            assert_eq!(
                ids_from_instance_id(instance).map(|i| i.to_string()),
                Some(want.to_string()),
                "{instance}"
            );
        }
    }

    #[test]
    fn an_instance_id_without_ids_is_none_rather_than_a_guess() {
        for bad in [
            "",
            "USB\\ROOT_HUB30\\4&1cb3952&0&0",
            "USB\\VID_303A\\1C:DB",
            "USB\\PID_1001\\1C:DB",
            // Truncated / non-hex fields must not be zero-padded into a
            // different device: a grant is a consent record.
            "USB\\VID_30&PID_1001\\x",
            "USB\\VID_ZZZZ&PID_1001\\x",
            "USB\\VID_303A&PID_10",
        ] {
            assert_eq!(ids_from_instance_id(bad), None, "must refuse {bad:?}");
        }
    }

    #[test]
    fn a_device_with_an_unparseable_id_is_dropped_not_fatal() {
        // One odd row must not blind the user to the rest of their hardware.
        let json = r#"{"Devices":[
            {"BusId":"3-2","ClientIPAddress":null,"Description":"x",
             "InstanceId":"USB\\ROOT_HUB30\\4&1cb3952&0&0","IsForced":false,
             "PersistedGuid":null,"StubInstanceId":null},
            {"BusId":"1-4","ClientIPAddress":null,"Description":"ok",
             "InstanceId":"USB\\VID_1A86&PID_7523\\5&2f3c1b1&0&2","IsForced":false,
             "PersistedGuid":"6ce17084-0138-4ab2-a73b-cc465da477cc",
             "StubInstanceId":null}]}"#;
        let d = parse(json).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].description, "ok");
    }

    #[test]
    fn a_row_missing_a_required_field_is_dropped() {
        let json = r#"{"Devices":[
            {"InstanceId":"USB\\VID_303A&PID_1001\\x"},
            {"BusId":"3-2"},
            {"BusId":null,"InstanceId":"USB\\VID_303A&PID_1001\\x"}]}"#;
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
                r#"{{"Devices":[{{"BusId":{},"ClientIPAddress":null,"Description":"x",
                   "InstanceId":"USB\\VID_303A&PID_1001\\x","IsForced":false,
                   "PersistedGuid":null,"StubInstanceId":null}}]}}"#,
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
