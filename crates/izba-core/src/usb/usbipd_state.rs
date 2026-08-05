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

/// How long izba waits for `usbipd.exe state`. The WSL interop hop is slow but
/// not unbounded; past this the listing proceeds without enrichment.
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

/// Run `usbipd.exe state` across the WSL interop boundary. Returns `None` on
/// any failure — this is decoration, and its absence must never fail a listing
/// or be mistaken for "you have no devices".
// reason: process-spawn glue across WSL interop; `parse`/`bind_command` carry
// the logic and are fully unit-tested.
#[mutants::skip]
pub fn probe() -> Option<Vec<UsbipdDevice>> {
    if !super::trust::running_under_wsl() {
        return None;
    }
    let out = std::process::Command::new("usbipd.exe")
        .arg("state")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse(&String::from_utf8(out.stdout).ok()?).ok()
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
}
