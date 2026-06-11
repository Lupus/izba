//! The `exec -it` operator checklist, encoded as reusable scenarios.

use crate::scripted_guest::{ExecOutcome, GuestScript};
use izba_proto::ExitStatus;

/// One checklist scenario: what command izba runs in the guest, plus the
/// scripted guest behaviour. Per-item assertions live in the test tier.
pub struct Scenario {
    pub name: &'static str,
    /// The guest command (the part after `--` in `izba exec -it <name> -- ...`).
    pub argv: Vec<String>,
    pub script: GuestScript,
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// vim's startup redraw, abbreviated, ending with the raw `0xbd` t_u7
/// ambiguous-width probe byte and a post-probe line. Asserting the post-probe
/// line renders is the regression guard for the Windows console byte bug.
fn vim_initial() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"\x1b[2J\x1b[1;1Hline-before-probe\r\n");
    v.extend_from_slice(b"\x1b[2;1Hwidth-probe -> ");
    v.push(0xbd);
    v.extend_from_slice(b"\x1b[3;1Hline-AFTER-probe\r\n");
    v
}

fn vim_resized(cols: u16, rows: u16) -> Vec<u8> {
    format!("\x1b[2J\x1b[1;1Hresized to {cols}x{rows}\r\n").into_bytes()
}

/// vim renders fullscreen (incl. the probe byte) and repaints on resize.
pub fn vim_redraw() -> Scenario {
    Scenario {
        name: "vim_redraw",
        argv: argv(&["vi", "/workspace/x"]),
        script: GuestScript {
            exec_outcome: ExecOutcome::Started,
            initial_emit: vim_initial(),
            on_resize: Some(vim_resized),
            end_when_input_contains: Some(b'q'),
            final_status: ExitStatus::Code(0),
        },
    }
}

/// A shell prompt is shown and VT input (arrow keys) is delivered to the guest.
pub fn arrow_keys() -> Scenario {
    Scenario {
        name: "arrow_keys",
        argv: argv(&["/bin/sh", "-l"]),
        script: GuestScript {
            exec_outcome: ExecOutcome::Started,
            initial_emit: b"sh-prompt$ ".to_vec(),
            on_resize: None,
            end_when_input_contains: Some(b'q'),
            final_status: ExitStatus::Code(0),
        },
    }
}

/// Ctrl-C (0x03) reaches the guest and ends the exec via a signal; izba itself
/// must survive. The final status `Signal(2)` maps to CLI exit `130`.
pub fn ctrl_c() -> Scenario {
    Scenario {
        name: "ctrl_c",
        argv: argv(&["sleep", "100"]),
        script: GuestScript {
            exec_outcome: ExecOutcome::Started,
            initial_emit: b"sleeping...".to_vec(),
            on_resize: None,
            end_when_input_contains: Some(0x03),
            final_status: ExitStatus::Signal(2),
        },
    }
}

/// Exit code passthrough: the guest exits with `code`, izba returns it.
pub fn exit_code(code: i32) -> Scenario {
    Scenario {
        name: "exit_code",
        argv: argv(&["true"]),
        script: GuestScript {
            exec_outcome: ExecOutcome::Started,
            initial_emit: Vec::new(),
            on_resize: None,
            end_when_input_contains: None,
            final_status: ExitStatus::Code(code),
        },
    }
}

/// Command-not-found maps to CLI exit 127 (no stream/wait).
pub fn command_not_found() -> Scenario {
    Scenario {
        name: "command_not_found",
        argv: argv(&["definitely-not-a-real-binary"]),
        script: GuestScript {
            exec_outcome: ExecOutcome::CommandNotFound,
            initial_emit: Vec::new(),
            on_resize: None,
            end_when_input_contains: None,
            final_status: ExitStatus::Code(0),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_proto::ExitStatus;

    #[test]
    fn vim_scenario_emits_probe_byte() {
        let s = vim_redraw();
        assert!(
            s.script.initial_emit.contains(&0xbd),
            "must carry the t_u7 probe byte"
        );
        assert!(s.script.on_resize.is_some());
    }

    #[test]
    fn exit_code_scenario_carries_status() {
        let s = exit_code(42);
        assert_eq!(s.script.final_status, ExitStatus::Code(42));
        assert!(s.script.end_when_input_contains.is_none());
    }
}
