use crate::daemon::DaemonApi;
use crate::views::{DaemonStatusView, SandboxView};

/// Core of the `list` command: maps daemon errors to a UI-friendly string.
pub fn list_core(d: &mut dyn DaemonApi) -> Result<Vec<SandboxView>, String> {
    d.list().map_err(|e| e.to_string())
}

/// Core of the `daemon_status` command.
pub fn status_core(d: &mut dyn DaemonApi) -> Result<DaemonStatusView, String> {
    d.status().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeDaemon;
    use crate::views::SbxState;

    #[test]
    fn list_core_returns_mapped_sandboxes() {
        let mut d = FakeDaemon::default();
        let out = list_core(&mut d).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "web");
        assert_eq!(out[0].state, SbxState::Running);
    }

    #[test]
    fn list_core_maps_error_to_string() {
        let mut d = FakeDaemon { fail_list: true, ..Default::default() };
        let err = list_core(&mut d).unwrap_err();
        assert!(err.contains("daemon unreachable"), "got: {err}");
    }

    #[test]
    fn status_core_returns_view() {
        let mut d = FakeDaemon::default();
        let s = status_core(&mut d).unwrap();
        assert_eq!(s.pid, 4242);
        assert_eq!(s.sandbox_count, 2);
    }
}
