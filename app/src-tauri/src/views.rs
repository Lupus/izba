use izba_core::build_info::BuildInfoOwned;
use serde::Serialize;

/// Version comparison surfaced to the About panel: this app's build, the linked
/// izba-core build, and (when reachable) the daemon's — with a mismatch flag.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VersionView {
    pub app: BuildInfoOwned,
    pub core: BuildInfoOwned,
    pub daemon: Option<BuildInfoOwned>,
    pub proto: u32,
    pub mismatch: bool,
}

/// This app binary's own build metadata. The app's `build.rs` (vergen) emits
/// the `VERGEN_*`/`IZBA_PROFILE` vars into THIS crate, so they describe the app
/// — distinct from `izba_core`'s, which describes the linked library.
pub fn app_build_info() -> BuildInfoOwned {
    fn or_unknown(v: Option<&str>) -> String {
        v.unwrap_or("unknown").to_string()
    }
    BuildInfoOwned {
        pkg_version: env!("CARGO_PKG_VERSION").to_string(),
        git_describe: or_unknown(option_env!("VERGEN_GIT_DESCRIBE")),
        git_sha: or_unknown(option_env!("VERGEN_GIT_SHA")),
        commit_date: or_unknown(option_env!("VERGEN_GIT_COMMIT_DATE")),
        build_timestamp: or_unknown(option_env!("VERGEN_BUILD_TIMESTAMP")),
        rustc: or_unknown(option_env!("VERGEN_RUSTC_SEMVER")),
        target: or_unknown(option_env!("VERGEN_CARGO_TARGET_TRIPLE")),
        profile: or_unknown(option_env!("IZBA_PROFILE")),
    }
}

/// Structured sandbox state for the frontend (parsed from izba's status string).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SbxState {
    Running,
    Degraded { reason: String },
    Stopped,
}

/// Parse izba's `Liveness::describe()` string into a structured state.
/// Formats: "running" | "stopped" | "degraded (<reason>)".
///
/// NOTE: the `degraded (...)` branch strips the final ')', so a reason that
/// itself ends with ')' would lose one character. izba's reasons never do
/// (see `liveness.rs`), but keep that invariant in mind if reasons change.
pub fn parse_state(status: &str) -> SbxState {
    if status == "running" {
        SbxState::Running
    } else if status == "stopped" {
        SbxState::Stopped
    } else if let Some(reason) = status
        .strip_prefix("degraded (")
        .and_then(|s| s.strip_suffix(')'))
    {
        SbxState::Degraded {
            reason: reason.to_string(),
        }
    } else {
        // Unknown/empty status is treated as stopped rather than panicking.
        SbxState::Stopped
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SandboxView {
    pub name: String,
    pub image: String,
    pub state: SbxState,
}

impl From<izba_core::daemon::proto::SandboxSummary> for SandboxView {
    fn from(s: izba_core::daemon::proto::SandboxSummary) -> Self {
        SandboxView {
            name: s.name,
            image: s.image_ref,
            state: parse_state(&s.status),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DaemonStatusView {
    pub version: String,
    pub pid: u32,
    pub uptime_ms: u64,
    pub sandbox_count: usize,
}

impl From<izba_core::daemon::proto::DaemonStatus> for DaemonStatusView {
    fn from(s: izba_core::daemon::proto::DaemonStatus) -> Self {
        DaemonStatusView {
            version: s.version,
            pid: s.pid,
            uptime_ms: s.uptime_ms,
            sandbox_count: s.sandboxes.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_running_and_stopped() {
        assert_eq!(parse_state("running"), SbxState::Running);
        assert_eq!(parse_state("stopped"), SbxState::Stopped);
    }

    #[test]
    fn parses_degraded_with_reason() {
        assert_eq!(
            parse_state("degraded (sidecar virtiofsd:workspace died)"),
            SbxState::Degraded {
                reason: "sidecar virtiofsd:workspace died".into()
            }
        );
    }

    #[test]
    fn unknown_status_is_stopped() {
        assert_eq!(parse_state("weird"), SbxState::Stopped);
        assert_eq!(parse_state(""), SbxState::Stopped);
    }

    #[test]
    fn summary_maps_to_view() {
        let s = izba_core::daemon::proto::SandboxSummary {
            name: "web".into(),
            image_ref: "ubuntu:24.04".into(),
            status: "running".into(),
        };
        let v: SandboxView = s.into();
        assert_eq!(
            v,
            SandboxView {
                name: "web".into(),
                image: "ubuntu:24.04".into(),
                state: SbxState::Running
            }
        );
    }
}
