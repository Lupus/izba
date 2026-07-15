use izba_core::daemon::proto::{DaemonRequest, DaemonResponse, SandboxDetail};
use izba_core::daemon::DaemonClient;
use izba_core::jail_account::orchestrate::{lockdown_state, unlock, WinBackend};
use izba_core::jail_account::LockdownState;
use izba_core::paths::Paths;

/// The #78 residual-risk warning: force-removing a not-stopped sandbox that
/// holds named persistent volumes triggers only a *best-effort* guest sync —
/// a hung guest is still killed, losing unsynced writes. Say so loudly.
fn force_rm_warning(detail: &SandboxDetail) -> Option<String> {
    if detail.status == "stopped" {
        return None;
    }
    let names: Vec<String> = detail
        .volumes
        .iter()
        // A volume is persistent exactly when it has a name (`is_persistent()`
        // is defined as `name.is_some()`), so filter_map on the name alone
        // already selects exactly the persistent volumes.
        .filter_map(|v| v.name.as_ref())
        .map(|n| format!("'{n}'"))
        .collect();
    if names.is_empty() {
        return None;
    }
    Some(format!(
        "⚠️  WARNING: removing '{}' while it is running — a best-effort guest sync \
         of persistent volume(s) {} is attempted before the VM is killed, but writes \
         from the last moments may be lost if the guest is unresponsive. Prefer \
         `izba stop {}` first for guaranteed durability.",
        detail.name,
        names.join(", "),
        detail.name
    ))
}

#[mutants::skip] // reason: drives a live daemon (Inspect pre-flight + Rm over the socket); e2e-only (daemon_e2e exercises rm --force). The #78 warning decision logic (force_rm_warning) is unit-tested below.
pub fn run(paths: &Paths, name: &str, force: bool) -> anyhow::Result<i32> {
    // Best-effort: if the sandbox is locked down, release the Windows account
    // before deleting the sandbox directory (the account must be deprovisioned
    // via the elevated helper; the state files live inside the sandbox dir).
    if matches!(lockdown_state(paths, name), LockdownState::Locked(_)) {
        if let Err(e) = unlock(&WinBackend, paths, name) {
            eprintln!(
                "warning: could not release the lock-down account for '{name}' \
                 (UAC declined or helper error: {e:#}); the account + firewall rule may still \
                 exist. Run `izba unlock {name}` or `izba windows-cleanup` to release it later."
            );
        }
    }

    let mut client = DaemonClient::connect(paths)?;

    // Best-effort pre-flight: warn about the force-removal durability gap.
    // Any Inspect failure (unknown sandbox, stale daemon) is ignored — the
    // authoritative outcome comes from the Rm RPC below.
    if force {
        if let Ok(DaemonResponse::Inspect(detail)) = client.request(
            &DaemonRequest::Inspect {
                name: name.to_string(),
            },
            &mut |_| {},
        ) {
            if let Some(warning) = force_rm_warning(&detail) {
                eprintln!("{warning}");
            }
        }
    }

    let resp = client.request(
        &DaemonRequest::Rm {
            name: name.to_string(),
            force,
        },
        &mut |_| {},
    )?;
    super::expect_ok(resp)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::volume::VolumeSpec;

    fn detail(status: &str, volumes: Vec<VolumeSpec>) -> SandboxDetail {
        SandboxDetail {
            name: "web".into(),
            image_ref: "ubuntu:22.04".into(),
            image_digest: "sha256:abc".into(),
            cpus: 2,
            mem_mb: 1024,
            workspace: "/ws".into(),
            status: status.into(),
            ports: Vec::new(),
            volumes,
            confinement: None,
            container: None,
            user_fallback: None,
        }
    }

    fn pvol(name: &str) -> VolumeSpec {
        VolumeSpec {
            name: Some(name.into()),
            guest_path: format!("/{name}").into(),
            size_bytes: 64 << 20,
            eph_id: None,
        }
    }

    fn evol() -> VolumeSpec {
        VolumeSpec {
            name: None,
            guest_path: "/eph".into(),
            size_bytes: 64 << 20,
            eph_id: Some(1),
        }
    }

    #[test]
    fn warns_when_running_with_persistent_volumes() {
        let w =
            force_rm_warning(&detail("running", vec![evol(), pvol("data")])).expect("must warn");
        assert!(w.contains("⚠️"), "loud-warning marker missing: {w}");
        assert!(w.contains("'data'"), "must name the volume: {w}");
        assert!(
            w.contains("izba stop"),
            "must point at the durable alternative: {w}"
        );
    }

    #[test]
    fn warns_for_degraded_sandboxes_too() {
        // Anything not fully stopped still holds a live-ish VMM whose guest
        // cache may be dirty — same risk, same warning.
        assert!(force_rm_warning(&detail("degraded (vmm dead)", vec![pvol("data")])).is_some());
    }

    #[test]
    fn silent_when_stopped() {
        assert!(force_rm_warning(&detail("stopped", vec![pvol("data")])).is_none());
    }

    #[test]
    fn silent_without_persistent_volumes() {
        assert!(force_rm_warning(&detail("running", vec![evol()])).is_none());
        assert!(force_rm_warning(&detail("running", Vec::new())).is_none());
    }

    #[test]
    fn names_every_persistent_volume() {
        let w = force_rm_warning(&detail("running", vec![pvol("data"), pvol("cache")]))
            .expect("must warn");
        assert!(w.contains("'data'") && w.contains("'cache'"), "got: {w}");
    }
}
