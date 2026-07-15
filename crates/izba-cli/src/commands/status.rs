//! `izba status NAME` — detailed per-sandbox status, including the host-side
//! VMM confinement actually achieved at launch (see `VmHandle::confinement`).

use anyhow::bail;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse, SandboxDetail};
use izba_core::daemon::DaemonClient;
use izba_core::jail_account::orchestrate::lockdown_state;
use izba_core::paths::Paths;

pub fn run(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    match client.request(&DaemonRequest::Inspect { name: name.into() }, &mut |_| {})? {
        DaemonResponse::Inspect(det) => {
            print!("{}", render(paths, &det));
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}

/// The human-readable status block. Confinement is the load-bearing line: if a
/// sandbox is unconfined the summary already starts with `UNCONFINED — …`, so
/// it stands out; `None` (stopped / pre-confinement state) renders as
/// `unknown`.
fn render(paths: &Paths, det: &SandboxDetail) -> String {
    let confinement = det.confinement.as_deref().unwrap_or("unknown");
    let lockdown = lockdown_state(paths, &det.name).summary();
    let mut out = format!(
        "name:        {}\n\
         image:       {}\n\
         digest:      {}\n\
         cpus:        {}\n\
         mem:         {} MiB\n\
         workspace:   {}\n\
         status:      {}\n\
         container:   {}\n\
         confinement: {}\n\
         lock-down:   {}\n",
        det.name,
        det.image_ref,
        det.image_digest,
        det.cpus,
        det.mem_mb,
        det.workspace,
        det.status,
        container_label(det.container),
        confinement,
        lockdown,
    );
    if let Some(declared) = det.user_fallback.as_deref() {
        // Loud-on-degradation (#114): the workload runs as root because the
        // image's symbolic USER could not be resolved host-side. Persisted in
        // state.json (Task 2) so this line re-surfaces the degradation on
        // every `izba status`, not just the one-shot start-time warning.
        out.push_str(&format!(
            "user:        root — image USER '{declared}' could not be resolved (symbolic-USER fallback)\n"
        ));
    }
    out
}

/// Human-readable label for the in-guest container state. `None` (stopped
/// sandbox, unreachable guest, or pre-Phase-7 daemon) and `Unknown` both render
/// as "unknown" — never a healthy claim. The honest exited/created cases carry
/// a parenthetical so `status` doesn't imply the workload is up when it isn't.
fn container_label(state: Option<izba_proto::ContainerState>) -> String {
    use izba_proto::ContainerState;
    match state {
        None | Some(ContainerState::Unknown) => "unknown".to_string(),
        Some(ContainerState::Running) => "running".to_string(),
        Some(ContainerState::Stopped) => "stopped (workload exited)".to_string(),
        Some(ContainerState::Created) => "created (not started)".to_string(),
        Some(ContainerState::Paused) => "paused".to_string(),
        Some(ContainerState::Creating) => "creating".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::daemon::proto::SandboxDetail;
    use izba_core::paths::Paths;

    fn test_paths(tmp: &tempfile::TempDir) -> Paths {
        Paths::with_root(tmp.path().to_path_buf())
    }

    fn detail(confinement: Option<&str>) -> SandboxDetail {
        detail_with_container(confinement, None)
    }

    fn detail_with_container(
        confinement: Option<&str>,
        container: Option<izba_proto::ContainerState>,
    ) -> SandboxDetail {
        SandboxDetail {
            name: "web".into(),
            image_ref: "ubuntu:24.04".into(),
            image_digest: "sha256:abc".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            status: "running".into(),
            ports: vec![],
            volumes: vec![],
            confinement: confinement.map(String::from),
            container,
            user_fallback: None,
        }
    }

    #[test]
    fn renders_confined_summary() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(
            &paths,
            &detail(Some("confined: restricted(limited)+low-il+job")),
        );
        assert!(
            out.contains("confinement: confined: restricted(limited)+low-il+job"),
            "{out}"
        );
        assert!(!out.contains("UNCONFINED"), "{out}");
    }

    #[test]
    fn renders_unconfined_prominently() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(
            &paths,
            &detail(Some(
                "UNCONFINED — --allow-unconfined: host-side VMM confinement disabled by user",
            )),
        );
        // The prominent UNCONFINED marker must survive verbatim.
        assert!(out.contains("confinement: UNCONFINED — "), "{out}");
    }

    #[test]
    fn renders_unknown_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(&paths, &detail(None));
        assert!(out.contains("confinement: unknown"), "{out}");
    }

    #[test]
    fn renders_container_running() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(
            &paths,
            &detail_with_container(None, Some(izba_proto::ContainerState::Running)),
        );
        assert!(out.contains("container:   running"), "{out}");
    }

    #[test]
    fn renders_container_exited_honestly() {
        // The headline honesty case: the VM (status) is up but the workload
        // container has exited — `status` must not imply the workload is alive.
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(
            &paths,
            &detail_with_container(None, Some(izba_proto::ContainerState::Stopped)),
        );
        assert!(
            out.contains("container:   stopped (workload exited)"),
            "{out}"
        );
    }

    #[test]
    fn renders_container_unknown_when_absent() {
        // A stopped sandbox / unreachable guest / pre-Phase-7 daemon → None →
        // "unknown", never a healthy claim.
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(&paths, &detail_with_container(None, None));
        assert!(out.contains("container:   unknown"), "{out}");
    }

    #[test]
    fn container_label_maps_all_states() {
        use izba_proto::ContainerState;
        assert_eq!(container_label(None), "unknown");
        assert_eq!(container_label(Some(ContainerState::Unknown)), "unknown");
        assert_eq!(container_label(Some(ContainerState::Running)), "running");
        assert_eq!(
            container_label(Some(ContainerState::Stopped)),
            "stopped (workload exited)"
        );
        assert_eq!(
            container_label(Some(ContainerState::Created)),
            "created (not started)"
        );
        assert_eq!(container_label(Some(ContainerState::Paused)), "paused");
        assert_eq!(container_label(Some(ContainerState::Creating)), "creating");
    }

    #[test]
    fn renders_user_fallback_prominently() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let mut det = detail(None);
        det.user_fallback = Some("node".into());
        let out = render(&paths, &det);
        assert!(out.contains("root"), "got: {out}");
        assert!(out.contains("'node'"), "got: {out}");
        assert!(out.contains("user:        root"), "got: {out}");
    }

    #[test]
    fn no_user_line_without_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(&paths, &detail(None));
        assert!(!out.contains("USER"), "got: {out}");
    }

    #[test]
    fn renders_lockdown_unlocked_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(&paths, &detail(None));
        assert!(out.contains("lock-down:   unlocked"), "{out}");
    }

    #[test]
    fn renders_lockdown_locked_when_state_file_present() {
        use izba_core::jail_account::state::{LockdownFile, LockedInfo, LOCKDOWN_FILE};
        use izba_core::state::save_json;

        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let sb_dir = paths.sandbox_dir("web");
        std::fs::create_dir_all(&sb_dir).unwrap();
        save_json(
            &sb_dir.join(LOCKDOWN_FILE),
            &LockdownFile {
                state: Some(LockedInfo {
                    account: "izba-sb-web".into(),
                    sid: "S-1-5-21-1-2-3-1001".into(),
                    net_blocked: true,
                }),
            },
        )
        .unwrap();

        let out = render(&paths, &detail(None));
        assert!(
            out.contains("lock-down:   locked(account=izba-sb-web"),
            "{out}"
        );
    }
}
