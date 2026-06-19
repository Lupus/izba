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
    format!(
        "name:        {}\n\
         image:       {}\n\
         digest:      {}\n\
         cpus:        {}\n\
         mem:         {} MiB\n\
         workspace:   {}\n\
         status:      {}\n\
         confinement: {}\n\
         lock-down:   {}\n",
        det.name,
        det.image_ref,
        det.image_digest,
        det.cpus,
        det.mem_mb,
        det.workspace,
        det.status,
        confinement,
        lockdown,
    )
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
        SandboxDetail {
            name: "web".into(),
            image_ref: "ubuntu:24.04".into(),
            image_digest: "sha256:abc".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            status: "running".into(),
            ports: vec![],
            confinement: confinement.map(String::from),
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
