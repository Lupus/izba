//! `izba status NAME` — detailed per-sandbox status, including the host-side
//! VMM confinement actually achieved at launch (see `VmHandle::confinement`).

use anyhow::bail;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse, SandboxDetail};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

pub fn run(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    match client.request(&DaemonRequest::Inspect { name: name.into() }, &mut |_| {})? {
        DaemonResponse::Inspect(det) => {
            print!("{}", render(&det));
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
fn render(det: &SandboxDetail) -> String {
    let confinement = det.confinement.as_deref().unwrap_or("unknown");
    format!(
        "name:        {}\n\
         image:       {}\n\
         digest:      {}\n\
         cpus:        {}\n\
         mem:         {} MiB\n\
         workspace:   {}\n\
         status:      {}\n\
         confinement: {}\n",
        det.name,
        det.image_ref,
        det.image_digest,
        det.cpus,
        det.mem_mb,
        det.workspace,
        det.status,
        confinement,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::daemon::proto::SandboxDetail;

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
        let out = render(&detail(Some("confined: restricted(limited)+low-il+job")));
        assert!(
            out.contains("confinement: confined: restricted(limited)+low-il+job"),
            "{out}"
        );
        assert!(!out.contains("UNCONFINED"), "{out}");
    }

    #[test]
    fn renders_unconfined_prominently() {
        let out = render(&detail(Some(
            "UNCONFINED — --allow-unconfined: host-side VMM confinement disabled by user",
        )));
        // The prominent UNCONFINED marker must survive verbatim.
        assert!(out.contains("confinement: UNCONFINED — "), "{out}");
    }

    #[test]
    fn renders_unknown_when_absent() {
        let out = render(&detail(None));
        assert!(out.contains("confinement: unknown"), "{out}");
    }
}
