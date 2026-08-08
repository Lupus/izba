//! `izba status NAME` — detailed per-sandbox status, including the host-side
//! VMM confinement actually achieved at launch (see `VmHandle::confinement`).

use anyhow::bail;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse, SandboxDetail, SandboxStats};
use izba_core::daemon::DaemonClient;
use izba_core::jail_account::orchestrate::lockdown_state;
use izba_core::paths::Paths;

/// Whether `run()` should fetch guest stats at all (#203): only worth the
/// extra RPC for a running docker-mode sandbox, since that's the only case
/// `engine_line` renders anything from `stats`.
fn wants_engine_stats(det: &SandboxDetail) -> bool {
    det.docker && det.status == "running"
}

#[mutants::skip] // reason: drives a live daemon (Inspect + best-effort Stats RPCs); orchestration exercised by daemon_e2e (docker_publish_reaches_inner_container asserts the engine line end-to-end). The pure pieces (wants_engine_stats, engine_line, render) are unit-tested separately.
pub fn run(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    match client.request(&DaemonRequest::Inspect { name: name.into() }, &mut |_| {})? {
        DaemonResponse::Inspect(det) => {
            // #203: for a running docker-mode sandbox, fetch guest stats to
            // surface nested-Docker-Engine liveness. Best-effort: any
            // transport error or non-Stats reply degrades to `None`
            // ("unknown") rather than failing `status` outright.
            let stats = if wants_engine_stats(&det) {
                match client.request(&DaemonRequest::Stats { name: name.into() }, &mut |_| {}) {
                    Ok(DaemonResponse::Stats(s)) => Some(s),
                    _ => None,
                }
            } else {
                None
            };
            print!("{}", render(paths, &det, stats.as_ref()));
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
fn render(paths: &Paths, det: &SandboxDetail, stats: Option<&SandboxStats>) -> String {
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
    if det.docker {
        // #198, spec §1: docker mode is a materially different security +
        // network profile (own netns + veth, userns-scoped admin caps, an
        // auto /var/lib/docker volume, an auto-started Docker Engine), so it
        // must be visible in `status`/`inspect`. Only shown when on — a normal
        // sandbox stays lean.
        out.push_str("mode:        docker (nested Docker Engine)\n");
        if det.status == "running" {
            // #203: a running docker-mode sandbox must show whether the
            // nested Docker Engine is actually up — a dead dockerd inside a
            // healthy-looking VM is otherwise invisible. Stopped sandboxes
            // print no engine line (there's nothing to report on).
            out.push_str(&engine_line(stats));
            out.push('\n');
        }
    }
    if let Some(declared) = det.user_fallback.as_deref() {
        // Loud-on-degradation (#114): the workload runs as root because the
        // image's symbolic USER could not be resolved host-side — this line
        // re-surfaces the degradation on every `izba status`, not just the
        // one-shot start-time warning. The wording is authored here, NOT
        // copied from the persisted `UserFallback::reason`: only the declared
        // USER string crosses the Inspect wire, and the reason's phrasing
        // targets the start-time warning context ("running the workload as
        // root"), which reads wrong next to a `user:` label.
        out.push_str(&format!(
            "user:        root — image USER '{declared}' could not be resolved (symbolic-USER fallback)\n"
        ));
    }
    out
}

/// The `engine:` line for a docker-mode sandbox (#203): a dead/absent
/// nested Docker Engine must be visible, not a silent "running" sandbox.
/// `stats` is None when the daemon Stats call itself failed, and
/// `stats.guest` is None when the sandbox is running but the in-guest probe
/// couldn't reach it (unresponsive/wedged guest) — both are honestly
/// "unknown". A THIRD case is distinct from either: the guest DID respond
/// (`stats.guest` is `Some`) but reported no docker engine state at all
/// (`guest.docker` is `None`) — that's not a communication failure, so it
/// gets its own wording rather than falsely implying the guest is silent.
fn engine_line(stats: Option<&SandboxStats>) -> String {
    let guest = stats.and_then(|s| s.guest.as_ref());
    match guest.and_then(|g| g.docker.as_ref()) {
        Some(e) if e.running => "engine:      running".to_string(),
        Some(e) => match &e.detail {
            // Daemon-sanitized (control chars stripped), safe to print.
            Some(d) => format!("engine:      not running ({d})"),
            None => {
                "engine:      not running (see /var/log/izba-dockerd.log in the guest)".to_string()
            }
        },
        None if guest.is_some() => {
            "engine:      unknown (guest reported no engine state)".to_string()
        }
        None => "engine:      unknown (guest not responding)".to_string(),
    }
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
            docker: false,
        }
    }

    #[test]
    fn wants_engine_stats_is_docker_and_running() {
        // All four docker×status combinations pin the exact `docker &&
        // status == "running"` truth table, so a flipped `&&`/`||` or a
        // flipped `==`/`!=` cannot survive.
        let mut det = detail(None);
        det.docker = false;
        det.status = "stopped".into();
        assert!(!wants_engine_stats(&det), "neither ⇒ off");
        det.docker = true;
        det.status = "stopped".into();
        assert!(!wants_engine_stats(&det), "docker but not running ⇒ off");
        det.docker = false;
        det.status = "running".into();
        assert!(!wants_engine_stats(&det), "running but not docker ⇒ off");
        det.docker = true;
        det.status = "running".into();
        assert!(wants_engine_stats(&det), "docker and running ⇒ on");
    }

    #[test]
    fn renders_confined_summary() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(
            &paths,
            &detail(Some("confined: restricted(limited)+low-il+job")),
            None,
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
            None,
        );
        // The prominent UNCONFINED marker must survive verbatim.
        assert!(out.contains("confinement: UNCONFINED — "), "{out}");
    }

    #[test]
    fn renders_unknown_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(&paths, &detail(None), None);
        assert!(out.contains("confinement: unknown"), "{out}");
    }

    #[test]
    fn renders_container_running() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(
            &paths,
            &detail_with_container(None, Some(izba_proto::ContainerState::Running)),
            None,
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
            None,
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
        let out = render(&paths, &detail_with_container(None, None), None);
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
        let out = render(&paths, &det, None);
        assert!(out.contains("root"), "got: {out}");
        assert!(out.contains("'node'"), "got: {out}");
        assert!(out.contains("user:        root"), "got: {out}");
    }

    #[test]
    fn no_user_line_without_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(&paths, &detail(None), None);
        assert!(!out.contains("USER"), "got: {out}");
    }

    #[test]
    fn renders_docker_mode_when_on() {
        // #198 / spec §1: a docker-mode sandbox must surface it in `status`.
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let mut det = detail(None);
        det.docker = true;
        let out = render(&paths, &det, None);
        assert!(out.contains("mode:        docker"), "got: {out}");
    }

    #[test]
    fn renders_engine_line_for_running_docker_sandbox() {
        // #203: the engine line rides directly under `mode:` when stats are
        // unavailable it still degrades to the honest "unknown" line rather
        // than being omitted.
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let mut det = detail(None);
        det.docker = true;
        det.status = "running".into();
        let out = render(&paths, &det, None);
        assert!(
            out.contains("mode:        docker (nested Docker Engine)\nengine:      unknown (guest not responding)\n"),
            "got: {out}"
        );
    }

    #[test]
    fn no_engine_line_for_stopped_docker_sandbox() {
        // Spec §5: a stopped docker-mode sandbox has no live guest to report
        // on, so `status` prints no `engine:` line at all.
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let mut det = detail(None);
        det.docker = true;
        det.status = "stopped".into();
        let out = render(&paths, &det, None);
        assert!(out.contains("mode:        docker"), "got: {out}");
        assert!(!out.contains("engine:"), "got: {out}");
    }

    #[test]
    fn no_docker_line_for_a_normal_sandbox() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(&paths, &detail(None), None);
        assert!(!out.contains("mode:"), "got: {out}");
    }

    #[test]
    fn renders_lockdown_unlocked_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let out = render(&paths, &detail(None), None);
        assert!(out.contains("lock-down:   unlocked"), "{out}");
    }

    #[test]
    fn engine_line_renders_all_states() {
        use izba_core::daemon::proto::SandboxStats;
        fn stats_with_guest(guest: Option<izba_proto::GuestStats>) -> SandboxStats {
            SandboxStats {
                name: "web".into(),
                running: true,
                uptime_ms: None,
                host: None,
                disk: izba_core::daemon::proto::HostDisk {
                    rw_img_bytes: 0,
                    volumes: vec![],
                    logs_bytes: 0,
                    image_bytes: 0,
                },
                guest,
            }
        }
        // The guest DID respond (guest: Some), just with no docker field set
        // (docker: None) — distinct from an unreachable guest.
        fn stats_with(docker: Option<izba_proto::DockerEngine>) -> SandboxStats {
            stats_with_guest(Some(izba_proto::GuestStats {
                processes: vec![],
                process_count: 0,
                load1_centi: 0,
                load5_centi: 0,
                load15_centi: 0,
                mem_total_kb: 0,
                mem_available_kb: 0,
                mounts: vec![],
                docker,
                container: None,
            }))
        }
        assert_eq!(
            engine_line(Some(&stats_with(Some(izba_proto::DockerEngine {
                running: true,
                detail: None
            })))),
            "engine:      running"
        );
        assert_eq!(
            engine_line(Some(&stats_with(Some(izba_proto::DockerEngine {
                running: false,
                detail: Some("failed to start daemon: no cgroup".into()),
            })))),
            "engine:      not running (failed to start daemon: no cgroup)"
        );
        assert_eq!(
            engine_line(Some(&stats_with(Some(izba_proto::DockerEngine {
                running: false,
                detail: None
            })))),
            "engine:      not running (see /var/log/izba-dockerd.log in the guest)"
        );
        // Stats call itself failed (daemon unreachable / RPC error): honest
        // unknown, "guest not responding".
        assert_eq!(
            engine_line(None),
            "engine:      unknown (guest not responding)"
        );
        // Sandbox running, but the in-guest stats probe couldn't reach it
        // (guest: None despite a successful Stats RPC): same wording — from
        // the caller's perspective the guest is silent either way.
        assert_eq!(
            engine_line(Some(&stats_with_guest(None))),
            "engine:      unknown (guest not responding)"
        );
        // Guest DID respond but reported no docker engine state at all: a
        // different flavor of "unknown" — not a communication failure.
        assert_eq!(
            engine_line(Some(&stats_with(None))),
            "engine:      unknown (guest reported no engine state)"
        );
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

        let out = render(&paths, &detail(None), None);
        assert!(
            out.contains("lock-down:   locked(account=izba-sb-web"),
            "{out}"
        );
    }
}
