use std::path::PathBuf;

use crate::daemon::DaemonApi;
use crate::views::{
    app_build_info, CreateOpts, DaemonStatusView, DiffView, PolicyView, PortRuleView, PromoteView,
    SandboxDetailView, SandboxView, SeedEntry, VersionView, VolumeInfoView,
};
use izba_core::daemon::egress::audit::EndpointSummary;
use izba_core::daemon::egress::config::{AllowEntry, GitRule};
use izba_core::manifest::store;
use izba_core::paths::Paths;
use izba_core::state::{load_json, SandboxConfig, CONFIG_FILE};

/// Core of the `list` command: maps daemon errors to a UI-friendly string.
pub fn list_core(d: &mut dyn DaemonApi) -> Result<Vec<SandboxView>, String> {
    d.list().map_err(|e| e.to_string())
}

/// Core of the `daemon_status` command.
pub fn status_core(d: &mut dyn DaemonApi) -> Result<DaemonStatusView, String> {
    d.status().map_err(|e| e.to_string())
}

/// Core of the `read_logs` command.
pub fn read_logs_core(d: &mut dyn DaemonApi, name: &str) -> Result<String, String> {
    d.read_logs(name).map_err(|e| e.to_string())
}

/// Core of the `version_info` command: this app's build, the linked core build,
/// and the daemon's (when reachable) with a mismatch flag. An unreachable
/// daemon is not an error here — the panel just shows "not running".
pub fn version_core(d: &mut dyn DaemonApi) -> Result<VersionView, String> {
    let app = app_build_info();
    let core = izba_core::build_info::BuildInfoOwned::current();
    let (daemon, proto, mismatch) = match d.version() {
        Ok((build, proto)) => {
            // Compare the commit sha only — the same identity the About panel
            // shows. NOT git_describe: the app's build.rs enables vergen's dirty
            // flag, and its npm/dist build dirties the tree before vergen runs, so
            // the app describe gets a `-dirty` suffix the (clean) daemon build
            // lacks — a false mismatch at the identical commit. NOT the whole
            // struct either: build_timestamp/rustc always differ across the two
            // separately-built binaries.
            let mismatch = build.git_sha != app.git_sha;
            (Some(build), proto, mismatch)
        }
        Err(_) => (None, 0, false),
    };
    Ok(VersionView {
        app,
        core,
        daemon,
        proto,
        mismatch,
    })
}

/// Start a sandbox (may boot-wait inside the daemon).
pub fn start_core(d: &mut dyn DaemonApi, name: &str) -> Result<(), String> {
    d.start(name).map_err(|e| e.to_string())
}

/// Stop a sandbox.
pub fn stop_core(d: &mut dyn DaemonApi, name: &str) -> Result<(), String> {
    d.stop(name).map_err(|e| e.to_string())
}

/// Restart = stop then start (izba never auto-restarts). Stop failure aborts
/// before start so a half-restart never silently boots a stale config.
pub fn restart_core(d: &mut dyn DaemonApi, name: &str) -> Result<(), String> {
    d.stop(name).map_err(|e| e.to_string())?;
    d.start(name).map_err(|e| e.to_string())
}

/// Remove a sandbox (force skips the running-state guard).
pub fn remove_core(d: &mut dyn DaemonApi, name: &str, force: bool) -> Result<(), String> {
    d.remove(name, force).map_err(|e| e.to_string())
}

/// Create a sandbox, forwarding daemon `Progress` messages via `on_progress`.
/// The workspace's `izba.yml` (if any) is PARSED before the daemon `Create`
/// RPC — see [`parse_workspace_manifest`] — so a corrupt manifest aborts the
/// create before any sandbox exists (CLI parity: `izba-cli`'s
/// `merge_manifest_into_opts` runs before `DaemonClient` create too, see
/// `crates/izba-cli/src/commands/create.rs`). Once the daemon confirms
/// creation, [`write_manifest_base`] does the write phase (needs the sandbox
/// dir to exist) — see its doc comment for why the base seed itself is
/// required, not cosmetic.
pub fn create_core(
    d: &mut dyn DaemonApi,
    opts: CreateOpts,
    on_progress: &mut dyn FnMut(&str),
) -> Result<String, String> {
    let req = opts.into_daemon_create().map_err(|e| e.to_string())?;
    let workspace = req.workspace.clone();
    // Parse-before-create: a corrupt izba.yml must fail HERE, before the
    // daemon RPC, so no orphan sandbox is left behind. Doing this after
    // `d.create(...)` (the pre-fix ordering) meant a parse error surfaced
    // only once the sandbox already existed on disk — the user's retry then
    // hit "already exists" with no way to fix it short of `izba rm`.
    let manifest = parse_workspace_manifest(&workspace)?;
    let name = d.create(req, on_progress).map_err(|e| e.to_string())?;
    if let Some(m) = manifest {
        // The sandbox EXISTS from here on. A seeding failure (rare: fs errors
        // under the data dir) must not masquerade as a failed create — that
        // sends the user into an "already exists" retry loop. Report the
        // truth and the recovery path instead of attempting a rollback
        // (destroying a just-created sandbox over a bookkeeping write is
        // worse than partial manifest state, which `izba diff` self-reports).
        write_manifest_base(&app_paths(), &name, &m).map_err(|e| {
            format!(
                "sandbox '{name}' was created, but applying izba.yml state failed: {e}. \
                 The sandbox exists with partial manifest state — check the Manifest tab, \
                 or remove it and create again."
            )
        })?;
    }
    Ok(name)
}

/// Parse phase of GUI-create manifest seeding: load & parse `workspace`'s
/// `izba.yml`, if any, WITHOUT touching the daemon or any sandbox directory —
/// safe to call before the `Create` RPC.
///
/// - No `izba.yml` in `workspace`: `Ok(None)`, matching pre-fix behavior for
///   the common case.
/// - `izba.yml` present but fails to parse: returns `Err` with the parse
///   message. CLI parity — `merge_manifest_into_opts` propagates the same
///   failure and aborts `izba create` before it ever reaches the daemon.
/// - Valid manifest: `Ok(Some(m))`, handed to [`write_manifest_base`] after
///   the sandbox is created.
fn parse_workspace_manifest(
    workspace: &std::path::Path,
) -> Result<Option<izba_core::manifest::Manifest>, String> {
    if !workspace.join("izba.yml").exists() {
        return Ok(None);
    }
    let (m, _raw, _dockerfile) =
        izba_core::manifest::ops::load_repo_manifest(workspace).map_err(|e| e.to_string())?;
    Ok(Some(m))
}

/// Write phase of GUI-create manifest seeding (CLI parity with
/// `crates/izba-cli/src/commands/create.rs`): seed the sandbox's manifest
/// reconciliation base (`manifest.base.yaml`) from `m`, clear any stale
/// review token, and seed `policy.yaml` from `m.spec.egress` (mirroring the
/// CLI's `persist_policy_config`, via the shared `EgressPolicyConfig::
/// write_to`). Called only after the daemon has confirmed the sandbox dir
/// exists — `store::write_base`/`clear_review` and `EgressPolicyConfig::
/// write_to` all write under `paths.sandbox_dir(name)`.
///
/// Without this, `compute_diff` (`crates/izba-core/src/manifest/ops.rs`)
/// falls back to `base = managed.clone()` for a sandbox that has never had a
/// base written — which makes `managed_ahead` UNREACHABLE for GUI-created
/// sandboxes: any later in-app change (e.g. editing the egress policy on the
/// Policy tab) gets misclassified as `repo_ahead` against the *unchanged*
/// `izba.yml`, and clicking Promote would silently REVERT the user's own
/// edit instead of the intended Export-to-capture-drift flow.
///
/// The base is written from the manifest exactly as it stood at creation
/// time — it is NOT reconciled against the form-provided `CreateOpts`
/// (image/cpus/mem stay form-authoritative, matching the CLI's "explicit
/// flags always win" rule). So a create where the form's image differs from
/// `izba.yml`'s honestly shows up as `managed_ahead` the moment `izba diff`/
/// the Manifest tab is opened — same semantics as a CLI flag override, and
/// exactly what Export exists to capture.
fn write_manifest_base(
    paths: &Paths,
    name: &str,
    m: &izba_core::manifest::Manifest,
) -> Result<(), String> {
    let sandbox_dir = paths.sandbox_dir(name);
    if let Some(ref eg) = m.spec.egress {
        eg.write_to(&sandbox_dir).map_err(|e| e.to_string())?;
    }
    store::write_base(&sandbox_dir, m).map_err(|e| e.to_string())?;
    store::clear_review(&sandbox_dir).map_err(|e| e.to_string())?;
    Ok(())
}

/// Core of `read_netlog`: per-endpoint aggregated audit summaries.
pub fn read_netlog_core(d: &mut dyn DaemonApi, name: &str) -> Result<Vec<EndpointSummary>, String> {
    d.read_netlog(name).map_err(|e| e.to_string())
}

/// Core of `policy_show`: the sandbox's effective egress policy.
pub fn policy_show_core(d: &mut dyn DaemonApi, name: &str) -> Result<PolicyView, String> {
    d.policy_show(name).map_err(|e| e.to_string())
}

/// Core of `policy_allow`: authorize a host:port (auto-reloads).
pub fn policy_allow_core(
    d: &mut dyn DaemonApi,
    name: &str,
    host: &str,
    port: u16,
) -> Result<(), String> {
    d.policy_allow(name, host, port).map_err(|e| e.to_string())
}

/// Core of `policy_block`: revoke a host:port (auto-reloads).
pub fn policy_block_core(
    d: &mut dyn DaemonApi,
    name: &str,
    host: &str,
    port: u16,
) -> Result<(), String> {
    d.policy_block(name, host, port).map_err(|e| e.to_string())
}

/// Core of `policy_set`: replace the allow-list wholesale (auto-reloads).
pub fn policy_set_core(
    d: &mut dyn DaemonApi,
    name: &str,
    allow: Vec<AllowEntry>,
) -> Result<(), String> {
    d.policy_set(name, allow).map_err(|e| e.to_string())
}

/// Core of `policy_add_endpoints`: additively merge entries (enforce only when flag set).
pub fn policy_add_endpoints_core(
    d: &mut dyn DaemonApi,
    name: &str,
    entries: Vec<SeedEntry>,
    enforce: bool,
) -> Result<(), String> {
    d.policy_add_endpoints(name, entries, enforce)
        .map_err(|e| e.to_string())
}

/// Core of `policy_set_full`: replace allow + git rule sets (enforce untouched).
pub fn policy_set_full_core(
    d: &mut dyn DaemonApi,
    name: &str,
    allow: Vec<AllowEntry>,
    git: Vec<GitRule>,
) -> Result<(), String> {
    d.policy_set_full(name, allow, git)
        .map_err(|e| e.to_string())
}

/// Core of `policy_git_allow`: authorize a git target (auto-reloads).
pub fn policy_git_allow_core(
    d: &mut dyn DaemonApi,
    name: &str,
    target: &str,
    write: bool,
) -> Result<(), String> {
    d.policy_git_allow(name, target, write)
        .map_err(|e| e.to_string())
}

/// Core of `policy_git_block`: revoke a git target (auto-reloads).
pub fn policy_git_block_core(
    d: &mut dyn DaemonApi,
    name: &str,
    target: &str,
) -> Result<(), String> {
    d.policy_git_block(name, target).map_err(|e| e.to_string())
}

/// Core of `policy_set_enforce`: set the enforcing flag (auto-reloads).
pub fn policy_set_enforce_core(d: &mut dyn DaemonApi, name: &str, on: bool) -> Result<(), String> {
    d.policy_set_enforce(name, on).map_err(|e| e.to_string())
}

/// Core of `inspect`: full sandbox detail (ports + volumes) mapped to a view.
pub fn inspect_core(d: &mut dyn DaemonApi, name: &str) -> Result<SandboxDetailView, String> {
    d.inspect(name)
        .map(SandboxDetailView::from)
        .map_err(|e| e.to_string())
}

/// Core of `port_list`: active port-publish rules mapped to views.
pub fn port_list_core(d: &mut dyn DaemonApi, name: &str) -> Result<Vec<PortRuleView>, String> {
    d.port_list(name)
        .map(|rules| rules.into_iter().map(PortRuleView::from).collect())
        .map_err(|e| e.to_string())
}

/// Core of `port_publish`: parses `rule_spec` as `[BIND:]HOST:GUEST` then publishes.
pub fn port_publish_core(
    d: &mut dyn DaemonApi,
    name: &str,
    rule_spec: &str,
    persist: bool,
) -> Result<(), String> {
    let rule = izba_core::portfwd::parse_rule(rule_spec).map_err(|e| e.to_string())?;
    d.port_publish(name, rule, persist)
        .map_err(|e| e.to_string())
}

/// Core of `port_unpublish`: removes the rule identified by `(bind, host_port)`.
pub fn port_unpublish_core(
    d: &mut dyn DaemonApi,
    name: &str,
    bind: std::net::Ipv4Addr,
    host_port: u16,
) -> Result<(), String> {
    d.port_unpublish(name, bind, host_port)
        .map_err(|e| e.to_string())
}

/// Core of `volume_list`: persistent volumes mapped to views.
pub fn volume_list_core(d: &mut dyn DaemonApi) -> Result<Vec<VolumeInfoView>, String> {
    d.volume_list()
        .map(|vols| vols.into_iter().map(VolumeInfoView::from).collect())
        .map_err(|e| e.to_string())
}

/// Core of `volume_remove`: remove a named persistent volume.
pub fn volume_remove_core(d: &mut dyn DaemonApi, name: &str) -> Result<(), String> {
    d.volume_remove(name).map_err(|e| e.to_string())
}

/// Core of `volume_prune`: prune unreferenced persistent volumes.
pub fn volume_prune_core(d: &mut dyn DaemonApi) -> Result<izba_core::volume::Pruned, String> {
    d.volume_prune().map_err(|e| e.to_string())
}

/// Resolve this app's data root the same way the CLI does:
/// `IZBA_DATA_DIR` wins when set, otherwise the per-OS default (mirrors
/// `crates/izba-cli/src/main.rs`'s `Paths::from_env_or_default(std::env::
/// var_os("IZBA_DATA_DIR")...)` line exactly). Without this the app silently
/// ignored the env var and every sandbox landed under the real `$HOME`
/// regardless — the GUI dogfood headless sidecar
/// (`hack/dogfood/gui/run_gui_journeys.py`) sets `IZBA_DATA_DIR` per journey
/// and depends on the app honoring it for per-journey isolation and the
/// reconcile oracle. Used by `RealDaemon::new` and the manifest cores below.
pub(crate) fn app_paths() -> Paths {
    Paths::from_env_or_default(std::env::var_os("IZBA_DATA_DIR").map(PathBuf::from))
}

/// Resolve sandbox `name`'s workspace directory from its `config.json` — the
/// single source of truth for "where is this sandbox's `izba.yml`". Name-only
/// manifest cores never take a frontend-supplied path (the config.json
/// record is host-authoritative; see the CLI's `sandbox_ref` by-name
/// resolution, which this mirrors).
fn workspace_for(paths: &Paths, name: &str) -> Result<PathBuf, String> {
    let cfg: Option<SandboxConfig> =
        load_json(&paths.sandbox_dir(name).join(CONFIG_FILE)).map_err(|e| e.to_string())?;
    let cfg = cfg.ok_or_else(|| format!("sandbox '{name}' not found"))?;
    if cfg.workspace.as_os_str().is_empty() {
        return Err(format!("sandbox '{name}' has no recorded workspace"));
    }
    Ok(cfg.workspace)
}

/// The exact error string `manifest_diff_core` returns when the sandbox's
/// workspace has no `izba.yml` at all. ManifestTab.tsx keys its "No izba.yml
/// found" guidance panel on this substring — a CORRUPT-but-present izba.yml
/// must NOT match it (that's a parse error from `compute_diff`, which also
/// happens to mention "izba.yml" in its message, e.g. `Manifest::load_str`'s
/// `.context("parsing izba.yml")`; it has to flow through as a raw, honest
/// error instead of being mislabeled "file doesn't exist").
pub const NO_MANIFEST_ERROR: &str = "no izba.yml found in workspace";

/// Core of `manifest_diff`: compute the structural diff between the sandbox's
/// recorded workspace `izba.yml` and the managed truth for sandbox `name`.
/// WRITES the review token — rendering the diff to the user IS the review
/// that gates a subsequent `manifest_promote` (mirrors the CLI's `izba diff`).
pub fn manifest_diff_core(name: &str) -> Result<DiffView, String> {
    let paths = app_paths();
    let ws = workspace_for(&paths, name)?;
    if !ws.join("izba.yml").exists() {
        return Err(NO_MANIFEST_ERROR.to_string());
    }
    let (state, deltas, token) =
        izba_core::manifest::ops::compute_diff(&paths, &ws, name).map_err(|e| e.to_string())?;
    store::write_review(&paths.sandbox_dir(name), &token).map_err(|e| e.to_string())?;
    Ok(DiffView::new(state, &deltas))
}

/// Core of `manifest_export`: write the managed truth back into the sandbox's
/// recorded workspace `izba.yml` and return the path written as a string.
pub fn manifest_export_core(name: &str) -> Result<String, String> {
    let paths = app_paths();
    let ws = workspace_for(&paths, name)?;
    izba_core::manifest::ops::export(&paths, &ws, name)
        .map(|p| p.display().to_string())
        .map_err(|e| e.to_string())
}

/// Core of `manifest_promote`: apply the reviewed `izba.yml` -> managed truth
/// for sandbox `name` (never `--force`s the review gate; `restart` mirrors
/// the CLI's `--restart` flag; scratch is never wiped from the app).
/// `spec.build:` promotion needs a whole throwaway builder-sandbox
/// orchestration that only the CLI drives today
/// (`izba-cli::commands::build::build_image`); the app surfaces a clear error
/// instead of attempting it.
pub fn manifest_promote_core(name: &str, restart: bool) -> Result<PromoteView, String> {
    // CLI parity: `promote::run` trusts its caller to have validated the name
    // (the CLI does this in `commands::promote::run`); `Paths::sandbox_dir`
    // is a bare join, so validate before any path is derived from `name`.
    izba_core::sandbox::validate_name(name).map_err(|e| e.to_string())?;
    let paths = app_paths();
    let ws = workspace_for(&paths, name)?;
    let opts = izba_core::manifest::promote::PromoteOpts {
        force: false,
        restart,
        reset_scratch: false,
    };
    let outcome = izba_core::manifest::promote::run(
        &paths,
        &ws,
        name,
        opts,
        &mut |_event| {},
        &mut |_dir, _build| {
            Err(anyhow::anyhow!(
                "spec.build is not supported from the app yet — use 'izba promote' in a terminal"
            ))
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(PromoteView::new(outcome))
}

/// Core of `volume_attach`: attach a volume spec (parsed from `spec_str`) to sandbox `name`.
pub fn volume_attach_core(d: &mut dyn DaemonApi, name: &str, spec_str: &str) -> Result<(), String> {
    let spec = izba_core::volume::parse_volume_flag(spec_str).map_err(|e| e.to_string())?;
    d.volume_attach(name, spec).map_err(|e| e.to_string())
}

/// Core of `volume_detach`: detach the volume at `guest_path` from sandbox `name`.
pub fn volume_detach_core(
    d: &mut dyn DaemonApi,
    name: &str,
    guest_path: String,
) -> Result<(), String> {
    d.volume_detach(name, guest_path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeDaemon;
    use crate::views::{CreateOpts, SbxState};

    /// Serializes tests that mutate process-global env vars consulted by
    /// `app_paths()`/`Paths::from_env_or_default` (`$HOME`, `IZBA_DATA_DIR`)
    /// — two such tests running concurrently in this test binary would
    /// clobber each other's sandbox trees or each other's restored values.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII: points `$HOME` at a fresh, empty tempdir for the test's
    /// duration (isolating `manifest_*_core`'s internal
    /// `Paths::from_env_or_default(None)` from the real machine), restoring
    /// the original value and cleaning up on drop.
    struct HomeGuard {
        original: Option<String>,
        home: std::path::PathBuf,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl HomeGuard {
        fn new() -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos();
            let home = std::env::temp_dir().join(format!("izba-app-cmd-test-home-{nanos}"));
            std::fs::create_dir_all(&home).unwrap();
            let original = std::env::var("HOME").ok();
            std::env::set_var("HOME", &home);
            HomeGuard {
                original,
                home,
                _lock: lock,
            }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }

    fn create_opts() -> CreateOpts {
        CreateOpts {
            name: "new".into(),
            image: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 1024,
            workspace: "/ws".into(),
            rw_size_gb: 4,
            ports: vec![],
            volumes: vec![],
        }
    }

    #[test]
    fn start_stop_remove_dispatch() {
        let mut d = FakeDaemon::default();
        start_core(&mut d, "web").unwrap();
        stop_core(&mut d, "web").unwrap();
        remove_core(&mut d, "web", true).unwrap();
        assert_eq!(d.calls, vec!["start:web", "stop:web", "rm:web:true"]);
    }

    #[test]
    fn restart_is_stop_then_start() {
        let mut d = FakeDaemon::default();
        restart_core(&mut d, "web").unwrap();
        assert_eq!(d.calls, vec!["stop:web", "start:web"]);
    }

    #[test]
    fn restart_does_not_start_if_stop_fails() {
        let mut d = FakeDaemon {
            fail_action: true,
            ..Default::default()
        };
        assert!(restart_core(&mut d, "web").is_err());
        assert_eq!(d.calls, vec!["stop:web"]); // start not attempted
    }

    #[test]
    fn create_core_streams_and_returns_name() {
        let mut d = FakeDaemon::default();
        let mut seen = Vec::new();
        let name = create_core(&mut d, create_opts(), &mut |m| seen.push(m.to_string())).unwrap();
        assert_eq!(name, "new");
        assert_eq!(seen, vec!["pulling image", "booting"]);
    }

    #[test]
    fn create_core_maps_bad_name_to_error() {
        let mut d = FakeDaemon::default();
        let mut bad = create_opts();
        bad.name = "Bad Name".into();
        let err = create_core(&mut d, bad, &mut |_| {}).unwrap_err();
        assert!(err.contains("invalid sandbox name"), "got: {err}");
    }

    /// `create_core` must seed the manifest reconciliation base from the
    /// chosen workspace's `izba.yml` — CLI parity, see `write_manifest_base`'s
    /// doc comment for why a missing base makes `managed_ahead` unreachable.
    #[test]
    fn create_core_seeds_manifest_base_from_workspace_izba_yml() {
        let guard = HomeGuard::new();
        let ws = guard.home.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("izba.yml"), MINIMAL_MANIFEST).unwrap();

        let paths = app_paths();
        // The real daemon's Create RPC creates the sandbox dir on disk before
        // replying `Created`; `FakeDaemon` never touches disk, so create it
        // here to let `write_manifest_base`'s writes land, mirroring reality.
        std::fs::create_dir_all(paths.sandbox_dir("new")).unwrap();

        let mut d = FakeDaemon::default();
        let mut opts = create_opts();
        opts.workspace = ws.display().to_string();
        let name = create_core(&mut d, opts, &mut |_| {}).unwrap();

        assert!(
            store::read_base(&paths.sandbox_dir(&name))
                .unwrap()
                .is_some(),
            "create_core must write manifest.base.yaml from the workspace izba.yml"
        );
    }

    /// A workspace with no `izba.yml` leaves `create_core` exactly as before
    /// this fix: no base is written, no error.
    #[test]
    fn create_core_no_manifest_is_noop_for_base_seeding() {
        let guard = HomeGuard::new();
        let ws = guard.home.join("ws-bare");
        std::fs::create_dir_all(&ws).unwrap();

        let paths = app_paths();
        std::fs::create_dir_all(paths.sandbox_dir("new")).unwrap();

        let mut d = FakeDaemon::default();
        let mut opts = create_opts();
        opts.workspace = ws.display().to_string();
        let name = create_core(&mut d, opts, &mut |_| {}).unwrap();

        assert!(store::read_base(&paths.sandbox_dir(&name))
            .unwrap()
            .is_none());
    }

    /// A workspace with a syntactically broken `izba.yml` must fail the
    /// create outright (CLI parity) rather than silently skip base-seeding —
    /// a silent skip would recreate the exact bug this fix closes. And,
    /// crucially, it must fail BEFORE the daemon is ever asked to create the
    /// sandbox: parsing after `d.create(...)` (the pre-fix ordering) left an
    /// orphan sandbox on disk that a retry would then hit as "already
    /// exists" — this asserts the daemon's `create` was never called.
    #[test]
    fn create_core_fails_on_unparseable_workspace_manifest() {
        let guard = HomeGuard::new();
        let ws = guard.home.join("ws-broken");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("izba.yml"), "not: [valid, izba.yml").unwrap();

        let mut d = FakeDaemon::default();
        let mut opts = create_opts();
        opts.workspace = ws.display().to_string();
        let err = create_core(&mut d, opts, &mut |_| {}).unwrap_err();
        assert!(err.contains("parsing izba.yml"), "got: {err}");
        assert!(
            d.calls.is_empty(),
            "daemon must never be asked to create a sandbox for an unparseable manifest, got: {:?}",
            d.calls
        );
    }

    /// Greptile P1 (PR #130): a seeding failure AFTER the daemon created the
    /// sandbox must not masquerade as a failed create (retry → "already
    /// exists" loop). The error must state the sandbox exists and how to
    /// recover. Natural failure here: the fake daemon returns a name but no
    /// sandbox dir exists under the data root, so `write_manifest_base`'s
    /// first write fails.
    #[test]
    fn create_core_seeding_failure_reports_created_sandbox() {
        let guard = HomeGuard::new();
        let ws = guard.home.join("ws-seedfail");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(
            ws.join("izba.yml"),
            "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nspec:\n  image: alpine:3.20\n",
        )
        .unwrap();

        let mut d = FakeDaemon::default();
        let mut opts = create_opts();
        opts.workspace = ws.display().to_string();
        let err = create_core(&mut d, opts, &mut |_| {}).unwrap_err();
        assert!(err.contains("was created"), "got: {err}");
        assert!(err.contains("remove it and create again"), "got: {err}");
        assert!(
            !d.calls.is_empty(),
            "the daemon create must have happened for this error to be honest"
        );
    }

    /// A fresh scratch dir under the OS temp dir, nanosecond-tagged like the
    /// other ad-hoc temp dirs in this file (this crate has no `tempfile`
    /// dev-dependency). Caller is responsible for `remove_dir_all` cleanup.
    fn scratch_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = std::env::temp_dir().join(format!("izba-app-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `parse_workspace_manifest` is the pure, unit-testable parse phase of
    /// the create-time seeding `create_core` wires up above. No `izba.yml`
    /// in `workspace` is a no-op — matches pre-fix behavior for the (still
    /// common) manifest-less create.
    #[test]
    fn parse_workspace_manifest_noop_when_no_manifest() {
        let tmp = scratch_dir("parse-noop");
        let ws = tmp.join("ws");
        std::fs::create_dir_all(&ws).unwrap();

        assert!(parse_workspace_manifest(&ws).unwrap().is_none());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// A valid `izba.yml` with a declared `spec.egress`: `parse_workspace_
    /// manifest` returns it, and `write_manifest_base` must then write
    /// `manifest.base.yaml`, clear any stale review token, and seed
    /// `policy.yaml` from the declared egress config.
    #[test]
    fn write_manifest_base_valid_manifest_writes_base_and_seeds_policy() {
        let tmp = scratch_dir("seed-valid");
        let paths = Paths::with_root(tmp.join("izba"));
        let name = "seeded";
        let sandbox_dir = paths.sandbox_dir(name);
        std::fs::create_dir_all(&sandbox_dir).unwrap();
        // A stale review token from some earlier state must be cleared —
        // mirrors the CLI's `store::clear_review` call in `create.rs`.
        store::write_review(&sandbox_dir, "stale-token").unwrap();

        let ws = tmp.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(
            ws.join("izba.yml"),
            "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nspec:\n  image: alpine:3\n  egress:\n    enforce: true\n    allow:\n      - github.com\n",
        )
        .unwrap();

        let m = parse_workspace_manifest(&ws).unwrap().unwrap();
        write_manifest_base(&paths, name, &m).unwrap();

        let base = store::read_base(&sandbox_dir).unwrap();
        assert!(base.is_some(), "manifest.base.yaml must be written");
        assert_eq!(base.unwrap().spec.image.as_deref(), Some("alpine:3"));

        assert!(
            store::read_review(&sandbox_dir).unwrap().is_none(),
            "stale review token must be cleared"
        );

        let policy = izba_core::daemon::egress::config::EgressPolicyConfig::load(&sandbox_dir)
            .unwrap()
            .expect("policy.yaml should be seeded from spec.egress");
        assert!(policy.enforce);
        assert_eq!(policy.allow.len(), 1);

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// A syntactically broken `izba.yml` returns the parse error verbatim
    /// from `parse_workspace_manifest` — before any sandbox dir needs to
    /// exist, and without ever reaching `write_manifest_base`. A silent skip
    /// would recreate the `managed_ahead`-unreachable bug for a typo'd
    /// manifest; a post-create parse (the pre-fix ordering) would leave an
    /// orphan sandbox behind.
    #[test]
    fn parse_workspace_manifest_parse_error_returns_err() {
        let tmp = scratch_dir("seed-parse-error");
        let ws = tmp.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("izba.yml"), "not: [valid, izba.yml").unwrap();

        let err = parse_workspace_manifest(&ws).unwrap_err();
        assert!(err.contains("parsing izba.yml"), "got: {err}");

        std::fs::remove_dir_all(&tmp).ok();
    }

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
        let mut d = FakeDaemon {
            fail_list: true,
            ..Default::default()
        };
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

    #[test]
    fn status_core_maps_error_to_string() {
        let mut d = FakeDaemon {
            fail_status: true,
            ..Default::default()
        };
        let err = status_core(&mut d).unwrap_err();
        assert!(err.contains("daemon unreachable"), "got: {err}");
    }

    #[test]
    fn version_core_flags_mismatch_when_daemon_differs() {
        // The fake daemon reports a sha that cannot match the real app build.
        let mut d = FakeDaemon {
            daemon_sha: "deadbeef".into(),
            ..Default::default()
        };
        let v = version_core(&mut d).unwrap();
        assert!(v.daemon.is_some());
        assert!(v.mismatch);
        assert!(!v.app.git_describe.is_empty());
    }

    #[test]
    fn version_core_no_mismatch_when_sha_matches() {
        // Same commit ⇒ same git_sha, even though the two binaries were built at
        // different instants (build_timestamp/rustc differ) and the app build may
        // be `-dirty` while the daemon is clean. The warning must NOT fire.
        let mut d = FakeDaemon {
            daemon_sha: app_build_info().git_sha,
            ..Default::default()
        };
        let v = version_core(&mut d).unwrap();
        assert!(v.daemon.is_some());
        assert!(!v.mismatch, "identical commit sha must not flag a mismatch");
    }

    #[test]
    fn read_logs_core_returns_text() {
        let mut d = FakeDaemon::default();
        let t = read_logs_core(&mut d, "web").unwrap();
        assert!(t.contains("boot"), "got: {t}");
    }

    #[test]
    fn read_netlog_core_returns_summaries() {
        let mut d = crate::fake::FakeDaemon::default();
        let rows = read_netlog_core(&mut d, "web").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host.as_deref(), Some("api.x.com"));
    }

    #[test]
    fn policy_edit_cores_record_calls() {
        let mut d = crate::fake::FakeDaemon::default();
        policy_allow_core(&mut d, "web", "api.x.com", 443).unwrap();
        policy_block_core(&mut d, "web", "api.x.com", 80).unwrap();
        policy_add_endpoints_core(&mut d, "web", vec![], false).unwrap();
        assert!(d.calls.iter().any(|c| c == "allow:web:api.x.com:443"));
        assert!(d.calls.iter().any(|c| c == "block:web:api.x.com:80"));
        assert!(d.calls.iter().any(|c| c.starts_with("add_endpoints:web:")));
    }

    #[test]
    fn version_core_no_mismatch_when_daemon_absent() {
        let mut d = FakeDaemon {
            daemon_absent: true,
            ..Default::default()
        };
        let v = version_core(&mut d).unwrap();
        assert!(v.daemon.is_none());
        assert!(!v.mismatch);
    }

    #[test]
    fn inspect_core_returns_mapped_view() {
        let mut d = FakeDaemon::default();
        let v = inspect_core(&mut d, "web").unwrap();
        assert_eq!(v.name, "web");
        assert_eq!(v.image, "ubuntu:24.04");
        assert_eq!(v.status, "running");
        assert!(v.ports.is_empty());
        assert!(v.volumes.is_empty());
    }

    #[test]
    fn port_list_core_returns_mapped_rules() {
        use std::net::Ipv4Addr;
        let mut d = FakeDaemon {
            ports: vec![izba_core::state::PortRule {
                bind: Ipv4Addr::new(127, 0, 0, 1),
                host_port: 8080,
                guest_port: 80,
            }],
            ..Default::default()
        };
        let rules = port_list_core(&mut d, "web").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].bind, "127.0.0.1");
        assert_eq!(rules[0].host_port, 8080);
    }

    #[test]
    fn port_publish_unpublish_core_record_calls() {
        let mut d = FakeDaemon::default();
        port_publish_core(&mut d, "web", "8080:80", false).unwrap();
        assert!(d.calls.iter().any(|c| c == "publish:web:8080:80:false"));

        let bind: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        port_unpublish_core(&mut d, "web", bind, 8080).unwrap();
        assert!(d.calls.iter().any(|c| c == "unpublish:web:127.0.0.1:8080"));
    }

    #[test]
    fn volume_list_core_returns_mapped_views() {
        let mut d = FakeDaemon::default();
        let vols = volume_list_core(&mut d).unwrap();
        assert_eq!(vols.len(), 1);
        assert_eq!(vols[0].name, "cache");
        assert_eq!(vols[0].size_bytes, 1 << 30);
    }

    #[test]
    fn volume_remove_prune_core_record_calls() {
        let mut d = FakeDaemon::default();
        volume_remove_core(&mut d, "cache").unwrap();
        volume_prune_core(&mut d).unwrap();
        assert!(d.calls.iter().any(|c| c == "vrm:cache"));
        assert!(d.calls.iter().any(|c| c == "vprune"));
    }

    #[test]
    fn volume_attach_detach_core_record_calls() {
        let mut d = FakeDaemon::default();
        volume_attach_core(&mut d, "web", "cache:/data:1g").unwrap();
        volume_detach_core(&mut d, "web", "/data".into()).unwrap();
        assert!(d.calls.iter().any(|c| c == "vattach:web:/data"));
        assert!(d.calls.iter().any(|c| c == "vdetach:web:/data"));
    }

    /// A minimal image-only `izba.yml` — defaults from #122 (PR #129's
    /// era) fill in `resources`/`rootDisk`, so this is enough to be a valid
    /// manifest for `compute_diff`/`export`/`promote::run`.
    const MINIMAL_MANIFEST: &str =
        "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nspec:\n  image: ubuntu:24.04\n";

    /// Sets up sandbox `name` under `guard`'s redirected `$HOME`: a workspace
    /// dir containing a minimal `izba.yml`, plus a `config.json` under
    /// `<data>/sandboxes/<name>/` recording that workspace — the on-disk
    /// shape `workspace_for` reads. Returns `(Paths, workspace dir)`.
    fn setup_sandbox(guard: &HomeGuard, name: &str) -> (Paths, PathBuf) {
        setup_sandbox_with_manifest(guard, name, Some(MINIMAL_MANIFEST))
    }

    /// Same as `setup_sandbox`, but `manifest` controls what (if anything) is
    /// written to the workspace's `izba.yml`: `Some(content)` writes it
    /// verbatim (letting a test seed a corrupt document), `None` leaves the
    /// workspace without an `izba.yml` at all (the genuinely-missing case).
    fn setup_sandbox_with_manifest(
        guard: &HomeGuard,
        name: &str,
        manifest: Option<&str>,
    ) -> (Paths, PathBuf) {
        let paths = Paths::from_env_or_default(None);

        let ws = guard.home.join("ws").join(name);
        std::fs::create_dir_all(&ws).unwrap();
        if let Some(content) = manifest {
            std::fs::write(ws.join("izba.yml"), content).unwrap();
        }

        let sandbox_dir = paths.sandbox_dir(name);
        std::fs::create_dir_all(&sandbox_dir).unwrap();
        let cfg = SandboxConfig {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 1,
            mem_mb: 1024,
            workspace: ws.clone(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 1,
        };
        std::fs::write(
            sandbox_dir.join(CONFIG_FILE),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();

        (paths, ws)
    }

    #[test]
    fn manifest_diff_core_resolves_workspace_and_writes_review() {
        let guard = HomeGuard::new();
        let name = "web";
        let (paths, _ws) = setup_sandbox(&guard, name);

        manifest_diff_core(name).unwrap();

        let token = store::read_review(&paths.sandbox_dir(name)).unwrap();
        assert!(
            token.is_some(),
            "manifest_diff_core must write the review token"
        );
    }

    #[test]
    fn manifest_diff_core_missing_sandbox_err() {
        let _guard = HomeGuard::new();
        let err = manifest_diff_core("ghost").unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    /// A workspace with no `izba.yml` at all must fail with the exact stable
    /// sentinel `NO_MANIFEST_ERROR` — ManifestTab.tsx keys its "No izba.yml
    /// found" guidance panel on this string.
    #[test]
    fn manifest_diff_core_no_manifest_file_err() {
        let guard = HomeGuard::new();
        let name = "web";
        setup_sandbox_with_manifest(&guard, name, None);

        let err = manifest_diff_core(name).unwrap_err();
        assert_eq!(err, NO_MANIFEST_ERROR);
    }

    /// A CORRUPT (present but unparseable) `izba.yml` must NOT be classified
    /// as "missing" — its error must flow through as the raw parse failure,
    /// not the `NO_MANIFEST_ERROR` sentinel, so the frontend renders it
    /// honestly instead of telling the user the file doesn't exist.
    #[test]
    fn manifest_diff_core_parse_error_is_not_missing_manifest() {
        let guard = HomeGuard::new();
        let name = "web";
        setup_sandbox_with_manifest(&guard, name, Some("not: [valid, izba.yml"));

        let err = manifest_diff_core(name).unwrap_err();
        assert_ne!(err, NO_MANIFEST_ERROR, "got: {err}");
        assert!(err.contains("parsing izba.yml"), "got: {err}");
    }

    #[test]
    fn manifest_export_core_writes_workspace_yaml() {
        let guard = HomeGuard::new();
        let name = "web";
        let (_paths, ws) = setup_sandbox(&guard, name);

        let written = manifest_export_core(name).unwrap();
        assert_eq!(written, ws.join("izba.yml").display().to_string());
    }

    #[test]
    fn manifest_export_core_missing_sandbox_err() {
        let _guard = HomeGuard::new();
        let err = manifest_export_core("ghost").unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[test]
    fn manifest_promote_core_missing_sandbox_err() {
        let _guard = HomeGuard::new();
        let err = manifest_promote_core("ghost", false).unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    /// CLI parity (final-review Minor): promote validates the name BEFORE any
    /// path is derived from it — a traversal-shaped name must be rejected by
    /// `validate_name`, never reach `Paths::sandbox_dir`'s bare join.
    #[test]
    fn manifest_promote_core_rejects_traversal_name() {
        let _guard = HomeGuard::new();
        let err = manifest_promote_core("../escape", false).unwrap_err();
        assert!(err.contains("invalid sandbox name"), "got: {err}");
    }

    /// `app_paths()` must honor `IZBA_DATA_DIR` exactly like the CLI does —
    /// this is what lets the GUI dogfood headless sidecar isolate each
    /// journey's sandboxes instead of silently landing them under the real
    /// `$HOME`.
    #[test]
    fn app_paths_honors_izba_data_dir() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = std::env::temp_dir().join(format!("izba-app-paths-test-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let original = std::env::var_os("IZBA_DATA_DIR");
        std::env::set_var("IZBA_DATA_DIR", &dir);

        let paths = app_paths();
        assert_eq!(paths.root(), dir.as_path());

        match original {
            Some(v) => std::env::set_var("IZBA_DATA_DIR", v),
            None => std::env::remove_var("IZBA_DATA_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without `IZBA_DATA_DIR` set, `app_paths()` must fall back to the same
    /// per-OS default `Paths::from_env_or_default(None)` uses (here, the
    /// redirected `$HOME` from `HomeGuard`).
    #[test]
    fn app_paths_falls_back_to_default_without_izba_data_dir() {
        let _guard = HomeGuard::new(); // holds ENV_LOCK + redirects $HOME
        let original = std::env::var_os("IZBA_DATA_DIR");
        std::env::remove_var("IZBA_DATA_DIR");

        let expected = Paths::from_env_or_default(None);
        let actual = app_paths();
        assert_eq!(actual.root(), expected.root());

        if let Some(v) = original {
            std::env::set_var("IZBA_DATA_DIR", v);
        }
    }
}
