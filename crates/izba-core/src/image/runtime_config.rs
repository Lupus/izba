//! Host-side generation of the OCI runtime `config.json` for the guest's
//! single workload container (Pillar A2).
//!
//! Pure transforms over the captured image config ([`oci_client::config`]) plus
//! izba's per-sandbox overrides, producing an [`oci_spec::runtime::Spec`] that
//! crun consumes inside the guest. Kept free of I/O so the merge semantics —
//! the part docker users notice — are exhaustively unit-tested.

use anyhow::{bail, Result};
use oci_client::config::Config;
use oci_spec::runtime::{LinuxNamespaceType, ProcessBuilder, RootBuilder, Spec, UserBuilder};

/// The container rootfs inside the guest — the overlay init mounts at `/rootfs`
/// (erofs lower + ext4 upper). Workspace and user volumes are submounts under
/// it, so they ride along in the container's rootfs subtree.
pub const CONTAINER_ROOTFS: &str = "/rootfs";

/// Resolve the container's process argv exactly as `docker run` does.
///
/// Faithful port of moby's `daemon/commit.go::merge` followed by
/// `daemon/create.go::mergeAndVerifyConfig` (the `[""]` reset + "no command"
/// check). The non-obvious rules this captures:
///
/// - An explicit entrypoint override (`--entrypoint X`) **clears the image
///   CMD** — image `Cmd`/`Entrypoint` are inherited *only* when no entrypoint
///   override was given. So `--entrypoint X` alone runs just `[X]`.
/// - `--entrypoint ""` clears the entrypoint and likewise does **not** inherit
///   the image CMD; with no command args it is an error.
/// - Image `Cmd` is inherited only when neither an entrypoint override nor
///   command args were supplied.
///
/// Inputs mirror moby's `containertypes.Config` fields:
/// - `image_entrypoint`/`image_cmd`: the image's `Entrypoint`/`Cmd`.
/// - `user_entrypoint`: `None` = `--entrypoint` not passed; `Some(["X"])` =
///   `--entrypoint X`; `Some([""])` = `--entrypoint ""` (the CLI never yields an
///   empty vec).
/// - `user_cmd`: `None` = no positional command args; `Some(args)` = the
///   positional command override.
pub fn resolve_process_args(
    image_entrypoint: &[String],
    image_cmd: &[String],
    user_entrypoint: Option<&[String]>,
    user_cmd: Option<&[String]>,
) -> Result<Vec<String>> {
    // moby daemon/commit.go::merge — image Cmd/Entrypoint are inherited only
    // when no entrypoint override was supplied (the outer `len(Entrypoint)==0`
    // gate uses the user value, before the [""] reset below).
    let mut entrypoint: Vec<String> = user_entrypoint.map(<[_]>::to_vec).unwrap_or_default();
    let mut cmd: Vec<String> = user_cmd.map(<[_]>::to_vec).unwrap_or_default();
    if entrypoint.is_empty() {
        if cmd.is_empty() {
            cmd = image_cmd.to_vec();
        }
        // moby's `userConf.Entrypoint == nil`: only inherit when the override
        // was absent entirely (not an explicit empty value).
        if user_entrypoint.is_none() {
            entrypoint = image_entrypoint.to_vec();
        }
    }
    // moby create.go: reset the entrypoint if it is exactly [""].
    if entrypoint.len() == 1 && entrypoint[0].is_empty() {
        entrypoint.clear();
    }
    if entrypoint.is_empty() && cmd.is_empty() {
        bail!("no command specified: image has no Entrypoint/Cmd and none was provided");
    }
    entrypoint.extend(cmd);
    Ok(entrypoint)
}

/// Merge environment layers the way `docker run` resolves them: the image's
/// `Env` is the base, izba's trust-env defaults (CA bundle etc.) layer on top,
/// and `-e` user overrides win last. Later definitions of the same `KEY`
/// replace earlier ones (docker last-wins) while preserving first-appearance
/// order, yielding a deduped `KEY=VALUE` list for the OCI spec.
///
/// The "only when a CA bundle is present" gate is the caller's job — it passes
/// an empty `trust_env` when the gate is closed.
pub fn merge_env(image_env: &[String], trust_env: &[String], user_env: &[String]) -> Vec<String> {
    // Ordered last-wins-by-key: track first-appearance index per key so a later
    // layer updates the value in place rather than appending a duplicate.
    let mut order: Vec<String> = Vec::new();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for entry in image_env.iter().chain(trust_env).chain(user_env) {
        let key = entry.split_once('=').map_or(entry.as_str(), |(k, _)| k);
        match index.get(key) {
            Some(&i) => order[i] = entry.clone(),
            None => {
                index.insert(key.to_string(), order.len());
                order.push(entry.clone());
            }
        }
    }
    order
}

/// Resolve the container's working directory: an explicit override wins (e.g.
/// `/workspace` for interactive sandboxes), else the image's `WorkingDir`, else
/// the OCI default `/`.
pub fn resolve_cwd(image_working_dir: Option<&str>, cwd_override: Option<&str>) -> String {
    cwd_override
        .or(image_working_dir)
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_string()
}

/// Parse a numeric OCI/docker `User` spec into `(uid, gid)`.
///
/// `"1000:1000"` → `(1000, 1000)`; `"1000"` → `(1000, 0)` (docker's gid default
/// for a numeric uid without a passwd lookup); `""` → `(0, 0)`. Returns `None`
/// when either component is a non-numeric *name* — that requires resolving
/// against the container's `/etc/passwd`, which is deferred to the guest side
/// (Phase 4), not guessed host-side.
pub fn parse_numeric_user(user: &str) -> Option<(u32, u32)> {
    if user.is_empty() {
        return Some((0, 0));
    }
    match user.split_once(':') {
        Some((u, g)) => Some((u.parse().ok()?, g.parse().ok()?)),
        None => Some((user.parse().ok()?, 0)),
    }
}

/// Default cwd for an interactive sandbox — the virtiofs `workspace` mount,
/// also exec's default cwd today.
pub const INTERACTIVE_CWD: &str = "/workspace";

/// Render the 6 canonical CA-bundle env pairs as `"KEY=VALUE"` strings for
/// the OCI spec's process environment.
///
/// Keep in sync with `izba-init trust.rs::trust_env_pairs()`:
/// - `NODE_EXTRA_CA_CERTS`/`DENO_CERT` → `/etc/izba/ca.pem` (add to built-in roots)
/// - `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`/`GIT_SSL_CAINFO`
///   → `/etc/izba/ca-bundle.pem` (replace trust set, so must include system roots)
///
/// `izba-core` cannot depend on `izba-init`, so the pairs are duplicated here.
pub fn trust_env_strings() -> Vec<String> {
    const CA_PEM: &str = "/etc/izba/ca.pem";
    const CA_BUNDLE: &str = "/etc/izba/ca-bundle.pem";
    [
        ("NODE_EXTRA_CA_CERTS", CA_PEM),
        ("DENO_CERT", CA_PEM),
        ("SSL_CERT_FILE", CA_BUNDLE),
        ("REQUESTS_CA_BUNDLE", CA_BUNDLE),
        ("CURL_CA_BUNDLE", CA_BUNDLE),
        ("GIT_SSL_CAINFO", CA_BUNDLE),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={v}"))
    .collect()
}

/// Which process runs as the container's PID 1 (decision **D4**).
pub enum ContainerMode<'a> {
    /// Interactive dev sandbox (izba's default): a pause process holds the
    /// container's namespaces open as PID 1; the user's shell arrives later via
    /// `crun exec`. The image `Entrypoint`/`Cmd` are **not** run — this
    /// preserves today's boot-to-idle-then-`exec` UX (a bare image whose CMD is
    /// a shell would otherwise read EOF and exit, killing the sandbox).
    /// `pause_argv` is the argv of the vendored pause binary (bind-mounted into
    /// the container by the caller).
    Interactive { pause_argv: &'a [String] },
    /// Service member: the image entrypoint/cmd (merged with overrides) run as
    /// PID 1; its death is honest-unhealthy (no auto-restart).
    Service,
}

/// Inputs for [`generate_spec`]. Borrows so the generator stays a pure
/// transform with no ownership of izba's sandbox state.
pub struct SpecParams<'a> {
    /// PID-1 mode for the container (interactive pause vs image entrypoint).
    pub mode: ContainerMode<'a>,
    /// The image's runtime config (`oci_client`), if any was captured.
    pub image: Option<&'a Config>,
    /// `--entrypoint` override (Service mode): `None` = not passed; see
    /// [`resolve_process_args`]. Ignored in Interactive mode.
    pub entrypoint_override: Option<&'a [String]>,
    /// Positional command override (Service mode; `None` = none given).
    pub cmd_override: Option<&'a [String]>,
    /// `-e` user env overrides (last-wins).
    pub env_overrides: &'a [String],
    /// izba trust-env defaults; empty when the CA gate is closed (caller's job).
    pub trust_env: &'a [String],
    /// Working-dir override; else image WD (Service) / [`INTERACTIVE_CWD`].
    pub cwd_override: Option<&'a str>,
    /// Already-resolved process user `(uid, gid)` (see [`parse_numeric_user`]).
    pub user: (u32, u32),
    /// Guest hostname (the sandbox name).
    pub hostname: &'a str,
    /// Allocate a terminal for the container process (interactive shells).
    pub terminal: bool,
}

/// Generate the OCI runtime [`Spec`] for the guest's single workload container.
///
/// Starts from the standard rootful Linux spec ([`Spec::default`] — standard
/// mounts + namespaces) and applies izba's policy: process argv/env/cwd/user
/// from the docker-faithful merges, rootfs at [`CONTAINER_ROOTFS`], and — the
/// load-bearing decision **D1** — drops the network namespace so the container
/// shares izba-init's netns (egress/port-relay/ssh all live there).
pub fn generate_spec(params: &SpecParams) -> Result<Spec> {
    let cfg = params.image;
    let image_ep: Vec<String> = cfg.and_then(|c| c.entrypoint.clone()).unwrap_or_default();
    let image_cmd: Vec<String> = cfg.and_then(|c| c.cmd.clone()).unwrap_or_default();
    let image_env: Vec<String> = cfg.and_then(|c| c.env.clone()).unwrap_or_default();
    let image_wd: Option<String> = cfg.and_then(|c| c.working_dir.clone());

    let (args, cwd) = match params.mode {
        ContainerMode::Interactive { pause_argv } => {
            // Image entrypoint/cmd are NOT run; the pause holds the namespaces.
            (
                pause_argv.to_vec(),
                params.cwd_override.unwrap_or(INTERACTIVE_CWD).to_string(),
            )
        }
        ContainerMode::Service => (
            resolve_process_args(
                &image_ep,
                &image_cmd,
                params.entrypoint_override,
                params.cmd_override,
            )?,
            resolve_cwd(image_wd.as_deref(), params.cwd_override),
        ),
    };
    let env = merge_env(&image_env, params.trust_env, params.env_overrides);

    let user = UserBuilder::default()
        .uid(params.user.0)
        .gid(params.user.1)
        .build()?;
    let process = ProcessBuilder::default()
        .terminal(params.terminal)
        .args(args)
        .env(env)
        .cwd(cwd)
        .user(user)
        .build()?;
    let root = RootBuilder::default()
        .path(CONTAINER_ROOTFS)
        .readonly(false)
        .build()?;

    // Start from the standard rootful Linux spec (default mounts + namespaces),
    // then apply izba policy on top.
    let mut spec = Spec::default();
    spec.set_process(Some(process));
    spec.set_root(Some(root));
    spec.set_hostname(Some(params.hostname.to_string()));

    // D1: the container shares izba-init's network namespace — drop `network`
    // from the namespace set so crun does not unshare a fresh (routeless) one.
    if let Some(linux) = spec.linux_mut().as_mut() {
        if let Some(mut nss) = linux.namespaces().clone() {
            nss.retain(|n| n.typ() != LinuxNamespaceType::Network);
            linux.set_namespaces(Some(nss));
        }
    }
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // ---- Table from moby daemon/commit.go::merge + create.go ----

    #[test]
    fn no_override_concatenates_entrypoint_and_cmd() {
        let args = resolve_process_args(&v(&["/ep"]), &v(&["a", "b"]), None, None).unwrap();
        assert_eq!(args, v(&["/ep", "a", "b"]));
    }

    #[test]
    fn no_override_only_entrypoint() {
        let args = resolve_process_args(&v(&["/ep"]), &[], None, None).unwrap();
        assert_eq!(args, v(&["/ep"]));
    }

    #[test]
    fn no_override_only_cmd() {
        let args = resolve_process_args(&[], &v(&["/cmd"]), None, None).unwrap();
        assert_eq!(args, v(&["/cmd"]));
    }

    #[test]
    fn no_override_both_empty_is_error() {
        assert!(resolve_process_args(&[], &[], None, None).is_err());
    }

    #[test]
    fn cmd_override_keeps_image_entrypoint() {
        // docker run IMAGE x  (image has ENTRYPOINT /ep, CMD a) -> /ep x
        let args = resolve_process_args(&v(&["/ep"]), &v(&["a"]), None, Some(&v(&["x"]))).unwrap();
        assert_eq!(args, v(&["/ep", "x"]));
    }

    #[test]
    fn entrypoint_override_clears_image_cmd() {
        // docker run --entrypoint /new IMAGE  (image CMD a) -> /new  (NOT /new a)
        let args =
            resolve_process_args(&v(&["/ep"]), &v(&["a"]), Some(&v(&["/new"])), None).unwrap();
        assert_eq!(args, v(&["/new"]));
    }

    #[test]
    fn entrypoint_override_plus_cmd_override() {
        let args = resolve_process_args(
            &v(&["/ep"]),
            &v(&["a"]),
            Some(&v(&["/new"])),
            Some(&v(&["y"])),
        )
        .unwrap();
        assert_eq!(args, v(&["/new", "y"]));
    }

    #[test]
    fn empty_entrypoint_override_with_cmd_runs_cmd_only() {
        // docker run --entrypoint "" IMAGE z -> z  (entrypoint cleared)
        let args =
            resolve_process_args(&v(&["/ep"]), &v(&["a"]), Some(&v(&[""])), Some(&v(&["z"])))
                .unwrap();
        assert_eq!(args, v(&["z"]));
    }

    #[test]
    fn empty_entrypoint_override_without_cmd_is_error() {
        // docker run --entrypoint "" alpine  -> "no command specified"
        // (image CMD is NOT inherited because Entrypoint was non-empty at merge)
        assert!(resolve_process_args(&v(&["/ep"]), &v(&["a"]), Some(&v(&[""])), None).is_err());
    }

    // ---- env merge ----

    #[test]
    fn env_image_only_passes_through() {
        let env = merge_env(&v(&["PATH=/usr/bin", "LANG=C"]), &[], &[]);
        assert_eq!(env, v(&["PATH=/usr/bin", "LANG=C"]));
    }

    #[test]
    fn env_user_override_wins_last_and_keeps_position() {
        let env = merge_env(
            &v(&["PATH=/usr/bin", "LANG=C"]),
            &[],
            &v(&["PATH=/opt/bin"]),
        );
        assert_eq!(env, v(&["PATH=/opt/bin", "LANG=C"]));
    }

    #[test]
    fn env_new_keys_append_in_override_order() {
        let env = merge_env(&v(&["LANG=C"]), &[], &v(&["FOO=1", "BAR=2"]));
        assert_eq!(env, v(&["LANG=C", "FOO=1", "BAR=2"]));
    }

    #[test]
    fn env_trust_layers_between_image_and_user() {
        // trust-env adds CA path; a later -e of the same key still wins.
        let env = merge_env(
            &v(&["PATH=/usr/bin"]),
            &v(&["SSL_CERT_FILE=/etc/izba/ca.pem", "PATH=/trust/bin"]),
            &v(&["PATH=/opt/bin"]),
        );
        assert_eq!(env, v(&["PATH=/opt/bin", "SSL_CERT_FILE=/etc/izba/ca.pem"]));
    }

    #[test]
    fn env_entry_without_equals_treated_as_key() {
        // `-e VAR` (bare) overrides image VAR=... as the whole-string key.
        let env = merge_env(&v(&["VAR=old"]), &[], &v(&["VAR"]));
        assert_eq!(env, v(&["VAR"]));
    }

    // ---- cwd ----

    #[test]
    fn cwd_override_wins() {
        assert_eq!(resolve_cwd(Some("/img"), Some("/workspace")), "/workspace");
    }

    #[test]
    fn cwd_falls_back_to_image_working_dir() {
        assert_eq!(resolve_cwd(Some("/img"), None), "/img");
    }

    #[test]
    fn cwd_defaults_to_root() {
        assert_eq!(resolve_cwd(None, None), "/");
        assert_eq!(resolve_cwd(Some(""), None), "/");
    }

    // ---- numeric user ----

    #[test]
    fn user_uid_and_gid() {
        assert_eq!(parse_numeric_user("1000:1001"), Some((1000, 1001)));
    }

    #[test]
    fn user_uid_only_defaults_gid_zero() {
        assert_eq!(parse_numeric_user("1000"), Some((1000, 0)));
    }

    #[test]
    fn user_empty_is_root() {
        assert_eq!(parse_numeric_user(""), Some((0, 0)));
    }

    #[test]
    fn user_name_needs_passwd_resolution() {
        assert_eq!(parse_numeric_user("node"), None);
        assert_eq!(parse_numeric_user("node:1000"), None);
        assert_eq!(parse_numeric_user("1000:wheel"), None);
    }

    // ---- full spec assembly ----

    fn image_config(json: serde_json::Value) -> Config {
        serde_json::from_value(json).unwrap()
    }

    fn base_params<'a>(image: &'a Config) -> SpecParams<'a> {
        SpecParams {
            mode: ContainerMode::Service,
            image: Some(image),
            entrypoint_override: None,
            cmd_override: None,
            env_overrides: &[],
            trust_env: &[],
            cwd_override: None,
            user: (0, 0),
            hostname: "web",
            terminal: false,
        }
    }

    #[test]
    fn spec_process_reflects_merges_and_user() {
        let img = image_config(serde_json::json!({
            "Entrypoint": ["/bin/server"],
            "Cmd": ["--port", "80"],
            "Env": ["PATH=/usr/bin"],
            "WorkingDir": "/srv",
        }));
        let mut p = base_params(&img);
        p.env_overrides = &[];
        p.user = (1000, 1000);
        let spec = generate_spec(&p).unwrap();
        let proc = spec.process().as_ref().expect("process");
        assert_eq!(
            proc.args().clone().unwrap(),
            v(&["/bin/server", "--port", "80"])
        );
        assert_eq!(proc.env().clone().unwrap(), v(&["PATH=/usr/bin"]));
        assert_eq!(proc.cwd().to_string_lossy(), "/srv");
        assert_eq!(proc.user().uid(), 1000);
        assert_eq!(proc.user().gid(), 1000);
        assert!(!proc.terminal().unwrap_or(false));
    }

    #[test]
    fn spec_root_is_rootfs_writable() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&base_params(&img)).unwrap();
        let root = spec.root().as_ref().expect("root");
        assert_eq!(root.path().to_string_lossy(), CONTAINER_ROOTFS);
        assert_eq!(root.readonly(), Some(false));
    }

    #[test]
    fn spec_hostname_and_terminal_applied() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut p = base_params(&img);
        p.hostname = "myhost";
        p.terminal = true;
        let spec = generate_spec(&p).unwrap();
        assert_eq!(spec.hostname().as_deref(), Some("myhost"));
        assert!(spec.process().as_ref().unwrap().terminal().unwrap());
    }

    #[test]
    fn spec_omits_network_namespace_keeps_others() {
        // D1: container shares izba-init's netns -> no network ns in the spec.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&base_params(&img)).unwrap();
        let nss = spec.linux().as_ref().unwrap().namespaces().clone().unwrap();
        let types: Vec<LinuxNamespaceType> = nss.iter().map(|n| n.typ()).collect();
        assert!(
            !types.contains(&LinuxNamespaceType::Network),
            "network namespace must be omitted (D1)"
        );
        assert!(types.contains(&LinuxNamespaceType::Pid));
        assert!(types.contains(&LinuxNamespaceType::Mount));
        assert!(types.contains(&LinuxNamespaceType::Ipc));
        assert!(types.contains(&LinuxNamespaceType::Uts));
    }

    #[test]
    fn spec_interactive_cwd_override_and_cmd_override() {
        let img = image_config(serde_json::json!({
            "Entrypoint": ["/bin/server"],
            "Cmd": ["--port", "80"],
            "WorkingDir": "/srv",
        }));
        let mut p = base_params(&img);
        p.cwd_override = Some("/workspace");
        let shell = v(&["/bin/bash"]);
        p.entrypoint_override = Some(&shell);
        let spec = generate_spec(&p).unwrap();
        let proc = spec.process().as_ref().unwrap();
        // entrypoint override clears image cmd -> just the shell
        assert_eq!(proc.args().clone().unwrap(), v(&["/bin/bash"]));
        assert_eq!(proc.cwd().to_string_lossy(), "/workspace");
    }

    #[test]
    fn spec_interactive_runs_pause_ignores_image_entrypoint() {
        // D4: interactive mode runs the pause as PID 1, NOT the image cmd.
        let img = image_config(serde_json::json!({
            "Entrypoint": ["/bin/server"],
            "Cmd": ["--port", "80"],
            "WorkingDir": "/srv",
        }));
        let pause = v(&["/sbin/izba-pause"]);
        let mut p = base_params(&img);
        p.mode = ContainerMode::Interactive { pause_argv: &pause };
        let spec = generate_spec(&p).unwrap();
        let proc = spec.process().as_ref().unwrap();
        assert_eq!(proc.args().clone().unwrap(), v(&["/sbin/izba-pause"]));
        // interactive default cwd is /workspace, not the image WorkingDir
        assert_eq!(proc.cwd().to_string_lossy(), INTERACTIVE_CWD);
    }

    #[test]
    fn spec_interactive_honors_cwd_override() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let pause = v(&["/sbin/izba-pause"]);
        let mut p = base_params(&img);
        p.mode = ContainerMode::Interactive { pause_argv: &pause };
        p.cwd_override = Some("/data");
        let spec = generate_spec(&p).unwrap();
        assert_eq!(
            spec.process().as_ref().unwrap().cwd().to_string_lossy(),
            "/data"
        );
    }

    #[test]
    fn spec_serializes_to_json() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&base_params(&img)).unwrap();
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"ociVersion\""));
        assert!(json.contains("/rootfs"));
    }

    #[test]
    fn spec_trust_env_layered_when_present() {
        let img = image_config(serde_json::json!({
            "Cmd": ["/bin/sh"],
            "Env": ["PATH=/usr/bin"],
        }));
        let mut p = base_params(&img);
        let trust = v(&["SSL_CERT_FILE=/etc/izba/ca.pem"]);
        p.trust_env = &trust;
        let spec = generate_spec(&p).unwrap();
        let env = spec.process().as_ref().unwrap().env().clone().unwrap();
        assert!(env.contains(&"SSL_CERT_FILE=/etc/izba/ca.pem".to_string()));
        assert!(env.contains(&"PATH=/usr/bin".to_string()));
    }
}
