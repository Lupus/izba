//! Unified sandbox references (#123): every wired command accepts a sandbox
//! NAME or a WORKSPACE directory through one deterministic rule set —
//! path-looking arguments are workspaces, bare words are names first, and no
//! argument means "the workspace I'm standing in". See README
//! "Referring to sandboxes".

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use izba_core::paths::Paths;
use izba_core::state::{load_json, SandboxConfig, CONFIG_FILE};

/// A resolved reference: the sandbox name plus, when known, its workspace dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SandboxRef {
    pub name: String,
    /// `Some` for workspace-form references and for name-form references whose
    /// config.json records a workspace; `None` only if that record is missing.
    pub workspace: Option<PathBuf>,
    /// `true` only for the bare-word existing-sandbox arm of [`resolve`] — the
    /// positional itself pinned the sandbox name. `false` for every
    /// workspace-form reference (including the omitted-arg and path-syntax
    /// arms), where a `--name` override legitimately retargets which sandbox
    /// the workspace's managed truth belongs to.
    pub by_name: bool,
}

/// Path syntax is decided SYNTACTICALLY, never from disk state: `.`/`..`, any
/// separator, or a `./`/`../` prefix. Sandbox names can never contain a
/// separator (`[a-z0-9][a-z0-9_.-]*`), so this is unambiguous.
fn is_path_syntax(arg: &str) -> bool {
    arg == "." || arg == ".." || arg.contains('/') || arg.contains('\\')
}

fn sandbox_exists(paths: &Paths, name: &str) -> bool {
    paths.sandbox_dir(name).join(CONFIG_FILE).is_file()
}

/// The workspace dir recorded at create time (config.json `workspace`).
pub(crate) fn recorded_workspace(paths: &Paths, name: &str) -> anyhow::Result<Option<PathBuf>> {
    let cfg: Option<SandboxConfig> = load_json(&paths.sandbox_dir(name).join(CONFIG_FILE))?;
    Ok(cfg.map(|c| c.workspace))
}

/// The sandbox a workspace dir refers to: izba.yml `metadata.name` when the
/// manifest exists (malformed YAML propagates — never silently the wrong
/// sandbox), else the sanitized dir basename.
pub(crate) fn workspace_sandbox_name(dir: &Path) -> anyhow::Result<String> {
    if dir.join("izba.yml").is_file() {
        let m = super::load_manifest_yaml(dir)?;
        if let Some(n) = m.metadata.name {
            izba_core::sandbox::validate_name(&n)
                .with_context(|| format!("izba.yml metadata.name {n:?}"))?;
            return Ok(n);
        }
    }
    super::workspace_default_name(dir)
}

fn workspace_ref(dir: &Path) -> anyhow::Result<SandboxRef> {
    let name = workspace_sandbox_name(dir)?;
    Ok(SandboxRef {
        name,
        workspace: Some(dir.to_path_buf()),
        by_name: false,
    })
}

/// The safety rail for a bare word that names an EXISTING sandbox: if
/// `./<arg>/izba.yml` resolves to a DIFFERENT sandbox, the argument has two
/// live meanings. Refuse rather than silently pick one and discard the other's
/// `enforce:`/`protocol:` posture.
///
/// SHARED by [`resolve`] and [`resolve_for_create`] deliberately. It first
/// shipped inside `resolve` alone, and `resolve_for_create` was written
/// without it — so `izba run myapp` attached to sandbox `myapp` while
/// `izba status myapp` refused the same argument, and `./myapp/izba.yml` was
/// neither applied nor mentioned. Duplicating the rail is precisely how the
/// two drift; a test pins that they refuse identically.
fn reject_ambiguous_existing(arg: &str) -> anyhow::Result<()> {
    let as_dir = Path::new(arg);
    if !as_dir.join("izba.yml").is_file() {
        return Ok(());
    }
    let dir_name = workspace_sandbox_name(as_dir)?;
    if dir_name != arg {
        bail!(
            "'{arg}' is both a sandbox name and a directory whose izba.yml \
             resolves to sandbox '{dir_name}' — pass './{arg}' for the \
             directory, or the exact sandbox name"
        );
    }
    Ok(())
}

/// Resolve an optional positional argument into a [`SandboxRef`]:
///
/// 1. omitted     → the current directory's workspace;
/// 2. path syntax → that workspace directory (deterministic, never guesses);
/// 3. bare word   → an existing sandbox of that name; else, if `./word/izba.yml`
///    exists, that workspace (with a printed note); else a hint error naming
///    both interpretations;
/// 4. safety rail → a bare word matching an existing sandbox AND a
///    `./word/izba.yml` that resolves to a DIFFERENT sandbox is a hard error
///    (no silent wrong-target `rm`).
pub(crate) fn resolve(paths: &Paths, arg: Option<&str>) -> anyhow::Result<SandboxRef> {
    let arg = match arg {
        None => return workspace_ref(Path::new(".")),
        Some(a) => a,
    };
    if is_path_syntax(arg) {
        return workspace_ref(Path::new(arg));
    }
    let as_dir = Path::new(arg);
    let dir_has_manifest = as_dir.join("izba.yml").is_file();
    if sandbox_exists(paths, arg) {
        reject_ambiguous_existing(arg)?;
        return Ok(SandboxRef {
            name: arg.to_string(),
            workspace: recorded_workspace(paths, arg)?,
            by_name: true,
        });
    }
    if dir_has_manifest {
        eprintln!("note: no sandbox named '{arg}'; using workspace directory ./{arg}");
        return workspace_ref(as_dir);
    }
    bail!(
        "no sandbox named '{arg}' and no ./{arg}/izba.yml — pass an existing \
         sandbox name or a workspace directory (e.g. './{arg}'); to create a \
         sandbox, use `izba create` (or `izba run` to create + start + exec \
         in one step)"
    )
}

/// `--name` retargets the SANDBOX while the positional supplies the
/// WORKSPACE — that only makes sense for a workspace-form positional. A
/// bare-name positional already pins the sandbox, so a DIFFERENT --name is
/// contradictory: refuse instead of comparing one sandbox's workspace
/// against another's managed truth.
pub(crate) fn check_name_override(
    r: &SandboxRef,
    name_override: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(n) = name_override {
        if r.by_name && n != r.name {
            anyhow::bail!(
                "positional '{}' is a sandbox name and --name {n} names a different \
                 sandbox — pass a workspace directory with --name, or drop --name",
                r.name
            );
        }
    }
    Ok(())
}

/// Omitted-positional guard for DESTRUCTIVE commands: the resolved sandbox's
/// recorded workspace (config.json) must actually be the current directory —
/// a mere basename/metadata.name coincidence must not delete an unrelated
/// sandbox. Lenient when the sandbox has no config (the command's own
/// not-found error is better) — this guards misdirection, not existence.
pub(crate) fn ensure_cwd_is_workspace(paths: &Paths, r: &SandboxRef) -> anyhow::Result<()> {
    let Some(recorded) = recorded_workspace(paths, &r.name)? else {
        return Ok(());
    };
    let cwd = std::env::current_dir().context("reading current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);
    let rec = recorded.canonicalize().unwrap_or(recorded);
    if rec != cwd {
        anyhow::bail!(
            "current directory is not the recorded workspace of sandbox '{}' \
             (recorded: {}) — pass the sandbox name or its workspace directory \
             explicitly",
            r.name,
            rec.display()
        );
    }
    Ok(())
}

/// The sandbox the CURRENT directory's `izba.yml` declares, if any.
///
/// Deliberately total: a missing, unreadable or malformed manifest — or one
/// carrying no `metadata.name` — yields `None`. Resolution must never proceed
/// on a manifest it could not read; [`cwd_manifest_ignored_warning`] reports
/// that case separately rather than swallowing it.
fn cwd_manifest_name() -> Option<String> {
    if !Path::new("izba.yml").is_file() {
        return None;
    }
    let m = super::load_manifest_yaml(Path::new(".")).ok()?;
    let n = m.metadata.name?;
    izba_core::sandbox::validate_name(&n).ok()?;
    Some(n)
}

/// The create-capable counterpart of [`resolve`], for `run`/`create` — the two
/// verbs whose positional may legitimately name a sandbox that does not exist
/// yet, and the only two that may materialise a workspace directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CreateTarget {
    /// A bare word naming an EXISTING sandbox: address it directly.
    Existing(String),
    /// A workspace directory. It already exists for every arm EXCEPT the
    /// path-syntax one — which is precisely why path syntax is the only
    /// spelling allowed to create a directory (#242).
    Workspace(PathBuf),
}

/// Resolve `run`/`create`'s positional into a [`CreateTarget`]:
///
/// 1. path syntax → that workspace directory (the ONE form that may be created
///    if missing);
/// 2. bare word naming an existing sandbox → that sandbox, subject to
///    [`reject_ambiguous_existing`];
/// 3. bare word with a `./word/izba.yml` → that workspace (with a printed
///    note), mirroring [`resolve`];
/// 4. bare word equal to the CWD manifest's `metadata.name` → the current
///    directory: the project sandbox that `--name <word>` and `.` already
///    reach (#242);
/// 5. 3 and 4 both match → a hard error naming both interpretations;
/// 6. otherwise → a hint error, having created NO directory.
///
/// Arm 4 cannot be steered by the agent-writable `izba.yml`: it is taken only
/// when the manifest's name EQUALS the name the user typed, so a manifest can
/// confirm the target but never redirect it to a different sandbox.
///
/// Arm 6 is the #242 fix proper: before it, a bare word matching nothing fell
/// through to `create_dir_all`, so a typo silently became a new workspace and
/// a manifest's `enforce:`/`protocol:` posture was discarded without a word.
pub(crate) fn resolve_for_create(paths: &Paths, arg: &str) -> anyhow::Result<CreateTarget> {
    if is_path_syntax(arg) {
        return Ok(CreateTarget::Workspace(PathBuf::from(arg)));
    }
    if sandbox_exists(paths, arg) {
        reject_ambiguous_existing(arg)?;
        return Ok(CreateTarget::Existing(arg.to_string()));
    }
    let as_dir = Path::new(arg);
    let subdir_manifest = as_dir.join("izba.yml").is_file();
    let cwd_names_arg = cwd_manifest_name().is_some_and(|n| n == arg);
    match (subdir_manifest, cwd_names_arg) {
        (true, true) => bail!(
            "'{arg}' is ambiguous: ./izba.yml declares sandbox '{arg}' for the current \
             directory, and ./{arg}/izba.yml is a workspace of its own — pass '.' for \
             this directory, or './{arg}' for the subdirectory"
        ),
        (true, false) => {
            eprintln!("note: no sandbox named '{arg}'; using workspace directory ./{arg}");
            Ok(CreateTarget::Workspace(as_dir.to_path_buf()))
        }
        (false, true) => Ok(CreateTarget::Workspace(PathBuf::from("."))),
        (false, false) => bail!(
            "no sandbox named '{arg}', no ./{arg}/izba.yml, and ./izba.yml does not \
             declare '{arg}' — pass an existing sandbox name, a workspace directory \
             (e.g. './{arg}'), or `--name {arg} .` to create '{arg}' for the current \
             directory"
        ),
    }
}

/// Does `dir` denote the current directory? Compared canonically, so the
/// absolute workspace recorded in a sandbox's `config.json` and the literal
/// `"."` a workspace-form positional yields are the same answer.
fn is_cwd(dir: &Path) -> bool {
    let Ok(cwd) = std::env::current_dir() else {
        return false;
    };
    let cwd = cwd.canonicalize().unwrap_or(cwd);
    let d = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    d == cwd
}

/// The "a discarded manifest is never silent" warning (#242): `Some` whenever
/// the current directory holds an `izba.yml` that is NOT the manifest being
/// applied to the resolved sandbox.
///
/// Keyed on `applied_workspace`, NOT on the sandbox name: `izba create --name
/// other .` genuinely applies the cwd manifest under a different name, and a
/// false alarm there would train users to ignore the one message that reports
/// a dropped `enforce:`. Callers pass the workspace whose manifest governs the
/// command — for a sandbox addressed by name, the workspace its `config.json`
/// records (`None` when it records none, which cannot be the cwd manifest).
///
/// Pure (returns the text rather than printing it) so the decision is
/// unit-testable; the caller prints it. An UNREADABLE cwd manifest still
/// warns — "I could not parse it" is exactly the case where a dropped
/// `enforce:` would otherwise go unmentioned.
pub(crate) fn cwd_manifest_ignored_warning(
    applied_workspace: Option<&Path>,
    resolved_name: &str,
) -> Option<String> {
    if !Path::new("izba.yml").is_file() {
        return None;
    }
    if applied_workspace.is_some_and(is_cwd) {
        return None;
    }
    match workspace_sandbox_name(Path::new(".")) {
        Ok(n) => Some(format!(
            "warning: ./izba.yml declares sandbox '{n}', but this command targets \
             '{resolved_name}' — that manifest was NOT applied, so its `image`, its \
             `egress` `enforce:`/`protocol:` declarations and every other field are \
             ignored here"
        )),
        Err(e) => Some(format!(
            "warning: ./izba.yml could not be read ({e:#}), so it was NOT applied to \
             sandbox '{resolved_name}' — its `enforce:`/`protocol:` declarations, if \
             any, are not in effect"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = concat!(
        "apiVersion: izba.dev/v1alpha1\n",
        "kind: Sandbox\n",
        "metadata: { name: fromyaml }\n",
        "spec:\n",
        "  image: ubuntu:24.04\n",
    );

    /// A tempdir-rooted Paths + one registered sandbox with a recorded workspace.
    fn fixture(name: &str) -> (tempfile::TempDir, Paths, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let ws = tmp.path().join("recorded-ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(paths.sandbox_dir(name)).unwrap();
        let cfg = format!(
            r#"{{"image_digest":"d","image_ref":"ubuntu:24.04","cpus":2,
                "mem_mb":4096,"workspace":{}}}"#,
            serde_json::to_string(&ws).unwrap()
        );
        std::fs::write(paths.sandbox_dir(name).join(CONFIG_FILE), cfg).unwrap();
        (tmp, paths, ws)
    }

    #[test]
    fn bare_word_resolves_existing_sandbox_with_recorded_workspace() {
        let (_tmp, paths, ws) = fixture("myapp");
        let r = resolve(&paths, Some("myapp")).unwrap();
        assert_eq!(r.name, "myapp");
        assert_eq!(r.workspace.as_deref(), Some(ws.as_path()));
        assert!(r.by_name, "bare-word existing-sandbox arm must set by_name");
    }

    #[test]
    fn path_syntax_is_always_a_workspace() {
        let (_tmp, paths, _ws) = fixture("myapp");
        // Even though a sandbox "myapp" exists, "./myapp" is path syntax.
        let tmp2 = tempfile::tempdir().unwrap();
        let dir = tmp2.path().join("myapp");
        std::fs::create_dir_all(&dir).unwrap();
        let dir_s = dir.to_string_lossy().into_owned();
        let r = resolve(&paths, Some(&dir_s)).unwrap();
        assert_eq!(r.name, "myapp", "basename-derived name");
        assert_eq!(r.workspace.as_deref(), Some(dir.as_path()));
        assert!(!r.by_name, "path-syntax positional is workspace-form");
    }

    #[test]
    fn omitted_arg_means_current_workspace() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let (_tmp, paths, _ws) = fixture("other");
        let r = resolve(&paths, None).unwrap();
        // cwd's basename, sanitized — matches workspace_default_name(".").
        let expected = super::super::workspace_default_name(Path::new(".")).unwrap();
        assert_eq!(r.name, expected);
        assert_eq!(r.workspace.as_deref(), Some(Path::new(".")));
        assert!(!r.by_name, "omitted-arg positional is workspace-form");
    }

    #[test]
    fn bare_word_falls_back_to_local_dir_with_manifest() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        // Run from tmp as cwd is not possible in a unit test; use a relative
        // path via current_dir juggling — instead exercise the fallback through
        // an absolute-path-free bare word by chdir-ing.
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("izba.yml"), MANIFEST).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let r = resolve(&paths, Some("proj"));
        std::env::set_current_dir(prev).unwrap();
        let r = r.unwrap();
        assert_eq!(
            r.name, "fromyaml",
            "manifest metadata.name wins for the dir"
        );
        assert_eq!(r.workspace.as_deref(), Some(Path::new("proj")));
    }

    #[test]
    fn bare_word_matching_nothing_is_a_hint_error() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let err = resolve(&paths, Some("ghost")).unwrap_err().to_string();
        assert!(err.contains("no sandbox named 'ghost'"), "{err}");
        assert!(
            err.contains("./ghost"),
            "hint must show the dir form: {err}"
        );
        assert!(
            err.contains("izba create"),
            "must hint the create verbs: {err}"
        );
    }

    /// Pins every arm of the syntactic split (kills the `||`→`&&` mutants):
    /// `.`/`..`/separators are path syntax; a bare word never is.
    #[test]
    fn path_syntax_arms_are_each_sufficient() {
        assert!(is_path_syntax("."));
        assert!(is_path_syntax(".."));
        assert!(is_path_syntax("a/b"));
        assert!(is_path_syntax("./x"));
        assert!(is_path_syntax("a\\b"));
        assert!(!is_path_syntax("myapp"));
        assert!(!is_path_syntax("my.app"));
    }

    #[test]
    fn ambiguous_bare_word_is_a_hard_error() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let (tmp, paths, _ws) = fixture("proj");
        // ./proj/izba.yml resolves to a DIFFERENT sandbox name ("fromyaml").
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("izba.yml"), MANIFEST).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let res = resolve(&paths, Some("proj"));
        std::env::set_current_dir(prev).unwrap();
        let err = res.unwrap_err().to_string();
        assert!(err.contains("both a sandbox name and a directory"), "{err}");
        assert!(err.contains("'fromyaml'"), "{err}");
    }

    #[test]
    fn agreeing_bare_word_resolves_as_the_sandbox() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        // Sandbox "proj" exists AND ./proj/izba.yml names the SAME sandbox — fine.
        let (tmp, paths, ws) = fixture("proj");
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("izba.yml"), MANIFEST.replace("fromyaml", "proj")).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let r = resolve(&paths, Some("proj"));
        std::env::set_current_dir(prev).unwrap();
        let r = r.unwrap();
        assert_eq!(r.name, "proj");
        assert_eq!(r.workspace.as_deref(), Some(ws.as_path()));
    }

    // -- check_name_override --------------------------------------------

    #[test]
    fn check_name_override_rejects_different_name_when_by_name() {
        let r = SandboxRef {
            name: "myapp".to_string(),
            workspace: None,
            by_name: true,
        };
        let err = check_name_override(&r, Some("other"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("myapp"), "{err}");
        assert!(err.contains("other"), "{err}");
    }

    #[test]
    fn check_name_override_allows_same_name_when_by_name() {
        let r = SandboxRef {
            name: "myapp".to_string(),
            workspace: None,
            by_name: true,
        };
        assert!(check_name_override(&r, Some("myapp")).is_ok());
    }

    #[test]
    fn check_name_override_allows_different_name_for_workspace_form() {
        let r = SandboxRef {
            name: "myapp".to_string(),
            workspace: Some(PathBuf::from("/some/dir")),
            by_name: false,
        };
        assert!(check_name_override(&r, Some("other")).is_ok());
    }

    #[test]
    fn check_name_override_allows_none() {
        let r = SandboxRef {
            name: "myapp".to_string(),
            workspace: None,
            by_name: true,
        };
        assert!(check_name_override(&r, None).is_ok());
    }

    // -- ensure_cwd_is_workspace ------------------------------------------

    #[test]
    fn ensure_cwd_is_workspace_rejects_mismatch() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let (_tmp, paths, _ws) = fixture("myapp");
        let elsewhere = tempfile::tempdir().unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(elsewhere.path()).unwrap();
        let r = SandboxRef {
            name: "myapp".to_string(),
            workspace: None,
            by_name: true,
        };
        let res = ensure_cwd_is_workspace(&paths, &r);
        std::env::set_current_dir(prev).unwrap();
        let err = res.unwrap_err().to_string();
        assert!(err.contains("myapp"), "{err}");
    }

    #[test]
    fn ensure_cwd_is_workspace_allows_match() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let (_tmp, paths, ws) = fixture("myapp");
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&ws).unwrap();
        let r = SandboxRef {
            name: "myapp".to_string(),
            workspace: None,
            by_name: true,
        };
        let res = ensure_cwd_is_workspace(&paths, &r);
        std::env::set_current_dir(prev).unwrap();
        assert!(res.is_ok(), "{res:?}");
    }

    #[test]
    fn ensure_cwd_is_workspace_allows_missing_config() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let r = SandboxRef {
            name: "ghost".to_string(),
            workspace: None,
            by_name: true,
        };
        assert!(ensure_cwd_is_workspace(&paths, &r).is_ok());
    }
    // -- resolve_for_create (#242) ---------------------------------------

    /// Restores the process cwd on drop — including while unwinding.
    struct CwdGuard(PathBuf);
    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    /// Run `f` with the process cwd temporarily set to `dir`, restoring it
    /// afterwards. Callers must hold `CWD_LOCK`.
    ///
    /// The restore is a Drop guard, not a trailing statement, because a
    /// failing assertion inside `f` PANICS: with a trailing restore the cwd
    /// stays inside a tempdir that is then deleted, and every later
    /// cwd-dependent test fails for a reason that has nothing to do with it.
    /// One real assertion failure would otherwise read as twenty.
    fn with_cwd<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
        let prev = std::env::current_dir().unwrap();
        let _guard = CwdGuard(prev);
        std::env::set_current_dir(dir).unwrap();
        f()
    }

    /// Path syntax always means the directory — even when a sandbox of the
    /// same basename exists (mirrors `path_syntax_is_always_a_workspace`).
    #[test]
    fn create_path_syntax_is_always_a_workspace() {
        let (_tmp, paths, _ws) = fixture("myapp");
        let tmp2 = tempfile::tempdir().unwrap();
        let dir = tmp2.path().join("myapp");
        std::fs::create_dir_all(&dir).unwrap();
        let dir_s = dir.to_string_lossy().into_owned();
        assert_eq!(
            resolve_for_create(&paths, &dir_s).unwrap(),
            CreateTarget::Workspace(dir)
        );
    }

    /// Path syntax is the ONE form allowed to name a not-yet-existing
    /// directory: `izba run ./newproj` must still scaffold it.
    #[test]
    fn create_path_syntax_may_name_a_missing_directory() {
        let (_tmp, paths, _ws) = fixture("myapp");
        let tmp2 = tempfile::tempdir().unwrap();
        let missing = tmp2.path().join("newproj");
        let s = missing.to_string_lossy().into_owned();
        assert_eq!(
            resolve_for_create(&paths, &s).unwrap(),
            CreateTarget::Workspace(missing)
        );
    }

    #[test]
    fn create_bare_word_resolves_an_existing_sandbox() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let (tmp, paths, _ws) = fixture("myapp");
        let r = with_cwd(tmp.path(), || resolve_for_create(&paths, "myapp"));
        assert_eq!(r.unwrap(), CreateTarget::Existing("myapp".to_string()));
    }

    #[test]
    fn create_bare_word_uses_a_subdirectory_holding_a_manifest() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("izba.yml"), MANIFEST).unwrap();
        let r = with_cwd(tmp.path(), || resolve_for_create(&paths, "proj"));
        assert_eq!(r.unwrap(), CreateTarget::Workspace(PathBuf::from("proj")));
    }

    /// #242, the headline fix: a bare name matching the CWD manifest's
    /// `metadata.name` IS the project sandbox — the same target `--name` and
    /// `.` already reach — never a fresh `./<name>/` workspace whose empty
    /// dir silently discards the manifest's `enforce:`/`protocol:` posture.
    #[test]
    fn create_bare_word_matching_cwd_manifest_name_is_the_project_sandbox() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        std::fs::write(
            tmp.path().join("izba.yml"),
            MANIFEST.replace("fromyaml", "my-sandbox"),
        )
        .unwrap();
        let r = with_cwd(tmp.path(), || resolve_for_create(&paths, "my-sandbox"));
        assert_eq!(r.unwrap(), CreateTarget::Workspace(PathBuf::from(".")));
        assert!(
            !tmp.path().join("my-sandbox").exists(),
            "must not materialise a stray ./my-sandbox/ directory"
        );
    }

    /// The typo case: a bare word matching nothing errors, and — the
    /// regression this issue exists for — writes NO directory.
    #[test]
    fn create_bare_word_matching_nothing_errors_and_creates_no_directory() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let res = with_cwd(tmp.path(), || resolve_for_create(&paths, "ghost"));
        let err = res.unwrap_err().to_string();
        assert!(err.contains("no sandbox named 'ghost'"), "{err}");
        assert!(
            err.contains("./ghost"),
            "hint must show the dir form: {err}"
        );
        assert!(
            !tmp.path().join("ghost").exists(),
            "a bare-word miss must not create ./ghost/"
        );
    }

    /// A cwd manifest naming the argument AND a `./<arg>/izba.yml` naming a
    /// different sandbox are two live interpretations — refuse rather than
    /// silently pick one.
    #[test]
    fn create_bare_word_matching_both_cwd_manifest_and_subdir_is_a_hard_error() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        std::fs::write(
            tmp.path().join("izba.yml"),
            MANIFEST.replace("fromyaml", "proj"),
        )
        .unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("izba.yml"), MANIFEST).unwrap();
        let res = with_cwd(tmp.path(), || resolve_for_create(&paths, "proj"));
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("./izba.yml"),
            "must name the cwd manifest: {err}"
        );
        assert!(
            err.contains("./proj"),
            "must name the subdirectory form: {err}"
        );
    }

    /// An EXISTING sandbox wins over the cwd-manifest arm — and the two agree
    /// anyway, since the cwd manifest resolves to that same sandbox.
    #[test]
    fn create_existing_sandbox_wins_over_cwd_manifest() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let (tmp, paths, _ws) = fixture("my-sandbox");
        std::fs::write(
            tmp.path().join("izba.yml"),
            MANIFEST.replace("fromyaml", "my-sandbox"),
        )
        .unwrap();
        let r = with_cwd(tmp.path(), || resolve_for_create(&paths, "my-sandbox"));
        assert_eq!(r.unwrap(), CreateTarget::Existing("my-sandbox".to_string()));
    }

    /// The safety rail `resolve` already applies must apply here too, or the
    /// two resolvers disagree on the same argument: `run myapp` would attach to
    /// sandbox `myapp` while silently discarding `./myapp/izba.yml`'s
    /// `enforce:`/`protocol:` posture — the exact class #242 exists to close.
    #[test]
    fn create_bare_word_that_is_both_a_sandbox_and_a_divergent_dir_is_a_hard_error() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let (tmp, paths, _ws) = fixture("proj");
        // ./proj/izba.yml resolves to a DIFFERENT sandbox ("fromyaml").
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("izba.yml"), MANIFEST).unwrap();
        let res = with_cwd(tmp.path(), || resolve_for_create(&paths, "proj"));
        let err = res.unwrap_err().to_string();
        assert!(err.contains("both a sandbox name and a directory"), "{err}");
        assert!(err.contains("'fromyaml'"), "{err}");
    }

    /// ...and when the two AGREE there is nothing to disambiguate: the
    /// existing sandbox is the answer, exactly as `resolve` decides it.
    #[test]
    fn create_bare_word_that_is_both_a_sandbox_and_an_agreeing_dir_resolves_as_the_sandbox() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let (tmp, paths, _ws) = fixture("proj");
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("izba.yml"), MANIFEST.replace("fromyaml", "proj")).unwrap();
        let r = with_cwd(tmp.path(), || resolve_for_create(&paths, "proj"));
        assert_eq!(r.unwrap(), CreateTarget::Existing("proj".to_string()));
    }

    /// The rail is SHARED, not duplicated: both resolvers must reject the same
    /// argument identically, so the drift Greptile caught cannot reappear.
    #[test]
    fn both_resolvers_reject_an_ambiguous_bare_word_identically() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let (tmp, paths, _ws) = fixture("proj");
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("izba.yml"), MANIFEST).unwrap();
        let (a, b) = with_cwd(tmp.path(), || {
            (
                resolve(&paths, Some("proj")).err().map(|e| e.to_string()),
                resolve_for_create(&paths, "proj")
                    .err()
                    .map(|e| e.to_string()),
            )
        });
        assert!(a.is_some(), "resolve must refuse an ambiguous bare word");
        assert_eq!(a, b, "the two resolvers must give the same refusal");
    }

    // -- cwd_manifest_ignored_warning (#242) -----------------------------

    /// The manifest governing a DIFFERENT workspace than the cwd is a
    /// discarded declaration — say so, naming both sides.
    #[test]
    fn cwd_manifest_warning_fires_when_a_different_workspace_is_applied() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("izba.yml"), MANIFEST).unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let msg = with_cwd(tmp.path(), || {
            cwd_manifest_ignored_warning(Some(elsewhere.path()), "other")
        });
        let msg = msg.expect("a cwd izba.yml that is not the applied manifest must warn");
        assert!(msg.contains("izba.yml"), "must name the file: {msg}");
        assert!(
            msg.contains("fromyaml"),
            "must name the sandbox it declares: {msg}"
        );
        assert!(
            msg.contains("other"),
            "must name the sandbox actually targeted: {msg}"
        );
    }

    #[test]
    fn cwd_manifest_warning_is_silent_when_the_cwd_manifest_is_the_one_applied() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("izba.yml"), MANIFEST).unwrap();
        let msg = with_cwd(tmp.path(), || {
            cwd_manifest_ignored_warning(Some(Path::new(".")), "fromyaml")
        });
        assert_eq!(msg, None, "the applied manifest must not warn about itself");
    }

    /// `izba create --name override .` DOES apply the cwd manifest — only the
    /// sandbox name was overridden. Keying the warning on the name rather than
    /// the applied workspace would make this a false alarm, training users to
    /// ignore the one message that reports a dropped `enforce:`.
    #[test]
    fn cwd_manifest_warning_is_silent_when_only_the_name_was_overridden() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("izba.yml"), MANIFEST).unwrap();
        let msg = with_cwd(tmp.path(), || {
            cwd_manifest_ignored_warning(Some(Path::new(".")), "override")
        });
        assert_eq!(msg, None);
    }

    /// The `Existing` arm passes the sandbox's RECORDED workspace: when that
    /// is the cwd, `izba run <name>` and `izba run .` are the same command, so
    /// there is nothing to warn about.
    #[test]
    fn cwd_manifest_warning_is_silent_when_the_target_records_the_cwd() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("izba.yml"), MANIFEST).unwrap();
        let abs = tmp.path().to_path_buf();
        let msg = with_cwd(tmp.path(), || {
            cwd_manifest_ignored_warning(Some(&abs), "fromyaml")
        });
        assert_eq!(msg, None, "an absolute cwd path must compare equal to '.'");
    }

    /// A sandbox addressed by name with no recorded workspace at all still
    /// leaves the cwd manifest unapplied.
    #[test]
    fn cwd_manifest_warning_fires_when_no_workspace_is_applied() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("izba.yml"), MANIFEST).unwrap();
        let msg = with_cwd(tmp.path(), || cwd_manifest_ignored_warning(None, "other"));
        assert!(
            msg.is_some(),
            "no applied workspace means nothing applied it"
        );
    }

    #[test]
    fn cwd_manifest_warning_is_silent_without_a_manifest() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let msg = with_cwd(tmp.path(), || {
            cwd_manifest_ignored_warning(Some(Path::new(".")), "anything")
        });
        assert_eq!(msg, None);
    }

    /// An UNPARSEABLE cwd manifest is still a discarded declaration — the
    /// whole point of the warning is that a dropped `enforce:` is never
    /// silent, so "could not read it" must not degrade into saying nothing.
    #[test]
    fn cwd_manifest_warning_fires_when_the_manifest_cannot_be_parsed() {
        let _g = super::super::CWD_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("izba.yml"), "{{{ not yaml").unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let msg = with_cwd(tmp.path(), || {
            cwd_manifest_ignored_warning(Some(elsewhere.path()), "target")
        });
        let msg = msg.expect("an unparseable cwd izba.yml must still warn");
        assert!(msg.contains("izba.yml"), "{msg}");
        assert!(msg.contains("target"), "{msg}");
    }
}
