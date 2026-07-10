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
fn recorded_workspace(paths: &Paths, name: &str) -> anyhow::Result<Option<PathBuf>> {
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
    })
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
        if dir_has_manifest {
            let dir_name = workspace_sandbox_name(as_dir)?;
            if dir_name != arg {
                bail!(
                    "'{arg}' is both a sandbox name and a directory whose izba.yml \
                     resolves to sandbox '{dir_name}' — pass './{arg}' for the \
                     directory, or the exact sandbox name"
                );
            }
        }
        return Ok(SandboxRef {
            name: arg.to_string(),
            workspace: recorded_workspace(paths, arg)?,
        });
    }
    if dir_has_manifest {
        eprintln!("note: no sandbox named '{arg}'; using workspace directory ./{arg}");
        return workspace_ref(as_dir);
    }
    bail!(
        "no sandbox named '{arg}' and no ./{arg}/izba.yml — pass an existing \
         sandbox name or a workspace directory (e.g. './{arg}')"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static CWD_LOCK: Mutex<()> = Mutex::new(());

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
    }

    #[test]
    fn omitted_arg_means_current_workspace() {
        let _g = CWD_LOCK.lock().unwrap();
        let (_tmp, paths, _ws) = fixture("other");
        let r = resolve(&paths, None).unwrap();
        // cwd's basename, sanitized — matches workspace_default_name(".").
        let expected = super::super::workspace_default_name(Path::new(".")).unwrap();
        assert_eq!(r.name, expected);
        assert_eq!(r.workspace.as_deref(), Some(Path::new(".")));
    }

    #[test]
    fn bare_word_falls_back_to_local_dir_with_manifest() {
        let _g = CWD_LOCK.lock().unwrap();
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
    }

    #[test]
    fn ambiguous_bare_word_is_a_hard_error() {
        let _g = CWD_LOCK.lock().unwrap();
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
        let _g = CWD_LOCK.lock().unwrap();
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
}
