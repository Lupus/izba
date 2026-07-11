//! `izba promote` — apply izba.yml -> managed truth, gated on a prior `izba
//! diff` review. Live fields apply immediately; restart fields update
//! config.json and take effect on next start (or now with --restart).
//!
//! The orchestration itself (the review gate, drift classification, and the
//! live daemon RPC sequencing) lives in `izba_core::manifest::promote::run` —
//! an event-callback API shared with a future Tauri app command (see that
//! module's doc comment for the byte-parity contract). This file is the
//! CLI-side resolver + renderer: resolve the sandbox reference, validate the
//! name, wire `PromoteEvent`s straight to `println!`/`eprintln!` (so stdout/
//! stderr are unchanged from before the extraction), and supply the
//! `spec.build:` image-resolution callback — that needs the CLI-only
//! throwaway-builder-sandbox orchestration in `commands::build`, which
//! `izba-core` must not depend on.

use std::path::Path;

use anyhow::{Context, Result};
use izba_core::manifest::promote::{PromoteEvent, PromoteOpts};
use izba_core::manifest::schema::BuildSpec;
use izba_core::paths::Paths;

#[mutants::skip] // reason: drives a live daemon (via izba_core::manifest::promote::run) + image build/pull; e2e-only (daemon_e2e manifest_diff_promote_live_path). The decision logic it composes is unit-tested separately (izba-core manifest::promote, this file's build_opts_from tests).
pub fn run(
    paths: &Paths,
    target: Option<&str>,
    name_override: Option<&str>,
    force: bool,
    restart: bool,
    reset_scratch: bool,
) -> Result<i32> {
    // #123: NAME-or-DIR positional through the shared resolver.
    let r = super::sandbox_ref::resolve(paths, target)?;
    super::sandbox_ref::check_name_override(&r, name_override)?;
    let dir = r
        .workspace
        .clone()
        .with_context(|| format!("sandbox '{}' has no recorded workspace directory", r.name))?;
    let dir = dir.as_path();
    // #123: the RESOLVED reference pins the target sandbox — never the
    // agent-writable metadata.name. A divergent metadata.name must not
    // redirect which managed truth is mutated (diff/export use the same rule).
    let name = name_override.unwrap_or(&r.name).to_string();
    izba_core::sandbox::validate_name(&name)?;

    let outcome = izba_core::manifest::promote::run(
        paths,
        dir,
        &name,
        PromoteOpts {
            force,
            restart,
            reset_scratch,
        },
        &mut |ev| match ev {
            PromoteEvent::Info(m) => println!("{m}"),
            PromoteEvent::Warn(m) => eprintln!("{m}"),
        },
        &mut |dir, b| {
            let opts = build_opts_from(dir, b)?;
            crate::commands::build::build_image(paths, &opts)
        },
    )?;
    let _ = outcome; // CLI output is fully carried by the events
    Ok(0)
}

fn build_opts_from(dir: &Path, b: &BuildSpec) -> Result<crate::commands::build::BuildOpts> {
    let context_raw = dir.join(b.context.as_deref().unwrap_or("."));
    let context = izba_core::manifest::ops::ensure_within(dir, &context_raw)?;
    let dockerfile_raw = context.join(b.dockerfile.as_deref().unwrap_or("Dockerfile"));
    let dockerfile = izba_core::manifest::ops::ensure_within(&context, &dockerfile_raw)?;
    let (cpus, mem) = match &b.resources {
        Some(r) => {
            let mem = izba_core::manifest::quantity::parse_mib(&r.memory)
                .context("build.resources.memory")?;
            (r.cpus, mem)
        }
        None => (2, 4096),
    };
    Ok(crate::commands::build::BuildOpts {
        dockerfile,
        tag: b.tag.clone(),
        context,
        build_allow: b.allow.clone(),
        cpus,
        mem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::manifest::schema::Resources;

    /// validate_name is the first check in promote::run (hoisted before any path
    /// construction). This sentinel asserts it rejects traversal names.
    #[test]
    fn validate_name_rejects_traversal() {
        assert!(
            izba_core::sandbox::validate_name("../../etc").is_err(),
            "traversal name must be rejected by validate_name"
        );
    }

    fn make_workspace() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch\n").unwrap();
        tmp
    }

    fn build_spec_with_memory(memory: &str) -> BuildSpec {
        BuildSpec {
            context: None,
            dockerfile: None,
            tag: None,
            allow: vec![],
            resources: Some(Resources {
                cpus: 2,
                memory: memory.to_string(),
            }),
        }
    }

    fn build_spec_no_resources() -> BuildSpec {
        BuildSpec {
            context: None,
            dockerfile: None,
            tag: None,
            allow: vec![],
            resources: None,
        }
    }

    #[test]
    fn build_opts_from_valid_binary_si_memory() {
        // "4Gi" is valid binary SI — should parse to 4096 MiB.
        let tmp = make_workspace();
        let spec = build_spec_with_memory("4Gi");
        let opts = build_opts_from(tmp.path(), &spec).unwrap();
        assert_eq!(opts.mem, 4096);
    }

    #[test]
    fn build_opts_from_invalid_decimal_si_memory_returns_err() {
        // "4GB" uses decimal SI which parse_mib does not accept — must propagate Err.
        // Provide a real workspace so ensure_within canonicalize succeeds and we
        // reach the memory-parse stage (portable: no hardcoded Unix /tmp).
        let tmp = make_workspace();
        let spec = build_spec_with_memory("4GB");
        match build_opts_from(tmp.path(), &spec) {
            Ok(_) => panic!("expected Err for invalid memory \"4GB\""),
            Err(e) => assert!(
                e.to_string().contains("build.resources.memory"),
                "error context should mention build.resources.memory, got: {e}"
            ),
        }
    }

    #[test]
    fn build_opts_from_no_resources_defaults_to_4096() {
        // When resources is None the default mem should be 4096 (not an error).
        let tmp = make_workspace();
        let spec = build_spec_no_resources();
        let opts = build_opts_from(tmp.path(), &spec).unwrap();
        assert_eq!(opts.mem, 4096);
        assert_eq!(opts.cpus, 2);
    }
}
