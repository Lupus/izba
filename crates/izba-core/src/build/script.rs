//! The in-guest BuildKit driver script.
//!
//! `izba build` boots a throwaway builder sandbox from the BuildKit image
//! (pause-PID-1, so buildkitd is NOT auto-running) and execs this script
//! non-interactively. It starts `buildkitd`, waits for the worker to come up,
//! then runs the Dockerfile build, writing the result as an OCI archive to
//! `/out/img.tar` — the guest mountpoint of the `izba-buildout` rw share the
//! host ingests after the build.

/// Render the build script for a Dockerfile named `filename` (relative to the
/// build context, which is shared at `/workspace`).
///
/// - `buildkitd` uses the overlayfs snapshotter rooted at `/var/lib/buildkit`
///   (the persistent `izba-buildcache` volume — incremental cache across builds).
/// - The worker-ready poll bounds boot to ~60s before buildctl runs.
/// - Output is `type=oci,dest=/out/img.tar` for host ingest.
pub fn build_script(filename: &str) -> String {
    format!(
        "set -e\n\
         buildkitd --oci-worker-snapshotter=overlayfs --root /var/lib/buildkit >/var/log/buildkitd.log 2>&1 &\n\
         for i in $(seq 1 60); do buildctl debug workers >/dev/null 2>&1 && break; sleep 1; done\n\
         buildctl build --frontend dockerfile.v0 --local context=/workspace --local dockerfile=/workspace --opt filename={filename} --output type=oci,dest=/out/img.tar\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_script_default_dockerfile() {
        let s = build_script("Dockerfile");
        assert!(
            s.contains("--oci-worker-snapshotter=overlayfs"),
            "overlayfs snapshotter flag: {s}"
        );
        assert!(
            s.contains("type=oci,dest=/out/img.tar"),
            "oci output to /out/img.tar: {s}"
        );
        assert!(s.contains("--opt filename=Dockerfile"), "filename opt: {s}");
        assert!(
            s.contains("--local context=/workspace"),
            "context share: {s}"
        );
        assert!(
            s.contains("--local dockerfile=/workspace"),
            "dockerfile share: {s}"
        );
    }

    #[test]
    fn build_script_custom_filename() {
        let s = build_script("Dockerfile.dev");
        assert!(
            s.contains("--opt filename=Dockerfile.dev"),
            "custom filename injected: {s}"
        );
        // The default name must not leak in when a custom one is requested.
        assert!(
            !s.contains("filename=Dockerfile "),
            "no stray default filename: {s}"
        );
    }
}
