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
/// - A DNS-readiness poll then waits for the in-guest izbad resolver to answer:
///   immediately after boot the resolver can SERVFAIL its first query ("server
///   misbehaving") before it warms up, and BuildKit issues the base-image
///   manifest `HEAD` at once without retrying DNS — so prime it first.
/// - Output is `type=oci,dest=/out/img.tar` for host ingest.
pub fn build_script(filename: &str) -> String {
    // `filename` is user-controlled (`izba build -f <path>`) and is interpolated
    // into a `/bin/sh -c` command, so it MUST be shell-quoted: an unquoted path
    // with a space (`sub dir/Dockerfile`) would word-split buildctl's args, and a
    // shell metacharacter could otherwise inject into the builder shell.
    let filename = sh_single_quote(filename);
    format!(
        "set -e\n\
         buildkitd --oci-worker-snapshotter=overlayfs --root /var/lib/buildkit >/var/log/buildkitd.log 2>&1 &\n\
         for i in $(seq 1 60); do buildctl debug workers >/dev/null 2>&1 && break; sleep 1; done\n\
         buildctl debug workers >/dev/null 2>&1 || {{ echo \"timed out waiting for buildkitd (60s)\" >&2; tail -n 50 /var/log/buildkitd.log >&2 2>&1; exit 1; }}\n\
         for i in $(seq 1 30); do nslookup registry-1.docker.io 127.0.0.1 >/dev/null 2>&1 && break; sleep 1; done\n\
         nslookup registry-1.docker.io 127.0.0.1 >/dev/null 2>&1 || {{ echo \"timed out waiting for DNS (30s)\" >&2; cat /etc/resolv.conf >&2 2>&1; nslookup registry-1.docker.io 127.0.0.1 >&2 2>&1; exit 1; }}\n\
         set +e\n\
         buildctl build --progress=plain --frontend dockerfile.v0 --local context=/workspace --local dockerfile=/workspace --opt filename={filename} --output type=oci,dest=/out/img.tar\n\
         rc=$?\n\
         if [ \"$rc\" -ne 0 ]; then\n\
           echo \"=== izba build diagnostics (buildctl rc=$rc) ===\" >&2\n\
           echo \"--- /etc/resolv.conf ---\" >&2; cat /etc/resolv.conf >&2 2>&1\n\
           echo \"--- nslookup registry-1.docker.io @127.0.0.1 ---\" >&2; nslookup registry-1.docker.io 127.0.0.1 >&2 2>&1\n\
           echo \"--- buildkitd.log (tail) ---\" >&2; tail -n 50 /var/log/buildkitd.log >&2 2>&1\n\
         fi\n\
         exit $rc\n"
    )
}

/// POSIX single-quote a string for safe interpolation into a `/bin/sh` command:
/// wrap in `'…'` and rewrite each embedded `'` as `'\''` (close-quote, an
/// escaped literal quote, reopen-quote). The result is a single shell word.
fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
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
        assert!(
            s.contains("--opt filename='Dockerfile'"),
            "filename opt (shell-quoted): {s}"
        );
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
    fn build_script_waits_for_dns_readiness_before_buildctl() {
        // The resolver can SERVFAIL its first post-boot query; gate buildctl on
        // a successful resolution so BuildKit's eager manifest HEAD doesn't race
        // the cold-start warm-up. The DNS poll must precede the `buildctl build`.
        let s = build_script("Dockerfile");
        let dns = s
            .find("nslookup registry-1.docker.io 127.0.0.1")
            .expect("DNS-readiness poll present");
        let build = s.find("buildctl build").expect("buildctl build present");
        assert!(dns < build, "DNS poll must run before buildctl build: {s}");
    }

    #[test]
    fn build_script_custom_filename() {
        let s = build_script("Dockerfile.dev");
        assert!(
            s.contains("--opt filename='Dockerfile.dev'"),
            "custom filename injected: {s}"
        );
        // The default name must not leak in when a custom one is requested.
        assert!(
            !s.contains("filename='Dockerfile' "),
            "no stray default filename: {s}"
        );
    }

    #[test]
    fn build_script_shell_quotes_filename() {
        // A path with a space must stay a SINGLE buildctl arg (no word-split),
        // and an embedded single quote must be escaped, not break out of the
        // quoting. `izba build -f` passes this through verbatim.
        let s = build_script("sub dir/Docker'file");
        assert!(
            s.contains("--opt filename='sub dir/Docker'\\''file'"),
            "filename must be POSIX single-quoted with escaped inner quote: {s}"
        );
        // The raw, unquoted form must NOT appear (that would word-split).
        assert!(
            !s.contains("filename=sub dir"),
            "unquoted filename must not leak: {s}"
        );
    }

    #[test]
    fn build_script_exits_on_buildkitd_poll_timeout() {
        // After the buildkitd poll loop the script must explicitly exit 1 with
        // a clear message (not silently fall through to a confusing
        // connection-refused from `buildctl`).  It must also dump the
        // buildkitd.log tail so console.log shows why the daemon never came up.
        let s = build_script("Dockerfile");
        let poll_end = s.find("seq 1 60").expect("buildkitd poll present") + "seq 1 60".len();
        let buildctl_start = s.find("buildctl build").expect("buildctl build present");
        let between = &s[poll_end..buildctl_start];
        assert!(
            between.contains("exit 1"),
            "exit 1 must appear between buildkitd poll and buildctl build: {s}"
        );
        assert!(
            between.contains("timed out") || between.contains("timeout"),
            "timeout message must appear between buildkitd poll and buildctl build: {s}"
        );
        assert!(
            between.contains("buildkitd.log"),
            "buildkitd.log tail must be dumped on buildkitd poll timeout: {s}"
        );
    }

    #[test]
    fn build_script_exits_on_dns_poll_timeout() {
        // After the DNS poll loop the script must explicitly exit 1 with a
        // clear message.  It must also dump resolv.conf so console.log shows
        // the resolver configuration at the time of the failure.
        let s = build_script("Dockerfile");
        let poll_end = s.find("seq 1 30").expect("DNS poll present") + "seq 1 30".len();
        let buildctl_start = s.find("buildctl build").expect("buildctl build present");
        let between = &s[poll_end..buildctl_start];
        assert!(
            between.contains("exit 1"),
            "exit 1 must appear between DNS poll and buildctl build: {s}"
        );
        assert!(
            between.contains("timed out") || between.contains("timeout"),
            "timeout message must appear between DNS poll and buildctl build: {s}"
        );
        assert!(
            between.contains("resolv.conf"),
            "resolv.conf must be dumped on DNS poll timeout: {s}"
        );
    }
}
