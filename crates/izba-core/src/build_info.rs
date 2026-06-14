//! Compile-time build metadata — the single source of truth shared by the CLI,
//! the daemon (same binary), and, via the linked library, the desktop app.
//! Git/build fields resolve through `option_env!` so a build without `.git`
//! (release tarball) degrades to "unknown" rather than failing to compile.
//! `build.rs` (vergen-gitcl) populates the `VERGEN_*` vars.

use serde::{Deserialize, Serialize};

/// Static build metadata, resolved at compile time.
#[derive(Clone, Copy, Debug)]
pub struct BuildInfo {
    pub pkg_version: &'static str,
    pub git_describe: &'static str,
    pub git_sha: &'static str,
    pub commit_date: &'static str,
    pub build_timestamp: &'static str,
    pub rustc: &'static str,
    pub target: &'static str,
    pub profile: &'static str,
}

const fn or_unknown(v: Option<&'static str>) -> &'static str {
    match v {
        Some(s) => s,
        None => "unknown",
    }
}

fn sha_short_of(sha: &str) -> &str {
    if sha == "unknown" {
        "unknown"
    } else {
        &sha[..sha.len().min(7)]
    }
}

impl BuildInfo {
    /// This binary's build metadata.
    pub const fn current() -> Self {
        BuildInfo {
            pkg_version: env!("CARGO_PKG_VERSION"),
            git_describe: or_unknown(option_env!("VERGEN_GIT_DESCRIBE")),
            git_sha: or_unknown(option_env!("VERGEN_GIT_SHA")),
            commit_date: or_unknown(option_env!("VERGEN_GIT_COMMIT_DATE")),
            build_timestamp: or_unknown(option_env!("VERGEN_BUILD_TIMESTAMP")),
            rustc: or_unknown(option_env!("VERGEN_RUSTC_SEMVER")),
            target: or_unknown(option_env!("VERGEN_CARGO_TARGET_TRIPLE")),
            // `IZBA_PROFILE` is emitted by build.rs from the cargo `PROFILE`
            // env ("debug"/"release") — friendlier than vergen's opt-level.
            profile: or_unknown(option_env!("IZBA_PROFILE")),
        }
    }

    /// First 7 chars of the commit sha, or "unknown".
    pub fn sha_short(&self) -> &str {
        sha_short_of(self.git_sha)
    }

    /// One-liner for `--version`: `0.1.0 (9f0d480)`.
    pub fn short(&self) -> String {
        format!("{} ({})", self.pkg_version, self.sha_short())
    }

    /// Multi-line block for `izba version`.
    pub fn long(&self) -> String {
        format!(
            "izba {}\n git:     {}\n commit:  {} {}\n built:   {}\n rustc:   {}   target: {}\n profile: {}",
            self.pkg_version,
            self.git_describe,
            self.sha_short(),
            self.commit_date,
            self.build_timestamp,
            self.rustc,
            self.target,
            self.profile,
        )
    }

    pub fn to_owned(&self) -> BuildInfoOwned {
        BuildInfoOwned {
            pkg_version: self.pkg_version.into(),
            git_describe: self.git_describe.into(),
            git_sha: self.git_sha.into(),
            commit_date: self.commit_date.into(),
            build_timestamp: self.build_timestamp.into(),
            rustc: self.rustc.into(),
            target: self.target.into(),
            profile: self.profile.into(),
        }
    }
}

/// Wire/serde form sent over the daemon protocol and returned to the app UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildInfoOwned {
    pub pkg_version: String,
    pub git_describe: String,
    pub git_sha: String,
    pub commit_date: String,
    pub build_timestamp: String,
    pub rustc: String,
    pub target: String,
    pub profile: String,
}

impl BuildInfoOwned {
    /// This binary's build metadata, owned.
    pub fn current() -> Self {
        BuildInfo::current().to_owned()
    }

    pub fn sha_short(&self) -> &str {
        sha_short_of(&self.git_sha)
    }

    /// One-liner: `0.1.0 (9f0d480)`.
    pub fn short(&self) -> String {
        format!("{} ({})", self.pkg_version, self.sha_short())
    }
}

impl Default for BuildInfoOwned {
    /// All-"unknown" — what an old daemon frame (missing `build`) deserializes
    /// to via `#[serde(default)]`.
    fn default() -> Self {
        BuildInfo {
            pkg_version: "unknown",
            git_describe: "unknown",
            git_sha: "unknown",
            commit_date: "unknown",
            build_timestamp: "unknown",
            rustc: "unknown",
            target: "unknown",
            profile: "unknown",
        }
        .to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BuildInfo {
        BuildInfo {
            pkg_version: "0.1.0",
            git_describe: "v0.1.0-rc1-3-g9f0d480",
            git_sha: "9f0d480abcdef",
            commit_date: "2026-06-14",
            build_timestamp: "2026-06-14T10:00:00Z",
            rustc: "1.96.0",
            target: "x86_64-unknown-linux-gnu",
            profile: "3",
        }
    }

    #[test]
    fn short_is_semver_and_short_sha() {
        assert_eq!(sample().short(), "0.1.0 (9f0d480)");
    }

    #[test]
    fn sha_short_handles_unknown() {
        let mut b = sample();
        b.git_sha = "unknown";
        assert_eq!(b.sha_short(), "unknown");
    }

    #[test]
    fn long_contains_all_fields() {
        let s = sample().long();
        for needle in [
            "0.1.0",
            "v0.1.0-rc1-3-g9f0d480",
            "2026-06-14",
            "1.96.0",
            "x86_64-unknown-linux-gnu",
        ] {
            assert!(s.contains(needle), "long() missing {needle}: {s}");
        }
    }

    #[test]
    fn owned_roundtrips_through_serde() {
        let owned = sample().to_owned();
        let json = serde_json::to_string(&owned).unwrap();
        let back: BuildInfoOwned = serde_json::from_str(&json).unwrap();
        assert_eq!(owned, back);
    }

    #[test]
    fn default_is_all_unknown() {
        assert_eq!(BuildInfoOwned::default().git_sha, "unknown");
        assert_eq!(BuildInfoOwned::default().short(), "unknown (unknown)");
    }

    #[test]
    fn current_builds_and_short_is_nonempty() {
        // Smoke: the real env-backed constructor compiles and produces output.
        assert!(!BuildInfo::current().short().is_empty());
    }
}
