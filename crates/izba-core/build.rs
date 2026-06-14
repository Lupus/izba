//! Emits compile-time build metadata (git describe/sha/commit-date, build
//! timestamp, rustc, target, profile) consumed by `src/build_info.rs`. A
//! missing `.git` (e.g. a release-tarball build) must NOT fail the build: the
//! Emitter has no `fail_on_error` feature, so unavailable `VERGEN_GIT_*` vars
//! are defaulted rather than erroring, and `build_info` treats absent/empty
//! values as "unknown".

use vergen_gitcl::{Build, Cargo, Emitter, Gitcl, Rustc};

fn main() {
    let build = Build::all_build();
    let cargo = Cargo::all_cargo();
    let rustc = Rustc::all_rustc();
    // `all()` enables every VERGEN_GIT_* instruction; override describe to use
    // tags + the "-dirty" suffix.
    let gitcl = Gitcl::all().describe(true, true, None).build();

    // Friendly profile name ("debug"/"release") straight from cargo.
    if let Ok(profile) = std::env::var("PROFILE") {
        println!("cargo:rustc-env=IZBA_PROFILE={profile}");
    }

    let mut emitter = Emitter::default();
    let _ = emitter
        .add_instructions(&build)
        .and_then(|e| e.add_instructions(&cargo))
        .and_then(|e| e.add_instructions(&rustc))
        .and_then(|e| e.add_instructions(&gitcl))
        .and_then(|e| e.emit());
}
