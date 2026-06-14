//! Emits VERGEN_* build metadata so PID 1 can log its own build (git describe +
//! build timestamp) to the serial console at boot. Best-effort: a missing
//! `.git` must not fail the static musl build (no `fail_on_error` feature).

use vergen_gitcl::{Build, Emitter, Gitcl};

fn main() {
    let build = Build::all_build();
    let gitcl = Gitcl::all().describe(true, true, None).build();

    let mut emitter = Emitter::default();
    let _ = emitter
        .add_instructions(&build)
        .and_then(|e| e.add_instructions(&gitcl))
        .and_then(|e| e.emit());
}
