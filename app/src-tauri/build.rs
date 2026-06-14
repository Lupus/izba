use vergen_gitcl::{Build, Cargo, Emitter, Gitcl, Rustc};

fn main() {
    tauri_build::build();

    // Friendly profile name ("debug"/"release") straight from cargo.
    if let Ok(profile) = std::env::var("PROFILE") {
        println!("cargo:rustc-env=IZBA_PROFILE={profile}");
    }

    // Best-effort build metadata for the app binary itself (mirrors
    // izba-core/build.rs). A missing `.git` must not fail the build.
    let build = Build::all_build();
    let cargo = Cargo::all_cargo();
    let rustc = Rustc::all_rustc();
    let gitcl = Gitcl::all().describe(true, true, None).build();
    let mut emitter = Emitter::default();
    let _ = emitter
        .add_instructions(&build)
        .and_then(|e| e.add_instructions(&cargo))
        .and_then(|e| e.add_instructions(&rustc))
        .and_then(|e| e.add_instructions(&gitcl))
        .and_then(|e| e.emit());
}
