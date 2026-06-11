use crate::SandboxOpts;
use izba_core::paths::Paths;
use izba_core::{image, sandbox};
use std::path::Path;

pub fn run(paths: &Paths, opts: &SandboxOpts, dir: &Path) -> anyhow::Result<i32> {
    let workspace = super::ensure_workspace(dir)?;
    let name = super::name_for(opts, &workspace)?;
    let ports = super::parse_publish(&opts.publish)?;
    eprintln!("resolving {} (pulls if not cached)...", opts.image);
    let digest = image::ensure_image(paths, &opts.image)?;
    sandbox::create(
        paths,
        &name,
        &super::create_opts(opts, digest, workspace, ports),
    )?;
    println!("{name}");
    Ok(0)
}
