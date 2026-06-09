use izba_core::paths::Paths;
use izba_core::sandbox;

pub fn run(paths: &Paths, name: &str, force: bool) -> anyhow::Result<i32> {
    let connector = sandbox::default_connector();
    sandbox::remove(paths, name, &connector, force)?;
    Ok(0)
}
