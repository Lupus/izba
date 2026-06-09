use izba_core::paths::Paths;
use izba_core::sandbox;
use std::time::Duration;

const STOP_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    let connector = sandbox::default_connector();
    sandbox::stop(paths, name, &connector, STOP_TIMEOUT)?;
    Ok(0)
}
