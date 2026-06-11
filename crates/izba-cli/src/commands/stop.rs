use izba_core::daemon::proto::DaemonRequest;
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

pub fn run(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    let resp = client.request(
        &DaemonRequest::Stop {
            name: name.to_string(),
        },
        &mut |_| {},
    )?;
    super::expect_ok(resp)?;
    Ok(0)
}
