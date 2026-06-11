use izba_core::paths::Paths;
use izba_core::sandbox;

pub fn run(paths: &Paths) -> anyhow::Result<i32> {
    let connector = sandbox::default_connector();
    let infos = sandbox::list(paths, &connector)?;
    println!("{:<24} {:<32} STATUS", "NAME", "IMAGE");
    for info in infos {
        let status = info.liveness.describe();
        println!("{:<24} {:<32} {}", info.name, info.image_ref, status);
    }
    Ok(0)
}
