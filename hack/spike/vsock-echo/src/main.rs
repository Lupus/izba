//! Spike rung-4 guest endpoint: echo every byte received on vsock port 1025.
//! Prints SPIKE-VSOCK-ECHO-READY once listening so the console log proves liveness.

use std::io::{Read, Write};

fn main() {
    let listener = vsock::VsockListener::bind_with_cid_port(libc::VMADDR_CID_ANY, 1025)
        .expect("bind vsock port 1025");
    println!("SPIKE-VSOCK-ECHO-READY");
    for conn in listener.incoming() {
        let mut conn = match conn {
            Ok(c) => c,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let mut buf = [0u8; 4096];
        loop {
            match conn.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if conn.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    }
}
