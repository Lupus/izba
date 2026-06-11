use izba_proto::{read_frame, write_frame, ExitStatus, Request, Response, CONTROL_PORT};
use izba_ttytest::scripted_guest::{ExecOutcome, GuestScript, ScriptedGuest};
use std::io::{Read, Write};

#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use uds_windows::UnixStream;

/// Perform the CH hybrid handshake to `port` on the guest's vsock.sock.
fn connect(sock: &std::path::Path, port: u32) -> UnixStream {
    let mut s = UnixStream::connect(sock).expect("connect vsock.sock");
    s.write_all(format!("CONNECT {port}\n").as_bytes()).unwrap();
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = s.read(&mut b).unwrap();
        assert_ne!(n, 0, "EOF before OK line");
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
    }
    assert!(
        String::from_utf8_lossy(&line).starts_with("OK "),
        "handshake not OK: {:?}",
        String::from_utf8_lossy(&line)
    );
    s
}

#[test]
fn answers_handshake_and_health() {
    let script = GuestScript {
        exec_outcome: ExecOutcome::Started,
        initial_emit: Vec::new(),
        on_resize: None,
        end_when_input_contains: None,
        final_status: ExitStatus::Code(0),
    };
    let guest = ScriptedGuest::start(script).expect("start guest");

    let mut conn = connect(&guest.vsock_path(), CONTROL_PORT);
    write_frame(&mut conn, &Request::Health).unwrap();
    match read_frame::<_, Response>(&mut conn).unwrap() {
        Response::Health(info) => assert!(!info.version.is_empty()),
        other => panic!("unexpected: {other:?}"),
    }
    drop(conn);
    drop(guest);
}
