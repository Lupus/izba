use izba_proto::{
    read_frame, write_frame, ExitStatus, Request, Response, StreamAttach, StreamKind, CONTROL_PORT,
    STREAM_PORT,
};
use izba_ttytest::scripted_guest::{ExecOutcome, GuestScript, ScriptedGuest};
use std::io::{Read, Write};

#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use uds_windows::UnixStream;

/// CH hybrid handshake, reading the OK line byte-by-byte (a BufReader could
/// swallow framed/stream bytes that arrive right after the newline).
fn connect(sock: &std::path::Path, port: u32) -> UnixStream {
    let mut s = UnixStream::connect(sock).unwrap();
    s.write_all(format!("CONNECT {port}\n").as_bytes()).unwrap();
    let mut b = [0u8; 1];
    loop {
        let n = s.read(&mut b).unwrap();
        assert_ne!(n, 0, "EOF before OK line");
        if b[0] == b'\n' {
            break;
        }
    }
    s
}

#[test]
fn stream_emits_records_input_and_ends() {
    fn resized(cols: u16, rows: u16) -> Vec<u8> {
        format!("RESIZED {cols}x{rows}").into_bytes()
    }
    let script = GuestScript {
        exec_outcome: ExecOutcome::Started,
        initial_emit: b"HELLO-STREAM".to_vec(),
        on_resize: Some(resized),
        end_when_input_contains: Some(b'q'),
        final_status: ExitStatus::Code(7),
    };
    let guest = ScriptedGuest::start(script).unwrap();

    // Open the stream and read the initial emit.
    let mut stream = connect(&guest.vsock_path(), STREAM_PORT);
    write_frame(
        &mut stream,
        &StreamAttach {
            exec_id: 1,
            kind: StreamKind::Tty,
        },
    )
    .unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap();
    assert!(std::str::from_utf8(&buf[..n])
        .unwrap()
        .contains("HELLO-STREAM"));

    // Drive a resize over the control port; expect a RESIZED frame on the stream.
    let mut ctrl = connect(&guest.vsock_path(), CONTROL_PORT);
    write_frame(
        &mut ctrl,
        &Request::Resize {
            exec_id: 1,
            cols: 90,
            rows: 20,
        },
    )
    .unwrap();
    assert!(matches!(
        read_frame::<_, Response>(&mut ctrl).unwrap(),
        Response::Ok
    ));
    let n = stream.read(&mut buf).unwrap();
    assert!(std::str::from_utf8(&buf[..n])
        .unwrap()
        .contains("RESIZED 90x20"));
    assert_eq!(guest.last_resize(), Some((90, 20)));

    // Send the end byte; the exec should end and Wait return the final status.
    stream.write_all(b"q").unwrap();
    let status = {
        let mut wait = connect(&guest.vsock_path(), CONTROL_PORT);
        write_frame(&mut wait, &Request::Wait { exec_id: 1 }).unwrap();
        match read_frame::<_, Response>(&mut wait).unwrap() {
            Response::Wait { status } => status,
            other => panic!("unexpected: {other:?}"),
        }
    };
    assert_eq!(status, ExitStatus::Code(7));

    // The input we sent was recorded.
    let recorded = guest.received_input();
    assert!(recorded.contains(&b'q'), "input not recorded: {recorded:?}");
}
