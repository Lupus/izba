use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("clean EOF before frame")]
    Eof,
    #[error("frame of {0} bytes exceeds limit")]
    TooLarge(u32),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), FrameError> {
    let payload = serde_json::to_vec(msg)?;
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&payload)?;
    w.flush()?;
    Ok(())
}

pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, FrameError> {
    let mut len_buf = [0u8; 4];
    // First byte distinguishes clean EOF from truncation.
    match r.read(&mut len_buf[..1])? {
        0 => return Err(FrameError::Eof),
        _ => r.read_exact(&mut len_buf[1..])?,
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    /// Reader that yields at most 1 byte per read() call — exercises torn reads.
    struct Trickle<R: Read>(R);
    impl<R: Read> Read for Trickle<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.0.read(&mut buf[..1])
        }
    }

    #[test]
    fn roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &serde_json::json!({"a": 1})).unwrap();
        let v: serde_json::Value = read_frame(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn torn_reads() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &serde_json::json!({"k": "v".repeat(1000)})).unwrap();
        let v: serde_json::Value = read_frame(&mut Trickle(Cursor::new(&buf))).unwrap();
        assert_eq!(v["k"].as_str().unwrap().len(), 1000);
    }

    #[test]
    fn two_frames_back_to_back() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &1u32).unwrap();
        write_frame(&mut buf, &2u32).unwrap();
        let mut c = Cursor::new(&buf);
        assert_eq!(read_frame::<_, u32>(&mut c).unwrap(), 1);
        assert_eq!(read_frame::<_, u32>(&mut c).unwrap(), 2);
    }

    #[test]
    fn oversize_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME + 1).to_le_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        assert!(matches!(
            read_frame::<_, u32>(&mut Cursor::new(&buf)),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn clean_eof_is_distinguishable() {
        let r = read_frame::<_, u32>(&mut Cursor::new(Vec::new()));
        assert!(matches!(r, Err(FrameError::Eof)));
    }

    #[test]
    fn truncated_mid_payload_is_distinguishable_from_eof() {
        // Complete length header claiming 10 bytes, but only 4 bytes of payload follow.
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        let r = read_frame::<_, serde_json::Value>(&mut Cursor::new(&buf));
        assert!(
            matches!(r, Err(FrameError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof),
            "expected UnexpectedEof, got {r:?}"
        );
    }

    // -------------------------------------------------------------------------
    // proptest: property-based tests
    // -------------------------------------------------------------------------

    use proptest::prelude::*;

    use crate::messages::{
        ErrorKind, ExecRequest, ExitStatus, HealthInfo, Request, Response, StreamAttach,
        StreamKind, StreamOpen,
    };

    /// Build an arbitrary ExecRequest.
    fn arb_exec_request() -> impl Strategy<Value = ExecRequest> {
        (
            proptest::collection::vec(any::<String>(), 0..8),
            proptest::collection::vec((any::<String>(), any::<String>()), 0..4),
            any::<String>(),
            any::<bool>(),
            any::<u32>(),
            any::<u32>(),
        )
            .prop_map(|(argv, env, cwd, tty, uid, gid)| ExecRequest {
                argv,
                env,
                cwd,
                tty,
                uid,
                gid,
            })
    }

    /// Build an arbitrary Request covering all variants.
    fn arb_request() -> impl Strategy<Value = Request> {
        prop_oneof![
            Just(Request::Health),
            arb_exec_request().prop_map(Request::Exec),
            any::<u32>().prop_map(|exec_id| Request::Wait { exec_id }),
            (any::<u32>(), any::<i32>())
                .prop_map(|(exec_id, signal)| Request::Kill { exec_id, signal }),
            (any::<u32>(), any::<u16>(), any::<u16>()).prop_map(|(exec_id, cols, rows)| {
                Request::Resize {
                    exec_id,
                    cols,
                    rows,
                }
            }),
            Just(Request::Shutdown),
        ]
    }

    fn arb_error_kind() -> impl Strategy<Value = ErrorKind> {
        prop_oneof![
            Just(ErrorKind::CommandNotFound),
            Just(ErrorKind::ExecNotFound),
            Just(ErrorKind::BadRequest),
            Just(ErrorKind::Internal),
            Just(ErrorKind::PathNotFound),
            Just(ErrorKind::ConnectFailed),
        ]
    }

    fn arb_exit_status() -> impl Strategy<Value = ExitStatus> {
        prop_oneof![
            any::<i32>().prop_map(ExitStatus::Code),
            any::<i32>().prop_map(ExitStatus::Signal),
        ]
    }

    /// Build an arbitrary Response covering all variants.
    fn arb_response() -> impl Strategy<Value = Response> {
        prop_oneof![
            (any::<String>(), any::<u64>()).prop_map(|(version, uptime_ms)| {
                Response::Health(HealthInfo { version, uptime_ms })
            }),
            any::<u32>().prop_map(|exec_id| Response::ExecStarted { exec_id }),
            arb_exit_status().prop_map(|status| Response::Wait { status }),
            Just(Response::Ok),
            (arb_error_kind(), any::<String>())
                .prop_map(|(kind, message)| Response::Error { kind, message }),
        ]
    }

    fn arb_stream_kind() -> impl Strategy<Value = StreamKind> {
        prop_oneof![
            Just(StreamKind::Stdin),
            Just(StreamKind::Stdout),
            Just(StreamKind::Stderr),
            Just(StreamKind::Tty),
        ]
    }

    /// Build an arbitrary StreamOpen covering all variants.
    fn arb_stream_open() -> impl Strategy<Value = StreamOpen> {
        prop_oneof![
            (any::<u32>(), arb_stream_kind())
                .prop_map(|(exec_id, kind)| { StreamOpen::Attach(StreamAttach { exec_id, kind }) }),
            any::<u16>().prop_map(|port| StreamOpen::TcpDial { port }),
            any::<String>().prop_map(|dest| StreamOpen::TarExtract { dest }),
            any::<String>().prop_map(|src| StreamOpen::TarCreate { src }),
            (any::<String>(), any::<u16>())
                .prop_map(|(addr, port)| StreamOpen::TcpConnect { addr, port }),
            Just(StreamOpen::Dns),
            Just(StreamOpen::DnsTcp),
        ]
    }

    proptest! {
        /// write_frame then read_frame is the identity for Request.
        /// Can fail if serde_json roundtrip diverges (e.g. NaN in floats — not
        /// applicable here since all fields are integer or string) or if the
        /// framing length math is wrong.
        #[test]
        fn prop_request_roundtrip(req in arb_request()) {
            let mut buf = Vec::new();
            write_frame(&mut buf, &req).unwrap();
            let back: Request = read_frame(&mut Cursor::new(&buf)).unwrap();
            prop_assert_eq!(format!("{req:?}"), format!("{back:?}"));
        }

        /// Same property for Response.
        #[test]
        fn prop_response_roundtrip(resp in arb_response()) {
            let mut buf = Vec::new();
            write_frame(&mut buf, &resp).unwrap();
            let back: Response = read_frame(&mut Cursor::new(&buf)).unwrap();
            prop_assert_eq!(format!("{resp:?}"), format!("{back:?}"));
        }

        /// Same property for StreamOpen.
        #[test]
        fn prop_stream_open_roundtrip(open in arb_stream_open()) {
            let mut buf = Vec::new();
            write_frame(&mut buf, &open).unwrap();
            let back: StreamOpen = read_frame(&mut Cursor::new(&buf)).unwrap();
            prop_assert_eq!(format!("{open:?}"), format!("{back:?}"));
        }

        /// Split-point invariance: feed bytes in arbitrary-sized chunks and
        /// still decode correctly. Can fail if the chunked reader path in
        /// read_frame differs from the contiguous path (e.g., if read_exact
        /// handling were broken for torn length-prefix or payload reads).
        #[test]
        fn prop_split_point_invariance(
            open in arb_stream_open(),
            // chunk sizes in 1..=32; at least one chunk needed
            chunks in proptest::collection::vec(1usize..=32, 1..=64),
        ) {
            let mut buf = Vec::new();
            write_frame(&mut buf, &open).unwrap();
            let mut src = ChunkedSource { data: buf, chunks, pos: 0, chunk_idx: 0 };
            let back: StreamOpen = read_frame(&mut src).unwrap();
            prop_assert_eq!(format!("{open:?}"), format!("{back:?}"));
        }

        /// Arbitrary bytes fed to read_frame must never panic and must never
        /// attempt an allocation larger than MAX_FRAME.  The large-length
        /// prefix case (0xFFFFFFFF) in particular must be rejected, not
        /// attempted.  This property covers: Err(TooLarge), Err(Eof),
        /// Err(Io(...)), Err(Json(...)) — all are acceptable outcomes.
        /// Panic is not.
        #[test]
        fn prop_no_panic_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let result = read_frame::<_, serde_json::Value>(&mut Cursor::new(&data));
            // Verify the large-length-prefix case: if the encoded length exceeds
            // MAX_FRAME, the error must be TooLarge (not an OOM from vec allocation).
            if data.len() >= 4 {
                let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                if len > MAX_FRAME {
                    prop_assert!(
                        matches!(result, Err(FrameError::TooLarge(_))),
                        "expected TooLarge for len={len}, got {result:?}"
                    );
                }
            }
            // Regardless of input, no panic occurred (reaching here means that).
        }
    }

    /// A Read impl that delivers data in user-specified chunk sizes.
    struct ChunkedSource {
        data: Vec<u8>,
        chunks: Vec<usize>,
        pos: usize,
        chunk_idx: usize,
    }

    impl Read for ChunkedSource {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            // Determine max bytes to yield this call.
            let chunk_max = if self.chunk_idx < self.chunks.len() {
                let c = self.chunks[self.chunk_idx];
                self.chunk_idx += 1;
                c.max(1) // never yield 0 bytes when data remains (would signal EOF)
            } else {
                // No more chunk sizes specified — yield rest in one shot.
                self.data.len() - self.pos
            };
            let available = self.data.len() - self.pos;
            let to_yield = buf.len().min(chunk_max).min(available);
            if to_yield == 0 {
                return Ok(0);
            }
            buf[..to_yield].copy_from_slice(&self.data[self.pos..self.pos + to_yield]);
            self.pos += to_yield;
            Ok(to_yield)
        }
    }
}
