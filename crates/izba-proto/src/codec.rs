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
}
