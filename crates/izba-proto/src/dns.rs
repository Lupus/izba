//! DNS message helpers shared by the guest stub and izbad's resolver:
//! RFC 1035 §4.2.2 framing (2-byte big-endian length prefix) and SERVFAIL
//! synthesis. No DNS parsing lives here — messages are opaque bytes.

use std::io::{self, Read, Write};

/// Write one length-prefixed DNS message.
pub fn write_dns_msg<W: Write>(w: &mut W, msg: &[u8]) -> io::Result<()> {
    let len = u16::try_from(msg.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "dns message over 64 KiB"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(msg)
}

/// Read one length-prefixed DNS message; `Ok(None)` on clean EOF at a
/// message boundary (the peer closed between messages).
pub fn read_dns_msg<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    // First byte by hand to distinguish boundary-EOF from a truncated frame.
    if r.read(&mut len[..1])? == 0 {
        return Ok(None);
    }
    r.read_exact(&mut len[1..])?;
    let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut msg)?;
    Ok(Some(msg))
}

/// Turn `query` into a SERVFAIL response in place: QR=1, RA=1, RCODE=2.
/// ID and question section are preserved so the client can match it.
pub fn servfail(query: &[u8]) -> Vec<u8> {
    let mut resp = query.to_vec();
    if resp.len() >= 4 {
        resp[2] |= 0x80; // QR: this is a response
        resp[3] = (resp[3] & 0xf0) | 0x02; // RCODE = SERVFAIL
        resp[3] |= 0x80; // RA
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip_and_boundary_eof() {
        let mut buf = Vec::new();
        write_dns_msg(&mut buf, b"query-one").unwrap();
        write_dns_msg(&mut buf, b"q2").unwrap();
        let mut c = Cursor::new(&buf);
        assert_eq!(read_dns_msg(&mut c).unwrap().unwrap(), b"query-one");
        assert_eq!(read_dns_msg(&mut c).unwrap().unwrap(), b"q2");
        assert!(read_dns_msg(&mut c).unwrap().is_none(), "clean EOF -> None");
    }

    #[test]
    fn truncated_frame_is_an_error() {
        let mut buf = Vec::new();
        write_dns_msg(&mut buf, b"hello").unwrap();
        buf.truncate(4); // length prefix promises 5 bytes; only 2 present
        let mut c = Cursor::new(&buf);
        assert!(read_dns_msg(&mut c).is_err());
    }

    #[test]
    fn servfail_sets_qr_ra_rcode_keeps_id() {
        // 12-byte header: ID=0xbeef, flags=0x0100 (RD), 1 question.
        let q = [0xbeu8, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let r = servfail(&q);
        assert_eq!(&r[..2], &[0xbe, 0xef], "ID preserved");
        assert_eq!(r[2], 0x81, "QR set, RD preserved");
        assert_eq!(r[3], 0x82, "RA set, RCODE=2");
        assert_eq!(r.len(), q.len());
    }

    #[test]
    fn servfail_on_runt_query_does_not_panic() {
        assert_eq!(servfail(&[0x01]), vec![0x01]);
    }

    // -------------------------------------------------------------------------
    // proptest: property-based tests
    // -------------------------------------------------------------------------

    use proptest::prelude::*;

    proptest! {
        /// For any payload in 0..=65535 bytes, write_dns_msg then read_dns_msg
        /// is the identity.  Can fail if the u16-BE length prefix is
        /// misencoded or if read_dns_msg reads the wrong number of bytes.
        #[test]
        fn prop_dns_frame_roundtrip(
            payload in proptest::collection::vec(any::<u8>(), 0..=65535usize),
        ) {
            let mut buf = Vec::new();
            write_dns_msg(&mut buf, &payload).unwrap();
            let mut c = Cursor::new(&buf);
            let decoded = read_dns_msg(&mut c).unwrap().unwrap();
            prop_assert_eq!(decoded, payload);
            // After one message, reading again must return None (clean EOF).
            let eof = read_dns_msg(&mut c).unwrap();
            prop_assert!(eof.is_none(), "expected clean EOF, got {eof:?}");
        }

        /// servfail on arbitrary query bytes must never panic.  Additionally:
        /// - The output always has the same length as the input.
        /// - When the input has >= 4 bytes (enough to have ID + partial flags),
        ///   byte [2] must have QR (bit 7) set.
        /// - When the input has >= 4 bytes, byte [3] must have RA (bit 7) set
        ///   and RCODE bits (low 4) equal to 2 (SERVFAIL).
        /// - The first 2 bytes (DNS ID) are always preserved verbatim.
        /// - When the input has >= 6 bytes (full header through QDCOUNT), the
        ///   QDCOUNT field (bytes 4..6) is preserved (servfail does not touch it).
        ///
        /// Can fail if servfail incorrectly modifies bytes it should not touch
        /// or fails to set the required flag bits.
        #[test]
        fn prop_servfail_robustness(query in proptest::collection::vec(any::<u8>(), 0..=512usize)) {
            let resp = servfail(&query);

            // Length preserved: servfail copies and modifies in place.
            prop_assert_eq!(resp.len(), query.len(), "length must be preserved");

            if query.len() >= 2 {
                // ID (bytes 0..2) must be preserved verbatim.
                prop_assert_eq!(&resp[..2], &query[..2], "ID (bytes 0..2) must be preserved");
            }

            if query.len() >= 4 {
                // QR bit (bit 7 of byte 2) must be set.
                prop_assert!(
                    resp[2] & 0x80 != 0,
                    "QR bit must be set in byte 2, got {:#04x}",
                    resp[2]
                );
                // RA bit (bit 7 of byte 3) must be set.
                prop_assert!(
                    resp[3] & 0x80 != 0,
                    "RA bit must be set in byte 3, got {:#04x}",
                    resp[3]
                );
                // RCODE (low 4 bits of byte 3) must be 2 (SERVFAIL).
                prop_assert_eq!(
                    resp[3] & 0x0f,
                    0x02,
                    "RCODE must be 2 (SERVFAIL), byte[3]={:#04x}",
                    resp[3]
                );
            }

            if query.len() >= 6 {
                // QDCOUNT (bytes 4..6) must be preserved — servfail keeps the
                // question section intact so the client can match responses.
                prop_assert_eq!(
                    &resp[4..6],
                    &query[4..6],
                    "QDCOUNT (bytes 4..6) must be preserved"
                );
            }
        }
    }
}
