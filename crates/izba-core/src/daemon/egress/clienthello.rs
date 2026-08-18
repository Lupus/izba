// SPDX-License-Identifier: Apache-2.0
//! A total, bounded ClientHello SNI extractor for the pinning-passthrough
//! decision (M5 spec D3, §7.4).
//!
//! The bytes here are written by a hostile guest, so this module reads them
//! with `get(..)` only — no indexing, no slicing that can panic, no recursion,
//! and no allocation beyond one bounded hostname.
//!
//! It answers three things, and the difference between the last two is
//! load-bearing: `Found` (decide), `Incomplete` (the buffer holds a valid
//! prefix — the caller must peek again), and `None` (this is not a ClientHello
//! we will act on). The caller fails CLOSED to termination on both `Incomplete`
//! after its retry budget and `None`: a short read must never become a way to
//! escape inspection.

/// The longest hostname we will accept from an SNI extension (RFC 1035).
const MAX_SNI_LEN: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sni {
    /// A complete ClientHello carrying this (lowercased, dot-stripped) name.
    Found(String),
    /// A well-formed prefix: peek again for more bytes.
    Incomplete,
    /// Not a ClientHello, or a complete one with no usable `server_name`.
    None,
}

/// Extract the SNI from a peeked buffer.
pub fn peek_sni(buf: &[u8]) -> Sni {
    // TLSPlaintext: type(1) legacy_version(2) length(2) fragment
    let Some(header) = buf.get(..5) else {
        return Sni::Incomplete;
    };
    if header[0] != 0x16 {
        return Sni::None; // not a handshake record
    }
    let rec_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let Some(fragment) = buf.get(5..5 + rec_len) else {
        return Sni::Incomplete;
    };

    // Handshake: msg_type(1) length(3) body
    let Some(&msg_type) = fragment.first() else {
        return Sni::None;
    };
    if msg_type != 0x01 {
        return Sni::None; // not a ClientHello
    }
    let Some(len_bytes) = fragment.get(1..4) else {
        return Sni::None;
    };
    let hs_len =
        ((len_bytes[0] as usize) << 16) | ((len_bytes[1] as usize) << 8) | len_bytes[2] as usize;
    let Some(body) = fragment.get(4..4 + hs_len) else {
        // The record is complete but the handshake message is not: the
        // ClientHello is fragmented across records. We do not reassemble —
        // treat it as "more bytes wanted", which after the caller's retry
        // budget fails closed to termination.
        return Sni::Incomplete;
    };

    let mut c = Cursor { buf: body, at: 0 };
    if c.skip(2 + 32).is_none() {
        return Sni::None; // client_version + random
    }
    if c.skip_vec8().is_none() {
        return Sni::None; // legacy_session_id
    }
    if c.skip_vec16().is_none() {
        return Sni::None; // cipher_suites
    }
    if c.skip_vec8().is_none() {
        return Sni::None; // legacy_compression_methods
    }
    let Some(exts) = c.take_vec16() else {
        return Sni::None; // no extensions block at all ⇒ no SNI
    };

    let mut e = Cursor { buf: exts, at: 0 };
    while let Some(ext_type) = e.take_u16() {
        let Some(ext_body) = e.take_vec16() else {
            return Sni::None;
        };
        if ext_type != 0x0000 {
            continue;
        }
        // ServerNameList: list_length(2) then entries of type(1) length(2) name
        let mut l = Cursor {
            buf: ext_body,
            at: 0,
        };
        let Some(list) = l.take_vec16() else {
            return Sni::None;
        };
        let mut n = Cursor { buf: list, at: 0 };
        while let Some(name_type) = n.take_u8() {
            let Some(name) = n.take_vec16() else {
                return Sni::None;
            };
            if name_type != 0x00 {
                continue; // only host_name is defined
            }
            return match normalize_sni(name) {
                Some(s) => Sni::Found(s),
                None => Sni::None,
            };
        }
        return Sni::None;
    }
    Sni::None
}

/// Lowercase, strip one trailing dot, and refuse anything that is not a plain
/// ASCII hostname of a sane length. The result is compared against the
/// operator's allow-list, so a name we cannot canonicalize is refused outright.
fn normalize_sni(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_SNI_LEN {
        return None;
    }
    let s = std::str::from_utf8(raw).ok()?;
    if !s.is_ascii() {
        return None;
    }
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty()
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

/// A non-panicking forward reader over a byte slice.
struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn skip(&mut self, n: usize) -> Option<()> {
        self.at = self.at.checked_add(n)?;
        (self.at <= self.buf.len()).then_some(())
    }

    fn take_u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.at)?;
        self.at += 1;
        Some(v)
    }

    fn take_u16(&mut self) -> Option<u16> {
        let s = self.buf.get(self.at..self.at + 2)?;
        self.at += 2;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.buf.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    /// A `u8`-length-prefixed vector's body.
    fn take_vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.take_u8()? as usize;
        self.take(n)
    }

    /// A `u16`-length-prefixed vector's body.
    fn take_vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.take_u16()? as usize;
        self.take(n)
    }

    fn skip_vec8(&mut self) -> Option<()> {
        self.take_vec8().map(|_| ())
    }

    fn skip_vec16(&mut self) -> Option<()> {
        self.take_vec16().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid TLS 1.2+ ClientHello record whose
    /// only extension is `server_name` carrying `host` (or no extensions when
    /// `host` is `None`).
    fn client_hello(host: Option<&str>) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(h) = host {
            let mut sni = vec![0x00]; // NameType: host_name
            sni.extend_from_slice(&(h.len() as u16).to_be_bytes());
            sni.extend_from_slice(h.as_bytes());
            let mut list = (sni.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&sni);
            ext.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type server_name
            ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
            ext.extend_from_slice(&list);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0x00); // session_id length
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01); // compression_methods length
        body.push(0x00);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![0x01]; // HandshakeType: client_hello
        let n = body.len();
        hs.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01]; // handshake, legacy version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_the_sni_from_a_well_formed_client_hello() {
        let buf = client_hello(Some("pinned.vendor.com"));
        assert_eq!(peek_sni(&buf), Sni::Found("pinned.vendor.com".into()));
    }

    #[test]
    fn lowercases_and_strips_the_trailing_dot() {
        let buf = client_hello(Some("Pinned.Vendor.COM."));
        assert_eq!(peek_sni(&buf), Sni::Found("pinned.vendor.com".into()));
    }

    #[test]
    fn a_client_hello_without_server_name_is_none() {
        assert_eq!(peek_sni(&client_hello(None)), Sni::None);
    }

    // The load-bearing distinction: "not yet" must not read as "no".
    #[test]
    fn every_truncation_of_a_valid_hello_is_incomplete_never_none() {
        let full = client_hello(Some("pinned.vendor.com"));
        for cut in 1..full.len() {
            assert_eq!(
                peek_sni(&full[..cut]),
                Sni::Incomplete,
                "a {cut}-byte prefix must ask for more, not answer"
            );
        }
    }

    #[test]
    fn an_empty_buffer_is_incomplete() {
        assert_eq!(peek_sni(&[]), Sni::Incomplete);
    }

    #[test]
    fn a_non_handshake_record_is_none() {
        assert_eq!(
            peek_sni(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]),
            Sni::None
        );
    }

    #[test]
    fn a_handshake_that_is_not_a_client_hello_is_none() {
        let mut buf = client_hello(Some("h.example.com"));
        buf[5] = 0x02; // ServerHello
        assert_eq!(peek_sni(&buf), Sni::None);
    }

    #[test]
    fn a_non_ascii_or_oversized_name_is_refused() {
        let long = "a".repeat(300);
        assert_eq!(peek_sni(&client_hello(Some(&long))), Sni::None);
        let mut buf = client_hello(Some("ok.example.com"));
        let pos = buf.len() - 3;
        buf[pos] = 0xff; // not ASCII
        assert_eq!(peek_sni(&buf), Sni::None);
    }

    // Totality: no input may panic.
    #[test]
    fn arbitrary_truncations_and_mutations_never_panic() {
        let full = client_hello(Some("pinned.vendor.com"));
        for i in 0..full.len() {
            for b in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut m = full.clone();
                m[i] = b;
                let _ = peek_sni(&m);
                let _ = peek_sni(&m[..i]);
            }
        }
    }
}
