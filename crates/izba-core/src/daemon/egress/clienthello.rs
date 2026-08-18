// SPDX-License-Identifier: Apache-2.0
//! A total, bounded ClientHello SNI extractor for the pinning-passthrough
//! decision (M5 spec D3, §7.4).
//!
//! The bytes here are written by a hostile guest, so this module reads them
//! through `get(..)`; the few direct indexes that remain are on slices whose
//! length a preceding `get(..)` already fixed, so none of them can panic.
//! No slicing that can panic beyond that, no recursion, and no allocation
//! beyond one bounded hostname.
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
    // A big-endian u24. Decoded through `u32::from_be_bytes` with a leading
    // zero rather than hand-rolled shifts and ors: the hand-rolled form spells
    // out an arithmetic identity that a mutation cannot always change
    // observably (the three shifted bytes occupy disjoint bit ranges, so `|`
    // and `^` are indistinguishable there), which leaves un-killable mutants
    // sitting on a length field that guest bytes control. This form has no
    // arithmetic to mutate.
    let hs_len = u32::from_be_bytes([0, len_bytes[0], len_bytes[1], len_bytes[2]]) as usize;
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

/// Lowercase, strip trailing dots, and refuse anything that is not a plain
/// ASCII hostname of a sane length. The result is compared against the
/// operator's allow-list, so a name we cannot canonicalize is refused outright.
/// Trailing-dot stripping matches `config::normalize_policy_host` and
/// `dns_snoop::normalize` (`trim_end_matches('.')`, not just one dot) — all
/// three must strip the same way, or a name that differs only in that
/// identity would silently fail to match across the hatch/allow-list/snoop
/// boundary.
fn normalize_sni(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_SNI_LEN {
        return None;
    }
    let s = std::str::from_utf8(raw).ok()?;
    // Redundant-on-purpose: the `[a-z0-9-.]` whitelist below already rejects
    // every non-ASCII character, so this can never be the deciding check.
    // Kept explicit anyway so the ASCII assumption is visible at the point
    // it matters, rather than an emergent property of the whitelist that a
    // future edit to the whitelist could silently drop.
    if !s.is_ascii() {
        return None;
    }
    let s = s.trim_end_matches('.');
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
        // Validate BEFORE advancing: on a bounds failure the cursor must be
        // left exactly where it was, never past the end of the buffer — a
        // corrupted cursor handed to a later `take_*` call would be a
        // landmine for a future caller that skips an attacker-supplied `n`.
        let end = self.at.checked_add(n)?;
        (end <= self.buf.len()).then(|| self.at = end)
    }

    fn take_u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.at)?;
        self.at += 1;
        Some(v)
    }

    fn take_u16(&mut self) -> Option<u16> {
        let end = self.at.checked_add(2)?;
        let s = self.buf.get(self.at..end)?;
        self.at = end;
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
        client_hello_padded(host, 0)
    }

    /// As [`client_hello`], plus a trailing filler extension of `pad` bytes so
    /// the handshake body can be pushed past a single length byte. The filler
    /// uses an unassigned extension type, which the walk must skip.
    fn client_hello_padded(host: Option<&str>, pad: usize) -> Vec<u8> {
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
        if pad > 0 {
            ext.extend_from_slice(&0x5a5au16.to_be_bytes()); // unassigned ext type
            ext.extend_from_slice(&(pad as u16).to_be_bytes());
            ext.extend(std::iter::repeat_n(0x00u8, pad));
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

    /// Build a ClientHello whose `server_name` extension carries an explicit
    /// list of `(NameType, name)` entries, in order — for exercising the
    /// `name_type` filter and multi-entry lists directly, independent of
    /// `client_hello`'s single-`host_name` shortcut.
    fn client_hello_with_names(entries: &[(u8, &str)]) -> Vec<u8> {
        let mut list = Vec::new();
        for (name_type, name) in entries {
            list.push(*name_type);
            list.extend_from_slice(&(name.len() as u16).to_be_bytes());
            list.extend_from_slice(name.as_bytes());
        }
        let mut list_with_len = (list.len() as u16).to_be_bytes().to_vec();
        list_with_len.extend_from_slice(&list);
        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type server_name
        ext.extend_from_slice(&(list_with_len.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list_with_len);

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

    /// A ClientHello whose handshake message is genuinely fragmented across
    /// two TLS records — not merely a truncated buffer. The first record's
    /// handshake header still declares the FULL body length, but the record
    /// itself carries only a prefix of that body; `peek_sni` must not
    /// reassemble across records, and must fail closed to `Incomplete`
    /// (never `None`) — the M5 spec (§7.4) singles this branch out as the one
    /// place an obvious implementation could pick the wrong direction.
    #[test]
    fn a_client_hello_split_across_two_records_is_incomplete_not_none() {
        let full = client_hello(Some("pinned.vendor.com"));
        // `full` is exactly one TLS record whose payload IS the handshake
        // message (msg_type(1) + length(3) + body): the record header (5
        // bytes) precedes it 1:1, so `hs` below is the raw handshake bytes.
        let hs = &full[5..];
        let split = 10;
        assert!(
            split > 4 && split < hs.len(),
            "split must leave a genuine partial body inside record 1"
        );

        let mut buf = Vec::new();
        // Record 1: only the first `split` bytes of the handshake message —
        // its own length header still claims the full body.
        buf.extend_from_slice(&[0x16, 0x03, 0x01]);
        buf.extend_from_slice(&(split as u16).to_be_bytes());
        buf.extend_from_slice(&hs[..split]);
        // Record 2: the rest, framed as a second genuine TLS record.
        let rest = &hs[split..];
        buf.extend_from_slice(&[0x16, 0x03, 0x01]);
        buf.extend_from_slice(&(rest.len() as u16).to_be_bytes());
        buf.extend_from_slice(rest);

        assert_eq!(peek_sni(&buf), Sni::Incomplete);
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

    /// The length bound is `> MAX_SNI_LEN`, so a name of EXACTLY 253 bytes —
    /// the longest legal hostname — must still be accepted. Pins the boundary
    /// in both directions: an off-by-one to `>=` would silently refuse the
    /// longest names a real client can present, and refusing is invisible
    /// (it just means that host can never take the hatch).
    #[test]
    fn a_name_of_exactly_the_maximum_length_is_accepted() {
        let suffix = ".example.com";
        let at_limit = format!("{}{suffix}", "a".repeat(MAX_SNI_LEN - suffix.len()));
        assert_eq!(at_limit.len(), MAX_SNI_LEN);
        assert_eq!(
            peek_sni(&client_hello(Some(&at_limit))),
            Sni::Found(at_limit.clone())
        );

        let over_limit = format!("a{at_limit}");
        assert_eq!(over_limit.len(), MAX_SNI_LEN + 1);
        assert_eq!(peek_sni(&client_hello(Some(&over_limit))), Sni::None);
    }

    /// An ASCII character outside the hostname whitelist is refused. The
    /// pre-existing coverage only used a non-ASCII byte, which the `is_ascii`
    /// check rejects first — so the whitelist itself was never exercised, and
    /// inverting any of its comparisons went unnoticed. Underscore is the
    /// realistic case: legal in DNS, not in a hostname izba can match against
    /// an allow-list entry.
    #[test]
    fn an_ascii_character_outside_the_hostname_whitelist_is_refused() {
        for bad in [
            "under_score.example.com",
            "sla/sh.example.com",
            "co:lon.example.com",
        ] {
            assert_eq!(
                peek_sni(&client_hello(Some(bad))),
                Sni::None,
                "{bad} is not a hostname the allow-list can express"
            );
        }
        // The characters the whitelist DOES admit — hyphen and dot included —
        // so the test above cannot pass by refusing everything.
        assert_eq!(
            peek_sni(&client_hello(Some("a-b.c9.example.com"))),
            Sni::Found("a-b.c9.example.com".into())
        );
    }

    /// A handshake body longer than 255 bytes puts a non-zero value in the
    /// MIDDLE byte of the u24 length, which is the only way to exercise the
    /// multi-byte decode — every other test's hello is short enough that the
    /// two high bytes are zero and any decode would agree.
    #[test]
    fn a_handshake_longer_than_one_length_byte_decodes_correctly() {
        let host = "long.example.com";
        let padded = client_hello_padded(Some(host), 400);
        assert_eq!(padded[6], 0, "high length byte");
        assert_ne!(padded[7], 0, "middle length byte must be exercised");
        assert_eq!(peek_sni(&padded), Sni::Found(host.into()));
    }

    /// A `ServerNameList` entry whose `NameType` is not `host_name` (`0x00`)
    /// is not a name a real TLS server would ever see as SNI — the filter at
    /// `:103` must skip it rather than treat its payload as a hostname. This
    /// is the false-`Found` bypass guard: without it, an attacker-chosen
    /// undefined-NameType entry could smuggle a pinned host's name past the
    /// parser and win an unterminated splice for a name no server honours.
    #[test]
    fn a_non_host_name_type_entry_is_not_an_sni() {
        let buf = client_hello_with_names(&[(0x01, "pinned.vendor.com")]);
        assert_eq!(peek_sni(&buf), Sni::None);
    }

    /// A decoy non-`host_name` entry ahead of the real one: the filter must
    /// skip past it rather than abort the whole list, and the genuine
    /// `host_name` entry must still be found.
    #[test]
    fn a_non_host_name_type_entry_is_skipped_not_aborting() {
        let buf =
            client_hello_with_names(&[(0x01, "decoy.example.com"), (0x00, "real.example.com")]);
        assert_eq!(peek_sni(&buf), Sni::Found("real.example.com".into()));
    }

    /// An SNI of exactly `"."` strips to the empty string and must be
    /// refused, not accepted as an empty hostname.
    #[test]
    fn a_bare_dot_sni_is_refused() {
        assert_eq!(peek_sni(&client_hello(Some("."))), Sni::None);
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
