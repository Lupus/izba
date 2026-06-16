//! Terminating system DNS resolver with live config reload. Replaces the
//! start-time-captured `UdpForwarder`: re-reads host DNS config and self-heals
//! on network change (VPN reconnect) via lazy-on-failure + poll + if-watch.

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Record, RecordType};

/// The query types the guest is allowed to resolve. Terminating resolution
/// gives us this control point; v1 hardcodes a sane set.
// TODO(policy): make per-sandbox DNS caps policy-driven (M-future).
pub(crate) struct DnsCaps {
    allowed: &'static [RecordType],
}

impl DnsCaps {
    pub(crate) const fn v1() -> Self {
        Self {
            allowed: &[
                RecordType::A,
                RecordType::AAAA,
                RecordType::CNAME,
                RecordType::MX,
                RecordType::TXT,
                RecordType::SRV,
                RecordType::PTR,
                RecordType::NS,
                RecordType::SOA,
                RecordType::CAA,
            ],
        }
    }

    pub(crate) fn permits(&self, qtype: RecordType) -> bool {
        self.allowed.contains(&qtype)
    }
}

/// Build a response that echoes the request's id + question with the given
/// rcode and no answers (NOTIMP / NXDOMAIN / NODATA).
fn response_with_rcode(req: &Message, rcode: ResponseCode) -> anyhow::Result<Vec<u8>> {
    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
    for q in &req.queries {
        resp.add_query(q.clone());
    }
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = rcode;
    Ok(resp.to_vec()?)
}

/// Build a NOERROR response echoing the question and carrying `records` as the
/// answer section. Records come straight from hickory's `Lookup`, so no
/// per-RData destructuring is needed.
fn response_with_answers(req: &Message, records: &[Record]) -> anyhow::Result<Vec<u8>> {
    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
    for q in &req.queries {
        resp.add_query(q.clone());
    }
    for r in records {
        resp.add_answer(r.clone());
    }
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;
    Ok(resp.to_vec()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    fn sample_query(id: u16, qtype: RecordType) -> Message {
        let mut m = Message::new(id, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.set_name(Name::from_str("example.com.").unwrap());
        q.set_query_type(qtype);
        m.add_query(q);
        m
    }

    #[test]
    fn v1_caps_permit_common_types_and_reject_dangerous_ones() {
        let caps = DnsCaps::v1();
        assert!(caps.permits(RecordType::A));
        assert!(caps.permits(RecordType::AAAA));
        assert!(caps.permits(RecordType::SRV));
        assert!(!caps.permits(RecordType::ANY));
        assert!(!caps.permits(RecordType::AXFR));
    }

    #[test]
    fn rcode_response_echoes_id_and_question() {
        let req = sample_query(0x1234, RecordType::A);
        let bytes = response_with_rcode(&req, ResponseCode::NotImp).unwrap();
        let resp = Message::from_vec(&bytes).unwrap();
        assert_eq!(resp.id, 0x1234);
        assert_eq!(resp.message_type, MessageType::Response);
        assert_eq!(resp.response_code, ResponseCode::NotImp);
        assert_eq!(resp.queries.len(), 1);
        assert_eq!(resp.queries[0].query_type(), RecordType::A);
        assert!(resp.answers.is_empty());
    }
}
