//! Peer-credential authorization for the izbad control socket (F-09).
//!
//! Until this landed, the control socket's only gate was the 0700 daemon
//! directory — and on Windows not even that, since `transport::bind_socket`
//! chmods only under `cfg(unix)`. Any process that could open the socket
//! could Create/Start/Stop/Rm sandboxes, `GuestRpc`-exec inside a guest,
//! `OpenStream`-splice into one, publish ports, and shut the daemon down.
//! With the M5 credential vault attached that becomes a local escalation
//! into *spending the user's credentials*, which is why this closes first.
//!
//! The decision is a pure function over `(peer uid, owner uid)` so it is
//! fully unit-testable; reading the peer uid is a thin per-platform shim.

/// How strongly the daemon authenticated this connection's peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAuth {
    /// The kernel reported the peer's uid and it matched the daemon owner.
    Enforced,
    /// The platform exposes no peer-credential API for AF_UNIX (Windows, and
    /// any unix that is not Linux). Directory permissions are the only gate.
    /// Reported at startup — never treated as a successful authentication.
    Unavailable,
}

/// The accept-time verdict for one control connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerVerdict {
    Allow(PeerAuth),
    Deny { peer_uid: u32, owner_uid: u32 },
}

/// Decide whether a peer may drive the control plane.
///
/// `peer` is `None` where the platform cannot report it. That is NOT a
/// rejection — refusing every connection would make izbad unusable on
/// Windows — but it is also not an authentication, which is why it carries
/// [`PeerAuth::Unavailable`] rather than [`PeerAuth::Enforced`].
pub fn authorize_peer(peer: Option<u32>, owner: u32) -> PeerVerdict {
    match peer {
        Some(uid) if uid == owner => PeerVerdict::Allow(PeerAuth::Enforced),
        Some(uid) => PeerVerdict::Deny {
            peer_uid: uid,
            owner_uid: owner,
        },
        None => PeerVerdict::Allow(PeerAuth::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_uid_is_allowed_and_enforced() {
        assert_eq!(
            authorize_peer(Some(1000), 1000),
            PeerVerdict::Allow(PeerAuth::Enforced)
        );
    }

    #[test]
    fn different_uid_is_denied_and_reports_both_uids() {
        // The classic case: `sudo izba ...` reaching a user-owned daemon.
        assert_eq!(
            authorize_peer(Some(0), 1000),
            PeerVerdict::Deny {
                peer_uid: 0,
                owner_uid: 1000,
            }
        );
    }

    #[test]
    fn root_owner_still_rejects_a_non_root_peer() {
        // Direction matters both ways: a root-owned daemon must not accept a
        // normal user either.
        assert_eq!(
            authorize_peer(Some(1000), 0),
            PeerVerdict::Deny {
                peer_uid: 1000,
                owner_uid: 0,
            }
        );
    }

    #[test]
    fn unavailable_peer_credentials_allow_but_do_not_claim_enforcement() {
        assert_eq!(
            authorize_peer(None, 1000),
            PeerVerdict::Allow(PeerAuth::Unavailable)
        );
    }
}
