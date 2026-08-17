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

use crate::vmm::UdsStream;

/// Read the connected peer's uid.
///
/// `Ok(None)` means "this platform has no peer-credential API", which is a
/// permanent property of the platform, not a transient failure:
/// Windows AF_UNIX exposes no `SO_PEERCRED` equivalent, and only Linux is a
/// supported izba host among the unices. An `Err` is a real syscall failure
/// on a platform that *does* support it, and is treated as a denial by
/// [`authorize_stream`].
#[cfg(target_os = "linux")]
pub fn peer_uid(stream: &UdsStream) -> std::io::Result<Option<u32>> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let cred = getsockopt(stream, PeerCredentials)
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    Ok(Some(cred.uid()))
}

/// Non-Linux unix: no supported peer-credential path (izba hosts are Linux
/// and Windows). Reported as unavailable rather than guessed.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn peer_uid(_stream: &UdsStream) -> std::io::Result<Option<u32>> {
    Ok(None)
}

/// Windows AF_UNIX has no peer-credential API. The control socket's gate
/// there is the containing directory's ACL.
#[cfg(windows)]
pub fn peer_uid(_stream: &UdsStream) -> std::io::Result<Option<u32>> {
    Ok(None)
}

/// The uid izbad runs as — the only uid permitted to drive the control
/// plane. `None` on platforms with no uid concept.
#[cfg(unix)]
pub fn owner_uid() -> Option<u32> {
    Some(nix::unistd::geteuid().as_raw())
}

#[cfg(windows)]
pub fn owner_uid() -> Option<u32> {
    None
}

/// Accept-time gate for one control connection.
///
/// A syscall failure on a platform that supports peer credentials is a
/// DENIAL, not an "unavailable" — otherwise an induced failure would be a
/// bypass. `owner_uid() == None` (Windows) short-circuits to
/// [`PeerAuth::Unavailable`] without consulting the socket.
pub fn authorize_stream(stream: &UdsStream) -> PeerVerdict {
    let Some(owner) = owner_uid() else {
        return PeerVerdict::Allow(PeerAuth::Unavailable);
    };
    match peer_uid(stream) {
        Ok(peer) => authorize_peer(peer, owner),
        Err(_) => PeerVerdict::Deny {
            peer_uid: u32::MAX,
            owner_uid: owner,
        },
    }
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

    /// A socketpair carries real peer credentials on Linux and both ends
    /// belong to this test process — so this exercises the true kernel path
    /// WITHOUT binding a listener (house constraint: unit tests never bind).
    #[cfg(target_os = "linux")]
    #[test]
    fn peer_uid_of_a_socketpair_is_our_own_euid() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let got = peer_uid(&a).expect("SO_PEERCRED on a socketpair must succeed");
        assert_eq!(
            got,
            Some(nix::unistd::geteuid().as_raw()),
            "socketpair peer uid must be this process's euid"
        );
    }

    /// End-to-end on the real syscall path: our own socketpair peer is us,
    /// so the verdict must be Allow(Enforced) — not Allow(Unavailable),
    /// which would mean the platform shim silently returned None.
    #[cfg(target_os = "linux")]
    #[test]
    fn authorize_stream_allows_our_own_socketpair_with_enforcement() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(authorize_stream(&a), PeerVerdict::Allow(PeerAuth::Enforced));
    }

    #[cfg(unix)]
    #[test]
    fn owner_uid_is_reported_on_unix() {
        assert_eq!(owner_uid(), Some(nix::unistd::geteuid().as_raw()));
    }
}
