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
    Deny {
        /// The connecting peer's uid, or `u32::MAX` as a sentinel meaning
        /// "the peer-credential syscall itself failed" — it can never equal
        /// a real uid, so a log/audit consumer must not print it as one; see
        /// [`verdict_for_peer_result`].
        peer_uid: u32,
        owner_uid: u32,
    },
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
#[mutants::skip] // reason: compiled on no CI platform (CI is Linux + Windows only), so no test on either shard can ever exercise or kill a mutant here. Kept as its own cfg arm (not merged with the Windows stub below) because the two carry different rationale and merging would silently widen the cfg to future targets.
pub fn peer_uid(_stream: &UdsStream) -> std::io::Result<Option<u32>> {
    Ok(None)
}

/// Windows AF_UNIX has no peer-credential API. The control socket's gate
/// there is the containing directory's ACL.
#[cfg(windows)]
#[mutants::skip] // reason: compiles on Windows CI, but killing a mutant here needs a live UdsStream to call it with, and uds_windows::UnixStream has no pair() — constructing one requires binding a listener, which this project's unit tests forbid. owner_uid()/enforcement_mode() Windows behaviour is covered directly below instead.
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

/// The enforcement this platform can actually achieve — the SINGLE source of
/// truth for both the startup report (`server.rs`) and the accept-time
/// verdict ([`authorize_stream`]). Before this existed, the two derived
/// availability from different predicates (`owner_uid().is_some()` vs the
/// real `#[cfg(target_os = "linux")]` gate on [`peer_uid`]), so a non-Linux
/// unix host — an arm this module deliberately defines — would print
/// "enforced" while every connection actually resolved to `Unavailable`.
/// Both call sites must go through this function so they cannot disagree.
pub fn enforcement_mode() -> PeerAuth {
    enforcement_mode_for(cfg!(target_os = "linux"), owner_uid())
}

/// Pure core of [`enforcement_mode`], with the platform predicate injected so
/// every (platform, owner) combination is testable — including the non-Linux
/// unix case, which no CI platform can exercise natively and which is exactly
/// where a `&&`/`||` slip would falsely claim enforcement.
fn enforcement_mode_for(is_linux: bool, owner: Option<u32>) -> PeerAuth {
    if is_linux && owner.is_some() {
        PeerAuth::Enforced
    } else {
        PeerAuth::Unavailable
    }
}

/// Map a [`peer_uid`] outcome to a verdict. Pure and platform-independent,
/// so the syscall-failure path is directly unit-testable without depending
/// on any real kernel error behaviour.
///
/// A syscall failure on a platform that supports peer credentials is a
/// DENIAL, not an "unavailable" — otherwise an induced failure would be a
/// bypass. `peer_uid: u32::MAX` on that arm is deliberate: it can never
/// equal a real uid, so it can never accidentally match `owner`.
fn verdict_for_peer_result(peer: std::io::Result<Option<u32>>, owner: u32) -> PeerVerdict {
    match peer {
        Ok(peer) => authorize_peer(peer, owner),
        Err(_) => PeerVerdict::Deny {
            peer_uid: u32::MAX,
            owner_uid: owner,
        },
    }
}

/// Accept-time gate for one control connection.
///
/// Gated on [`enforcement_mode`] — the same predicate the startup report
/// uses — so an "Unavailable" platform short-circuits to
/// [`PeerAuth::Unavailable`] without consulting the socket, and an "Enforced"
/// platform always has `owner_uid()` available (the `expect` below can never
/// fire: `enforcement_mode()` only returns `Enforced` when `owner_uid()` is
/// `Some`).
pub fn authorize_stream(stream: &UdsStream) -> PeerVerdict {
    if enforcement_mode() == PeerAuth::Unavailable {
        return PeerVerdict::Allow(PeerAuth::Unavailable);
    }
    let owner = owner_uid().expect("enforcement_mode() == Enforced implies owner_uid().is_some()");
    verdict_for_peer_result(peer_uid(stream), owner)
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

    #[test]
    fn verdict_for_peer_result_allows_matching_uid_with_enforcement() {
        assert_eq!(
            verdict_for_peer_result(Ok(Some(1000)), 1000),
            PeerVerdict::Allow(PeerAuth::Enforced)
        );
    }

    #[test]
    fn verdict_for_peer_result_reports_unavailable_when_platform_cannot_tell() {
        assert_eq!(
            verdict_for_peer_result(Ok(None), 1000),
            PeerVerdict::Allow(PeerAuth::Unavailable)
        );
    }

    /// The safety-critical arm: a syscall failure must be a DENIAL, never an
    /// "unavailable" — an induced failure (e.g. an attacker triggering an
    /// error on the accept path) must not become a bypass. This is the one
    /// property the whole shim exists to guarantee, so it gets a direct,
    /// kernel-independent test rather than resting on unverified `errno`
    /// behaviour from a contrived socket state.
    #[test]
    fn verdict_for_peer_result_denies_on_syscall_failure_with_sentinel_uid() {
        let err = std::io::Error::from(std::io::ErrorKind::NotConnected);
        assert_eq!(
            verdict_for_peer_result(Err(err), 1000),
            PeerVerdict::Deny {
                peer_uid: u32::MAX,
                owner_uid: 1000,
            }
        );
    }

    /// IMPORTANT 1's guard: `enforcement_mode()` — what the startup report
    /// prints — must agree with what `authorize_stream` can ACTUALLY produce
    /// on this platform, for a peer that is legitimately us (a `UdsStream`
    /// pair, never a bound listener). If a future edit reintroduces two
    /// separate availability predicates, this fails on whichever platform
    /// they disagree on.
    #[test]
    fn enforcement_mode_agrees_with_authorize_stream_on_our_own_pair() {
        let (a, _b) = UdsStream::pair().expect("UdsStream::pair() must succeed");
        let verdict = authorize_stream(&a);
        match enforcement_mode() {
            PeerAuth::Enforced => assert_eq!(
                verdict,
                PeerVerdict::Allow(PeerAuth::Enforced),
                "enforcement_mode() claims Enforced but authorize_stream() disagreed: {verdict:?}"
            ),
            PeerAuth::Unavailable => assert_eq!(
                verdict,
                PeerVerdict::Allow(PeerAuth::Unavailable),
                "enforcement_mode() claims Unavailable but authorize_stream() disagreed: {verdict:?}"
            ),
        }
    }

    // enforcement_mode_for covers all four (is_linux, owner) combinations
    // directly, including the non-Linux-unix case that no CI platform can
    // produce natively (CI is Linux + Windows only) — that is exactly the
    // combination a `&&`/`||` slip in the real predicate would get wrong.

    #[test]
    fn enforcement_mode_for_linux_with_owner_is_enforced() {
        assert_eq!(enforcement_mode_for(true, Some(1000)), PeerAuth::Enforced);
    }

    /// The mutant-killing case: simulates a non-Linux unix (no `SO_PEERCRED`
    /// path, `is_linux = false`) that nonetheless has a uid concept
    /// (`owner = Some`, e.g. macOS/BSD's `geteuid()`). Such a platform must
    /// NEVER report `Enforced` merely because it has a uid — enforcement
    /// requires BOTH the Linux syscall path and a uid. `&&` gives
    /// `Unavailable` here; the mutant's `||` would flip this to `Enforced`,
    /// falsely claiming a peer-credential guarantee the platform cannot back.
    #[test]
    fn enforcement_mode_for_non_linux_unix_with_owner_is_unavailable_not_enforced() {
        assert_eq!(
            enforcement_mode_for(false, Some(1000)),
            PeerAuth::Unavailable
        );
    }

    #[test]
    fn enforcement_mode_for_linux_without_owner_is_unavailable() {
        assert_eq!(enforcement_mode_for(true, None), PeerAuth::Unavailable);
    }

    #[test]
    fn enforcement_mode_for_non_linux_without_owner_is_unavailable() {
        assert_eq!(enforcement_mode_for(false, None), PeerAuth::Unavailable);
    }

    /// Windows has no uid concept at all: `owner_uid()` must report `None`,
    /// which is the fact the whole "Windows residual" (directory-ACL-only
    /// gating) rests on.
    #[cfg(windows)]
    #[test]
    fn owner_uid_is_none_on_windows() {
        assert_eq!(owner_uid(), None);
    }

    /// End-to-end on the real Windows platform predicate: with no uid
    /// concept, `enforcement_mode()` must resolve to `Unavailable`, never
    /// `Enforced` — pinning the same contract `owner_uid_is_none_on_windows`
    /// checks, but through the actual public entry point.
    #[cfg(windows)]
    #[test]
    fn enforcement_mode_is_unavailable_on_windows() {
        assert_eq!(enforcement_mode(), PeerAuth::Unavailable);
    }
}
