//! Re-export the pure naming/argv builders from [`izba_jail_naming`].
//!
//! All logic lives in the zero-dependency `izba-jail-naming` crate so that the
//! ELEVATED `izba-jail-helper` binary can consume it directly without pulling in
//! `izba-core`'s heavy dependency tree (hyper / TLS / OCI / hickory …).
pub use izba_jail_naming::*;
