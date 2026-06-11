//! izbad — the izba daemon. One daemon per data root; the CLI is a thin
//! client (`client::DaemonClient`), the server (`server`) wraps the same
//! sandbox lifecycle functions the daemonless CLI used to call directly.
//! Disk state remains the single source of truth: the daemon rebuilds its
//! world from sandbox dirs + pid identity at startup (adoption), so killing
//! it never harms sandboxes.

pub mod proto;
