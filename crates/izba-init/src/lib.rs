//! izba-init library: modules exposed for testing and the cargo-fuzz crate.
//!
//! The binary (PID 1) consumes these modules directly; the fuzz harness and
//! property tests link against this lib target so they share the same compiled
//! code without duplicating compilation.
pub mod tarfs;
