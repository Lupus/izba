//! izba-init library: modules exposed for testing and the cargo-fuzz crate.
//!
//! The binary (PID 1) consumes these modules directly; the fuzz harness and
//! property tests link against this lib target so they share the same compiled
//! code without duplicating compilation.
pub mod tarfs;
/// Guest-side USB attach. Exposed so its parsing and handshake are
/// host-testable; the sysfs writes only run inside a guest.
pub mod usb;
