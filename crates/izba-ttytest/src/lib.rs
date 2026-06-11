//! Test-support harness for izba's interactive `exec -it` terminal path.
//!
//! - [`harness`] drives the real `izba` binary through a PTY/ConPTY and scrapes
//!   the screen with a vt100 parser.
//! - [`scripted_guest`] fakes a running sandbox over a Unix-domain socket so the
//!   host terminal layer can be tested with no VM.
//! - [`scenarios`] encodes the operator checklist as reusable scenarios.
//!
//! This crate is `publish = false`; it exists only for the test tiers in
//! `crates/izba-cli/tests/`.

pub mod harness;
pub mod scenarios;
pub mod scripted_guest;
