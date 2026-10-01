//! Measurement tool for spike #249: time the phases of izbad's container-state
//! probe against a running sandbox and show the raw value the guest returned.
//!
//! `izba status` renders `container: unknown` for two different outcomes of
//! `probe_container_state` (`crates/izba-core/src/daemon/server.rs`): the probe
//! returning `None` (it failed, or ran out of its 5 s bound), and the guest
//! answering `Some(ContainerState::Unknown)` (its own `crun state` failed).
//! Nothing in the product tells them apart or says how long each phase took.
//! This crate does both, talking to the guest directly — no daemon involved.
//!
//! Everything except [`run`] is pure or driven through a socketpair, so it is
//! unit-tested without a VM.

pub mod args;
pub mod classify;
pub mod measure;
pub mod run;
pub mod stats;
pub mod summary;
