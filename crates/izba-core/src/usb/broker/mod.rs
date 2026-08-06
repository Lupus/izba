//! The guest-facing USB plane (vsock 1028).
//!
//! izbad binds one listener per sandbox, **only** while that sandbox holds at
//! least one device grant. With USB off there is nothing for a guest to dial —
//! not a listener that would refuse, but no socket at all. That is the phase-2
//! "disabled USB adds no attack surface" promise kept structurally rather than
//! argued.

pub mod session;
