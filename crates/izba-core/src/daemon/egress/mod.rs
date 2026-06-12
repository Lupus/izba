//! izbad-owned egress: the guest-initiated vsock 1027 plane. Module seams
//! (policy / dns / router / manager) are deliberately separable — M2 fills
//! policy, M4 fronts dns with member names, M5 branches MITM off the router.

pub mod policy;
