// SSH constants for the guest side of izba-ssh delivery.
//
// The izba-ssh virtiofs share delivers the SSH host key and
// authorized_keys into the guest. izba-init mounts it read-only
// at /rootfs/izba-ssh; a later task copies the files into the
// sshd runtime dir.

/// virtiofs tag of the read-only SSH share izbad attaches per-sandbox.
pub const SSH_TAG: &str = "izba-ssh";

/// Guest mountpoint of the SSH share inside /rootfs.
/// Used by the sshd-launch task to locate the injected keys.
#[allow(dead_code)]
pub const SSH_MOUNT: &str = "/izba-ssh";
