//! Docker-mode veth datapath (spec §3): wire the workload container's own
//! netns to init's with a veth pair carrying the SAME addresses the shared
//! netns used (RESOLVER_IP init-side as the gateway, GUEST_IP container-
//! side), so the workload-visible network contract is unchanged while the
//! nft interception point moves structurally out of the workload's reach.
//!
//! **Command-form decision (verified against the real vendored binary):**
//! iproute2's `-n`/`--netns` global option does NOT accept an arbitrary
//! `/proc/<pid>/ns/net` path — it always resolves its argument as a NAME
//! under `/var/run/netns/` (iproute2's `ip netns` option handling; exact
//! source file not pinned here — verified by binary behavior, not by reading
//! iproute2's source). Confirmed by running the actual vendored `dist/ip`
//! (iproute2 6.12.0) unsandboxed: `ip -n /proc/self/ns/net link show lo`
//! fails with `Cannot open network namespace "/proc/self/ns/net": No such
//! file or directory` even though the path itself exists — the binary is not
//! treating it as a path at all. `ip netns attach <name> <pid>` IS present in
//! this build (`ip netns help` lists it) and is the supported way to give a
//! live process's netns a name iproute2 will accept via `-n`; it failed only
//! on `mkdir /var/run/netns: Permission denied` when tried unprivileged here
//! (this dev host already had `/var/run`, so the failure was pure
//! permissions) — that mkdir call is what `apply` now covers up front for the
//! guest, whose initramfs has no `/var` at all (see `apply`'s doc). So
//! `commands` emits: create the pair, push the container end into the
//! container's netns by PID directly (`ip link set … netns <pid>`, which —
//! unlike the `-n` option — DOES accept a bare pid), attach a named handle to
//! that pid's netns, then address/route the container side via
//! `-n <NETNS_NAME>`. Task 7 e2e should confirm the full sequence end-to-end
//! as root in a real guest — including that `apply`'s `create_dir_all` +
//! `netns attach` actually succeeds against the initramfs's real (missing)
//! `/var/run/netns`, not just this dev host's pre-existing one.

pub const IP_PATH: &str = "/sbin/ip";
pub const VETH_INIT: &str = "veth0";
pub const VETH_CTR: &str = "veth1";
/// Name `ip netns attach` registers for the container's netns so subsequent
/// commands can select it via `-n NETNS_NAME` (iproute2 requires a
/// `/var/run/netns/<name>` handle, not a `/proc/<pid>/ns/net` path — see the
/// module doc).
pub const NETNS_NAME: &str = "izba";

/// The full /sbin/ip invocation plan. Pure — unit-tested; `apply` executes it.
///
/// `ip link set <dev> netns <pid>` accepts a bare pid directly (a distinct
/// iproute2 feature from the `-n`/`--netns` global option, which does not);
/// entering the container's netns for the remaining container-side commands
/// goes through `ip netns attach NETNS_NAME <pid>` + `-n NETNS_NAME` (see the
/// module doc for why the naive `-n /proc/<pid>/ns/net` form doesn't work).
pub fn commands(container_pid: u32) -> Vec<Vec<String>> {
    let pid = container_pid.to_string();
    let resolver_cidr = format!("{}/24", crate::net::RESOLVER_IP);
    let guest_cidr = format!("{}/24", crate::net::GUEST_IP);
    let gateway = crate::net::RESOLVER_IP.to_string();

    fn v(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }
    fn ns(parts: &[&str]) -> Vec<String> {
        let mut c = vec![
            IP_PATH.to_string(),
            "-n".to_string(),
            NETNS_NAME.to_string(),
        ];
        c.extend(parts.iter().map(|s| s.to_string()));
        c
    }

    vec![
        v(&[
            IP_PATH, "link", "add", VETH_INIT, "type", "veth", "peer", "name", VETH_CTR,
        ]),
        v(&[IP_PATH, "link", "set", VETH_CTR, "netns", &pid]),
        v(&[IP_PATH, "addr", "add", &resolver_cidr, "dev", VETH_INIT]),
        v(&[IP_PATH, "link", "set", VETH_INIT, "up"]),
        v(&[IP_PATH, "netns", "attach", NETNS_NAME, &pid]),
        ns(&["link", "set", "lo", "up"]),
        ns(&["addr", "add", &guest_cidr, "dev", VETH_CTR]),
        ns(&["link", "set", VETH_CTR, "up"]),
        ns(&["route", "add", "default", "via", &gateway]),
    ]
}

/// Execute [`commands`] via the vendored static ip. Fail-honest: the first
/// failing command aborts with an error naming it; the caller logs loudly
/// and leaves the sandbox alive/diagnosable (spec §3 failure honesty).
// reason: shells out to /sbin/ip against live netns state — guest-only; the
// command plan is unit-tested via `commands`.
#[mutants::skip]
pub fn apply(container_pid: u32) -> std::io::Result<()> {
    // `ip netns attach` registers the named handle by bind-mounting it at
    // /var/run/netns/<name>, and only mkdirs that FINAL component (not
    // recursively) — so it silently assumes /var/run already exists. izba's
    // initramfs ships no /var at all (see hack/build-initramfs.sh's
    // skeleton), so without this the guest's first `netns attach` would fail
    // ENOENT on the missing parent. create_dir_all (mkdir -p) makes /var and
    // /var/run too, so this is correct regardless of what the initramfs
    // happens to pre-create.
    std::fs::create_dir_all("/var/run/netns")?;
    for c in commands(container_pid) {
        let status = std::process::Command::new(&c[0]).args(&c[1..]).status()?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "veth setup command failed (exit {status}): {}",
                c.join(" ")
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_wire_both_netns_with_the_canonical_addresses() {
        let cmds = commands(423);
        let flat: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        // Pair created init-side, one end pushed into the container netns by PID.
        assert!(flat
            .iter()
            .any(|c| c.contains("link add") && c.contains("type veth")));
        assert!(flat.iter().any(|c| c.contains("netns 423")));
        // Init side gets RESOLVER_IP, container side GUEST_IP with default route back.
        assert!(flat
            .iter()
            .any(|c| c.contains(&format!("{}/24", crate::net::RESOLVER_IP))));
        assert!(flat
            .iter()
            .any(|c| c.contains(&format!("{}/24", crate::net::GUEST_IP))));
        assert!(flat.iter().any(|c| c.contains("route add default via")
            && c.contains(&crate::net::RESOLVER_IP.to_string())));
        // Every command is a /sbin/ip invocation (single vendored binary).
        assert!(cmds.iter().all(|c| c[0] == IP_PATH));
        // Container-netns commands go through a named `ip netns attach` handle
        // (the verified real-binary form — see the module doc), not a raw
        // /proc/<pid>/ns/net path, which the vendored ip rejects.
        assert!(flat
            .iter()
            .any(|c| c.contains("netns attach") && c.contains("izba") && c.contains("423")));
        assert!(flat.iter().any(|c| c.contains("-n izba")));
    }

    #[test]
    fn commands_bring_up_loopback_inside_container_netns() {
        let flat: Vec<String> = commands(7).iter().map(|c| c.join(" ")).collect();
        assert!(flat
            .iter()
            .any(|c| c.contains("-n izba") && c.contains("lo") && c.contains("up")));
    }

    #[test]
    fn commands_attach_precedes_any_dash_n_usage() {
        // `ip netns attach izba <pid>` must run before any `-n izba ...`
        // command, or the named handle won't exist yet.
        let cmds = commands(99);
        let flat: Vec<String> = cmds.iter().map(|c| c.join(" ")).collect();
        let attach_pos = flat
            .iter()
            .position(|c| c.starts_with(&format!("{IP_PATH} netns attach {NETNS_NAME}")))
            .expect("netns attach command present");
        for (i, c) in flat.iter().enumerate() {
            if c.contains("-n izba") {
                assert!(
                    i > attach_pos,
                    "`-n izba` command at {i} precedes attach at {attach_pos}: {c}"
                );
            }
        }
    }

    #[test]
    fn commands_move_veth_ctr_into_container_netns_before_addressing_it() {
        // `ip link set veth1 netns <pid>` must precede any command that
        // configures veth1 from within the container netns.
        let cmds = commands(55);
        let move_pos = cmds
            .iter()
            .position(|c| {
                c.contains(&"netns".to_string())
                    && c.contains(&"55".to_string())
                    && c[0] == IP_PATH
                    && c.contains(&VETH_CTR.to_string())
            })
            .expect("the netns-move command exists");
        let ctr_up_pos = cmds
            .iter()
            .position(|c| {
                c.contains(&"-n".to_string())
                    && c.contains(&VETH_CTR.to_string())
                    && c.contains(&"up".to_string())
            })
            .expect("the container-side link-up command exists");
        assert!(move_pos < ctr_up_pos);
    }

    #[test]
    fn commands_are_deterministic_and_pid_specific() {
        let a = commands(1);
        let b = commands(2);
        assert_ne!(a, b);
        assert_eq!(commands(1), commands(1));
    }
}
