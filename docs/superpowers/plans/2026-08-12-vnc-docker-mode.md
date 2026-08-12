# VNC × docker mode + VNC sprint cleanups — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `--docker --vnc` sandboxes work (issue #216) by binding the KasmVNC listener to the wildcard address in docker mode, plus three VNC-subsystem cleanups: relay port collision avoidance (#221), coverage-job bundle staging (#219), and a flaky-test fix (#220).

**Architecture:** The docker-mode workload owns a fresh netns; init's `tcp_dial` already falls back to the container's veth address `192.168.127.2` and the nft output chain already exempts it — so the only datapath change is the guest-side bind address. The four host-side refusal gates then come out, and a new KVM e2e proves the whole chain. No wire change, **no `DAEMON_PROTO_VERSION` bump**.

**Tech Stack:** Rust workspace (izba-init / izba-core / izba-cli), GitHub Actions YAML, KVM integration tests.

**Spec:** `docs/superpowers/specs/2026-08-12-vnc-docker-mode-design.md`

## Global Constraints

- Working directory: `/home/kolkhovskiy/git/izba/.claude/worktrees/vnc-docker-mode` (branch `worktree-vnc-docker-mode`). Never `cd` to the main checkout.
- `[ -f .cargo-env ] && source .cargo-env` before any cargo command.
- All six workspace gates must be green before every commit (see CLAUDE.md “Build & test”); the ones a task lists are the fast subset to run mid-task.
- Conventional commits (`feat(init): …`, `fix(core): …`, `test(cli): …`, `ci: …`, `docs: …`).
- Unit tests never bind unix/vsock listeners without a `PermissionDenied` runtime-skip (sandbox denies bind); `UnixStream::pair()` fakes preferred.
- KVM integration runs need the Bash sandbox DISABLED (`/dev/kvm` is invisible inside the sandbox, works outside — never conclude “no KVM”).
- No `DAEMON_PROTO_VERSION` bump anywhere in this plan — nothing changes the wire.
- The refusal message string `"VNC is not yet supported for docker-mode sandboxes"` must be GONE from the tree when the plan completes (grep proves it).

---

### Task 1: izba-init — docker-aware listener bind

**Files:**
- Modify: `crates/izba-init/src/vnc.rs` (constants ~:79-96, `desktop_exec_argvs` ~:318, `start_desktop` ~:372, tests)
- Modify: `crates/izba-init/src/main.rs:466` (the `vnc::start_desktop()` call; `let docker = …` already exists at `main.rs:193`)

**Interfaces:**
- Produces: `pub fn desktop_exec_argvs(cgroup_manager: crate::oci::CgroupManager, docker: bool) -> Vec<Vec<String>>` and `pub fn start_desktop(docker: bool)`. In docker mode the server argv carries `-interface 0.0.0.0`; everything else identical.
- Consumes: nothing new (`main.rs`’s existing `docker` local, parsed from `izba.docker=1`).

- [ ] **Step 1: Write the failing tests** — append to the `tests` module of `crates/izba-init/src/vnc.rs`:

```rust
    // ── docker mode (#216, spec 2026-08-12) ─────────────────────────────────

    #[test]
    fn docker_mode_binds_the_wildcard_for_the_veth_fallback() {
        let argvs = desktop_exec_argvs(crate::oci::CgroupManager::Cgroupfs, true);
        let server = argvs[0].last().unwrap();
        // The container owns its netns: loopback is unreachable from init,
        // and the veth address does not exist yet when this exec is issued
        // (veth::apply runs after `running`), so wildcard is the only bind
        // that cannot race. Reachability rides tcp_dial's GUEST_IP fallback.
        assert!(
            server.contains("-interface 0.0.0.0"),
            "docker mode must bind the wildcard address: {server}"
        );
        // -publicIP is NOT a bind address — it only suppresses KasmVNC's
        // WebRTC public-IP lookup — so it stays pinned to loopback.
        assert!(server.contains("-publicIP 127.0.0.1"), "{server}");
    }

    /// The docker argv must differ from the default argv ONLY in the
    /// `-interface` value (the `egress::output_chain(false)` guard pattern):
    /// any other divergence is silent drift between the two modes.
    #[test]
    fn docker_mode_differs_from_the_default_argv_only_in_the_interface_bind() {
        for mgr in [
            crate::oci::CgroupManager::Cgroupfs,
            crate::oci::CgroupManager::Disabled,
        ] {
            let plain = desktop_exec_argvs(mgr, false);
            let docker = desktop_exec_argvs(mgr, true);
            assert_eq!(plain.len(), docker.len());
            for (p, d) in plain.iter().zip(docker.iter()) {
                let rewritten: Vec<String> = p
                    .iter()
                    .map(|a| a.replace("-interface 127.0.0.1", "-interface 0.0.0.0"))
                    .collect();
                assert_eq!(
                    &rewritten, d,
                    "docker argv must differ from the default only in -interface"
                );
            }
        }
    }
```

Also update every EXISTING call of `desktop_exec_argvs(<mgr>)` in the tests module to `desktop_exec_argvs(<mgr>, false)` — including the `scripts()` helper and `desktop_exec_argvs_honours_the_cgroup_manager` / `stale_display_cleanup_targets_exactly_the_display_the_server_claims` — so the existing pins keep proving the DEFAULT mode.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-init vnc 2>&1 | tail -20`
Expected: compile error (`desktop_exec_argvs` takes 1 argument, 2 supplied).

- [ ] **Step 3: Implement**

In `crates/izba-init/src/vnc.rs`:

1. Replace the `LISTEN_ADDR` doc comment’s **KNOWN GAP** paragraph (lines ~83-95) — the gap is now closed. New text for the two constants:

```rust
/// Address the X server's VNC/websocket endpoint binds to in the DEFAULT
/// (shared-netns) case. Loopback only: the guest has no NIC, and the host
/// reaches the port exclusively through init's vsock `TcpDial` relay, which
/// dials `127.0.0.1` first.
const LISTEN_ADDR: &str = "127.0.0.1";

/// Bind address in docker mode (#216, spec 2026-08-12). A docker-mode
/// sandbox gives the workload its OWN netns (`image/runtime_config.rs` §3),
/// so a loopback listener would sit on the CONTAINER's private loopback,
/// which init cannot dial. The wildcard bind makes the endpoint reachable at
/// `crate::net::GUEST_IP` over the veth pair — exactly where
/// `server::tcp_dial`'s docker-mode fallback dials after loopback refuses
/// (and init's nft output chain already exempts that address from the
/// egress REDIRECT). Binding `GUEST_IP` itself would race `veth::apply`:
/// the address exists only after crun reports `running`, the same window
/// this exec is issued in. Exposure is contained to the container netns
/// (the workload already owns the display outright via `-ac`; nested
/// containers are the same trust zone) and HTTP/ws stays behind BasicAuth.
/// The listening surface is pinned end-to-end by `vnc_docker_e2e`: `:6901`
/// is the ONLY wildcard listener (Xkasmvnc 1.5.0 opens no raw-RFB or
/// X11-TCP port — a real-VM observation, also asserted by
/// `vnc_desktop_e2e`'s listener check).
const LISTEN_ADDR_DOCKER: &str = "0.0.0.0";
```

2. `desktop_exec_argvs` — new signature and interface selection (`-publicIP` keeps `LISTEN_ADDR`):

```rust
pub fn desktop_exec_argvs(
    cgroup_manager: crate::oci::CgroupManager,
    docker: bool,
) -> Vec<Vec<String>> {
    let env = vnc_env();
    let listen = if docker { LISTEN_ADDR_DOCKER } else { LISTEN_ADDR };
    // INJECTION NOTE (both format! sites below): every substitution here is a
    // compile-time constant. Anything host- or cmdline-derived must be quoted
    // or passed as argv instead — this string is handed to a container-root
    // `sh -c`.
    let server = format!(
        "mkdir -p /var/log; \
         exec {CONTAINER_BUNDLE_DIR}/bin/Xkasmvnc {DISPLAY} \
         -geometry {GEOMETRY} -depth {DEPTH} \
         -interface {listen} -websocketPort {WEBSOCKET_PORT} -publicIP {LISTEN_ADDR} \
         …(rest of the format string unchanged)…"
    );
    …
}
```

Also extend the `desktop_exec_argvs` doc comment’s item 1 (`-interface keeps the listener on loopback…`) with one sentence: “In docker mode the interface is the wildcard instead — see `LISTEN_ADDR_DOCKER`.”

3. `start_desktop` — thread it through:

```rust
pub fn start_desktop(docker: bool) {
    …
    for argv in desktop_exec_argvs(cgmgr, docker) {
    …
}
```

4. `crates/izba-init/src/main.rs:466`: `vnc::start_desktop(docker);` — and adjust the comment above it: the display is still orthogonal to docker mode for START ORDERING, but the bind address follows the netns split, so drop/adjust the “orthogonal” wording (e.g. “OUTSIDE the `if docker` block above — a display starts the same way in both modes; only the bind address follows the netns split (`vnc.rs`).”).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p izba-init 2>&1 | tail -5`
Expected: PASS (all init tests, including the two new ones).

- [ ] **Step 5: Gates + commit**

```bash
cargo clippy -p izba-init --all-targets -- -D warnings && cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
git add crates/izba-init/src/vnc.rs crates/izba-init/src/main.rs
git commit -m "feat(init): bind the VNC listener to the wildcard address in docker mode (#216)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: remove the four docker+vnc refusal gates

**Files:**
- Modify: `crates/izba-core/src/daemon/server.rs` (`handle_create` bail ~:528-543; `handle_vnc_set` bail ~:1528-1548; tests ~:2778-2850 and ~:3266-3345)
- Modify: `crates/izba-core/src/image/runtime_config.rs` (tests module — one new composition pin)
- Modify: `crates/izba-cli/src/commands/create.rs:35-46`, `crates/izba-cli/src/commands/run.rs:275-286`

**Interfaces:**
- Consumes: Task 1 is logically prior but there is no compile dependency.
- Produces: `DaemonRequest::Create{vnc: true, docker: Some(true)}` → `Created`; `VncSet{enabled: true}` on a docker sandbox → `Ok`. Task 6’s e2e relies on both.

- [ ] **Step 1: Write the failing daemon tests** — in `crates/izba-core/src/daemon/server.rs`, REPLACE the test `handle_create_refuses_vnc_plus_docker` with:

```rust
    /// #216 (spec 2026-08-12): docker mode + VNC is now a supported
    /// combination — the desktop binds the wildcard address in the
    /// container's netns and the relay reaches it over the veth fallback —
    /// so `handle_create` must accept it and persist both flags.
    #[test]
    fn handle_create_accepts_vnc_plus_docker() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);

        match rpc(
            &mut c,
            &DaemonRequest::Create(DaemonCreate {
                name: "web".into(),
                image_ref: "ubuntu:24.04".into(),
                cpus: 1,
                mem_mb: 256,
                workspace: dir.path().join("ws"),
                rw_size_gb: 1,
                ports: Vec::new(),
                volumes: Vec::new(),
                allow_unconfined: false,
                builder: false,
                docker: Some(true),
                vnc: true,
            }),
        ) {
            DaemonResponse::Created { name } => assert_eq!(name, "web"),
            other => panic!("expected Created, got {other:?}"),
        }
        let config: SandboxConfig =
            load_json(&d.paths.sandbox_dir("web").join(CONFIG_FILE))
                .unwrap()
                .unwrap();
        assert!(config.vnc, "vnc must persist");
        assert!(config.docker, "docker must persist");
        assert!(config.docker_effective(), "and be effective (not builder)");
    }
```

and REPLACE `vnc_set_refuses_to_enable_on_a_docker_mode_sandbox` with:

```rust
    /// #216 (spec 2026-08-12): enabling VNC on an existing docker-mode
    /// sandbox is supported — the netns split is handled by the guest-side
    /// wildcard bind, not by refusing here.
    #[test]
    fn vnc_set_enables_on_a_docker_mode_sandbox() {
        let (dir, d) = test_daemon();
        let mut c = client_conn(&d);
        match rpc(
            &mut c,
            &DaemonRequest::Create(DaemonCreate {
                name: "web".into(),
                image_ref: "ubuntu:24.04".into(),
                cpus: 1,
                mem_mb: 256,
                workspace: dir.path().join("ws"),
                rw_size_gb: 1,
                ports: Vec::new(),
                volumes: Vec::new(),
                allow_unconfined: false,
                builder: false,
                docker: Some(true),
                vnc: false,
            }),
        ) {
            DaemonResponse::Created { .. } => {}
            other => panic!("create: {other:?}"),
        }
        expect_ok_resp(rpc(
            &mut c,
            &DaemonRequest::VncSet {
                name: "web".into(),
                enabled: true,
            },
        ));
        let config: SandboxConfig =
            load_json(&d.paths.sandbox_dir("web").join(CONFIG_FILE))
                .unwrap()
                .unwrap();
        assert!(config.vnc, "VncSet must flip config.vnc on a docker sandbox");
    }
```

(Reuse the existing imports/helpers of that tests module — `test_daemon`, `client_conn`, `rpc`, `expect_ok_resp`, `load_json`, `SandboxConfig`, `CONFIG_FILE` are all already in scope there; mirror how `vnc_set_allows_enabling_on_a_builder_forced_off_docker_sandbox` calls `expect_ok_resp`.)

Keep `handle_create_allows_vnc_plus_docker_when_builder_forces_docker_off` and `vnc_set_allows_enabling_on_a_builder_forced_off_docker_sandbox`, but update their doc comments: they no longer document an exception to a refusal, they pin `docker_effective()` (builder wins) — e.g. “A `builder` create forces docker off; `vnc: true` alongside it must still succeed and persist `docker: true` with `docker_effective() == false`.”

- [ ] **Step 2: Write the failing composition pin** — in `crates/izba-core/src/image/runtime_config.rs` tests, next to `a_vnc_sandbox_gets_bundle_xkbcomp_and_secrets_bound_in` (~:2204):

```rust
    /// #216 (spec 2026-08-12): docker mode and VNC compose in ONE spec — the
    /// fresh container-owned network namespace (docker, spec §3) and the VNC
    /// binds must both be present; neither feature may mask the other. The
    /// refusal that used to make this combination unrepresentable is gone.
    #[test]
    fn a_docker_vnc_sandbox_gets_both_the_fresh_netns_and_the_vnc_binds() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&SpecParams {
            docker: true,
            vnc: true,
            ..base_params(&img)
        })
        .unwrap();
        // docker half: the `network` namespace entry is KEPT (pathless) so
        // crun creates a fresh netns — the D1 default drops it.
        let nss = spec
            .linux()
            .as_ref()
            .unwrap()
            .namespaces()
            .clone()
            .unwrap_or_default();
        assert!(
            nss.iter().any(|n| n.typ() == LinuxNamespaceType::Network),
            "docker mode must keep the fresh network namespace: {nss:?}"
        );
        // vnc half: bundle + secrets binds present.
        let has = |dest: &str| {
            spec.mounts()
                .as_ref()
                .unwrap()
                .iter()
                .any(|m| m.destination().to_str() == Some(dest))
        };
        assert!(has(VNC_BUNDLE_CONTAINER_DIR), "vnc bundle bind missing");
        assert!(has(VNC_SECRETS_CONTAINER_DIR), "vnc secrets bind missing");
    }
```

(`generate_spec`, `SpecParams`, `base_params`, `image_config`, `LinuxNamespaceType` are already used by that tests module — check the existing docker-mode netns test near the D1 comment ~:992-1018 for the exact namespace-assertion idiom and reuse it verbatim if it differs from the above.)

- [ ] **Step 3: Run to verify failures**

Run: `cargo test -p izba-core handle_create_accepts_vnc_plus_docker vnc_set_enables_on_a_docker_mode_sandbox a_docker_vnc_sandbox 2>&1 | tail -15`
Expected: the two daemon tests FAIL (`expected Created, got Error…not yet supported`); the runtime_config pin may already PASS (it is a pin against future masking, not a behavior change — that is fine, note it in the commit).

- [ ] **Step 4: Remove the gates**

1. `crates/izba-core/src/daemon/server.rs` `handle_create`: delete the whole block — comment (“VNC + docker mode is a broken combination…”) plus `if c.vnc && docker { bail!(…) }` (~:528-543).
2. `handle_vnc_set`: delete the docker refusal — the comment and `if cfg.docker_effective() { bail!(…) }` — KEEPING `crate::volume::validate_volumes(&cfg.volumes, true)?;` inside `if enabled { … }`.
3. `crates/izba-cli/src/commands/create.rs`: delete the preflight comment + `if merged.vnc && merged.docker { bail!(…) }` (~:35-46).
4. `crates/izba-cli/src/commands/run.rs`: same deletion (~:275-286).
5. If `bail!` becomes unused in either CLI file, drop it from the `use` line (clippy/`-D warnings` will tell you).

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p izba-core -p izba-cli 2>&1 | tail -5`
Expected: PASS. Then prove the string is gone from code:
`grep -rn "not yet supported for docker-mode" crates/ && echo LEFTOVER || echo CLEAN` → expect `CLEAN`.

- [ ] **Step 6: Gates + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
git add crates/izba-core/src/daemon/server.rs crates/izba-core/src/image/runtime_config.rs \
        crates/izba-cli/src/commands/create.rs crates/izba-cli/src/commands/run.rs
git commit -m "feat(core,cli): accept docker+vnc — remove the four #216 refusal gates

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: #221 — VNC relay avoids persisted fixed ports

**Files:**
- Modify: `crates/izba-core/src/daemon/relays.rs` (two new pub fns + tests)
- Modify: `crates/izba-core/src/daemon/server.rs` (`publish_vnc_relay` ~:1561)

**Interfaces:**
- Produces: `pub fn persisted_host_ports(paths: &Paths) -> std::collections::HashSet<u16>` and `pub fn allocate_avoiding(avoid: &HashSet<u16>, attempts: usize, bind: impl FnMut() -> anyhow::Result<u16>, unbind: impl FnMut(u16)) -> anyhow::Result<(u16, bool)>` in `daemon::relays`.
- Consumes: existing `load_rules_migrating`, `RelayManager::{publish_bound, unpublish}`.

- [ ] **Step 1: Write the failing tests** — in `crates/izba-core/src/daemon/relays.rs` tests module (which already has `rule(port)` and `Paths::with_root` — see ~:264):

```rust
    // ── #221: ephemeral VNC-relay allocation vs persisted fixed ports ───────

    #[test]
    fn persisted_host_ports_collects_every_sandboxs_fixed_rules() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        for s in ["a", "b", "empty"] {
            std::fs::create_dir_all(paths.sandbox_dir(s)).unwrap();
        }
        save_rules(&paths, "a", &[rule(8080), rule(8081)]).unwrap();
        save_rules(&paths, "b", &[rule(9090)]).unwrap();
        assert_eq!(
            persisted_host_ports(&paths),
            [8080, 8081, 9090].into_iter().collect()
        );
    }

    #[test]
    fn persisted_host_ports_is_empty_without_sandboxes_or_rules() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        assert!(persisted_host_ports(&paths).is_empty());
        std::fs::create_dir_all(paths.sandbox_dir("bare")).unwrap();
        assert!(persisted_host_ports(&paths).is_empty());
    }

    #[test]
    fn allocate_avoiding_rebinds_off_a_persisted_port() {
        let avoid: std::collections::HashSet<u16> = [40001].into_iter().collect();
        let ports = std::cell::RefCell::new(vec![40002u16, 40001]); // popped back-first
        let unbound = std::cell::RefCell::new(Vec::new());
        let (port, collided) = allocate_avoiding(
            &avoid,
            10,
            || Ok(ports.borrow_mut().pop().expect("bind called too often")),
            |p| unbound.borrow_mut().push(p),
        )
        .unwrap();
        assert_eq!((port, collided), (40002, false));
        assert_eq!(
            *unbound.borrow(),
            vec![40001],
            "the colliding bind must be undone before the retry"
        );
    }

    #[test]
    fn allocate_avoiding_keeps_the_last_port_when_every_attempt_collides() {
        let avoid: std::collections::HashSet<u16> = [40001].into_iter().collect();
        let binds = std::cell::RefCell::new(0usize);
        let unbound = std::cell::RefCell::new(Vec::new());
        let (port, collided) = allocate_avoiding(
            &avoid,
            3,
            || {
                *binds.borrow_mut() += 1;
                Ok(40001)
            },
            |p| unbound.borrow_mut().push(p),
        )
        .unwrap();
        assert_eq!(
            (port, collided),
            (40001, true),
            "a colliding relay beats no display at all"
        );
        assert_eq!(*binds.borrow(), 3, "exactly `attempts` binds");
        assert_eq!(
            unbound.borrow().len(),
            2,
            "every abandoned bind is undone; the kept one is not"
        );
    }

    #[test]
    fn allocate_avoiding_binds_once_when_clear_of_the_avoid_set() {
        let unbound = std::cell::RefCell::new(Vec::new());
        let (port, collided) = allocate_avoiding(
            &std::collections::HashSet::new(),
            10,
            || Ok(50000),
            |p| unbound.borrow_mut().push(p),
        )
        .unwrap();
        assert_eq!((port, collided), (50000, false));
        assert!(unbound.borrow().is_empty());
    }

    #[test]
    fn allocate_avoiding_propagates_a_bind_error() {
        let r = allocate_avoiding(
            &std::collections::HashSet::new(),
            10,
            || anyhow::bail!("forced"),
            |_p| {},
        );
        assert!(r.is_err());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core relays 2>&1 | tail -10`
Expected: compile error (`persisted_host_ports` / `allocate_avoiding` not found).

- [ ] **Step 3: Implement** — in `crates/izba-core/src/daemon/relays.rs`, after `load_rules_migrating`:

```rust
/// Every host port persisted as a fixed rule in ANY sandbox's `ports.json`.
///
/// The VNC relay's ephemeral allocation avoids these (#221): a kernel-chosen
/// port that matches a persisted rule would make that sandbox's next `start`
/// fail its publish and DROP the rule (pre-existing conflict behavior) — a
/// user-visible loss from a cosmetic collision. Best-effort: an unreadable
/// `ports.json` contributes nothing rather than failing the relay.
pub fn persisted_host_ports(paths: &Paths) -> std::collections::HashSet<u16> {
    let mut out = std::collections::HashSet::new();
    let Ok(entries) = std::fs::read_dir(paths.sandboxes_dir()) else {
        return out;
    };
    for e in entries.flatten() {
        if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Ok((rules, _)) = load_rules_migrating(paths, name) {
            out.extend(rules.iter().map(|r| r.host_port));
        }
    }
    out
}

/// Bind-with-avoidance (#221): call `bind` (kernel-chosen ephemeral port);
/// when the result lands in `avoid`, undo it via `unbind` and try again, up
/// to `attempts` total binds. Returns `(port, collided)` — if every attempt
/// collided the LAST bind is KEPT and `collided` is `true` (the caller warns
/// loudly): a colliding relay beats no display at all. Only the host-port
/// number matters, not the bind address: overlapping addresses on one port
/// conflict at bind time regardless.
pub fn allocate_avoiding(
    avoid: &std::collections::HashSet<u16>,
    attempts: usize,
    mut bind: impl FnMut() -> anyhow::Result<u16>,
    mut unbind: impl FnMut(u16),
) -> anyhow::Result<(u16, bool)> {
    let mut port = bind()?;
    for _ in 1..attempts {
        if !avoid.contains(&port) {
            return Ok((port, false));
        }
        unbind(port);
        port = bind()?;
    }
    Ok((port, avoid.contains(&port)))
}
```

Then rewrite `publish_vnc_relay` in `crates/izba-core/src/daemon/server.rs` (module already has `use crate::daemon::relays::{self, RelayManager};`) — keep the existing doc comment and append one paragraph: “The kernel-chosen port additionally avoids every persisted fixed rule across sandboxes (#221) via `relays::allocate_avoiding`.”:

```rust
fn publish_vnc_relay(d: &Arc<Daemon>, name: &str) -> anyhow::Result<u16> {
    let avoid = relays::persisted_host_ports(&d.paths);
    let (port, collided) = relays::allocate_avoiding(
        &avoid,
        10,
        || {
            d.vnc_relays.publish_bound(
                &d.paths,
                name,
                crate::state::PortRule {
                    bind: std::net::Ipv4Addr::LOCALHOST,
                    host_port: 0,
                    guest_port: crate::vnc::WEBSOCKET_PORT,
                },
            )
        },
        |p| {
            let _ = d
                .vnc_relays
                .unpublish(name, std::net::Ipv4Addr::LOCALHOST, p);
        },
    )?;
    if collided {
        eprintln!(
            "izbad: VNC relay for '{name}' kept port {port}, which a sandbox's \
             ports.json persists as a fixed rule — that sandbox's next start may \
             fail its publish (rebind attempts exhausted)"
        );
    }
    Ok(port)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p izba-core 2>&1 | tail -5`
Expected: PASS (new relays tests + every existing VNC-relay test, e.g. `vnc_relay_never_persists_into_ports_json`, unchanged).

- [ ] **Step 5: Gates + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
git add crates/izba-core/src/daemon/relays.rs crates/izba-core/src/daemon/server.rs
git commit -m "fix(core): VNC relay allocation avoids persisted fixed ports (#221)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: #220 — deflake `tcp_dial_without_fallback_reports_connect_failed`

**Files:**
- Modify: `crates/izba-init/src/server.rs:982-1011` (the test only — no production code)

**Interfaces:** none (test-only).

- [ ] **Step 1: Rewrite the test** — replace the whole test body with:

```rust
    /// The no-fallback dial must surface `ConnectFailed`. The free port is
    /// obtained by bind-and-drop, which is inherently racy under parallel
    /// execution: another test can bind the dropped port before our dial
    /// (observed twice in PR #215 review runs — #220), making the dial
    /// SUCCEED. A success is therefore treated as a raced port and retried
    /// with a fresh one, never asserted against.
    #[test]
    fn tcp_dial_without_fallback_reports_connect_failed() {
        use std::net::TcpListener;
        for attempt in 0..5 {
            let port = match TcpListener::bind(("127.0.0.1", 0)) {
                Ok(l) => {
                    let p = l.local_addr().unwrap().port();
                    drop(l); // nothing is listening on p now — usually
                    p
                }
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    eprintln!(
                        "SKIP tcp_dial_without_fallback_reports_connect_failed: sandbox denies bind: {e}"
                    );
                    return;
                }
                Err(e) => panic!("unexpected bind failure: {e}"),
            };
            let (mut client, server) = UnixStream::pair().unwrap();
            let h = std::thread::spawn(move || tcp_dial(server, port, None));
            match read_frame::<_, Response>(&mut client).unwrap() {
                Response::Error { kind, .. } => {
                    assert_eq!(kind, ErrorKind::ConnectFailed);
                    // Conn is closed after the error frame.
                    let mut rest = Vec::new();
                    client.read_to_end(&mut rest).unwrap();
                    assert!(rest.is_empty());
                    h.join().unwrap();
                    return;
                }
                Response::Ok => {
                    // Raced: something bound the port between drop and dial.
                    // Drop our end — tcp_dial tears down on EOF — and retry.
                    eprintln!(
                        "tcp_dial deflake: port {port} was re-bound mid-test (attempt {attempt}), retrying"
                    );
                    drop(client);
                    h.join().unwrap();
                }
                other => panic!("expected ConnectFailed (or a raced Ok), got {other:?}"),
            }
        }
        panic!(
            "5 consecutive bind-and-drop ports were all re-bound by parallel \
             tests — something is systematically grabbing freed ports"
        );
    }
```

- [ ] **Step 2: Run it — both alone and with the full parallel suite**

Run: `cargo test -p izba-init tcp_dial_without_fallback -- --nocapture 2>&1 | tail -3`
Expected: PASS.
Run: `for i in 1 2 3; do cargo test -p izba-init 2>&1 | tail -1; done`
Expected: `ok` three times (the original flake fired under full-parallel runs).

- [ ] **Step 3: Commit**

```bash
cargo clippy -p izba-init --all-targets -- -D warnings && cargo fmt --check
git add crates/izba-init/src/server.rs
git commit -m "test(init): deflake tcp_dial_without_fallback under parallel port churn (#220)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: #219 — coverage jobs stage kasmvnc.erofs

**Files:**
- Modify: `.github/workflows/e2e.yml` — jobs `linux-kvm-coverage` (~:438) and `windows-whp-coverage` (~:757)

**Interfaces:** none (CI YAML only). The staging steps are a verbatim mirror of the `linux-kvm` / `windows-whp` gate jobs’ steps.

- [ ] **Step 1: `linux-kvm-coverage`**

1. `needs: [kernel, initramfs]` → `needs: [kernel, initramfs, kasmvnc-erofs]`.
2. After the existing `initramfs` download-artifact step, add:

```yaml
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: kasmvnc-erofs
          path: dist/
```

3. Immediately AFTER the `Swatinem/rust-cache` step (`prefix-key: e2e-coverage`) and before `Install cargo-llvm-cov`, add (comment included — the ordering is the PR #215 trap):

```yaml
      - name: Stage kasmvnc.erofs at the production exe-relative discovery path
        # Same staging as the linux-kvm gate job (#219 — the coverage job used
        # to skip it, so vnc_desktop_e2e self-skipped and the coverage report
        # silently omitted the whole VNC plane).
        #
        # ORDER IS LOAD-BEARING: must run AFTER Swatinem/rust-cache — the
        # cache restore replaces target/ wholesale and would silently delete
        # an earlier-staged bundle.
        run: |
          mkdir -p target/artifacts
          cp dist/kasmvnc.erofs target/artifacts/kasmvnc.erofs
      - name: Verify kasmvnc.erofs staged (fail loudly, never silently skip the VNC e2e)
        run: |
          test -f target/artifacts/kasmvnc.erofs || {
            echo "target/artifacts/kasmvnc.erofs missing — the kasmvnc-erofs artifact job is broken; vnc_desktop_e2e would silently self-skip instead of proving the feature" >&2
            exit 1
          }
```

- [ ] **Step 2: `windows-whp-coverage`**

1. `needs: [kernel, initramfs, erofs-exe]` → `needs: [kernel, initramfs, erofs-exe, kasmvnc-erofs]`.
2. After the `e2e-mkfs-erofs-windows` download step, add the same `kasmvnc-erofs` download step as above.
3. Immediately AFTER its `Swatinem/rust-cache` step (`prefix-key: e2e-windows-coverage`), add the same two steps with `shell: bash` on each `run:` step (the Windows gate job’s staging step at ~:218-236 is the template — copy its `shell: bash` form verbatim, adjusting only the comment as in Step 1).

- [ ] **Step 3: Validate the YAML**

Run: `command -v actionlint >/dev/null && actionlint .github/workflows/e2e.yml || python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/e2e.yml')); print('yaml ok')"`
Expected: no errors / `yaml ok`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/e2e.yml
git commit -m "ci: stage kasmvnc.erofs in both coverage jobs so the VNC e2e stops self-skipping (#219)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: `vnc_docker_e2e` — the KVM proof

**Files:**
- Modify: `crates/izba-cli/tests/daemon_e2e.rs` (new test after `vnc_desktop_e2e`; all helpers already exist: `want`, `izba`, `assert_ok`, `stdout_of`, `SandboxGuard`, `DIND_IMAGE`, `vnc_bundle_path`, `parse_vnc_url`, `prove_desktop_session`, `guest_listeners`, `vnc_diag`, `docker_diag`, `BTreeSet`, `Instant`, `Duration`)

**Interfaces:**
- Consumes: Tasks 1–2 (the combination must create and the guest must bind wildcard).

- [ ] **Step 1: Write the test**

```rust
/// Docker mode + VNC (#216, spec 2026-08-12-vnc-docker-mode): a docker-mode
/// sandbox gives the workload its OWN netns, so the desktop binds the
/// WILDCARD address and the relay reaches it through init's `TcpDial` veth
/// fallback (`192.168.127.2`) instead of shared loopback. The full session
/// contract must hold exactly as in `vnc_desktop_e2e` — auth, ws+RFB,
/// restart survival — with the nested docker engine alive alongside.
#[test]
fn vnc_docker_e2e() {
    if !want() {
        return;
    }
    // Production discovery only — same rule as vnc_desktop_e2e.
    assert!(
        std::env::var_os("IZBA_KASMVNC_EROFS").is_none(),
        "this e2e must prove production discovery — unset IZBA_KASMVNC_EROFS"
    );
    let bundle = vnc_bundle_path();
    if !bundle.as_deref().map(Path::exists).unwrap_or(false) {
        eprintln!(
            "SKIP vnc_docker_e2e: kasmvnc.erofs not staged — see vnc_desktop_e2e's \
             skip message for the staging recipe"
        );
        return;
    }

    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let no_env: &[(&str, &str)] = &[];
    let name = "vnc-docker-e2e";
    let _guard = SandboxGuard {
        data: data.clone(),
        name,
    };

    // [1] create --docker --vnc: the exact combination PR #215 refused.
    // Same sizing as docker_publish_reaches_inner_container — dockerd plus
    // an X session need more than the 1-cpu default.
    let o = izba(
        &data,
        no_env,
        &[
            "create", "--docker", "--vnc", "--image", DIND_IMAGE, "--cpus", "2", "--mem",
            "2048", "--name", name, &ws_s,
        ],
    );
    assert_ok(&o, "create --docker --vnc");
    let o = izba(&data, no_env, &["start", name]);
    assert_ok(&o, "start (docker+vnc)");

    // [2] Full session proof through the relay: 401 challenge, credentialed
    // 200, real websocket upgrade + RFB greeting. Every byte crosses the
    // veth — init's loopback dial finds nothing (the container owns :6901
    // in its own netns), so the TcpDial fallback to 192.168.127.2 is the
    // hop this test exists to prove.
    let o = izba(&data, no_env, &["vnc", "url", name]);
    assert_ok(&o, "vnc url (docker)");
    let url = stdout_of(&o).trim().to_string();
    let (password, port) = parse_vnc_url(&url);
    prove_desktop_session(&data, name, port, &password, "docker first boot");

    // [3] Listener posture: `izba exec` enters the CONTAINER netns in
    // docker mode, so this reads the container's own table. With
    // `-SecurityTypes None` and `-ac`, any OTHER wildcard listener from the
    // X server (raw RFB 5901, X11-TCP 6001) would be an unauthenticated
    // desktop for everything in the netns — :6901 (BasicAuth-gated) must be
    // the only one.
    let listeners = guest_listeners(&data, name);
    assert!(
        listeners.contains(&(6901, "00000000".to_string())),
        "the desktop must bind the wildcard address in docker mode \
         (loopback is unreachable across the netns split), got: {listeners:?}\n{}",
        vnc_diag(&data, name)
    );
    for (p, addr) in &listeners {
        if addr.chars().all(|c| c == '0') {
            assert_eq!(
                *p, 6901,
                "the desktop websocket must be the ONLY wildcard listener, got: {listeners:?}"
            );
        }
    }
    let ports: BTreeSet<u16> = listeners.iter().map(|(p, _)| *p).collect();
    assert!(
        !ports.contains(&6001) && !ports.contains(&5901),
        "no X11-TCP (6001) or raw-RFB (5901) listener may exist: {listeners:?}"
    );
    // init's own services (sshd 22, egress relay 15001) live in the OTHER
    // netns; seeing them here would mean exec did not enter the container
    // netns and [2] proved nothing about the veth path.
    assert!(
        !ports.contains(&22) && !ports.contains(&15001),
        "init-netns services must not be visible from the container: {listeners:?}"
    );

    // [3b] The X server really owns display :1 in the container.
    let o = izba(
        &data,
        no_env,
        &["exec", name, "--", "sh", "-c", "ls /tmp/.X11-unix/"],
    );
    assert_ok(&o, "ls /tmp/.X11-unix/ (docker)");
    assert!(
        stdout_of(&o).contains("X1"),
        "the X server must own display :1, got: {:?}\n{}",
        stdout_of(&o),
        vnc_diag(&data, name)
    );

    // [4] Coexistence: the nested engine still comes up beside the desktop
    // (same 120 s ceiling as docker_publish_reaches_inner_container).
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut engine_up = false;
    while Instant::now() < deadline {
        let o = izba(
            &data,
            no_env,
            &["exec", name, "--", "docker", "info", "--format", "{{.ID}}"],
        );
        if o.status.success() {
            engine_up = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    assert!(
        engine_up,
        "dockerd never became ready beside the desktop within 120s\n{}\n{}",
        docker_diag(&data, name),
        vnc_diag(&data, name)
    );

    // [5] RESTART: the stale-X-lock class (persistent /tmp overlay) does
    // not care about docker mode, and neither may the fix. Fresh password,
    // full session re-proof, and the log must not show X's stale-lock death.
    let o = izba(&data, no_env, &["stop", name]);
    assert_ok(&o, "stop (docker+vnc restart)");
    let o = izba(&data, no_env, &["start", name]);
    assert_ok(&o, "start (docker+vnc restart)");
    let o = izba(&data, no_env, &["vnc", "url", name]);
    assert_ok(&o, "vnc url (docker, after restart)");
    let url2 = stdout_of(&o).trim().to_string();
    let (password2, port2) = parse_vnc_url(&url2);
    assert_ne!(
        password2, password,
        "each start must mint a fresh VNC password"
    );
    prove_desktop_session(&data, name, port2, &password2, "docker after restart");
    let o = izba(
        &data,
        no_env,
        &["exec", name, "--", "cat", "/var/log/izba-vnc.log"],
    );
    assert_ok(&o, "read the guest vnc log after restart");
    assert!(
        !stdout_of(&o).contains("already active for display"),
        "a restarted docker+vnc sandbox must not trip X's stale display lock:\n{}",
        stdout_of(&o)
    );
}
```

- [ ] **Step 2: Verify it compiles and self-skips without KVM/bundle**

Run: `cargo test -p izba-cli --test daemon_e2e vnc_docker_e2e 2>&1 | tail -3`
Expected: compiles; test returns quickly (env-gated `want()` or bundle skip).

- [ ] **Step 3: Commit**

```bash
cargo clippy -p izba-cli --all-targets -- -D warnings && cargo fmt --check
git add crates/izba-cli/tests/daemon_e2e.rs
git commit -m "test(cli): vnc_docker_e2e — docker+vnc session, listener posture, restart (#216)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

(The real-VM run happens in Task 8 — this task only lands the test.)

---

### Task 7: docs — refusal mentions become the shipped design

**Files:**
- Modify: `CLAUDE.md` (docker-mode bullet list, the `- **Docker mode (#198, izba.docker=1)…** ` block)
- Modify: `docs/superpowers/specs/2026-08-11-vnc-desktop-environment-design.md:63`

**Interfaces:** none.

- [ ] **Step 1: CLAUDE.md** — inside the “Docker mode (#198…)” load-bearing block, append one sub-bullet after the “Port reach-through” bullet:

```markdown
  - **VNC in docker mode (#216, spec 2026-08-12):** the desktop binds the
    WILDCARD address (`-interface 0.0.0.0` vs loopback in the shared-netns
    default) so the relay reaches it via `tcp_dial`'s veth fallback to
    `192.168.127.2`; the container netns is the exposure boundary and
    BasicAuth stays in front of HTTP/ws. The two `desktop_exec_argvs` modes
    differ ONLY in `-interface` (guard test); `vnc_docker_e2e` pins `:6901`
    as the container's only wildcard listener.
```

- [ ] **Step 2: LXDE spec pointer** — in `docs/superpowers/specs/2026-08-11-vnc-desktop-environment-design.md`, the out-of-scope bullet

```
- Any change to the KasmVNC/auth/relay plumbing, the `docker+vnc` refusal
  (#216), or the `DAEMON_PROTO_VERSION`. This is a guest-bundle + init-argv
  change only.
```

becomes

```
- Any change to the KasmVNC/auth/relay plumbing, the `docker+vnc` refusal
  (#216 — since LIFTED by `2026-08-12-vnc-docker-mode-design.md`, which owns
  the docker-mode listener posture), or the `DAEMON_PROTO_VERSION`. This is
  a guest-bundle + init-argv change only.
```

- [ ] **Step 3: Sweep for stragglers**

Run: `grep -rn "docker.*vnc.*refus\|vnc.*docker.*refus\|not yet supported for docker" --include='*.md' --include='*.rs' --include='*.ts' --include='*.tsx' . | grep -v superpowers/plans | grep -v 2026-08-12-vnc-docker-mode`
Expected: only historical mentions inside older spec/plan documents’ narrative (leave those); no live code/doc claims that the combination is refused. Fix anything else found.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md docs/superpowers/specs/2026-08-11-vnc-desktop-environment-design.md
git commit -m "docs: docker+vnc is supported — update the refusal mentions (#216)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: local verification — full gates + real-VM KVM e2e

**Files:** none (verification only).

**Interfaces:** consumes everything above.

- [ ] **Step 1: The six workspace gates**

```bash
source .cargo-env 2>/dev/null || true
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```

Expected: all green.

- [ ] **Step 2: App gate** (daemon behavior changed; types did not — still prove it):

```bash
cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test); cd ..
```

Expected: green.

- [ ] **Step 3: Stage artifacts for the KVM run** (UNSANDBOXED Bash from here on — `/dev/kvm` is invisible inside the sandbox):

```bash
mkdir -p target/artifacts
# Reuse the main checkout's staged artifacts when present:
for f in vmlinux vmlinux-usb initramfs.cpio.gz kasmvnc.erofs; do
  [ -f target/artifacts/$f ] || cp /home/kolkhovskiy/git/izba/target/artifacts/$f target/artifacts/ 2>/dev/null || true
done
ls -la target/artifacts/   # need at least vmlinux, initramfs.cpio.gz, kasmvnc.erofs
```

If `kasmvnc.erofs` is missing everywhere: `hack/build-kasmvnc-erofs.sh && cp dist/kasmvnc.erofs target/artifacts/`. If the kernel/initramfs are missing, follow `docs/testing.md` (fetch/build), or run `bash hack/devbuild.sh` guidance — but the main checkout normally has them.

- [ ] **Step 4: Run the three e2e proofs** (unsandboxed, `--test-threads=1`):

```bash
IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e \
  vnc_desktop_e2e vnc_docker_e2e docker_publish_reaches_inner_container \
  -- --test-threads=1 --nocapture 2>&1 | tail -40
```

Expected: **3 passed, 0 failed — and zero `SKIP` lines in the output** (a SKIP here means artifacts are mis-staged, not success; job-green ≠ test-ran).

- [ ] **Step 5: Commit nothing — record results.** If anything failed, fix via the normal debug loop (each fix is its own commit on the task it belongs to) and re-run this task from Step 1.

---

### Task 9: delivery — push, PR, CI iteration

**Files:** none (process). Repo-owner authorization in CLAUDE.md applies: push the branch, open the PR (NEVER draft), iterate CI to CLEAN. Unsandboxed Bash for `gh`.

- [ ] **Step 1: Push and open the PR**

```bash
git log --oneline origin/main..HEAD   # sanity: only this plan's commits
git push -u origin worktree-vnc-docker-mode
gh pr create --title "VNC × docker mode: wildcard bind + relay/CI/test cleanups" --body "$(cat <<'EOF'
Docker-mode sandboxes now get a working VNC desktop (#216): the workload owns
its netns, so the KasmVNC listener binds the wildcard address there and the
relay rides init's existing TcpDial veth fallback (192.168.127.2). The four
refusal gates are removed; a new KVM e2e (vnc_docker_e2e) proves the full
session (BasicAuth, ws+RFB, restart survival, listener posture: :6901 is the
container's ONLY wildcard listener) with the nested engine alive alongside.

Rode along, same subsystem:
- #221: the ephemeral VNC relay port now avoids every persisted fixed rule
  across sandboxes (bounded rebind; loud warning on exhaustion).
- #219: both coverage jobs stage kasmvnc.erofs (after rust-cache, verified
  fail-loud) so the VNC e2e stops self-skipping in coverage runs.
- #220: deflaked tcp_dial_without_fallback_reports_connect_failed (bind-drop
  port races under parallel execution → bounded retry).

No wire change, no DAEMON_PROTO_VERSION bump.

Spec: docs/superpowers/specs/2026-08-12-vnc-docker-mode-design.md

Closes #216
Closes #219
Closes #220
Closes #221

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 2: Dispatch the devbuild for manual testing** (parallel with PR checks): `bash hack/devbuild.sh` — record the exact `dist/local/<ts>-<sha>/` path it reports (it auto-copies to the MAIN checkout from a worktree; never cite `dist/local/latest`).

- [ ] **Step 3: Dispatch `e2e.yml` on the branch** and prove #219:

```bash
gh workflow run e2e.yml --ref worktree-vnc-docker-mode
gh run watch <run-id>
# Then grep BOTH coverage jobs' logs: vnc_desktop_e2e must PASS, not SKIP.
gh run view <run-id> --log | grep -E "vnc_(desktop|docker)_e2e|SKIP vnc" | head
```

Expected: coverage jobs show the VNC e2e running (PASS lines, no `SKIP vnc_desktop_e2e`).

- [ ] **Step 4: CI iteration to CLEAN** — all required checks green, SonarCloud gate green (`mergeStateStatus: CLEAN`, not `UNSTABLE`), Greptile satisfied per the `greploop` skill (note: Greptile OSS credits may still be exhausted — if the app never reviews, record that and rely on the other two fronts, as PR #224 did). Re-run infra-flaky jobs; never paper over a real red. If checks won’t start and `mergeStateStatus` is `DIRTY`: it is a merge conflict — rebase on `origin/main`, resolve, `git push --force-with-lease`.

- [ ] **Step 5: Report** — summary, PR link, devbuild artifact path + ready-to-paste install commands (per CLAUDE.md delivery loop step 3).
