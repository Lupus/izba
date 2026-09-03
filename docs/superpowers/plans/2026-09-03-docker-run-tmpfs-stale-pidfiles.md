# Docker-mode `/run` tmpfs (stale pid files, #214) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A docker-mode sandbox whose VMM was killed uncleanly (daemon killed, host reboot) must bring its nested Docker Engine up normally on the next `izba start`, with no manual pid-file deletion.

**Architecture:** The workload's `/run` (and, via the `/var/run → /run` symlink every mainstream base image ships, `/var/run`) currently lives on the persistent rw disk (the overlay upper), so `docker.pid` / `containerd.pid` survive an unclean stop; on the next boot the same low PIDs exist again and dockerd refuses to start ("process with PID 2 is still running"). The fix mounts a fresh `tmpfs` over the container's `/run` in the **docker-mode OCI spec only**, ordered BEFORE the `/run/izba/*` bind mounts (a later tmpfs would shadow the VNC secrets bind). The bug is reproduced first by extending the existing docker e2e with an unclean-stop → `izba start` → engine-ready phase; that phase must FAIL on the unfixed tree.

**Tech Stack:** Rust; `oci-spec` `MountBuilder` (host-side spec generation in `crates/izba-core/src/image/runtime_config.rs`); the KVM-gated daemon e2e in `crates/izba-cli/tests/daemon_e2e.rs` (real Cloud Hypervisor microVM + real nested dockerd, `docker:28-dind` image).

**Spec:** GitHub issue #214 (https://github.com/Lupus/izba/issues/214) is the requirements document; the docker-mode design it extends is `docs/superpowers/specs/2026-08-07-docker-in-sandbox-design.md` (§4 storage: `/var/lib/docker` is an anonymous ext4 volume, NOT the overlay upper; §5 engine auto-start: no auto-restart, `izba stop && izba start` is the recovery). The acceptance criteria copied verbatim from #214:

- After an unclean stop (daemon killed while running) followed by `izba start`, the nested engine starts normally with no manual intervention.
- The same holds for the second-layer `containerd.pid` case, not just `docker.pid`.
- If the tmpfs approach is chosen, images that symlink `/var/run → /run` are verified to still work.
- Non-pid state on the persistent rw disk is preserved across the fix.
- An e2e or integration test covers the unclean-stop → restart → engine-up sequence.

## Global Constraints

- Approach chosen (user decision 2026-09-03): **tmpfs over `/run` in the OCI spec**, NOT init-side `*.pid` cleanup. Out of scope: auto-restarting a failed engine; clearing arbitrary state on the rw disk; #207 liveness work.
- The non-docker OCI spec must be UNCHANGED: no `/run` mount for a non-docker sandbox, with or without VNC (guard-tested).
- Mount order is load-bearing: the `/run` tmpfs must be ordered before every mount whose destination starts with `/run/` (today: the VNC secrets bind at `/run/izba/vnc-secrets`). crun applies `mounts` in array order.
- The tmpfs options are exactly `["nosuid", "nodev", "mode=755"]` (what systemd mounts a real host's `/run` with; NOT Docker's `--tmpfs` default `noexec,size=64m` — the point is "what an image expects of `/run` on a real host"). No `size=` (kernel default = half of guest RAM; only guest memory is at stake).
- The tmpfs is emitted by exactly ONE function, `add_docker_run_tmpfs`, called from `generate_spec` under `if params.docker`, after `rebind_sys_mount` and before the USB/VNC mount helpers.
- No `DAEMON_PROTO_VERSION` bump, no wire change, no init change, no cmdline change.
- Six workspace gates + the app gate (see repo `CLAUDE.md` "Build & test") must be green before every commit; `[ -f .cargo-env ] && source .cargo-env` first. Real-VM verification needs KVM, which is visible ONLY with the Bash sandbox DISABLED (`dangerouslyDisableSandbox: true`) — `/dev/kvm` exists and works on this machine; "no KVM" is a sandbox artefact, never a real finding.
- Local KVM e2e recipe (artifacts already installed under `~/.local/share/izba/artifacts/`, refreshed 2026-08-20, post-docker-mode):

  ```sh
  source .cargo-env
  IZBA_INTEGRATION=1 \
  IZBA_KERNEL=$HOME/.local/share/izba/artifacts/vmlinux \
  IZBA_INITRAMFS=$HOME/.local/share/izba/artifacts/initramfs.cpio.gz \
  IZBA_TEST_CACHE=$HOME/.cache/izba-itest \
  cargo test -p izba-cli --test daemon_e2e docker_publish_reaches_inner_container -- --test-threads=1 --nocapture
  ```

  For `vnc_docker_e2e` additionally stage the bundle at the production exe-relative path first: `mkdir -p target/artifacts && cp ~/.local/share/izba/artifacts/kasmvnc.erofs target/artifacts/`.
- Conventional commits with `Refs #214` in the body; tests first (TDD); `git add` specific paths only, never `git add -A`.

---

### Task 1: Reproduce — unclean-stop phase in the docker e2e

**Files:**
- Modify: `crates/izba-cli/tests/daemon_e2e.rs` (the `docker_publish_reaches_inner_container` test, currently ending at the `// Teardown is the SandboxGuard's job` comment after phase `[4]`; add two helpers next to `daemon_pid`)

**Interfaces:**
- Consumes: `izba(data, envs, args) -> Output`, `stdout_of`, `assert_ok`, `docker_diag(data, name) -> String`, `SandboxGuard`, `DIND_IMAGE`, and `izba_core::state::{load_json, RunState, STATE_FILE}` (already imported; `RunState.vmm_pid: PidIdentity { pid: u32, starttime: u64 }`).
- Produces: nothing other tasks consume; Task 2 makes this phase pass.

Why extend rather than add a test: a docker-mode sandbox is the most expensive thing the suite boots (2 vCPU / 2 GiB, dind pull + nested nginx pull), and the unclean-stop sequence needs exactly the state phases `[1]`–`[3]` already build. Phases are numbered and commented, matching the file's house style.

- [ ] **Step 1: Add the two helpers** right after `fn daemon_pid` (near line 69):

```rust
/// SIGKILL a host process — the e2e's stand-in for an unclean stop (daemon
/// killed, host reboot): the guest gets no shutdown at all, so whatever the
/// workload had written to its persistent disks is exactly what the next
/// boot finds. Linux-only (`kill(1)`), like the KVM suite it serves.
fn kill9(pid: u32) {
    let o = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output()
        .expect("run kill");
    assert!(
        o.status.success(),
        "kill -9 {pid} failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// Wait until `/proc/<pid>` is gone (the process was reaped), so a
/// following `izba start` sees a dead VMM rather than a dying one.
fn wait_pid_gone(pid: u32, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}
```

- [ ] **Step 2: Capture the nested container id in phase `[3]`.** The `docker run -d` call's stdout is the 64-hex container id. Directly after its `assert!(o.status.success(), "nested `docker run -d -p 8080:80 nginx` failed: ...")` block add:

```rust
    // The nested container's id: phase [6] uses it to prove the engine's
    // OWN state (`/var/lib/docker`, the anonymous ext4 volume — spec §4)
    // survives the unclean stop that the pid files must NOT survive.
    let nested_id = stdout_of(&o).trim().to_string();
    assert_eq!(
        nested_id.len(),
        64,
        "docker run -d must print the full container id, got {nested_id:?}"
    );
```

- [ ] **Step 3: Append phases `[5]`–`[7]`** in place of the trailing `// Teardown is the SandboxGuard's job (it also runs on panic).` comment (keep that comment as the new last line):

```rust
    // [5] #214: an UNCLEAN stop. SIGKILL the VMM — no guest shutdown, so
    // dockerd's and containerd's pid files stay exactly where the engine
    // wrote them. Then a plain `izba start`, as a user would after a host
    // reboot: it must succeed on its own, with NO `izba stop` and NO manual
    // pid-file deletion in between.
    let state_path = data.join("sandboxes").join(name).join(STATE_FILE);
    let st: RunState = load_json(&state_path)
        .expect("read state.json")
        .expect("state.json present while running");
    let vmm_pid = st.vmm_pid.pid;
    kill9(vmm_pid);
    assert!(
        wait_pid_gone(vmm_pid, Duration::from_secs(10)),
        "VMM pid {vmm_pid} still present 10s after SIGKILL"
    );
    let o = izba(&data, no_env, &["start", name]);
    assert!(
        o.status.success(),
        "`izba start` after an unclean stop must succeed unaided: {}\n{}",
        String::from_utf8_lossy(&o.stderr),
        docker_diag(&data, name)
    );

    // [6] The engine must come back on its own. This is the #214 symptom:
    // without a fresh /run, dockerd finds the previous boot's docker.pid,
    // sees its (reused) PID alive, and refuses to start — and after
    // docker.pid, containerd.pid fails the same way one layer down. `docker
    // info` succeeding proves BOTH layers started (dockerd only answers
    // once its containerd is up).
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut ready = false;
    while Instant::now() < deadline {
        if izba(
            &data,
            no_env,
            &["exec", name, "--", "docker", "info", "--format", "{{.ID}}"],
        )
        .status
        .success()
        {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    assert!(
        ready,
        "dockerd never came back within 120s of restarting after an unclean stop (#214)\n{}",
        docker_diag(&data, name)
    );
    let engine_log = izba(
        &data,
        no_env,
        &["exec", name, "--", "cat", "/var/log/izba-dockerd.log"],
    );
    let engine_log = stdout_of(&engine_log);
    assert!(
        !engine_log.contains("is still running"),
        "the engine log must not carry a stale-pidfile refusal from either layer:\n{engine_log}"
    );

    // [6b] Non-pid state is preserved: the nested container from [3] is
    // still known to the (restarted) engine — `/var/lib/docker` lives on a
    // persistent volume and the fix must not touch it.
    let o = izba(
        &data,
        no_env,
        &[
            "exec", name, "--", "docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}}",
        ],
    );
    assert_ok(&o, "docker ps -a after the unclean restart");
    let ids = stdout_of(&o);
    assert!(
        ids.lines().any(|l| l.trim() == nested_id),
        "the nested container {nested_id} must survive the unclean restart in `docker ps -a`, got:\n{ids}\n{}",
        docker_diag(&data, name)
    );

    // [7] The shape the fix relies on, observed from inside the workload:
    // this image (Alpine-based dind) symlinks /var/run → /run, and /run is
    // a fresh tmpfs — so dockerd's default pidfile paths (/var/run/docker.pid,
    // /var/run/docker/containerd/containerd.pid) structurally cannot reach
    // the persistent rw disk.
    let o = izba(
        &data,
        no_env,
        &[
            "exec",
            name,
            "--",
            "sh",
            "-c",
            "readlink -f /var/run; awk '$2==\"/run\"{print $3}' /proc/mounts",
        ],
    );
    assert_ok(&o, "inspect /var/run + /run inside the workload");
    let shape: Vec<String> = stdout_of(&o).lines().map(|l| l.trim().to_string()).collect();
    assert_eq!(
        shape,
        vec!["/run".to_string(), "tmpfs".to_string()],
        "expected /var/run → /run and /run on tmpfs, got {shape:?}"
    );
    // Teardown is the SandboxGuard's job (it also runs on panic).
```

- [ ] **Step 4: Compile-check the test without running it** (KVM not needed):

Run: `source .cargo-env && cargo test -p izba-cli --test daemon_e2e --no-run`
Expected: compiles with no warnings. Also `cargo clippy -p izba-cli --all-targets -- -D warnings` and `cargo fmt --check` clean.

- [ ] **Step 5: Run the extended test on the UNFIXED tree to prove it reproduces #214** (Bash sandbox DISABLED — KVM is invisible inside it):

Run (from the repo root):
```sh
source .cargo-env
IZBA_INTEGRATION=1 \
IZBA_KERNEL=$HOME/.local/share/izba/artifacts/vmlinux \
IZBA_INITRAMFS=$HOME/.local/share/izba/artifacts/initramfs.cpio.gz \
IZBA_TEST_CACHE=$HOME/.cache/izba-itest \
cargo test -p izba-cli --test daemon_e2e docker_publish_reaches_inner_container -- --test-threads=1 --nocapture 2>&1 | tee /tmp/claude/e2e-214-before.log
```
Expected: FAIL in phase `[6]` — `dockerd never came back within 120s of restarting after an unclean stop (#214)` — and the `docker_diag` dump's `/var/log/izba-dockerd.log` section contains `process with PID <n> is still running` (the docker.pid refusal; it may also show the containerd.pid one). Phases `[1]`–`[5]` must all pass (in particular the `izba start` in `[5]` must succeed — if it does NOT, report that as a separate finding with the exact stderr; it is a product bug outside #214's scope, not something to paper over with a retry loop). Save the failing output; quote the refusal line in the report file. If the test instead fails earlier, or passes, STOP and report — the reproduction is the deliverable of this task.

- [ ] **Step 6: Commit the failing test**

```bash
git add crates/izba-cli/tests/daemon_e2e.rs
git commit -m "test(cli): reproduce #214 — docker engine bricked after an unclean stop

Extend docker_publish_reaches_inner_container with an unclean-stop phase:
SIGKILL the VMM, plain \`izba start\`, and require the nested engine to come
back, the earlier nested container to survive in \`docker ps -a\`, and the
workload's /var/run → /run to sit on a fresh tmpfs. Fails on this tree with
dockerd's 'process with PID N is still running' refusal.

Refs #214"
```

---

### Task 2: Fix — tmpfs over `/run` in the docker-mode OCI spec

**Files:**
- Modify: `crates/izba-core/src/image/runtime_config.rs` — constants next to `DOCKER_READONLY_PROC_SYS` (~line 1197); a new `add_docker_run_tmpfs` next to `add_usb_device_access` (~line 1223); one call in `generate_spec` right after `rebind_sys_mount(&mut spec);` (~line 1108); three tests in the `tests` module next to `docker_mode_gets_rw_cgroup_mount` (~line 2775).
- Modify: `CLAUDE.md` — one new bullet in the "Docker mode (#198, `izba.docker=1`)" list, after the "cgroup delegation + engine auto-start" bullet.
- Test: `crates/izba-core/src/image/runtime_config.rs` (unit tests) + the Task 1 e2e phase + `vnc_docker_e2e` (ordering vs the VNC secrets bind, on a real VM).

**Interfaces:**
- Consumes: `generate_spec(&SpecParams) -> Result<Spec>`, `SpecParams { docker: bool, vnc: bool, .. }`, the test helpers `image_config(json) -> Config` and `base_params(&Config) -> SpecParams` (both in the `tests` module), `MountBuilder`.
- Produces: `pub const DOCKER_RUN_TMPFS: &str = "/run"`; `const DOCKER_RUN_TMPFS_OPTIONS: &[&str] = &["nosuid", "nodev", "mode=755"]`; `fn add_docker_run_tmpfs(spec: &mut Spec) -> Result<()>`.

- [ ] **Step 1: Write the three failing tests** in the `tests` module, directly after `docker_mode_gets_rw_cgroup_mount`:

```rust
    #[test]
    fn docker_mode_mounts_a_fresh_tmpfs_over_run() {
        // #214: /run on the persistent rw disk let docker.pid/containerd.pid
        // outlive an unclean stop; the reused low PIDs then made dockerd
        // refuse to start. A tmpfs /run is fresh on every boot by construction.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut params = base_params(&img);
        params.docker = true;
        let spec = generate_spec(&params).unwrap();
        let mounts = spec.mounts().as_ref().unwrap();
        let runs: Vec<_> = mounts
            .iter()
            .filter(|m| m.destination().to_string_lossy() == DOCKER_RUN_TMPFS)
            .collect();
        assert_eq!(runs.len(), 1, "exactly one /run mount, got {runs:?}");
        let run = runs[0];
        assert_eq!(run.typ().as_deref(), Some("tmpfs"));
        let opts = run.options().clone().unwrap_or_default();
        for want in DOCKER_RUN_TMPFS_OPTIONS {
            assert!(
                opts.iter().any(|o| o == want),
                "missing {want} in {opts:?}"
            );
        }
        assert!(
            !opts.iter().any(|o| o.starts_with("size=")),
            "no size cap: only guest memory is at stake, got {opts:?}"
        );
    }

    #[test]
    fn docker_run_tmpfs_precedes_every_mount_beneath_run() {
        // crun applies `mounts` in array order: a tmpfs mounted AFTER a bind
        // beneath /run would shadow that bind. Docker+VNC is the shape that
        // has one (the VNC secrets at /run/izba/vnc-secrets).
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut params = base_params(&img);
        params.docker = true;
        params.vnc = true;
        let spec = generate_spec(&params).unwrap();
        let mounts = spec.mounts().as_ref().unwrap();
        let run_idx = mounts
            .iter()
            .position(|m| m.destination().to_string_lossy() == DOCKER_RUN_TMPFS)
            .expect("/run tmpfs present");
        let beneath: Vec<usize> = mounts
            .iter()
            .enumerate()
            .filter(|(_, m)| m.destination().to_string_lossy().starts_with("/run/"))
            .map(|(i, _)| i)
            .collect();
        assert!(
            !beneath.is_empty(),
            "precondition: docker+vnc binds something beneath /run"
        );
        for i in beneath {
            assert!(
                i > run_idx,
                "mount #{i} ({}) sits beneath /run but is ordered BEFORE the /run tmpfs (#{run_idx}); crun would mount the tmpfs over it",
                mounts[i].destination().display()
            );
        }
    }

    #[test]
    fn non_docker_spec_leaves_run_on_the_image_rootfs() {
        // The fresh /run is docker-mode-only: every other sandbox keeps the
        // OCI default (no /run mount), with or without a display.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        for vnc in [false, true] {
            let mut params = base_params(&img);
            params.vnc = vnc;
            let spec = generate_spec(&params).unwrap();
            assert!(
                !spec
                    .mounts()
                    .as_ref()
                    .unwrap()
                    .iter()
                    .any(|m| m.destination().to_string_lossy() == DOCKER_RUN_TMPFS),
                "non-docker (vnc={vnc}) spec must not mount /run"
            );
        }
    }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `source .cargo-env && cargo test -p izba-core docker_mode_mounts_a_fresh_tmpfs_over_run docker_run_tmpfs_precedes non_docker_spec_leaves_run`
Expected: compile error — `DOCKER_RUN_TMPFS` / `DOCKER_RUN_TMPFS_OPTIONS` not found.

- [ ] **Step 3: Add the constants** directly after the `DOCKER_READONLY_PROC_SYS` const:

```rust
/// Docker mode only: the container path that gets a fresh `tmpfs` on every
/// boot (see [`add_docker_run_tmpfs`]).
pub const DOCKER_RUN_TMPFS: &str = "/run";

/// Options for the docker-mode `/run` tmpfs — what systemd mounts a real
/// host's `/run` with, since the point is to give the image the `/run` it was
/// written against. Deliberately NOT Docker's `--tmpfs` defaults
/// (`noexec,size=64m`): `/run` is not `noexec` on any mainstream host, and a
/// size cap protects nothing here (only guest memory is at stake; the kernel
/// default is half of it).
const DOCKER_RUN_TMPFS_OPTIONS: &[&str] = &["nosuid", "nodev", "mode=755"];
```

- [ ] **Step 4: Add `add_docker_run_tmpfs`** directly before `fn add_usb_device_access`:

```rust
/// Docker mode only: mount a fresh `tmpfs` over the container's `/run`
/// (#214).
///
/// The workload's rootfs is an overlay whose upper is the PERSISTENT rw disk,
/// so without this mount everything dockerd writes under `/run` — its own
/// `docker.pid`, containerd's `containerd.pid`, the sockets — survives an
/// unclean stop (daemon killed, host reboot). On the next boot the same low
/// PIDs exist again (dockerd IS the process its own stale pidfile names), so
/// dockerd's "is that pid alive" check false-positives and the engine refuses
/// to start; and because a dead engine stays dead (no auto-restart), the
/// sandbox comes up permanently docker-less until someone deletes the files
/// by hand. A tmpfs `/run` is fresh on every boot **by construction** — the
/// same contract every real host and every systemd-based image assumes — and
/// needs no init-side cleanup that would have to resolve `/var/run → /run`
/// inside the rootfs (a naive follow lands in init-root `/run`) under the
/// docker-mode fs-id guard.
///
/// dockerd's default pidfile paths are under `/var/run`, which every
/// mainstream base image (Alpine, Debian/Ubuntu, Fedora, Arch) ships as a
/// symlink to `/run`; crun resolves a mount destination INSIDE the rootfs, so
/// the tmpfs covers them. An image with a real `/var/run` DIRECTORY is not
/// covered (none of the docker-capable images do that; a second tmpfs there
/// would stack over `/run` in the symlink case).
///
/// **Ordering is load-bearing:** crun applies `mounts` in array order, so this
/// must be pushed BEFORE any mount whose destination lies beneath `/run` —
/// today the VNC secrets bind at [`VNC_SECRETS_CONTAINER_DIR`] — or the tmpfs
/// would shadow it (guard-tested by
/// `docker_run_tmpfs_precedes_every_mount_beneath_run`). Non-docker sandboxes
/// keep `/run` on the image rootfs (guard-tested too).
fn add_docker_run_tmpfs(spec: &mut Spec) -> Result<()> {
    if let Some(mounts) = spec.mounts_mut().as_mut() {
        mounts.push(
            MountBuilder::default()
                .destination(PathBuf::from(DOCKER_RUN_TMPFS))
                .typ("tmpfs")
                .source(PathBuf::from("tmpfs"))
                .options(
                    DOCKER_RUN_TMPFS_OPTIONS
                        .iter()
                        .map(|o| (*o).to_string())
                        .collect::<Vec<String>>(),
                )
                .build()?,
        );
    }
    Ok(())
}
```

- [ ] **Step 5: Call it from `generate_spec`** — insert between `rebind_sys_mount(&mut spec);` and the `// USB passthrough:` comment:

```rust
    // Docker mode: a fresh tmpfs `/run` on every boot, so the engine's pid
    // files can never outlive an unclean stop (#214). BEFORE the USB/VNC
    // helpers below: the VNC secrets bind lives beneath /run and crun
    // mounts in array order.
    if params.docker {
        add_docker_run_tmpfs(&mut spec)?;
    }
```

- [ ] **Step 6: Run the unit tests**

Run: `source .cargo-env && cargo test -p izba-core runtime_config`
Expected: all pass, including the three new ones and every pre-existing docker/vnc/usb spec test (`usb_does_not_disturb_the_rest_of_the_spec`, `vnc_does_not_disturb_the_rest_of_the_spec`, `a_sandbox_without_vnc_has_stock_shm_and_no_vnc_mounts` must stay green — they assert on the non-docker shape, which is untouched).

- [ ] **Step 7: Add the CLAUDE.md bullet** after the "cgroup delegation + engine auto-start" bullet in the Docker-mode list (keep the list's 2-space indent + `- **…:**` shape):

```markdown
  - **Fresh `/run` per boot (#214):** the docker-mode OCI spec mounts a `tmpfs`
    over the container's `/run` (`add_docker_run_tmpfs`, ordered BEFORE the
    `/run/izba/*` binds — crun mounts in array order, so a later tmpfs would
    shadow the VNC secrets bind; guard-tested). Reason: the overlay upper is
    the persistent rw disk, so `docker.pid`/`containerd.pid` survived an
    unclean stop and the reused low PIDs made dockerd refuse to start on the
    next boot. Mainstream images symlink `/var/run → /run`, which crun
    resolves inside the rootfs, so dockerd's default pidfile paths land on
    the tmpfs; a real `/var/run` directory is NOT covered. Non-docker
    sandboxes keep `/run` on the image rootfs (guard-tested).
```

- [ ] **Step 8: Real-VM verification** (Bash sandbox DISABLED). First the Task 1 phase, which must now PASS end to end:

```sh
source .cargo-env
IZBA_INTEGRATION=1 \
IZBA_KERNEL=$HOME/.local/share/izba/artifacts/vmlinux \
IZBA_INITRAMFS=$HOME/.local/share/izba/artifacts/initramfs.cpio.gz \
IZBA_TEST_CACHE=$HOME/.cache/izba-itest \
cargo test -p izba-cli --test daemon_e2e docker_publish_reaches_inner_container -- --test-threads=1 --nocapture 2>&1 | tee /tmp/claude/e2e-214-after.log
```
Expected: `test result: ok. 1 passed`. Then the docker+VNC combination, which is where the mount ORDER is exercised for real (the VNC secrets bind beneath `/run` must still be visible to the desktop):

```sh
mkdir -p target/artifacts && cp ~/.local/share/izba/artifacts/kasmvnc.erofs target/artifacts/
IZBA_INTEGRATION=1 \
IZBA_KERNEL=$HOME/.local/share/izba/artifacts/vmlinux \
IZBA_INITRAMFS=$HOME/.local/share/izba/artifacts/initramfs.cpio.gz \
IZBA_TEST_CACHE=$HOME/.cache/izba-itest \
cargo test -p izba-cli --test daemon_e2e vnc_docker_e2e -- --test-threads=1 --nocapture 2>&1 | tee /tmp/claude/e2e-214-vnc-docker.log
```
Expected: `test result: ok. 1 passed` (NOT a `SKIP … kasmvnc.erofs not staged` line — that is a silent skip and does not count). Quote the `test result` lines of both runs in the report.

- [ ] **Step 9: The full gate set** (all must be green; the app gate matters because `runtime_config.rs` is embedded by `app/src-tauri`):

```sh
source .cargo-env
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
(cd app/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
```
Expected: every command exits 0. (`cargo test --workspace` runs unsandboxed too — some unit tests need `bind`; a sandboxed run can show EPERM-class failures that are not real.)

- [ ] **Step 10: Commit**

```bash
git add crates/izba-core/src/image/runtime_config.rs CLAUDE.md
git commit -m "fix(core): mount a fresh tmpfs over /run in docker mode

The workload's /run lived on the persistent rw disk (overlay upper), so
docker.pid/containerd.pid outlived an unclean stop; on the next boot the
same low PIDs existed again and dockerd refused to start, leaving the
sandbox permanently docker-less (no auto-restart). Mount a tmpfs over the
container's /run in the docker-mode OCI spec — ordered before the
/run/izba/* binds, which crun would otherwise see shadowed — so the pid
files structurally cannot persist. /var/run → /run is a symlink in every
mainstream base image and crun resolves it inside the rootfs. Non-docker
specs are unchanged (guard-tested).

Closes #214"
```

---

## Self-review

- **Spec coverage:** AC1 (unclean stop → `izba start` → engine up) = Task 1 phases `[5]`/`[6]` + Task 2 fix. AC2 (containerd.pid layer) = `docker info` only succeeds once containerd is up + the `is still running` log assertion covers both refusals. AC3 (symlink images still work) = phase `[7]` proves `/var/run → /run` on the Alpine dind image and that the engine works on it. AC4 (non-pid state preserved) = phase `[6b]` (`docker ps -a` still lists the pre-kill container). AC5 (e2e coverage) = Task 1. Out-of-scope items untouched: no auto-restart, nothing deleted from the rw disk, #207 untouched.
- **Placeholder scan:** none.
- **Type consistency:** `DOCKER_RUN_TMPFS`, `DOCKER_RUN_TMPFS_OPTIONS`, `add_docker_run_tmpfs` named identically across Task 2's steps and CLAUDE.md; `kill9`/`wait_pid_gone` used only in Task 1; `nested_id` defined in phase `[3]` before its use in `[6b]`.
