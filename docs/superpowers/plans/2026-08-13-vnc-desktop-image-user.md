# VNC Desktop Runs As The Image User — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The KasmVNC desktop (X server + izba-session stack) runs as the container's configured user (image `USER`, e.g. `agent`) instead of container root, per `docs/superpowers/specs/2026-08-13-vnc-desktop-image-user-design.md`.

**Architecture:** Two-line semantic change in `izba-init`'s `vnc.rs` (`crun exec` with `user: None` inherits the OCI spec's `process.user`, exactly like default `izba exec`), plus the root-run stale-display cleanup exec growing into the ground-preparation step (writable X socket dir, pre-created 666 log, legacy root-owned state removal). Proven by unit pins on the argvs and a new KVM e2e leg booting a digest-pinned `USER 101` image.

**Tech Stack:** Rust (izba-init, izba-cli e2e), crun OCI exec, KasmVNC.

## Global Constraints

- `[ -f .cargo-env ] && source .cargo-env` before any cargo command.
- All six workspace gates green before every commit: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`, `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`, `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`. (For per-task speed, `cargo test -p izba-init` / `-p izba-cli` + fmt + clippy on the touched crate is enough mid-task; the full six run in the final task.)
- Conventional commits; TDD (write the failing test, watch it fail, then implement).
- Unit tests never bind unix/vsock listeners.
- KVM suites need the Bash sandbox disabled (`/dev/kvm` is invisible inside the sandbox, but works — never conclude "no KVM").
- Working directory: `/home/kolkhovskiy/git/izba/.claude/worktrees/vnc-desktop-image-user` (branch `worktree-vnc-desktop-image-user`).

---

### Task 1: Desktop spawns inherit the container's configured user

**Files:**
- Modify: `crates/izba-init/src/vnc.rs` (`desktop_exec_argvs` + its doc comment + module doc; tests `desktop_exec_argvs_runs_server_then_wm_as_root_with_honest_logging`)

**Interfaces:**
- Consumes: `crate::oci::crun_exec_argv(cgroup_manager, tty, cwd, env, user: Option<&str>, argv)` — `None` means "no `--user` flag, crun applies the container's configured `process.user`" (see `crates/izba-init/src/exec.rs::crun_user_arg` for the precedent).
- Produces: `desktop_exec_argvs` emitting argvs with **no** `--user` flag. Task 3's e2e relies on this behavior.

- [ ] **Step 1: Flip the unit test to expect no `--user`**

In `crates/izba-init/src/vnc.rs`, rename the test `desktop_exec_argvs_runs_server_then_wm_as_root_with_honest_logging` to `desktop_exec_argvs_runs_server_then_wm_as_the_image_user_with_honest_logging` and replace its `--user 0:0` window assertion and the `--user`-precedes-id ordering check with:

```rust
assert!(
    !argv.iter().any(|a| a == "--user"),
    "desktop must inherit the container's configured user (the image \
     USER, like a default `izba exec`), never a pinned uid: {argv:?}"
);
```

Keep the rest of the test (crun path, `exec` subcommand, container-id positional presence, `VNC_LOG` in the trailing script, server/wm script content) intact. The container-id `id_pos` lookup can stay for the positional-presence assertion; only the `--user` ordering line goes.

- [ ] **Step 2: Run the test to verify it fails**

Run: `source .cargo-env 2>/dev/null; cargo test -p izba-init vnc:: -- --nocapture 2>&1 | tail -20`
Expected: FAIL — the argvs still carry `--user 0:0`.

- [ ] **Step 3: Implement — pass `user: None` for both desktop spawns**

In `desktop_exec_argvs`, change both `crun_exec_argv(...)` calls from `Some("0:0")` to `None`. Rewrite the doc-comment paragraph that currently reads "Both run as **container root** (`--user 0:0`, the dockerd precedent) …" to:

```text
Both run as the **container's configured user** — the OCI spec's
`process.user`, which izba-core's `resolve_process_user` filled from the
image `USER` (uid, primary gid, supplementary groups). Passing no `--user`
is what selects it: crun then applies the container's own process user,
exactly like a default `izba exec`. An image with no `USER` (alpine) keeps
a root desktop; a `USER agent` image gets its desktop — and everything
launched from it — as `agent`, matching exec/ssh (spec 2026-08-13).
Ground the desktop needs but cannot create unprivileged (the X socket
dir, the log file, the `/tmp` XDG parents) is prepared by the root-run
cleanup exec ([`stale_display_cleanup_argv`]), which is awaited first.
```

Also update the module doc's item 2 ("init `crun exec`s the KasmVNC X server and a window manager inside it") to say "…inside it, as the image's configured user".

- [ ] **Step 4: Run the izba-init suite**

Run: `cargo test -p izba-init`
Expected: PASS (all tests, not just the flipped one).

- [ ] **Step 5: fmt + clippy on the touched crate, then commit**

Run: `cargo fmt && cargo clippy -p izba-init --all-targets -- -D warnings`

```bash
git add crates/izba-init/src/vnc.rs
git commit -m "feat(init): run the VNC desktop as the image user, not container root

crun exec with no --user applies the container's configured process.user
(the image USER, its primary gid and supplementary groups) — the same
resolution a default izba exec already gets. Root-USER images keep a root
desktop; a USER agent image now gets its desktop as agent.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Cleanup exec prepares non-root-writable ground

**Files:**
- Modify: `crates/izba-init/src/vnc.rs` (`stale_display_cleanup_argv` + its doc comment; new consts; tests)

**Interfaces:**
- Consumes: nothing new.
- Produces: `stale_display_cleanup_argv` (same signature) whose script additionally chmods `/tmp/.X11-unix` 1777, pre-creates `VNC_LOG` mode 666, removes the legacy root-owned desktop state, and makes `/tmp/.config` + `/tmp/.cache` 1777. New module const `LEGACY_ROOT_STATE: &str`.

- [ ] **Step 1: Write the failing tests**

Add to `crates/izba-init/src/vnc.rs` tests:

```rust
/// The desktop now runs unprivileged (see `desktop_exec_argvs`), so the
/// root-run cleanup is the only thing that can make its ground writable:
/// the X socket dir, the append-only log, and the XDG parents under
/// HOME=/tmp — plus removal of the root-owned state a pre-change (root
/// desktop) boot left in the persistent overlay, which would otherwise be
/// unwritable by the image user forever (dead desktop after an upgrade).
#[test]
fn stale_display_cleanup_prepares_nonroot_ground() {
    let argv = stale_display_cleanup_argv(crate::oci::CgroupManager::Cgroupfs);
    let script = argv.last().unwrap();
    assert!(
        script.contains("chmod 1777 /tmp/.X11-unix /tmp/.config /tmp/.cache"),
        "a non-root X server/session must be able to create the socket and \
         its XDG subdirs: {script}"
    );
    assert!(
        script.contains(&format!("[ -e {VNC_LOG} ] || : > {VNC_LOG}")),
        "the log must exist before an unprivileged writer appends — and an \
         existing log must NOT be truncated: {script}"
    );
    assert!(
        script.contains(&format!("chmod 666 {VNC_LOG}")),
        "any image uid must be able to append to the honest log: {script}"
    );
    assert!(
        script.contains(&format!("rm -rf {LEGACY_ROOT_STATE}")),
        "root-owned desktop state from pre-change boots must go: {script}"
    );
    // The removal must precede the mkdir/chmod that rebuilds the parents.
    let rm = script.find("rm -rf").unwrap();
    let chmod = script.find("chmod 1777").unwrap();
    assert!(rm < chmod, "legacy removal must come first: {script}");
    // Still container root: it is what deletes root-owned legacy files.
    assert!(
        argv.windows(2).any(|w| w[0] == "--user" && w[1] == "0:0"),
        "cleanup must stay root — it removes root-owned leftovers: {argv:?}"
    );
}

/// The font cache the cleanup clears must be the path the bundle's
/// generated fonts.conf actually uses — pinned against
/// hack/build-kasmvnc-erofs.sh, the single place that writes it.
#[test]
fn legacy_font_cache_path_matches_the_bundle_fonts_conf() {
    let sh = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../hack/build-kasmvnc-erofs.sh"
    ))
    .expect("hack/build-kasmvnc-erofs.sh readable from the workspace");
    assert!(
        sh.contains("<cachedir>/tmp/izba-vnc-fontcache</cachedir>"),
        "bundle fonts.conf cachedir moved — update LEGACY_ROOT_STATE too"
    );
    assert!(
        LEGACY_ROOT_STATE.contains("/tmp/izba-vnc-fontcache"),
        "cleanup must clear the bundle's font cache: {LEGACY_ROOT_STATE}"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-init vnc:: 2>&1 | tail -20`
Expected: FAIL — `LEGACY_ROOT_STATE` undefined (compile error). That is the honest red for a const-driven script.

- [ ] **Step 3: Implement the ground preparation**

Add above `stale_display_cleanup_argv`:

```rust
/// Space-separated izba-owned desktop state a pre-change (root-desktop)
/// boot may have left root-owned in the persistent overlay's `/tmp`,
/// removed by the cleanup exec on every start so the image user can
/// recreate it: the seeded lxpanel/pcmanfm profile parents
/// (`izba-session` re-seeds them from the bundle), the generated
/// Applications-menu cache, and the fontconfig cache (path pinned against
/// `hack/build-kasmvnc-erofs.sh`'s fonts.conf by a drift test). Never
/// user state — all four are regenerated on every desktop start.
const LEGACY_ROOT_STATE: &str =
    "/tmp/.config/lxpanel /tmp/.config/pcmanfm /tmp/.cache/menus /tmp/izba-vnc-fontcache";
```

Replace the script in `stale_display_cleanup_argv` with:

```rust
format!(
    // `rm -f`/`rm -rf` never fail on an absent path, so a first boot is
    // a clean no-op. Removal goes FIRST: mkdir/chmod then rebuild the
    // parents any-uid-writable (1777 under an already-1777 /tmp). The log
    // is created empty iff absent (`: >` would truncate an existing one)
    // and opened up to 666 so the unprivileged desktop can append.
    "rm -f {X_LOCK} {X_SOCKET}; \
     rm -rf {LEGACY_ROOT_STATE}; \
     mkdir -p /tmp/.X11-unix /tmp/.config /tmp/.cache /var/log; \
     chmod 1777 /tmp/.X11-unix /tmp/.config /tmp/.cache; \
     [ -e {VNC_LOG} ] || : > {VNC_LOG}; chmod 666 {VNC_LOG}; true"
)
```

Extend the function's doc comment with a short paragraph:

```text
Since the desktop dropped container root (spec 2026-08-13), this exec is
also the GROUND PREPARATION for an unprivileged desktop: it makes the X
socket dir and the `/tmp` XDG parents any-uid-writable, pre-creates the
log file mode 666 (an image uid cannot create files under `/var/log`),
and removes the root-owned desktop state a pre-change boot left in the
persistent overlay — without which an upgraded sandbox's desktop is dead
on arrival. It stays `--user 0:0` deliberately: root is what can delete
those legacy files.
```

Check the two pre-existing cleanup tests still hold verbatim (`rm -f {X_LOCK} {X_SOCKET}` and `mkdir -p /tmp/.X11-unix` are still substrings of the new script — they are, since the combined `mkdir -p` starts with `/tmp/.X11-unix`).

- [ ] **Step 4: Run the izba-init suite**

Run: `cargo test -p izba-init`
Expected: PASS.

- [ ] **Step 5: fmt + clippy, then commit**

Run: `cargo fmt && cargo clippy -p izba-init --all-targets -- -D warnings`

```bash
git add crates/izba-init/src/vnc.rs
git commit -m "feat(init): vnc cleanup exec prepares ground for the unprivileged desktop

The root-run stale-display cleanup now also chmods the X socket dir and
/tmp XDG parents 1777, pre-creates /var/log/izba-vnc.log mode 666 (path
contract unchanged), and removes the root-owned desktop state a
pre-change boot left in the persistent overlay — an upgraded sandbox's
desktop would otherwise be dead on arrival.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: e2e — the desktop provably runs as the image USER

**Files:**
- Modify: `crates/izba-cli/tests/daemon_e2e.rs` (new helper `desktop_proc_uids`, a uid-0 assertion in `vnc_desktop_e2e`, new test `vnc_desktop_runs_as_image_user_e2e`)

**Interfaces:**
- Consumes: existing helpers in the same file — `izba(data, env, args)`, `assert_ok`, `stdout_of`, `parse_vnc_url`, `prove_desktop_session(data, name, port, password, phase)`, `assert_desktop_procs(data, name, phase)`, `vnc_bundle_path()`, `vnc_diag`, `SandboxGuard`, `want()`.
- Produces: nothing downstream.

- [ ] **Step 1: Write the helper and the two test changes**

Add near `assert_desktop_procs`:

```rust
/// Real uids of every container process whose `/proc/<pid>/comm` equals
/// `comm`, via `izba exec`. Matching on comm (exact file content) rather
/// than cmdline is what keeps the probe from matching ITSELF: the probe's
/// own argv carries the target name as literal script text, but its comm
/// is `sh` — the same self-satisfaction trap `menu_cache_entries`
/// documents. Every substitution is a test-literal process name; nothing
/// host-derived reaches the `sh -c`.
fn desktop_proc_uids(data: &Path, name: &str, comm: &str) -> Vec<u32> {
    let script = format!(
        "for p in /proc/[0-9]*; do \
           [ \"$(cat \"$p/comm\" 2>/dev/null)\" = \"{comm}\" ] || continue; \
           awk '/^Uid:/{{print $2}}' \"$p/status\"; \
         done; true"
    );
    let o = izba(data, &[], &["exec", name, "--", "sh", "-c", &script]);
    assert_ok(&o, "read desktop process uids");
    stdout_of(&o)
        .split_whitespace()
        .map(|s| s.parse().expect("uid must be numeric"))
        .collect()
}
```

In `vnc_desktop_e2e`, directly after the first `assert_desktop_procs(&data, name, "fresh")`-style call (grep for the call with the fresh/first phase), add:

```rust
// alpine declares no USER, so the configured user is root: the desktop
// must still run as uid 0 — a no-USER image keeps its exact behavior
// (the image-user change is proven by vnc_desktop_runs_as_image_user_e2e).
let uids = desktop_proc_uids(&data, name, "Xkasmvnc");
assert!(
    !uids.is_empty() && uids.iter().all(|u| *u == 0),
    "no-USER image must keep a root desktop, got uids {uids:?}\n{}",
    vnc_diag(&data, name)
);
```

Add the new test after `vnc_desktop_e2e`:

```rust
/// The desktop runs as the image's configured USER, not container root —
/// the user-visible promise: in a `USER agent`-style image, the X server,
/// window manager, and everything launched from the desktop are the same
/// identity `izba exec`/ssh already get. Boots the digest-pinned
/// `nginxinc/nginx-unprivileged` (`USER 101`, the repo's standing non-root
/// fixture — see izba-core's userns_numeric_user_owns_workspace) with
/// `--vnc`, holds the desktop to the same working-session bar as the
/// alpine flow (a session that WORKS as uid 101, not merely processes that
/// exist), then reads each component's uid off /proc.
#[test]
fn vnc_desktop_runs_as_image_user_e2e() {
    if !want() {
        return;
    }
    assert!(
        std::env::var_os("IZBA_KASMVNC_EROFS").is_none(),
        "this e2e must prove production discovery — unset IZBA_KASMVNC_EROFS"
    );
    let bundle = vnc_bundle_path();
    if !bundle.as_deref().map(Path::exists).unwrap_or(false) {
        eprintln!(
            "SKIP vnc_desktop_runs_as_image_user_e2e: kasmvnc.erofs not staged — \
             run hack/build-kasmvnc-erofs.sh and copy dist/kasmvnc.erofs to the \
             exe-relative artifacts dir"
        );
        return;
    }
    // Pinned digest of nginxinc/nginx-unprivileged:alpine (USER 101) — the
    // same fixture izba-core's integration suite pins; digest-pinning keeps
    // the test reproducible if the floating tag is re-pushed.
    const UNPRIV_IMAGE: &str = "nginxinc/nginx-unprivileged@sha256:054e14f543eb688809d59ec2ad1644d1a61678e247c87a318ad605977eb37eaf";

    let root = tempfile::tempdir().unwrap();
    let data: PathBuf = root.path().join("izba");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let ws_s = ws.to_string_lossy().into_owned();
    let no_env: &[(&str, &str)] = &[];
    let name = "vnc-unpriv";
    let _guard = SandboxGuard {
        data: data.clone(),
        name,
    };

    let o = izba(
        &data,
        no_env,
        &["create", "--vnc", "--image", UNPRIV_IMAGE, "--name", name, &ws_s],
    );
    assert_ok(&o, "create --vnc (USER 101 image)");
    let o = izba(&data, no_env, &["start", name]);
    assert_ok(&o, "start (vnc, USER 101 image)");

    let o = izba(&data, no_env, &["vnc", "url", name]);
    assert_ok(&o, "vnc url");
    let url = stdout_of(&o).trim().to_string();
    let (password, port) = parse_vnc_url(&url);

    // Same bar as the alpine flow: a real credentialed websocket/RFB
    // session, then the full component set live.
    prove_desktop_session(&data, name, port, &password, "unpriv");
    assert_desktop_procs(&data, name, "unpriv");

    for comm in ["Xkasmvnc", "openbox"] {
        let uids = desktop_proc_uids(&data, name, comm);
        assert!(
            !uids.is_empty(),
            "[unpriv] no live {comm} process found\n{}",
            vnc_diag(&data, name)
        );
        assert!(
            uids.iter().all(|u| *u == 101),
            "[unpriv] {comm} must run as the image USER 101, got {uids:?}\n{}",
            vnc_diag(&data, name)
        );
    }
}
```

Adjust names/details to the file's actual local style if a helper differs (e.g. the exact phase strings used by the first `assert_desktop_procs` call) — but keep the assertions and the comm-based matching exactly as above.

- [ ] **Step 2: Verify it compiles and self-skips**

Run: `cargo test -p izba-cli --test daemon_e2e vnc -- --list 2>&1 | tail -5` then `cargo test -p izba-cli --test daemon_e2e vnc_desktop_runs_as_image_user_e2e`
Expected: compiles; test returns immediately (env-gated `want()` false in this shell). The real run happens in Task 5.

- [ ] **Step 3: fmt + clippy, then commit**

Run: `cargo fmt && cargo clippy -p izba-cli --all-targets -- -D warnings`

```bash
git add crates/izba-cli/tests/daemon_e2e.rs
git commit -m "test(e2e): prove the VNC desktop runs as the image USER

New KVM e2e boots the digest-pinned nginx-unprivileged (USER 101) with
--vnc, holds the desktop to the same working-session bar as the alpine
flow, and reads each component's uid off /proc/<pid>/status matched by
comm (cmdline matching would let the probe satisfy itself). The alpine
flow gains the inverse pin: a no-USER image keeps a root desktop.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Docs sweep — retire the "runs as root" claims

**Files:**
- Modify: `docs/superpowers/specs/2026-08-09-vnc-display-design.md` (amendment note at the "container root" decision site)
- Modify: `docs/superpowers/specs/2026-08-11-vnc-desktop-environment-design.md` (only if it repeats the root claim — grep first)
- Modify: `README.md` (only if its VNC section mentions the desktop running as root — grep first)

**Interfaces:** none (docs only).

- [ ] **Step 1: Find every stale claim**

Run: `grep -rn "root" docs/superpowers/specs/2026-08-09-vnc-display-design.md docs/superpowers/specs/2026-08-11-vnc-desktop-environment-design.md README.md | grep -iv "rootfs\|root menu\|root window\|root-window"`
Read each hit in context; only statements that the desktop/X server/session **processes run as container root** count.

- [ ] **Step 2: Amend, don't rewrite**

Historical specs stay as decided-then; under each such statement add a one-line amendment:

```markdown
> **Amendment (2026-08-13):** superseded — the desktop now runs as the
> image's configured `USER`, see
> [2026-08-13-vnc-desktop-image-user-design.md](2026-08-13-vnc-desktop-image-user-design.md).
```

README (if hit): update the sentence itself to say the desktop runs as the image's configured user (the same identity `izba exec` gets).

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/ README.md
git commit -m "docs: VNC desktop user amendments — image USER, not container root

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Verification — six gates + real-VM KVM e2e

**Files:** none new (fixes only if something is red).

- [ ] **Step 1: All six workspace gates**

Run (from the worktree root, `source .cargo-env` first):
1. `cargo test --workspace`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo fmt --check`
4. `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`
5. `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`
6. `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`
Expected: all green. (izba-core/izba-proto public types untouched, so the app gate is not required — verify with `git diff main --stat -- crates/izba-core crates/izba-proto` showing no hits.)

- [ ] **Step 2: Stage artifacts for the KVM run**

The e2e needs kernel/initramfs/CH artifacts plus `kasmvnc.erofs` at the exe-relative `target/debug/../artifacts/` (i.e. `target/artifacts/`). Check the main checkout first: `ls /home/kolkhovskiy/git/izba/target/artifacts/` — if populated, copy (or symlink) into the worktree's `target/artifacts/`. Otherwise run `hack/fetch-artifacts.sh` (see `hack/README.md`) and `hack/build-kasmvnc-erofs.sh`. The initramfs must carry Task 1/2's izba-init: rebuild it after the musl build (`hack/build-initramfs.sh` — check `hack/README.md` for the exact invocation and env).

- [ ] **Step 3: Run the VNC e2e tests on real KVM (sandbox disabled)**

Run: `IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e vnc_desktop -- --test-threads=1 --nocapture`
Expected: `vnc_desktop_e2e` AND `vnc_desktop_runs_as_image_user_e2e` both PASS (not SKIP — watch stderr for the skip lines; a skip is a failed verification, fix the staging).
This is the load-bearing proof (USB post-mortem rule: a green static board is not proof for a feature that only manifests in a real VM).

- [ ] **Step 4: Commit any fixes; update the plan checkboxes**

If the e2e surfaced product bugs, fix them TDD-style (failing unit test first where expressible) and re-run Step 3 until green.
