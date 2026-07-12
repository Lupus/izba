# Promote Restart-Leg Atomicity (#131) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An image/restart-class `promote` whose Stop/scratch-reset/Start leg fails must leave drift bookkeeping truthful (`repo == managed == base`, review token consumed) with an honest, actionable error — never a silent persistent `diverged`.

**Architecture:** Move the base-advance + review-token-clear into the same commit unit as `apply::write_managed` (before the restart leg) in `izba_core::manifest::promote::run_with_client`; wrap the restart-leg failures with context; map the new error strings to GUI copy in `ManifestTab.tsx` and mirror them in the dogfood oracle copy map.

**Tech Stack:** Rust (izba-core fake-daemon socketpair tests), React/TypeScript (Playwright mock spec), Python (dogfood oracle map).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-12-promote-restart-atomicity-design.md` — follow it verbatim, including exact error/copy strings.
- `promote.rs` must never print directly — every message via `on_event`/`emit_warn` (enforced by `promote_rs_never_prints_directly`).
- Success-path CLI output stays byte-identical: `promoted {name}` remains the LAST event; only disk writes move.
- Unit tests never bind unix/vsock listeners — use the existing `fake_daemon` (`UdsStream::pair()`) harness in `promote.rs` tests.
- Worktree toolchain: `export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo PATH=/home/kolkhovskiy/git/izba/.toolchain/cargo/bin:$PATH` before any cargo command.
- Rust gates for Task 1: `cargo test -p izba-core manifest::promote`, then `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`.
- App gate for Task 2: `cd app && npm ci && npm run build && npx playwright test e2e/manifest.spec.ts` (browsers may need `npx playwright install chromium`), plus `cd src-tauri && cargo fmt --check`.
- Conventional commits; never `git add -A`.

---

### Task 1: Core reorder + honest restart-leg errors (TDD)

**Files:**
- Modify: `crates/izba-core/src/manifest/promote.rs` (production: ~lines 391–462; tests: append to `mod tests`)

**Interfaces:**
- Consumes: existing test helpers in `promote.rs` `mod tests` — `fake_daemon`, `expect_inspect_reply`, `expect_and_ok`, `seed_managed`, `seed_cached_image`, `manifest_yaml`, `opts`, `no_build`; `store::{read_base, read_review, write_review, review_token}`; `crate::manifest::classify`, `DriftState`.
- Produces: exact error strings Task 2 maps in the GUI:
  - Start failure (existing, unchanged): `failed to start sandbox after promote (config already committed); run `izba start {name}` to retry: {err}`
  - Stop failure (new): `failed to stop sandbox for restart (the promote itself is committed; restart manually to apply): {err}`
  - scratch-reset failure (new): `failed to reset the rw scratch disk after promote (config already committed); run `izba start {name}` to retry: {err}`

- [ ] **Step 1: Write the two failing tests**

Append to `mod tests` in `promote.rs`. Both need a fake-daemon reply helper for an `Error` response — add alongside `expect_and_ok`:

```rust
    /// Read the next request, assert it matches `expect`, reply `Error{message}`.
    fn expect_and_error(
        s: &mut UdsStream,
        expect: impl Fn(&DaemonRequest) -> bool,
        what: &str,
        message: &str,
    ) {
        let req: DaemonRequest = read_frame(s).unwrap();
        assert!(expect(&req), "expected {what}, got {req:?}");
        write_frame(
            s,
            &DaemonResponse::Error {
                message: message.to_string(),
            },
        )
        .unwrap();
    }

    /// #131: a Start failure during the restart leg must NOT leave the drift
    /// bookkeeping diverged — the commit unit (config.json + manifest.base.yaml
    /// + consumed review token) lands before the lifecycle leg, so afterwards
    /// `izba diff` reports in-sync and `izba start` is the whole recovery.
    #[test]
    fn run_with_client_start_failure_still_advances_base() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml("newimg", 2, "");
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(&paths, "web", "testimg", 2, vec![], vec![], None);
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "newimg");
        // Give reset_rw_scratch a real rw.img (reset_scratch: true path).
        let f = std::fs::File::create(sandbox_dir.join("rw.img")).unwrap();
        f.set_len(64 << 20).unwrap();
        drop(f);

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "running");
            expect_and_ok(
                &mut s,
                |r| matches!(r, DaemonRequest::Stop { name } if name == "web"),
                "Stop",
            );
            expect_and_error(
                &mut s,
                |r| matches!(r, DaemonRequest::Start { name, .. } if name == "web"),
                "Start",
                "vmm exploded",
            );
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let err = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, true, true),
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("config already committed"), "{msg}");
        assert!(msg.contains("izba start web"), "{msg}");
        // The commit unit landed: base == repo manifest, token consumed.
        let base = store::read_base(&sandbox_dir).unwrap().expect("base written");
        let base_n = Normalized::from_manifest(&base, "web").unwrap();
        let repo_n = Normalized::from_manifest(
            &ops::load_repo_manifest(&repo_dir).unwrap().0,
            "web",
        )
        .unwrap();
        assert_eq!(base_n, repo_n, "base must record the promoted manifest");
        assert!(store::read_review(&sandbox_dir).unwrap().is_none());
        // Drift is in-sync, not diverged: managed was written before the leg.
        let managed = ops::managed_normalized(&paths, "web").unwrap();
        assert_eq!(
            crate::manifest::classify(&base_n, &repo_n, &managed),
            DriftState::InSync
        );
    }

    /// #131 (Stop leg): a Stop failure equally lands the commit unit first,
    /// with an error saying the promote itself is committed.
    #[test]
    fn run_with_client_stop_failure_still_advances_base() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let repo_dir = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let yaml = manifest_yaml("newimg", 2, "");
        std::fs::write(repo_dir.join("izba.yml"), &yaml).unwrap();
        let sandbox_dir = seed_managed(&paths, "web", "testimg", 2, vec![], vec![], None);
        let token = store::review_token(&yaml, None);
        store::write_review(&sandbox_dir, &token).unwrap();
        seed_cached_image(&paths, "newimg");

        let mut client = fake_daemon(|mut s| {
            expect_inspect_reply(&mut s, "web", "running");
            expect_and_error(
                &mut s,
                |r| matches!(r, DaemonRequest::Stop { name } if name == "web"),
                "Stop",
                "stop refused",
            );
        });
        let mut events: Vec<PromoteEvent> = Vec::new();
        let mut on_event = |e: PromoteEvent| events.push(e);
        let err = run_with_client(
            &paths,
            &repo_dir,
            "web",
            opts(false, true, true),
            &mut on_event,
            &mut no_build,
            &mut client,
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("the promote itself is committed"), "{msg}");
        let base = store::read_base(&sandbox_dir).unwrap().expect("base written");
        let base_n = Normalized::from_manifest(&base, "web").unwrap();
        assert_eq!(
            base_n.image,
            ImageSource::Ref("newimg".into()),
            "base must record the promoted manifest"
        );
        assert!(store::read_review(&sandbox_dir).unwrap().is_none());
    }
```

(If `Normalized`/`DriftState`/`ImageSource`/`ops` aren't already in scope in
`mod tests`, they are importable from `super::*` — check the top of the test
module; `ImageSource` comes via `crate::manifest::normalize::ImageSource`,
already `use`d by the production code.)

- [ ] **Step 2: Run the new tests, verify they FAIL for the right reason**

Run: `cargo test -p izba-core manifest::promote::tests::run_with_client_start_failure_still_advances_base manifest::promote::tests::run_with_client_stop_failure_still_advances_base` (or `cargo test -p izba-core run_with_client_st` to catch both).
Expected: both FAIL — `base written` panics (`read_base` is `None`: today the base never advances on the failure path) for the first; the second additionally fails the "promote itself is committed" assert.

- [ ] **Step 3: Implement the reorder + error contexts**

In `run_with_client` production code:

1. Immediately after `apply::write_managed(paths, name, &repo, &digest)?;` insert:

```rust
    // #131: advance the base + consume the review token in the SAME commit
    // unit as config.json/policy.yaml above — all four record one fact,
    // "this manifest revision was promoted". The restart leg below is a
    // lifecycle action on already-committed config: if it fails, `izba diff`
    // stays in-sync (repo == managed == base) and `izba start` is the whole
    // recovery — never a diverged state no user edit explains.
    store::write_base(&dir_managed, &m)?;
    store::clear_review(&dir_managed)?;
```

2. Delete the old `store::write_base(&dir_managed, &m)?;` and
   `store::clear_review(&dir_managed)?;` lines near the end (keep the
   `on_event(PromoteEvent::Info(format!("promoted {name}")));` exactly where
   it is — success-path event ordering is byte-identical).

3. Wrap the Stop RPC (the `if is_running { send_ok(... Stop ...)? }` inside
   the restart branch):

```rust
            if is_running {
                if let Err(err) = send_ok(
                    client,
                    &DaemonRequest::Stop {
                        name: name.to_string(),
                    },
                    &mut warnings,
                    on_event,
                ) {
                    bail!(
                        "failed to stop sandbox for restart (the promote itself \
                         is committed; restart manually to apply): {err}"
                    );
                }
            }
```

4. Wrap the scratch reset:

```rust
            if p.image_changed && reset_scratch {
                if let Err(err) = crate::sandbox::reset_rw_scratch(paths, name) {
                    bail!(
                        "failed to reset the rw scratch disk after promote \
                         (config already committed); run `izba start {name}` \
                         to retry: {err}"
                    );
                }
            }
```

5. The Start-failure `bail!` keeps its existing message verbatim.

6. Update the atomicity doc-comment at the top of the `if is_running` live-RPC
   block to describe the two-phase contract (live RPCs → commit unit → lifecycle
   leg) and cite #131.

- [ ] **Step 4: Run the module tests, then the full gates**

Run: `cargo test -p izba-core manifest::promote` — all pass (new + existing;
the existing `run_with_client_*` success-path tests double as the
byte-parity regression net).
Then: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`.
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/manifest/promote.rs
git commit -m "fix(core): promote advances the base with the managed config, before the restart leg

A failing Stop/scratch-reset/Start no longer strands the sandbox in a
persistent diverged drift state: the commit unit (config.json +
policy.yaml + manifest.base.yaml + consumed review token) lands before
the lifecycle leg, whose failures now carry honest recovery hints.

Fixes #131"
```

---

### Task 2: GUI copy for the new restart-leg errors + oracle mirror

**Files:**
- Modify: `app/src/components/ManifestTab.tsx` (mapPromoteError block, ~lines 60–84)
- Modify: `app/e2e/manifest.spec.ts` (one new spec alongside the existing promote-error specs)
- Modify: `hack/dogfood/gui/gui_oracles.py` (`_ERROR_COPY_MAP`)

**Interfaces:**
- Consumes: Task 1's exact error strings (see Task 1 "Produces").
- Produces: GUI copy constants `PROMOTE_START_FAILED_ERROR` / `PROMOTE_STOP_FAILED_ERROR` (referenced by the spec test and the oracle map).

- [ ] **Step 1: Write the failing Playwright spec**

In `app/e2e/manifest.spec.ts`, next to the existing promote-error mapping
spec(s) (grep for `mapPromoteError`-related copy like "Review the diff
first"), add — following the file's existing mock/setup helpers exactly:

```ts
test("promote start-failure renders the friendly committed-but-not-started copy", async ({ page }) => {
  // Arrange the same image-drift mock state the existing promote specs use,
  // but make manifest_promote reject with the core's start-failure message.
  await setupManifestMock(page, {
    diff: IMAGE_DRIFT_DIFF,
    promoteError:
      "failed to start sandbox after promote (config already committed); run `izba start web` to retry: vmm exploded",
  });
  await openManifestTab(page);
  await tickPromoteCheckboxesAndConfirm(page);
  await expect(
    page.getByText(
      "Promoted, but the sandbox failed to start on the new configuration. Use Start on the sandbox to retry.",
    ),
  ).toBeVisible();
});
```

**Adapt the helper names to what `manifest.spec.ts` actually defines** (read
the file first — it has an established mock-injection pattern via
`window.__MOCK_MANIFEST__` and per-spec promote rejection wiring; reuse it
verbatim rather than inventing new helpers). Add a sibling spec for the
stop-failure string mapping to
`"Promoted, but the sandbox could not be stopped to apply restart-class changes. Stop and Start it manually."`.

- [ ] **Step 2: Run the spec, verify it fails**

Run: `cd app && npm ci && npx playwright install chromium && npx playwright test e2e/manifest.spec.ts`
Expected: the two new specs FAIL (raw CLI-speak message rendered instead of the mapped copy).

- [ ] **Step 3: Implement the mapping**

In `ManifestTab.tsx`, alongside the existing constants:

```ts
const PROMOTE_START_FAILED_ERROR =
  "Promoted, but the sandbox failed to start on the new configuration. Use Start on the sandbox to retry.";
const PROMOTE_STOP_FAILED_ERROR =
  "Promoted, but the sandbox could not be stopped to apply restart-class changes. Stop and Start it manually.";
```

And in `mapPromoteError`, before the fallthrough `return message;`:

```ts
  if (message.includes("failed to start sandbox after promote")) return PROMOTE_START_FAILED_ERROR;
  if (message.includes("failed to stop sandbox for restart")) return PROMOTE_STOP_FAILED_ERROR;
```

- [ ] **Step 4: Mirror in the dogfood oracle copy map**

In `hack/dogfood/gui/gui_oracles.py`, add to `_ERROR_COPY_MAP` (matching its
existing `(needle, expected_copy)` shape exactly):

```python
    ("failed to start sandbox after promote",
     "Promoted, but the sandbox failed to start on the new configuration. Use Start on the sandbox to retry."),
    ("failed to stop sandbox for restart",
     "Promoted, but the sandbox could not be stopped to apply restart-class changes. Stop and Start it manually."),
```

Run the dogfood harness unit tests: `python -m pytest hack/dogfood/ -q` (or the
repo's documented invocation — check `hack/dogfood/local-harness.md`).

- [ ] **Step 5: Run the full app gate**

Run: `cd app && npm run build && npx playwright test e2e/manifest.spec.ts && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`
Expected: all green (Task 1 touched izba-core, so the src-tauri gate matters here).

- [ ] **Step 6: Commit**

```bash
git add app/src/components/ManifestTab.tsx app/e2e/manifest.spec.ts hack/dogfood/gui/gui_oracles.py
git commit -m "fix(app): friendly copy for promote restart-leg failures (#131)

Maps the core's committed-but-not-restarted errors to GUI copy instead
of leaking 'izba start <name>' CLI-speak; mirrors the strings in the
dogfood oracle copy map."
```
