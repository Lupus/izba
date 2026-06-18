# Tauri app UX improvements — design

**Date:** 2026-06-18
**Status:** approved
**Scope:** `app/` (React frontend + `app/src-tauri` backend). One Rust change
(item 2) lives in `app/src-tauri`, so the **App CI** gate must be run locally.

A punch list of six UX papercuts in the desktop app, each with an approved
approach. Items are independent and can land in any order.

## 1. Daemon startup — three-state status

**Problem.** `usePolling` starts at `daemon = null, error = null`. `TopBar`
treats *anything that is not an error* as green "daemon running", so the very
first frame — before the first poll resolves, while `izbad` is still spinning up
under `connect_spawning_izba` — is mislabeled "daemon running" with a blank
version. Sandboxes and version then pop in a beat later.

**Design.**
- Extend `PollState` (`app/src/lib/store.ts`) with
  `phase: "connecting" | "ready" | "unreachable"`. Initial value `"connecting"`.
  The phase leaves `"connecting"` only after the **first** poll settles:
  success → `"ready"`, failure → `"unreachable"`. Later polls flip between
  `ready`/`unreachable` exactly as today. Keep `daemon`/`error` as-is for
  backward compat with other consumers.
- `TopBar` (`app/src/components/TopBar.tsx`) renders by phase:
  - `connecting` → neutral/gray **pulsing** dot + "Connecting…"
  - `ready` → green dot + `daemon running · v{version}`
  - `unreachable` → orange dot + "daemon unreachable"
  It never renders "running" until a real status has arrived.
- Add a small shared **Spinner** primitive (`app/src/components/Spinner.tsx`) —
  a CSS-animated dot/ring — reused by item 4. (The "connecting" pulsing dot can
  be a Tailwind `animate-pulse` on the dot; the spinner primitive is mainly for
  the buttons in item 4. Use whichever reads best; both are trivial.)

**Why `connecting` is reachable:** `RealDaemon::with_client` calls
`DaemonClient::connect_spawning_izba`, which spawns `izba daemon run` and blocks
on the first connect. So the first `Promise.all([list, status])` is genuinely
*pending* (not erroring) during boot — the connecting state shows, then flips to
green when status arrives. If the spawn/connect fails it errors → unreachable.

## 2. Build-mismatch warning — compare git identity only

**Problem.** `version_core` (`app/src-tauri/src/commands.rs:31`) computes
`mismatch = build != app`, a full `BuildInfoOwned` struct compare over all 8
fields including `build_timestamp`. The app and daemon are separate binaries
built at different instants, so `build_timestamp` (and possibly `rustc`) always
differs even for the identical commit → the ⚠ warning is effectively always on.

**Design.** Compare git identity only:
```rust
let mismatch = build.git_describe != app.git_describe;
```
`git_describe` encodes `<tag>-<n>-g<sha>[-dirty]`, so the same commit (regardless
of build timestamp / rustc / target / profile) produces no warning, while a
different commit or a `-dirty` tree flags ⚠.

**Tests** (`app/src-tauri/src/commands.rs`):
- `version_core_flags_mismatch_when_daemon_differs` already sets a distinct
  daemon sha → `git_describe` differs → still passes; keep it.
- Add a no-mismatch case where the daemon's `git_describe` equals the app's
  (e.g. a fake that reports the app's own describe) → asserts `!v.mismatch`.

## 3. Shell tab persistence

**Problem.** `ShellPanel`'s `activeId` is local component state. `Detail`
conditionally renders the Shell tab, so leaving for Netlog unmounts `ShellPanel`
and loses `activeId`; on return its mount effect re-selects
`all[all.length - 1]` (the newest shell). Result: it always reopens "Shell 2".

**Design.** Persist the active shell per sandbox in `shellStore`
(`app/src/lib/shellStore.ts`):
- Add `activeBySandbox: Record<string, string>` with `getActive(sandbox)` /
  `setActive(sandbox, id)` accessors (module-level, like the existing session
  store).
- `ShellPanel`: on selection (`onClick`) call `setActive`. On mount, restore
  `getActive(sandbox)` if it still maps to a live session; otherwise fall back to
  newest (current behaviour). Clear/repair the entry when a session closes so a
  stale id never sticks.

Switching to Netlog and back now reopens the shell you left on.

## 4. Start/stop/restart spinner

**Problem.** During a transition the buttons disable (`disabled:opacity-50`) but
give no positive "working" signal.

**Design.** In `Detail` (`app/src/components/Detail.tsx`):
- Track which action is in flight. Extend `act()` to take a label, e.g.
  `act("stop", fn)`, storing `busyAction: "start" | "stop" | "restart" | "remove" | null`
  instead of a bare `busy` boolean (`busy === busyAction !== null`).
- The triggering button shows the item-1 `Spinner` + present-progressive verb
  ("Stopping…", "Starting…", "Restarting…", "Removing…"); the other buttons
  stay disabled as today.

## 5. Policy-tab "add port" (`PolicyEditor` inline `PortEditor`)

**Problem.** `PortEditor` (`app/src/components/PolicyEditor.tsx:16-65`) only
commits on **Enter** — no button, no hint — and `commit()` silently swallows
non-numeric / out-of-range input (clears the draft, nothing added). The user
can't tell how to confirm and can type `sdfsdf` with no feedback.

**Design.**
- Add a visible **Add** button beside the field (Enter continues to work).
- On invalid input — non-integer, outside 1–65535, or duplicate of an existing
  port — show an inline error message and **keep** the draft text so it can be
  corrected, instead of silently clearing.
- Clear the error and the draft on a successful add.

## 6. Creation-wizard port rows (`NewSandbox`)

**Problem.** The wizard port row (`app/src/components/NewSandbox.tsx:157-203`)
uses a cryptic `placeholder="127.0.0.1 (optional)"` for the bind field with no
explanation, and host/guest accept any string (`sdfsdf`) with no validation —
the backend rejects it only at create time.

**Design.**
- Replace the placeholder-as-documentation with clear column headers above the
  rows — **Bind (optional)**, **Host port**, **Guest port** — plus a one-line
  hint that bind defaults to `127.0.0.1` when left empty.
- Validate per row: host and guest must be integers in 1–65535; bind is
  optional (any non-empty string is passed through to the backend, which
  validates the address). Show a per-row inline error and **disable Create**
  while any partially-filled row is invalid. A fully-empty row is still ignored
  (current behaviour) so a stray "+ Add port" click can't block submit.

## Out of scope

- Port-forwarding management for **running** sandboxes — no UI exists today and
  it was not requested. The wizard remains the only place to declare ports.
- Any change to the daemon wire protocol or `izba-core` public types.

## Verification

- Frontend unit tests for the new store/validation logic where practical
  (vitest, per the SonarCloud coverage gate — `app/` must feed lcov).
- The Rust change (item 2) is covered by `commands.rs` unit tests.
- Run the **App CI** gate locally before committing, per `CLAUDE.md`:
  `cd app && npm ci && npm run build && (cd src-tauri && cargo clippy
  --all-targets -- -D warnings && cargo test)`.
