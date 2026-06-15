# izba desktop app — P3 polish: form fixes + global multi-shell sessions

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. TDD; steps use `- [ ]`.

**Goal:** Fix three UX issues found while validating P3, on the same `feat/izba-app-p3-logs-shell` branch (updates PR #18):
1. New-sandbox form: vCPU/Memory/Disk number inputs overflow/overlap their grid tracks.
2. Ports input is a raw `[BIND:]HOST:GUEST`-per-line textarea → replace with an add/remove row editor (bind/host/guest fields).
3. Shell restarts on every Shell-tab open and supports only one session → make shells **global background sessions**: each survives Detail-tab switches AND sandbox switches (re-attach with scrollback), with **mini-tabs** to add (`+`), select, and close (`×`). A shell closes **only** via its `×` (natural exit marks it "exited" but keeps it).

**Architecture:** Backend keeps sessions alive already; switch its `shells` map from one-per-sandbox to **session-id keyed** (a `lib.rs`-only change; `ShellSession`/`RealShell` untouched). Frontend introduces a **module-level shell store** that owns persistent xterm `Terminal` instances (one per session, grouped by sandbox). The terminal's DOM element is created once and **portaled** (appended/detached) into the active viewer, so unmounting the viewer (tab/sandbox switch) never disposes the terminal or loses scrollback. Output listeners are registered at session creation, so output accrues even when no viewer is mounted.

**Tech stack:** Rust (Tauri), TypeScript/React, `@xterm/xterm` + `@xterm/addon-fit`, vitest.

**Toolchain (before cargo):**
```sh
export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo
export PATH="$CARGO_HOME/bin:$PATH"
```
StrictMode is ON (`app/src/main.tsx`) → all mount/portal logic must be idempotent (guard with an `opened` flag and check `el.parentElement` before appending).

**Gate (mirrors app.yml):** from repo root — `cargo {fmt --check, clippy --all-targets -D warnings, test}` on `app/src-tauri` (`--manifest-path app/src-tauri/Cargo.toml`); from `app/` — `npm run build` + `npm test`. All green before each commit.

---

## Task 1: NewSandbox — fix input width overlap

**Files:** `app/src/components/NewSandbox.tsx`

The three number inputs sit in `grid grid-cols-3 gap-3`. `<input>` has an intrinsic min-content width (~`size=20`), which overflows narrow grid tracks and visually overlaps. Fix: give the inputs `w-full min-w-0`.

- [ ] **Step 1:** In `NewSandbox.tsx`, add `w-full min-w-0` to the `className` of each of the three number inputs (vCPUs, Memory, Disk) — e.g. `className="w-full min-w-0 rounded-lg border border-line px-2 py-1.5"`. (Also harmless to add `min-w-0` to the Name/Image/Workspace inputs, but the grid ones are the bug.)
- [ ] **Step 2:** Gate (`cd app && npm run build && npm test`). Existing `newSandbox.test.tsx` must still pass.
- [ ] **Step 3:** Commit (`app/src/components/NewSandbox.tsx`):
```
fix(app): keep New-sandbox number inputs from overflowing their grid

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

---

## Task 2: NewSandbox — structured ports editor

**Files:** `app/src/components/NewSandbox.tsx`, `app/src/test/newSandbox.test.tsx`

Replace the `portsText` textarea with a list of rows. Each row: a **Bind** (optional, e.g. `127.0.0.1`), **Host** port, **Guest** port, and a remove (`×`) button; plus an **+ Add port** button. State is `useState<PortRow[]>([])` where `PortRow = { bind: string; host: string; guest: string }`. On submit, assemble each non-empty row into the existing wire string: `host:guest`, prefixed with `bind:` when `bind` is set — i.e. `${bind ? bind + ":" : ""}${host}:${guest}`. Skip rows missing host or guest. The backend still parses with `portfwd::parse_rule`, so the assembled strings are unchanged in meaning.

- [ ] **Step 1 (test first):** In `newSandbox.test.tsx`, add a test: render, click **Add port**, fill host=`8080` guest=`80` (use `getByLabelText`/`getByPlaceholderText` within the new row), submit, and assert `api.create` was called with `ports: ["8080:80"]`. Add a second: a row with bind=`127.0.0.1` host=`5432` guest=`5432` → `ports: ["127.0.0.1:5432:5432"]`. Follow the file's existing `vi.hoisted`/mock pattern for `../lib/ipc` and `@tauri-apps/plugin-dialog`. (The existing tests that don't touch ports must keep passing — `ports` defaults to `[]`.)
- [ ] **Step 2:** Run `npm test -- newSandbox` → new tests fail.
- [ ] **Step 3 (implement):** Replace the `portsText` state + textarea block. Add:
```tsx
  interface PortRow { bind: string; host: string; guest: string; }
  const [ports, setPorts] = useState<PortRow[]>([]);
  const setPort = (i: number, patch: Partial<PortRow>) =>
    setPorts((rows) => rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const addPort = () => setPorts((rows) => [...rows, { bind: "", host: "", guest: "" }]);
  const removePort = (i: number) => setPorts((rows) => rows.filter((_, j) => j !== i));
```
In `submit()`, build the wire strings:
```tsx
      ports: ports
        .filter((r) => r.host.trim() && r.guest.trim())
        .map((r) =>
          `${r.bind.trim() ? `${r.bind.trim()}:` : ""}${r.host.trim()}:${r.guest.trim()}`,
        ),
```
Render the editor (replace the old `<label>…<textarea>…</label>`):
```tsx
          <div className="grid gap-1">
            <span className="text-ink-2">Ports</span>
            <div className="grid gap-1.5">
              {ports.map((r, i) => (
                <div key={i} className="flex items-center gap-1.5">
                  <input
                    aria-label={`Port ${i + 1} bind`}
                    placeholder="127.0.0.1 (optional)"
                    value={r.bind}
                    onChange={(e) => setPort(i, { bind: e.target.value })}
                    className="min-w-0 flex-1 rounded-lg border border-line px-2 py-1.5 text-xs"
                  />
                  <input
                    aria-label={`Port ${i + 1} host`}
                    placeholder="host"
                    inputMode="numeric"
                    value={r.host}
                    onChange={(e) => setPort(i, { host: e.target.value })}
                    className="w-20 min-w-0 rounded-lg border border-line px-2 py-1.5 text-xs"
                  />
                  <span className="text-ink-3">:</span>
                  <input
                    aria-label={`Port ${i + 1} guest`}
                    placeholder="guest"
                    inputMode="numeric"
                    value={r.guest}
                    onChange={(e) => setPort(i, { guest: e.target.value })}
                    className="w-20 min-w-0 rounded-lg border border-line px-2 py-1.5 text-xs"
                  />
                  <button
                    type="button"
                    aria-label={`Remove port ${i + 1}`}
                    onClick={() => removePort(i)}
                    className="rounded-lg border border-line px-2 py-1.5 text-ink-2 hover:bg-hover"
                  >
                    ×
                  </button>
                </div>
              ))}
              <button
                type="button"
                onClick={addPort}
                className="justify-self-start rounded-lg border border-line px-2 py-1 text-xs text-ink-2 hover:bg-hover"
              >
                + Add port
              </button>
            </div>
          </div>
```
Remove the now-unused `portsText` state.
- [ ] **Step 4:** Gate (`npm run build && npm test`) green.
- [ ] **Step 5:** Commit (`NewSandbox.tsx`, `newSandbox.test.tsx`):
```
feat(app): structured add/remove ports editor in New-sandbox

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

---

## Task 3: Backend — session-id keyed shell commands

**Files:** `app/src-tauri/src/lib.rs`

Switch `AppState.shells` from `HashMap<sandbox_name, …>` to `HashMap<session_id, …>` and make `shell_open` mint + return a unique id. Events carry the id. `ShellSession`/`RealShell`/`DaemonApi` are unchanged. Multiple sessions per sandbox (and across sandboxes) now coexist.

- [ ] **Step 1:** Add a counter to `AppState`:
```rust
use std::sync::atomic::{AtomicU64, Ordering};
// in AppState:
    pub shells: Mutex<HashMap<String, ShellHandle>>, // keyed by session id now
    pub shell_seq: AtomicU64,
```
and in `run()`: `shell_seq: AtomicU64::new(0),`. (`ShellHandle` type alias stays.)
- [ ] **Step 2:** Change `ShellOutput`/`ShellExit` payloads to carry `id` instead of `name`:
```rust
#[derive(Clone, serde::Serialize)]
struct ShellOutput { id: String, data: String }
#[derive(Clone, serde::Serialize)]
struct ShellExit { id: String }
```
- [ ] **Step 3:** Rewrite `shell_open` to mint an id, key by it, and return it:
```rust
#[tauri::command]
async fn shell_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    name: String,
) -> Result<String, String> {
    let id = format!("sh-{}", state.shell_seq.fetch_add(1, Ordering::Relaxed));
    let make = state.make_daemon.clone();
    let out_app = app.clone();
    let out_id = id.clone();
    let exit_app = app.clone();
    let exit_id = id.clone();
    let session = tauri::async_runtime::spawn_blocking(move || {
        let mut d = make();
        d.open_shell(
            &name,
            Box::new(move |bytes: Vec<u8>| {
                let data = base64::engine::general_purpose::STANDARD.encode(&bytes);
                let _ = out_app.emit("shell-output", ShellOutput { id: out_id.clone(), data });
            }),
            Box::new(move || {
                let _ = exit_app.emit("shell-exit", ShellExit { id: exit_id });
            }),
        )
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(|e| e.to_string())?;
    state
        .shells
        .lock()
        .map_err(|e| format!("state poisoned: {e}"))?
        .insert(id.clone(), Arc::new(Mutex::new(session)));
    Ok(id)
}
```
(Note: the old stale-eviction-by-name is removed — ids are unique, nothing to evict.)
- [ ] **Step 4:** Change `shell_write`/`shell_resize`/`shell_close` to take `id: String` instead of `name: String` (the `shell_handle` helper looks up by id; bodies otherwise unchanged). Update the helper's param name to `id` for clarity.
- [ ] **Step 5:** Gate (cargo build/test/clippy/fmt on `app/src-tauri`). Green.
- [ ] **Step 6:** Commit (`app/src-tauri/src/lib.rs`):
```
feat(app): key shell sessions by id (multiple shells per sandbox)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

---

## Task 4: Frontend — id-based shell IPC

**Files:** `app/src/lib/types.ts`, `app/src/lib/ipc.ts`, `app/src/test/ipc.test.ts`

- [ ] **Step 1:** In `types.ts`, change the payloads to id-keyed:
```ts
export interface ShellOutputPayload { id: string; data: string; }
export interface ShellExitPayload { id: string; }
```
- [ ] **Step 2:** In `ipc.ts`, update the wrappers and event helpers to be id-based:
```ts
  shellOpen: (name: string) => invoke<string>("shell_open", { name }), // returns session id
  shellWrite: (id: string, data: string) => invoke<void>("shell_write", { id, data }),
  shellResize: (id: string, cols: number, rows: number) =>
    invoke<void>("shell_resize", { id, cols, rows }),
  shellClose: (id: string) => invoke<void>("shell_close", { id }),
```
```ts
export function onShellOutput(id: string, cb: (bytes: Uint8Array) => void): Promise<UnlistenFn> {
  return listen<ShellOutputPayload>("shell-output", (e) => {
    if (e.payload.id === id) cb(b64ToBytes(e.payload.data));
  });
}
export function onShellExit(id: string, cb: () => void): Promise<UnlistenFn> {
  return listen<ShellExitPayload>("shell-exit", (e) => {
    if (e.payload.id === id) cb();
  });
}
```
- [ ] **Step 3:** Update `ipc.test.ts`: `shellWrite`/`shellResize` assertions now pass an id (e.g. `api.shellWrite("sh-0", "x")` → `invoke("shell_write", { id: "sh-0", data: "x" })`). Keep `b64ToBytes` test. `shellOpen` still invokes `shell_open` with `{ name }`.
- [ ] **Step 4:** Gate (`npm run build && npm test`). Note: this will break `shellView.test.tsx` references until Task 5 replaces that component — it is acceptable for THIS task's commit to temporarily remove/replace `shellView.test.tsx` only if needed; prefer to land Tasks 4+5 so the suite is green at each commit. If `npm test` is red solely due to the old ShellView, coordinate: implement Task 5 in the same working session before committing Task 4, OR temporarily skip the old shellView test file and restore in Task 5. Document whichever you choose.
- [ ] **Step 5:** Commit (`types.ts`, `ipc.ts`, `ipc.test.ts`):
```
feat(app): id-based shell IPC wrappers + events

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

---

## Task 5: Frontend — global persistent multi-shell + mini-tabs

**Files:** create `app/src/lib/shellStore.ts`, create `app/src/components/ShellPanel.tsx`, replace `app/src/components/ShellView.tsx` (delete or repurpose), modify `app/src/components/Detail.tsx`, tests `app/src/test/shellStore.test.ts` + `app/src/test/shellPanel.test.tsx` (replace `shellView.test.tsx`).

### Design

**`shellStore.ts`** — a module-level singleton (survives component unmounts) exposing a `useSyncExternalStore`-friendly API. It owns persistent terminals:
```ts
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { api, onShellOutput, onShellExit } from "./ipc";

export interface ShellSession {
  id: string;
  sandbox: string;
  label: string;
  term: Terminal;
  fit: FitAddon;
  el: HTMLDivElement;     // kept alive; portaled into the active viewer
  opened: boolean;        // term.open(el) called once
  exited: boolean;
  unlisten: Array<() => void>;
}

const sessions: ShellSession[] = [];
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

export const shellStore = {
  subscribe(l: () => void) { listeners.add(l); return () => listeners.delete(l); },
  snapshot() { return sessions as readonly ShellSession[]; },
  forSandbox(sandbox: string) { return sessions.filter((s) => s.sandbox === sandbox); },

  async open(sandbox: string): Promise<string> {
    const el = document.createElement("div");
    el.style.width = "100%";
    el.style.height = "100%";
    const term = new Terminal({ fontSize: 13, cursorBlink: true });
    const fit = new FitAddon();
    term.loadAddon(fit);
    // Placeholder session inserted synchronously so the UI shows the tab; id filled after open.
    const session: ShellSession = {
      id: "", sandbox, label: "", term, fit, el, opened: false, exited: false, unlisten: [],
    };
    sessions.push(session);
    session.label = `Shell ${sessions.filter((s) => s.sandbox === sandbox).length}`;
    emit();
    // Subscribe BEFORE opening so no early output is lost; filter is by id, so we
    // must know the id first — open the backend shell, then wire listeners to its id.
    const id = await api.shellOpen(sandbox);
    session.id = id;
    const outUn = await onShellOutput(id, (bytes) => term.write(bytes));
    const exitUn = await onShellExit(id, () => {
      session.exited = true;
      term.write("\r\n\x1b[2m[process exited]\x1b[0m\r\n");
      emit();
    });
    session.unlisten.push(outUn, exitUn);
    term.onData((d) => void api.shellWrite(id, d));
    emit();
    return id;
  },

  async close(id: string) {
    const i = sessions.findIndex((s) => s.id === id);
    if (i < 0) return;
    const s = sessions[i];
    sessions.splice(i, 1);
    emit();
    s.unlisten.forEach((u) => u());
    if (s.id) await api.shellClose(s.id).catch(() => {});
    s.term.dispose();
    s.el.remove();
  },
};
```
> **Ordering note (early output):** unlike single-shell P3, here the id is only known after `shellOpen` resolves, so the output listener is registered just after. `/bin/sh`'s prompt is tiny and the exec round-trip dominates, so in practice nothing is lost; if a banner is ever dropped this is the known trade-off of id-keyed events. (Do not try to subscribe before open — there is no id to filter on yet.)

**`ShellPanel.tsx`** — for the selected sandbox: mini-tab bar of that sandbox's sessions + `+` + per-tab `×`, and a viewer that portals the active session's `el`:
```tsx
import { useSyncExternalStore, useState, useEffect, useRef } from "react";
import { shellStore } from "../lib/shellStore";

export function ShellPanel({ sandbox }: { sandbox: string }) {
  useSyncExternalStore(shellStore.subscribe, shellStore.snapshot);
  const all = shellStore.forSandbox(sandbox);
  const [activeId, setActiveId] = useState<string | null>(null);

  // Default the active tab to the first session; auto-open one if none exist.
  useEffect(() => {
    if (all.length === 0) { void shellStore.open(sandbox); return; }
    if (!activeId || !all.some((s) => s.id === activeId)) {
      setActiveId(all[all.length - 1].id || all[all.length - 1].label);
    }
  }, [sandbox, all.length]); // eslint-disable-line react-hooks/exhaustive-deps

  const active = all.find((s) => (s.id || s.label) === activeId) ?? all[0] ?? null;

  return (
    <div className="flex h-full flex-col">
      <div role="tablist" className="flex items-center gap-1 border-b border-line pb-1">
        {all.map((s) => {
          const key = s.id || s.label;
          return (
            <div
              key={key}
              className={
                "flex items-center gap-1 rounded-t px-2 py-1 text-xs " +
                (active && (active.id || active.label) === key ? "bg-hover font-semibold" : "text-ink-2")
              }
            >
              <button type="button" role="tab" onClick={() => setActiveId(key)}>
                {s.label}{s.exited ? " (exited)" : ""}
              </button>
              <button
                type="button"
                aria-label={`Close ${s.label}`}
                onClick={() => { if (s.id) void shellStore.close(s.id); }}
                className="text-ink-3 hover:text-warn"
              >
                ×
              </button>
            </div>
          );
        })}
        <button
          type="button"
          aria-label="New shell"
          onClick={() => void shellStore.open(sandbox)}
          className="rounded px-2 py-1 text-xs text-ink-2 hover:bg-hover"
        >
          +
        </button>
      </div>
      <div className="min-h-0 flex-1">
        {active && <ShellViewer key={active.id || active.label} sandbox={sandbox} sessionKey={active.id || active.label} />}
      </div>
    </div>
  );
}

function ShellViewer({ sandbox, sessionKey }: { sandbox: string; sessionKey: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const s = shellStore.forSandbox(sandbox).find((x) => (x.id || x.label) === sessionKey);
    const host = ref.current;
    if (!s || !host) return;
    if (s.el.parentElement !== host) host.appendChild(s.el); // idempotent (StrictMode)
    if (!s.opened) { s.term.open(s.el); s.opened = true; }
    s.fit.fit();
    const ro = new ResizeObserver(() => {
      s.fit.fit();
      if (s.id) void api.shellResize(s.id, s.term.cols, s.term.rows);
    });
    ro.observe(host);
    if (s.id) void api.shellResize(s.id, s.term.cols, s.term.rows);
    return () => {
      ro.disconnect();
      if (s.el.parentElement === host) host.removeChild(s.el); // detach, do NOT dispose
    };
  }, [sandbox, sessionKey]);
  return <div ref={ref} data-testid="shell-host" className="h-full w-full" />;
}
```
(import `api` from `../lib/ipc` in ShellPanel for the resize calls.)

**`Detail.tsx`** — render `ShellPanel` for the Shell tab instead of `ShellView`. Keep the running-guard hint. Because the store is global, the panel can unmount on tab/sandbox switch without losing sessions:
```tsx
        {tab === "shell" &&
          (running ? (
            <ShellPanel sandbox={name} />
          ) : (
            <div className="text-ink-3">Start the sandbox to open a shell.</div>
          ))}
```
Update the import to `import { ShellPanel } from "./ShellPanel";` and remove the `ShellView` import.

### Steps
- [ ] **Step 1 (store test first):** `shellStore.test.ts` — mock `@xterm/xterm`, `@xterm/addon-fit`, and `../lib/ipc` (`shellOpen` resolves `"sh-0"`, `onShellOutput`/`onShellExit` resolve `() => {}`). Assert: `open("web")` pushes a session, calls `api.shellOpen("web")`, and the session ends up with `id === "sh-0"`; `forSandbox("web")` returns it; `close("sh-0")` calls `api.shellClose("sh-0")`, disposes the term, and removes it from `snapshot()`. (Use `await` for open/close.)
- [ ] **Step 2:** Run → fails (no store).
- [ ] **Step 3 (implement store).** Create `shellStore.ts`.
- [ ] **Step 4 (panel test):** `shellPanel.test.tsx` — mock the SAME modules. Assert: mounting `ShellPanel` with no sessions auto-opens one (`api.shellOpen` called); clicking `+` opens another (2 mini-tabs); clicking a tab's `×` calls `shellStore.close`/`api.shellClose`. Mock xterm so `term.open`/`fit` are no-ops; the `el` is a real detached div (jsdom `document.createElement` works).
- [ ] **Step 5 (implement panel + viewer).** Create `ShellPanel.tsx`.
- [ ] **Step 6:** Wire `Detail.tsx` to `ShellPanel`; delete `ShellView.tsx` and `shellView.test.tsx` (replaced). Update `detail.test.tsx` if it referenced `ShellView` (it mocks `../components/ShellView` → change to mock `../components/ShellPanel` with a `shell-for-{sandbox}` stub so the existing tab test still asserts shell content).
- [ ] **Step 7:** Full gate: `cargo` gates on `app/src-tauri` + `cd app && npm run build && npm test`. All green, no orphaned imports/files (`git status` clean of stray files; use `git rm` for `ShellView.tsx`/`shellView.test.tsx`).
- [ ] **Step 8:** Commit (stage explicitly, use `git rm` for the deleted files):
```
feat(app): global persistent shells with mini-tabs (+ / select / ×)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

---

## Final verification
- Full gate green (5 commands). PR #18 updated by pushing the branch.
- **Manual (no CI/VM):** create form — vCPU/Mem/Disk no longer overlap; add/remove port rows produce `[bind:]host:guest`. Shell — open Shell tab gives a terminal; switch to Logs/Overview and back → same session, scrollback intact; `+` adds a second; switch sandboxes and return → sessions still alive; `×` closes one; natural `exit` shows `(exited)` and keeps the tab until `×`.

## Notes / deferred
- Sessions persist globally until `×` (or app exit / sandbox stop→stream EOF marks them exited). No cap on count — user-managed.
- Active-tab selection is panel-local; returning to a sandbox defaults to its last session. Per-sandbox remembered active tab is a possible follow-up.
- Early-output ordering trade-off documented in `shellStore.open` (id-keyed events require the id before subscribing).
