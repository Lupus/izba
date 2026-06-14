# izba Desktop App — Design

**Date:** 2026-06-14
**Status:** Approved design (pre-implementation)
**Topic:** A Tauri-based desktop GUI for managing izba microVM sandboxes — a
"Rancher Desktop"-style experience for izba.

## 1. Goal & scope

A polished desktop application that lets a user manage their local izba
installation the way Rancher Desktop / Docker Desktop manage their respective
runtimes: see what's running at a glance, inspect status, read logs, open an
interactive shell, manage egress, and drive sandbox lifecycle — without
touching the CLI.

### In scope (v1)

1. **Sandbox overview + status** — list every sandbox with live health
   (running / degraded+reason / stopped), image, vCPU/mem, uptime, workspace.
2. **Lifecycle controls** — Start / Stop / Restart (= stop+start) / Remove,
   with confirmation on destructive actions.
3. **Console log viewer** — read + live-follow `logs/console.log`; search,
   copy, jump-to-bottom.
4. **Interactive shell** — a real terminal embedded in the app (xterm.js bound
   to an `exec -it` PTY stream).
5. **Create sandbox** — a form: workspace dir, image, cpus/mem, rw size,
   published ports, optional egress `--policy` file; streams create progress.
6. **Ports + "open in browser"** — publish / unpublish / list port forwards;
   click a published port to open the guest's web service in the browser.
7. **Egress firewall + netlog** — live audit log of allow/deny decisions
   (`izba netlog`), plus the sandbox's policy view.
8. **System tray + launch-on-login** — Rancher-style background app: tray
   status, quick start/stop, show/hide window, autostart toggle.

### Out of scope (v2+)

- **File copy** (host↔guest drag-drop / `izba cp`) — deferred.
- macOS packaging — the architecture is cross-platform, but macOS is not a v1
  validation target.
- Multi-sandbox mesh / project-level orchestration views (tracked separately in
  the mesh-networking design).

## 2. Foundational decisions (locked)

| Decision | Choice | Rationale |
| --- | --- | --- |
| **Integration** | Embed `izba-core`; call `DaemonClient` directly | Same Rust workspace, typed `DaemonRequest`/`DaemonResponse`, native streaming, daemon auto-start/upgrade for free. |
| **Platform** | Cross-platform (Linux + Windows), no bridging | The app is just another `izba-core` consumer, exactly like the CLI. `DaemonClient` already resolves the correct per-OS socket (AF_UNIX on Linux; `%LOCALAPPDATA%\izba\daemon\izbad.sock` on Windows). A Windows build talks to Windows izbad; a Linux build to Linux izbad. |
| **Layout** | Sidebar sandbox-list + tabbed detail | Sandboxes are the central objects; keeps shell/logs one click away (Docker-Desktop-like). |
| **Aesthetic** | Lean **light** theme, **Calm Indigo** accent | Readability- and ergonomics-first; high contrast, generous spacing. |
| **Frontend stack** | React + TypeScript + Vite + Tailwind + xterm.js | Most mature Tauri path; best terminal support; easy to hand-build the custom light theme. |
| **Backend placement** | `app/src-tauri` is **NOT** a root cargo-workspace member | Protects the six existing CI gates (musl `izba-init`, `windows-gnu` cross-checks, clippy/fmt) from webview/MSVC/Tauri toolchain bleed. Path-dep on `izba-core`; own lockfile + own CI job. |

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  izba desktop app (Tauri 2)                                   │
│                                                               │
│  Frontend (WebView)              Backend (Rust, src-tauri)    │
│  ┌─────────────────────┐         ┌──────────────────────────┐ │
│  │ React + TS + Vite   │  invoke │ Tauri commands           │ │
│  │ Tailwind, xterm.js  │ ──────► │  list/inspect/create/    │ │
│  │                     │ ◄────── │  start/stop/rm/ports/    │ │
│  │ views, polling store│  events │  netlog/exec-PTY         │ │
│  └─────────────────────┘         └───────────┬──────────────┘ │
│                                              │ izba_core      │
│                                              ▼ DaemonClient   │
└──────────────────────────────────────────────┼──────────────┘
                                                │ framed JSON
                                                ▼ over AF_UNIX
                              ~/.local/share/izba/daemon/izbad.sock
                                                │
                                                ▼
                                          izbad → microVMs
```

- **Backend** (`app/src-tauri`, Rust): constructs `izba_core::DaemonClient`
  exactly like the CLI. Per-OS socket logic, auto-start, and version
  negotiation come for free. Exposes one thin Tauri **command** per operation.
- **Frontend** (`app/src`, TypeScript): React views over a typed `invoke()`
  wrapper layer and a polling store. No business logic beyond presentation.
- **Boundary contract:** the frontend never talks to izbad directly; every
  daemon interaction flows through a typed Tauri command. This keeps the wire
  protocol entirely on the Rust side and the frontend trivially mockable.

### 3.1 Tauri command surface (backend → izba-core)

Each maps to a `DaemonClient` RPC (see `crates/izba-core/src/daemon/proto.rs`):

| Command | izba-core call | Notes |
| --- | --- | --- |
| `list()` | `DaemonRequest::List` | rail + overview; polled |
| `inspect(name)` | `DaemonRequest::Inspect` | detail pane; polled |
| `create(opts)` | `DaemonRequest::Create` | streams `Progress` frames → events |
| `start(name)` | `DaemonRequest::Start` | |
| `stop(name)` | `DaemonRequest::Stop` | |
| `restart(name)` | `Stop` then `Start` | izba never auto-restarts |
| `remove(name, force)` | `DaemonRequest::Rm` | confirm in UI |
| `port_list(name)` | `DaemonRequest::PortList` | |
| `port_publish(name, rule)` | `DaemonRequest::PortPublish` | |
| `port_unpublish(name, bind, host)` | `DaemonRequest::PortUnpublish` | |
| `netlog(name, follow)` | read `logs/egress-audit.jsonl` | tail → events |
| `exec_open(name, cmd, tty)` | `DaemonRequest::OpenStream` + `StreamOpen::Attach` | PTY pump → events |
| `daemon_status()` | `DaemonRequest::Status` | top bar health/version |

## 4. Screens & components

Layout A, light theme, Calm Indigo accent.

- **Top bar:** brand mark + live daemon health/version dot.
- **Left rail:** `＋ New sandbox`; sandbox list with status dots and image
  subtitle; footer items `⛨ Firewall` (global view) and `⚙ Settings`.
- **Detail (tabs)** for the selected sandbox:
  - **Overview** — Configuration card (image, vCPU, mem, workspace, uptime),
    state badge with degraded-reason inline, action buttons, ports summary.
  - **Logs** — `console.log` viewer, live-follow toggle, search, jump-to-bottom.
  - **Shell** — xterm.js terminal bound to an `exec -it` PTY.
  - **Ports** — table of forwards; publish form; unpublish; "→ open in browser".
  - **Firewall** — live netlog audit stream (timestamp · verdict · tier ·
    host:port · rule) + the sandbox's policy text.
- **New-sandbox wizard** (modal): workspace dir picker (Tauri dialog), image,
  cpus/mem, rw size, ports, optional policy file; create-progress view.
- **System tray:** daemon status; quick start/stop of recent sandboxes;
  show/hide window. Launch-on-login toggle lives in Settings.

## 5. Data flow

- **Reads (polling):** izbad exposes no event stream, so the rail polls `list`
  every ~2s and the open detail polls `inspect`. Polling backs off (or pauses)
  when the window is hidden / tray-only, to stay cheap.
- **Streaming (Tauri event channels):**
  - **Shell:** `exec_open` opens the izba-core stream (`OpenStream` →
    `StreamOpen::Attach` PTY). The backend spawns a pump task: guest stdout →
    Tauri events → xterm `write`. xterm keystrokes → a `exec_write` command →
    stream stdin. Terminal resize → `Resize` RPC. One channel per shell
    session; closing the tab tears down the stream with a full `SHUT_RDWR`
    (per the documented CH half-close contract).
  - **Logs / netlog follow:** the backend tails the file and emits append
    events; the frontend appends to a virtualized list.
- **Writes:** lifecycle / create / port ops are one-shot commands → RPC →
  optimistic refresh (and a forced `list`/`inspect` re-poll).

## 6. Error handling

- `DaemonClient::connect()` auto-starts/upgrades izbad. If the daemon is truly
  unreachable, show a dismissible top banner with a Retry action; the rest of
  the UI degrades gracefully (last-known state, disabled actions).
- Typed RPC errors surface as toasts with the daemon's `Error { message }`.
- Destructive actions (`remove`, `stop`) require explicit confirmation.
- A **degraded** sandbox shows its reason string inline (e.g. "sidecar
  virtiofsd:workspace died") rather than a bare red dot — honest unhealthy
  reasons, matching izba's disk-state liveness model.
- Shell/stream errors (guest gone, EOF) close the terminal with a clear status
  line rather than a silent hang.

## 7. Testing strategy

- **Backend (Rust):** the command layer is unit-tested against a **fake
  in-process daemon** speaking the framed-JSON protocol, reusing izba's
  existing `UnixStream::pair()` / `PairListener` fake patterns (no `bind`, no
  KVM, no real VMs). Each command asserts the right `DaemonRequest` is sent and
  the response is mapped correctly. Stream/PTY pump tested with a scripted fake
  byte source.
- **Frontend (TypeScript):** Vitest component tests for each view with the
  Tauri `invoke`/event API mocked; assert rendering of running/degraded/stopped
  states, confirm-dialog gating, and tab behavior.
- **No KVM in app CI:** the app talks to izbad, which is mocked end-to-end. Real
  VM coverage stays in the existing izba-core/cli integration suites.
- **CI:** one new `app` job (frontend `npm ci` + typecheck + build; `cargo
  check`/clippy on `app/src-tauri`). The six core gates are unchanged because
  `app/src-tauri` is outside the root workspace.

## 8. Project structure

```
app/
├── package.json              # React, xterm.js, vite, tailwind, @tauri-apps/api
├── vite.config.ts
├── tsconfig.json
├── tailwind.config.ts
├── index.html
├── src/                      # TypeScript frontend
│   ├── main.tsx
│   ├── App.tsx
│   ├── theme.css             # light theme tokens (Calm Indigo)
│   ├── lib/
│   │   ├── ipc.ts            # typed invoke() wrappers + event subscriptions
│   │   └── store.ts          # polling store (list/inspect)
│   ├── components/           # Rail, TopBar, StatusBadge, Toast, ConfirmDialog
│   └── views/                # Overview, Logs, Shell, Ports, Firewall, NewSandbox
└── src-tauri/
    ├── Cargo.toml            # path dep: izba-core = { path = "../../crates/izba-core" }
    │                         # NOT a member of the root workspace
    ├── tauri.conf.json
    ├── build.rs
    └── src/
        ├── main.rs           # Tauri builder, command registration, tray
        ├── commands.rs       # one fn per daemon op
        ├── stream.rs         # exec PTY pump + log/netlog tailing
        └── tray.rs           # system tray + launch-on-login
```

The root workspace's `Cargo.toml` adds `app/src-tauri` to `workspace.exclude`
(or simply omits it from `members`) so `cargo build --workspace` and the
cross-compile gates never see it.

## 9. Build & CI notes

- Tauri 2.x; Linux needs `libwebkit2gtk-4.1`/`libgtk-3` dev libs; Windows uses
  WebView2 (MSVC). These deps are isolated to the new `app` CI job.
- The app's daemon access is identical to the CLI's, so existing daemon e2e
  coverage already exercises the underlying RPCs; the app job focuses on
  compile + unit/component correctness.
- Versioning: the app reports its built-against izba version in the top bar and
  via `DaemonClient` hello; a daemon mismatch triggers izbad
  restart/upgrade as it does for the CLI.

## 10. Open questions / future

- **Resource metrics:** v1 shows config (cpus/mem allocation) and uptime.
  Live CPU/mem *usage* meters require a guest-side metrics source that izba does
  not yet expose; shown as allocation-only until a metrics RPC exists. (The
  Overview mockup's memory meter is illustrative and will read allocation in
  v1.)
- **macOS:** architecture is portable; packaging/validation deferred.
- **File copy (v2):** slots cleanly into a new "Files" tab using `TarExtract`/
  `TarCreate` streams.
