# `izbad` — the izba daemon — Design

Status: approved 2026-06-11 (brainstormed interactively; egress proxy
explicitly excluded from this iteration).

Origin: v1 design §9 anticipated `izbad` as the first v2 step ("same core,
second thin binary") and §6 deferred supervision to it. sbx parity target:
a host-side sandbox daemon + REST API — minus the MITM proxy/governance/secrets,
which arrive in later iterations.

## 1. Goals and non-goals

**Goals**

- **Process anchor + supervision:** izbad owns (spawns and watches) every
  per-sandbox host process — VMM, passt, virtiofsd — and runs port relays
  as in-daemon threads. It continuously re-verifies liveness, marks
  sandboxes unhealthy with a specific reason, and auto-restarts dead
  **relays only**.
- **API surface:** a versioned RPC API over a local socket so IDEs, agents,
  or a future MCP server can drive sandboxes without shelling out to the
  CLI. The CLI itself becomes a thin client of this API.
- **Daemon-first, zero-ceremony:** the CLI auto-starts izbad on first use;
  users never manage it unless they want to (`izba daemon …`).
- **Stateless-restartable:** killing izbad (crash, upgrade, `daemon stop`)
  never harms sandboxes; the next daemon adopts them from disk.
- **Fully functional on Windows** in this iteration (AF_UNIX both sides;
  the OpenVMM vsock assert has only been observed under synthetic stream
  churn — if it surfaces in real workloads, the graceful full-shutdown
  teardown contract is the mitigation).

**Non-goals (this iteration)**

- Egress MITM proxy, domain allow-lists, credential injection (next
  iteration, hangs off this daemon).
- Auto-restart of VMs/sidecars: a dead virtiofsd/passt cannot rejoin a
  running Cloud Hypervisor (vhost-user reconnect was deliberately ruled out
  in v1), so VMM/sidecar death → honest "unhealthy: <reason>", never a
  silent restart. Per-sandbox `--restart` policies are future work.
- Remote/TCP access, multi-user sockets, REST/HTTP API, event
  subscriptions, systemd/service packaging (though `izba daemon run` is
  foreground and systemd-friendly by construction).

## 2. The invariant evolves, it does not break

v1's load-bearing invariant — *a sandbox = its dir under
`~/.local/share/izba/sandboxes/<name>/` + live processes, liveness always
re-verified via pid+starttime* — **remains the single source of truth**.
izbad holds no authoritative state: at startup it rebuilds its in-memory
view by discovering sandbox dirs and re-verifying liveness, exactly what
every CLI invocation does today. Consequences:

- **Crash recovery is startup.** No journal, no reconciliation protocol.
- **Upgrades are trivial.** Old daemon exits (sandboxes are detached
  children and keep running); new binary's daemon adopts.
- **`izba daemon stop` is safe.** Sandboxes keep running unsupervised;
  the next CLI command revives the daemon, which re-adopts.

VMM/sidecar children are therefore still spawned **detached** via the
existing `procmgr` machinery — izbad supervises by identity-checked
polling, not by parenthood.

## 3. Topology and protocol

- One izbad per data root, enforced by `flock` on `<data>/daemon/lock`
  (Windows: the same advisory-lock helper used elsewhere in core).
- Control socket: `<data>/daemon/izbad.sock`, AF_UNIX on **both** OSes via
  the existing `UdsStream` alias (std on Unix, `uds_windows` on Windows —
  native since Win10 1803). No named-pipe code path.
- Daemon log: `<data>/daemon/daemon.log`, truncated at daemon start.
- Wire format: u32-LE length-prefixed JSON frames via the izba-proto codec.
  The daemon message types live in `izba-core::daemon::proto` (izba-proto
  stays the guest-shared protocol only — it cannot depend on core types like
  `PortRule`, and both ends of the daemon protocol live in izba-core anyway):
  - `DaemonHello { version }` ⇄ `DaemonResponse::HelloOk { version }` — first
    exchange on every connection. The server always answers with its own
    version; the **client** compares and drives the upgrade dance on
    mismatch (exact match required — CLI and daemon are the same binary in
    normal operation).
  - `DaemonRequest` / `DaemonResponse` — control RPCs (see §4).
  - `DaemonRequest::OpenStream { name }` converts the connection: after the
    daemon replies `Ok` (sandbox validated, vsock stream-port dialed), the
    connection becomes a raw byte splice to the guest. The client then sends
    the guest `StreamOpen` frame itself, in-band — the daemon never parses
    stream framing at all.
- Long-running ops (create/pull, start-with-boot-wait) emit zero or more
  `DaemonResponse::Progress { … }` frames before the terminal Ok/Error on
  the same connection; the CLI renders them as today's progress output.

### The stream splice

Guest byte streams pass through izbad as a **pure splice**:

```
izba exec -it … (CLI)                         izbad                      guest
  control conn ── DaemonRequest::GuestRpc{name, req} ──► hybrid-vsock 1025 ──►
  stream  conn ── DaemonRequest::OpenStream{name} ─────────────────┐
                                                                   ▼
                                              validate name, dial vsock 1026,
                                              reply Ok; client sends the guest StreamOpen in-band,
                                              then splice bytes both ways
```

All existing exec/cp/attach framing, exit-code mapping (127 / 128+n), and
the vsock half-close teardown contract (full `SHUT_RDWR` once TX is done —
CH drops guest→host half-close) are unchanged; only the dialer moves from
"CLI dials vsock" to "CLI dials izbad, izbad dials vsock". The splice
applies the same graceful shutdown+drain teardown on both legs.

## 4. API surface (DaemonRequest)

| Group | Variants |
| --- | --- |
| Sandboxes | `Create`, `Start`, `Stop`, `Rm`, `List`, `Inspect` |
| Guest proxy | `GuestRpc { name, req: Request }` → wrapped guest `Response` |
| Ports | `PortPublish`, `PortUnpublish`, `PortList` |
| Daemon | `Status` (version, uptime, supervised set), `Shutdown` |

`DaemonRequest::OpenStream { name }` is the only stream-conversion request this iteration. Exact request/response fields are an
implementation-plan concern; the rule is that they carry the same data the
corresponding `izba-core` functions take today.

## 5. CLI surface

Every existing command keeps its exact UX but executes via `DaemonClient`:

```
izba daemon run        # run izbad in the foreground (debugging, systemd)
izba daemon status     # version, uptime, socket path, supervised sandboxes
izba daemon stop       # graceful daemon exit; sandboxes keep running
```

`ensure_daemon()` (in `DaemonClient`): try connect → on `ENOENT`/refused,
briefly take the daemon flock (acquiring it proves no daemon is alive),
remove the stale socket, **release the lock**, then spawn
`current_exe() daemon run` detached via procmgr and retry connect with
short backoff (~3 s total). The daemon takes the same flock itself, so a
concurrent double-spawn resolves cleanly: the loser exits "daemon already
running" and both clients connect to the winner. On final failure the
error includes the tail of `daemon.log` (same philosophy as boot failures
printing `console.log`).

Version mismatch at hello: client sends `Shutdown { reason: upgrade }`,
waits boundedly for exit, re-runs `ensure_daemon()` once. Sandboxes are
untouched throughout.

`izba daemon status` and `izba daemon stop` never auto-start a daemon (they
report "not running" instead). `Status` includes the daemon pid so tests and
scripts can kill the process directly. `daemon stop` pauses published port
relays (they are daemon threads) until the next daemon starts and re-adopts.

The hidden `__port-relay` subcommand and its pid-file machinery are
**deleted** (relays are daemon threads now). `izba daemon run` refuses to
start if the flock is held ("daemon already running").

## 6. Daemon internals (`izba-core/src/daemon/`)

Sync + threads throughout — matching core, where tokio is deliberately
confined inside image pull. Client connections number in the handfuls.

| Module | Responsibility |
| --- | --- |
| `transport.rs` | platform alias `UdsListener`, socket bind (perms, stale unlink), connect helper, version string |
| `server.rs` | accept loop; thread per connection; hello, then dispatch control frames or hand stream conns to the splice path |
| `registry.rs` | `Mutex<HashMap<name, SandboxEntry>>` — verified pid identities (VMM + sidecars), health + reason, relay thread handles, per-sandbox op lock. Built at startup by adoption (§7) |
| `relays.rs` | in-daemon relay threads (bind + cancellable accept loop per rule) and `ports.json` rules persistence incl. legacy-schema migration |
| `supervisor.rs` | background thread, 1–2 s tick: re-verify every owned process (existing `liveness.rs`), set unhealthy reasons, respawn dead relay threads, drive the idle-exit timer |
| `client.rs` | `DaemonClient`: `ensure_daemon()`, hello/version check, typed RPC methods, `open_guest_stream()` returning a raw stream for the CLI's existing framing code |

- **Concurrency:** per-sandbox mutex in the registry serializes state
  transitions; ops on different sandboxes run in parallel; the per-sandbox
  `flock` stays as defense-in-depth against a pre-daemon `izba` binary
  operating on the same root.
- **Idle exit:** zero running sandboxes AND zero client connections for
  15 min (env-overridable, `IZBA_DAEMON_IDLE_SECS`, `0` = never) → stop
  accepting (closes the race: the check is re-done under the registry lock
  before exit), unlink socket, drop flock, exit 0. A client that loses the
  race gets connection-refused and `ensure_daemon()` restarts izbad —
  worst case one retry, never a hang.
- **Security:** `<data>/daemon/` is `0700`, socket `0600` (Unix); on
  Windows the data-root ACLs gate access. Local single-user only.

## 7. Adoption, ports, and migration

At startup izbad walks sandbox dirs (`discover`), loads `state.json`, and
re-verifies pid identities — each sandbox lands in the registry as
running/unhealthy/stopped with reasons. Then:

- **Port rules** persist in `ports.json` as plain rules (the relay
  `PidIdentity` field is dropped — relay liveness is now in-memory daemon
  state). Adoption re-creates one relay thread per rule for running
  sandboxes; a daemon restart therefore implies a brief listening gap, by
  design.
- **Legacy relay processes** (pre-daemon `izba __port-relay`, found via
  old-schema `ports.json` records): verify pid identity, kill, respawn as
  threads. One-time, lazy, logged.
- Half-created sandbox dirs (daemon died mid-`create`) are removed at
  adoption — the existing partial-create rule, now with a fixed owner.

## 8. Error handling

| Failure | Behavior |
| --- | --- |
| daemon won't start | error + tail of `daemon.log`, exit 1 |
| stale socket file | flock-guarded unlink + respawn (race-free) |
| version mismatch | automatic shutdown→respawn→retry, once; then error |
| daemon dies mid-RPC | "daemon connection lost; rerun the command", exit 1 |
| daemon dies mid-stream | stream EOF; exec reports the lost connection |
| guest errors | wrapped `Response` passes through `GuestRpc` unchanged (127/128+n mapping intact) |
| VMM/sidecar dies | supervisor marks unhealthy + reason within one tick; `ls`/`inspect` report it; no auto-restart |
| relay thread dies | supervisor respawns it next tick, logged |
| second `izba daemon run` | "daemon already running", exit 1 |

## 9. Testing

- **Unit (six gates, no sockets bound):** proto roundtrips for the new
  frames; server dispatch + hello/version logic over in-memory pairs;
  registry adoption decisions with fake liveness probes; supervisor tick
  logic (dead relay → respawn, dead VMM → unhealthy + reason, idle-exit
  countdown) against injected clocks; `ensure_daemon` state machine with a
  scripted fake daemon on a socketpair. Tests that genuinely need a
  listener runtime-skip on `PermissionDenied` (existing convention).
- **Integration (KVM, `IZBA_INTEGRATION=1`, serial):** full lifecycle
  through the daemon (auto-start on first `run`); exec/cp/port through the
  proxy; **kill -9 izbad mid-life → next CLI adopts, sandbox unaffected,
  relays respawned**; idle-exit with `IZBA_DAEMON_IDLE_SECS=2`;
  version-mismatch upgrade dance via an env-injected fake version; legacy
  relay-process migration.
- **ttytest e2e:** the existing `exec -it` checklist exercises the daemon
  path for free (it drives the real binary, which is now daemon-first).
  The scripted fake-guest tests gain one extra bind (the daemon socket) —
  covered by the same `PermissionDenied` runtime-skip.
- **Windows (after the KVM suite is green):** extend
  `hack/spike/validate-izba-windows.ps1` with a daemon section — auto-start
  on first `run`, `daemon status`, full lifecycle (run/exec/cp/port/stop),
  kill the daemon process → next command adopts, `daemon stop` leaves the
  sandbox running — and run it from WSL via `powershell.exe` interop
  against the staged `izba.exe` (`hack/stage-izba-windows.sh`).

## 10. Out of scope, recorded for later

- Egress MITM proxy + credential injection (next iteration; runs inside
  izbad, reaches the guest via the existing networking).
- `--restart` policies / VM auto-restart; crash-loop backoff.
- Event subscription API (push health changes to clients).
- REST/HTTP gateway for non-Rust integrators, if framed JSON proves to be
  a real adoption barrier.
- Service/systemd packaging and start-on-boot.
