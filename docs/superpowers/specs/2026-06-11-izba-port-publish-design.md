# `izba port` — TCP port publishing via vsock relay — Design

Status: approved 2026-06-11. Companion spec:
[2026-06-11-izba-cp-design.md](2026-06-11-izba-cp-design.md) — its §2 is the
canonical definition of the shared `StreamOpen` wire groundwork (including
this feature's `TcpDial` variant and `ErrorKind::ConnectFailed`), landed on
main before either feature branch forks.

sbx parity target: `sbx port` (TCP port publishing over the control plane).
izba's passt subnet decision: commit ea9e413 (static 192.168.127.0/24).

## 1. Goals and non-goals

**Goals**

- Reach a TCP service inside a running sandbox from the host:
  `curl 127.0.0.1:8080` → guest port 80.
- **Both** create-time stable ports (`izba create -p 8080:80`, persisted,
  re-applied on every `run`) and **runtime** publish/unpublish against an
  already-running VM (`izba port publish NAME 8080:80`).
- Default bind `127.0.0.1` (agent workloads are untrusted; LAN exposure is
  opt-in via an explicit bind address).
- Daemonless: every published rule is an independent, detached, pid-tracked
  relay process — fits the "sandbox = dir + live processes" invariant.
- Cross-platform by construction: pure vsock (no passt/consomme involvement),
  so the same code serves Cloud Hypervisor/Linux and OpenVMM/Windows.

**Non-goals (v1)**

- UDP (a byte-stream relay cannot carry datagram boundaries faithfully).
- passt `-t` kernel-path acceleration (can be added later behind the same UX;
  passt is userspace NAT anyway, so the relay's performance class is similar).
- Guest-initiated ("reverse") forwards; port ranges; container-style
  `EXPOSE` metadata.

## 2. CLI surface

```
izba create -p [BIND:]HOST:GUEST ... [dir]    # repeatable; persisted
izba port publish NAME [BIND:]HOST:GUEST      # runtime, VM must be running
izba port unpublish NAME [BIND:]HOST          # kill that rule's relay
izba port ls NAME                             # active rules + liveness
```

- Rule syntax: `HOST:GUEST` or `BIND:HOST:GUEST`; `BIND` is an IPv4 address
  (default `127.0.0.1`), ports are u16 ≥ 1. Examples: `-p 8080:80`,
  `-p 0.0.0.0:8080:80`.
- A rule's identity (uniqueness key) is `(BIND, HOST)`. Publishing a
  duplicate key → error; `unpublish` takes the key (GUEST not needed).
- `port publish`/`unpublish`/`ls` require an existing sandbox; `publish`
  additionally requires it to be running (same liveness check as `exec`).
- `izba port ls` prints one line per rule: `BIND:HOST -> GUEST` plus the
  relay pid; dead relays (pid+starttime mismatch) are pruned from the
  records and not shown.

## 3. Architecture

```
curl ──TCP──▶ relay process (izba __port-relay, host)        ── per rule
                 │  accept()
                 │  per connection:
                 ▼
              hybrid-vsock CONNECT 1026 (run/vsock.sock)
                 │  StreamOpen::TcpDial{port: GUEST}
                 ▼
              izba-init ──connect──▶ 127.0.0.1:GUEST (guest netns)
                 │  Response::Ok  → pump bytes both ways
                 │  Response::Error{ConnectFailed} → relay closes client conn
```

- **Relay = `izba` itself**, re-invoked as a hidden clap subcommand:
  `izba __port-relay --vsock <run/vsock.sock> --bind <ip> --host-port <p>
  --guest-port <p> --pid-file <run/port-<bind>-<hostport>.pid>`. Spawned
  detached via the existing `procmgr::spawn_detached(cmd, log)` with log
  `logs/port-<bind>-<hostport>.log`. The relay loop lives in
  `izba-core::portfwd` so a future `izbad` reuses it without the
  re-invocation trick.
- Init's dial target is `127.0.0.1:GUEST` — the guest has a single netns, so
  this reaches listeners bound to either loopback or 0.0.0.0.
- One relay process per rule keeps unpublish trivial (`kill_pid`) and
  failure domains independent.

### Graceful shutdown (OpenVMM churn mitigation)

Relay connection teardown is **always** `shutdown(Write)` on the vsock side
followed by draining the remaining guest→host bytes until EOF — never an
abrupt drop with buffered TX. This is simultaneously correct relay behavior
(no truncated responses) and the planned izba-side mitigation for the known
OpenVMM `virtio_vsock` assert crash under stream churn
(connections.rs:1093, documented in project memory). The init side mirrors
it: on guest-socket EOF, `shutdown(Write)` toward the host and drain.

## 4. State and persistence

- **`config.json`** (`SandboxConfig`) gains
  `#[serde(default)] pub ports: Vec<PortRule>` — existing sandboxes keep
  deserializing.

  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  pub struct PortRule {
      pub bind: Ipv4Addr,   // serde as string, e.g. "127.0.0.1"
      pub host_port: u16,
      pub guest_port: u16,
  }
  ```

- **`ports.json`** (new per-sandbox file, sibling of `state.json`): the
  *active* relays — `Vec<PortRecord { rule: PortRule, relay: PidIdentity }>`.
  Written with the existing crash-safe `state::save_json`. It is the single
  source of truth for `port ls`/`unpublish`; liveness is always re-verified
  via pid+starttime, never trusted from the file (the standing invariant).
- **Lifecycle hooks:**
  - `run`: after the boot health check passes, spawn one relay per
    `config.ports` rule and write `ports.json`. A relay that fails to bind
    does not fail the `run`; it is reported as a warning (the VM is up; the
    port is not) and excluded from `ports.json`.
  - `port publish`: spawn relay, append record.
  - `port unpublish`: kill relay (pid-identity-checked), remove record.
  - `stop` / `rm --force`: kill all recorded relays alongside the VMM and
    sidecars, then remove `ports.json` (stop) / the sandbox dir (rm).
  - Stale `ports.json` after a crash: pruned lazily by any `port` command
    and by `run` (which starts from the config rules afresh).

## 5. Relay process details (`izba-core::portfwd`)

- Binds `TcpListener` on `(bind, host_port)` **before** detaching is not
  possible (detached spawn = new process), so publish-time feedback uses a
  **parent preflight**: the publishing CLI binds `(bind, host_port)` itself,
  drops the socket, then spawns the relay. This catches the common
  port-in-use error synchronously; the residual TOCTOU race is accepted and
  documented (the relay's own bind failure lands in its log and the rule
  shows up dead in `port ls`).
- After binding, the relay writes its pid file and enters the accept loop;
  per connection it spawns a thread (the per-connection cost is two pumps,
  same shape as the exec stream pumps in the CLI).
- vsock handshake per connection: `hybrid_connect(run/vsock.sock, 1026)`
  (existing helper, byte-by-byte `OK` read), send `StreamOpen::TcpDial`,
  read one `Response` frame. `Ok` → pump; anything else → close client.
- Init-side dial timeout: 10 s cap (loopback connects normally fail fast
  with ECONNREFUSED; the cap guards pathological states), surfaced as
  `Error{ConnectFailed, <os message>}`.
- Relay exit conditions: SIGTERM/kill (unpublish/stop/rm), listener error.
  If the VM dies, in-flight connections error out and new accepts fail at
  the vsock connect step — the relay stays alive but useless;
  `stop`/`run`/`rm` clean it up (and `run` re-spawns from config). This is
  acceptable daemonless behavior and is documented in `port ls` output via
  liveness.

## 6. Error handling

| Failure | Behavior |
| --- | --- |
| rule parse error | CLI usage error, exit 2 (clap) |
| duplicate `(bind, host_port)` in records or config | "port already published", exit 1 |
| host port in use | preflight bind fails → exit 1 with OS message |
| publish on non-running sandbox | "sandbox NAME is not running", exit 1 |
| guest port closed | per-connection: client conn closed immediately after accept (curl: "connection reset"); relay logs the `ConnectFailed` message |
| VM dies under a live relay | pumps error out; relay lingers until stop/rm/run cleanup |
| unpublish unknown rule | "no such published port", exit 1 |

## 7. Testing

- **Unit (six gates, no real listeners where sandboxes forbid bind —
  socketpair fakes per the `PairListener` pattern):**
  - rule parsing matrix (`8080:80`, `0.0.0.0:8080:80`, garbage, port 0).
  - `PortRule`/`PortRecord`/`SandboxConfig` serde incl. missing-`ports`
    back-compat fixture.
  - init `TcpDial` arm: dial a socketpair-faked target; `Ok` + pumped bytes;
    refused target → `ConnectFailed`.
  - relay pump logic over socketpairs: bidirectional transfer, EOF-drain
    ordering (shutdown(Write)+drain), client-close and guest-close paths.
  - Tests that genuinely need a `TcpListener` runtime-skip on
    `PermissionDenied` (existing convention).
- **Integration (KVM, `IZBA_INTEGRATION=1`):**
  - create with `-p 18080:8000`, run, start a listener in the guest via
    exec (`python3 -m http.server 8000` exists in ubuntu:24.04), curl
    `127.0.0.1:18080` from the test, assert body.
  - runtime `port publish` on the same running sandbox with a second rule,
    curl it; `port unpublish` → connection refused; `port ls` shows exactly
    the live rule set.
  - `stop` kills relays (no orphaned `__port-relay` processes).
- **Windows:** by construction (vsock path + `uds_windows` already proven by
  exec); folded into the `validate-izba-windows.ps1` manual gate. The churn
  mitigation (§3) is expected to *reduce* the known OpenVMM assert risk, not
  eliminate it — the upstream issue stays open.

## 8. Out of scope, recorded for later

- UDP forwarding; passt `-t` acceleration behind the same UX; port ranges;
  `izba update` for editing persisted rules (workaround: recreate, or
  runtime-publish).
- An auto-republish supervisor (a daemonless izba has no process to watch
  relays; `izbad` will).
