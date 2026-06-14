# Testing improvements roadmap

Derived from the first full coverage run (E2E run 27510040571, 2026-06-14) across
all three coverage scenarios. This is a QA work-list: where coverage is lacking,
what test would close it, and how much it would move the needle.

## The three scenarios (and what each proves)

| Scenario | Workflow / job | Overall lines | Notable |
| --- | --- | --- | --- |
| Host fast suite | `coverage.yml` (every PR) | **81.6%** | unit + non-VM integration |
| Host + KVM e2e (merged) | `e2e.yml` → `linux-kvm-coverage` | **85.8%** | adds real-VM host paths |
| Windows WHP e2e | `e2e.yml` → `windows-whp-coverage` | **79.3%** | real OpenVMM/WHP driver |

**Per-crate (merged Linux):** izba-proto 98.5 · izba-core 90.7 · izba-init 78.1 ·
izba-ttytest 74.6 · izba-cli 66.7.

### What already moved the needle (evidence, not theory)

Adding the real-VM KVM e2e leg on top of the host suite moved:

- **Overall 81.6% → 85.8%** (+4.2 pts).
- **izba-cli 40.2% → 66.7%** (+26.5 pts) — the single biggest jump.
- `cli/commands/daemon.rs` **0% → ~83%**, `daemon/server.rs` +, `vmm/*` + .

The lesson: **the host unit suite structurally cannot reach CLI-command code or
real VMM/daemon-spawn paths.** Every point of izba-cli coverage came from running
the actual `izba` binary as a subprocess. So the highest-leverage investment is
more *CLI-driven, subprocess-level* tests — not more unit tests.

## Prioritized work-list

Ranked by coverage-per-effort. "Lines" = uncovered lines in the merged Linux
report unless noted; "VM?" = whether the test needs a booted microVM.

### Tier 1 — CLI surface e2e (highest leverage, low effort)

These files are thin clap wrappers that the host suite leaves at **0%** and even
the KVM e2e misses because `daemon_e2e` exercises lifecycle but not these verbs.
A single CLI-driven lifecycle test (spawn `izba`, like `daemon_e2e` already does)
covers all of them at once.

| Target | Lines | VM? | Test to add |
| --- | --: | --- | --- |
| `cli/commands/create.rs` | 23 (0%) | yes | `izba create <img> .` then assert state.json/`ls` |
| `cli/commands/stop.rs` | 11 (0%) | yes | `izba stop` on a running sandbox |
| `cli/commands/rm.rs` | 12 (0%) | yes | `izba rm` + `izba rm --force` |
| `cli/commands/ls.rs` | 13 (0% host) | yes | covered incidentally; assert table output |
| `cli/commands/netlog.rs` | 51 (19%) | yes | `izba netlog` after egress traffic; assert audit rows |
| `cli/commands/port.rs` | 33 (58%) | yes | `izba port publish/ls/unpublish` round-trip via CLI |

**Could've moved the needle:** ~140 izba-cli lines (~+15 pts on izba-cli alone)
for one extended CLI lifecycle test reusing the `daemon_e2e` harness. Best
ROI on the board.

### Tier 2 — izba-init host-testable units (no VM, pure unit tests)

Per the crate contract, *everything in izba-init except `main.rs` is
host-testable*, yet these are thin:

| Target | Lines | Test to add |
| --- | --: | --- |
| `init/net.rs` | 51 (42.7%) | unit-test the NIC-less bring-up plan (lo + dummy0 + alias + default route) against a fake netlink/command sink |
| `init/egress.rs` | 90 (65.9%) | unit-test the nft REDIRECT ruleset construction + the DNS/TCP framing decisions (the `NFT_RULESET` doc invariants) |
| `init/exec.rs` | 63 (84.8%) | error/edge branches of the PTY+pipe exec engine |
| `init/server.rs` | 71 (84.8%) | more `PairListener`-style frame-handling cases |

**Could've moved the needle:** ~140+ lines of pure host unit tests, zero VM cost,
runs on every PR. `net.rs` and `egress.rs` are the load-bearing egress datapath
— under-tested for how central they are.

### Tier 3 — image pipeline (OCI → flatten → erofs)

Weak across the board, weakest on Windows:

| Target | Linux | Windows | Test to add |
| --- | --- | --- | --- |
| `image/pull.rs` | 29.9% | 0% | pull against a **local OCI fixture/registry** (avoid network flake) |
| `image/erofs.rs` | — | 11.1% | erofs build from a fixture layer; assert mkfs invocation/output |
| `image/mod.rs` | — | 0% | pipeline orchestration happy-path + error |
| `image/flatten.rs` | — | 95.5% | the documented PAX-xattr-drop edge |

**Could've moved the needle:** the image pipeline is currently only exercised
incidentally by full boots. A fixture-driven pipeline test (no network) would
cover ~150 lines deterministically and remove a hidden network dependency.

### Tier 4 — cross-platform parity (Windows gaps the WHP suite skips)

Some paths are well-covered on Linux but **0% on Windows** because the WHP
validation suite doesn't drive them:

| Target | Linux | Windows | Test to add |
| --- | --- | --- | --- |
| `core/cp.rs` | 88.7% | **0%** | add a `cp` round-trip to `validate-izba-windows.ps1` |
| `cli/commands/exec.rs` | 57.7% | **0%** | add `exec` to the Windows validation suite |
| `cli/terminal.rs` | — | 13.2% | covered only when the ConPTY canary passes; widen tty cases |

**Could've moved the needle:** the WHP validation suite is the only Windows
host-path driver; extending it with `cp` + `exec` would lift ~330 Windows lines
and close the biggest Linux/Windows parity gaps.

### Tier 5 — daemon core depth

`daemon/server.rs` (110 uncovered) and `daemon/client.rs` (81) carry the most
uncovered *lines by count* even after e2e — error paths, adoption edge cases,
proto-mismatch handling (now especially relevant after the proto-gating change;
see the daemon_e2e upgrade-dance handoff). Targeted unit/integration tests for
the adopt/respawn/proto-mismatch branches.

## Non-goals (don't chase)

- **`init/main.rs` 0% (158 lines).** This is the guest PID-1 entry that runs
  *inside* the microVM; it is not capturable without in-guest instrumentation
  (explicitly out of scope). It will always read 0% and should be mentally
  excluded from the gap list.
- **`vmm/cloud_hypervisor.rs` on Windows / `vmm/openvmm.rs` on Linux.** Each
  driver only runs on its platform; the "low" number on the other platform is
  unit-test-only and expected. Read each driver's number from its *own*
  platform report.

## Suggested sequencing

1. **Tier 1** (one extended CLI lifecycle e2e) — biggest single jump, reuses
   existing harness.
2. **Tier 2** (izba-init units) — cheap, runs on every PR, hardens the egress
   datapath.
3. **Tier 4** (Windows `cp`/`exec` in the validation suite) — closes the parity
   gap the new Windows coverage leg exposed.
4. **Tier 3** (image pipeline fixture) — removes a network dependency and covers
   a whole subsystem.
5. **Tier 5** (daemon depth) — after the upgrade-dance contract is settled.

## Process notes

- Coverage is **report-only**; once these tiers land and the baseline stabilizes,
  consider a **ratchet threshold** in `coverage.yml` (fail if overall drops below
  the established baseline) so coverage can only go up.
- The merged Linux number is the headline to track over time; Windows is its own
  platform baseline (never cross-merge them).
- Re-generate any of these reports locally: `IZBA_INTEGRATION=1 hack/coverage.sh
  --html` (Linux merged), or browse the `coverage-report-e2e*` CI artifacts.
