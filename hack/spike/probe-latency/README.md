# probe-latency

Spike tool for [#249](https://github.com/Lupus/izba/issues/249): `izba status`
showed `container: unknown` for a running workload on Windows/OpenVMM.

## Why it exists

izbad fills that field with `probe_container_state`
(`crates/izba-core/src/daemon/server.rs`): `sandbox::control` (a liveness
assessment, which does its own `Health` exchange, then a second dial of the
control port), one `Request::Health`, one `Response`, all under a 5 s overall
deadline (`CONTAINER_PROBE_TIMEOUT`). Two different outcomes both print as
"unknown":

- the probe returned `None` — a step failed or ran out of time, the reply was
  not a `Health`, or the `Health` had no `container` field;
- the guest answered `Some(ContainerState::Unknown)` — its own `crun state`
  failed or was unparseable.

Nothing in the product shows which one happened or how long each phase took.
This tool does, by running the same calls against the guest directly. The
daemon is not involved, and no product code is changed.

The desktop app's Overview does not use that probe: it reads
`stats.guest.container`, which izbad fills with `probe_guest_stats` — the same
dial, then `Request::Stats`, accepting only `Response::Stats`, under its own
5 s bound (`STATS_PROBE_TIMEOUT`). The guest samples CPU for ~250 ms inside
that call, so it is the slower of the two. `--request stats` measures it.

## What it measures

Per iteration, against a **running** sandbox:

| measurement | sequence | timings (µs) |
| --- | --- | --- |
| `probe` | `sandbox::control` → write request → read `Response` | `control_us`, `health_us` or `stats_us`, `total_us` |
| `direct` | bare connector dial → write request → read `Response` | `dial_us`, `rpc_us`, `total_us` |

The request is `Health` by default and `Stats` with `--request stats`; a run
measures one or the other. The probe's round-trip key is named after it
(`health_us` / `stats_us`).

`probe` is the daemon's sequence without its `DeadlineStream`, so a slow phase
is measured at its real length instead of being cut off at the bound. `direct`
isolates one dial and one guest round trip (which includes the guest's
`crun state`); `control_us - dial_us` is roughly what the liveness assessment
costs. That assessment always does a `Health` exchange, whichever request is
being measured.

The only timeout the tool adds is a per-syscall safety cap of
`max(30 s, 2 × bound)` on the stream (`io_cap_ms` in the summary), so a wedged
guest ends an iteration as a `read` failure instead of hanging the run.

## Build and run

It is its own cargo workspace (see the comment in `Cargo.toml`), so build it
from this directory:

```sh
cargo test
cargo build --release --target x86_64-pc-windows-gnu   # needs gcc-mingw-w64-x86-64
```

Copy `probe-latency.exe` to the Windows host and run it as the user that owns
the sandbox, while the sandbox is running:

```
probe-latency <sandbox-name> [--request health|stats] [--iterations N] [--interval-ms M] [--parallel K] [--bound-ms B]
```

| flag | default | meaning |
| --- | --- | --- |
| `--request` | `health` | guest RPC to send: `health` (what `izba status` / Inspect is built from) or `stats` (what the app's Overview is built from) |
| `--iterations` | 20 | iterations per worker |
| `--interval-ms` | 250 | pause between iterations |
| `--parallel` | 1 | concurrent workers, each doing all iterations — do overlapping probes interfere? |
| `--bound-ms` | 5000 | the bound to compare against; reporting only, nothing is cut off at it |

The data root is `$IZBA_DATA_DIR` when set, otherwise the per-OS default — the
same resolution as `izba`.

Exit status: `0` if every measurement saw `some:running`, `1` otherwise, `2` on
a usage error.

## Reading the output

One JSON object per line on stdout: two per iteration (`probe`, then `direct`),
then one summary line.

```json
{"worker":0,"iteration":3,"measurement":"probe","request":"health","started_ms":812,"control_us":2140,"health_us":930,"total_us":3070,"ok":true,"inspect_container":"some:running","phase_failed":null,"failed_after_us":null,"error":null,"response":{"type":"health","version":"…","uptime_ms":51234,"container":"running"}}
```

- `request` — `health` or `stats`; also in the summary.
- `inspect_container` — the container state the product would get: with
  `health`, `SandboxDetail.container`; with `stats`, `stats.guest.container`.
  - `"none"`: no state — a step failed, the reply was not the type this
    request expects (a `Health` reply to a `Stats` request counts for
    nothing, as in the daemon), or it carried no `container`;
  - `"some:<state>"`: the guest's answer, e.g. `"some:running"`.
    **`"some:unknown"` is the guest reporting `Unknown`** — a different outcome
    from `"none"`, though the product prints "unknown" for both.
- `ok` — every step completed. A well-formed reply of the wrong type is
  `ok: true` and still `"none"`.
- `phase_failed` — `control` / `dial` / `write` / `read`, with `error` holding
  the full error chain.
- A duration is a number only if its phase **completed**. A failed measurement
  has `failed_after_us` (start to failure) instead, so a time-to-failure never
  enters the latency figures.
- `response` — the guest's reply as received, re-serialized. A `Stats` reply
  carries a process list, so it is cut down to
  `{"type":"stats","container":…}`; every other reply is shown in full.
- `started_ms` — offset from tool start, for lining up overlapping workers.

The last line is `{"summary": {…}}`. For `probe` and `direct` it gives
`iterations`, `failures`, the tally of distinct `inspect_container` values, and
for each timing field `count` / `failures` / `min` / `p50` / `p95` / `max`.
Percentiles are nearest-rank (always an observed sample; with the default 20
iterations p95 is the second-largest). `max_total_as_fraction_of_bound` is the
slowest completed `total_us` over `bound_ms` — `1.0` means it took exactly the
bound; failed iterations are not in it, see `max_failed_after_us`.
