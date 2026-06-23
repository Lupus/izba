# crun-as-single-container OCI runtime for izba guests (Stance B)

**Status:** LOCAL DRAFT — design exploration, not yet approved. Date: 2026-06-22.
**Decision owner:** lupus@oxnull.net.

> This doc captures the design for running the user's workload as an OCI
> container via **crun** inside the izba guest microVM, the dependent
> **Dockerfile/OCI-image compatibility** surface, and the **build-in-VM**
> feature. It synthesizes four parallel research threads (in-guest runtime
> integration, userns+virtiofs uid mapping, exec/SSH namespace teleport, kernel
> delta + builder). Citations are inline; every external claim is sourced.

---

## 1. Why (problem + the locked product context)

Users want to "run services on sandbox start" — docker, `docker compose`, an
MCP server, a few daemons their agent needs. The product North Star already
locked the shape of the answer (`docs/vision.md`, the mesh spec): **"your image,
your rules" — izba mandates no base image and no in-guest layout; in-VM
orchestration is the guest's own docker compose; izba leverages, does not
reimplement.** So izba's job is not to embed a supervisor — it is to **run the
user's image faithfully** and get out of the way, while keeping the microVM the
trust boundary.

Today the guest runs the workload as a **bare `chroot(/rootfs)` + uid-drop
process** under `izba-init` (PID 1), with **no mount/pid/user namespace**
("no mount namespace for workloads (chroot only)" is a documented v1 trade-off),
and izba reads **none** of the OCI image's runtime config (it pulls layers and
flattens to erofs; the config blob holding `Entrypoint/Cmd/Env/WorkingDir/User`
is discarded — `crates/izba-core/src/image/pull.rs`). There is also **no
"run something on boot" primitive** at all.

### Decision: Stance B

Run the user's workload as a **single OCI container via `crun`** inside the
guest. This one mechanism delivers, together:

1. **OCI runtime-config fidelity** — `Entrypoint/Cmd/Env/WorkingDir/User` applied
   by a real runtime, so any OCI image "just works" (the docker/OCI-compatibility
   the user asked for). This **subsumes** the alternative of hand-rolling the
   image-config→exec mapping in `izba-init`.
2. **Defense-in-depth** — user namespace (fake root), seccomp, cgroups, device
   cgroup. A malicious workload must escape the container *before* it can throw
   guest-kernel/virtio exploits at the VMM.
3. **In-guest resource bounding** — cgroup limits on the workload, which is the
   correct home for per-sandbox bounding (resolves the deferred **F-28**; the
   host-side `setrlimit` approach was abandoned because it breaks the VMM).
4. **The substrate** for the user's own nested `dockerd`+compose and for
   build-in-VM (next sections).

**Honest security framing (load-bearing — do not overclaim):** the **VM remains
the security boundary**. The in-guest container is **hardening** — least
privilege + attack-surface reduction that *lengthens* the chain to the VMM. It is
**not a second guarantee**. Linux namespaces are historically the weakest
isolation primitive (a poor *primary* boundary, a good *secondary* speed-bump).
seccomp and user-ns are the bigger VMM-surface wins; the device cgroup is weaker
than it sounds because the virtio surface is reached via kernel *drivers*
(fs/net), not workload-opened `/dev` nodes. This reverses the "chroot-only"
v1 trade-off and gives F-28 a home, and it must be sold as such in the security
register (`docs/security/`).

### Non-goals / guardrails

- **izba-init stays a single-container runtime, never a container manager.** One
  container per VM. Multi-service = the user's own nested `dockerd`/compose, OR
  multiple VMs in the mesh (M4). Enforce structurally (one `Option<Container>`,
  not a map).
- **No host-side container engine, no `docker build` on the host** (see §6).
- **No systemd-as-entrypoint** — it wants to be PID 1 / own cgroups+dbus and
  fights running as a child. Supervisors that work fine non-PID-1 (s6,
  supervisord, runit, dockerd) are the supported "orchestrator in your image"
  path.

---

## 2. Architecture overview

```
HOST (izba-core)                                 GUEST microVM
────────────────                                 ─────────────
image pull/ingest                                izba-init (PID 1, static musl)
  └ capture OCI config blob                        ├ mounts: erofs lower + ext4 upper
  └ generate config.json  ──[izba-oci share]──►    │  overlay → /rootfs ; virtiofs /workspace
sandbox::start()                                   ├ net: lo + dummy0 + nft REDIRECT stub
  └ FsShare workspace, izba-trust, izba-oci         ├ egress stub (vsock 1027)
                                                    ├ vsock servers (control 1025 / stream 1026)
                                                    └ crun create+start  ──►  WORKLOAD CONTAINER
                                                         rootfs = /rootfs                (one per VM)
exec / ssh  ──[vsock]──► izba-init ──[crun exec]──►  joins container ns (mnt/pid/user/…)
                                                    shares init's NET namespace (decision §3)
```

**Five pillars**, each detailed below: (A) the crun runtime integration,
(B) userns+virtiofs uid mapping [the gating spike], (C) exec+SSH teleport,
(D) kernel delta, (E) build-in-VM.

---

## 3. Cross-cutting decisions (all four threads converged here)

| # | Decision | Rationale |
|---|---|---|
| D1 | **Container shares `izba-init`'s network namespace** (omit `network` from the OCI `namespaces` list) | The egress model — `dummy0` structural deny + nft nat-output REDIRECT + DNS stub + loopback `resolv.conf` — lives in init's netns. A fresh container netns would get a bare `lo`, no routes, no nft → **egress breaks entirely**. Port relays (`TcpDial`) and SSH port-forward also assume guest-loopback == the service's loopback. This is consistent with "the guest is one vsock island." |
| D2 | **Single container per VM**; `izba exec`/ssh are `crun exec` *into* it, never a second `crun create` | Keeps izba-init a runtime, not a manager. |
| D3 | **Host-side `config.json` generation** (izba-core), delivered via a new **`izba-oci`** per-sandbox read-only virtiofs share | All policy inputs (entrypoint/cmd merge, trust-env, volumes, workspace cwd) live host-side; keeps the static-musl init minimal; the share mirrors the proven `izba-trust`/`izba-ssh` pattern. Cmdline is too small/whitespace-tokenized for env. |
| D4 | **Interactive mode = pause-PID-1 + `crun exec` shell**; **service mode = image entrypoint as PID-1** | A crashing/short-lived entrypoint must not lock exec/ssh out of the namespaces (interactive dev is izba's core use case). Service members (mesh, M4) run the entrypoint as PID 1 and its death = honest unhealthy (no auto-restart, per the existing contract). |
| D5 | **One shared "enter-container" primitive** in izba-init, used by BOTH exec and ssh | Anti-divergence by construction: exec and ssh cannot drift into different environments. |
| D6 | **Vendor a static `crun`** into the initramfs (sha-pinned, musl), via `IZBA_CRUN`, mirroring `IZBA_NFT` | crun (C, ~0.3–2 MB static) fits the initramfs ethos; runc (Go) is heavier and harder to fully-static on musl. |

---

## 4. Pillar A — crun runtime integration (guest + host)

### A1. Capture + persist the OCI image config (host)

`oci-client` 0.17 (already a dep) exposes
`Client::pull_manifest_and_config(&Reference, &RegistryAuth) -> (manifest,
manifest_digest, config_json)`; the config deserializes to
`oci_client::config::ConfigFile` with `.config.{user,env,cmd,entrypoint,
working_dir,labels,exposed_ports}`.

- Extend `ResolvedImage` (`image/pull.rs`) to keep `config_json`; switch the
  manifest fetch to `pull_manifest_and_config` (same digest; platform resolver
  already pins linux/amd64).
- Persist it content-addressed next to `rootfs.erofs`: add
  `ImageStore::config_path(digest)` → `<images>/<digest>/config.json`, written in
  `ensure_image`'s publish closure (`image/mod.rs`).
- **Cache migration:** `is_cached` keys on `rootfs.erofs` only; images cached by a
  pre-crun izba lack `config.json`. On a cache hit with no config, re-fetch
  config-only (cheap: manifest+config, no layers). If re-fetch fails (registry
  now unreachable), fall back to a synthetic minimal config with a **loud
  warning** — never silently.

### A2. Generate `config.json` (host, izba-core)

New `image/runtime_config.rs`: pure `(ConfigFile, SandboxConfig, overrides) →
OCI Spec`, heavily unit-tested (golden files per representative image:
alpine/ubuntu/node).

**Entrypoint/Cmd merge — docker-run faithful** (verified against moby
`daemon/commit.go::merge` + `daemon/create.go::mergeAndVerifyConfig`; implemented
as `image/runtime_config.rs::resolve_process_args`, 9-case test matrix):

| Case | `process.args` |
|---|---|
| no override | `Ep ++ Cm` (both empty → error "no command") |
| `CMD...`, no `--entrypoint` | `Ep ++ CMD` (override Cmd, keep Entrypoint) |
| `--entrypoint X`, no CMD | `[X]` — **an entrypoint override clears the image CMD** |
| `--entrypoint X` + `CMD...` | `[X] ++ CMD` |
| `--entrypoint ""` + `CMD...` | drop Entrypoint; args = `CMD` only |
| `--entrypoint ""`, no CMD | **error "no command"** — image `Cm` is NOT inherited |

> The load-bearing rule (moby `merge`): the image's `Entrypoint`/`Cmd` are
> inherited **only when no `--entrypoint` override was given** (the outer
> `len(Entrypoint)==0` gate). So any explicit `--entrypoint` — including
> `--entrypoint ""` — suppresses the image CMD. The earlier draft's
> `[X] ++ Cm` / "args = Cm" rows were wrong and have been corrected here.

**Field mapping:** `env` = image env → izba trust-env defaults (only if CA bundle
present, same gate as today) → `-e` overrides, last-wins; `working_dir` →
`process.cwd` (image WorkingDir for service mode; `/workspace` default for
interactive); `user` → prefer numeric; if a username, **let crun resolve it
against the container's `/etc/passwd`** (avoids a guest fixup pass); `labels` →
`annotations`. **`namespaces` omits `network`** (D1). Mounts: `/proc`,`/sys`,
`/dev`,`/dev/pts`,`/dev/shm` + the `/workspace` bind + user-volume mounts.

### A3. crun lifecycle in izba-init (guest)

- **Boot placement:** start the container **after `bring_up_egress()` and after
  the vsock servers are listening** (so the workload has working egress
  immediately and exec/ssh can attach the moment the host's boot-health probe
  passes). Read `config.json` from the `izba-oci` share; `crun create` +
  `crun start`.
- **`Health` must keep answering even if container start fails** → the host sees
  "booted but workload failed", not a boot timeout.
- **Supervision:** a `Container` abstraction reusing the existing
  `StatusCell` (`Mutex<Option<ExitStatus>> + Condvar`) shape so `Request::Wait`
  semantics are unchanged; supervise the entrypoint via `crun wait` in a thread.
  **No auto-restart** (honest unhealthy on death — existing contract).
- **Shutdown:** `crun kill SIGTERM` → bounded grace (reuse host stop window) →
  `crun kill SIGKILL` → `crun delete --force` → kill lingering `crun exec`
  sessions → `sync` + poweroff. The host's stop already SIGKILLs the VMM after
  its grace window, so a wedged teardown can't hang the host.
- **crun runtime state** on tmpfs (`/run/crun` or `--root /tmp/crun`).

### A4. Vendoring (`hack/build-crun.sh`, new)

Mirror `hack/build-nft.sh`: sha-pinned Alpine container, pinned crun source
tarball (verify sha256), `./configure --enable-static LDFLAGS=-static`, strip,
assert `statically linked`, emit `dist/crun` + print sha256. Static deps
(`libseccomp-static`, `yajl-static`, `libcap-static`) are all available on
Alpine. Wire `IZBA_CRUN` into `build-initramfs.sh` exactly like `IZBA_NFT`; add a
sha-pinned `crun` CI artifact job; teach `devbuild.sh`/`fetch-artifacts.sh`.

### A5. Interactive mode: the `izba-pause` PID-1 (DECIDED)

PID 1 owns the container's lifetime — when it exits the kernel tears down the
container's namespaces and cgroup, so exec/ssh would have nothing to join. For
the **interactive dev sandbox** (`izba run` with no service command — izba's core
use case), making the image entrypoint PID 1 is wrong: a bare image whose `CMD`
is a shell reads EOF at boot (no terminal attached), exits, and the sandbox dies
on arrival.

So interactive mode runs a **pause process as PID 1** — a tiny program that
installs a `SIGCHLD` reaper and then blocks forever in `pause()` (the K8s
"sandbox/pause container" pattern):

```c
int main(void){ signal(SIGCHLD, reap); for(;;) pause(); }
```

- **"Blocked" here is the goal, not a hang.** It sits descheduled in the kernel
  wait queue consuming ~0 CPU and a few KB, holding the namespaces open until a
  signal arrives (shutdown). It also **reaps orphaned zombies** that exec'd shells
  may leave behind (better than `sleep infinity`).
- The interactive shell then arrives as a `crun exec` *into* this living
  container (like `docker exec -it`); shells can come, go, and crash without
  killing the sandbox. This preserves today's "boot to idle, exec in" UX with
  minimal behavioral change.
- Ship a static **`izba-pause`** vendored in the initramfs (same pattern as crun)
  and bind-mount it as the interactive entrypoint, rather than depending on
  `sleep infinity` existing in the user's image.

**Service mode** (`izba run --service` / a long-running entrypoint) keeps the
image entrypoint *as* PID 1: the container lives as long as the service does, and
the service dying = honest unhealthy (no auto-restart) — which is the point of a
service member.

---

## 5. Pillar B — userns + virtiofs uid mapping (THE GATING SPIKE)

> **⚠ SPIKE OUTCOME (2026-06-22, CH/Linux leg) — see
> `2026-06-22-crun-userns-virtiofs-spike-findings.md`.** Run on the real
> post-§7-delta **6.12.30** kernel + virtiofsd 1.13.3 + CH 42 + crun 1.28:
> **Option B (guest idmapped virtiofs mount) is NOT viable on 6.12.30** —
> virtio_fs rejects `default_permissions` (`Unknown parameter`) and the OCI
> `idmap` mount does not translate (host-uid files appear as `nobody`, writes
> `EOVERFLOW`). **Revised recommendation: Option A primary** (userns
> `hostID`=sandbox-uid; VMM-independent, no kernel idmap), **Option C
> (virtiofsd `--translate-uid`, confirmed present in 1.13.3) as fallback**,
> **Option B deferred** until a kernel with working virtio_fs idmapped mounts.
> Kernel userns itself works (create + size-1 maps). Two crun-on-initramfs
> rough edges (non-identity-map `readlink ''`; size>1 map rejected) must be
> re-validated in izba's real overlay-root boot (Phase 4), not the minimal
> spike. The "DECIDED / Primary: Option B" text below is **superseded** by this.


**Problem:** with a user namespace, files on the virtiofs `workspace` share (owned
by the host uid) get remapped and may appear as `nobody`/unwritable inside the
container.

**This is fully solved in public prior art** (Kata Containers, podman/crun
rootless, idmapped mounts). izba's case is the *easy* one: it knows the host uid
and controls the guest kernel, virtiofsd version, and crun config.

### Ranked options

- **Option A — pick the container userns mapping so `hostID` = the host uid**
  (zero extra mechanism). With `{containerID:0, hostID:<host_uid>, size:1}` (+ a
  subuid range), workspace files already appear owned by container-root and
  writes land back as the host uid — no chown, no idmapped mount. Covers the
  single-owner-uid common case. (OCI: if a mount's `uidMappings` aren't given,
  the runtime uses the container's userns mapping.)
- **Option B — guest-side idmapped mount of the virtiofs share (SOTA, primary).**
  crun applies `mount_setattr(MOUNT_ATTR_IDMAP)` per the OCI mount `idmap`/`ridmap`
  option, giving that mount its own translation independent of the process userns.
  Requires **guest kernel ≥ 6.12** (FUSE/virtio_fs gained `FS_ALLOW_IDMAP` in
  6.12), **virtiofsd ≥ 1.13** (`FUSE_ALLOW_IDMAP`), and the share mounted with
  **`default_permissions`** (absence = silent `EINVAL`). **Fails closed.**
- **Option C — virtiofsd `--translate-uid`/`--translate-gid` (fallback, no kernel
  bump).** Internal host↔guest uid translation in virtiofsd, e.g.
  `--translate-uid=map:<guest_uid>:<host_uid>:1`. **virtiofsd ≥ 1.13** (shipped in
  1.13.0, *not* 1.12). Caveats: **mutually exclusive with `--posix-acl`**; with a
  container userns you must translate to the **guest-kernel** uid the userns
  consumes (double-shift), not directly to container-0.

### ⚠ Per-VMM constraint: OpenVMM bundles virtiofs (fewer knobs)

The Option B/C requirements above (`--translate-uid`, virtiofsd ≥ 1.13,
`default_permissions`, FUSE_INIT idmap flags) assume the **standalone Rust
virtiofsd** that **Cloud Hypervisor uses on the Linux/KVM path** — izba sha-pins
it, so the version floor and launch flags are fully under our control there. The
**Windows/WHP path via OpenVMM does NOT use a separate virtiofsd**: its virtiofs
backend is **bundled inside OpenVMM**, with a different (likely smaller) set of
exposed knobs and its own FUSE-feature support. So:

- Neither Option B (idmap FUSE flags) nor Option C (`--translate-uid`) can be
  assumed available on OpenVMM — they may be absent, partial, or differently
  spelled. **The spike must run on BOTH drivers, and the achievable floor may
  differ per-VMM.** Treat OpenVMM's virtiofs idmap/translate capability as
  unknown until measured.
- If OpenVMM's bundled backend lacks the mechanism, fallbacks (in preference
  order) are: rely on Option A's userns-`hostID`-arithmetic alone (no per-mount
  idmap needed for the single-owner-uid case — VMM-independent); or carry a
  per-driver capability flag and **fail closed + loud** on the OpenVMM path until
  upstreamed; or (last resort, separate effort) contribute the knob to OpenVMM.

### Recommendation (DECIDED)

**Spike first, then default userns ON with idmap; fail-closed + loud if the
kernel/virtiofsd floor isn't met — never a silent downgrade.**

**Primary: Option B**, with the container userns chosen per Option A so the
common single-uid case needs no idmapped mount at all; **Option C as the
no-kernel-bump fallback.** On Linux/CH izba controls the kernel (the 6.12 floor
is just a build decision — and we're already expanding the kernel, §7) and
sha-pins virtiofsd (a one-line pin bump to ≥ 1.13). Idmapped mounts **fail
closed**, which matches izba's posture; they compose with the container userns
instead of fighting it. **Capability is probed per-VMM at launch**; if a driver
can't meet the floor, the sandbox refuses to start with a loud, specific reason
(consistent with the `--allow-unconfined`-style "loud on degradation" rule) —
userns is never silently dropped.

### Gating spike (do this EARLY, before committing to userns-by-default)

Run every test on **both** the Cloud Hypervisor (Linux/KVM) and OpenVMM
(Windows/WHP) drivers; record the achievable floor per-VMM.

1. Boot a ≥6.12 guest; mount `workspace` virtiofs with `default_permissions`;
   from inside run a crun `idmap` mount (or `mount-idmapped --map-mount
   b:<host_uid>:0:1`). **Pass = mount succeeds, host file shows as uid 0;
   Fail = `EINVAL`** (kernel FUSE config / virtiofsd FUSE_INIT flags /
   `default_permissions` missing). Highest-value test.
2. Same, but through **izba's real Cloud Hypervisor + vhost-user virtiofsd launch
   with `--memory shared=on`** (docs only cover bare virtiofsd) **and** through
   the **OpenVMM bundled virtiofs backend** — does OpenVMM negotiate the FUSE
   idmap flags / expose any translate option at all? This is the open unknown.
3. **Round-trip:** container-root creates a file in `/workspace`; verify it lands
   on the host owned by the host uid, no chown (both drivers).
4. **erofs+overlay rootfs userns + virtiofs idmapped bind inside it** combination.
5. Confirm the **pinned virtiofsd is ≥ 1.13** (CH path); enumerate OpenVMM's
   virtiofs FUSE-feature support.
6. **Fallback validation:** confirm Option A's userns-`hostID`-arithmetic alone
   gives correct workspace ownership with NO per-mount idmap — this is the
   VMM-independent path that works even if a backend lacks idmap/translate.

**Spike artifact:** `hack/spike/crun-userns-virtiofs-spike.sh` for the CH leg and
a `.ps1` for the OpenVMM/WHP leg. Ground all writeups in the public docs cited
below — **do not reference any proprietary sandbox's internals.**

### Citations (B)

- virtiofsd README + version tags (translate landed in **1.13.0**, MR !237;
  idmapped mounts MR !245): gitlab.com/virtio-fs/virtiofsd (`/-/raw/main/README.md`,
  `/-/raw/v1.13.0/README.md`, `/-/merge_requests/237`, `/-/merge_requests/245`)
- idmapped mounts + FUSE 6.12: kernel.org `filesystems/idmappings.html`;
  `man7.org/linux/man-pages/man2/mount_setattr.2.html`; lwn.net/Articles/985803;
  kernelnewbies.org/Linux_6.12
- OCI mount `uidMappings`/`idmap`/`ridmap` + userns fallback rule:
  github.com/opencontainers/runtime-spec `config.md` + `config-linux.md`;
  crun `crun.1.md`
- podman `--userns=keep-id`, volume `:idmap`: docs.podman.io
- Kata virtio-fs how-to / rootless-vmm how-to: github.com/kata-containers

---

## 6. Pillar C — exec + SSH teleport into the container

Both must converge on **D5: one `crun_exec::spawn(EnterSpec)`** primitive in
izba-init (`EnterSpec = {argv, env, cwd, tty, uid, gid, winsize}`), shelling out
to **`crun exec`** rather than hand-rolling `setns`.

**Why `crun exec`, not hand-rolled setns:** entering a *user* namespace correctly
(setns ordering, uid-map interaction with setuid, re-applying seccomp/caps/cgroup
so the exec is as confined as PID 1, `$PATH`/argv0 resolution against the
container rootfs) is exactly the class of bug the security program cares about.
crun already owns these semantics from `config.json`; one tool = one source of
truth. (A raw `setns`-to-bare-`/rootfs` path can remain as an `izba exec --raw`
diagnostic for a wedged container — not the default, not what ssh uses.)

`spawn` first gates on **`crun state` (running?)** → a new
`ErrorKind::ContainerNotRunning` for the dead-container case (one chokepoint →
identical UX for exec and ssh, never a hang, never a silent bare-rootfs
fallback). It returns the existing `ExecProc` shape, so **everything downstream —
`wait`/`kill`/`resize`/`take_stream`/the reaper/the never-pruned exec-id map — is
reused verbatim.** Only the spawn step changes.

### C1. `izba exec`

Host CLI + wire protocol are **unchanged** (`ExecRequest` already carries
argv/env/cwd/tty/uid/gid; two-channel layout, resize watcher, exit mapping
stay). Internal edits: `ExecEngine::exec` calls the primitive; `child_pre_exec`
loses `chroot`/`setuid` (crun does it), keeps `setsid`/`TIOCSCTTY` for the
stdio-pass PTY option.

**Exit-code translation (resolved — honest crun pass-through):**
- The design originally assumed a missing command → **crun exit 127** → re-map
  to `Response::Error{CommandNotFound}`. **Real crun 1.28 exits `1`** for a
  missing executable (ambiguous with a legitimate `exit 1`), and prints
  `executable file ... not found` to **stderr**. Reproducing the pre-crun
  127/CommandNotFound would require fragile stderr-sniffing, so we **adopt the
  honest container-runtime behavior** (decision, validated on real KVM): crun
  resolves the command inside the container and izba **passes crun's exit code
  straight through** (`Code(n)`), with crun's clear stderr diagnostic. `izba
  exec /missing` therefore exits `1`, like `docker exec`. The `CommandNotFound`
  frame stays in the wire protocol for genuine can't-reach-workload cases (and
  the host RPC-wiring / scripted-guest tests still exercise its → 127 mapping).
- **Signal death:** crun exec exits `128+n` when the workload is signal-killed.
  Rather than decode `128+n` back to `Signal(n)`, init passes crun's `Code(128+n)`
  straight through (the host CLI already renders `128+n`); re-encoding would
  double-add. `Signal(n)` is reserved for when the crun-exec process ITSELF is
  killed (e.g. our `kill`/`kill_all`). See `decode_wait_status`.
- **PTY/resize:** keep the existing explicit `Resize` RPC → `TIOCSWINSZ` on init's
  PTY master (PTY-on-init-side, "option i"). Native `crun exec --tty
  --console-socket` (container-owned devpts) is a hardening follow-up.

### C2. SSH

The host bridge (`__ssh-proxy` → `TcpDial{22}` → daemon splice) and the
**vendored-sshd-in-initramfs** model are unchanged. **Only the session entry
changes:** `ChrootDirectory /rootfs` is deleted (it lands in bare rootfs,
diverging from exec). Replace with a `ForceCommand` + Subsystem wrapper:

```
# hack/sshd_config
ForceCommand /sbin/izba-ssh-session
Subsystem sftp /sbin/izba-ssh-session __sftp
```

`/sbin/izba-ssh-session` should be an **`izba-init __ssh-session` subcommand that
calls the same `crun_exec::spawn`** code path as exec (literal shared
implementation = strongest anti-divergence). Logic: empty `$SSH_ORIGINAL_COMMAND`
+ tty → `crun exec --tty <cid> <login-shell> -l`; non-empty (scp/rsync/VS Code's
`sh -c '…'`) → `crun exec [--tty?] <cid> sh -c "$SSH_ORIGINAL_COMMAND"`; `__sftp`
→ `crun exec <cid> sftp-server`.

- **sshd stays in initramfs (not in the container)** — the SSH design's security
  posture requires sshd's binary/keys/config to live in izba-controlled space,
  never the hostile overlay.
- **sftp parity needs a vendored static `sftp-server`** bind-mounted into the
  container (mirrors crun/nft vendoring): `internal-sftp` would run in the sshd
  (initramfs) namespace = wrong environment. This is the one new artifact SSH
  needs beyond crun.
- **PTY:** when the client requests a PTY, sshd allocates it; the wrapper runs
  `crun exec` **without `--tty`** using sshd's PTY slave as stdio → SIGWINCH flows
  sshd→PTY→container child, **resize works for free** (no izba Resize RPC).
- **VS Code Remote-SSH:** the bootstrap `sh -c` arrives as `$SSH_ORIGINAL_COMMAND`
  → installs/runs the VS Code server **inside the container** (`~/.vscode-server`
  in the container `$HOME`); its forked children are already in-namespace.
  **Port-forwarding works only because the container shares init's netns (D1)** —
  otherwise VS Code's `localhost:3000` (sshd/init netns) ≠ the service's
  `localhost:3000` (container netns). Another reason D1 is load-bearing.

### C3. Edge cases / open items

- **cp (`TarExtract`/`TarCreate`)** currently confines to on-disk `/rootfs`. The
  container's mountns may bind over parts of `/rootfs`. v1: keep cp on `/rootfs`
  (the container rootfs *is* `/rootfs` on disk) and **document the caveat**; v2:
  route cp through `crun exec tar` like `docker cp`.
- New `ErrorKind::ContainerNotRunning` touches `izba-proto` — additive
  `#[serde]`, check the Windows cross gate + the App gate; likely no
  `DAEMON_PROTO_VERSION` bump, but confirm enum round-trip.
- Confirm crun places `crun exec` children in the container cgroup (bounded by the
  same limits as PID 1) and forwards SIGTERM/SIGKILL (preserves `killpg` job
  control).

---

## 7. Pillar D — guest kernel delta

The user has accepted a larger guest kernel. `hack/kernel.config` is a **fragment**
merged over `x86_64_defconfig` then `make olddefconfig`, so individual symbols
not force-enabled by defconfig **must be pinned explicitly**. All izba options are
`=y` (no module-load path in the initramfs). Concrete add-list, grouped:

**a. Namespaces** — `USER_NS`, `PID_NS`, `NET_NS`, `UTS_NS`, `IPC_NS`.
**b. cgroup v2 controllers** — `MEMCG`, `CGROUP_PIDS`, `CPUSETS`, `CGROUP_SCHED`,
`FAIR_GROUP_SCHED`, `CFS_BANDWIDTH`, `BLK_CGROUP`, `CGROUP_BPF`, `CGROUP_CPUACCT`,
`CGROUP_FREEZER`. *(cgroup v2 has no `devices` file — device control is a
`BPF_CGROUP_DEVICE` eBPF program gated by `CGROUP_BPF`; do **not** add the v1-only
`CONFIG_CGROUP_DEVICE`.)*
**c. seccomp** — `SECCOMP`, `SECCOMP_FILTER`.
**d. overlay/storage** — none (`OVERLAY_FS` already present; docker `overlay2`
and buildkit's overlay snapshotter ride it). Do not add btrfs/devicemapper.
**e. docker bridge networking** — `BRIDGE`, `BRIDGE_NETFILTER`, `VETH`, `VXLAN`,
`MACVLAN`, `VLAN_8021Q`, `BRIDGE_VLAN_FILTERING`.
**f. iptables/netfilter xt** — `IP_NF_IPTABLES`, `IP_NF_FILTER`, `IP_NF_MANGLE`,
`IP_NF_NAT`, `IP_NF_TARGET_MASQUERADE`, `IP_NF_TARGET_REDIRECT`, `IP_NF_RAW`,
`NETFILTER_XT_NAT`, `NETFILTER_XT_MATCH_ADDRTYPE`, `NETFILTER_XT_MATCH_CONNTRACK`,
`NETFILTER_XT_MARK`. *(docker speaks the legacy `ip_tables` API even on nft hosts;
the existing `NF_TABLES`/`NF_NAT`/`NF_CONNTRACK` block served only izba's nft
stub.)*
**g. misc/eBPF** — `BPF`, `BPF_SYSCALL` (prereq for `CGROUP_BPF`), `BPF_JIT`
(decided on), `KEYS`, `POSIX_MQUEUE`.

Do **not** add stale symbols moby's `check-config.sh` still probes
(`NF_NAT_IPV4`, `NF_NAT_NEEDED`, `DEVPTS_MULTIPLE_INSTANCES`, `MEMCG_SWAP*`,
`CGROUP_DEVICE`). **IPv6 in-guest is DECIDED OUT** — the guest is IPv4-only
(`192.168.127.x`, no IPv6 egress path); omit all `IP6_NF_*`. A compose file
requesting IPv6 fails loudly, which is the intended behavior. (Keep the existing
`# CONFIG_IPV6 is not set` posture if present; do not re-enable it.)

**Attack-surface flags (note in the config comment block as a deliberate
tradeoff):** `USER_NS` and `BPF_SYSCALL` are the two meaningful surface additions
(historical LPE/verifier CVEs). Accepted because the **entire guest is already
the untrusted blast radius** (guest-is-hostile model); userns in a throwaway
microVM does not cross izba's trust boundary the way it does on a shared host.
**`BPF_JIT` is DECIDED ON** (`CONFIG_BPF_JIT=y`) — kept for cgroup-device-program
and any nft/bpf JIT performance; the verifier surface is already in-radius via
`BPF_SYSCALL`, so the JIT adds little marginal exposure inside the hostile-guest
model.

**NIC-less independence (confirmed):** bridge/veth/vxlan create *virtual*
interfaces for the guest's *internal* docker fabric; they need no virtio/physical
NIC. `VIRTIO_NET` stays off; outbound still flows container → `docker0` (NAT) →
guest routing → the existing nft REDIRECT → vsock 1027. Internal topology vs the
host↔guest boundary are orthogonal.

**nft/iptables coexistence (must be integration-tested):** docker's container
traffic is *forwarded* (PREROUTING/POSTROUTING-MASQUERADE/FORWARD), while izba's
REDIRECT is on nat-**OUTPUT**; but docker also adds a `DOCKER` jump in nat-OUTPUT
for published-port hairpin — **same chain as izba's REDIRECT.** Risk: misordered
rules or MASQUERADE-before-REDIRECT conntrack interaction could let container
egress **escape the vsock-1027 funnel = egress-policy bypass.** Mitigation:
ensure izba's REDIRECT has strict priority/position; consider pinning docker to a
dedicated nft table (docker 29 `--firewall-backend=nftables`, once
non-experimental). This is the roadmap's "not yet exercised: full compose stack"
item.

**Citations (D):** moby `contrib/check-config.sh`
(raw.githubusercontent.com/moby/moby/master/contrib/check-config.sh); Docker
packet-filtering + nftables docs (docs.docker.com/engine/network/…); runc
`docs/cgroup-v2.md`; kernel `admin-guide/cgroup-v2.html`; rootlesscontaine.rs
cgroup2; buildkit `docs/rootless.md`.

---

## 8. Pillar E — build-in-VM (Dockerfile → sandbox, no host builder)

**Thesis:** every Dockerfile `RUN` is untrusted code → the build **must run in a
microVM, never on the host**; this is also cross-platform-free (a Linux builder
VM regardless of Linux/Windows host, same reason pulls pin linux/amd64). izba
**orchestrates** an existing builder; it does **not** reimplement buildkit.

**Flow** (`izba build -f Dockerfile -t name ./ctx`):
1. Boot a throwaway builder microVM from an izba-vendored builder image
   (buildkit + buildctl baked in), reusing `sandbox::start()` wholesale.
2. Build context rides in over the **existing `workspace` virtiofs share**; a
   named **`izba-buildcache`** persistent volume → `/var/lib/buildkit`
   (incremental cache); an output volume/share → `/out`.
3. Guest runs `buildkitd & buildctl build --frontend dockerfile.v0 --local
   context=/workspace --local dockerfile=/workspace --output
   type=oci,dest=/out/img.tar`.
4. VM exits; host **ingests** `/out/img.tar` (next).

**Builder = BuildKit** (not buildah): it *is* `docker build` since 23.0 (exact
`dockerfile.v0` fidelity), first-class `type=oci` export, best cache, static Go
binaries. Run it **as root inside the disposable builder VM** (the VM is the
boundary) with the overlayfs snapshotter — sidesteps rootless-overlay caveats.
Each `RUN` is a nested runc/crun container → **covered by the §7 kernel set**
(same kernel serves docker-in-VM and buildkit-in-VM).

**oci-archive ingest (the missing izba-core hook):** today `image::ensure_image`
is registry-only (`resolve → fetch_layers → flatten_layers → build_erofs →
publish`). Add `image/ingest.rs::ingest_oci_archive(path)`: read the OCI-layout
tar (index→manifest→layers), confirm digest, feed layer readers into the
**existing** `flatten_layers`, then the **identical** erofs+publish tail (factor
the shared tail into a helper). Route `image_ref` starting with `oci-archive:` to
this instead of `ensure_image`. Once ingested, `build_vm_disks` keys the rootfs
off `image_digest` → the real sandbox boots with **zero** further change.

**CLI surface** (orthogonal to `izba run --image <ref>`):
```
izba run --image oci-archive:/path/img.tar   # NEW ref scheme → ingest_oci_archive
izba build -f Dockerfile -t myimg ./ctx      # build (in VM) → ingest → tag
izba run --image myimg                        # run a previously-built local tag
izba run --build ./Dockerfile                 # one-shot: build then run
```

**Builder image delivery (DECIDED): lazy-pull on first build, cached locally.**
The builder image is **not** shipped in the installer; on the first `izba build`,
izba pulls a sha-pinned builder image reference and caches it in the normal image
store (`images/<digest>/rootfs.erofs`), reused for all subsequent builds. Keeps
the installer small; the one-time pull needs egress+DNS (prereq #2) and the build
network policy (prereq #4). The pinned reference + digest live as constants in
izba-core. (If true offline/airgapped builds are later required, a
`hack/build-builder-image.sh` ship-in-installer path can be added without changing
the ingest/handoff.)

---

## 9. Known prerequisites & gating blockers

1. **`/var/lib/docker` (and `/var/lib/buildkit`) sized ext4 volume** — docker's
   overlay2 on izba's already-overlay `/rootfs` is overlay-on-overlay; needs a
   real fs (M3 volume mechanism). `izba run` for a docker-enabled sandbox should
   default-attach a sized volume.
2. **DNS transparent-reply fix — THE gating blocker.** The `udp dport 53`
   REDIRECT *reply* path is broken (wildcard-socket source mismatch; conntrack
   never un-NATs). dockerd strips loopback resolvers and falls back to hardcoded
   `8.8.8.8:53 UDP` → container DNS dead; buildkit `FROM` pulls also need DNS.
   The `IP_ORIGDSTADDR` transparent-reply fix (reply from the original dst so
   conntrack un-NATs) is folded into M4 and is a prerequisite for both
   docker-in-VM and build-in-VM-that-pulls.
3. **nft/iptables coexistence integration test** (§7) — egress-bypass risk.
4. **Build-time egress policy (DECIDED: separate build network policy).** Building
   untrusted Dockerfiles with unrestricted egress is itself a risk, so the builder
   VM runs under its **own dedicated build-network policy** — distinct from the
   sandbox's run-time egress policy — enforced through the same izbad vsock-1027
   plane (allow-list + audit). It allow-lists what a build legitimately needs
   (the builder-image pull, base-image registries, declared package mirrors) and
   denies the rest, so a malicious `RUN curl | sh` can't exfiltrate freely. The
   policy is configurable per build and pairs with the DNS fix (#2). This is its
   own policy surface, NOT AllowAll.

---

## 10. Phased build order

- **Spike 0 (do first, de-risks userns-by-default):** the userns+virtiofs spike
  (§5). Decides Option A/B/C and whether userns is default.
- **Phase 0 — kernel enablement (blocking):** apply the §7 delta; rebuild; smoke
  test `crun run busybox echo ok` in a booted guest.
- **Phase 1 — vendor static crun** (`build-crun.sh`, `IZBA_CRUN`, CI artifact).
- **Phase 2 — capture+persist OCI config** (host, unit-tested; cache self-heal).
- **Phase 3 — host-side `config.json` generator** (golden-file tests; netns
  omitted; entrypoint/cmd merge matrix); write `izba-oci` share in
  `sandbox::start`.
- **Phase 4 — guest crun lifecycle** (`oci.rs` share consts, `container.rs`,
  mount `izba-oci`, start after egress). Service-mode container boots its
  entrypoint; console shows output.
- **Phase 5 — rewire exec to `crun exec` + interactive (pause-PID-1) mode +
  `--entrypoint`/`--service`** (the exit-code translation TDD; ttytest Tier1/2;
  egress+DNS+MITM from inside the container).
- **Phase 6 — SSH teleport** — DONE. `izba-init __ssh-session` ForceCommand
  rewires every SSH session (interactive shell + remote commands) through
  `crun exec` into the running `izba` container, sharing its mount/pid
  namespaces exactly like `izba exec`. `ChrootDirectory /rootfs` is deleted.
  Remaining follow-up: native in-container sftp-server (sftp/scp currently
  run `/bin/sh -c "$SSH_ORIGINAL_COMMAND"` via the wrapper, which works for
  most tools but not sftp protocol over `Subsystem sftp`). VS Code Remote-SSH
  and port-forward validation needs a real KVM/WHP e2e run.
- **Phase 7 — health/status honesty** (optional `container` field on
  `HealthInfo`, `#[serde(default)]`, proto bump if needed; `izba status` reports
  container-exited honestly; App gate).
- **Track E (parallelizable after Phase 0+kernel):** oci-archive ingest →
  `izba build` builder VM → `--build`. Gated on prereqs #1/#2 for the
  docker/pull paths.

---

## 11. Decisions log (owner, 2026-06-22)

All previously-open decisions are now resolved:

- **D-A — userns:** **spike first (§5), then default-on with idmap; fail-closed +
  loud** if the kernel/virtiofsd floor isn't met per-VMM — never a silent
  downgrade. ✅ resolved.
- **D-B — interactive default:** **pause-PID-1 + `crun exec` shell** (see §A5);
  service mode uses entrypoint-PID-1. ✅ resolved.
- **D-C — IPv6 in-guest:** **no.** Guest stays IPv4-only; omit all `IP6_NF_*`
  (§7). ✅ resolved.
- **D-D — `BPF_JIT`:** **on** (`CONFIG_BPF_JIT=y`, §7). ✅ resolved.
- **D-E — builder image:** **lazy-pull on first build, cached locally** (§8); not
  shipped in the installer. ✅ resolved.
- **D-F — build-time egress:** **separate dedicated build-network policy** via the
  izbad vsock-1027 plane (§9 #4); not AllowAll. ✅ resolved.

**Remaining genuinely-open item:** the §5 spike outcome itself — specifically
whether the OpenVMM bundled virtiofs backend can meet the idmap/translate floor,
which determines per-VMM userns capability and the fallback path. Everything else
is decided.

## 12. Security-register touchpoints (update `docs/security/`)

- **Resolves F-28** (per-sandbox resource bounding via in-guest cgroups; the
  host-side `setrlimit` was abandoned as VMM-hostile).
- **Reverses** the "no mount namespace for workloads (chroot only)" v1 trade-off.
- **New honest claim:** in-guest container = hardening/least-privilege/surface
  reduction, **not** a second guarantee; VM stays the boundary.
- **New surface:** `USER_NS` + `BPF_SYSCALL` (accepted, hostile-guest blast
  radius). The container shares init's netns (D1) and can reach the egress
  chokepoints (`127.0.0.1:53`/REDIRECT port) directly — acceptable since izbad
  still enforces policy on vsock 1027; note it.
- **New egress-bypass risk:** docker's in-guest iptables vs izba's REDIRECT
  (§7) — must be integration-tested before docker-in-VM ships.
