# Keeping izba's control plane out of the guest's reach (F-30 deep-dive)

> Companion analysis for **F-30** in
> [findings-2026-06-15.md](findings-2026-06-15.md). Scope: where the per-sandbox
> egress **policy** — and, more generally, every authoritative izba
> control-plane / state file — may live relative to the guest-writable
> `/workspace` share, analysed under the program's core assumption that **the
> guest, *including its kernel*, is hostile** (threat-model A1). crun is
> defense-in-depth, not a wall (cf. F-21).

## TL;DR

- **Good news, stated precisely:** the live egress policy is **already host-only
  and host-enforced**. izbad reads `~/.local/share/izba/sandboxes/<name>/policy.yaml`
  and never re-reads anything inside the guest while the sandbox runs. An agent
  editing a `policy.yaml` that happens to sit in the project root **does not
  change a running sandbox's restrictions.** The concern is narrower than "the
  agent edits its own firewall."
- **The residual risk is real but bounded:** (1) a *human* re-persist footgun
  (`izba run --policy ./policy.yaml` re-reads a possibly-tampered workspace file);
  (2) information disclosure + deception (the file the user trusts sits where the
  agent can rewrite it); (3) **forward risk** — the compose-for-microVMs manifest
  and the M5 credential vault must not regress this by putting authority in the
  workspace.
- **Under a hostile *kernel*, the options do not rank the way intuition
  suggests.** Option **B** (mount the in-repo control dir read-only *inside the
  guest*) provides **zero** security — guest-side `MS_RDONLY` is advisory to a
  kernel that can `remount,rw` or issue raw FUSE writes. It is the same tier as
  crun: defense-in-depth only. Option **A** (host-side pin + refuse-in-workspace)
  and Option **C** (host-only, never exported) are the only robust controls, and
  **C is the cheapest robust answer** because "not in any share" needs no new
  host-enforcement machinery.

## 1. The mechanism today (code-confirmed)

| Fact | Citation |
| --- | --- |
| `--policy FILE` is read **host-side** by the CLI, validated, then **copied** into the host state dir as `policy.yaml`. | `izba-cli/src/commands/mod.rs:104-118`; `daemon/egress/config.rs` `POLICY_FILE` |
| izbad loads/enforces from the **state-dir copy** at start and on hot-reload; reload re-reads the state-dir copy, **never** the original source path. | `daemon/egress/mod.rs:81-108`, `server.rs:439`, `daemon/egress/mod.rs:268-273` |
| Enforcement is **100% host-side** in izbad (MITM tier-1 + DNS-snoop/raw-TCP tier-2); the guest never sees the policy file. | `daemon/egress/{router.rs,mitm_runtime.rs,policy.rs}` |
| The `workspace` virtiofs share = the user's project dir, mounted **read-write** into the guest (`/workspace`). | `sandbox.rs:659-663`; `izba-init/src/mounts.rs:86` (no flags ⇒ RW) |
| The `izba-trust` / `izba-ssh` / `izba-oci` shares are "read-only" **only via a guest-side `MS_RDONLY` flag** set by init. virtiofsd (v1.13.3, one process per share) is launched with **no host-side read-only flag** — `--socket-path`, `--shared-dir`, `--cache auto`, `--sandbox <mode>` and nothing else. | `izba-init/src/mounts.rs` (`&["ro"]`→`MS_RDONLY`); `vmm/cloud_hypervisor.rs:61-77`; `hack/fetch-artifacts.sh:135` |
| crun inherits init's mounts; the OCI spec does not remount the workspace share. | `image/runtime_config.rs:317-332`; `izba-init/src/mounts.rs:124-135` |

## 2. What "the guest kernel is hostile" deletes

The guest trust domain is **{guest kernel, init/PID 1, crun container}** — one
domain, no internal boundary (threat-model A1; F-21 already records this for the
in-guest nft "deny"). Concretely, a hostile guest kernel can:

- ignore mount flags — `mount -o remount,rw /any/ro/mount`, or unmount an
  overmount init set up;
- **bypass the guest VFS entirely** and emit raw `FUSE_WRITE` / `FUSE_SETATTR`
  requests over the virtio-fs transport for any inode virtiofsd has exported.
  virtiofsd does not know or care how the guest *mounted* the share; it performs
  the op with **its own host process credentials**. izba runs virtiofsd as the
  invoking host user with no uid drop (F-06/F-29), so those credentials can write
  every file under `--shared-dir`.

**Therefore the only enforcement points that survive A1 are host-side:** (a) what
izbad/the CLI choose to *read* and *trust*, and (b) what virtiofsd is *able* to
write — which is governed by the host directory it is pointed at and the host
process credentials it runs as, **not** by any in-guest mount flag.

This single fact decides the A/B/C ranking below.

## 3. Option A — host-side pin + refuse-in-workspace

**Mechanism (host-only):** snapshot+hash the policy into host state at
create/apply time; never re-read the original source path while the sandbox is
live; if a `--policy` path canonicalises to *inside* the workspace, **warn loudly
and refuse** absent an explicit `--policy-allow-in-workspace` override (matches
the "loud on security degradation" UX rule). On any content change since the last
trust, refuse until the human re-approves (direnv model, §5).

**Why it is robust under A1:** every step runs on the host. It does not depend on
any in-guest enforcement, so the hostile-kernel assumption does not weaken it.

**Residual risks (all host-side, all real):**

1. **Re-persist / re-apply footgun.** A human re-running `--policy
   ./workspace/policy.yaml` re-reads a file the guest may have rewritten. The
   refuse-in-workspace guard closes the *accidental* case; the override flag
   re-opens it deliberately.
2. **Multi-sandbox shared-workspace poisoning (forward risk).** In
   compose-for-microVMs, several VMs share one project. VM-1 (hostile) edits the
   in-repo manifest; the user's next `izba up` re-reads it and poisons VM-2.
   Mitigated only by content-hash-on-change + explicit re-trust — **"copy once"
   is not enough.** A must be content-pinned, not merely snapshot-once.
3. **A does not relocate the file.** Disclosure and deception persist: the agent
   can still *read* the allow-list (probe gaps) and *rewrite* the in-repo copy to
   mislead a human reviewing the repo. A's mitigation for deception is indirect —
   `izba status` must show the **live host-pinned** policy so the human checks
   izba, not the repo file.
4. **A forbids any "reconcile policy from the repo while running" feature.** Under
   A1 you can never treat a guest-writable file as a source of truth that is
   periodically reconciled. This is a *design constraint A imposes*, not a bug.

**Verdict:** necessary and cheap; closes enforcement-integrity and the accidental
footgun. **Insufficient alone** for disclosure/secrets.

## 4. Option B — in-repo `.izba/`, read-only *inside the guest*

**Original framing:** keep config in-repo at `.izba/`; after mounting the
workspace, have init RO-bind-overmount `/rootfs/workspace/.izba` so the guest
"can't write it."

**This is null under A1.** The read-only-ness is enforced by the *guest kernel's*
VFS. A hostile kernel remounts it RW, unmounts the overmount, or issues raw FUSE
writes to virtiofsd for the underlying inodes — which virtiofsd serves, because
the workspace export is RW and virtiofsd runs as the host user. **B as a security
control is exactly as strong as crun: defense-in-depth against a *non-kernel*
compromise, nothing more.** Given the explicit "kernel is hostile" framing, B
must not be counted as a boundary.

Independent mechanical fragility (even ignoring A1): the RO overmount must
survive crun's mount setup/propagation, and a single virtiofs share has **uniform
host permission for its whole tree** — you cannot make `.izba` host-RO while the
rest of `/workspace` is RW *within one share* (see §6).

**"B done right" = host enforcement, at which point it is mostly C.** To make the
control dir genuinely write-protected against the guest you must serve it as a
**separate** export whose *host side* rejects writes. Three ways, all with cost:

- a virtiofsd that actually enforces a read-only export (the launched v1.13.3
  passes no such flag; support unverified — and even so it is whole-share, so a
  dedicated `.izba` share is required);
- the `.izba` virtiofsd running under a **dedicated read-only uid** (the uid
  jailer izba defers in F-29) — host *permission* enforcement;
- the `.izba` share fed from a **host read-only bind mount** (`mount
  -o remount,ro,bind` on the host, then `--shared-dir` that) so writes get EROFS
  from the *host* kernel — robust, but creating it needs host mount privilege,
  which the daemonless model lacks.

Each gets you host-enforced *write* protection but still leaks *read*
(disclosure). At that effort you have done most of C's work for strictly weaker
isolation. **Recommendation: drop B as a security control; keep an in-guest RO
mount only as cosmetic footgun-reduction, explicitly labelled DiD.**

## 5. Option C — host-only control plane (recommended), made good DX

**Mechanism:** the authoritative config never enters any virtiofs export. It is
read by the **host** (izba has full host-FS access to the project dir) and stored
under host state — e.g. `~/.local/share/izba/projects/<canonical-path-hash>/`.
Robust under A1 *for free*: there is no share for the guest to write **or read**,
so it is the only option that also closes disclosure (decisive for the M5 vault).

The objection is DX ("host-only is inconvenient"). Prior art shows the
**control-plane / data-plane split is the accepted norm**, and the inconvenience
is avoidable:

| Tool | Pattern | Lesson for izba |
| --- | --- | --- |
| **docker-compose** | `compose.yaml` lives **in the repo** (versioned, reviewable) but is read by the **host CLI/daemon** and **never mounted** into the containers it defines; only explicitly-listed volumes are. | The manifest can be in-repo *and* host-only. izba's wrinkle: it shares the *whole* cwd, so it must keep the control file **out of the served tree**, not merely "not list it." |
| **kubernetes / terraform** | Manifests in repo, applied by a host tool to a control plane / state backend; never mounted into the pod. Terraform explicitly steers `*.tfstate` **out** of the repo. | State and authority belong to the host side; the repo holds *source*, not *runtime authority*. |
| **direnv / mise / asdf** | `.envrc` / `.mise.toml` lives in-repo, but is inert until `direnv allow` / `mise trust`; trust is a **host-side, content-hashed allowlist** (`~/.local/share/direnv/allow/<hash>`). Any edit auto-distrusts until re-allowed. | This is exactly the fix for A's footgun: in-repo authoring convenience + host-side content-pin + **explicit re-trust on change**. Adopt it verbatim. |
| **VS Code Workspace Trust / `.vscode/`** | Editor refuses to run tasks from an untrusted folder; the trust decision is stored **host-side keyed by path**. | An in-repo control dir is fine if *activation* is a deliberate host-side act, not implicit. |
| **Claude Code** | Transcripts + project config under `~/.claude/projects/<hashed-project-path>/`, keyed by canonical project path. The user notes it is "not super convenient but accepted." | Direct precedent for host-state-keyed-by-project-path; community-accepted ergonomics. |

**Synthesised C-DX (docker-compose × direnv):**

1. `izba.yaml` (manifest) and policy live **in the repo** — versioned,
   diffable, discoverable (the DX win).
2. izba reads them **host-side** to create/configure sandboxes and **pins** the
   content (hash) into host state at `apply`/`up` time (the C win).
3. The pinned host copy is **authoritative**; the in-repo file is *source you
   must (re-)apply to activate*, **never live-reconciled** (closes A1 reconcile
   risk).
4. Any change to the in-repo file since the last apply ⇒ **refuse until the human
   re-approves** (`izba trust` / re-`apply`), direnv-style (closes the footgun +
   multi-sandbox poisoning).
5. `izba status` always renders the **live host-pinned** policy, so review never
   depends on the in-repo copy (closes deception).

If full non-disclosure is required (the vault), step (1) must additionally keep
the file **out of the served workspace tree** — i.e. genuine C, not "in-repo but
visible." For egress allow-lists, in-repo-but-visible (disclosure accepted, like
F-01's probing surface) is a reasonable tradeoff; for secrets it is not.

## 6. virtiofs tricks — honest enumeration

The load-bearing virtiofs fact: **a single virtiofs share has one uniform
host-enforced permission for its entire tree; per-subtree *host-enforced*
read-only requires a *separate* export. Any RO applied inside the guest is
kernel-advisory and null under A1.**

| # | Trick | Host-enforced under A1? | Cost / note |
| --- | --- | --- | --- |
| 1 | Guest-side `MS_RDONLY` (today's trust/ssh/oci) | ❌ No — advisory | Already used; **document as DiD-only.** A hostile kernel writes back into the host state subdir (see §7). |
| 2 | virtiofsd `--readonly` export (if the binary supports it) | ✅ Yes, but **whole-share** | v1.13.3 as launched passes no such flag; support unverified. Needs a **dedicated** `.izba` share. Read/disclosure still allowed. |
| 3 | Dedicated `.izba` share fed from a **host RO bind mount** | ✅ Yes (host kernel ⇒ EROFS) | Needs host mount privilege — daemonless model lacks it. |
| 4 | Dedicated `.izba` share served by a **read-only uid** | ✅ Yes (host perms) | Needs the F-29 uid jailer izba doesn't yet have on Linux. |
| 5 | **Don't export it (Option C)** | ✅ Yes (nothing to reach) | **Free**, and the only one that also kills disclosure. The strongest "trick" is the absence of a share. |
| 6 | virtiofsd `--sandbox namespace/chroot` | n/a | Protects the *host from virtiofsd*, not files-within-share from the guest. Orthogonal (F-06/F-07). |
| 7 | Overlay inversion (share RO lower, guest-side writable upper) | partial | Guest still *reads* the lower; a hostile kernel reads it directly. Adds complexity over 2–4, no real gain. |

**Verdict:** every robust virtiofs option reduces to "make the control plane a
separate host-enforced export." Since that still leaks reads and costs new
machinery, **C (no export) dominates whenever disclosure matters**, and **A
suffices whenever only write/enforcement-integrity matters** (because enforcement
never re-reads the guest file).

## 7. Recommendation, proposed invariant, and a related note

**Recommendation**

- **Ship A now** (host-side, cheap, robust): pin-at-apply with a content hash;
  never re-read a source path under the workspace while live; **warn + refuse**
  when `--policy` resolves inside the workspace (override = loud
  `--policy-allow-in-workspace`); make change-since-trust require explicit
  re-approval (direnv model).
- **Design the compose manifest + M5 vault around C** (host-state keyed by
  canonical project path; in-repo `izba.yaml` as *applied source*, not runtime
  authority). Secrets/vault material must be genuine C (never in any export).
- **Do not rely on B** (in-guest RO) as a control; if used at all, label it
  defense-in-depth alongside crun.

**Security invariant #9 (now canonical in threat-model §7):**

> *Authoritative control-plane/state input is never read from a guest-writable
> path while a sandbox is live; in-repo config is host-pinned at apply time and
> re-activation after any change is an explicit host-side act.*

**Related finding F-31 — the trust/ssh/oci shares are guest-RW under this same gap.**
Because their RO is guest-flag-only (§1), a hostile guest kernel can write back
into `~/.local/share/izba/sandboxes/<name>/{trust,ssh,oci}/`. Impact is **low
today** because each flows host→guest and tampering is self-directed (the guest's
own CA anchor / its own sshd keys / its own crun `config.json` read in-guest).
But it is a real **guest→host filesystem-write primitive bounded to those state
subdirs**. The standing rule: **do not add any host-side reader of those
directories that assumes the files are host-authored** — that would convert a
benign self-write into a host-trust bug. (virtiofsd `--sandbox namespace` +
openat2 confines path resolution to the shared subtree, so this does not extend
beyond those dirs — but it is exactly the kind of assumption that should be
written down.)
