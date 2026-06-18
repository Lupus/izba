# Vendor-neutral fine-grained git + HTTP-method egress controls (MVP-A)

**Status:** approved design (2026-06-18)
**Milestone fit:** pulls M5's `{host,method,path}` L7 split *forward*, scoped to a
shippable MVP, on top of M2's already-shipped MITM datapath. No new datapath
shape.
**Lineage:** adapts `Lupus/docker-mitm-bridge` `opa-policies/{policy.rego,data.yml}`,
but **de-marries it from GitHub** — keying on the git smart-HTTP wire protocol
(vendor-neutral) instead of `host == "github.com"`.

## 1. Problem & goal

M2 shipped a per-sandbox, default-deny **host:port** allow-list enforced by a
`regorus` engine over a TLS-MITM datapath. The MITM already decrypts every
request and the policy engine is already handed `input.host` / `input.method` /
`input.path` — but `egress.rego` consumes only `host` + `port`. Method and path
are plumbed-but-unused.

Two real controls are therefore one grammar+rego edit away, with **zero datapath
reshape**:

1. **Fine-grained, vendor-neutral git controls** — allow clone/fetch but not
   push (or neither, or both) **per repo / owner / host**, across
   github/gitlab/bitbucket/gitea/**any** HTTP git endpoint. Not GitHub-married.
2. **HTTP method-class controls** — allow only `GET`/`HEAD` to static mirrors
   (pypi, npm, crates) while leaving POST-based APIs (Anthropic, OpenAI) fully
   open. This is exactly the upstream `allowed_domains` (GET/HEAD) vs
   `unrestricted_domains` (all-methods) two-tier model, currently sitting inert
   in our data doc as `_upstream_tiers_for_M5`.

The unifying realization that makes both **one** feature: **`access: read |
read-write` is a single verb spanning both planes.** Git read = clone/fetch;
git write = push. HTTP read = `GET`/`HEAD`; HTTP write = everything else. One
mental model — *least-privilege read vs. full access* — applied to two resource
types (`allow:` hosts and `git:` repos), one UI picker, one CLI verb.

### Non-goals (explicitly deferred)

- **Ref-level write rules** (block push to `main`, block force-push). Requires
  parsing the `git-receive-pack` POST body (the `old-sha new-sha refname` pkt-lines)
  — a streaming/body-inspection datapath change. Out of this MVP.
- **Explicit `methods: [...]` lists** on a host. The two-value `access` verb
  covers the real cases; a power-user method-list escape hatch is a clean future
  add, deliberately deferred to keep the grammar tight.
- **Credential injection / per-role git tokens** — remains M5.
- **Git over SSH** — izba egress is HTTP-MITM; SSH git is opaque to L7 and is
  governed only at host:port (tier-2). Unchanged.

## 2. Decisions (locked during brainstorming 2026-06-18)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Dedicated top-level `git:` block, **repo-keyed** (`repo:`/`host:` globs). | Cleanest mental model; git is a named first-class concept, not raw path globs in the user's face. |
| D2 | Git rules govern **only git wire ops**; they self-grant the git endpoints. Ordinary HTTP to the same host (web UI, REST API, raw downloads) still needs an `allow:` entry. | Clean separation of concerns; most predictable; no accidental web-UI grant. |
| D3 | Depth = **read vs write per repo**. No ref-level, no POST-body parsing. | Decidable from method+path+query alone → no datapath reshape. |
| D4 | **`access: read \| read-write` is one shared verb** for both `allow:` hosts and `git:` repos. Omitted ⇒ `read-write` (back-compat + POST-API correctness). | Unifies the two features; resurrects the upstream two-tier model as a field, not two parallel lists. |
| D5 | **Posture is always explicit.** Every sandbox always has a `policy.yaml` carrying `enforce: true\|false`. The implicit "no file ⇒ allow-all" is removed; legacy sandboxes are backfilled to a written `enforce: false` on adoption. | Kills the empty-vs-missing footgun: one and only one way to read posture. |
| D6 | **Full UI scope**: `enforce` toggle + git section in PolicyEditor, git-aware netlog rows, CLI `izba policy git …` + `izba policy enforce on\|off`. | The feature's value is the cohesion of editor + buttons + netlog. |
| D7 | The `[80,443]` web-default-port literal gets **one source of truth**. | Removes the triple/quadruple-literal smell (Rust `DEFAULT_PORTS` + every `egress_data.json` entry + two TS copies). |

## 3. Grammar — `policy.yaml`

```yaml
enforce: true                    # D5: posture is ALWAYS explicit

allow:                           # ordinary HTTP host allow-list
  - api.anthropic.com            # string form → access: read-write, ports [80,443]
  - host: pypi.org
    access: read                 # GET/HEAD only (static mirror)
  - host: files.pythonhosted.org
    access: read
  - host: registry.npmjs.org
    access: read
  - host: db.internal
    ports: [5432]                # custom port, all methods (access omitted ⇒ read-write)

git:                             # vendor-neutral git rules (D1)
  - repo: github.com/myorg/app   # exact repo
    access: read-write           # clone/fetch + push
  - repo: gitlab.com/vendor/*    # owner/group glob
    access: read                 # clone/fetch only
  - host: bitbucket.org          # any repo on a host
    access: read
```

### 3.1 `allow:` entry forms (back-compat preserved)

`AllowEntry` is an untagged enum; **string** and **`{host, ports}`** forms parse
exactly as today.

- **String** `- api.anthropic.com` → `access: read-write`, ports `[80,443]`.
- **Object** `{ host, ports?, access? }`:
  - `ports` optional, default `[80,443]` (D7's single constant).
  - `access` optional, default `read-write`.
  - So `{host: pypi.org, access: read}` needs no `ports`; `{host: db.internal,
    ports: [5432]}` needs no `access`.

`access` semantics for an HTTP host:
- `read-write` (default) → any method on the listed ports.
- `read` → only `GET`/`HEAD` on the listed ports.

`read` is opt-in by design: POST-based APIs must stay all-methods, so the safe
default never breaks them.

### 3.2 `git:` rule forms

`GitRule { target, access }` where `target` is one of:
- `repo: <glob>` — `host/owner/repo`, `.git` suffix optional, `*` allowed
  (`gitlab.com/vendor/*`, `github.com/myorg/app`). Subgroups (`gitlab.com/g/sub/repo`)
  are matched by the full path or a deeper glob.
- `host: <glob>` — any repo on a host (`bitbucket.org`).

`access`:
- `read` → clone/fetch (`git-upload-pack`).
- `read-write` → push (`git-receive-pack`), **implies read**.

Git rules **self-grant** the matched git wire endpoints (any port — HTTP git is
`:443`/`:80` in practice, but a custom-port git server still works since the op
identity, not the port, is what's matched) — no separate `allow:` host entry is
needed to clone/push. They do **not** grant ordinary HTTP to that host (D2).

## 4. Vendor-neutral git matching (the wire protocol)

Git's "smart HTTP" protocol is identical across all servers. The read/write
discriminator lives in **path + query**, never the host:

| Operation | Capability discovery | Data transfer |
|-----------|----------------------|---------------|
| **read** (clone/fetch) | `GET  <repo>/info/refs?service=git-upload-pack` | `POST <repo>/git-upload-pack` |
| **write** (push) | `GET  <repo>/info/refs?service=git-receive-pack` | `POST <repo>/git-receive-pack` |

Both legs of each operation must be authorized for it to proceed (the client
issues the discovery `GET` first, then the data `POST`). A **read** grant allows
the upload-pack pair; a **write** grant additionally allows the receive-pack
pair. Crucially, `?service=git-receive-pack` on the discovery `GET` is what
distinguishes a push attempt from a fetch — so the **query string is
load-bearing**.

`repo_id(host, path)` derivation: strip the trailing `/info/refs`,
`/git-upload-pack`, or `/git-receive-pack` from the path, strip an optional
`.git`, and prefix `host` → `host/owner/repo[/subgroup…]`. Match (via
`glob.match`) against the `git:` rule targets.

### 4.1 Datapath-adjacent change (the one honest line item)

The MITM currently builds both the audit `L7Request` and the policy input from
`req.uri().path()` — **dropping the query string** (`crates/izba-core/src/
daemon/egress/mitm.rs`, the `L7Request` builder + the `FlowDesc` construction
sites use `req.uri().path().to_string()`). The handler already has
`req.uri().path_and_query()` (used by `rewrite_outgoing_host`).

Change: capture the query so the policy can see `?service=…`. Two options,
**chosen: (a)**:
- **(a) Add `FlowDesc.query: Option<String>`** (and the matching `L7Request`
  field) populated from `path_and_query`'s query part; `input_json` emits
  `input.query` as a parsed object `{service: "..."}` (mirrors upstream's
  `input.request.query.service`). Keeps `path` clean (no query), matches the
  upstream rego shape, audit log gains the query for git-op legibility.
- (b) Fold query into `path`. Rejected: forces the rego to substring-parse and
  pollutes the audit `path`.

This is a **field capture from an already-parsed URI** — not a streaming, body,
or connection-shape change. The OpenVMM churn invariant and the blocking vsock
plane are untouched.

## 5. Rego — `egress.rego` (rewrite, replacing the inert M5 stub)

The commented-out `_upstream_tiers_for_M5` block and the dead `allow if {…}`
stub at the bottom of `egress.rego` are **deleted** and replaced by live,
tested, vendor-neutral rules. Sketch (final form in implementation):

```rego
package egress
import rego.v1

default allow := false

dest_name := input.host
dest_name := input.dest if not input.host

read_method if input.method in ["GET", "HEAD"]

# --- HTTP host allow-list (D4: access verb) ---
# data.host_rules[dest_name] = {"ports": [..], "access": "read"|"read-write"}
allow if {
    rule := data.host_rules[dest_name]
    input.port in rule.ports
    host_access_ok(rule.access)
}
allow if {
    rule := data.sandbox_host_rules[input.sandbox][dest_name]
    input.port in rule.ports
    host_access_ok(rule.access)
}
host_access_ok("read-write")
host_access_ok("read") if read_method

# --- Vendor-neutral git rules (D1/D2/D3) ---
git_op := {"service": svc, "kind": kind} if { ... }   # parse path+query
repo := repo_id(input.host, input.path)
allow if {
    rule := matching_git_rule(repo)                   # glob.match over data.git_rules
    git_op.kind == "read"
    rule.access in ["read", "read-write"]
}
allow if {
    rule := matching_git_rule(repo)
    git_op.kind == "write"
    rule.access == "read-write"
}

# decision := {allow, reason} preserved; reason gains
# "allowed: git read myorg/app" / "denied: git write not authorized" etc.
```

Fail-closed behavior (eval error or `false` ⇒ Deny) is unchanged. The two
upstream tiers are now expressed as `access` on `host_rules`, not two lists.

## 6. Config compiler — `config.rs`

`EgressPolicyConfig` gains:

```rust
pub struct EgressPolicyConfig {
    #[serde(default)]                 // D5: default false, but always written
    pub enforce: bool,
    #[serde(default)]
    pub allow: Vec<AllowEntry>,
    #[serde(default)]
    pub git: Vec<GitRule>,
}
```

- `AllowEntry::Scoped` grows `access: Access` (default `ReadWrite`) and makes
  `ports` optional (default = `WEB_DEFAULT_PORTS`). `AllowEntry::Host(String)`
  unchanged.
- `enum Access { Read, ReadWrite }` (serde `read` / `read-write`), shared by
  `AllowEntry` and `GitRule`.
- `GitRule { target: GitTarget, access: Access }`, `enum GitTarget { Repo(String),
  Host(String) }`.
- `to_rego_data_json` emits `host_rules` / `sandbox_host_rules` as
  `{ports, access}` maps **plus** `git_rules` (a list of `{target, access}`),
  replacing the old `global_domains` / `sandbox_ports` port-only maps.
- New editor helpers mirroring the existing `allow`/`block`:
  `git_allow(target, access)`, `git_block(target)`, `set_host_access(host,
  access)`, `set_enforce(bool)`. All edits route through these so CLI + app stay
  consistent (the M2.1 "one core grammar helper" principle).

### 6.1 Posture & migration (D5)

- **Create** always materializes `policy.yaml`: a bare sandbox gets
  `enforce: false` (today's allow-all, stated). `izba create --policy <file>`
  loads the user's file; if it lacks `enforce:`, default to **`true`**
  (fail-safe: authoring a policy signals intent to enforce).
- **Load / adopt**: a sandbox whose dir has **no** `policy.yaml` (legacy,
  pre-this-change) is treated as `enforce: false` and backfilled by writing the
  explicit file, so going forward there is exactly one representation.
- `enforce: false` ⇒ `AllowAll` (non-enforcing). `enforce: true` with empty
  `allow`+`git` ⇒ deny-all — now explicit, not inferred. The CLI/app still warn
  loudly on an enforcing-but-empty policy ("this denies all egress — intended?").

## 7. Smell consolidation (folded in, not bolted on)

| Smell | Resolution |
|-------|-----------|
| **Inert M5 rego stub** + `_upstream_tiers_for_M5` data keys | **Deleted**, replaced by the live `access`-based host rules (§5). The two tiers are reborn as a field. |
| **Empty-vs-missing `policy.yaml`** footgun | **Resolved** by D5/§6.1: posture is an explicit `enforce` field, always present. |
| **`[80,443]` triple/quad-literal** | **One source of truth** (D7): a Rust `WEB_DEFAULT_PORTS` const (already `DEFAULT_PORTS`) drives the compiler and the embedded default-policy generation (generate, don't literal-list per host); exported to the frontend as a single `WEB_DEFAULT_PORTS` TS const consumed by both `PolicyEditor` and `NetlogView`, replacing the four inline copies. |

## 8. UX (D6 — Full scope)

Existing surface: `PolicyEditor` (host+ports chips), `NetlogView` (live table,
allow/block, already captures `last_method`/`last_path`), `FirewallStatus` badge.
Types in `app/src/lib/types.ts`, IPC in `app/src/lib/ipc.ts`.

- **PolicyEditor**
  - An **`enforce` on/off toggle** at the top (D6 — flippable here and in CLI,
    not just hand-edited). Off ⇒ the rest is visibly disabled ("bare sandbox").
  - A shared **read / read-write picker** component, used on both host rows and
    a new **Git repos** section (repo/host glob input + the picker).
- **NetlogView**
  - Recognizes git wire ops from `last_method` + `last_path` and renders them as
    `git clone → owner/repo` / `git push → owner/repo` rows.
  - Action buttons write `git:` rules: **allow-read**, **allow-write**, **block**.
    For plain HTTP rows, "block" additionally offers **restrict to read** (sets
    `access: read`). Raw-IP rows keep the disabled-Allow SSRF guard.
- **CLI** (`crates/izba-cli/src/commands/`)
  - `izba policy git allow <target> [--write]` / `izba policy git block <target>`.
  - `izba policy enforce on|off`.
  - Existing `izba policy show/allow/block/enable/reload` extended to render the
    `git:` section and `enforce` state; `izba netlog --summary` labels git ops.
- **IPC / types**: `PolicyView` gains `enforce: boolean` + `git: GitRule[]`;
  `EndpointSummary` already has `last_method`/`last_path`. New invokes:
  `policy_git_allow`, `policy_git_block`, `policy_set_enforce`,
  `policy_set_host_access` (or fold into the existing `policy_set`).

## 9. Testing & verification

- **Rego table tests** (in `policy.rs`, pure in-memory — sandbox-safe) proving
  vendor-neutrality across **github / gitlab / bitbucket / gitea / a bare
  self-hosted host**: each of {clone allowed, push denied-when-read, push
  allowed-when-read-write, discovery-GET service split, `.git`-suffix and
  no-suffix paths, owner-glob, host-glob, non-git HTTP to the host falls through
  to host allow-list}.
- **HTTP `access` tests**: `read` host allows GET/HEAD and denies POST; default
  (omitted) allows POST; port scoping still composes with `access`.
- **Config tests**: round-trip of the new `enforce`/`git`/`access` YAML;
  back-compat — every existing string-list and `{host,ports}` file parses
  unchanged and means `read-write`; `enforce` default for hand-authored files.
- **Migration test**: a sandbox dir with no `policy.yaml` loads as
  `enforce:false` and is backfilled.
- **Smell tests**: a single `WEB_DEFAULT_PORTS` constant (grep-assert no stray
  `[80, 443]` literals in production paths); the rego no longer references the
  deleted tier keys.
- **Frontend**: `policyEditor.test.tsx` / `netlogView.test.tsx` extended for the
  enforce toggle, the read/read-write picker, and git-op row recognition.
- **The six workspace gates** + the **app gate** (`izba-core`/`izba-proto`
  public types change → run `cd app && npm ci && npm run build && (cd src-tauri
  && cargo clippy --all-targets -- -D warnings && cargo test)` per CLAUDE.md).
- **e2e** (KVM + WHP): a real in-guest `git clone` of an allowed repo succeeds
  and `git push` to a read-only repo is refused, both platforms.

## 10. Risks

- **Git-over-HTTP variants**: some servers serve `info/refs` at slightly
  different sub-paths or use dumb-HTTP (no `?service=`). Mitigation: the
  vendor-neutral matcher keys on the well-specified smart-HTTP shape; dumb-HTTP
  fetch falls through to the host allow-list (deny-by-default if not listed) —
  documented, acceptable for MVP.
- **GitLab subgroups** deepen the repo path; `repo:` exact + `*` globs cover the
  common cases, `host:` covers the rest. Documented.
- **`enforce` default for hand-authored files = true** could surprise a user who
  hand-writes a permissive-looking file; mitigated by the loud
  enforcing-but-empty warning and by izba always writing the field.
- **Query plumbing** touches `mitm.rs`; covered by §4.1 being a pure field
  capture + the e2e git tests.

## 11. Out-of-scope follow-ups (named, not built)

- Ref-level write rules (force-push / protected branches) — needs receive-pack
  body parsing.
- Explicit `methods: [...]` host escape hatch.
- Git-over-SSH L7 controls.
- Credential injection for git (M5).
