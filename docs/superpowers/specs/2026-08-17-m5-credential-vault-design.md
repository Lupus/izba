# M5 — credential vault: per-role injection over an OpenShell-compatible provider format

**Status:** proposed design (2026-08-17) — brainstormed with the owner, not yet approved for an implementation plan.
**Scope:** M5. Touches the egress policy grammar, the MITM datapath, a new credential subsystem, the manifest, the CLI, the daemon control plane, and one open security finding (F-09).
**Grounded in:** [docs/credential-proxying-building-blocks.md](../../credential-proxying-building-blocks.md) (the survey — four families, the injection ladder, the failure list), [docs/roadmap.md](../../roadmap.md) §M5, [docs/vision.md](../../vision.md) (capability-not-secrets, locked), [docs/security/policy-state-guest-isolation.md](../../security/policy-state-guest-isolation.md) (Option C — vault material is host-only), and NVIDIA OpenShell `providers-v2` (Apache-2.0, commit `d51a653f9cedeafa602364df61b74c4bd5a9495e`).

---

## 1. Problem

A sandboxed agent needs to call `api.anthropic.com`, push to GitHub, and hit a private API. Today the only way is to put the real credential inside the guest, where a prompt-injected or compromised agent can read it and exfiltrate it. The goal is **a credential the agent can use but cannot keep**: nothing that still works outside the sandbox ever enters it.

**In scope (V0 + V1):**

- Family A (bearer-shaped): strip, inject, and sentinel-redeem at the MITM — API keys, the GitHub API, git-over-HTTPS.
- Family B (OAuth-minted): host-side `izba login`, plus in-band harvest of RFC 6749 token responses.
- Ingestion of unmodified OpenShell `providers-v2` provider files, one-way, with a per-field compatibility lint.
- A third policy axis — **inspectability** — that decouples "izbad may parse this as HTTP" from port numbers and from credentials.
- Closing **F-09** (no peer-credential check on izbad's control socket), which is a prerequisite rather than a nicety.

### Non-goals (explicitly deferred)

- **Family C (signature-based: AWS SigV4, GCP SA JWT).** Needs either request re-signing or a guest-facing short-lived-credential broker. Named in §13.
- **Family D (SSH agent brokering, database protocols).** Same reason.
- **SPIFFE / `token_grant`.** izba has no workload identity; rejected at load (D16).
- **Downscoping minters** (GitHub App installation tokens, STS session policies, RFC 8693). This is rung 1 of the ladder and the biggest remaining security win, but it is a separate arc.
- **OCSF audit schema.** The audit record grows typed credential fields (D-audit); mapping them onto OCSF is deferred.
- **Metering and budgets.** The records make it possible; no UX is designed.

---

## 2. Constraints

- **A1 — the guest is hostile from the first instruction.** Anything computed inside the microVM is attacker-supplied. This is what makes binary attribution advisory rather than authoritative (D13), and what makes host-only vault material non-negotiable.
- **Option C (F-30).** Vault material must never enter any virtiofs export. In-guest read-only is null under A1 — virtiofsd serves raw FUSE writes as the host user.
- **No secrets in `izba.yml`, ever.** The manifest may carry references; never material.
- **#138 — an unknown key must never silently widen scope on any ingestion path.** This forces izba to parse provider files *more strictly* than upstream does (D4).
- **Never silently downgrade a security control.** Every degradation is loud, at install time and in `status`.
- **The vsock plane is blocking, and the OpenVMM churn invariant holds.** Nothing here may change the guest leg's blocking semantics.
- **Tier-2 is an opaque splice.** `router.rs:294-299` pumps bytes with no L7 visibility. Any destination that must carry a credential has to reach tier-1, and that must be a declared, checkable property rather than an accident of port numbering.

---

## 3. Decisions

Locked during brainstorming, 2026-08-17.

| # | Decision | Rationale |
| --- | --- | --- |
| **D1** | **Three orthogonal policy axes: reachability, inspectability, injectability.** Each is declared explicitly, each strictly narrows the one above it, and installing a provider can never widen any of them — it fails with a message naming the axis to open. | The survey's "two allowlists, not one" (§4.1), extended to the axis that was hiding inside "tier-1". Conflating reach with injection is exactly how an allowed host becomes an exfiltration channel. |
| **D2** | **Inspectability becomes a first-class policy field**, `protocol: http \| tcp` on an allow entry, implicit `http` on 80/443. The tier-1 gate at `router.rs:245` stops testing `matches!(port, 80 \| 443)` and asks the policy instead. | Deriving MITM from "a credential exists here" would make a credential operation silently change firewall behaviour. It also blocks L7 rules on an internal API on `:8000`, which is wanted independently of credentials — pre-existing M2 debt. |
| **D3** | **Inspect-versus-passthrough is decided before TLS termination**, from the ClientHello SNI obtained by a non-consuming peek. | `mitm_runtime.rs:266-275` already peeks without consuming, and its own comment notes the datapath is "robust regardless of port". Deciding on the real handshake avoids any dependence on DNS-snoop, which the docs are explicit is not a security boundary. |
| **D4** | **Ingest unmodified OpenShell `providers-v2` files, one-way (OpenShell → izba), failing closed per field**, with `izba provider lint` printing a per-field honored / advisory / rejected table. izba rejects unknown keys even though upstream ignores them. | Delivers reuse of an existing provider ecosystem without inheriting a laxer ingestion contract. Upstream has **no `deny_unknown_fields` and no version marker at all**, so strict parsing is safe today and fails loudly on future drift instead of silently. |
| **D5** | **Reimplement the provider DTO; do not depend on `openshell-providers`.** Vendor only pure functions, with SPDX headers preserved and the upstream commit recorded. | `ProviderTypeProfile` is exported but **every component type is private** — a downstream crate can read a field but cannot name, construct, or match `CredentialProfile`/`EndpointProfile`/etc. Depending on the crate also drags tonic, prost, tokio-full and a protoc-invoking `build.rs` in order to parse YAML. |
| **D6** | **Credential binding resolution is typed Rust, not Rego.** `egress.rego` is untouched; `allow` and `resolvable` keep their current meaning. | Matches upstream (its binding table is Rust; only the network decision is OPA). Matches the house rule that IP/CIDR logic never goes in Rego. Keeps the security-critical matcher unit-testable without marshalling headers into a policy engine. Supersedes the roadmap's assumption that M5 extends `egress.rego`. |
| **D7** | **Ambiguous bindings are rejected at install, never tie-broken at runtime.** | Upstream's runtime tie-break is lexicographic max of the raw tab-joined key string — an artifact of `(u32, String)` tuple ordering, not a design. Upstream itself rejects ambiguity at authoring time for `audience_overrides`; that is the better half of its own design. |
| **D8** | **izba honors `auth_style` as the authoritative injection location.** Substitution happens there and nowhere else, with upstream's opt-ins preserved for body and WebSocket. | Upstream stores and validates `auth_style` but leaves it **inert for static credentials**, resolving a placeholder wherever it appears. Honoring it makes izba a behavioural superset on a field upstream ignores — strictly narrowing, so no upstream file breaks. |
| **D9** | **Placeholders use izba's own format** (`izba:resolve:env:v<N>_KEY`), accept the upstream form inbound, and add **shaped placeholders** (`opaque \| jwt \| prefixed:<p>`) as an izba extension. The revision-scoped resolution rule is adopted verbatim. | Provider files declare env var *names*; the placeholder value is generated by the runtime and never appears in a file — so choosing our own format costs nothing. Shapes matter because clients parse tokens locally (upstream had to mint a JWT-shaped dummy for Codex's `id_token`). The revision rule stops a stale process resolving a replacement provider's credential. |
| **D10** | **A built-in credential store is the primary path** (`izba credential set`): OS keyring where available, else a sealed file. `secretRef` (`env:`/`exec:`/`file:`) is a secondary source. **Refresh material is a separate, structurally non-injectable type.** | Owner's call, matching the Docker `sbx` UX. The non-injectable refresh type is upstream's rule and worth copying verbatim: no placeholder may ever resolve to refresh material. **Caveat added 2026-08-17 (§10):** the store shares one gate with the control socket on both platforms, and DPAPI/libsecret unseal silently for the owning user — so the built-in store resists offline theft, not a compromised account. An interactive-confirmation `exec:` resolver is the strictly stronger option and should be documented as such where a user has one, rather than presented as merely an alternative. |
| **D11** | **Never inject into a cleartext leg unless the endpoint explicitly declares it** (`tls: none`). | Injecting a bearer token into plain HTTP puts the real secret on the wire beyond izbad. Upstream's SPIFFE example uses `tls: none` for exactly the legitimate case — an in-cluster `http://` token issuer. |
| **D12** | **A provider file can never turn inspection *off*.** An imported endpoint with `protocol: ""` on 443 is honored as *inspect*; only the operator's `policy.yaml` may open the pinning passthrough. | An installable artifact must not be able to author a security downgrade. izba may enforce more than a file declares, never less — and `lint` says so rather than leaving it surprising. |
| **D13** | **`binaries[]` is accepted as an AND-only advisory narrowing of egress admission**, labeled advisory at install, in `provider show`, and in the audit record. It may never grant an exemption. | izba-init is izba's own code outside the workload's namespaces, so its attestation is sound against a contained workload and worthless against a guest escape. An attestation that can only narrow is strictly non-negative: forged, you land on the baseline you would have had without it. Note upstream also uses `binaries` for **network admission, not credential selection**. |
| **D14** | **F-09 (`SO_PEERCRED` on the control socket) lands in this arc, before any grant can attach.** | With a vault attached, "any local process can drive izbad" becomes "any local process can spend the user's credentials". Shipping the vault first would be a net security regression. |
| **D15** | **Family B: host-side `izba login` is the primary path; in-band harvest is secondary.** | Relocation is what the field converged on and the only option that also works for pinned providers. Harvest is unusually cheap for izba (everything is already MITM'd) and covers device and paste flows generically, but carries the structural-validity and redeemable-refresh hazards. |
| **D16** | **`token_grant`/SPIFFE and `credential_signing`/SigV4 are rejected at load**, naming the missing capability. | izba has no workload identity and no re-signing path. A named rejection is honest; silently ignoring the field would give weaker enforcement than the file declares. |

**Deferred (not built now):** rung-1 downscoping minters, the guest-facing broker plane for families C and D, OCSF, metering, and per-container attribution via the docker-mode veth topology (§13).

### 3.1 Staging — this spec is deliberately larger than one plan

It should be decomposed into four sequenced plans, in the shape the USB feature used (phases, each independently green on all gates):

| Phase | Content | Independently valuable? |
| --- | --- | --- |
| **P0** | F-09 `SO_PEERCRED` (D14) | **Delivered** — closed an open MED finding on its own |
| **P1** | The inspectability axis: `protocol` field, `Policy::inspects`, the router gate, the SNI pre-peek and passthrough hatch (D2, D3, D12) | **Delivered** — paid off the M2 debt; L7 rules on any declared port and the pinning hatch landed with no credential code at all. Plan: [2026-08-18-m5-p1-inspectability](../plans/2026-08-18-m5-p1-inspectability.md) |
| **P2** | Provider ingestion, lint, store, binding + specificity, and family-A injection (D4–D11, D13, D16) | Yes — the bulk of the daily value |
| **P3** | Family B: `izba login`, then in-band harvest (D15) | Yes |

P1 is the load-bearing sequencing choice: it is a pure egress-policy improvement that ships and is tested before any credential exists, so a regression in the firewall datapath cannot be confused with a regression in the vault.

---

## 4. Architecture

```
                     policy.yaml  (host-only, operator-authored)
                     ├── allow[]           → REACHABILITY
                     └── allow[].protocol  → INSPECTABILITY
                                                  │
  guest                                           │        <data>/credentials/
  ┌───────────────┐                               │        ├── providers/<id>.yaml   ← providers-v2
  │ agent         │  Authorization:               ▼        └── store/               ← sealed material
  │  izba:resolve │  Bearer izba:resolve…   ┌──────────────────────────────┐
  │  :env:v3_KEY  │ ───nft REDIRECT───┐     │ izbad                        │
  └───────────────┘                   │     │                              │
         │ vsock 1027                 └────▶│ router::tcp_connect          │
         ▼                                  │   ├ SSRF floor (unchanged)   │
  <run>/vsock.sock_1027                     │   └ policy.inspects(port)?   │
                                            │        │yes          │no     │
                                            │        ▼             ▼       │
                                            │   peek ClientHello  tier-2   │
                                            │   SNI passthrough?  opaque   │
                                            │        │no                   │
                                            │        ▼                     │
                                            │   MITM: serve_mitm           │
                                            │    └ handle_request          │
                                            │       1 Host/SNI guards      │
                                            │       2 policy.check         │
                                            │       3 rewrite_outgoing_host│
                                            │       4 CREDENTIAL RESOLVE ──┼──▶ INJECTABILITY
                                            │         strip → bind → inject│    (provider endpoints
                                            │       5 audit                │     ∩ sandbox grant)
                                            │       6 upstream_send        │
                                            └──────────────────────────────┘
                                                          │ TLS verified vs vetted Host
                                                          ▼   (webpki, unchanged)
                                                      upstream
```

The credential decision sits at step 4, after the host is pinned by `rewrite_outgoing_host` and before the request leaves. That is the only point in the codebase with a decrypted, policy-vetted request, a mutable `HeaderMap`, and a host that is guaranteed equal to the certificate host and the upstream wire host.

---

## 5. The inspectability axis

### 5.1 Grammar

```yaml
enforce: true
allow:
  - api.anthropic.com                 # bare host ⇒ ports [80,443], protocol http (implicit)
  - host: internal.example.com
    ports: [8000]
    access: read-write
    protocol: http                    # NEW — L7-inspectable, so rules and injection apply
  - host: pinned.vendor.com
    ports: [443]
    protocol: tcp                     # NEW — pinning escape hatch; loud, no injection
  - host: db.internal
    ports: [5432]                     # protocol omitted ⇒ tcp ⇒ tier-2, as today
```

`protocol: http` means *HTTP semantics*; whether the leg is TLS is decided by the wire peek, not the declaration, so it cannot be wrong about which. `tls:` (on an imported provider endpoint) is therefore an **assertion izba can check** against the observed handshake, not an instruction — a mismatch is a deny.

Values: `http` (alias `rest` on import) and `tcp`. `graphql`, `mcp`, `json-rpc`, `sql` and `websocket` rule grammars are rejected at install with a named reason (D4) — izba's rule vocabulary is method, path, and the vendor-neutral git rules.

### 5.2 Why `protocol: tcp` on 443 is the pinning hatch

The survey requires a documented passthrough for TLS-pinned clients that no MITM can serve. `protocol: tcp` on a specific host is that hatch: it is operator-authored (D12), it is reported by the CLI, and it disables injection for that host by construction. Per D3 the decision is taken on the ClientHello SNI before termination.

**`protocol: http → tcp` on a host is a `⚠ weakens egress` transition** — it drops L7 enforcement — and must be flagged by `manifest::diff::egress_weakens` alongside its CLI and GUI renderers.

**As delivered (P1, 2026-08-18) — three corrections to the paragraphs above, each of which narrows rather than widens.**

*The hatch does rest on DNS-snoop, and must.* This section originally said the SNI decision "does not rest on DNS-snoop". That is wrong, and the reason is worth recording: the SNI is a string the **guest** chooses, and a passthrough performs no upstream certificate verification by construction — that is the whole point. Deciding on the SNI alone would therefore splice a guest-chosen *address* on the strength of a guest-chosen *name*, i.e. an unrestricted exfiltration channel. Tier-1 does not have this problem because it verifies the upstream certificate against the vetted host. So `router::passthrough_names` derives the candidate set from what izbad's **own resolver** answered for that destination, filtered through `decide_tier2`: **a passthrough flow is exactly a tier-2 flow that additionally proves its SNI**, inheriting the DNS-rebinding guard unchanged. A second, independent `policy.check` per candidate name is retained deliberately — during implementation the axis was briefly computed by two folds that disagreed (`to_rego_data_json` last-wins vs a unioning `InspectionTable`), which produced a live hatch on a host the allow-list denied; that filter was the only thing closing it.

*The hatch is reported by `izba policy show`, not `izba status`.* `status` renders no egress posture at all. Since `izba policy allow` also writes `policy.yaml` directly without passing the `izba diff`/`promote` weakening gate, `policy show` is the **only** surface in the product that reveals a pinning passthrough, and its warning is worded to carry that weight alone. An egress block in `status` is a named follow-up.

*Two weakening transitions, not one.* `manifest::diff::egress_weakens` flags a newly-declared passthrough **and** the loss of inspection on a still-reachable port. The second is not reducible to the first: `inspects(port)` is policy-global and port-keyed — it must be, since the tier-1 gate decides before the handshake and has no host — so removing one host's `protocol: http` entry can drop a *different* host from L7 to opaque, which no per-host fold can see. Both checks consult `InspectionTable` rather than re-folding `protocol`, so the diff cannot drift from the datapath.

Two further rules P1 settled: an explicit `protocol: tcp` on a **wildcard** host is a parse error (matching an SNI against a wildcard would fork the wildcard semantics that live in `egress.rego`, and a divergence there is exactly the shape of a security bug), and the hatch is **TLS-only** — a cleartext leg has no pinning to protect, so it always terminates.

---

## 6. OpenShell `providers-v2` compatibility contract

One-way: an unmodified upstream file installs into izba, or fails with a per-field reason. izba files may use extensions (D9) and are not expected to load upstream. There is **no version marker in the format**, so a file is recognised by shape and the source commit is recorded at install.

| Field | izba | Note |
| --- | --- | --- |
| `id`, `display_name`, `description`, `category` | honored | `category` parsing normalises case and `-`→`_`, as upstream |
| `credentials[].name`, `.env_vars`, `.required` | honored | `env_vars` may not use the reserved revision namespace |
| `credentials[].auth_style` + `header_name` / `query_param` / `path_template` | **honored, more strictly than upstream** | D8. Upstream leaves these inert for static credentials |
| `credentials[].refresh` (`static`, `external`, `oauth2_refresh_token`, `oauth2_client_credentials`) | honored | material stored as the non-injectable type (D10) |
| `credentials[].refresh` (`google_service_account_jwt`, `aws_sts_assume_role`) | **rejected** | family C; no signing path (D16) |
| `credentials[].token_grant` | **rejected** | no SPIFFE workload identity (D16) |
| `endpoints[].host`, `.port`, `.ports`, `.path` | honored | `ports` wins over `port`, as upstream |
| `endpoints[].protocol` | honored as a **positive** declaration only | D12 — never disables inspection |
| `endpoints[].tls` | honored as a checkable assertion | `none` also gates D11; `skip`/`passthrough` rejected on a credential-bearing endpoint |
| `endpoints[].access` | honored, mapped | `read-only` → izba `read`; `read-write` and `full` → izba `read-write`. izba has no third tier, so `full` is recorded by `lint` as mapped-not-identical |
| `endpoints[].rules[]`, `.deny_rules[]` (REST subset: `method`, `path`) | honored | `rules` absent ≠ empty; `rules: []` and `deny_rules: []` stay validation errors, as upstream |
| `endpoints[].rules[]` (graphql/mcp/json-rpc/sql/websocket forms) | **rejected** | izba cannot enforce those vocabularies |
| `endpoints[].request_body_credential_rewrite`, `.websocket_credential_rewrite` | honored, default `false` | with upstream's 256 KiB cap and content-type allowlist |
| `endpoints[].credential_signing`, `.signing_service`, `.signing_region` | **rejected** | family C (D16) |
| `endpoints[].allowed_ips` | honored | intersected with the SSRF floor, which always wins |
| `binaries[]` | **accepted as ADVISORY** | D13; both the bare-string and object forms parse |
| `resource_version`, `source`, `scope`, `annotations` | parsed, ignored | gateway-side state; `annotations` are explicitly unverified upstream |
| unknown keys | **rejected** | #138 (D4) — upstream silently ignores them |

**Endpointless profiles** (upstream binds them via a policy-side `credential_binding`) install, but grant attachment requires izba-side endpoints; `lint` says so.

---

## 7. Components

### 7.1 `crates/izba-core/src/daemon/egress/config.rs`

`AllowEntry::Scoped` gains `protocol: Protocol` (`#[derive(Default)] Http` for 80/443, else `Tcp`), with `is_default_protocol` for `skip_serializing_if` so canonical YAML stays unchanged for existing files. Parsing goes through the existing manual walk — a new `parse_protocol` leaf helper beside `parse_access` (`config.rs:818`), and a new `other =>` arm entry in the valid-keys error string. `AllowEntry::protocol()` joins `host()/ports()/access()` as the single place the "omitted ⇒ default" rule lives.

`to_rego_data_json` is **unchanged**: `protocol` is consumed in Rust at the router gate, never by Rego (D6).

### 7.2 `crates/izba-core/src/daemon/egress/policy.rs`

`trait Policy` gains one method: `fn inspects(&self, port: u16) -> bool`, plus `fn passthrough_host(&self, host: &str) -> bool` for the SNI-keyed hatch. `AllowAll` returns `false` for both (a bare sandbox is never MITM'd — M1 behaviour preserved). `RegoPolicy` answers from the compiled config rather than the engine.

### 7.3 `crates/izba-core/src/daemon/egress/router.rs`

The gate at `:245` becomes `if policy.enforces() && policy.inspects(port)`. The fail-closed `None => …` arm for an unavailable MITM runtime is unchanged and now covers every inspected port. The SSRF floor and the USB guard are untouched and still run first.

### 7.4 `crates/izba-core/src/daemon/egress/mitm_runtime.rs`

The 5-byte classification peek grows to a ClientHello-sized non-consuming peek. When the bytes are a ClientHello, SNI is extracted **before** termination — parsed from the peeked buffer, since `peek` leaves the bytes in the socket for either path to re-read. If `policy.passthrough_host(sni)` the connection is spliced with `pump_bidirectional` and audited as `Tier::L3` / `passthrough`; otherwise it terminates exactly as today. The passthrough path replays nothing, because nothing was consumed.

**Implementation hazard to handle explicitly:** a ClientHello can span more than one TCP segment, so a single `peek` may return a short buffer. The loop must retry to a bounded limit and then **fail closed to termination** (the inspected path), never to passthrough — a short read must not become a way to escape inspection. This is the one place where the obvious implementation has an exploitable failure direction.

### 7.5 `crates/izba-core/src/daemon/egress/mitm.rs`

`L7Request` grows `headers` (an immutable view). A `CredentialResolver` trait is threaded alongside `policy: Arc<dyn MitmPolicy>` through `serve_mitm` into `handle_request`, captured by the same per-request `service_fn` closure so h2 multiplexing cannot smuggle an uninjected request. The resolve step sits between `rewrite_outgoing_host` (`:673`) and `upstream_send` (`:680`) — after the host is pinned. `bridge_websocket` (`:719`) takes the same step before forwarding the upgrade, or WebSocket becomes an unstripped bypass.

### 7.6 `crates/izba-core/src/credential/` (new)

- `provider.rs` — the providers-v2 DTO and its strict `from_value` walk, mirroring `config.rs`'s pattern.
- `lint.rs` — the per-field honored/advisory/rejected report (D4).
- `binding.rs` — endpoint matching and the specificity scorer. Host term based at `100_000` with a `10_000`-per-`*` penalty, `+100` per label, `+1` per literal char; path term `0` for empty/`**`, else `1_000_000 + literal chars`, so any path selector outranks every host score. Ties are an **install-time error** (D7).
- `placeholder.rs` — generation, recognition (longest-match first), revision parsing, and shapes (D9).
- `store.rs` — keyring/sealed-file material, reusing `vnc.rs:168`'s `write_private_0600` and `jail_account/dpapi.rs` for Windows sealing.
- `inject.rs` — strip-then-insert, RFC 7230 `tchar` header-name validation with the framing denylist, the resolved-value guard, and the CWE-22 path guard. **Vendored from upstream with SPDX headers preserved**, with one deliberate strengthening: upstream's `validate_resolved_secret` is a three-byte blacklist while its own middleware boundary uses an `is_safe_value` whitelist (HTAB, `0x20..=0x7e`, `>= 0x80`); izba uses the whitelist everywhere.

### 7.7 `crates/izba-core/src/daemon/egress/audit.rs`

`AuditRecord` gains `Option` credential fields — grant id, decision (`inject` / `redeem` / `strip` / `deny` / `harvest`), matched pattern, and whether an advisory `binaries` term participated. All `skip_serializing_if` so existing JSONL stays readable.

**`Tier` is deliberately not extended.** A credential decision happens *within* an L7 flow, so it keeps `Tier::L7` and is described by the new fields; inventing a `Tier::Credential` would double-count one flow across two tiers and break `audit::aggregate`'s per-endpoint arithmetic. A pre-termination passthrough (§7.4) records `Tier::L3` with rule `passthrough`, which is what it actually is. **The injected value is never logged.**

### 7.8 `crates/izba-core/src/manifest/`

`SandboxSpec` gains `credentials: Option<CredentialsConfig>` after `egress` — **references only, never material**. `normalize.rs` sorts it canonically, `diff.rs` gains a `FieldDelta` arm, and two new weakening transitions are flagged: adding a grant, and `protocol: http → tcp` (§5.2).

### 7.9 `crates/izba-cli/src/commands/{provider,credential}.rs`

Modelled on `usb.rs` (daemon-level config plus per-sandbox consent) rather than `policy.rs`. `provider install|list|show|lint|remove`; `credential set|unset|status`. `set` never takes the secret as an argv value. Grant attachment uses the `--confirm` echo-back pattern from `usb.rs:24-36`.

### 7.10 `crates/izba-core/src/daemon/proto.rs`

One `DAEMON_PROTO_VERSION` bump to **7** covering the whole `Provider*`/`Credential*` set, with its `v7` clause appended to the changelog doc comment. `ReloadPolicy` is extended rather than duplicated: it already loads-and-compiles once to avoid a TOCTOU, and grants ride the same snapshot.

### 7.11 `crates/izba-core/src/daemon/{transport,server}.rs` — F-09

`SO_PEERCRED` on accept, before a handler thread is spawned; reject any peer whose uid is not the daemon owner's. Defence in depth alongside the existing 0700 directory, and a hard precondition for grant attachment (D14).

**Platform reality, corrected during planning:** izbad uses **AF_UNIX on both OSes** (`transport.rs:1-3` — std on Unix, `uds_windows` on Windows), not named pipes, and **Windows AF_UNIX exposes no uid-equivalent peer credential**. There is therefore no Windows enforcement path; the socket is gated there by the containing directory's ACL. Note `bind_socket` chmods 0700 only under `cfg(unix)`, and `create_dir_700` likewise hardens only under `cfg(unix)` (`paths.rs:156`) — so on Windows izba does no explicit ACL work at all and inherits `%LOCALAPPDATA%`'s default (owning user + SYSTEM + Administrators). F-09's premise that "the sole gate is the 0700 dir" does not hold there. izbad reports the achieved mode at startup rather than implying enforcement, mirroring how VMM confinement records its achieved level. Non-Linux unix is likewise reported unavailable: izba's supported hosts are Linux and Windows, so a `getpeereid` path would be untested code on an unsupported target.

**Why the Windows residual is acceptable — and the sharper reason, added 2026-08-17.** The peer-PID ioctl that does exist on Windows AF_UNIX (`SIO_AF_UNIX_GETPEERPID`) is PID-only and TOCTOU-prone via PID recycling. That is true, but it is *not* the load-bearing argument, and the spec should not lean on it: winning that race requires the recycled PID to land on a process running as the target identity inside a microsecond-wide window, which is hard, and by this spec's own D13 reasoning an AND-only advisory narrowing is strictly non-negative even when forgeable.

The real reason is that **peer authentication and the credential store sit behind one and the same boundary**, so the check is moot against the only attacker who could exploit its weakness:

| Attacker | Reach the control socket? | Read the credential store? |
| --- | --- | --- |
| Different non-admin user | No — `%LOCALAPPDATA%` ACL (Windows) / 0700 dir (Linux) | No — same gate |
| **Same user** | **Yes** | **Yes** — same gate; DPAPI user-scope and libsecret both unseal *silently* for that user |
| Administrator / SYSTEM / root | Yes | Yes |

A same-user attacker never needs to race a PID: reading the store is strictly less work for the same result. And this is **not Windows-specific** — on Linux the daemon dir is 0700 and the store 0600 in the same tree, so `SO_PEERCRED` does not protect credentials from a same-uid process either.

**What F-09 therefore actually buys** (narrower than "credentials are protected", and worth stating precisely so nobody over-trusts it): it closes the **cross-uid** case in the configurations where file permissions fail to — a data root on a filesystem that ignores `chmod` (WSL DrvFs/9p under `/mnt/c`, FAT, some network mounts), an inherited fd, or a confused local deputy tricked into connecting, which runs as its own uid. Plus an honest error for `sudo izba` instead of a confusing one. It is cheap, AND-only, and non-negative — but it is not the control that protects credential material.

**Consequence, and it is the important one:** on both platforms the load-bearing controls for the vault are the store's at-rest protection and the credential's *scope and lifetime* — D10's broker-not-store direction and the ladder's rung 1 (§13) — not peer authentication. See §10 and F-CRED-3.

---

## 8. Data flow — the agent calls `api.anthropic.com`

1. Operator: `izba provider install ./anthropic.yaml` → parsed strictly, linted, stored host-only under `<data>/credentials/providers/`.
2. Operator: `izba credential set anthropic api_token` → material sealed into the store. Never in `izba.yml`, never in a share.
3. Operator grants the sandbox the provider; `izba diff` shows it as a weakening and `izba promote` applies it behind the review token.
4. Sandbox start: init receives `ANTHROPIC_API_KEY=izba:resolve:env:v3_ANTHROPIC_API_KEY` through `merge_env`, shaped per D9. **No secret is present in the guest.**
5. Agent sends `POST /v1/messages` with `Authorization: Bearer izba:resolve:env:v3_…` to `api.anthropic.com:443`.
6. `router::tcp_connect`: SSRF floor, then `policy.inspects(443)` → true → ClientHello peek → SNI is not on the passthrough list → `mitm_hop`.
7. `handle_request`: duplicate-`Host`, authority/`Host`, and SNI/`Host` guards; `policy.check` allows; `rewrite_outgoing_host` pins the host.
8. Credential resolve: the placeholder is recognised and its revision validated; the binding `(api.anthropic.com, 443, /v1/**)` matches with a unique best score; `binaries` (advisory) is consistent; the leg is TLS so D11 is satisfied. The placeholder is **stripped** and the real key inserted per `auth_style`.
9. `upstream_send` re-originates over TLS verified against the vetted host. Audit records `inject` with the grant id and no value.
10. On the way back, the response is scanned; a reflected secret is redacted and alarmed.

A placeholder presented to a **non-matching** host is stripped, never forwarded, and denied `403 credential_endpoint_mismatch` — matching upstream's error code and body so tooling written against it behaves identically.

---

## 9. Error handling (fail-closed / fail honest, never silent)

| Condition | Behaviour |
| --- | --- |
| Provider file has an unknown key | Install refused, key and valid-key list named (#138 shape) |
| Provider uses `token_grant` / `credential_signing` | Install refused, naming the missing capability (D16) |
| Two bindings tie on specificity | Install refused, both named (D7) |
| Credential endpoint port is not inspectable | Install refused, naming the `policy.yaml` line to add (D1) |
| Credential endpoint is `tls: skip`/`passthrough` | Install refused — cannot inject into what is not parsed |
| Grant attached while F-09 is unfixed | Attachment refused (D14) |
| Placeholder presented to a non-matching endpoint | Strip, deny `403 credential_endpoint_mismatch`, audit as probable exfiltration |
| Placeholder with a stale/invalid revision | Fail closed, no resolution (D9) |
| Resolved value fails the character whitelist | Fail closed, reason logged, value never logged |
| Cleartext leg without `tls: none` | Injection refused (D11) |
| Any placeholder marker survives rewriting | Request refused rather than forwarded — upstream's post-scan, adopted |
| MITM runtime unavailable on an inspected port | Existing fail-closed deny at `router.rs:253` |
| Secret store unreadable | Grant resolves to nothing; request denied, never sent uncredentialed |

---

## 10. Security considerations

**A placeholder is not a secret.** It is a sandbox-bound reference redeemable only on the originating sandbox's vsock plane and only toward its bound endpoint. It follows that a guest may leak one over tier-2, where izbad has no visibility, and the leak is **inert**. This is the strongest argument for the sentinel model: it stays sound precisely on the channels izba cannot inspect.

**What this does not do.** It stops the agent *stealing* a credential. It does not stop the agent *using* one while the sandbox lives. Any service accepting authenticated writes remains an exfiltration channel once its credential is injected — demonstrated publicly against Copilot through an allowlisted `raw.githubusercontent.com`. The mitigations are scope (rung 1), L7 method and path rules, audit, and revocation — not the proxy.

**Binary attribution is advisory and must stay AND-only** (D13). Used as an additional conjunct it is strictly non-negative: forged, the result equals the no-attribution baseline. Used as an exemption it would be an escalation. The label must appear at install, in `provider show`, and in the audit record so no operator mistakes it for a boundary.

**The store is now a concentrated target.** Upstream ecosystems have been breached this way. `secretRef` indirection (D10) keeps izba a broker rather than a store wherever the user already has a secret manager.

**A same-user local process is out of scope for the socket layer, by construction.** izbad's control socket and the credential store sit behind the *same* gate on both platforms — the 0700 daemon directory on Linux, the inherited `%LOCALAPPDATA%` ACL on Windows. A process running as the izba owner can therefore read the store directly and has no reason to attack the socket at all; conversely a different-uid process is stopped by that gate before peer authentication is even consulted. F-09's check is a genuine defence-in-depth win for the cases where the file gate *fails* — a `chmod`-ignoring data root, an inherited fd, a confused local deputy — but no amount of socket authentication protects credential material from a same-user attacker. §7.11 has the full case table.

This matters because it relocates the load-bearing control. Sealing does not save you either: **DPAPI user-scope and libsecret both unseal silently for the same user**, so an encrypted-at-rest store is only as strong as the account. The two mechanisms that actually bound a same-user attacker are:

- **An external resolver that requires interactive confirmation** — `secretRef: exec:` into `op`/`vault` with a biometric or touch prompt. This is the strongest argument for D10's broker-not-store direction, stronger than the concentrated-target one above.
- **Rung 1 — downscope-and-mint.** Short-lived, narrowly-scoped credentials bound the *window and blast radius* of an attacker who is already inside the account, which no file permission or socket check can. This is why rung 1 is not merely the polish at the end of the ladder (§13).

Stated plainly so it is not rediscovered: **the vault's threat model is a hostile guest, not a hostile local user.** A compromised host account defeats it, and is a different problem.

**Unchanged and load-bearing:** the SSRF floor, the confused-deputy guards, per-request re-checking, and upstream certificate verification against the vetted host. Credential injection is safe *because* those hold.

---

## 11. Testing (TDD)

- **Unit, in-file.** Placeholder recognition including longest-match and revision parsing; the specificity scorer including the `1_000_000` tier ordering and the ambiguity rejection; header-name and value validation; the CWE-22 path guard; strict provider parsing with per-field error strings; `protocol` parsing and defaults. All pure — no sockets, honoring the no-bind constraint.
- **Guard tests.** `egress::output_chain` byte-equality style: a policy with no `protocol` fields must compile to a byte-identical Rego data doc, proving the default datapath is untouched.
- **Integration.** A new `crates/izba-core/tests/credential_mitm.rs` copying `egress_mitm.rs`'s skeleton verbatim — `install_ring`, the `can_bind()` runtime skip, `spawn_upstream` — asserting on **what the upstream actually received**: real credential present, placeholder absent, and the wrong-host case denied with the exact 403 body. Plus an `:8000` case proving inspection follows the declaration rather than the port, and a passthrough case proving no termination occurred.
- **e2e (KVM-gated).** A real sandbox whose env holds only a placeholder reaches a credentialed upstream, with `izba netlog` showing an `inject` record and no secret.
- **Gates.** All six workspace gates, plus the app gate — `AuditRecord`, `SandboxSpec` and the daemon proto are public types the Tauri app embeds by path, so `cargo {test,clippy} --workspace` will not catch a break there.

**Honest limits.** CI cannot prove a pinned client's behaviour, cannot exercise a real OAuth provider, and cannot test the OS keyring on a headless runner — those paths get fakes plus a documented manual checklist.

---

## 12. Risks

| Risk | Mitigation |
| --- | --- |
| Widening MITM to new ports breaks a client that was previously spliced | Opt-in per host:port; `protocol: tcp` is the documented hatch; `status` reports every inspected port |
| Upstream schema drifts and files stop installing | Strict parsing fails loudly rather than silently under-enforcing; the source commit is recorded; `lint` is the diagnostic |
| Operators read `binaries` as enforcement | Advisory label at three surfaces (D13) and an explicit paragraph in the docs |
| The store becomes the crown jewels | `secretRef` indirection; sealed at rest; never in a share or the manifest. **Honest limit:** sealing resists offline theft, not a compromised account — DPAPI/libsecret unseal silently for the same user (§10, F-CRED-3) |
| izbad scope creep (risk #6★) | This adds no second datapath — families C and D, which would, are explicitly deferred |
| Harvest breaks a client that parses tokens locally | Shaped placeholders (D9); harvest is secondary to host-side login (D15) |

---

## 13. Out-of-scope follow-ups (named, not built)

- **The broker plane** for families C and D: a guest-facing endpoint served by izba-init (container-credentials URI, `SSH_AUTH_SOCK`) carrying requests to izbad over vsock. **Must not be built by weakening `is_hard_denied`** — init terminates the address locally so izbad serves rather than dials.
- **Rung-1 minters**: GitHub App installation tokens, STS session policies, RFC 8693 token exchange. **Re-weighted 2026-08-17:** this is not end-of-ladder polish. Per §10 it is one of only two mechanisms that bound a *same-user* attacker — short-lived, narrowly-scoped credentials limit the window and blast radius of someone who already has the account, which no file permission, socket check, or at-rest sealing can. Treat it as the next security-material phase after V0/V1, ahead of the broker plane on security grounds even though the broker plane unlocks more use cases.
- **An interactive-confirmation `secretRef` resolver** — `exec:` into `op`/`vault`/a hardware token that prompts. The other of the two same-user mitigations (§10), and cheap relative to a minter: it is a resolver variant, not a new subsystem.
- **Per-container attribution.** In docker mode the workload's netns was created by init, so "which container" is known from topology init controls rather than workload-influenced data — structurally stronger than binary identity and unavailable to container-based designs.
- OCSF audit schema; metering and budgets; SigV4 re-signing; SPIFFE identity.

**Surfaced by P1 (2026-08-18), named not built.** All six are diagnosability
or authoring gaps, not enforcement gaps — the datapath fails closed in every
case below.

- **`izba policy allow --protocol http|tcp`.** P1 added no policy-mutation CLI
  surface, because threading the axis through the normalized-mutation contract
  (#170/#172: `collapse_duplicate_hosts`, `set_host_access`, the
  compile-faithful diff fold) is separate work from the axis itself. Authoring
  works today by editing `policy.yaml` or through `izba.yml` + `izba diff` /
  `izba promote`, which is also where the weakening gate lives.
- **An egress block in `izba status`.** §5.2 assumed `status` reported the
  hatch; it renders no egress posture at all, so P1 landed the reporting in
  `izba policy show`. Inspected ports, passthrough hosts and enforce posture in
  `status` would be a small standalone improvement.
- **A superseded `protocol: tcp` disappears silently.** The passthrough set
  folds last-wins per exact host to match `to_rego_data_json`, so a later
  duplicate entry for the same host drops an earlier explicit declaration with
  no warning. Safe direction — the flow is inspected rather than spliced — but
  the operator's declaration vanishes and a genuinely pinning client then
  breaks with nothing pointing at the duplicate. A `policy lint` warning would
  close it without touching the fold. Note the deliberate asymmetry:
  `inspect_ports` unions, which is also the safe direction for that set.
- **A declined passthrough explains nothing.** When a flow the operator
  declared `protocol: tcp` fails to take the hatch — a record-fragmented
  ClientHello exhausting the peek budget, an SNI absent from the DNS-snoop
  candidate set, a `decide_tier2` refusal — izbad silently terminates it
  instead. Correct and safe, but a pinning client fails with nothing in
  `izba netlog` saying why. An audit record for the declined case (reason,
  observed SNI, candidate count) would close it.
- **Reassembling a ClientHello fragmented across TLS records.** `peek_sni`
  reads the first record only; a hello split across records reports
  `Incomplete` and so fails closed to termination, which breaks passthrough for
  a client that fragments. Rare in practice, honest in behaviour, worth fixing
  if a real client hits it.
- **`protocol` is stored per-entry, but the hatch is per-port.** An entry
  carries one `Option<Protocol>` covering all its ports, so
  `izba policy allow pinned.vendor.com:8080` on a host declaring
  `protocol: tcp` extends the hatch to a port the operator never named. P1
  preserves the declaration across that mutation rather than dropping it —
  dropping silently performs an unflagged `http → tcp` weakening, which is
  worse — and pins the behaviour in a test. A per-port representation, or
  refusing the mutation on a hatch-carrying host, would close it properly.

---

## 14. New findings (for the register)

- **F-CRED-1 (MED)** — a placeholder may traverse tier-2 unobserved. Accepted: a placeholder is not a secret (§10). Recorded so the reasoning is auditable rather than rediscovered.
- **F-CRED-2 (MED)** — `binaries` attribution is guest-self-reported and TOCTOU-racy (a process may exec between connect and lookup). Advisory, AND-only (D13).
- **F-CRED-3 (MED — raised from LOW, 2026-08-17)** — the credential store is long-lived material at rest, inheriting F-16's critique of the CA key. **This is the vault's primary residual, not a footnote.** Raised after working the boundary analysis in §10: because the store and the control socket sit behind the same gate on both platforms, a same-user process reads the store directly, and neither F-09's peer check nor sealing stops it — DPAPI user-scope and libsecret unseal silently for that user. Sealing therefore protects against offline theft of the file (backups, a stolen disk, a different user), not against a compromised account. The mitigations that bite are an interactive-confirmation `secretRef` resolver and rung-1 short-lived credentials; both are named but neither is built in V0/V1. Rotation remains undesigned.
- **F-CRED-4 (INFO)** — izba enforces more than an imported provider declares in two places (D8, D12). Reported by `lint`; the direction is always stricter, never laxer.
- **F-CRED-5 (MED, prerequisite) — CLOSED ([#230](https://github.com/Lupus/izba/issues/230)).** The egress accept loop now runs `peercred::authorize_stream` on every connection, before any per-connection work and before a handler thread exists; a foreign-uid peer is logged (`egress_peer_denial_log`, which names the sandbox) and dropped, so it sees EOF and relays no bytes. Linux: enforced via `SO_PEERCRED`. Windows: unchanged residual, identical to F-09 — no peer-credential API, so the verdict is `Allow(Unavailable)` and the directory ACL remains the only gate; the daemon's startup line now says so for *both* planes rather than naming only the control socket. **The P2 prerequisite is satisfied.** Original finding, for the record: `crates/izba-core/src/daemon/egress/mod.rs:248` accepted connections on the per-sandbox vsock-1027 unix listener (`<run dir>/vsock.sock_1027`) with **no peer check**, gated only by the same 0700 run directory that F-09 already established is insufficient as the *sole* gate for a peer-authoritative socket. This is precisely the plane P2 will use to inject real credential material into an outbound request, and its only legitimate peer is the same-uid VMM process bridging the guest's vsock dial — exactly the shape `peercred::authorize_stream` (F-09, `crates/izba-core/src/daemon/peercred.rs`) already solves for the control socket. Before any grant can attach real secrets to a flow, the same accept-time check had to be wired onto this listener. Named here so it was caught in review rather than rediscovered once the vault exists.

---

## 15. Open implementation questions (resolve during planning, not blocking)

1. Keyring backend on Linux — `libsecret` couples to a desktop session that a headless workstation lacks; the sealed-file fallback may simply be the default there.
2. Whether `izba login` should proxy the browser open out to the host (Clawker's `BROWSER` trick) or stay a pure host-side command.
3. Whether the response-side secret scan (§8 step 10) is per-grant opt-in or always on — it costs response buffering.
4. ~~Whether `protocol` belongs on the manifest's `spec.egress`~~ — **resolved
   during P1: it was never a choice.** `izba.yml`'s `spec.egress` deserializes
   through `EgressPolicyConfig`'s own strict walk, so `protocol` rides the
   manifest automatically; the `spec.usb` comparison does not apply, because
   that mirrors a separate consent record while `spec.egress` reuses the policy
   type verbatim. What P1 owed was therefore a test that it survives the
   manifest path, plus the weakening flags — both delivered.
