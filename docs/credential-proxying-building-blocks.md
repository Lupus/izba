# Credential proxying — building blocks, prior art, and the izba M5 design space

> Research doc, 2026-08-17. Companion to
> [egress-firewall-building-blocks.md](egress-firewall-building-blocks.md), which
> surveyed the M2 allow-list + MITM blocks. This one surveys the **M5 credential
> vault**: how to make real credentials never enter a sandbox, across every way a
> tool acquires one — BYO API keys, in-sandbox OAuth logins, cloud SDK credential
> chains, and SSH.
>
> Status: **research + design space**, not an approved spec. It builds on decisions
> already locked in [vision.md](vision.md), [roadmap.md](roadmap.md) §M5, and
> [security/policy-state-guest-isolation.md](security/policy-state-guest-isolation.md).

---

## 0. TL;DR

**The goal in one sentence.** A credential the agent can *use* but cannot *keep*:
a compromised or prompt-injected agent must not be able to walk out of the sandbox
with anything that still works outside it.

**Finding 1 — this is no longer research; it is a productized pattern.** Host-side
secret store + sentinel in the sandbox + destination-keyed substitution at an
egress MITM now ships in Docker `sbx`, NVIDIA OpenShell, Infisical Agent Vault,
iron-proxy (Hermes), nono, Clawker, and Agenta. izba should **copy a mature schema
and copy the field's known failure list**, not reinvent either. The best public
spec is NVIDIA's
[OpenShell providers-v2](https://docs.nvidia.com/openshell/sandboxes/providers-v2);
the best public prose explanation is
[Docker's sandbox credentials page](https://docs.docker.com/ai/sandboxes/security/credentials/).

**Finding 2 — "credential proxying" is four mechanisms, not one.** There are four
structurally different ways a secret is carried, and a technique that works for one
is useless for the others:

| Family | How the secret is used | Swappable at an L7 proxy? | Mechanism |
| --- | --- | --- | --- |
| **A. Bearer-shaped** | Sent verbatim (`Authorization: Bearer`/`Basic`, `x-api-key`, query param) | **Yes** — substitution | Strip + inject / sentinel redeem at the MITM |
| **B. Minted in-flight** | Does not exist until an OAuth dance creates it | **Yes** — on the *response* | Host-side login, or in-band harvest + sentinel |
| **C. Proof-of-possession** | Used to *compute* a signature (AWS SigV4, GCP SA JWT, HMAC, mTLS) | **No** — nothing to swap | Re-sign at the proxy, or broker short-lived derived creds |
| **D. Non-HTTP** | SSH pubkey auth, Postgres/MySQL/Redis wire protocols | **No** — not HTTP | Sign-on-host agent brokering; protocol connectors |

izba's shipped M2 MITM gives family A almost for free and family B for cheap.
**Families C and D need a second datapath — a guest-facing broker endpoint — that
does not exist today.** A design that only does header injection will silently fail
on `aws`, `gcloud`, `terraform`, and `git push` over SSH. Hermes states it flatly:
*"Signature-based auth (AWS SigV4, GCP service-account OAuth) bypasses the proxy
entirely."*

**Finding 3 — there is a quality ladder, and header injection is only rung 2 of 4.**

1. **Downscope-and-mint** — izbad exchanges one powerful host credential for a
   narrow, short-lived one (GitHub App installation token scoped to one repo and
   expiring in 1h; STS `AssumeRole` with a session policy; LiteLLM-style virtual
   keys with budget + model limits; RFC 8693 token exchange). The guest may hold
   the derived token — it is already narrow and expiring.
2. **Inject** — guest holds nothing; izbad adds the header on the way out.
3. **Harvest + sentinel** — guest holds an unforgeable, sandbox-bound *reference*
   only izbad can redeem.
4. **Passthrough** — the real credential sits in the guest. Status quo; defensible
   only for cert-pinned or non-HTTP destinations, and it must be loud.

Most of the field, and izba's own current sketch, stops at rung 2/3. **Rung 1 is
where the security actually is**, because it is the only rung that bounds *abuse*
rather than merely *exfiltration*.

**Finding 4 — the honest limitation, stated up front.** Every mechanism here stops
the agent from *stealing* a credential. **None stop it from *using* one** while the
sandbox lives. The proxy converts "steal the key and use it forever, anywhere" into
"abuse the key from inside a logged, rate-limited, revocable, L7-scoped channel for
as long as the sandbox runs." That is a large, real win — and it is not
containment. Trail of Bits demonstrated the residual concretely: Copilot exfiltrated
data through an *allowlisted* `raw.githubusercontent.com`. **Any service that
accepts authenticated writes becomes an exfil channel the moment you inject its
credential.** Anyone claiming a credential proxy makes a hostile agent harmless is
selling something.

---

## 1. The landscape

### 1.1 Docker `sbx` — the closest published reference design

Docker's own wording: *"An HTTP/HTTPS proxy on your host intercepts outbound
requests from the sandbox, looks up the matching credential on the host, and
overwrites the auth header before forwarding."*

- **Host store**: `sbx secret set <service>` writes to the OS keychain (macOS
  Keychain / Windows Credential Manager / Linux Secret Service). Headless Linux
  falls back to an encrypted file under `~/.config/com.docker.sandboxes` — which
  Docker's own docs call *"weaker than an OS keychain, which also mediates access
  per application."*
- **Sentinel in the sandbox**: the literal string `proxy-managed` for built-in
  services, `sbx-cs-<rand>` for custom ones. Note the per-sandbox randomness only
  on the custom path — the fixed string is weaker.
- **Per-host binding**: a fixed domain map per service (anthropic →
  `api.anthropic.com`, `console.anthropic.com`, `claude.ai`; github →
  `api.github.com`, `github.com`; …), with wildcards where `*` matches one label
  and `**` matches multiple — **the same semantics izba already implements** in
  `egress.rego:41-52`.
- **Operator consent as the anti-confused-deputy control**: third-party kits
  declare *where* they want a credential injected, but the operator must approve the
  binding in `~/.config/sbx/credentials.yaml` before anything is released. The kit
  never carries the secret, and never gets to widen its own domain list.
- **OAuth**: built-in providers (Claude Code, Codex) run the dance **host-side**,
  refresh host-side, and inject at egress; the refresh token and client secret never
  leave the host. **But**: *"Proxy-managed OAuth isn't supported for third-party
  sandbox agents."* Third-party kits doing OAuth inside the sandbox land the token
  inside the sandbox.
- **SSH**: host agent forwarded via `SSH_AUTH_SOCK`. Keys stay on the host; the
  sandbox gets a signing oracle.

**The instructive bug** ([docker/for-mac#7842](https://github.com/docker/for-mac/issues/7842)):
sbx sets `apiKeyHelper: "echo proxy-managed"` in Claude Code's settings, so Claude
sends `Authorization: Bearer proxy-managed` on the **API-key** code path — but a
Pro/Max subscription needs the **OAuth** code path with different headers. Result:
"Invalid Bearer token." **Lesson: sentinel injection silently assumes the client's
auth code path is the one you rewrite. Subscription-OAuth and API-key are different
code paths inside the same binary.**

### 1.2 NVIDIA OpenShell — the most sophisticated public design

Three tiers (gateway stores provider credentials → per-sandbox supervisor →
policy proxy), egress forced through the proxy by **network-namespace routing**
rather than `HTTPS_PROXY` env vars, so the agent cannot opt out. TLS terminated
with an ephemeral CA for L7 inspection; events emitted as OCSF.

**`auth_style` enum**: `bearer` | `basic` | `header` (+`header_name`) | `query`
(+`query_param`) | `path` (+`path_template` with `{credential}`), plus AWS SigV4
signing, optional WebSocket text-frame rewriting, optional body rewriting.

**The five-condition resolution gate — the core anti-confused-deputy design.** A
real value is substituted only if *all* hold:

1. the placeholder belongs to the currently attached provider state;
2. the calling binary **and** destination are policy-allowed;
3. host, port, **and path** match the credential binding;
4. the HTTP method/protocol is allowed by L7 rules;
5. the credential has not expired.

Otherwise: **HTTP 403, error code `credential_endpoint_mismatch`.** Note it binds on
*path*, not merely domain — materially tighter than Docker.

**Refresh strategies**, all host-side: `oauth2_refresh_token`,
`oauth2_client_credentials`, `google_service_account_jwt`, `aws_sts_assume_role`.
And the principle worth stealing verbatim: *"Provider refresh stores
non-injectable refresh material separately from the provider's current credential
values"* — **refresh tokens are structurally incapable of being injected into a
sandbox request.**

**SPIFFE integration** is the best answer to "what does the sandbox actually hold":
the sandbox's JWT-SVID is used as an RFC 7523 client assertion to obtain a
short-lived access token. The sandbox's credential is a *workload identity*, not a
sentinel string — so theft off-box is worthless by construction.

**AWS SigV4**: sandbox gets `AWS_ACCESS_KEY_ID=placeholder`; the proxy strips the
placeholder signature and re-signs with real credentials. Modes `sigv4` (auto-detect
via `x-amz-content-sha256`), `sigv4:body` (buffers, 10 MiB cap), `sigv4:no_body`.

**Explicit non-coverage**, in their words: *"Raw TLS tunnels and non-HTTP protocols
bypass credential substitution entirely."*

### 1.3 The rest of the field, and what each contributes

| Project | Contribution worth taking |
| --- | --- |
| **CyberArk Secretless Broker** (2018–) | The oldest and best abstraction for **family D**: the broker *performs the authentication phase of the backend protocol itself*, then becomes a byte pump. Connectors for PostgreSQL, MySQL, SSH, SSH-agent, HTTP Basic/Conjur/SigV4. Not a MITM — the client points at a local listener — so no TLS-interception tax, at the cost of client reconfiguration. |
| **iron-proxy / Hermes** (Apache-2.0, Go) | Best hardening checklist: CA key `0600` opened with **`O_NOFOLLOW`**, proxy bound to the guest interface **never `0.0.0.0`**, SSRF CIDR denial applied **post-DNS-resolution** (kills rebinding), token rotation invalidating all sentinels. |
| **Infisical Agent Vault** | `unmatched_host_policy=deny` — fail-closed as the default posture, not an option. |
| **nono** (Luke Hinds) | Kernel-level enforcement (Landlock v4 / Seatbelt) that the child process may *only* reach the proxy port. env-var `HTTPS_PROXY` alone is trivially bypassed. |
| **grepular's `claude-sandbox`** | Richest small-project feature set: injection with **method filtering**, **GraphQL operation filtering** (allow queries, block mutations), WebSocket frame replacement, dynamic token refresh via host commands, and — importantly — **stripping auth tokens out of *responses*** so upstream cannot echo the real secret back into the sandbox. |
| **LiteLLM / Portkey / OpenRouter** | The **virtual-key** instance of the pattern: sandbox holds `sk-litellm-…`, gateway maps it by sha256 to the real provider key, with per-key budgets, rate limits, model restrictions, expiry, and spend logs. This is rung 1 for LLM traffic and it is mature. |
| **Arcade.dev / Nango / Composio** | Commercial OAuth token brokers — "credentials never enter the model context." Also a cautionary tale: **Composio disclosed a May 2026 incident** where attackers compromised employees' OAuth tokens and reached internal systems. The vault is a concentrated target. |
| **Clawker** | Two neat tricks: forwards the container's `BROWSER` handler out through the host proxy so an in-sandbox `/login` can open the *host's* browser, and **filters `credential.helper` lines out of the copied `.gitconfig`** so the guest can't fall back to a host-style helper. |

---

## 2. The four families, in detail

### 2.A Bearer-shaped — solved by substitution

`Authorization: Bearer sk-…`, `Authorization: Basic base64(user:token)`,
`x-api-key:`, `?api_key=`. Covers Anthropic, OpenAI, most SaaS, the GitHub
REST/GraphQL API, and **git-over-HTTPS** — which uses `Basic` with the token in the
*password half*, so an engine that only understands `Bearer` will silently fail
`git push`.

Two sub-modes; a complete design needs both:

- **Unconditional injection.** The grant says "add this header on matching
  requests." The guest sends nothing. Strongest — no token-shaped object exists
  anywhere in the sandbox.
- **Sentinel redemption.** The guest holds a random, sandbox-bound placeholder;
  izbad swaps it. Required when the tool refuses to make the request at all without
  a configured key (very common — SDKs that throw `MissingAPIKey` before any
  network call), or when two identities exist for one host and the sentinel selects
  between them.

**Always strip before deciding.** Any inbound credential header on a matching flow
is removed first, so a credential the guest obtained by some other route cannot
ride along. OpenShell does exactly this on its inference path, explicitly to prevent
an agent smuggling its own key to a provider.

**Constrain *where* substitution may happen.** Docker matches the placeholder
*anywhere in the request*, which is convenient and is a **credential-smuggling
primitive**: an agent can get the real secret injected into an arbitrary field of an
otherwise-legal request — e.g. into a gist body POSTed to `api.github.com`.

*Corrected 2026-08-17 after reading the schema:* OpenShell is **not** as strict as
this doc first claimed. For static credentials its `auth_style` metadata is
"stored and validated" but is **not** the injection mechanism — the proxy resolves a
placeholder wherever it appears among a supported location set (header value,
`Bearer ` prefix, Basic `base64(user:ph)`, query parameter, path segment). What it
*does* do is put the genuinely dangerous locations behind per-endpoint opt-ins
(`request_body_credential_rewrite` and `websocket_credential_rewrite`, both default
`false`) and refuse cookies, response bodies and WebSocket binary frames outright.
So the real control in both systems is the **binding** (host + port + path), not the
location. izba's opportunity is to be stricter for free: honor `auth_style` as the
authoritative location when it is declared, keep the same opt-ins for body and
WebSocket, and record the resolved location in the audit record.

### 2.B OAuth logins — three interception points

This is the user-facing question: *`claude /login` and `gh auth login` mint new
credentials inside the sandbox — can that be captured generically?* Yes, three ways,
and they compose.

**Where the tokens actually land** (verified):

| Tool | Sandbox-side artifact |
| --- | --- |
| Claude Code | macOS Keychain item `Claude Code-credentials`; elsewhere `~/.claude/.credentials.json` = `{accessToken, refreshToken, expiresAt}`. `CLAUDE_CODE_OAUTH_TOKEN` takes precedence. Also an `apiKeyHelper` shell-out hook. |
| `gh` | System keyring by default since Feb 2023; `--insecure-storage` → plaintext `oauth_token` in `~/.config/gh/hosts.yml`. **In a microVM the keyring is normally absent and `gh` silently falls back to plaintext** ([cli/cli#10108](https://github.com/cli/cli/issues/10108)). Also registers itself as a git credential helper. |
| Codex | `~/.codex/auth.json` with `tokens.{access_token, refresh_token, id_token, account_id}`. |

**Point 1 — relocate the login to the host (best, and what the field converged on).**
`izba login <provider>` runs the dance host-side with the real browser, vaults the
tokens, and writes a *structurally valid* credential file into the guest whose token
fields are placeholders. This is Docker's `--oauth` providers and OpenShell's
[#988](https://github.com/NVIDIA/OpenShell/issues/988) /
[#1925](https://github.com/NVIDIA/OpenShell/issues/1925). It is also the only option
that works for cert-pinned providers. Clawker's `BROWSER`-forwarding trick lets an
in-sandbox `/login` still feel native by opening the host's browser.

**Point 2 — in-band harvest at the MITM (generic, and unusually cheap for izba).**
Because RFC 6749 §5.1 fixes the shape of a token response (`access_token`,
`refresh_token`, `token_type`, `expires_in`), a single rule — *"on a response from a
declared token endpoint, extract the token fields, vault them, substitute
sentinels"* — covers every compliant provider with **no per-provider code**. The
flow: guest completes a device or paste flow → izbad sees the decrypted token
response → vaults the real tokens → returns shape-matching sentinels → guest writes
sentinels to its config → later requests are redeemed.

**Refresh closes the loop elegantly**: when the access token expires, the tool POSTs
its `refresh_token` — also a sentinel — back to the token endpoint; izbad swaps in
the real one, receives a fresh real pair, vaults it, and returns sentinels again.
Nothing real is ever resident in the guest.

This forces a requirement pure header injection misses: **the refresh leg carries
the token in a form-encoded or JSON *body*.** So the substitution engine must cover
headers, query params, **and bodies** for declared endpoints — with a hard size cap
and fail-closed behaviour on overflow, since it means buffering.

Two hazards temper this, and they are why the field prefers point 1:

- **Clients parse tokens locally.** OpenShell's Codex work is the canonical example:
  `tokens.id_token` *cannot* be an opaque placeholder because Codex decodes it as a
  JWT before any networking, so they had to mint a non-secret JWT-shaped dummy.
  Sentinels must be **structurally valid**, not merely opaque — JWT-shaped where a
  JWT is expected, `sk-`/`gho_`-prefixed and correct-length where SDKs validate,
  with a plausible `exp` where clients check expiry locally.
- **Refresh material becomes redeemable.** A harvested refresh sentinel is something
  izbad *will* exchange on the guest's behalf, which is weaker than OpenShell's rule
  that refresh material is structurally non-injectable. The guest cannot obtain
  material, but it can force refreshes — a nuisance where providers rotate refresh
  tokens one-time-use.

**Point 3 — credential-helper hooks.** Claude Code's `apiKeyHelper` and git's
credential helper are documented shell-outs; point them at a host-brokered command.
Cheap and robust — but see the Docker `apiKeyHelper` bug in §1.1 for how this can
force the wrong auth code path.

**The loopback-redirect problem.** For authorization-code + PKCE the CLI opens a
listener on `127.0.0.1:PORT` *inside* the guest while the browser is on the *host*,
where that port means something else. Ranked answers: relocate host-side (point 1);
prefer device flow (RFC 8628) or the manual-paste variant, which need no callback
and harvest for free; or publish the callback port where the tool lets you pin it.
Auto-detecting the guest listener is possible — init is PID 1 and can read
`/proc/net/tcp`, the OpenShell `procfs.rs` salvage finding a second use — but it is
stateful and racy.

### 2.C Signature-based — substitution is impossible

AWS SigV4 never puts the secret key on the wire; it HMACs a canonical form of the
request. There is nothing to swap. **Any design assuming header injection covers
"credentials" simply does not work for `aws`, and by extension `boto3`, the CDK,
`terraform`, and S3-backed tooling.** GCP service-account JWT signing and Azure SAS
are the same class.

- **Re-sign at the proxy** — the well-trodden path. Give the guest a syntactically
  valid but meaningless key pair (iron uses AWS's own documented example key). The
  proxy parses the credential scope from `Authorization`/`X-Amz-Credential`, **gates
  region and service against allowlists (403 on mismatch)**, resolves the real
  credentials, hashes the body (or `UNSIGNED-PAYLOAD`), strips the placeholder
  signature and re-signs, injecting `Authorization`, `X-Amz-Date`,
  `X-Amz-Content-Sha256`. Envoy ships this natively as the
  [AWS request signing filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/aws_request_signing_filter);
  `awslabs/aws-sigv4-proxy`, iron, and OpenShell all implement it. Correct, gives
  true zero-real-material, but it is real work and ongoing churn.
- **Broker short-lived derived credentials** — simpler and usually better. izbad
  holds the long-lived credential, calls `AssumeRole` with a narrowing session
  policy, and vends 15-minute credentials through the endpoint SDKs already poll:
  `AWS_CONTAINER_CREDENTIALS_FULL_URI` + `AWS_CONTAINER_AUTHORIZATION_TOKEN`, the
  mechanism ECS and EKS use. GCP (`metadata.google.internal`) and Azure IMDS have
  the same shape, so **one broker service with three provider adapters** covers all
  of them.

The guest does hold real material in the second option — but narrow and expiring in
minutes, which is rung 1 and a strictly better outcome than proxying a long-lived
key. An exfiltrated 15-minute single-role credential is a bounded incident.

**This must not be built by weakening `is_hard_denied`.** `169.254.0.0/16` is
load-bearing anti-SSRF (`router.rs:481`). The broker endpoint should be **terminated
inside the guest by izba-init**, which binds the address locally and carries the
request to izbad over the existing vsock plane as its own frame type — so izbad
*serves* a request rather than *dialing* a forbidden destination. The floor stays a
floor.

### 2.D Non-HTTP — SSH and database protocols

`git push` over SSH, `ssh` to a server, `scp`. No HTTP, nothing to rewrite.

**SSH agent brokering**: izba-init exposes an `SSH_AUTH_SOCK`; the agent protocol is
carried over vsock to izbad, which holds the keys and performs signatures. The key
never enters the guest. This is what Docker and Clawker both do, and it is the
natural continuation of izba's
[deferred agent-forwarding item](superpowers/specs/2026-06-22-ssh-access-design.md).

Honest limitation: the agent protocol does not carry the destination, so izbad
cannot scope a signature to "github.com only" — the guest gets a signing oracle for
anything, while forwarded. Mitigations are per-sandbox key sets and optional
host-side confirmation (`ssh-add -c` semantics). Prefer HTTPS + credential helper
where possible, precisely because it *is* mediatable.

**Databases**: Secretless-style protocol connectors, not MITM. A first version can
reasonably declare this out of scope.

---

## 3. Where izba stands

izba's architecture has already paid most of the entry price, and in two places is
**structurally ahead of the field**.

**Already free:**

| SOTA recommendation | izba status |
| --- | --- |
| "Enforce at the kernel/netns, not `HTTPS_PROXY` — env vars are trivially bypassed" (nono needs Landlock; OpenShell needs netns routing) | **Free by construction.** The guest is a NIC-less vsock island with `dummy0` as a structural deny. There is no proxy env var to unset and no route to bypass. |
| "Match on the authenticated destination, never a client-supplied `Host:`" | **Shipped.** `handle_request` rejects duplicate `Host` (`mitm.rs:598`), authority≠Host (`:618`), SNI≠Host (`:640`), then `rewrite_outgoing_host` (`:692`) pins the upstream wire Host to the vetted value. **policy host == cert host == wire host** is exactly the invariant credential injection needs. |
| "Hard-deny SSRF CIDRs including 169.254.169.254, post-resolution" | **Shipped**, unconditionally, ahead of all policy (`router.rs:481`). |
| "Policy must run per-request, not per-connection" | **Shipped** (F-03) — the hyper `service_fn` re-checks every request on keep-alive and h2. |
| "Treat the MITM CA key as a root key; host-only, 0600" | **Shipped** (`ca.rs`, threat-model invariant #5). `O_NOFOLLOW` and rotation are cheap adds; F-16 already notes the gaps. |
| "You need a CA in the guest trust store, with all the bundle env vars" | **Shipped** — `trust_env_pairs()` sets six, one more than Hermes' four. |
| Wildcard host semantics (`*` one label, `**` many) | **Shipped** and identical to Docker's (`egress.rego:41-52`). |

**The marginal cost of credential proxying for izba is therefore low**: the CA-trust
tax, the MITM datapath, the policy engine, and the audit sink are all already paid
for by M2.

**What is missing:**

- **No credential code at all** in the datapath — only seam markers (`router.rs:4`,
  `mitm.rs:278`, and `L7Request`'s own doc at `mitm.rs:281`: *"headers/body would
  join it for credential injection"*). `rewrite_outgoing_host` is the only header
  mutation that exists.
- **One allowlist, not two** (see §5.1 — this is the most important gap).
- **No response-side handling** — no stripping of credentials echoed back.
- **No broker plane** for families C and D.
- **`L7Request` carries no headers**, so no credential decision can be expressed yet.

**Two existing patterns to reuse rather than reinvent**: host-holds-secret /
guest-gets-artifact is already shipped twice (the VNC password in
`crates/izba-core/src/vnc.rs`, and the SSH material), and **at-rest sealing already
exists on Windows** in `jail_account/dpapi.rs`. Delivery into the guest is also
solved: `merge_env` (`image/runtime_config.rs:212`) layers image → trust → user env,
and `izba-init` is already a multi-personality binary (`main.rs:48` dispatches PID
1, `__pause`, and the SSH login shell off argv) — so a `git credential-izba`
personality needs no new initramfs artifact.

---

## 4. Design sketch for izba

### 4.1 Two allowlists, not one — the single most important structural decision

**Hosts the sandbox may *reach*** and **hosts a given credential may be *injected
for*** are different sets, and conflating them is precisely how the exfiltration
channel gets built. izba today has one (`egress.rego`'s `allow`). M5 must add a
second, narrower one, and the credential set must never be widened implicitly by the
reachability set.

Follow OpenShell rather than Docker on tightness: bind on **{host, port, path,
method}**, restrict substitution to **declared locations only**, and fail closed
with a distinct, debuggable reason code (`credential_endpoint_mismatch`) rather than
a generic 403.

### 4.2 The grant, and why izba should be a broker rather than a store

A **grant** binds a *role* — per the locked decision, effectively per-sandbox /
per-trust-domain, since in-guest role separation is unsound under A1
(threat-model §8) — to a destination pattern, a secret reference, and an
`auth_style`.

The load-bearing recommendation: **izba should be a credential broker, not a
credential store.** The grant carries a `secretRef` resolved at use time — `env:` /
`file:` / `exec:` (shell out to `gh auth token`, `pass`, `op`, `vault`) /
`keyring:` / DPAPI-sealed on Windows — with a built-in encrypted store as opt-in,
not default. This:

- keeps the manifest free of material, satisfying the locked "no secrets are ever
  rendered into `izba.yml`" rule and Option C's requirement that material never
  enter any virtiofs export;
- makes rotation someone else's already-solved problem;
- avoids izba inheriting the F-16 critique (long-lived plaintext PKCS#8, never
  rotates) across a far more valuable asset;
- shrinks the blast radius of izba itself becoming the concentrated target that
  burned Composio.

**Refresh material must be a separate, structurally non-injectable type** — no
placeholder may ever resolve to it (OpenShell's rule). Resolved secrets live in
memory with a TTL and are zeroized on drop.

`exec:` resolvers are a sandbox-escape vector if anything from the guest or the
intercepted request can influence the command or its arguments. **The command and
args must be fixed in host-side config, full stop** — this is the same requirement
Docker states for its own host-command feature.

### 4.3 Where each piece hooks in

**Families A + B (the MITM branch).** The single injection point is
`handle_request`, between the policy `Allow` at `mitm.rs:664` and `upstream_send` at
`mitm.rs:680` — the only place in the codebase with a decrypted, policy-vetted
request, a mutable `HeaderMap`, and a *pinned* host. `L7Request` (`mitm.rs:285`)
grows headers, per its own doc comment. Response-side harvest and response-side
credential stripping hook the returned response in the same function.
`bridge_websocket` (`mitm.rs:719`) is the second path upstream and must be handled
in the same commit or it becomes an un-stripped bypass.

**Families C + D (the broker plane).** A new guest-facing service: izba-init binds
the local endpoint (container-credentials URI, `SSH_AUTH_SOCK`), carries requests
over vsock, izbad performs the privileged operation. This is a second datapath and
the main reason M5 is bigger than "add a header."

**Policy.** A third rule in the shipped `egress.rego` returning a *grant id* rather
than a boolean, evaluated on the same input as `allow` and `resolvable` — which
already demonstrate the multi-rule pattern. One engine, one input marshalling, one
file; the "don't fork a second rego" constraint holds. The existing
`access: read | read-write` verb (`egress.rego:17`) and canonical `git_repo_id`
(`:74`) are the natural places for credential scope to attach.

**Audit.** `AuditRecord` (`audit.rs:36`) grows credential-decision fields: grant id,
decision (`inject`/`redeem`/`strip`/`deny`/`harvest`), matched pattern, specificity,
and a distinct reason code per deny. The injected value is never logged. Every
downstream consumer (`format_record`, `aggregate`, the netlog CLI, the Tauri Netlog
tab) is affected — a change-all-ends edit. **Metering and revocation fall out of the
same records**, because every flow already transits one daemon; this is how M5's
"independently revocable and meterable" exit criterion gets satisfied, and it gives
izba LiteLLM-style virtual-key semantics (budget, model allowlist, spend accounting)
as an L7 rule rather than a separate product.

### 4.4 Sentinel security model

A sentinel is **not a secret** — it is a sandbox-bound capability reference. This
resolves an apparent contradiction in the existing docs, where
[vision.md](vision.md) says the agent "holds a placeholder" while
[roadmap.md](roadmap.md) §M5 says "the guest never even holds a placeholder." Both
are right once *secret* and *reference* are distinguished: unconditional injection
puts nothing in the guest; sentinel redemption puts a non-secret reference there;
both keep the credential host-only. **The docs should be reconciled explicitly**,
because the stronger phrasing, read literally, forbids the mechanism that makes
gating SDKs work at all.

Binding rules that make a leaked sentinel worthless:

- Redeemable **only** on the originating sandbox's vsock plane — izbad already knows
  the sandbox from `OrigDst.sandbox`, carried per-flow through `DstMap`.
- Redeemable **only** toward a destination matching the grant. Presented elsewhere it
  is stripped, never forwarded, and audited as a probable exfiltration attempt.
- **Per-sandbox and random**, ≥128 bits — never a fixed string like Docker's
  `proxy-managed`. A near-miss is a probe and should be logged as one.
- **Structurally valid** for whatever parses it client-side (§2.B).
- The sentinel never travels upstream; the real secret never travels downstream.

The realistic risk is not sentinel leakage but **sentinel reuse**: a sentinel is
only valuable to an attacker who can also route traffic through izbad. izba's vsock
island closes that by construction — there is no listener a LAN peer could reach.
Rotate on sandbox teardown anyway.

**Strip credentials from responses** (grepular's trick): because responses are
already decrypted, izbad can scan for the secret it just injected and redact or
alarm if a destination reflects it. Catches the "allowed host echoes headers" class;
costs response buffering, so per-grant opt-in.

### 4.5 Suggested staging

| Stage | Scope | Buys |
| --- | --- | --- |
| **V0** | Family A: strip + inject + sentinel redeem, declared-location-only substitution, two allowlists, `secretRef` resolvers, Rego `credential` rule, audit fields | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, GitHub API **and** git-over-HTTPS. Most of the day-to-day value. |
| **V1** | Family B: `izba login` host-side relocation + placeholder credential files; then in-band harvest with body/query substitution | In-sandbox `/login` flows and their refresh loops |
| **V2** | Families C + D: metadata broker (AWS/GCP/Azure short-lived creds), SSH agent brokering | `aws`, `gcloud`, `terraform`, `git push` over SSH |
| **V3** | Rung 1: downscoping minters (GitHub App installation tokens, STS session policies, RFC 8693), OCSF schema, SPIFFE identity | Bounds *abuse*, not just exfiltration |

V0 is small and genuinely covers most of an agent sandbox's daily traffic.

---

## 5. Failure modes — the field's hard-won list

**TLS trust is the biggest operational tax, and it is per-runtime.** Node's
`NODE_EXTRA_CA_CERTS` *appends* to the bundled Mozilla store and **`fetch`/undici
has historically ignored it**; Claude Code specifically does not honour it when set
in `~/.claude/settings.json` ([claude-code#10458](https://github.com/anthropics/claude-code/issues/10458))
— it must be in the real process env, which is exactly what izba's `merge_env` does,
so izba is on the right side of this by luck as much as design. Go ignores
`SSL_CERT_FILE` on macOS and Windows (platform verifier). Deno needs `--cert` or
`Deno.createHttpClient`. Rust's `rustls` + `webpki-roots` ignores the system store
entirely. Java needs a JKS/PKCS12 truststore, not a PEM. **Long-lived sandboxes
across CA rotation are a documented bug factory** (Azure Container Apps #1749;
NemoClaw shipped with the CA simply not injected, breaking all TLS). Keep the CA
long-lived and rotate only leaves — which is what izba already does.

**Ship a documented passthrough escape hatch** for pinned or unparseable clients,
with a loud warning that no injection happens there — never a silent downgrade, per
[the loud-on-security-degradation principle](security/README.md).

**Confused deputy is the structural weakness of the whole pattern** (CWE-441). The
proxy holds real credentials and injects them at the request of an untrusted party;
that is the definition. Beyond the two-allowlist rule in §4.1: re-evaluate the
binding **after every redirect** and never follow a cross-host redirect with the
credential attached; scope by method and path so a `repo`-scoped token does not also
grant `DELETE /repos/{o}/{r}`.

**Protocol coverage gaps to state honestly**: gRPC (h2 trailers and bidi streaming
break naive body substitution), WebSocket (binary frames and permessage-deflate),
**QUIC/HTTP-3 — universally unsupported by every proxy in this space; block UDP/443
or clients silently bypass you**. izba's NIC-less island already blocks it, which is
another structural win worth noting.

**Keyring-absent silent fallback**: `gh` in a microVM will normally find no keyring
and quietly write a plaintext token. If harvest is not in place, that plaintext token
is a real credential sitting in the guest.

---

## 6. Prerequisites and interactions

Three existing findings stop being merely open and become **blocking** once real
credentials are brokered:

- **F-09 — izbad's control socket has no `SO_PEERCRED` check**, paired with **F-10**
  (`OpenStream` splices a client-chosen, daemon-unparsed `StreamOpen`). Verified
  still open: nothing in `crates/izba-core/src/daemon/` reads peer credentials. The
  sole gate is the 0700 daemon dir, so any local process can `Create`/`Start` a
  sandbox and `GuestRpc`-exec inside it. With a vault attached that is a local
  privilege escalation into **spending the user's credentials** — an unprivileged
  process could stand up a sandbox bound to a provider and drive credential-bearing
  requests through izbad. **This must close first.**
- **F-05 — the DNS QNAME exfiltration channel is CLOSED** (issue #148 closed; the
  `resolvable` rule at `egress.rego:104-127` now denies any QNAME absent from every
  rule, for enforcing sandboxes). The findings register's 2026-07-21 status line is
  stale on this point. Worth recording the asymmetry anyway, because it generalises:
  the vault design is **robust to side channels for credentials specifically**,
  since the credential is never in the guest to exfiltrate. That is a genuine
  argument *for* the vault — it is the one control that survives an exfil channel
  reopening. It does nothing for other data.
- **F-30 / Option C — vault material must never enter any virtiofs export.** In-guest
  read-only is null under A1 (virtiofsd serves raw FUSE writes as the host user;
  guest `MS_RDONLY` is advisory). The `secretRef` design satisfies this by
  construction: there is no material to place anywhere.

**Binary attribution must remain advisory.** OpenShell gates credentials on the
calling binary's path and sha256 — condition 2 of its five. Under izba's A1 that
value would be computed by izba-init *inside a hostile guest* and shipped over the
wire, i.e. attacker-supplied. It is excellent for audit and UX and must **never** be
an authorization input. Worth writing down, because the temptation is strong and the
failure is silent.

---

## 7. Open questions

1. **The credential-mapping grammar** — the one named open design decision in the
   roadmap, to be settled with the M4 manifest-grammar session so M4 and M5 share
   one schema. Recommendation: start from OpenShell `providers-v2`.
2. **Rung 1 minters** — GitHub Apps and AWS STS are the obvious two. Does a generic
   RFC 8693 resolver cover enough of the rest? (Almost no consumer providers
   implement 8693; Google/Okta/Auth0/Authlete do.)
3. **Rotation and revocation UX** under the locked static-policy + reload-verb
   regime — an M5 exit criterion with no mechanism designed. Does revoking a grant
   tear live connections?
4. **Re-sign vs broker for AWS** — §2.C recommends brokering; confirm nobody needs
   true zero-material for cloud.
5. **Do we want in-band harvest at all**, given the field converged on host-side
   relocation? It is cheaper for izba than for anyone else, but it carries the
   structural-validity and redeemable-refresh hazards of §2.B.
6. **izbad scope creep (risk #6★)** — explicitly flagged for re-check "before M5
   folds in the vault." The broker plane in §4.3 is a *second datapath* inside
   izbad, which makes this question sharper, not softer.
