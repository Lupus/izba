# Egress-firewall building blocks (M2 + M5)

OSS building-block survey + decisions for the **agent firewall** (M2: per-sandbox
domain allow-list + audit log) and the **credential vault / MITM** (M5: terminate
TLS, L7 policy, credential injection). Companion to
[design-lineage.md](design-lineage.md) (the project-wide prior-art map): this is
the "what to leverage instead of reinventing" record that informs the egress
plane. Researched 2026-06-13 via multi-agent web + source review; claims below
are source-verified (project repos / vendor docs), not blog-only.

See also: [roadmap.md](roadmap.md) (M2/M5 definitions, risk register),
[vision.md](vision.md) (the credential-vault north star),
[specs/2026-06-12-izba-mesh-networking-design.md](superpowers/specs/2026-06-12-izba-mesh-networking-design.md)
(izbad as the policy hub; the `daemon/egress/router.rs` dispatch point M5 hangs
off).

## TL;DR decisions

| Block | Decision | Status |
| --- | --- | --- |
| Policy engine | **regorus** (Microsoft, pure-Rust OPA/Rego interpreter) — reuses our docker-mitm-bridge Rego lineage | Spike proven in-tree (see below) |
| M2 domain allow-list mechanism | **DNS-snoop** (Cilium toFQDNs / Azure-Firewall model) — the only thing that recovers the FQDN, since the guest hands izbad an IP literal | Designed; not yet built |
| Reference architecture / salvage source | **NVIDIA OpenShell** (Apache-2.0, ~90% Rust) — our M2+M5 vision already shipped; mine its modules | Source-verified; M5 salvage spike in progress |
| M5 MITM datapath | rustls + rcgen on a pre-established stream (lift OpenShell's `l7/tls.rs`, or hand-roll on `tokio_rustls`) — **not** hudsucker's `Proxy` (owns its listener, assumes forward-proxy CONNECT) | M5 spike in progress |
| Rejected alternatives | Cedar / cel-rust / casbin-rs (not better than regorus given existing Rego); hudsucker as a turnkey proxy (wrong shape) | — |

## 1. Policy engine — regorus

`regorus` (github.com/microsoft/regorus, latest 0.10.x, MIT/Apache/BSD,
OPA-v1.2.0-conformant, `no_std`-capable) is an embeddable pure-Rust Rego
interpreter — no sidecar, no FFI, sub-ms eval for an allow-list-sized policy.

Why it wins: we already have working Rego from **docker-mitm-bridge**
(mitmproxy + OPA, `opa-policies/policy.rego` + `data.yml`: a domain→tier map —
*restricted* = GET/HEAD-only for pypi/npm/github, *unrestricted* = all-methods
for api.anthropic.com/api.openai.com). regorus runs that lineage essentially
as-is, and the L7 method/path/body horizon (M5) is the same engine with richer
`input`.

Load-bearing integration facts (from a working spike behind the existing
`Policy` trait):

- The **`arc` feature is required** for `Engine: Send + Sync` (the `Policy`
  trait bound). Without it `Engine` uses `Rc` and won't satisfy izbad's
  thread-per-connection model.
- `Engine`'s eval methods take `&mut self`; `Policy::check` takes `&self`.
  Resolve with **clone-per-check** — `Engine: Clone` cheap-clones the compiled
  AST behind `Arc`; no `Mutex` on the hot path. Build one template `Engine` at
  daemon start (policies + data loaded), `clone()` per connection. Hot-reload =
  swap the template behind an `ArcSwap`/`RwLock`.
- Marshal `FlowDesc` → JSON → `engine.set_input_json(...)` →
  `eval_rule("data.egress.decision")` (capture `{allow, reason}` for the audit
  log) or `eval_bool_query("data.egress.allow", false)`. Fail-closed (any eval
  error ⇒ Deny).
- **Do CIDR/IP logic in Rust, never in Rego** — regorus's `net.*` builtins are
  unreliable/partial; pass pre-computed labels into `input`. (We already have
  `ipnet`.) `regex`/`glob`/`startswith`/`endswith`/`in` are all supported, which
  covers domain/method/path matching.
- Trim features: `default-features = false, features = ["std","arc","regex","glob"]`.

**Rejected:** Cedar (different PARC language — would mean rewriting all our
Rego), cel-rust (expression evaluator only — no policy/default-deny/rule-set
structure), casbin-rs (ships firewall semantics but a less expressive language).
None beat "we already have Rego and like it."

## 2. M2 domain allow-list — DNS-snoop

**The problem the allow-list must solve first:** the guest derives the egress
destination from `SO_ORIGINAL_DST` on the nft-REDIRECTed socket and sends izbad
an **IP literal** in `StreamOpen::TcpConnect{addr,port}`
(`crates/izba-init/src/egress.rs`) — there is **no hostname** in the frame. A
domain allow-list keyed on `FlowDesc.addr` is meaningless until the name is
recovered.

**The fix is nearly free for izba** because izbad is *both* the guest's resolver
(it forwards `Dns` frames) *and* its TCP dialer — it sees both halves of every
flow on one vsock plane, per sandbox. This is the position Cilium's in-agent DNS
proxy and Azure Firewall's DNS-proxy engineer for themselves; izba has it
structurally, which **eliminates the client/firewall resolution-divergence race
both prior-art systems must design around.**

Mechanism (Cilium toFQDNs + Azure Firewall network rules):

1. Snoop the DNS responses izbad forwards; build a **per-sandbox**
   `IpAddr → {fqdn, expiry}` map. Parse with `hickory-proto` (read-only), not a
   hand-rolled RFC1035 parser (attacker-influenced data).
2. Clamp each entry's lifetime to **`clamp(dns_ttl, 60s, 15min)`** — Azure's
   15-minute cap plus a floor so TTL=0/round-robin records don't expire before
   the connection that prompted the lookup. Re-resolution refreshes.
3. On `TcpConnect{addr=IP}`: look up which FQDN(s) *this sandbox* resolved to
   that IP, match against the allow-list (exact / `*.x` one-label / `**.x` any
   depth, Cilium semantics)*(Shipped: matched in `egress.rego` via `glob.match`
   with a `.` delimiter — one canonical matcher for both MITM and snoop tiers)*,
   Allow/Deny + **audit record**.
4. **No snoop record ⇒ default-Deny.** An agent dialing a raw IP it never
   resolved is exactly the pattern domain-allow-listing exists to catch
   (matches Azure + Cilium default-deny). A narrow `allow_raw_cidrs` escape
   hatch covers legitimately-static endpoints.
5. Independently, an **RFC1918/link-local egress denylist** at the dial site
   (drop `10/8`, `192.168/16`, `172.16/12`, `127/8`, `169.254/16`, `::1`,
   `fc00::/7`) closes DNS-rebinding-to-metadata regardless of snoop state.

Concurrency: per-sandbox `Arc<Mutex<SandboxSnoop>>` shards (the sandbox name is
already the isolation boundary; drop the shard on sandbox teardown). Expiry:
lazy-on-lookup (authoritative for correctness) + a cheap background sweep
(memory hygiene). No prefetch (matches Azure).

**Honest limitation — document at the call site and in user docs:** DNS-snoop is
an **observability + cooperative-agent boundary, not a hard security boundary.**
A shared CDN IP serving both an allowed and a denied FQDN defeats it (Azure
documents this exact gap for network rules), as does a hostile in-guest process
abusing a still-live mapping. **Hard enforcement is M5 MITM** (the decrypted
`Host`/SNI is unambiguous). State the M2-vs-M5 trust model explicitly.

> **Interaction with leapfrogging to M5:** if we commit to MITM-everything, the
> HTTPS allow-list decision moves to the decrypted `Host` header (precise, no
> shared-IP ambiguity), reusing the same regorus policy with richer input.
> DNS-snoop then shrinks to the **non-MITM'd tail** (raw TCP, non-HTTP). So M5
> partially subsumes M2's DNS-snoop rather than stacking on it.

## 3. Reference architecture & salvage source — NVIDIA OpenShell

`github.com/NVIDIA/OpenShell` (Apache-2.0, Rust ~90%, a "safe runtime for
autonomous AI agents") is essentially izba's combined **M2+M5 already shipped**,
and is both our closest competitor and a permissively-licensed salvage source.
**Source-verified** (not just README):

- **Egress enforcement is in-process Rust, NOT K8s-delegated** — a forward proxy
  + regorus, deliberately substrate-independent (works across its
  Docker/Podman/VM/K8s drivers). K3s-in-Docker is one deployment, not the
  mechanism. So architecture-borrowing is sound *and* code reuse is real.
- Every outbound connection → policy engine → **Allow / Route-for-inference
  (strip caller creds, inject backend creds) / Deny+log**, with L7 method+path
  enforcement (its demo denies `POST /repos/.../issues` while allowing GET).

Salvageable modules (all `crates/openshell-sandbox/src/`, Apache-2.0; retain
license headers + NOTICE when lifting):

| Module | What it gives izba | izba note |
| --- | --- | --- |
| `procfs.rs` | `/proc/net/tcp` inode→fd-owner→binary sha256 + ancestry — **binary attribution izba has none of today** | Must run **guest-side** in izba-init (PID 1 owns `/proc`); ship `{binary_path,sha256,ancestors}` in the egress frame (izba-proto extension) |
| `opa.rs` + `data/sandbox-policy.rego` | regorus wrapper; `NetworkInput{host,port,binary_path,binary_sha256,ancestors}` schema = the `FlowDesc` izba should grow into; YAML→data-doc compile | Mostly covered by our regorus spike |
| `l7/tls.rs` | rustls+rcgen ephemeral-CA MITM **on a pre-established stream** (cert cache) = izba's M5 datapath; lower-friction than hudsucker (which owns a listener) | M5 datapath spike validating the lift |
| `l7/token_grant_injection.rs` | header strip(Authorization)/inject(Bearer) + specificity-scored dest→cred matching | = izba M5 credential injection |
| `secrets.rs` | in-memory placeholder/expiry secret model (`openshell:resolve:env:KEY`), secrets never in child environ | M5 vault seed |
| `child_env.rs` | canonical CA-bundle env var list (`NODE_EXTRA_CA_CERTS`/`SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`/`GIT_SSL_CAINFO`/`DENO_CERT`…) so guest tools trust the MITM CA | Lift the list verbatim for the CA-in-guest step |

**Do not reuse:** `openshell-router` (it's an LLM-*inference* backend router, not
egress), the gateway/K8s-driver/Helm, SPIFFE/SVID + gRPC supervisor transport
(izba uses framed-JSON over AF_UNIX). Keep the `TokenGrantResolver` trait *shape*
only.

**Impedance mismatch:** OpenShell uses forward-proxy/CONNECT + `HTTP_PROXY` env
(+ netns belt-and-suspenders). izba's vsock-1027 inversion is *structurally
stronger* (NIC-less guest, `dummy0` deny — no bypass), so borrow the
policy/attribution/MITM/cred logic, **not** the HTTP_PROXY enforcement mechanism.

> **Library vs vendor — settled: vendor-specific-files-with-attribution.**
> Nothing is published to crates.io. A git-dependency is a trap: it drags a
> Kubernetes control-plane's whole build graph (kube, k8s-openapi, sqlx, tonic,
> spiffe, z3) **and** the parts you want most (`secrets`, `child_env`,
> `token_grant`) are private (`mod`, not `pub mod`) — unreachable as a lib API.
> Licensing is clean: **Apache-2.0 → Apache-2.0** (izba is also Apache-2.0). Per
> Apache §4: keep the per-file `SPDX-FileCopyrightText`/`SPDX-License-Identifier`
> headers on lifted files, add a "modified by izba" line, and add one `NOTICE`
> stanza (no propagation duty — OpenShell ships no NOTICE). No GPL/AGPL anywhere
> in the closure of the target files. `l7/tls.rs`, `secrets.rs`, `procfs.rs`,
> `child_env.rs` lift cleanly; `token_grant_injection.rs` + `opa.rs` drag
> internal `openshell_core` protos + the `openshell_ocsf` audit layer — **better
> reimplemented from their (pure-function) design** than vendored.

## 4. M5 MITM datapath — why not hudsucker's `Proxy`

`hudsucker` (Apache/MIT, hyper/tokio) is a capable MITM library, but its
`Proxy`/`ProxyBuilder` **owns its `TcpListener`** and assumes the client speaks
forward-proxy `CONNECT` — izba has *neither* (it holds an already-accepted vsock
`UdsStream` carrying a raw TLS ClientHello). Its MITM core (`InternalProxy`) is
`pub(crate)`. So hudsucker is reusable only as a *library* (`RcgenAuthority`,
the `HttpHandler` trait shape), not as a turnkey proxy.

Two viable datapaths (both force a **tokio runtime into the egress plane**,
which is blocking-std threads today; non-MITM'd flows stay on the current
splice):

- **Lift/adapt OpenShell's `l7/tls.rs`** — already operates on a pre-established
  stream; likely lowest-friction. *(Being validated by the M5 spike.)*
- **Hand-roll** on `tokio_rustls::TlsAcceptor::accept(stream)` +
  `hyper_util::auto::Builder::serve_connection(io, svc)`, reusing only
  hudsucker's `RcgenAuthority`.
- *(Fallback)* hudsucker **loopback-hop**: the blocking splice thread connects to
  a local hudsucker port; original destination passed via a source-port-keyed
  rendezvous map. Keeps the vsock blocking-thread + OpenVMM churn-teardown
  invariant untouched, but adds a localhost hop and synthesizes a CONNECT line.

Use the **ring** rustls CryptoProvider (cross-compiles to `x86_64-pc-windows-gnu`
more reliably than aws-lc-rs — izba-core is CI-gated on that target).

**M5 prerequisites independent of the datapath:** (a) izba's root CA baked into
the **guest trust store** at boot (izba-init work, beside resolv.conf/hostname);
(b) cert-pinning clients break — accepted/documented posture per the roadmap
decision.

## M5 salvage spike — results (2026-06-13)

A worktree spike vendored OpenShell's `l7/tls.rs` MITM datapath into izba
(`crates/izba-core/src/daemon/egress/mitm.rs`, 678 lines, per-item SPDX
attribution) and **all gates pass**:

- `cargo test -p izba-core --lib` → **164/164 green**, including a full
  end-to-end MITM test: terminate the guest's TLS under the izba CA → read the
  decrypted `GET /v1/messages` + `Host` (L7 visibility for policy/creds) →
  re-originate TLS to the upstream → pipe the response back. Also a
  policy-deny-short-circuits test.
- `cargo clippy --all-targets -- -D warnings` clean; `cargo fmt --check` clean.
- **`cargo check --target x86_64-pc-windows-gnu` clean** (the make-or-break):
  `rustls`/`tokio-rustls`/`rcgen` on the **ring** CryptoProvider cross-compile
  without a C toolchain dance. (aws-lc-rs is *also* linked transitively via
  oci-client's reqwest, so production izbad must `install_default()` the ring
  provider explicitly — the spike does this.)

**Lift verdict:** `l7/tls.rs` is **lift-with-light-adaptation** — only
`miette`→`anyhow`, drop `tracing`, and generalize over `AsyncRead + AsyncWrite`
instead of `tokio::net::TcpStream` (so it's transport-decoupled from vsock). The
`CertCache` overflow-clear policy and leaf-minting lifted near-verbatim.

**Credential injection** (separate assessment): the load-bearing functions are
**pure and lift near-verbatim** (`inject_header` strip+insert, `validate_header_name`
RFC-7230 + framing-denylist, `validate_resolved_secret` CWE-113 guard, the
host/path **specificity scorer**) — no OCSF/SPIFFE drag. izba's "no key in the
guest" can be **stronger** than OpenShell's: the credential lives only in
izbad's vault keyed by `(role|sandbox, host\tport\tpath)`; the guest never even
holds a placeholder. Keep the `TokenGrantResolver` trait seam for an M4-manifest
/ rotating vault.

**CA-in-guest** (separate assessment): **small (~120–180 lines, no proto
change)**, env-var-first (the 6-var bundle, CA concatenated with the guest's
system bundle), CA transported host→guest as a second read-only `izba-trust`
virtiofs share, written in izba-init beside `write_resolv_conf()`
(`main.rs:99`), env defaults injected at the exec choke point (`exec.rs:94`).
Orthogonal to the datapath.

### What the spike did NOT prove (the remaining M5 risk surface)

- **The vsock↔tokio bridge.** The spike drove the datapath over in-memory
  `tokio::io::duplex`, not the real blocking `UdsStream`. Wiring it to the
  production router needs the loopback-hop or adapter-stream bridge (see §4) and
  forces a tokio runtime into the egress plane (non-MITM'd flows can stay on the
  blocking splice).
- **Real-OpenVMM churn re-validation.** The async `pump_bidirectional` mirrors
  the blocking `portfwd` drain-to-EOF discipline, but the OpenVMM
  churn-teardown invariant must be re-proven under it (the gate that caught the
  original M0 crash).
- **HTTP/2 + WebSocket + non-HTTP-on-443 fallthrough.** The spike handles
  HTTP/1.1; production needs h2/ws and an opaque-tunnel fallthrough for
  non-TLS/non-HTTP traffic on intercepted ports (OpenShell's `looks_like_tls`
  peek — already lifted — is the classifier).

> **Bottom line:** the salvage holds. The hard datapath (TLS termination, per-SNI
> leaf minting, L7 visibility, churn-safe pump) compiles, tests green, and
> cross-compiles to Windows. The residual work is izba-specific integration
> (vsock bridge, CA-in-guest, h2/fallthrough), not reinventing the MITM core.
