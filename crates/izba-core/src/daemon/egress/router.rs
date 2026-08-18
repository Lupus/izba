//! Per-connection dispatch for the egress plane: read the guest's
//! `StreamOpen` frame, then route. `TcpConnect` → policy → host dial-out →
//! splice; `Dns` (and `TcpConnect` to :53 — a hardcoded-resolver client) →
//! the resolver. The M5 MITM/vault branch hangs off this dispatch point.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use izba_proto::{dns, read_frame, write_frame, ErrorKind, Response, StreamOpen};

use super::audit::{AuditRecord, AuditSink, Tier};
use super::dns::Resolver;
use super::dns_snoop::{self, SnoopStore};
use super::mitm_runtime::{MitmRuntime, OrigDst};
use super::policy::{FlowDesc, Policy, Verdict};
use crate::vmm::UdsStream;

/// Same cap as the guest-side TcpDial: a wedged dial must not pin a thread.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// The IANA-registered USB/IP port. `usbipd-win` and Linux `usbipd` both listen
/// here by default, and neither offers any authentication or authorization.
pub const USBIP_PORT: u16 = 3240;

/// Per-sandbox USB context for the F-USB-1 floor (see [`usbip_guard`]).
///
/// `Default` is "no USB", which is what a sandbox without device grants gets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UsbGuard {
    /// True when this sandbox holds at least one USB device grant.
    pub sandbox_usb_enabled: bool,
    /// The host-configured upstream usbip endpoint, when one is configured.
    pub upstream: Option<(IpAddr, u16)>,
}

/// Canonicalize an IPv6-embedded IPv4 address to its v4 form, so a mapped or
/// compatible spelling cannot slip past an address comparison. Mirrors what
/// [`is_hard_denied`] and [`is_lan`] already do.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => embedded_v4(v6).map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// F-USB-1 default: a **USB-enabled but non-enforcing** sandbox does not reach
/// a usbip upstream over the generic egress plane, because importing a device
/// that way would bypass the per-device allowlist izbad enforces on the USB
/// plane.
///
/// The governing principle is deliberate and narrow: **this default may fill in
/// where the user has expressed no decision; it must never veto one they made.**
///
/// - A **bare** sandbox has made no per-destination decision (it declined a
///   firewall, so everything non-hard-denied is permitted wholesale). Where it
///   also holds USB grants there is a competing consent channel worth
///   defending, so the default applies. To opt out, declare a policy and list
///   the endpoint explicitly — which turns it into the enforcing case below.
/// - An **enforcing** sandbox is already default-deny, so this check would add
///   nothing except overriding an explicit rule. Reaching a usbip port there
///   requires the user to literally write `ports: [3240]` against a named host
///   (a bare host entry authorizes only [80, 443] — see
///   [`AllowEntry::DEFAULT_PORTS`](super::config::AllowEntry::DEFAULT_PORTS)),
///   which is about as deliberate as the policy language gets. That rule is
///   honored; the user is warned instead, at the moment they write it
///   ([`usbip_exposure_warning`](super::config::usbip_exposure_warning)).
/// - A **bare sandbox with no USB grants** keeps LAN access, as before.
///
/// This is unlike the [`is_hard_denied`] SSRF floor, which is genuinely
/// non-overridable: loopback / link-local / metadata are confused-deputy
/// targets, dangerous precisely because izbad dials them from the HOST's
/// network position, so the guest reaches what it structurally could not reach
/// itself. A usbip server on a LAN address is an ordinary external destination
/// the user is naming on purpose, and does not warrant the same veto.
///
/// The check is by port AND by configured endpoint, because one usbipd is
/// reachable at several addresses at once (loopback, the WSL gateway, a LAN
/// address, and their IPv6-embedded spellings) and because a usbipd may be
/// configured to listen somewhere other than 3240. Note it is a default, not a
/// boundary: a usbipd on an unconfigured non-3240 port is not matched.
pub fn usbip_guard(
    guard: UsbGuard,
    enforcing: bool,
    ip: IpAddr,
    port: u16,
) -> Option<&'static str> {
    // An explicit policy decision is honored; see the doc comment.
    if enforcing || !guard.sandbox_usb_enabled {
        return None;
    }
    if port == USBIP_PORT {
        return Some(
            "usbip upstream (port 3240) not reachable from a USB-enabled sandbox \
             without an explicit policy rule",
        );
    }
    if let Some((up_ip, up_port)) = guard.upstream {
        if port == up_port && canonical(up_ip) == canonical(ip) {
            return Some(
                "configured usbip upstream not reachable from a USB-enabled sandbox \
                 without an explicit policy rule",
            );
        }
    }
    None
}

/// Serve one guest-initiated egress connection (the vsock-1027 bridge).
/// `mitm` (when present) routes tier-1 HTTP(S) ports through the loopback hop.
#[allow(clippy::too_many_arguments)]
pub fn handle_conn(
    mut conn: UdsStream,
    sandbox: &str,
    policy: Arc<dyn Policy>,
    resolver: &dyn Resolver,
    mitm: Option<&MitmRuntime>,
    audit: &AuditSink,
    snoop: &SnoopStore,
    usb: UsbGuard,
) {
    let open: StreamOpen = match read_frame(&mut conn) {
        Ok(o) => o,
        Err(_) => return, // malformed first frame: nothing spliced yet, just drop
    };
    match open {
        StreamOpen::TcpConnect { addr, port } => tcp_connect(
            conn, sandbox, policy, resolver, mitm, audit, snoop, usb, &addr, port,
        ),
        // `Dns` is UDP-origin (cap answers at 512, TC=1 on overflow); `DnsTcp`
        // is TCP-origin (return the full answer, up to 64 KiB).
        StreamOpen::Dns => dns_loop(conn, &*policy, resolver, sandbox, audit, snoop, false),
        StreamOpen::DnsTcp => dns_loop(conn, &*policy, resolver, sandbox, audit, snoop, true),
        _ => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: "unsupported StreamOpen on the egress port".into(),
                },
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn tcp_connect(
    mut conn: UdsStream,
    sandbox: &str,
    policy: Arc<dyn Policy>,
    resolver: &dyn Resolver,
    mitm: Option<&MitmRuntime>,
    audit: &AuditSink,
    snoop: &SnoopStore,
    usb: UsbGuard,
    addr: &str,
    port: u16,
) {
    // TCP DNS: izbad IS the resolver — always allowed (the resolver path, not
    // arbitrary guest egress), answer locally. After Ok the raw stream carries
    // RFC 1035 TCP framing, exactly the `Dns` stream contract. This is a
    // TCP-origin query (the guest dialed an upstream resolver on :53 over TCP),
    // so answers are NOT capped at the 512-byte UDP limit.
    if port == 53 {
        if write_frame(&mut conn, &Response::Ok).is_err() {
            return;
        }
        dns_loop(conn, &*policy, resolver, sandbox, audit, snoop, true);
        return;
    }
    let ip: IpAddr = match addr.parse() {
        Ok(ip) => ip,
        Err(_) => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: format!("not an IP literal: {addr}"),
                },
            );
            return;
        }
    };

    // NON-OVERRIDABLE SSRF floor for the whole TCP datapath (tier-1 MITM +
    // tier-2), applied before any policy: loopback / link-local + cloud metadata
    // / unspecified — the host itself and IMDS credentials are never a legitimate
    // egress target for ANY sandbox. (RFC1918/LAN is NOT blocked here; it is
    // policy-governed in decide_tier2 — bare-permissive, enforcing-by-IP-rule.)
    // port 53 short-circuited above.
    if is_hard_denied(ip) {
        let flow = FlowDesc::l3(sandbox, addr, port);
        audit.record(AuditRecord::from_flow(
            Verdict::Deny,
            &flow,
            ip,
            Tier::L3,
            "blocked address (loopback/link-local/metadata)",
        ));
        let _ = write_frame(
            &mut conn,
            &Response::Error {
                kind: ErrorKind::ConnectFailed,
                message: format!("egress to {addr}:{port} denied: blocked address"),
            },
        );
        return;
    }

    // F-USB-1 floor: no enforcing sandbox, and no USB-enabled sandbox, may
    // reach a usbip upstream over the generic egress plane — that would import
    // a device without ever passing the per-device allowlist. Checked BEFORE
    // tier 1, so a upstream configured on an HTTP(S) port cannot reach the MITM
    // hop instead. (A bare sandbox with no grants is deliberately unaffected;
    // see `usbip_guard`.)
    if let Some(reason) = usbip_guard(usb, policy.enforces(), ip, port) {
        let flow = FlowDesc::l3(sandbox, addr, port);
        audit.record(AuditRecord::from_flow(
            Verdict::Deny,
            &flow,
            ip,
            Tier::L3,
            reason,
        ));
        let _ = write_frame(
            &mut conn,
            &Response::Error {
                kind: ErrorKind::ConnectFailed,
                message: format!(
                    "egress to {addr}:{port} denied: {reason}. Attach devices with \
                     `izba usb attach`, which enforces the per-device allowlist; or, to \
                     reach the server directly anyway, declare an egress policy listing \
                     this host and port explicitly."
                ),
            },
        );
        return;
    }

    // Tier 1 — an INSPECTED port under an ENFORCING policy MUST be terminated by
    // the MITM, so the allow-list is judged on the decrypted Host (an IP is never
    // on a domain allow-list, so we do NOT pre-check on the IP here). Which ports
    // are inspected is now declared by the policy (`protocol:`, M5 D2) rather than
    // hard-coded to 80/443 — but the web ports are always in that set, so this
    // gate only ever widens (DP-1). A bare (non-enforcing) sandbox skips this
    // entirely and keeps the transparent direct dial — no CA trust, no http/1.1
    // downgrade, M1 behavior preserved.
    if policy.enforces() && policy.inspects(port) {
        match mitm {
            Some(mitm) => {
                let passthrough: Arc<[String]> =
                    passthrough_names(&*policy, snoop, sandbox, ip, port, usb).into();
                mitm_hop(
                    conn,
                    mitm,
                    Arc::clone(&policy),
                    ip,
                    port,
                    sandbox,
                    passthrough,
                )
            }
            // FAIL CLOSED: a firewall was declared but the MITM runtime is
            // unavailable (CA/runtime init failed at daemon start). Deny rather
            // than fall through to a tier-2 direct dial — silently downgrading
            // an "enforced" sandbox to DNS-snoop-only (no L7, smuggling-prone)
            // is exactly the wrong failure direction for a security control.
            None => {
                let flow = FlowDesc::l3(sandbox, addr, port);
                audit.record(AuditRecord::from_flow(
                    Verdict::Deny,
                    &flow,
                    ip,
                    Tier::L7,
                    "HTTP(S) firewall (MITM) unavailable — fail-closed",
                ));
                let _ = write_frame(
                    &mut conn,
                    &Response::Error {
                        kind: ErrorKind::ConnectFailed,
                        message: format!(
                            "egress to {addr}:{port} denied: HTTP(S) firewall unavailable \
                             (izbad MITM did not initialize) — failing closed"
                        ),
                    },
                );
            }
        }
        return;
    }

    // Tier 2 — non-HTTP TCP: recover the FQDN from DNS-snoop and decide_tier2.
    // Hard floor (loopback/link-local/metadata) is denied for all; an enforcing
    // policy is default-deny (a LAN target only via an explicit IP rule, never a
    // rebind-able domain); a bare sandbox is permissive for all non-hard-denied
    // addresses (incl. RFC1918/LAN).
    let (verdict, flow, rule) = decide_tier2(&*policy, snoop, sandbox, ip, port, usb);
    audit.record(AuditRecord::from_flow(verdict, &flow, ip, Tier::L3, rule));
    if verdict == Verdict::Deny {
        let _ = write_frame(
            &mut conn,
            &Response::Error {
                kind: ErrorKind::ConnectFailed,
                message: format!("egress to {addr}:{port} denied by policy"),
            },
        );
        return;
    }
    match TcpStream::connect_timeout(&SocketAddr::new(ip, port), DIAL_TIMEOUT) {
        Ok(target) => {
            if write_frame(&mut conn, &Response::Ok).is_err() {
                return;
            }
            crate::portfwd::pump_bidirectional(target, conn);
        }
        Err(e) => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::ConnectFailed,
                    message: e.to_string(),
                },
            );
        }
    }
}

/// Tier-1 loopback hop: pre-bind a loopback source so the source port is known
/// BEFORE connecting, register the `OrigDst` (register-before-connect → no race
/// with the MITM accept claim), dial the MITM listener, then splice the vsock
/// leg with the *unchanged* blocking pump (the OpenVMM churn invariant stays
/// untouched — only the loopback TCP enters tokio, never the vsock `UdsStream`).
fn mitm_hop(
    mut conn: UdsStream,
    mitm: &MitmRuntime,
    policy: Arc<dyn Policy>,
    ip: IpAddr,
    port: u16,
    sandbox: &str,
    passthrough: Arc<[String]>,
) {
    use socket2::{Domain, Socket, Type};
    let listen = mitm.listen_addr();
    let connect = || -> std::io::Result<TcpStream> {
        let sock = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        sock.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
        let src_port = sock
            .local_addr()?
            .as_socket()
            .map(|a| a.port())
            .ok_or_else(|| std::io::Error::other("no loopback source port"))?;
        // Register BEFORE connect so the accept handler can always claim it —
        // the flow carries its per-sandbox policy to the shared MITM runtime.
        mitm.register(
            src_port,
            OrigDst {
                ip,
                port,
                sandbox: sandbox.to_string(),
            },
            Arc::clone(&policy),
            Arc::clone(&passthrough),
        );
        sock.connect(&listen.into())?;
        Ok(sock.into())
    };
    match connect() {
        Ok(sock) => {
            if write_frame(&mut conn, &Response::Ok).is_err() {
                return;
            }
            crate::portfwd::pump_bidirectional(sock, conn);
        }
        Err(e) => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::ConnectFailed,
                    message: format!("MITM loopback dial: {e}"),
                },
            );
        }
    }
}

/// The DNS-snoop-bound names for `ip` that the operator declared as the TLS
/// pinning passthrough on `port` (§5.2). Empty — the case for every policy that
/// never writes `protocol: tcp` — means "inspect", so the datapath is unchanged,
/// AND costs nothing: `policy.has_passthrough()` short-circuits before the
/// `decide_tier2` ceiling call below, so a policy with no `protocol: tcp`
/// anywhere pays zero extra regorus evaluations on the common tier-1 path.
///
/// **Why this is not just `policy.passthrough_host(sni, port)`.** The SNI is a
/// string the guest chooses, and a passthrough has no upstream certificate
/// verification by construction — that is the whole point of the hatch. Deciding
/// on the SNI alone would therefore splice a guest-chosen ADDRESS on the
/// strength of a guest-chosen NAME: an unrestricted exfiltration channel. So the
/// candidate set is derived from what izbad's OWN resolver answered for this
/// address, and is filtered through `decide_tier2` — a passthrough flow is
/// exactly a tier-2 flow that additionally proves its SNI, and it inherits the
/// rebinding guard (`is_lan` ⇒ no name-authorized reach) unchanged.
pub fn passthrough_names(
    policy: &dyn Policy,
    snoop: &SnoopStore,
    sandbox: &str,
    ip: IpAddr,
    port: u16,
    usb: UsbGuard,
) -> Vec<String> {
    // A bare sandbox is never terminated, so it has nothing to pass through.
    if !policy.enforces() {
        return Vec::new();
    }
    // The zero-cost short-circuit for the overwhelmingly common policy: no
    // `protocol: tcp` anywhere means no candidate can ever pass the
    // `passthrough_host` filter below, so skip the `decide_tier2` ceiling
    // call (a regorus evaluation per DNS-snoop'd name) entirely.
    if !policy.has_passthrough() {
        return Vec::new();
    }
    // Tier-2 is the ceiling: if this flow would not be permitted as an opaque
    // splice, it is not permitted as a passthrough either.
    let (verdict, _, _) = decide_tier2(policy, snoop, sandbox, ip, port, usb);
    if verdict != Verdict::Allow {
        return Vec::new();
    }
    snoop
        .fqdns_for(sandbox, ip)
        .into_iter()
        .filter(|name| policy.passthrough_host(name, port))
        .filter(|name| {
            // SECOND layer, load-bearing, not defence-in-depth, for (at least)
            // two independent reasons a future edit could reopen:
            // 1. `InspectionTable::from_config`'s `passthrough` set and
            //    `to_rego_data_json`'s `sandbox_host_rules` map are two
            //    separate folds over the same unmerged `EgressPolicyConfig
            //    ::allow` — kept in lockstep today (both last-wins per exact
            //    host), but a future edit to either could let them diverge.
            // 2. `InspectionTable` never consults `AllowEntry::access()` at
            //    all — an `access: read` + `protocol: tcp` host answers
            //    `passthrough_host == true` unconditionally, while
            //    `RegoPolicy::check` denies it for any methodless (tier-2)
            //    flow (`egress.rego`'s `host_access_ok("read")` requires
            //    GET/HEAD, and `FlowDesc::l3` never carries a method).
            // Do not delete this as "redundant with decide_tier2" — it is the
            // only thing that closes both gaps.
            let mut f = FlowDesc::l3(sandbox, name.clone(), port);
            f.host = Some(name.clone());
            policy.check(&f) == Verdict::Allow
        })
        .collect()
}

/// Tier-2 (non-HTTP TCP) decision: recover the FQDN(s) izbad resolved for `ip`
/// and decide. Returns the verdict, the `FlowDesc` to audit, and a rule label.
///
/// Address posture (F-01):
/// - `is_hard_denied` (loopback / link-local + metadata / unspecified) is a
///   non-overridable Deny for EVERY sandbox — the SSRF floor.
/// - A bare (non-enforcing `AllowAll`) sandbox is permissive for everything else,
///   including RFC1918/LAN (M1 behavior — the user declined a firewall).
/// - An enforcing sandbox is default-deny. A snoop'd allow-listed FQDN authorizes
///   only a PUBLIC ip; it must NOT authorize a LAN ip (that is the DNS-rebinding
///   bypass — a guest controlling resolution points an allowed name at an
///   internal host). So a LAN target is reachable ONLY via an explicit IP rule in
///   the policy (`is_lan` ⇒ the raw-IP literal is the sole candidate).
pub fn decide_tier2(
    policy: &dyn Policy,
    snoop: &SnoopStore,
    sandbox: &str,
    ip: IpAddr,
    port: u16,
    usb: UsbGuard,
) -> (Verdict, FlowDesc, &'static str) {
    let names = snoop.fqdns_for(sandbox, ip);
    let mut flow = FlowDesc::l3(sandbox, ip.to_string(), port);
    flow.host = names.first().cloned();

    // Non-overridable SSRF floor (bare AND enforcing).
    if is_hard_denied(ip) {
        return (
            Verdict::Deny,
            flow,
            "blocked address (loopback/link-local/metadata)",
        );
    }

    // F-USB-1 floor (see `usbip_guard`): non-overridable for an enforcing or a
    // USB-enabled sandbox, and checked before the bare-permissive shortcut so a
    // USB-enabled bare sandbox cannot walk past it.
    if let Some(reason) = usbip_guard(usb, policy.enforces(), ip, port) {
        return (Verdict::Deny, flow, reason);
    }

    if !policy.enforces() {
        // Bare/M1: permissive for everything not hard-denied — incl. RFC1918/LAN.
        let verdict = policy.check(&flow);
        return (verdict, flow, "permissive");
    }

    // Enforcing: default-deny. A snoop'd FQDN may authorize only a public ip
    // (skipped for LAN to defeat DNS-rebinding); the raw-IP literal is always a
    // candidate (lets a policy permit a specific public OR LAN ip by listing it).
    let lan = is_lan(ip);
    if !lan {
        for name in &names {
            let mut f = flow.clone();
            f.addr = name.clone();
            f.host = Some(name.clone());
            if policy.check(&f) == Verdict::Allow {
                return (Verdict::Allow, f, "allow-list");
            }
        }
    }
    let mut raw = flow.clone();
    raw.addr = ip.to_string();
    raw.host = None;
    if policy.check(&raw) == Verdict::Allow {
        return (Verdict::Allow, raw, "allow-list (explicit IP)");
    }
    let rule = if lan {
        "LAN not in allow-list (list the IP to permit)"
    } else {
        "not in allow-list"
    };
    (Verdict::Deny, flow, rule)
}

/// An IPv4 embedded in a bypass-prone IPv6 form (mapped `::ffff:a.b.c.d`,
/// deprecated IPv4-compatible `::a.b.c.d`, or NAT64 `64:ff9b::a.b.c.d`), if any.
/// Centralizes the SSRF-bypass canonicalization shared by [`is_hard_denied`] and
/// [`is_lan`]. Uses `to_ipv4_mapped` (NOT `to_ipv4`) and explicitly skips `::`
/// and `::1` so those pure-v6 specials are classified by the native v6 checks,
/// never mis-mapped to `0.0.0.0`/`0.0.0.1`.
fn embedded_v4(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let seg = v6.segments();
    let tail = std::net::Ipv4Addr::new(
        (seg[6] >> 8) as u8,
        seg[6] as u8,
        (seg[7] >> 8) as u8,
        seg[7] as u8,
    );
    // IPv4-compatible ::a.b.c.d (high 96 bits zero), excluding :: and ::1.
    if seg[..6] == [0, 0, 0, 0, 0, 0]
        && !tail.is_unspecified()
        && tail != std::net::Ipv4Addr::new(0, 0, 0, 1)
    {
        return Some(tail);
    }
    // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052).
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        return Some(tail);
    }
    None
}

/// Destinations the egress plane must NEVER reach from ANY sandbox — not even an
/// explicit policy may allow them. Loopback (the host's own services, incl.
/// izbad), link-local + cloud metadata (`169.254.0.0/16`, `fe80::/10` — IMDS
/// credentials), and the unspecified/broadcast/documentation ranges, plus their
/// IPv6-embedded forms. The non-negotiable SSRF floor (F-01). RFC1918/LAN is NOT
/// here — that is policy-governed ([`is_lan`]).
fn is_hard_denied(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_v4(v6) {
                return is_hard_denied(IpAddr::V4(v4));
            }
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
            // link-local fe80::/10
        }
    }
}

/// RFC1918 / unique-local "LAN" destinations (and their IPv6-embedded forms).
/// NOT hard-denied: a bare sandbox may reach them (M1 permissive — the user
/// declined a firewall, so reaching their own LAN/localhost dev services is the
/// intended workflow), and an enforcing sandbox may reach them only when its
/// policy lists the IP *explicitly* — never via a domain, which would be a
/// DNS-rebinding bypass (see [`decide_tier2`]).
fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_v4(v6) {
                return is_lan(IpAddr::V4(v4));
            }
            (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        }
    }
}

/// Framed query/response pairs until EOF. Under an ENFORCING policy each query
/// is gated on its QNAME: a name the policy could not authorize is denied with
/// NXDOMAIN (an unparseable query with SERVFAIL) and audit-logged, and is NEVER
/// forwarded upstream — closing the QNAME-exfil channel. Allowed (and all
/// non-enforcing) queries forward as before; resolver failures become SERVFAIL.
/// Each forwarded answer is snooped (IP→FQDN for tier-2) BEFORE its reply is
/// written, so the mapping is installed before the guest can dial the address.
#[allow(clippy::too_many_arguments)]
fn dns_loop(
    mut conn: UdsStream,
    policy: &dyn Policy,
    resolver: &dyn Resolver,
    sandbox: &str,
    audit: &AuditSink,
    snoop: &SnoopStore,
    over_tcp: bool,
) {
    while let Ok(Some(query)) = dns::read_dns_msg(&mut conn) {
        if policy.enforces() {
            // The gate authorizes a single QNAME. `qname_of` returns `None` for a
            // multi-question message (QDCOUNT != 1) as well as an unparseable one,
            // so a packet that pairs an allow-listed first question with a smuggled
            // exfil-bearing second question is denied fail-closed, never forwarded.
            let name = dns_snoop::qname_of(&query);
            let authorized = name
                .as_deref()
                .is_some_and(|n| policy.allows_name(sandbox, n));
            if !authorized {
                let (reply, rule): (Vec<u8>, &str) = match &name {
                    Some(_) => (dns::nxdomain(&query), "DNS: not in allow-list"),
                    None => (dns::servfail(&query), "DNS: unparseable query (enforcing)"),
                };
                audit.record(AuditRecord::deny(
                    sandbox,
                    Ipv4Addr::UNSPECIFIED.into(),
                    53,
                    name.as_deref(),
                    Tier::L3,
                    rule,
                ));
                if dns::write_dns_msg(&mut conn, &reply).is_err() {
                    break;
                }
                continue;
            }
        }
        let result = if over_tcp {
            resolver.handle_tcp(&query)
        } else {
            resolver.handle(&query)
        };
        let resp = result.unwrap_or_else(|e| {
            eprintln!("izbad: dns forward failed: {e:#}");
            dns::servfail(&query)
        });
        snoop.record(sandbox, &dns_snoop::extract_a_aaaa(&resp));
        if dns::write_dns_msg(&mut conn, &resp).is_err() {
            break; // stop answering, but still drain + half-close below
        }
    }
    let _ = conn.shutdown(std::net::Shutdown::Write);
    // Drain to EOF so the guest is never force-closed with TX buffered
    // (the M0 vsock-churn contract; mirrors copy_until_eof's discipline).
    let mut sink = [0u8; 4096];
    loop {
        match std::io::Read::read(&mut conn, &mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::policy::{AllowAll, RegoPolicy};

    struct FakeResolver;
    impl Resolver for FakeResolver {
        fn handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut r = b"ans:".to_vec();
            r.extend_from_slice(query);
            Ok(r)
        }
    }

    struct FailingResolver;
    impl Resolver for FailingResolver {
        fn handle(&self, _q: &[u8]) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("upstream down")
        }
    }

    /// Distinguishes the UDP and TCP resolver entry points so a test can prove
    /// which one a given `StreamOpen` routes to.
    struct TransportResolver;
    impl Resolver for TransportResolver {
        fn handle(&self, q: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut r = b"udp:".to_vec();
            r.extend_from_slice(q);
            Ok(r)
        }
        fn handle_tcp(&self, q: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut r = b"tcp:".to_vec();
            r.extend_from_slice(q);
            Ok(r)
        }
    }

    struct DenyAll;
    impl Policy for DenyAll {
        fn check(&self, _f: &FlowDesc) -> Verdict {
            Verdict::Deny
        }
    }

    fn spawn_handler(
        policy: Arc<dyn Policy>,
        resolver: &'static (dyn Resolver + Sync),
    ) -> UdsStream {
        let (client, server) = UdsStream::pair().unwrap();
        let audit = AuditSink::new(crate::paths::Paths::with_root(
            std::env::temp_dir().join("izba-router-audit-test"),
        ));
        let snoop = SnoopStore::new();
        std::thread::spawn(move || {
            handle_conn(
                server,
                "web",
                policy,
                resolver,
                None,
                &audit,
                &snoop,
                UsbGuard::default(),
            )
        });
        client
    }

    #[test]
    fn dns_stream_roundtrips_queries() {
        let mut c = spawn_handler(Arc::new(AllowAll), &FakeResolver);
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        dns::write_dns_msg(&mut c, b"q1").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"ans:q1");
        dns::write_dns_msg(&mut c, b"q2").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"ans:q2");
        c.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(dns::read_dns_msg(&mut c).unwrap().is_none());
    }

    /// `StreamOpen::Dns` is UDP-origin → `handle`; `StreamOpen::DnsTcp` is
    /// TCP-origin → `handle_tcp`. Proves the new variant reaches the
    /// non-truncating resolver path (the DNS-over-TCP fix).
    #[test]
    fn dns_tcp_stream_routes_to_handle_tcp() {
        let mut c = spawn_handler(Arc::new(AllowAll), &TransportResolver);
        write_frame(&mut c, &StreamOpen::DnsTcp).unwrap();
        dns::write_dns_msg(&mut c, b"q").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"tcp:q");
    }

    #[test]
    fn dns_udp_stream_routes_to_handle() {
        let mut c = spawn_handler(Arc::new(AllowAll), &TransportResolver);
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        dns::write_dns_msg(&mut c, b"q").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"udp:q");
    }

    /// A guest dialing an upstream resolver on :53 over TCP (TcpConnect:53)
    /// is TCP-origin too — it must reach `handle_tcp`, not `handle`.
    #[test]
    fn tcp_connect_port53_is_tcp_origin() {
        let mut c = spawn_handler(Arc::new(AllowAll), &TransportResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "8.8.8.8".into(),
                port: 53,
            },
        )
        .unwrap();
        assert!(matches!(
            read_frame::<_, Response>(&mut c).unwrap(),
            Response::Ok
        ));
        dns::write_dns_msg(&mut c, b"q").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"tcp:q");
    }

    #[test]
    fn dns_resolver_failure_becomes_servfail() {
        let mut c = spawn_handler(Arc::new(AllowAll), &FailingResolver);
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        let q = [0xbeu8, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        dns::write_dns_msg(&mut c, &q).unwrap();
        let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
        assert_eq!(&resp[..2], &[0xbe, 0xef]);
        assert_eq!(resp[3] & 0x0f, 0x02, "RCODE=SERVFAIL");
    }

    #[test]
    fn tcp_connect_denied_by_policy() {
        // M5 P1 review, task 3, fix round 2, NEW-1: port 443 is now (correctly)
        // gated into tier-1 for ANY enforcing policy — including `DenyAll`,
        // which does not override `inspects` and so gets the trait's baseline
        // (fix round 2, item 1). This test's NAME claims tier-2 ("denied by
        // policy"), so it must dial a port `DenyAll.inspects` answers `false`
        // for, and it must pin the EXACT tier-2 message — a substring match on
        // "denied" is satisfied by BOTH branches and had already silently let
        // this test flip tiers twice across this plan (tier-1 -> tier-2 at
        // task 3's first commit, back to tier-1 at task 3's fix round 1) with
        // nobody noticing. Tier-1's own fail-closed path is already covered by
        // `enforcing_https_fails_closed_when_mitm_unavailable` below, so no
        // separate test is added for that branch here.
        let mut c = spawn_handler(Arc::new(DenyAll), &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "1.2.3.4".into(),
                port: 8000,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, message } => {
                assert_eq!(kind, ErrorKind::ConnectFailed);
                assert_eq!(message, "egress to 1.2.3.4:8000 denied by policy");
            }
            other => panic!("expected deny error, got {other:?}"),
        }
    }

    // --- decide_tier2: pure tier-2 decision (no listeners). ---

    #[test]
    fn decide_tier2_denies_raw_ip_with_no_snoop() {
        let p = RegoPolicy::embedded().unwrap();
        let snoop = SnoopStore::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let (v, _f, rule) = decide_tier2(&p, &snoop, "web", ip, 8443, UsbGuard::default());
        assert_eq!(v, Verdict::Deny);
        assert_eq!(rule, "not in allow-list", "{rule}");
    }

    #[test]
    fn decide_tier2_allows_snooped_allowlisted_fqdn() {
        let p = RegoPolicy::embedded().unwrap();
        let snoop = SnoopStore::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        snoop.record("web", &[("api.anthropic.com".to_string(), ip, 300)]);
        let (v, f, rule) = decide_tier2(&p, &snoop, "web", ip, 443, UsbGuard::default());
        assert_eq!(v, Verdict::Allow);
        assert_eq!(f.host.as_deref(), Some("api.anthropic.com"));
        assert_eq!(rule, "allow-list");
    }

    #[test]
    fn decide_tier2_denies_snooped_but_unlisted_fqdn() {
        let p = RegoPolicy::embedded().unwrap();
        let snoop = SnoopStore::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        snoop.record("web", &[("evil.example.com".to_string(), ip, 300)]);
        let (v, _f, rule) = decide_tier2(&p, &snoop, "web", ip, 8443, UsbGuard::default());
        assert_eq!(v, Verdict::Deny);
        assert_eq!(rule, "not in allow-list");
    }

    /// DNS-rebinding guard: a rebinding that points an allow-listed NAME at a LAN
    /// IP is denied — for an enforcing sandbox a snoop'd FQDN never authorizes a
    /// private target (only an explicit IP rule could, and none is listed here).
    #[test]
    fn decide_tier2_rebind_to_lan_via_allowlisted_name_is_denied() {
        let p = RegoPolicy::embedded().unwrap();
        let snoop = SnoopStore::new();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        snoop.record("web", &[("api.anthropic.com".to_string(), ip, 300)]);
        let (v, _f, rule) = decide_tier2(&p, &snoop, "web", ip, 8443, UsbGuard::default());
        assert_eq!(v, Verdict::Deny);
        assert!(rule.contains("LAN"), "{rule}");
    }

    /// F-01 floor: even a bare (AllowAll) sandbox must NEVER reach loopback /
    /// link-local+metadata / unspecified — the non-overridable SSRF floor.
    #[test]
    fn decide_tier2_bare_hard_denies_loopback_and_metadata() {
        let snoop = SnoopStore::new();
        for ip in ["127.0.0.1", "169.254.169.254", "0.0.0.0", "::1", "fe80::1"] {
            let (v, _f, rule) = decide_tier2(
                &AllowAll,
                &snoop,
                "web",
                ip.parse().unwrap(),
                6379,
                UsbGuard::default(),
            );
            assert_eq!(v, Verdict::Deny, "bare sandbox must not reach {ip}");
            assert!(rule.contains("blocked address"), "{ip}: {rule}");
        }
    }

    /// A bare (non-enforcing AllowAll) sandbox is permissive for everything not
    /// hard-denied — public AND RFC1918/LAN (the M1 contract: the user declined a
    /// firewall, so reaching their own LAN / localhost dev services is intended).
    #[test]
    fn decide_tier2_bare_allows_public_and_lan() {
        let snoop = SnoopStore::new();
        for ip in ["1.2.3.4", "10.0.0.5", "192.168.1.1", "172.16.0.1"] {
            let (v, _f, rule) = decide_tier2(
                &AllowAll,
                &snoop,
                "web",
                ip.parse().unwrap(),
                8443,
                UsbGuard::default(),
            );
            assert_eq!(v, Verdict::Allow, "bare sandbox should reach {ip}");
            assert_eq!(rule, "permissive");
        }
    }

    // --- F-USB-1: the usbip upstream is not reachable over generic egress. ---

    /// An ENFORCING sandbox's explicit rule is HONORED, not vetoed. Enforcing is
    /// already default-deny, so a usbip default there could only ever override a
    /// decision the user made on purpose — and opening 3240 cannot happen by
    /// accident, since a bare host entry authorizes only [80, 443]. The user is
    /// warned when they write the rule instead (`usbip_exposure_warning`).
    #[test]
    fn enforcing_sandbox_explicit_usbip_rule_is_honored() {
        let snoop = SnoopStore::new();
        let data = r#"{"host_rules": {"10.1.0.124": {"ports": [3240, 8080], "access": "read-write"}}, "sandbox_host_rules": {}, "sandbox_git_rules": {}}"#;
        let p = RegoPolicy::with_data(data).unwrap();
        let ip: IpAddr = "10.1.0.124".parse().unwrap();

        let (v, _f, rule) = decide_tier2(&p, &snoop, "web", ip, 3240, UsbGuard::default());
        assert_eq!(
            v,
            Verdict::Allow,
            "an explicit rule must not be vetoed: {rule}"
        );

        // Holding USB grants does not change that: the decision is still explicit.
        let guard = UsbGuard {
            sandbox_usb_enabled: true,
            upstream: Some((ip, 3240)),
        };
        let (v, _f, rule) = decide_tier2(&p, &snoop, "web", ip, 3240, guard);
        assert_eq!(v, Verdict::Allow, "{rule}");
    }

    /// An enforcing sandbox remains default-deny for a usbip port it did NOT
    /// list — the ordinary allow-list rule, with no special-casing either way.
    #[test]
    fn enforcing_sandbox_still_denies_unlisted_usbip_port() {
        let snoop = SnoopStore::new();
        let p = RegoPolicy::embedded().unwrap();
        let (v, _f, _) = decide_tier2(
            &p,
            &snoop,
            "web",
            "10.1.0.124".parse().unwrap(),
            3240,
            UsbGuard::default(),
        );
        assert_eq!(v, Verdict::Deny);
    }

    /// A USB-enabled sandbox must not bypass the device allowlist by speaking
    /// usbip itself — being bare (non-enforcing) does not exempt it.
    #[test]
    fn usb_enabled_bare_sandbox_cannot_reach_usbip_port() {
        let snoop = SnoopStore::new();
        let guard = UsbGuard {
            sandbox_usb_enabled: true,
            upstream: None,
        };
        let (v, _f, rule) = decide_tier2(
            &AllowAll,
            &snoop,
            "web",
            "192.168.1.50".parse().unwrap(),
            3240,
            guard,
        );
        assert_eq!(v, Verdict::Deny);
        assert!(rule.contains("usbip"), "{rule}");
    }

    /// A usbipd may be configured to listen somewhere other than 3240, so the
    /// configured endpoint is denied on its own port too.
    #[test]
    fn configured_upstream_endpoint_is_denied_on_its_own_port() {
        let snoop = SnoopStore::new();
        let up: IpAddr = "172.30.96.1".parse().unwrap();
        let guard = UsbGuard {
            sandbox_usb_enabled: true,
            upstream: Some((up, 4000)),
        };
        let (v, _f, rule) = decide_tier2(&AllowAll, &snoop, "web", up, 4000, guard);
        assert_eq!(v, Verdict::Deny);
        assert!(rule.contains("usbip"), "{rule}");

        // A different port on the same host is not implicated.
        let (v, _f, _) = decide_tier2(&AllowAll, &snoop, "web", up, 4001, guard);
        assert_eq!(v, Verdict::Allow);
    }

    /// The approved carve-out: a bare sandbox with NO USB grants keeps today's
    /// permissive LAN behaviour. It boots a kernel without `vhci-hcd`, so a
    /// usbip connection has nothing to attach to.
    #[test]
    fn bare_non_usb_sandbox_keeps_lan_access_on_3240() {
        let snoop = SnoopStore::new();
        let (v, _f, rule) = decide_tier2(
            &AllowAll,
            &snoop,
            "web",
            "192.168.1.50".parse().unwrap(),
            3240,
            UsbGuard::default(),
        );
        assert_eq!(v, Verdict::Allow, "bare non-USB sandbox is unchanged");
        assert_eq!(rule, "permissive");
    }

    /// The guard canonicalises IPv6-embedded IPv4 exactly as the SSRF floor
    /// does, so a mapped spelling of the upstream cannot slip past it.
    #[test]
    fn guard_canonicalises_ipv4_mapped_upstream() {
        let guard = UsbGuard {
            sandbox_usb_enabled: true,
            upstream: Some(("172.30.96.1".parse().unwrap(), 4000)),
        };
        for spelling in ["::ffff:172.30.96.1", "::172.30.96.1"] {
            let ip: IpAddr = spelling.parse().unwrap();
            assert!(
                usbip_guard(guard, false, ip, 4000).is_some(),
                "{spelling} must be recognised as the configured upstream"
            );
        }
    }

    /// The default applies only where the user expressed no decision: a bare
    /// USB-enabled sandbox. It never fires for an enforcing sandbox (whose every
    /// allow is explicit) nor for a bare sandbox without USB grants.
    #[test]
    fn guard_applies_only_to_bare_usb_enabled_sandboxes() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let usb = UsbGuard {
            sandbox_usb_enabled: true,
            upstream: None,
        };
        assert!(
            usbip_guard(usb, false, ip, 3240).is_some(),
            "bare + USB-enabled: no explicit decision to honor, so default-deny"
        );
        assert!(
            usbip_guard(usb, true, ip, 3240).is_none(),
            "enforcing: the explicit rule governs, never this default"
        );
        assert!(
            usbip_guard(UsbGuard::default(), false, ip, 3240).is_none(),
            "bare, no USB: unchanged LAN behaviour"
        );
        assert!(
            usbip_guard(UsbGuard::default(), true, ip, 3240).is_none(),
            "enforcing without USB: ordinary allow-list rules apply"
        );
    }

    /// Configurable LAN (enforcing): an enforcing sandbox reaches a private IP
    /// ONLY when its policy lists that IP literally. A domain rule cannot (the
    /// rebind bypass, covered above); the hard floor is non-overridable by policy.
    #[test]
    fn decide_tier2_enforcing_allows_explicitly_listed_lan_ip() {
        let snoop = SnoopStore::new();
        let data = r#"{"host_rules": {"10.1.0.124": {"ports": [8080], "access": "read-write"}}, "sandbox_host_rules": {}, "sandbox_git_rules": {}}"#;
        let p = RegoPolicy::with_data(data).unwrap();
        let ip: IpAddr = "10.1.0.124".parse().unwrap();
        let (v, f, rule) = decide_tier2(&p, &snoop, "web", ip, 8080, UsbGuard::default());
        assert_eq!(v, Verdict::Allow, "explicit IP rule must permit the LAN IP");
        assert_eq!(f.host, None, "matched as a raw IP, not a domain");
        assert!(rule.contains("explicit IP"), "{rule}");
        // A LAN IP NOT listed is still denied.
        let (v2, _f2, _r) = decide_tier2(
            &p,
            &snoop,
            "web",
            "10.1.0.200".parse().unwrap(),
            8080,
            UsbGuard::default(),
        );
        assert_eq!(v2, Verdict::Deny);
        // Loopback stays denied even if (absurdly) listed — the hard floor wins.
        let data2 = r#"{"host_rules": {"127.0.0.1": {"ports": [8080], "access": "read-write"}}, "sandbox_host_rules": {}, "sandbox_git_rules": {}}"#;
        let p2 = RegoPolicy::with_data(data2).unwrap();
        let (v3, _f3, r3) = decide_tier2(
            &p2,
            &snoop,
            "web",
            "127.0.0.1".parse().unwrap(),
            8080,
            UsbGuard::default(),
        );
        assert_eq!(v3, Verdict::Deny, "hard floor is non-overridable by policy");
        assert!(r3.contains("blocked address"), "{r3}");
    }

    /// A snooped, allow-listed FQDN reached on a non-web port is now DENIED —
    /// the tier-2 exfil channel the port loophole left open is closed.
    #[test]
    fn tier2_allowed_fqdn_on_non_web_port_is_denied() {
        let p = RegoPolicy::embedded().unwrap();
        let snoop = SnoopStore::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        snoop.record("web", &[("api.anthropic.com".to_string(), ip, 300)]);

        // Web port 443: allow (baseline — ensures the setup is correct).
        let (v_web, f_web, rule_web) =
            decide_tier2(&p, &snoop, "web", ip, 443, UsbGuard::default());
        assert_eq!(
            v_web,
            Verdict::Allow,
            "port 443 must be allowed: {rule_web}"
        );
        assert_eq!(f_web.host.as_deref(), Some("api.anthropic.com"));

        // Non-web port 22 on the SAME allowed FQDN: the port predicate now denies it.
        let (v_ssh, _f_ssh, rule_ssh) =
            decide_tier2(&p, &snoop, "web", ip, 22, UsbGuard::default());
        assert_eq!(v_ssh, Verdict::Deny, "port 22 must be denied: {rule_ssh}");
        assert_eq!(rule_ssh, "not in allow-list");
    }

    /// Scoped ports flow through tier-2: a host listed for 5432 is reachable on
    /// 5432 but not on 443.
    #[test]
    fn tier2_scoped_port_is_honored() {
        let p = RegoPolicy::with_data(
            r#"{"host_rules": {}, "sandbox_host_rules": {"web": {"db.internal": {"ports": [5432], "access": "read-write"}}}, "sandbox_git_rules": {}}"#,
        )
        .unwrap();
        let snoop = SnoopStore::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        snoop.record("web", &[("db.internal".to_string(), ip, 300)]);

        // Scoped port 5432: allow.
        let (v_pg, _f_pg, rule_pg) = decide_tier2(&p, &snoop, "web", ip, 5432, UsbGuard::default());
        assert_eq!(v_pg, Verdict::Allow, "port 5432 must be allowed: {rule_pg}");
        assert_eq!(rule_pg, "allow-list");

        // Non-scoped port 443: deny.
        let (v_tls, _f_tls, rule_tls) =
            decide_tier2(&p, &snoop, "web", ip, 443, UsbGuard::default());
        assert_eq!(v_tls, Verdict::Deny, "port 443 must be denied: {rule_tls}");
        assert_eq!(rule_tls, "not in allow-list");
    }

    /// dns_loop installs the IP→FQDN snoop mapping from each answer it returns.
    #[test]
    fn dns_loop_snoops_returned_a_records() {
        use crate::daemon::egress::dns_snoop;
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        use std::str::FromStr;

        let ip = std::net::Ipv4Addr::new(203, 0, 113, 7);
        let name = Name::from_str("api.anthropic.com.").unwrap();
        let mut msg = Message::query();
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(name, 300, RData::A(A(ip))));
        let response = msg.to_vec().unwrap();

        struct FixedResolver(Vec<u8>);
        impl Resolver for FixedResolver {
            fn handle(&self, _q: &[u8]) -> anyhow::Result<Vec<u8>> {
                Ok(self.0.clone())
            }
        }
        let resolver = FixedResolver(response);
        let snoop = SnoopStore::new();
        let _ = dns_snoop::extract_a_aaaa(&[]); // (parser exercised by its own tests)

        let (mut c, server) = UdsStream::pair().unwrap();
        let audit = AuditSink::new(crate::paths::Paths::with_root(
            std::env::temp_dir().join("izba-router-dnsloop-test"),
        ));
        // Borrow `snoop`/`resolver` into the scoped thread that runs dns_loop.
        std::thread::scope(|s| {
            let h =
                s.spawn(|| dns_loop(server, &AllowAll, &resolver, "web", &audit, &snoop, false));
            dns::write_dns_msg(&mut c, b"q").unwrap();
            let _ = dns::read_dns_msg(&mut c).unwrap(); // the resolved answer
            c.shutdown(std::net::Shutdown::Write).unwrap();
            drop(c); // let dns_loop's drain reach EOF and return
            h.join().unwrap();
        });

        assert_eq!(
            snoop.fqdns_for("web", IpAddr::V4(ip)),
            vec!["api.anthropic.com".to_string()],
            "the resolved A record was snooped into the store"
        );
    }

    /// FAIL-CLOSED: a declared (enforcing) policy whose MITM runtime is absent
    /// (`mitm=None`, e.g. CA/runtime init failed at daemon start) must DENY an
    /// HTTP(S) flow, never fall through to a tier-2 direct dial. `spawn_handler`
    /// always passes `mitm=None`, so this exercises exactly that path. The deny
    /// must cite the firewall being unavailable (tier-1 fail-closed), not a
    /// tier-2 "denied by policy" — proving the downgrade cannot happen even for
    /// an allow-listed host (the IP here is irrelevant; we never reach tier-2).
    #[test]
    fn enforcing_https_fails_closed_when_mitm_unavailable() {
        let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "1.2.3.4".into(),
                port: 443,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, message } => {
                assert_eq!(kind, ErrorKind::ConnectFailed);
                assert!(
                    message.contains("firewall unavailable"),
                    "expected a tier-1 fail-closed reason, got: {message}"
                );
            }
            other => panic!("expected fail-closed deny, got {other:?}"),
        }
    }

    #[test]
    fn tcp_connect_bad_addr_is_bad_request() {
        let mut c = spawn_handler(Arc::new(AllowAll), &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "not-an-ip".into(),
                port: 80,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::BadRequest),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn tcp_connect_port53_routes_to_resolver() {
        let mut c = spawn_handler(Arc::new(AllowAll), &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "8.8.8.8".into(),
                port: 53,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        dns::write_dns_msg(&mut c, b"tq").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"ans:tq");
    }

    #[test]
    fn unsupported_stream_open_is_bad_request() {
        let mut c = spawn_handler(Arc::new(AllowAll), &FakeResolver);
        write_frame(&mut c, &StreamOpen::TcpDial { port: 80 }).unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::BadRequest),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    // (IPv4-mapped / IPv4-compatible / NAT64 embedded-v4 bypass forms are
    // covered across both address tiers by `hard_denied_vs_lan_classification`.)

    /// The split that the F-01 posture rests on: loopback / link-local+metadata /
    /// unspecified / broadcast / docs are the NON-OVERRIDABLE hard floor; RFC1918
    /// / ULA are LAN (policy-governed), NOT hard-denied. Embedded-IPv4 v6 forms
    /// classify by their embedded v4 in BOTH tiers.
    #[test]
    fn hard_denied_vs_lan_classification() {
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::169.254.0.1",
            "64:ff9b::127.0.0.1",
        ] {
            let p: IpAddr = ip.parse().unwrap();
            assert!(is_hard_denied(p), "{ip} must be hard-denied");
            assert!(!is_lan(p), "{ip} is not LAN");
        }
        for ip in [
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "fc00::1",
            "fd12::3",
            "::ffff:10.0.0.5",
            "::192.168.0.1",
            "64:ff9b::10.0.0.1",
        ] {
            let p: IpAddr = ip.parse().unwrap();
            assert!(is_lan(p), "{ip} must be LAN");
            assert!(!is_hard_denied(p), "{ip} is LAN, not hard-denied");
        }
        for ip in ["1.2.3.4", "2606:4700:4700::1111", "::ffff:1.2.3.4"] {
            let p: IpAddr = ip.parse().unwrap();
            assert!(!is_hard_denied(p), "{ip} is public");
            assert!(!is_lan(p), "{ip} is public");
        }
    }

    /// A guest that stops reading responses mid-stream must not deadlock
    /// the handler: pending queries get consumed and the loop tears down.
    ///
    /// Honest scope: an in-process socketpair cannot deterministically
    /// force the server's response write to fail while an observer stays
    /// alive, so this test CANNOT distinguish `break`+drain from
    /// `return`+drop in dns_loop's write-failure arm — it guards the
    /// no-hang property only. The drain-on-write-failure contract itself
    /// is load-bearing-tested at the splice level
    /// (`portfwd::copy_drains_source_after_write_failure` and
    /// `server::splice_drains_guest_leg_when_client_dies`), which dns_loop
    /// mirrors.
    #[test]
    fn dns_loop_no_deadlock_when_client_stops_reading() {
        let (mut c, server) = UdsStream::pair().unwrap();
        let h = std::thread::spawn(move || {
            let mut s = server;
            let open: StreamOpen = read_frame(&mut s).unwrap();
            assert!(matches!(open, StreamOpen::Dns));
            let audit = AuditSink::new(crate::paths::Paths::with_root(
                std::env::temp_dir().join("izba-router-dnsloop-test"),
            ));
            dns_loop(
                s,
                &AllowAll,
                &FakeResolver,
                "web",
                &audit,
                &SnoopStore::new(),
                false,
            );
        });
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        // Happy-path: one round-trip confirms the loop is running.
        dns::write_dns_msg(&mut c, b"q0").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"ans:q0");
        // Send more queries but stop reading responses; the server must not
        // deadlock — it must consume our TX and tear down.
        dns::write_dns_msg(&mut c, b"q1").unwrap();
        dns::write_dns_msg(&mut c, b"q2").unwrap();
        c.shutdown(std::net::Shutdown::Write).unwrap();
        // Drop the read half so unread response data in the kernel buffer
        // does not prevent the peer's shutdown from completing.
        drop(c);
        h.join()
            .expect("dns_loop must not hang after write failure");
    }

    /// Build a minimal A-record DNS query for `name` with a fixed ID.
    fn dns_query(name: &str) -> Vec<u8> {
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;
        let mut m = Message::query();
        m.metadata.id = 0x1234;
        m.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        m.to_vec().unwrap()
    }

    /// Enforcing + unlisted QNAME → NXDOMAIN, and the query is NOT forwarded
    /// (a forwarded FakeResolver reply would be `ans:...`, not a valid NXDOMAIN
    /// derived from our query ID).
    #[test]
    fn enforcing_denies_unlisted_qname_with_nxdomain() {
        let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        let q = dns_query("evil.example.com.");
        dns::write_dns_msg(&mut c, &q).unwrap();
        let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
        assert_eq!(
            &resp[..2],
            &q[..2],
            "our query ID preserved (not a resolver echo)"
        );
        assert_eq!(resp[3] & 0x0f, 0x03, "RCODE=NXDOMAIN");
    }

    /// Enforcing + allow-listed QNAME → forwarded (FakeResolver echoes `ans:`).
    #[test]
    fn enforcing_allows_listed_qname_and_forwards() {
        let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        let q = dns_query("api.anthropic.com.");
        dns::write_dns_msg(&mut c, &q).unwrap();
        let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
        assert_eq!(&resp[..4], b"ans:", "listed name forwarded to the resolver");
    }

    /// Non-enforcing (bare) sandbox → unchanged pass-through for ANY name.
    #[test]
    fn non_enforcing_forwards_any_qname() {
        let mut c = spawn_handler(Arc::new(AllowAll), &FakeResolver);
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        let q = dns_query("evil.example.com.");
        dns::write_dns_msg(&mut c, &q).unwrap();
        let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
        assert_eq!(&resp[..4], b"ans:", "bare sandbox forwards unchanged");
    }

    /// DnsTcp gets identical enforcement to UDP Dns.
    #[test]
    fn enforcing_denies_unlisted_over_dnstcp() {
        let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
        write_frame(&mut c, &StreamOpen::DnsTcp).unwrap();
        let q = dns_query("evil.example.com.");
        dns::write_dns_msg(&mut c, &q).unwrap();
        let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
        assert_eq!(resp[3] & 0x0f, 0x03, "DnsTcp denial is NXDOMAIN too");
    }

    /// TcpConnect:53 (the guest dialing an upstream resolver) gets identical
    /// enforcement after the Ok handshake.
    #[test]
    fn enforcing_denies_unlisted_over_tcpconnect53() {
        let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "8.8.8.8".into(),
                port: 53,
            },
        )
        .unwrap();
        assert!(matches!(
            read_frame::<_, Response>(&mut c).unwrap(),
            Response::Ok
        ));
        let q = dns_query("evil.example.com.");
        dns::write_dns_msg(&mut c, &q).unwrap();
        let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
        assert_eq!(resp[3] & 0x0f, 0x03, "TcpConnect:53 denial is NXDOMAIN too");
    }

    /// Enforcing + unparseable query → SERVFAIL (fail-closed), not forwarded.
    #[test]
    fn enforcing_servfails_unparseable_query() {
        let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        // Not a DNS message; >=4 bytes so servfail() can still write RCODE bits.
        dns::write_dns_msg(&mut c, &[0xff, 0x00, 0x01, 0x02]).unwrap();
        let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
        assert_eq!(
            resp[3] & 0x0f,
            0x02,
            "unparseable under enforce -> SERVFAIL"
        );
    }

    /// Enforcing + a multi-question query whose FIRST question is allow-listed is
    /// STILL denied (fail-closed, not forwarded): `qname_of` yields no single
    /// QNAME for QDCOUNT != 1, closing the second-question smuggling channel. The
    /// deny is a SERVFAIL derived from our query (ID preserved), not a resolver
    /// echo (`ans:...`) — proving the packet never reached the resolver.
    #[test]
    fn enforcing_denies_multi_question_even_with_allowed_first() {
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;
        let mut m = Message::query();
        m.metadata.id = 0x5678;
        m.add_query(Query::query(
            Name::from_str("api.anthropic.com.").unwrap(), // allow-listed first
            RecordType::A,
        ));
        m.add_query(Query::query(
            Name::from_str("exfil.evil.example.com.").unwrap(), // smuggled second
            RecordType::TXT,
        ));
        let q = m.to_vec().unwrap();

        let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        dns::write_dns_msg(&mut c, &q).unwrap();
        let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
        assert_eq!(
            &resp[..2],
            &q[..2],
            "our query ID preserved (not a resolver echo)"
        );
        assert_eq!(
            resp[3] & 0x0f,
            0x02,
            "multi-question under enforce -> SERVFAIL, not forwarded"
        );
    }

    #[test]
    fn mitm_path_denies_hard_floor_origdst_before_mitm() {
        // An enforcing :443 flow to a loopback OrigDst is hard-floor-denied at the
        // top of tcp_connect, before ever reaching the MITM hop.
        let mut c = spawn_handler(Arc::new(RegoPolicy::embedded().unwrap()), &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "127.0.0.1".into(),
                port: 443,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, message } => {
                assert_eq!(kind, ErrorKind::ConnectFailed);
                assert!(
                    message.contains("blocked address"),
                    "want hard-floor deny, got: {message}"
                );
            }
            other => panic!("expected hard-floor deny, got {other:?}"),
        }
    }

    #[test]
    fn tcp_connect_loopback_is_hard_denied_even_for_bare() {
        // Loopback is the non-overridable SSRF floor — denied even for a bare
        // (AllowAll) sandbox.
        let mut c = spawn_handler(Arc::new(AllowAll), &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "127.0.0.1".into(),
                port: 9,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, message } => {
                assert_eq!(kind, ErrorKind::ConnectFailed);
                assert!(message.contains("blocked address"), "{message}");
            }
            other => panic!("expected hard-floor deny, got {other:?}"),
        }
    }

    // --- proptest property-based tests for the SSRF hard-floor classifier ---

    use proptest::prelude::*;
    use std::net::Ipv6Addr;

    // Property 1: embedded-v4 canonicalization consistency (the SSRF-bypass property).
    // For an arbitrary IPv4 address, construct its three bypass-prone IPv6 embeddings
    // and assert each classifies identically to the bare IPv4. If `embedded_v4` dropped
    // a branch (e.g. forgot NAT64), the embedded form would mis-classify as a benign
    // global address while the bare IPv4 is denied.
    //
    // The IPv4-compatible form (::a.b.c.d) deliberately excludes 0.0.0.0 and 0.0.0.1
    // because the impl skips those to keep :: and ::1 as pure-v6 specials.
    proptest! {
        #[test]
        fn embedded_v4_canonicalization_consistency(octets in any::<[u8; 4]>()) {
            let v4 = std::net::Ipv4Addr::from(octets);
            let v4_ip = IpAddr::V4(v4);

            let [o0, o1, o2, o3] = octets;
            let hi = ((o0 as u16) << 8) | o1 as u16;
            let lo = ((o2 as u16) << 8) | o3 as u16;

            // Form 1: IPv4-mapped ::ffff:a.b.c.d (via to_ipv6_mapped).
            let mapped = v4.to_ipv6_mapped();
            let mapped_ip = IpAddr::V6(mapped);
            prop_assert_eq!(
                is_hard_denied(mapped_ip),
                is_hard_denied(v4_ip),
                "mapped form hard_denied mismatch for {}",
                v4
            );
            prop_assert_eq!(
                is_lan(mapped_ip),
                is_lan(v4_ip),
                "mapped form lan mismatch for {}",
                v4
            );

            // Form 2: NAT64 64:ff9b::a.b.c.d (RFC 6052 well-known prefix).
            let nat64 = Ipv6Addr::from([0x0064, 0xff9b, 0, 0, 0, 0, hi, lo]);
            let nat64_ip = IpAddr::V6(nat64);
            prop_assert_eq!(
                is_hard_denied(nat64_ip),
                is_hard_denied(v4_ip),
                "NAT64 form hard_denied mismatch for {}",
                v4
            );
            prop_assert_eq!(
                is_lan(nat64_ip),
                is_lan(v4_ip),
                "NAT64 form lan mismatch for {}",
                v4
            );

            // Form 3: IPv4-compatible ::a.b.c.d — excluding 0.0.0.0 and 0.0.0.1
            // (the impl intentionally skips those so :: and ::1 stay pure-v6).
            prop_assume!(v4 != std::net::Ipv4Addr::new(0, 0, 0, 0));
            prop_assume!(v4 != std::net::Ipv4Addr::new(0, 0, 0, 1));
            let compat = Ipv6Addr::from([0u16, 0, 0, 0, 0, 0, hi, lo]);
            let compat_ip = IpAddr::V6(compat);
            prop_assert_eq!(
                is_hard_denied(compat_ip),
                is_hard_denied(v4_ip),
                "IPv4-compat form hard_denied mismatch for {}",
                v4
            );
            prop_assert_eq!(
                is_lan(compat_ip),
                is_lan(v4_ip),
                "IPv4-compat form lan mismatch for {}",
                v4
            );
        }
    }

    // Property 2: totality / no-panic.
    // `is_hard_denied` and `is_lan` must not panic on any arbitrary IpAddr.
    // The `let _ = ...` sinks prevent the calls from being dead-code optimized away.
    proptest! {
        #[test]
        fn classifier_totality_no_panic_v4(raw in any::<u32>()) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(raw));
            let _ = is_hard_denied(ip) | is_lan(ip);
        }

        #[test]
        fn classifier_totality_no_panic_v6(raw in any::<u128>()) {
            let ip = IpAddr::V6(Ipv6Addr::from(raw));
            let _ = is_hard_denied(ip) | is_lan(ip);
        }
    }

    // Property 3: disjointness (F-01 split).
    // `is_hard_denied` and `is_lan` are disjoint — no address can be both.
    // Hard-floor ranges (loopback / link-local / unspecified / broadcast / documentation)
    // and LAN ranges (RFC1918 / unique-local) must not overlap. A future edit that
    // accidentally moved RFC1918 into the hard floor would fire this property.
    proptest! {
        #[test]
        fn hard_denied_and_lan_are_disjoint_v4(raw in any::<u32>()) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(raw));
            prop_assert!(
                !(is_hard_denied(ip) && is_lan(ip)),
                "address {} is both hard_denied and lan",
                ip
            );
        }

        #[test]
        fn hard_denied_and_lan_are_disjoint_v6(raw in any::<u128>()) {
            let ip = IpAddr::V6(Ipv6Addr::from(raw));
            prop_assert!(
                !(is_hard_denied(ip) && is_lan(ip)),
                "address {} is both hard_denied and lan",
                ip
            );
        }
    }

    // --- Task 3: the inspectability-driven tier-1 gate + passthrough candidates. ---

    fn inspect_policy(yaml: &str) -> Arc<dyn Policy> {
        crate::daemon::egress::config::EgressPolicyConfig::from_yaml(yaml)
            .expect("parses")
            .into_policy("web")
            .expect("compiles")
    }

    // The guard test for the global constraint: a policy that declares no
    // protocol anywhere gates exactly where it gates today.
    #[test]
    fn a_policy_without_protocol_gates_on_the_web_ports_only() {
        let p = inspect_policy("enforce: true\nallow:\n  - github.com\n");
        for port in [80u16, 443] {
            assert!(p.inspects(port), "port {port} must still be tier-1");
        }
        for port in [22u16, 8000, 5432, 15001] {
            assert!(!p.inspects(port), "port {port} must still be tier-2");
        }
    }

    #[test]
    fn a_declared_http_port_is_gated_into_tier_one() {
        let p = inspect_policy(
            "enforce: true\nallow:\n  - host: internal.example.com\n    ports: [8000]\n    protocol: http\n",
        );
        assert!(p.enforces() && p.inspects(8000));
    }

    // DP-2: the hatch is bound to the address by DNS-snoop, not by the SNI.
    #[test]
    fn passthrough_candidates_require_a_snoop_binding() {
        let p = inspect_policy(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        let snoop = SnoopStore::new();
        // NOTE: not 203.0.113.0/24 (RFC 5737 TEST-NET-3) — this codebase's
        // `is_hard_denied` treats that whole range as "documentation" and
        // blocks it unconditionally (F-01), which would make this test pass
        // vacuously (deny-by-hard-floor, not deny-by-no-snoop-binding). Use an
        // ordinary public address instead, consistent with the rest of this
        // file's decide_tier2 tests (e.g. "1.2.3.4").
        let ip: IpAddr = "1.2.3.9".parse().unwrap();
        assert!(
            passthrough_names(&*p, &snoop, "web", ip, 443, UsbGuard::default()).is_empty(),
            "no snoop record ⇒ no passthrough, so a raw-IP dial can never splice"
        );
        snoop.record("web", &[("pinned.vendor.com".to_string(), ip, 300)]);
        assert_eq!(
            passthrough_names(&*p, &snoop, "web", ip, 443, UsbGuard::default()),
            vec!["pinned.vendor.com".to_string()]
        );
    }

    #[test]
    fn passthrough_candidates_exclude_a_host_without_the_declaration() {
        let p = inspect_policy("enforce: true\nallow:\n  - api.anthropic.com\n");
        let snoop = SnoopStore::new();
        let ip: IpAddr = "1.2.3.10".parse().unwrap(); // see the TEST-NET-3 note above
        snoop.record("web", &[("api.anthropic.com".to_string(), ip, 300)]);
        assert!(
            passthrough_names(&*p, &snoop, "web", ip, 443, UsbGuard::default()).is_empty(),
            "an ordinary allowed host must still be inspected"
        );
    }

    // The hatch inherits tier-2's DNS-rebinding guard for free.
    #[test]
    fn passthrough_candidates_are_empty_for_a_lan_address() {
        let p = inspect_policy(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        let snoop = SnoopStore::new();
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        snoop.record("web", &[("pinned.vendor.com".to_string(), ip, 300)]);
        assert!(
            passthrough_names(&*p, &snoop, "web", ip, 443, UsbGuard::default()).is_empty(),
            "a name must never authorize a LAN target (rebinding)"
        );
    }

    #[test]
    fn a_non_enforcing_policy_has_no_passthrough_candidates() {
        let snoop = SnoopStore::new();
        let ip: IpAddr = "1.2.3.11".parse().unwrap(); // see the TEST-NET-3 note above
        snoop.record("web", &[("pinned.vendor.com".to_string(), ip, 300)]);
        assert!(
            passthrough_names(&AllowAll, &snoop, "web", ip, 443, UsbGuard::default()).is_empty(),
            "a bare sandbox is never MITM'd, so it has nothing to pass through"
        );
    }

    // M5 P1 review, task 3, finding 1 (fix round 1), part 2: `has_passthrough`
    // / `InspectionTable::from_config` fixed the LAST-WINS divergence, but the
    // per-name `policy.check` filter in `passthrough_names` is load-bearing
    // for a SECOND, independent reason: `InspectionTable::from_config` only
    // reads `e.declared_protocol()` — it never consults `e.access()` at all.
    // `RegoPolicy::check`, by contrast, evaluates the real `egress.rego`
    // `host_access_ok` predicate, which for `access: read` REQUIRES the
    // request to carry an HTTP GET/HEAD method (`read_method`) — and a
    // tier-2/passthrough `FlowDesc` (`FlowDesc::l3`) never carries one
    // (`method: None`). So a `protocol: tcp` declaration paired with
    // `access: read` makes `passthrough_host` answer `true` (it never looks
    // at `access`) for a (host, port) that `policy.check` ALWAYS denies (no
    // method ⇒ `read_method` fails ⇒ `host_access_ok("read")` fails). Without
    // the filter, `passthrough_names` would splice a read-only-declared host
    // straight through with no upstream certificate verification at all.
    #[test]
    fn passthrough_candidates_exclude_a_read_only_declared_host() {
        // A SECOND, unrelated raw-IP rule is required so `decide_tier2` can
        // still ALLOW the flow (via the explicit-IP rule) even though the
        // name-based check on `pinned.vendor.com` denies (read + no method) —
        // otherwise `decide_tier2` itself would deny first and this could
        // never reach the per-name filter the test means to exercise.
        let p = inspect_policy(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    \
             protocol: tcp\n    access: read\n  - host: 1.2.3.12\n    ports: [443]\n",
        );
        // `InspectionTable` alone (ignorant of `access`) says this hatch is open.
        assert!(
            p.passthrough_host("pinned.vendor.com", 443),
            "setup: the table itself does not consult access"
        );
        let snoop = SnoopStore::new();
        let ip: IpAddr = "1.2.3.12".parse().unwrap();
        snoop.record("web", &[("pinned.vendor.com".to_string(), ip, 300)]);
        assert!(
            passthrough_names(&*p, &snoop, "web", ip, 443, UsbGuard::default()).is_empty(),
            "a read-only-declared host must never open the no-cert-verification hatch \
             for a methodless (tier-2) flow — the policy.check filter must catch this"
        );
    }

    // M5 P1 review, task 3, finding 3: the empty-candidate-list path must be
    // free even when NO snoop record exists at all — `has_passthrough()`
    // short-circuits `passthrough_names` before it ever calls `decide_tier2`.
    #[test]
    fn passthrough_candidates_are_empty_without_any_tcp_declaration_or_snoop_record() {
        let p = inspect_policy("enforce: true\nallow:\n  - github.com\n");
        assert!(!p.has_passthrough());
        let snoop = SnoopStore::new(); // deliberately empty — no record at all
        let ip: IpAddr = "1.2.3.13".parse().unwrap();
        assert!(
            passthrough_names(&*p, &snoop, "web", ip, 443, UsbGuard::default()).is_empty(),
            "no protocol: tcp anywhere in the policy ⇒ empty, without ever needing a \
             snoop binding to decide that"
        );
    }

    // End-to-end through the real `handle_conn`. `spawn_handler` passes
    // `mitm: None`, so an INSPECTED port answers with the fail-closed
    // "firewall unavailable" error while a spliced port takes tier-2 — which
    // makes the gate's branch directly observable without a MITM runtime.
    #[test]
    fn the_router_gate_follows_the_declaration_end_to_end() {
        let p = inspect_policy(
            "enforce: true\nallow:\n  - host: internal.example.com\n    ports: [8000]\n    protocol: http\n",
        );
        let mut c = spawn_handler(p, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "1.2.3.20".into(), // see the TEST-NET-3 note above
                port: 8000,
            },
        )
        .unwrap();
        let resp: Response = read_frame(&mut c).unwrap();
        match resp {
            Response::Error { message, .. } => assert!(
                message.contains("HTTP(S) firewall unavailable"),
                ":8000 was declared http, so it must take the tier-1 branch: {message}"
            ),
            other => panic!("expected the fail-closed tier-1 error, got {other:?}"),
        }
    }

    #[test]
    fn an_undeclared_port_still_takes_tier_two() {
        let p = inspect_policy(
            "enforce: true\nallow:\n  - host: internal.example.com\n    ports: [8000]\n    protocol: http\n",
        );
        let mut c = spawn_handler(p, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "1.2.3.21".into(), // see the TEST-NET-3 note above
                port: 5432,
            },
        )
        .unwrap();
        let resp: Response = read_frame(&mut c).unwrap();
        match resp {
            Response::Error { message, .. } => assert!(
                message.contains("denied by policy"),
                "5432 was never declared, so it stays tier-2: {message}"
            ),
            other => panic!("expected a tier-2 policy denial, got {other:?}"),
        }
    }
}
