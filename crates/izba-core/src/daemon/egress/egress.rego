# M2 egress policy — adapted from Lupus/docker-mitm-bridge's
# `opa-policies/policy.rego` (package mitmproxy.policy).
#
# LINEAGE: the upstream policy is an HTTP L7 allow-list keyed on
# `input.request.host` against two data tiers — `data.unrestricted_domains`
# (all methods) and `data.allowed_domains` (GET/HEAD only) — plus GitHub
# write-auth logic. izba's M2 FlowDesc carries only {sandbox, addr, port}: no
# HTTP method/path yet (that lands in M5 when the MITM proxy terminates TLS).
# So this spike collapses the two HTTP tiers into a single default-deny DOMAIN
# allow-list and adds the per-sandbox dimension that is M2's actual shape. The
# tier/data-document structure is preserved verbatim so the method/path L7
# rules can grow back in without a rewrite (see the commented-out `allow if`
# block at the bottom — that is upstream, ready to re-enable).

package egress

import rego.v1

# Default-deny: nothing leaves unless a rule below says so.
default allow := false

# The destination to match: the decrypted Host/SNI (tier-1, MITM) when present,
# else the addr the guest dialed (tier-2 / pre-MITM — an IP, or a DNS-snoop'd
# FQDN). A guest cannot smuggle past by faking the dialed IP: when MITM gives us
# the real host, that is what the allow-list judges.
dest_name := input.host

dest_name := input.dest if not input.host

# Global allow-list: a destination any sandbox may reach. This is the union of
# upstream's `allowed_domains` + `unrestricted_domains` tiers — once we enforce
# the HTTP method we re-split them (see bottom of file).
allow if {
	dest_name in data.global_domains
}

# Per-sandbox allow-list: a destination only THIS sandbox may reach. This is the
# M2 trust-domain dimension docker-mitm-bridge lacks — different sandboxes get
# different reachability from the same daemon.
allow if {
	some dest in data.sandbox_domains[input.sandbox]
	dest_name == dest
}

# Decision object mirrors upstream's `decision := {"allow", "reason"}` so the
# audit log + future denial UX have a human-readable cause from day one.
reason := "allowed: global domain" if {
	dest_name in data.global_domains
}

reason := "allowed: per-sandbox domain" if {
	not dest_name in data.global_domains
	some dest in data.sandbox_domains[input.sandbox]
	dest_name == dest
}

default reason := "denied: destination not in any allow-list"

decision := {
	"allow": allow,
	"reason": reason,
}

# ---------------------------------------------------------------------------
# M5 horizon (NOT active — FlowDesc has no method/path yet). When the MITM
# proxy lands, `input.request` regains {host, method, path, query} and these
# upstream rules re-enable the restricted vs. unrestricted split verbatim:
#
#     allow if {
#         input.request.host in data.unrestricted_domains
#     }
#     allow if {
#         input.request.host in data.allowed_domains
#         input.request.method in ["GET", "HEAD"]
#     }
#
# plus the GitHub git-upload-pack / git-receive-pack write-auth logic.
# ---------------------------------------------------------------------------
