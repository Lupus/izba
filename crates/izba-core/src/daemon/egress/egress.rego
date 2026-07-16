# izba egress policy — vendor-neutral.
#
# HTTP host rules carry an `access` verb (read = GET/HEAD; read-write = all
# methods). Git rules key on the smart-HTTP wire protocol (info/refs?service +
# the upload-pack/receive-pack data legs) so read/write control works for ANY
# git host, not just github.com. Per-sandbox scoped (one engine per sandbox).

package egress
import rego.v1

default allow := false

# Destination for HTTP host matching: decrypted Host (tier-1) else dialed addr.
dest_name := input.host
dest_name := input.dest if not input.host

read_method if input.method in ["GET", "HEAD"]

host_access_ok(access) if access == "read-write"
host_access_ok(access) if {
    access == "read"
    read_method
}

# --- HTTP host allow-list (access-aware) ---
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

# --- Wildcard HTTP host allow-list ---
# `glob.match` with `.` as the delimiter gives Cilium toFQDNs semantics:
# `*` = exactly one label, `**` = any depth (>= 1); the apex itself never
# matches — the literal `.` after the wildcard has nothing to consume.
allow if {
    some rule in data.wildcard_host_rules
    glob.match(rule.pattern, ["."], dest_name)
    input.port in rule.ports
    host_access_ok(rule.access)
}
allow if {
    some rule in data.sandbox_wildcard_host_rules[input.sandbox]
    glob.match(rule.pattern, ["."], dest_name)
    input.port in rule.ports
    host_access_ok(rule.access)
}

# --- Vendor-neutral git rules ---
service_kind("git-upload-pack") := "read"
service_kind("git-receive-pack") := "write"

# Discovery leg: GET <repo>/info/refs?service=<svc>
git_request := {"service": input.query.service, "repo_path": rp} if {
    input.method == "GET"
    endswith(input.path, "/info/refs")
    rp := trim_suffix(input.path, "/info/refs")
}
# Data leg: POST <repo>/git-upload-pack | <repo>/git-receive-pack
git_request := {"service": svc, "repo_path": rp} if {
    input.method == "POST"
    some svc in ["git-upload-pack", "git-receive-pack"]
    suffix := sprintf("/%s", [svc])
    endswith(input.path, suffix)
    rp := trim_suffix(input.path, suffix)
}

# Canonical repo id: "<host>/<owner>/<repo>", trimming ".git" and slashes.
git_repo_id := id if {
    bare := trim_suffix(trim(git_request.repo_path, "/"), ".git")
    id := sprintf("%s/%s", [input.host, bare])
}

git_rule_matches(rule) if {
    rule.repo
    glob.match(rule.repo, ["/"], git_repo_id)
}
git_rule_matches(rule) if {
    rule.host
    rule.host == input.host
}

git_kind := service_kind(git_request.service)

allow if {
    some rule in data.sandbox_git_rules[input.sandbox]
    git_rule_matches(rule)
    git_kind == "read"
    rule.access in {"read", "read-write"}
}
allow if {
    some rule in data.sandbox_git_rules[input.sandbox]
    git_rule_matches(rule)
    git_kind == "write"
    rule.access == "read-write"
}
