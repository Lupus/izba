# Bare-Host Web Ports [80, 443] Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A bare host target means web ports [80, 443] on every editing surface (CLI `policy allow|block`, GUI PolicyEditor Add host), matching the existing `policy.yaml` bare-host semantic, and the docs say so.

**Architecture:** `parse_target` returns a port *list* (bare → `AllowEntry::DEFAULT_PORTS`, `HOST:PORT` → that one port); `apply_edit` loops the existing per-port `EgressPolicyConfig::allow/block` mutators. GUI seeds new rows from `WEB_DEFAULT_PORTS`. No policy-evaluation, wire, or IPC change.

**Tech Stack:** Rust (clap CLI, izba-core), React/TypeScript (vitest).

**Spec:** `docs/superpowers/specs/2026-07-20-bare-host-web-ports-design.md`

## Global Constraints

- Bare `HOST` ⇒ ports `[80, 443]` exactly (`AllowEntry::DEFAULT_PORTS` — never a second hardcoded list); `HOST:PORT` ⇒ `vec![port]`, unchanged single-port meaning.
- Bare `block HOST` removes 80 and 443 only; other explicitly-added ports survive; entry drops when its last port goes (existing `block` mutator behavior — do not modify `config.rs`).
- No changes to `crates/izba-core` (the mutators and `DEFAULT_PORTS` already exist), no wire/proto changes, no `DAEMON_PROTO_VERSION` bump, no app IPC/type changes.
- Help/doc wording rule everywhere: "a bare HOST means the web ports 80 + 443; HOST:PORT means exactly that port."
- Conventional commits; each commit ends with the trailer line `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- TDD: write/adjust the failing test first, watch it fail, implement, watch it pass.

---

### Task 1: CLI `parse_target` + `apply_edit` port-list semantics

**Files:**
- Modify: `crates/izba-cli/src/commands/policy.rs` (all changes in this one file: clap doc-comments ~lines 14–31, `parse_target` ~150–161, `apply_edit` ~174–190, the Allow/Block match arms that call them, and the `tests` module)

**Interfaces:**
- Produces: `parse_target(&str) -> anyhow::Result<(String, Vec<u16>)>`; `apply_edit(&Path, Edit, &str, &[u16]) -> anyhow::Result<()>`. (Both `pub(crate)`, no callers outside this file — verified by grep.)

- [ ] **Step 1: Update the unit tests first (TDD)**

In the `tests` module of `policy.rs`, replace `parse_target_defaults_to_443` and add the explicit-port case:

```rust
#[test]
fn parse_target_bare_host_means_web_ports() {
    // a bare host must mean the same thing it means in policy.yaml
    assert_eq!(
        parse_target("api.x.com").unwrap(),
        ("api.x.com".to_string(), vec![80, 443])
    );
}

#[test]
fn parse_target_explicit_port_is_exactly_that_port() {
    assert_eq!(
        parse_target("api.x.com:8080").unwrap(),
        ("api.x.com".to_string(), vec![8080])
    );
}
```

Update the existing `apply_edit` round-trip test (the one asserting `ports: Some(vec![443])` after `apply_edit(dir.path(), Edit::Allow, "api.x.com", 443)`) to the new signature and semantics, and add block-symmetry cases:

```rust
#[test]
fn bare_allow_and_block_are_symmetric_web_ports() {
    let dir = tempfile::tempdir().unwrap();
    apply_edit(dir.path(), Edit::Allow, "api.x.com", &[80, 443]).unwrap();
    let cfg = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
    assert_eq!(
        cfg.allow[0],
        AllowEntry::Scoped {
            host: "api.x.com".to_string(),
            ports: Some(vec![80, 443]),
            access: Access::ReadWrite,
        }
    );
    apply_edit(dir.path(), Edit::Block, "api.x.com", &[80, 443]).unwrap();
    let cfg = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
    assert!(cfg.allow.is_empty());
}

#[test]
fn bare_block_leaves_explicitly_added_ports() {
    let dir = tempfile::tempdir().unwrap();
    apply_edit(dir.path(), Edit::Allow, "api.x.com", &[80, 443]).unwrap();
    apply_edit(dir.path(), Edit::Allow, "api.x.com", &[8443]).unwrap();
    apply_edit(dir.path(), Edit::Block, "api.x.com", &[80, 443]).unwrap();
    let cfg = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
    assert_eq!(cfg.allow[0].ports(), vec![8443]);
}
```

Update the two wildcard tests that call `apply_edit(…, "*.example.com", 443)` / `apply_edit(…, "foo.*.com", 443)` to pass `&[443]`; leave their assertions otherwise intact. Keep the existing invalid-port `parse_target` error test unchanged.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-cli policy` — expect compile errors (signature mismatch), which is the TDD failure signal here.

- [ ] **Step 3: Implement**

```rust
/// Parse a `HOST` or `HOST:PORT` target. A bare `HOST` means the web ports
/// (80 + 443, `AllowEntry::DEFAULT_PORTS`) — the same meaning a bare host
/// has in `policy.yaml`; `HOST:PORT` means exactly that one port.
pub(crate) fn parse_target(s: &str) -> anyhow::Result<(String, Vec<u16>)> {
    match s.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .with_context(|| format!("invalid port in '{s}'"))?;
            Ok((host.to_string(), vec![port]))
        }
        None => Ok((s.to_string(), AllowEntry::DEFAULT_PORTS.to_vec())),
    }
}
```

```rust
/// The daemon-free core of allow/block: persist the edit to `policy.yaml`.
pub(crate) fn apply_edit(
    sandbox_dir: &std::path::Path,
    edit: Edit,
    host: &str,
    ports: &[u16],
) -> anyhow::Result<()> {
    edit_policy_file(sandbox_dir, |cfg| {
        for &port in ports {
            match edit {
                Edit::Allow => {
                    cfg.allow(host, port);
                }
                Edit::Block => {
                    let _ = cfg.block(host, port);
                }
            }
        }
    })?;
    Ok(())
}
```

Adjust the Allow/Block command arms to the new types (pass `&ports`). Import `AllowEntry` at the top of the file the same way the tests module already does (it is `izba_core`'s egress config type). Update the four clap doc-comments that say "(port defaults to 443)":

- Allow verb doc: `/// Add HOST to the sandbox's HTTP(S) allow-list. A bare HOST opens the web ports (80 + 443); HOST:PORT opens exactly that port; access is read-write. …` (keep the existing trailing sentences).
- Allow arg doc: `/// Destination to allow: HOST, *.HOST, **.HOST, or HOST:PORT (bare host = web ports 80+443; :PORT = exactly that port)`
- Block verb doc: `/// Remove HOST from the allow-list. A bare HOST removes the web ports (80 + 443); HOST:PORT removes exactly that port; auto-reloads.`
- Block arg doc: `/// Destination to remove: HOST, *.HOST, **.HOST, or HOST:PORT (bare host = web ports 80+443; :PORT = exactly that port)`

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-cli policy` — expect all pass. Then `cargo clippy -p izba-cli --all-targets -- -D warnings` and `cargo fmt` — clean.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-cli/src/commands/policy.rs
git commit -m "feat(cli): bare policy target opens web ports 80+443 like policy.yaml"
```

---

### Task 2: GUI PolicyEditor "Add host" seeds web ports

**Files:**
- Modify: `app/src/components/PolicyEditor.tsx` (the `addHost` handler, ~line 221: `ports: [443]`)
- Test: `app/src/test/policyEditor.test.tsx`

**Interfaces:**
- Consumes: `WEB_DEFAULT_PORTS` from `app/src/lib/ports.ts` (already imported in PolicyEditor.tsx).

- [ ] **Step 1: Write the failing vitest first**

Add to `policyEditor.test.tsx` (mirror the file's existing render/fixture helpers — reuse its render setup verbatim rather than inventing a new one):

```tsx
it("Add host seeds the web default ports 80 and 443", async () => {
  // …existing render + open-editor boilerplate from neighboring tests…
  await user.click(screen.getByRole("button", { name: /add host/i }));
  const chips = screen.getAllByText(/^(80|443)$/);
  expect(chips.map((c) => c.textContent)).toEqual(
    expect.arrayContaining(["80", "443"])
  );
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd app && npx vitest run src/test/policyEditor.test.tsx`
Expected: the new test FAILS (only a `443` chip renders).

- [ ] **Step 3: Implement**

In the add-host handler, replace `ports: [443]` with `ports: [...WEB_DEFAULT_PORTS]`:

```tsx
editHosts((rs) => [...rs, { host: "", ports: [...WEB_DEFAULT_PORTS], access: "read-write" }]);
```

- [ ] **Step 4: Run the test file to verify all pass**

Run: `cd app && npx vitest run src/test/policyEditor.test.tsx`
Expected: PASS (all cases, including existing save-path tests — if one pinned `[443]` for a new row, update it to `[80, 443]`).

- [ ] **Step 5: Commit**

```bash
git add app/src/components/PolicyEditor.tsx app/src/test/policyEditor.test.tsx
git commit -m "feat(app): Add host seeds web default ports 80+443"
```

---

### Task 3: README — one bare-host rule, everywhere it speaks

**Files:**
- Modify: `README.md` (command table ~lines 211–212; "Working under enforce" paragraph ~lines 134–139)

- [ ] **Step 1: Update the command table**

```
izba policy  allow NAME HOST[:PORT]       # allow a destination (bare host = web ports 80+443); live-reloads
izba policy  block NAME HOST[:PORT]       # remove a destination (bare host = web ports 80+443); live-reloads
```

- [ ] **Step 2: Rewrite the enforce walk-through paragraph**

Replace the `:80`-spelling apt guidance (it documented the old 443-only CLI default) with:

```
  first (e.g. `izba policy allow NAME archive.ubuntu.com` and
  `izba policy allow NAME security.ubuntu.com` for apt on Ubuntu, plus
  whatever package index or registry you use), or pre-seed them in
  `policy.yaml`. A bare host opens the web ports 80 + 443 — the same meaning
  it has in `policy.yaml` — while `HOST:PORT` opens exactly that one port.
  `izba netlog NAME` lists exactly which endpoints were denied, so the log
  tells you what to allow next.
```

Keep surrounding lines byte-identical; verify with `git diff README.md` that only these two spots changed.

- [ ] **Step 3: Sanity-check consistency**

Run: `grep -n "defaults to 443\|defaults to port 443" README.md crates/izba-cli/src/commands/policy.rs` — expect NO hits anywhere after Tasks 1+3.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: bare policy targets mean web ports 80+443 everywhere"
```
