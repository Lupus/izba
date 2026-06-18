# Policy / Netlog UX redesign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make firewall enforcement, allow-list seeding, and traffic review three independent, non-destructive actions in the desktop app; give the Policy editor a sectioned single-Save always-editable shape; fix the netlog banner/label/button-state and layout papercuts.

**Architecture:** Frontend (React/TS) + a small app-backend (Tauri/Rust) seam change. Replace the destructive `policy_enable_from_traffic` (`*cfg = seed_from_summaries()` — wiped git rules, left `enforce:false`) with an **additive** `policy_add_endpoints(entries, enforce)` driven by a client-side **delta dialog**, plus a whole-editor-state `policy_set_full(allow, git)`. No rego / datapath change.

**Tech Stack:** Rust (izba-core, izba-cli, app/src-tauri Tauri 2), React + TypeScript + vitest, Tailwind.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-18-policy-netlog-ux-redesign-design.md` — every task implements part of it.
- **App is OUTSIDE the cargo workspace** (separate gate). App-backend changes run: `cd app/src-tauri && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`. Frontend runs: `cd app && npm test && npm run build`. The CLI/core change (Task 1) runs the workspace gates + `cargo check --target x86_64-pc-windows-gnu -p izba-core -p izba-cli`.
- **`cargo fmt` the app crate explicitly** — `cd app/src-tauri && cargo fmt` — the workspace-level fmt does NOT cover it (a prior PR red came from exactly this).
- **Toolchain:** `source .cargo-env` before cargo (worktree has it).
- **TDD:** test first, watch fail, minimal impl, watch pass, commit. Conventional commits.
- **Posture is a single bit:** the enforce toggle persists **immediately** (`policy_set_enforce`), never staged. Rules (host + git) are staged in the editor and persisted by one **Save** (`policy_set_full`); `enforce` is NOT part of `policy_set_full`.
- **Seeding is additive:** `policy_add_endpoints` and CLI `enable` MUST merge into the existing policy, never replace; an existing `git:` rule must survive (regression).
- **SSRF guard preserved:** raw-IP rows (no resolved host) are never allow-listable (disabled in the dialog and in netlog).
- **Netlog per-flow Allow/Block stays immediate** (observe-and-react surface); only the Policy editor is staged.

---

## File structure

| File | Responsibility | Tasks |
|------|----------------|-------|
| `crates/izba-core/src/daemon/egress/config.rs` | additive observed-merge helper for the CLI | 1 |
| `crates/izba-cli/src/commands/policy.rs` | `izba policy enable` → additive | 1 |
| `app/src-tauri/src/views.rs` | `SeedEntry` type | 2 |
| `app/src-tauri/src/daemon.rs` / `fake.rs` | `policy_add_endpoints`, `policy_set_full`; drop `policy_enable_from_traffic` | 2 |
| `app/src-tauri/src/commands.rs` / `lib.rs` | tauri commands + handler registration | 2 |
| `app/src/lib/git.ts` *(new)* | `git_repo_from_row`, `git_op_from_path`, `git_access_for`, `globMatch` | 3 |
| `app/src/lib/types.ts`, `app/src/lib/ipc.ts` | `SeedEntry`; `policyAddEndpoints`, `policySetFull`; drop `policyEnable` | 4 |
| `app/src/components/Section.tsx` *(new)* | collapsible section wrapper | 5 |
| `app/src/components/PolicyEditor.tsx` | sections, staged single-Save, always-editable, symmetric add | 6 |
| `app/src/components/SeedDialog.tsx` *(new)* | delta-review modal | 7 |
| `app/src/components/NetlogView.tsx` | honest banner, enforce toggle, Review-traffic trigger, git-row state + label | 8 |
| `app/src/components/Detail.tsx` + `PolicyEditor.tsx` root | layout/height fix | 9 |
| `app/src/test/*.test.tsx` | per-component tests | 3–9 |

Dependency order: 1 ⟂, 2 → (4 → {6,7,8}), 3 → {7,8}, 5 → 6, 7 → 8, 9 last.

---

## Task 1: CLI `policy enable` becomes additive (+ core merge helper)

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/config.rs`
- Modify: `crates/izba-cli/src/commands/policy.rs` (the `enable` fn)

**Interfaces:**
- Produces: `EgressPolicyConfig::add_observed_allowed(&mut self, summaries: &[EndpointSummary]) -> usize` — merges each summary whose latest verdict is Allow and that has a named host via `self.allow(host, port)`; returns the count of *newly added* host:port pairs. Does not touch `git` or `enforce`.

- [ ] **Step 1: Write failing test** (in `config.rs` tests, near `seed_from_summaries` tests)

```rust
#[test]
fn add_observed_allowed_is_additive_and_keeps_git() {
    use crate::daemon::egress::audit::{aggregate, AuditRecord, Tier};
    let mut allowed = AuditRecord::allow("web", "1.1.1.1".parse().unwrap(), 443, Some("api.x.com"), Tier::L7, "ok");
    allowed.ts_ms = 100;
    let mut denied = AuditRecord::deny("web", "2.2.2.2".parse().unwrap(), 22, Some("evil.com"), Tier::L3, "no");
    denied.ts_ms = 100;
    let summaries = aggregate(vec![allowed, denied]);

    let mut cfg = EgressPolicyConfig {
        enforce: true,
        allow: vec![AllowEntry::Host("existing.com".into())],
        git: vec![GitRule { target: GitTarget::Repo("github.com/o/a".into()), access: Access::Read }],
    };
    let added = cfg.add_observed_allowed(&summaries);
    assert_eq!(added, 1, "only the allowed named endpoint is added");
    assert!(cfg.allow.iter().any(|e| e.host() == "existing.com"), "existing host kept");
    assert!(cfg.allow.iter().any(|e| e.host() == "api.x.com"), "observed host added");
    assert!(!cfg.allow.iter().any(|e| e.host() == "evil.com"), "denied not added");
    assert_eq!(cfg.git.len(), 1, "git rules untouched");
    assert!(cfg.enforce, "enforce untouched");
}
```

- [ ] **Step 2: Run, verify fail**

Run: `source .cargo-env; cargo test -p izba-core daemon::egress::config::tests::add_observed_allowed_is_additive_and_keeps_git`
Expected: FAIL — `add_observed_allowed` undefined.

- [ ] **Step 3: Implement** (in `config.rs`, near `seed_from_summaries`)

```rust
impl EgressPolicyConfig {
    /// Additively merge the currently-allowed, named endpoints from `summaries`
    /// into this policy's host allow-list (raw-IP rows skipped — SSRF guard).
    /// Returns the number of host:port pairs newly added. Never removes a rule;
    /// never touches `git` or `enforce`.
    pub fn add_observed_allowed(&mut self, summaries: &[EndpointSummary]) -> usize {
        let mut added = 0;
        for s in summaries {
            if s.verdict != Verdict::Allow {
                continue;
            }
            if let Some(host) = &s.host {
                if self.allow(host, s.port) {
                    added += 1;
                }
            }
        }
        added
    }
}
```

(`EndpointSummary` is already imported in this module via `super::audit::EndpointSummary`; if not, add the use.)

- [ ] **Step 4: Rewire the CLI `enable`** in `crates/izba-cli/src/commands/policy.rs`. The current body is destructive (`edit_policy_file(&dir, |cfg| *cfg = seeded.clone())`). Replace the whole `enable` fn with the additive version:

```rust
fn enable(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    use izba_core::daemon::egress::audit::{aggregate, parse_line};
    let dir = paths.sandbox_dir(name);
    if !dir.exists() {
        anyhow::bail!("no such sandbox: {name}");
    }
    let audit_path = paths.logs_dir(name).join("egress-audit.jsonl");
    let text = std::fs::read_to_string(&audit_path).unwrap_or_default();
    let summaries = aggregate(text.lines().filter_map(parse_line));
    let mut added = 0usize;
    edit_policy_file(&dir, |cfg| {
        added = cfg.add_observed_allowed(&summaries);
    })?;
    println!("added {added} observed endpoint(s) to '{name}' allow-list");
    maybe_reload(paths, name);
    Ok(0)
}
```

Remove the now-unused `seed_from_summaries` import from `policy.rs` (the `use` line at the top). If, after Task 2 also stops using it, `seed_from_summaries` in `config.rs` is dead, delete it + its test (verify with `grep -rn seed_from_summaries` — covered in Final verification).

- [ ] **Step 5: Update any CLI `enable` test** that asserted replace-semantics to assert additive (existing rules kept). Run:

`source .cargo-env; cargo test -p izba-core -p izba-cli; cargo clippy -p izba-core -p izba-cli --all-targets -- -D warnings; cargo fmt`
Expected: PASS, zero warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/daemon/egress/config.rs crates/izba-cli/src/commands/policy.rs
git commit -m "fix(cli): izba policy enable is additive (merge observed, keep existing rules)"
```

---

## Task 2: App backend — additive `policy_add_endpoints` + `policy_set_full`; drop `policy_enable`

**Files:**
- Modify: `app/src-tauri/src/views.rs` (`SeedEntry`)
- Modify: `app/src-tauri/src/daemon.rs` (trait + `RealDaemon`), `app/src-tauri/src/fake.rs`
- Modify: `app/src-tauri/src/commands.rs`, `app/src-tauri/src/lib.rs`

**Interfaces:**
- Produces (consumed by Task 4 ipc):
  - `SeedEntry` (serde, tag `kind`): `Http { host: String, port: u16, access: Access }` | `Git { target: String, access: Access }`.
  - `policy_add_endpoints(name, entries: Vec<SeedEntry>, enforce: bool) -> Result<()>` — additive; sets enforce true only when `enforce`.
  - `policy_set_full(name, allow: Vec<AllowEntry>, git: Vec<GitRule>) -> Result<()>` — writes the whole rule set at once (enforce untouched).
- Removes: `policy_enable_from_traffic` / `policy_enable` (trait method, RealDaemon + FakeDaemon impls, `policy_enable_core`, the `#[tauri::command] policy_enable`, and its handler-list entry).

- [ ] **Step 1: Write failing test** (in `fake.rs` tests)

```rust
#[test]
fn policy_add_endpoints_is_additive_and_optionally_enforces() {
    let d = FakeDaemon::default();
    // seed an existing policy with a host + a git rule, enforce off
    d.policy_set_full("web",
        vec![AllowEntry::Host("existing.com".into())],
        vec![GitRule { target: GitTarget::Repo("github.com/o/a".into()), access: Access::Read }],
    ).unwrap();
    d.policy_add_endpoints("web", vec![
        SeedEntry::Http { host: "pypi.org".into(), port: 443, access: Access::Read },
    ], true).unwrap();
    let v = d.policy_show("web").unwrap();
    assert!(v.enforcing, "enforce flipped on");
    assert!(v.allow.iter().any(|e| matches!(e, AllowEntry::Host(h) if h == "existing.com") || e.host() == "existing.com"), "existing host kept");
    assert!(v.allow.iter().any(|e| e.host() == "pypi.org"), "added host present");
    assert_eq!(v.git.len(), 1, "git rule survives the add");
}
```

- [ ] **Step 2: Run, verify fail**

Run: `cd app/src-tauri && cargo test policy_add_endpoints_is_additive`
Expected: FAIL — `SeedEntry`, `policy_add_endpoints`, `policy_set_full` undefined.

- [ ] **Step 3: Implement.**
  - `views.rs`:
    ```rust
    use izba_core::daemon::egress::config::Access;

    #[derive(Debug, Clone, Deserialize)]
    #[serde(tag = "kind", rename_all = "lowercase")]
    pub enum SeedEntry {
        Http { host: String, port: u16, access: Access },
        Git { target: String, access: Access },
    }
    ```
  - `daemon.rs` `DaemonApi` trait: remove `policy_enable_from_traffic`; add:
    ```rust
    fn policy_add_endpoints(&mut self, name: &str, entries: Vec<crate::views::SeedEntry>, enforce: bool) -> anyhow::Result<()>;
    fn policy_set_full(&mut self, name: &str, allow: Vec<AllowEntry>, git: Vec<GitRule>) -> anyhow::Result<()>;
    ```
  - `RealDaemon` impls (route through the existing `edit_and_reload`):
    ```rust
    fn policy_add_endpoints(&mut self, name, entries, enforce) -> anyhow::Result<()> {
        use izba_core::daemon::egress::config::GitTarget;
        self.edit_and_reload(name, move |cfg| {
            for e in entries {
                match e {
                    SeedEntry::Http { host, port, access } => {
                        cfg.allow(&host, port);
                        cfg.set_host_access(&host, access);
                    }
                    SeedEntry::Git { target, access } => {
                        cfg.git_allow(GitTarget::parse(&target), access);
                    }
                }
            }
            if enforce { cfg.set_enforce(true); }
        })
    }
    fn policy_set_full(&mut self, name, allow, git) -> anyhow::Result<()> {
        self.edit_and_reload(name, move |cfg| { cfg.allow = allow; cfg.git = git; })
    }
    ```
  - `fake.rs`: mirror against its in-memory `EgressPolicyConfig` (same body, mutating `self.policy`). Remove `policy_enable_from_traffic`.
  - `commands.rs`: add `policy_add_endpoints_core` / `policy_set_full_core`; remove `policy_enable_core`.
  - `lib.rs`: add `#[tauri::command] policy_add_endpoints(state, name, entries, enforce)` and `policy_set_full(state, name, allow, git)`; remove `policy_enable`; update `generate_handler![...]` (drop `policy_enable`, add the two new).

- [ ] **Step 4: Run, verify pass + gate**

Run: `cd app/src-tauri && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS, zero warnings, fmt clean.

- [ ] **Step 5: Commit**

```bash
git add app/src-tauri/src
git commit -m "feat(app): additive policy_add_endpoints + policy_set_full; drop destructive policy_enable"
```

---

## Task 3: Frontend `lib/git.ts` — extract helpers + `git_access_for`

**Files:**
- Create: `app/src/lib/git.ts`
- Modify: `app/src/components/NetlogView.tsx` (import from lib/git instead of local defs — remove the local `git_repo_from_row`/`git_op_from_path`)
- Test: `app/src/test/git.test.ts` *(new)*

**Interfaces:**
- Produces: `git_repo_from_row(host, path)`, `git_op_from_path(path)` (moved verbatim from NetlogView), and:
  - `globMatch(pattern: string, value: string): boolean` — segment-wise on `/`; `*` matches exactly one segment; other segments exact. (No `**`.)
  - `git_access_for(repo: string, git: GitRule[]): Access | null` — strongest matching access (`read-write` > `read`), else null.

- [ ] **Step 1: Write failing tests** (`app/src/test/git.test.ts`)

```ts
import { describe, it, expect } from "vitest";
import { git_access_for, globMatch, git_repo_from_row } from "../lib/git";
import type { GitRule } from "../lib/types";

describe("globMatch", () => {
  it("* matches one segment only", () => {
    expect(globMatch("gitlab.com/vendor/*", "gitlab.com/vendor/lib")).toBe(true);
    expect(globMatch("gitlab.com/vendor/*", "gitlab.com/vendor/sub/lib")).toBe(false);
    expect(globMatch("github.com/o/a", "github.com/o/a")).toBe(true);
    expect(globMatch("github.com/o/a", "github.com/o/b")).toBe(false);
  });
});

describe("git_access_for", () => {
  const rules: GitRule[] = [
    { repo: "github.com/o/a", access: "read" },
    { host: "bitbucket.org", access: "read-write" },
    { repo: "gitlab.com/vendor/*" }, // access omitted → read
  ];
  it("exact repo → its access", () => expect(git_access_for("github.com/o/a", rules)).toBe("read"));
  it("host scope → its access", () => expect(git_access_for("bitbucket.org/x/y", rules)).toBe("read-write"));
  it("owner glob, access defaulted read", () => expect(git_access_for("gitlab.com/vendor/lib", rules)).toBe("read"));
  it("no match → null", () => expect(git_access_for("github.com/o/z", rules)).toBeNull());
});

describe("git_repo_from_row", () => {
  it("strips suffix + .git, prefixes host", () =>
    expect(git_repo_from_row("github.com", "/o/a.git/git-receive-pack")).toBe("github.com/o/a"));
});
```

- [ ] **Step 2: Run, verify fail**

Run: `cd app && npm test -- git`
Expected: FAIL — `lib/git` not found.

- [ ] **Step 3: Implement** `app/src/lib/git.ts` — move `git_repo_from_row` and `git_op_from_path` from NetlogView verbatim (the current linear string-op versions), then add:

```ts
import type { Access, GitRule } from "./types";

/** Segment-wise glob on `/`: `*` matches exactly one segment. No `**`. */
export function globMatch(pattern: string, value: string): boolean {
  const p = pattern.split("/");
  const v = value.split("/");
  if (p.length !== v.length) return false;
  return p.every((seg, i) => seg === "*" || seg === v[i]);
}

/** Strongest access a git ruleset grants this concrete repo, else null. */
export function git_access_for(repo: string, git: GitRule[]): Access | null {
  const host = repo.split("/")[0];
  let best: Access | null = null;
  for (const rule of git) {
    const matched = "repo" in rule ? globMatch(rule.repo, repo) : rule.host === host;
    if (!matched) continue;
    const a: Access = rule.access ?? "read";
    if (a === "read-write") return "read-write"; // strongest wins, short-circuit
    best = "read";
  }
  return best;
}
```

Then in `NetlogView.tsx`: delete the local `git_repo_from_row`/`git_op_from_path` defs and `import { git_repo_from_row, git_op_from_path } from "../lib/git";`. (Keep its other behavior unchanged this task — full netlog redesign is Task 8.) Update `app/src/test/netlogView.test.tsx` imports if it imported `git_repo_from_row` from NetlogView.

- [ ] **Step 4: Run, verify pass**

Run: `cd app && npm test && npm run build`
Expected: PASS + clean build.

- [ ] **Step 5: Commit**

```bash
git add app/src/lib/git.ts app/src/components/NetlogView.tsx app/src/test
git commit -m "refactor(app): extract git helpers to lib/git + add git_access_for"
```

---

## Task 4: Frontend types + ipc — `SeedEntry`, `policyAddEndpoints`, `policySetFull`

**Files:**
- Modify: `app/src/lib/types.ts`, `app/src/lib/ipc.ts`

**Interfaces:**
- Consumes: Task 2 command names.
- Produces: `SeedEntry` type; `api.policyAddEndpoints(name, entries, enforce)`, `api.policySetFull(name, allow, git)`; `api.policyEnable` removed.

- [ ] **Step 1: Write failing test** (`app/src/test/ipc.test.ts` — follow the existing mock-invoke pattern)

```ts
it("policyAddEndpoints invokes policy_add_endpoints with entries + enforce", async () => {
  const spy = mockInvoke();
  await api.policyAddEndpoints("web", [{ kind: "http", host: "pypi.org", port: 443, access: "read" }], true);
  expect(spy).toHaveBeenCalledWith("policy_add_endpoints", {
    name: "web", entries: [{ kind: "http", host: "pypi.org", port: 443, access: "read" }], enforce: true,
  });
});
```

- [ ] **Step 2: Run, verify fail** — `cd app && npm test -- ipc`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - `types.ts`:
    ```ts
    export type SeedEntry =
      | { kind: "http"; host: string; port: number; access: Access }
      | { kind: "git"; target: string; access: Access };
    ```
  - `ipc.ts`: remove `policyEnable`; add:
    ```ts
    policyAddEndpoints: (name: string, entries: SeedEntry[], enforce: boolean) =>
      invoke<void>("policy_add_endpoints", { name, entries, enforce }),
    policySetFull: (name: string, allow: AllowEntry[], git: GitRule[]) =>
      invoke<void>("policy_set_full", { name, allow, git }),
    ```
    Import `SeedEntry`, `GitRule` in ipc.ts as needed.

- [ ] **Step 4: Run, verify pass** — `cd app && npm test && npm run build`. (NetlogView still references `api.policyEnable` until Task 8 — to keep the build green, temporarily leave the old "Enable" button calling a no-op or guard; CLEANEST: do Task 8 and Task 4 such that the build is green at each commit. To avoid a broken intermediate, in THIS task also remove the single `api.policyEnable(name)` call site in NetlogView, replacing the button's onClick with a `// TODO Task 8: open SeedDialog` stub that does nothing, so the build compiles. Task 8 replaces it properly.)

- [ ] **Step 5: Commit**

```bash
git add app/src/lib app/src/components/NetlogView.tsx
git commit -m "feat(app): SeedEntry + policyAddEndpoints/policySetFull ipc; drop policyEnable"
```

---

## Task 5: `Section.tsx` — collapsible section wrapper

**Files:**
- Create: `app/src/components/Section.tsx`
- Test: `app/src/test/section.test.tsx` *(new)*

**Interfaces:**
- Produces: `<Section title={string} defaultOpen?={boolean}>{children}</Section>` — a titled, collapsible region (click the title row to toggle); `defaultOpen` defaults true.

- [ ] **Step 1: Write failing test**

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { Section } from "../components/Section";

it("toggles children visibility", () => {
  render(<Section title="Hosts"><p>body</p></Section>);
  expect(screen.getByText("body")).toBeVisible();
  fireEvent.click(screen.getByRole("button", { name: /Hosts/ }));
  expect(screen.queryByText("body")).toBeNull();
});
```

- [ ] **Step 2: Run, verify fail** — `cd app && npm test -- section`. Expected: FAIL.

- [ ] **Step 3: Implement**

```tsx
import { useState, type ReactNode } from "react";

export function Section({ title, defaultOpen = true, children }: Readonly<{
  title: string; defaultOpen?: boolean; children: ReactNode;
}>) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className="rounded-lg border border-line">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm font-semibold"
      >
        <span className="text-ink-3">{open ? "▾" : "▸"}</span>
        {title}
      </button>
      {open && <div className="border-t border-line p-3">{children}</div>}
    </section>
  );
}
```

- [ ] **Step 4: Run, verify pass** — `cd app && npm test -- section && npm run build`.

- [ ] **Step 5: Commit**

```bash
git add app/src/components/Section.tsx app/src/test/section.test.tsx
git commit -m "feat(app): collapsible Section component"
```

---

## Task 6: PolicyEditor — sections, staged single-Save, always-editable, symmetric add

**Files:**
- Modify: `app/src/components/PolicyEditor.tsx`
- Modify: `app/src/test/policyEditor.test.tsx`

**Interfaces:**
- Consumes: `Section` (Task 5), `AccessPicker`, `api.policySetFull`/`api.policySetEnforce` (Task 4), `WEB_DEFAULT_PORTS`.

**Behavior to implement:**
- State: `hosts: Row[]` (`{host, ports, access}`), `git: GitRow[]` (`{target, access}`), `enforcing: boolean`, `saved`, `error`. Drop `gitDraft`, `gitDraftTargets`, `gitSaved`, `saveGit`, `commitGitDraft`, `removeGitRow`'s immediate-block, and the AccessPicker immediate-persist.
- `dirty`: hosts/git differ from the last-loaded snapshot. Keep a `loaded` ref of the initial `{hosts, git}` to compare (JSON compare is fine).
- **Enforce toggle persists immediately** (`policySetEnforce`, with revert-on-error) — unchanged from today; NOT part of Save.
- **One Save**: `api.policySetFull(name, allowEntries, gitRules)` where `allowEntries` maps each host row to `{host, ports, access}` and `gitRules` maps each git row to `{repo|host (from "/" rule), access}` via a `toGitRule(target, access)` helper (a `/`-containing target → `{repo: target, access}`, else `{host: target, access}`). On success set `saved`, refresh `loaded` snapshot, clear `dirty`.
- **Always editable**: remove `<fieldset disabled={!enforcing}>`.
- **Two `<Section>`s**: `Hosts` and `Git repos`, each with its description; host rows + "Add host", git rows + "Add repo".
- **Symmetric add**: "Add host" appends `{host:"", ports:[443], access:"read-write"}`; "Add repo" appends `{target:"", access:"read"}` — both editable rows (the git target is a text `<input>`, NOT a disabled box). Remove the always-present git draft input.

- [ ] **Step 1: Write/adjust failing tests** (`policyEditor.test.tsx`)

```tsx
it("one Save persists hosts and git together via policySetFull", async () => {
  (api.policyShow as Mock).mockResolvedValue({ enforcing: false, allow: [{host:"a.com",ports:[443]}], git: [] });
  const setFull = api.policySetFull as Mock;
  render(<PolicyEditor name="web" />);
  // add a git repo row, type a target, pick read-write
  fireEvent.click(await screen.findByRole("button", { name: /Add repo/ }));
  fireEvent.change(screen.getByPlaceholderText("github.com/owner/repo"), { target: { value: "github.com/o/a" } });
  fireEvent.click(screen.getByRole("button", { name: /Save/ }));
  await waitFor(() => expect(setFull).toHaveBeenCalledWith("web",
    [{ host: "a.com", ports: [443], access: "read-write" }],
    [{ repo: "github.com/o/a", access: "read" }]));
});

it("git target input is editable even when firewall is off", async () => {
  (api.policyShow as Mock).mockResolvedValue({ enforcing: false, allow: [], git: [] });
  render(<PolicyEditor name="web" />);
  fireEvent.click(await screen.findByRole("button", { name: /Add repo/ }));
  const input = screen.getByPlaceholderText("github.com/owner/repo") as HTMLInputElement;
  expect(input.disabled).toBe(false);
});
```

(Adjust/remove the old tests that asserted immediate `policyGitAllow` on AccessPicker change or a separate "Save git" button — those behaviors are gone.)

- [ ] **Step 2: Run, verify fail** — `cd app && npm test -- policyEditor`. Expected: FAIL.

- [ ] **Step 3: Implement** the rewrite per Behavior above. Key save fn:

```tsx
async function save() {
  setError(null); setSaved(false);
  try {
    const allow: AllowEntry[] = hosts.filter(r => r.host.trim() !== "")
      .map(r => ({ host: r.host.trim(), ports: r.ports, access: r.access }));
    const git: GitRule[] = gitRows.filter(r => r.target.trim() !== "")
      .map(r => toGitRule(r.target.trim(), r.access));
    await api.policySetFull(name, allow, git);
    setLoaded({ hosts, git: gitRows }); setSaved(true);
  } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
}

function toGitRule(target: string, access: Access): GitRule {
  return target.includes("/") ? { repo: target, access } : { host: target, access };
}
```

Render: enforce toggle (immediate) on top, then `<Section title="Hosts">…</Section>` and `<Section title="Git repos">…</Section>`, then a single **Save** button with an inline `● unsaved changes` marker when `dirty`.

- [ ] **Step 4: Run, verify pass + app gate**

Run: `cd app && npm test && npm run build && (cd src-tauri && cargo clippy --all-targets -- -D warnings)`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src/components/PolicyEditor.tsx app/src/test/policyEditor.test.tsx
git commit -m "feat(app): policy editor — sections, single staged Save, always editable"
```

---

## Task 7: `SeedDialog.tsx` — delta-review modal

**Files:**
- Create: `app/src/components/SeedDialog.tsx`
- Test: `app/src/test/seedDialog.test.tsx` *(new)*

**Interfaces:**
- Consumes: `EndpointSummary[]`, `PolicyView`, `git_repo_from_row`/`git_op_from_path`/`git_access_for` (Task 3), `AccessPicker`, `api.policyAddEndpoints` (Task 4).
- Props: `{ name: string; rows: EndpointSummary[]; policy: PolicyView; enforcing: boolean; onClose: () => void; onApplied: () => void }`.

**Behavior:**
- **Delta**: from `rows`, build candidate entries NOT already covered by `policy`:
  - git rows (a row whose `last_path` is a git op): repo = `git_repo_from_row`; covered if `git_access_for(repo, policy.git) !== null`. Default access = `read-write` if `git_op_from_path === "push"` else `read`.
  - http rows (non-git, named host): covered if `policy.allow` has the host with that port (reuse the existing `allowKeys` logic — move it to lib or inline). Default access = `read` if the row's `last_method` ∈ {GET,HEAD} (or unknown) else `read-write`.
  - raw-IP rows (no host): listed disabled, never selectable.
- Each candidate row: a checkbox (default checked for non-raw-IP), the endpoint label, observed count, an `AccessPicker`.
- An **"Enforce firewall after adding"** checkbox, default unchecked; when `!enforcing` render it **prominently** (e.g. an amber/warn box with `⚠ firewall is currently OFF`); when `enforcing`, hide it (or render muted/disabled).
- **Add selected** → `api.policyAddEndpoints(name, selectedEntries, enforceAfter)` → `onApplied()` + `onClose()`. `Cancel` → `onClose()`.

- [ ] **Step 1: Write failing tests** (`seedDialog.test.tsx`)

```tsx
it("lists only the delta and adds selected via policyAddEndpoints", async () => {
  const add = api.policyAddEndpoints as Mock;
  const rows = [
    sum({ host: "pypi.org", port: 443, last_method: "GET", last_path: "/simple/" }),
    sum({ host: "api.x.com", port: 443, last_method: "POST", last_path: "/v1" }), // already in policy
  ];
  render(<SeedDialog name="web" rows={rows} enforcing={false}
    policy={{ enforcing:false, allow:[{host:"api.x.com",ports:[443]}], git:[] }}
    onClose={()=>{}} onApplied={()=>{}} />);
  expect(screen.queryByText(/api\.x\.com/)).toBeNull();          // covered → excluded
  expect(screen.getByText(/pypi\.org/)).toBeInTheDocument();      // delta
  fireEvent.click(screen.getByRole("button", { name: /Add .* selected/ }));
  await waitFor(() => expect(add).toHaveBeenCalledWith("web",
    [{ kind: "http", host: "pypi.org", port: 443, access: "read" }], false));
});

it("enforce-after checkbox is prominent when firewall is off and passes enforce=true when checked", async () => {
  const add = api.policyAddEndpoints as Mock;
  render(<SeedDialog name="web" rows={[sum({host:"pypi.org",port:443,last_method:"GET",last_path:"/"})]}
    enforcing={false} policy={{enforcing:false,allow:[],git:[]}} onClose={()=>{}} onApplied={()=>{}} />);
  expect(screen.getByText(/firewall is currently OFF/i)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("checkbox", { name: /Enforce firewall after adding/i }));
  fireEvent.click(screen.getByRole("button", { name: /Add .* selected/ }));
  await waitFor(() => expect(add).toHaveBeenCalledWith("web", expect.anything(), true));
});
```

(`sum(...)` = a small EndpointSummary factory in the test; mirror the netlogView test's factory.)

- [ ] **Step 2: Run, verify fail** — `cd app && npm test -- seedDialog`. Expected: FAIL.

- [ ] **Step 3: Implement** `SeedDialog.tsx` per Behavior (a modal overlay; build candidate list with `useMemo` over `rows`+`policy`; local `Map<key, {checked, access}>` state; the prominent enforce box gated on `!enforcing`).

- [ ] **Step 4: Run, verify pass** — `cd app && npm test && npm run build`.

- [ ] **Step 5: Commit**

```bash
git add app/src/components/SeedDialog.tsx app/src/test/seedDialog.test.tsx
git commit -m "feat(app): delta-review SeedDialog (additive, optional enforce-after)"
```

---

## Task 8: NetlogView redesign — banner, enforce toggle, Review trigger, git-row state + label

**Files:**
- Modify: `app/src/components/NetlogView.tsx`
- Modify: `app/src/test/netlogView.test.tsx`

**Interfaces:**
- Consumes: `SeedDialog` (Task 7), `git_access_for`/`git_repo_from_row`/`git_op_from_path` (Task 3), `api.policySetEnforce`.

**Behavior:**
- **Banner** (replace lines ~170–183):
  - `enforcing` → `🛡 Firewall ON · {allowRuleCount} allow rule(s)` (count = `policy.allow.length + policy.git.length`).
  - `!enforcing` → `🛡 Firewall OFF · all egress currently allowed`, sub-line `{rows.length} endpoint(s) observed · {blockedCount} were blocked while enforcing` where `blockedCount = rows.filter(r => r.deny_count > 0).length`. **No "all allowed".**
- **Enforce toggle** in the header (checkbox/switch) bound to `api.policySetEnforce(name, !enforcing)` with optimistic + revert (mirror PolicyEditor), reflecting `policy.enforcing`.
- **"Review observed traffic" button** (always available) opens `SeedDialog` (state `showSeed`). On `onApplied`, `void refresh()`.
- **Git rows** (replace the static-buttons block ~245–279): compute `const access = git_access_for(gitRepo, policy?.git ?? [])`. Label cell: `git → {gitRepo}` (drop the clone/push verb). Action cell: highlight the active access (`read`/`read-write`) using `AccessPicker`-style active styling; render **Block** when `access !== null` (calls `policyGitBlock`), and Allow-read/Allow-write call-to-action when `access === null`. Keep immediate persistence (`act(...)`). Policy column: show `access ?? "blocked"` (when enforcing) or `—` (when off), consistent with host rows.
- Remove the old `api.policyEnable` button/stub from Task 4.

- [ ] **Step 1: Write/adjust failing tests** (`netlogView.test.tsx`)

```tsx
it("off-state banner is honest (no 'all allowed', shows blocked-while-enforcing)", async () => {
  (api.policyShow as Mock).mockResolvedValue({ enforcing: false, allow: [], git: [] });
  (api.readNetlog as Mock).mockResolvedValue([
    sum({ host: "a.com", port: 443, deny_count: 3 }), sum({ host: "b.com", port: 443 }),
  ]);
  render(<NetlogView name="web" />);
  expect(await screen.findByText(/Firewall OFF/)).toBeInTheDocument();
  expect(screen.getByText(/1 were blocked while enforcing/)).toBeInTheDocument();
  expect(screen.queryByText(/all allowed/)).toBeNull();
});

it("a git row reflects its policy access and offers Block", async () => {
  (api.policyShow as Mock).mockResolvedValue({ enforcing: true, allow: [], git: [{ repo: "github.com/o/a", access: "read" }] });
  (api.readNetlog as Mock).mockResolvedValue([ sum({ host: "github.com", port: 443, last_method: "POST", last_path: "/o/a/git-upload-pack" }) ]);
  render(<NetlogView name="web" />);
  expect(await screen.findByText("git → github.com/o/a")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /^Block$/ })).toBeInTheDocument();
});
```

- [ ] **Step 2: Run, verify fail** — `cd app && npm test -- netlogView`. Expected: FAIL.

- [ ] **Step 3: Implement** the banner, enforce toggle, SeedDialog trigger + render, and git-row state/label per Behavior.

- [ ] **Step 4: Run, verify pass + app gate** — `cd app && npm test && npm run build`.

- [ ] **Step 5: Commit**

```bash
git add app/src/components/NetlogView.tsx app/src/test/netlogView.test.tsx
git commit -m "feat(app): netlog — honest banner, enforce toggle, review-traffic dialog, git-row state"
```

---

## Task 9: Layout fix — fill height, no gray zone

**Files:**
- Modify: `app/src/components/Detail.tsx` (tab content container, ~line 93) and `app/src/components/PolicyEditor.tsx` root.
- Possibly: the left sandbox-list panel container (find its parent in `Detail.tsx`/`App.tsx`).

**Behavior:** the Policy tab's action row crowds the bottom frame and the left panel leaves a gray gap at short window heights. Make the detail content a single flex column whose scroll region flexes:
- Detail tab content wrapper (`<div className="mt-4 min-h-0 flex-1">`): ensure it is `flex min-h-0 flex-1 flex-col`.
- `PolicyEditor` root: `flex h-full flex-col gap-3` with the sections area as `flex-1 min-h-0 overflow-y-auto` and the Save row outside the scroll area (sticky footer feel) OR inside but with `pb-*` so it doesn't touch the frame.
- Left list panel: ensure its container is `h-full` so it stretches to the pane height (no gray zone below).

- [ ] **Step 1: Reproduce** — `cd app && npm run build`, then (manual) note the current short-window behavior matches the report; OR add a lightweight snapshot/structural test asserting the PolicyEditor root has `h-full`+`flex-col` and the scroll region has `overflow-y-auto min-h-0` (a class-presence assertion in `policyEditor.test.tsx`).

- [ ] **Step 2: Implement** the flex/height classes above.

- [ ] **Step 3: Verify** — `cd app && npm test && npm run build`; manual: shrink the window, confirm the Save row no longer touches the frame and the left panel fills height. (If running the app is impractical in CI, the class-presence test + build is the gate; note the manual check.)

- [ ] **Step 4: Commit**

```bash
git add app/src/components/Detail.tsx app/src/components/PolicyEditor.tsx
git commit -m "fix(app): policy/netlog tab fills pane height; left panel no gray zone"
```

---

## Final verification (before pushing to PR #54)

- [ ] App frontend: `cd app && npm ci && npm test && npm run build` — green.
- [ ] App backend: `cd app/src-tauri && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check` — green.
- [ ] Workspace (Task 1): `source .cargo-env; cargo test -p izba-core -p izba-cli && cargo clippy -p izba-core -p izba-cli --all-targets -- -D warnings && cargo fmt --check && cargo check --target x86_64-pc-windows-gnu -p izba-core -p izba-cli`.
- [ ] `grep -rn "policy_enable\|policyEnable\|seed_from_summaries.*\*cfg\|Enable firewall — allow" app crates` — no destructive-replace remnants (the additive paths only).
- [ ] Manual smoke: disable enforce → banner honest, no auto-allow; "Review observed traffic" → delta only, checkmarks, enforce-after prominent; add → policy gains rules, git rules survive; Policy tab → two sections, one Save, git input typeable while off.

## Self-review notes (coverage vs spec)

- Spec D1 (pure enforce toggle) → Tasks 6, 8 (immediate `policySetEnforce`, not in Save). D2/D3 (delta dialog + enforce-after) → Task 7. D4 (honest banner) → Task 8. D5 (git-row state + `git →` label) → Tasks 3, 8. D6 (one staged Save) → Tasks 2 (`policy_set_full`), 6. D7 (sections, always-editable, symmetric add) → Tasks 5, 6. D8 (netlog immediate) → Task 8. The destructive-replace bug + additive merge → Tasks 1 (CLI), 2 (app). Layout → Task 9.
- Deferred (spec open item): confirm-on-navigate guard — not a task (the `● unsaved changes` marker in Task 6 covers the minimum); add later if desired.
