# Policy / Netlog UX redesign (firewall app)

**Status:** approved design (2026-06-18)
**Context:** follow-up polish on the vendor-neutral git-egress feature
([2026-06-18-vendor-neutral-git-http-egress-controls-design.md](2026-06-18-vendor-neutral-git-http-egress-controls-design.md),
PR #54). Driven by manual-test feedback on the desktop app's **Policy** and
**Netlog** tabs. Frontend + a small app-backend seam change only; no rego /
datapath change.

## Problem

The git-egress feature shipped a working policy plane, but manual testing
surfaced UX problems clustered in two tabs:

1. **Enforce and "seed from traffic" are fused into one destructive button.**
   The Netlog "Enable firewall — allow these N" action calls
   `policy_enable_from_traffic`, which does `*cfg = seed_from_summaries(...)` —
   a **wholesale replace**: it wipes existing host rules, wipes **all** git
   rules, and (because `seed_from_summaries` returns `EgressPolicyConfig::
   default()`) leaves `enforce: false`. So today the button destroys a curated
   policy *and* doesn't even enforce.
2. **The "no firewall" banner lies.** "This sandbox has no firewall · N
   endpoint(s) observed (all allowed)" is wrong: traffic observed while
   enforcement was on was *not* all allowed (the per-row ✗ counts prove it),
   and "all allowed" misrepresents the audit history as a current-state claim.
3. **Netlog git-row buttons are static.** Allow-read / Allow-write / Block on a
   git row never reflect or flip to the current policy state, unlike host rows.
4. **Netlog git label conflates operations.** `git clone → owner/repo` is
   misleading because pull/push fold into the same row.
5. **Policy editor has no visual section structure.** "Hosts this sandbox may
   reach" sits in no section; "Git repos" doesn't stand out.
6. **Asymmetric / broken add controls.** "Add host" appends a row on click;
   "Add git" shows an always-present inline input that is **disabled and
   untypeable** (the whole git section is inside `<fieldset disabled=
   {!enforcing}>`, so it greys out whenever the firewall is off).
7. **Two Save buttons** (Save + Save git) are confusing.
8. **Layout:** at short window heights the Add/Save-git buttons crowd the
   bottom frame and the left list panel leaves a gray gap below it.

## Goals / non-goals

- **Goal:** make enforcement, allow-listing, and traffic-review three clear,
  independent, non-destructive actions; give the editor a coherent
  single-Save, sectioned, always-editable shape; fix the label, button-state,
  and layout papercuts.
- **Non-goal:** no rego / policy-grammar change, no datapath change, no new
  daemon RPC beyond what the additive-merge seam needs. Deep-glob (`**`)
  state reflection in netlog is explicitly out (lightweight match only).

## Decisions (locked 2026-06-18)

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Enforce is a pure toggle** — sets `enforce` only, never touches rules. | Kills the fuse; matches the dry-run-then-enforce workflow. |
| D2 | **Seeding becomes a delta-review dialog** (checkboxes, additive merge), replacing the destructive "Enable firewall — allow these N". | Unifies empty-policy onboarding and curated-policy top-up; filters noise; never overwrites. |
| D3 | The delta dialog has an **"Enforce firewall after adding" checkbox**, default **off** (explicit), rendered **prominently when the firewall is currently off**, muted/hidden when already on. | Onboarding stays one-flow without ever silently flipping posture. |
| D4 | **Honest banner**: off ⇒ "Firewall OFF · all egress currently allowed" + observed/blocked history; on ⇒ "Firewall ON · K rules". No "all allowed" claim about observed traffic. | Truthful. |
| D5 | **Netlog git rows reflect + flip state** via a lightweight client-side match (exact repo, owner-`*` glob, host-scope); label is `git → owner/repo`. | Parity with host rows; Policy tab stays source of truth. |
| D6 | **Policy editor: one Save, fully staged.** Revert the immediate per-row git-access persistence; all host + git edits stage locally; one Save persists both; an "unsaved changes" indicator guards against loss. | A security policy should be composed and saved deliberately, not mutated per keystroke. |
| D7 | **Editor is always editable** (drop `disabled-when-not-enforcing`); two collapsible sections (`Hosts`, `Git repos`, expanded by default); symmetric "Add host"/"Add repo" (click → new row). | Enables dry-run curation; fixes the disabled-input bug; clear structure. |
| D8 | **Netlog per-flow Allow/Block stays immediate.** | That tab is observe-and-react on individual flows (one click = one rule); distinct from composing a policy in the editor. |

## Design

### A. Netlog: enforce / banner / delta dialog (Problems 1, 2)

`NetlogView` header logic splits into three concerns:

- **Status banner** (`FirewallStatus`-consistent):
  - `enforcing` ⇒ `🛡 Firewall ON · {allowRuleCount} allow rule(s)`.
  - `!enforcing` ⇒ `🛡 Firewall OFF · all egress currently allowed`, with a
    sub-line `{N} endpoint(s) observed · {M} were blocked while enforcing`
    (M = rows whose latest verdict was Deny / whose deny_count > 0). The per-row
    ✓/✗ counts are explicitly historical.
- **Enforce toggle** in the header (calls `policy_set_enforce`), mirroring the
  Policy-tab toggle; reflects live state.
- **"Review observed traffic" button** opens the **delta dialog**:

```
┌─ Review observed traffic ───────────────────────────────────────────┐
│ Endpoints observed but not yet in your policy   [Select all][None]   │
│ ─────────────────────────────────────────────────────────────────── │
│ [✓] pypi.org : 443                 HTTP  12✓   access ( ●read ○read-write ) │
│ [✓] github.com/semgrep/semgrep     git    8✓   access ( ●read ○read-write ) │
│ [ ] 203.0.113.9 : 443  raw IP — cannot allow-list (SSRF guard)  ✗disabled │
│ ─────────────────────────────────────────────────────────────────── │
│ [ ] Enforce firewall after adding        ⚠ firewall is currently OFF │   ← D3: prominent only when !enforcing
│                              [ Cancel ]  [ Add 2 selected to allow-list ] │
└──────────────────────────────────────────────────────────────────────┘
```

- **Delta computation (client-side):** from the netlog summaries, keep rows
  whose latest verdict was Allow OR Deny (both are "observed") **and** that are
  **not already covered** by the current `PolicyView` (host rule for `host:port`,
  or a git rule matching the repo). Raw-IP rows are listed disabled (SSRF
  guard), never selectable. HTTP rows default checked; the access radio defaults
  to `read` for a pure-GET/HEAD history else `read-write`. Git rows' access
  defaults to `read-write` if any push (`git-receive-pack`) was observed for
  that repo, else `read`.
- **Apply (`Add selected`):** an **additive** backend action that merges the
  selected entries into the existing policy via `cfg.allow(host, port)` /
  `cfg.set_host_access` and `cfg.git_allow(target, access)` — **never** `*cfg =`.
  If "Enforce after adding" is checked, also `cfg.set_enforce(true)` in the same
  edit. Returns the updated `PolicyView`.
- **Backend seam:** replace the wholesale `policy_enable_from_traffic` with an
  additive `policy_add_endpoints(name, entries: Vec<SeedEntry>, enforce: bool)`
  (`SeedEntry { kind: Http{host,port,access} | Git{target,access} }`) on the
  `DaemonApi` trait + a `#[tauri::command]`. `seed_from_summaries` is removed or
  repurposed into the client-side delta computation; the destructive
  `policy_enable` command and its tests go away. (The CLI `izba policy enable`
  verb, which also used `seed_from_summaries` to *replace*, is changed to be
  additive too, or removed — see Open items.)

### B. Netlog git rows (Problems 3, 4)

- **Label:** `git → {owner/repo}` (drop clone/push/pull verb).
- **State reflection:** a client-side `git_access_for(repo, view.git)` returns
  `"read" | "read-write" | null`:
  - exact `repo:` rule whose glob equals the repo;
  - owner-`*` rule (`host/owner/*`) covering the repo;
  - `host:` rule for the repo's host.
  Highlight the matching access button (`read`/`read-write`) as active; when a
  rule exists, show **Block** (revokes via `policy_git_block`); when none, the
  Allow-read/Allow-write buttons are the call-to-action. Clicking persists
  immediately (D8) and the row reflects the new state on the next refresh
  (already 1.5 s polling + instant post-action refresh).

### C. Policy editor (Problems 5, 6, 7)

`PolicyEditor` becomes a staged, sectioned form:

- **State:** `hosts: Row[]`, `git: GitRow[]`, `enforce: boolean`, plus a derived
  `dirty` flag (any field differs from the last-loaded `PolicyView`).
- **Two collapsible sections** (`<Section title… defaultOpen>`): **Hosts** (host
  + ports + `AccessPicker`) and **Git repos** (target + `AccessPicker`). Each
  with its one-line description.
- **Symmetric add:** "Add host" and "Add repo" each append a blank editable row;
  remove the always-present inline git input.
- **One Save:** persists hosts (`policy_set`) **and** git rules in a single
  action. Implementation: a new additive-free `policy_set_full(name, allow,
  git, enforce)` that writes the complete editor state at once (one
  `edit_policy_file` + one reload), so the editor is the authoritative writer of
  its own staged state. Save clears `dirty` and shows "saved · reloaded".
- **Always editable:** drop the `<fieldset disabled={!enforcing}>`; rules are
  editable regardless of `enforce`. The enforce toggle stays at the top of the
  editor and **persists immediately** on click (it is a single posture bit, not
  a rule — same as the Netlog enforce toggle, D8); it is **not** part of the
  staged Save. Save stages and persists only host + git **rules**. So `dirty`
  tracks rule edits, never the enforce bit.
- **Unsaved-changes guard:** a small "● unsaved changes" marker by Save when
  `dirty`; (optional, low-priority) confirm-on-navigate.

### D. Layout (Problem 8)

The Policy/Netlog tab content and the left sandbox-list panel don't share a
height model. Fix: the detail pane is a single `flex flex-col min-h-0` column;
the scrollable region uses `flex-1 min-h-0 overflow-y-auto` so the action row
never crowds the frame; the left list panel stretches to full pane height
(`h-full`). Verify against the screenshot scenario (short window, scrollbar at
bottom).

## Components touched

- `app/src/components/NetlogView.tsx` — banner, enforce toggle, delta-dialog
  trigger, git-row state + label.
- `app/src/components/SeedDialog.tsx` *(new)* — the delta-review modal.
- `app/src/components/PolicyEditor.tsx` — sections, staged one-Save,
  always-editable, symmetric add.
- `app/src/components/Section.tsx` *(new)* — collapsible section wrapper.
- `app/src/components/AccessPicker.tsx` — reused (host + git + dialog rows).
- `app/src/lib/git.ts` *(new)* — `git_repo_from_row`, `git_op_from_path`,
  `git_access_for` (moved out of NetlogView; shared with the dialog).
- `app/src/lib/types.ts`, `app/src/lib/ipc.ts` — `SeedEntry`,
  `policyAddEndpoints`, `policySetFull`; drop `policyEnable`.
- `app/src-tauri/src/{daemon,fake,commands,lib}.rs` — `policy_add_endpoints`,
  `policy_set_full`; remove `policy_enable_from_traffic`.
- `app/src/components/Detail.tsx` / tab container + the left list — layout (D).
- Tests: `app/src/test/{netlogView,policyEditor,seedDialog}.test.tsx`,
  app-backend daemon/fake tests.

## Testing

- **Delta dialog:** delta excludes already-covered endpoints; raw-IP disabled;
  checkbox select/all/none; access defaults (read vs read-write from observed
  ops); "Add selected" calls `policyAddEndpoints` with exactly the checked rows;
  "Enforce after adding" passes `enforce:true` only when checked; the enforce
  checkbox is prominent iff `!enforcing`.
- **Additive merge (backend):** `policy_add_endpoints` merges into an existing
  policy without dropping host or git rules; sets enforce only when asked; a
  regression test pinning that an existing `git:` rule survives a seed (the old
  bug).
- **Banner honesty:** off-state banner shows observed + blocked-while-enforcing
  counts, never "all allowed".
- **Git-row state:** `git_access_for` returns the right access for exact /
  owner-glob / host-scope; the netlog button highlights it; Block appears when a
  rule exists.
- **Editor:** one Save persists host + git + enforce together; `dirty` flag;
  add-host/add-repo both append a row; editing works while `!enforcing`.
- **Layout:** (manual / snapshot) the action row and left panel fill height at a
  short window.
- All app gates green: `cd app && npm test && npm run build && (cd src-tauri &&
  cargo clippy --all-targets -- -D warnings && cargo test)`.

## Decided sub-points (firmed during self-review)

- **Enforce toggle persistence:** persists **immediately** in both the editor
  and Netlog header (posture bit, not a rule). See §C.
- **CLI `izba policy enable`:** today it also used the destructive
  `seed_from_summaries` replace. It becomes **additive** — it merges observed
  *allowed* endpoints into the existing policy (never replaces, never drops git
  rules) and keeps `enforce` unchanged. The command keeps working as a
  non-interactive parallel to the app's delta dialog (no per-row selection in
  the CLI; it adds all observed allowed endpoints). Its tests update from
  "replace" to "merge" assertions.

## Open items (low-priority, may defer)

1. **Confirm-on-navigate** for unsaved editor changes — nice-to-have guard
   beyond the "● unsaved changes" marker; include only if cheap, else defer.
