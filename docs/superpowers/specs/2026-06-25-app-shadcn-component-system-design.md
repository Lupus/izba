# izba app — shadcn-native component system & consistency enforcement

> **Status:** design approved 2026-06-25. Next: implementation plan (writing-plans).
> **Scope:** the Tauri GUI only (`app/`, outside the cargo workspace). No
> changes to `izba-core`/`izba-proto`/CLI wire types.

## Problem

The Tauri desktop GUI (React 18 + Vite + Tailwind 3) hand-rolls every form with
ad-hoc Tailwind class strings. There is no shared component layer, so the same
conceptual element is styled differently across the 21 components. Audited
evidence:

- **"Remove row" button** is orange (`border-warn/40 text-warn hover:bg-warn/5`)
  in `VolumeRowEditor`, `VolumesTab`, `PolicyEditor` — but **gray**
  (`border-line text-ink-2 hover:bg-hover`) in `PortsTab`. Same action, two
  colors.
- **"Add" button** ranges from a narrow pill (`px-2 py-1 text-xs`) in
  `NewSandbox`/`VolumesTab` to a full-width `px-3 py-1.5 text-sm` bar in
  `PortsTab`/`PolicyEditor`.
- **Inputs** flip between `rounded` and `rounded-lg`, `py-1` and `py-1.5`,
  `text-xs` and `text-sm` by file.
- The primary "Save" in `PolicyEditor` is missing the `shadow-sm` every other
  primary CTA has.

The deeper problem: **consistency is currently a *visual* property**, and visual
defects are exactly what LLM review (reading Playwright screenshots) and human
spot-checks across 21 files miss. The fix must convert consistency into a
**mechanical, text-/diff-checkable invariant**.

## Goals

1. A single shadcn-native component layer; every button/input/select/dialog/
   badge routes through one definition with one variant taxonomy.
2. A shadcn-native CSS-variable token system as the single palette (replacing
   the ad-hoc `izba`-token Tailwind config), with a dark-mode seam in place.
3. A **hard lint gate** that makes drift a failing build check, not a visual
   judgment call — so an LLM/CI verifies consistency by grep, not by eyeball.
4. Migrate all 21 existing components onto the new layer with **no behavioral
   regression** and **no intended visual change** on day one.

## Non-goals (YAGNI / deferred)

- **Visual-regression CI gate** (Ladle kitchen-sink + Playwright `toHaveScreenshot`
  pixel-diff). Strong follow-up; explicitly out of scope here.
- **Redesign / restyle.** This is a vocabulary + structure migration; the app
  must look identical on day one.
- **Dark mode delivery.** We add the `darkMode: ["class"]` seam and a `.dark`
  block, but ship light-only; dark values may be filler/TODO.
- True destructive-vs-warning color split (red destructive). Deferred; see token
  decision below.

## Decisions (locked during brainstorming)

1. **Library: full shadcn/ui** (Radix primitives + CVA), copied into the repo
   (not a runtime UI-framework dependency). Gives accessible Dialog/Select/Switch
   to replace hand-rolled modals/toggles.
2. **Token strategy (B): shadcn-native CSS-var system.** Rewrite
   `tailwind.config.ts` to the shadcn convention; izba's hex palette is migrated
   into the CSS vars. Existing token class names (`bg-accent`, `text-ink`,
   `border-line`, …) are swept to the shadcn vocabulary across all components.
3. **Tailwind v3 era.** The project is on `tailwindcss@^3.4.0`, so we use the
   **Tailwind-v3 shadcn convention**: HSL channel CSS vars + `hsl(var(--token))`
   in `tailwind.config.ts` + `darkMode: ["class"]`. **Not** the Tailwind-v4
   `@theme`/oklch era.
4. **Scope: foundations + full migration** of all 21 components.
5. **Enforcement: hard lint gate with escape hatch.** ESLint errors fail the
   App CI build; a documented `eslint-disable` line is the explicit exception.

## Token foundation (decision B)

Introduce a `globals.css` defining shadcn's semantic CSS variables as **HSL
channels**, and rewrite `tailwind.config.ts` so `colors` reference
`hsl(var(--token))`. **Each var's value is set to the current izba hex**, so the
migration is vocabulary-only and the app looks identical on day one. The win is
structural (one vocabulary + theming seam), not a redesign.

| izba today | hex | → shadcn token | Notes |
|---|---|---|---|
| `accent` | `#3b6fe0` | `--primary` (+ `--ring`) | **Naming collision:** shadcn's own `accent` token is the *hover highlight*, not the brand color. izba's brand `accent` becomes `primary`. |
| `accent.weak` | `#eaf0fd` | `--accent` | shadcn `accent` = subtle highlight; fits the weak tint. |
| `ink` | `#1b2230` | `--foreground`, `--card-foreground`, `--popover-foreground` | |
| `ink-2` | `#5a6473` | `--muted-foreground` | |
| `ink-3` | `#8a93a3` | **izba-extra** `--muted-foreground-2` | shadcn has one muted-foreground; extend rather than lose the 3rd level. |
| `surface` | `#ffffff` | `--card`, `--popover` | |
| `bg` | `#f6f7f9` | `--background` | |
| `rail` | `#fbfcfd` | `--sidebar` | shadcn sidebar tokens. |
| `line` | `#e4e7ec` | `--border`, `--input` | |
| `hover` | `#eef1f5` | `--muted` (+ `--secondary`) | |
| `warn` | `#d97706` | `--destructive` | **Convention deviation:** shadcn `destructive` is usually red; deliberately set to izba orange so "Remove" buttons keep their hue (no visual change). A separate red `--warning`/`--destructive` split is a deferred follow-up. |
| `ok` | `#16a34a` | **izba-extra** `--success` | not in shadcn's default set; preserved. |
| `off` | `#9aa3b2` | onto `--muted-foreground-2` / disabled states | |

Two deliberate calls: (1) `accent`→`primary` resolves the name clash with
shadcn's `accent`; (2) `--destructive` = izba **orange**, not red, so nothing
shifts visually. Standard shadcn vars also defined: `--ring`, `--input`,
`--radius`. `darkMode: ["class"]` + a `.dark { … }` block (light-only ship;
dark values may be filler).

## Primitive inventory

~8 shadcn primitives + 2 izba composites. All route through `cn()`
(clsx + tailwind-merge) so callers override safely without re-introducing
arbitrary classes.

| Primitive | Source | Replaces / covers |
|---|---|---|
| `Button` | shadcn `button` (CVA) | every button; variants `default`(primary)/`secondary`/`destructive`/`ghost`/`outline`, sizes `sm`/`default`/`icon`. Kills orange-vs-gray "remove" + thin-bar-vs-normal "add" drift. |
| `Input` | shadcn `input` | all text/number inputs (`rounded` vs `rounded-lg`, `py-1` vs `py-1.5` drift). |
| `Select` | shadcn `select` (Radix) | native `<select>` usages. |
| `Label` | shadcn `label` | form labels. |
| `Dialog` | shadcn `dialog` (Radix) | `ConfirmDialog`, `SeedDialog`, `NewSandbox` modal shell — **highest-risk** (focus trap / Esc / portal). |
| `Switch`/`Checkbox` | shadcn | toggles (`EnforceToggle`). |
| `Badge` | shadcn `badge` | port chips, volume-type/reference badges (`px-1.5` vs `px-2` drift). |
| `Card` | shadcn `card` | `Section` container, row-editor cards, dialog surfaces. |
| `SegmentedControl` | **izba-composite** on Radix `ToggleGroup`/`Tabs` | `VolumeRowEditor` type selector + `AccessPicker` (`py-1.5` vs `py-0.5` height drift). |
| `FieldRow`/`RowEditor` | **izba-composite** | the add/remove-row pattern in `VolumesTab`/`PortsTab`/`PolicyEditor` — bakes in one add-button style + one destructive remove-button style. |

## TDD strategy

**Boundary, stated honestly:** TDD cannot assert "looks right" — that is the
deferred pixel-diff's job. TDD here locks down structure, behavior, variant
mapping, and the lint rule. Test-first surfaces:

1. **Variant-mapping tests (pure function).** cva variant functions are pure:
   `expect(buttonVariants({ variant: 'destructive' })).toContain('text-destructive')`.
   The real guard — one definition of "destructive," pinned by a test.
2. **Contract tests (vitest + testing-library).** Each primitive: renders the
   right element, forwards `ref` + props, fires `onClick`, honors `disabled`,
   `asChild` where relevant. Behavior, not pixels.
3. **Lint-rule tests (`RuleTester`).** The no-raw-control rule gets valid/invalid
   fixtures — classic TDD.
4. **Regression oracle = the existing 27 component tests.** Each migrated
   component keeps its existing vitest test green. Migration rule: **preserve
   behavior assertions (text/role/click/state); update only style/class
   assertions.** A behavior-assertion change is a red flag — especially for the
   Radix `Dialog` swaps, where focus/Esc/portal behavior must be re-verified,
   not assumed.

The "does it actually look consistent" check is a single human/LLM visual pass
at the end over a now-uniform baseline.

## Enforcement (the mechanical gate)

ESLint is net-new to `app/`. Introduced scoped to consistency, not general lint
churn:

1. **Ban raw interactive primitives in `src/components/`** —
   `no-restricted-syntax` (or a small custom rule `izba/no-raw-control`) flags
   JSX `<button>`/`<input>`/`<select>`, directing to `@/components/ui/*`. The
   keystone: turns "is this styled consistently?" (invisible to screenshot
   review) into "does this file contain a raw `<button>`?" (a reliable grep).
   Escape hatch: `// eslint-disable-next-line izba/no-raw-control -- <reason>`.
2. **Ban Tailwind arbitrary values** — `eslint-plugin-tailwindcss`
   `no-arbitrary-value` (+ `no-custom-classname`, classname ordering). Kills
   `px-[13px]`, raw hex, off-scale spacing.
3. **Allowlist exceptions** — `ui/` primitive files and `*.test.tsx` are exempt
   from rule #1 (primitives *are* the raw elements; tests render freely).

**CI wiring:** add `"lint": "eslint . --max-warnings 0"` to `package.json` and a
`frontend lint` step in `.github/workflows/app.yml` between `npm ci` and
`build`, errors-fail-build (mirroring the clippy `-D warnings` posture). Rule #1
is itself TDD'd via `RuleTester`.

## Migration execution (subagent-driven, TDD)

Five phases. Foundation + primitives are mostly sequential (shared scaffolding);
the form sweep fans out.

- **Phase 0 — Foundation (sequential).** Install deps
  (`class-variance-authority`, `clsx`, `tailwind-merge`, `tailwindcss-animate`,
  `lucide-react`, Radix per-primitive), `components.json`, `cn()` util,
  `globals.css` with the HSL var mapping, rewrite `tailwind.config.ts` to
  shadcn-native + `darkMode: ["class"]`. Gate: `npm run build` green, app renders
  unchanged.
- **Phase 1 — Primitives (low parallelism, TDD each).** Build the ~8 shadcn + 2
  composite primitives. Each: test-first (variant-mapping + contract) →
  `shadcn add` + token adapt → green. Cap concurrency (~3) to avoid churn races.
  Dialog + SegmentedControl + RowEditor get extra care (behavior-bearing).
- **Phase 2 — Enforcement (sequential).** ESLint config + custom rule
  (RuleTester TDD) + plugin + `lint` script + CI step. Running lint now is
  **expected to fail** across the 21 unmigrated components — that failing list
  is the migration worklist.
- **Phase 3 — Form sweep (high parallelism, subagent per component).** Order:
  **leaf/shared first** (`StatusDot`, `Spinner`, `Section`, `Rail`, `TopBar`),
  then independent forms fan out one subagent per component (`NewSandbox`,
  `PolicyEditor`, `PortsTab`, `VolumesTab`, `VolumeRowEditor`, `AccessPicker`,
  `StorageView`, `Detail`, `NetlogView`, `LogsView`, `FirewallStatus`,
  `EnforceToggle`, `ConfirmDialog`, `SeedDialog`, `About`, `ShellPanel`). Each
  subagent's contract: migrate to primitives + new tokens; keep the existing
  vitest test green, updating **only** style/class assertions, never behavior
  assertions; `npm run lint` clean for that file; report any behavior-assertion
  change for review. Dialogs flagged highest-risk (Radix focus/Esc/portal) —
  verified, not assumed.
- **Phase 4 — Full gate + visual review.** All green: `build` + `test` +
  `playwright` + `lint` + `cargo fmt/clippy`. Then one human/LLM visual pass over
  a now-uniform baseline (handoff point for the deferred pixel-diff follow-up).

## Risks

1. **Radix dialog behavior divergence** (focus trap / Esc / portal) vs hand-rolled
   modals — mitigated by preserving dialog behavior tests and explicit re-verify.
2. **Existing tests asserting class strings** break by design — subagents update
   style assertions only; behavior assertions are sacrosanct.
3. **`accent`→`primary` rename touches many files** — caught mechanically by
   build + lint, not by eye.
4. **SonarCloud/Greptile gates** (per repo policy): app coverage must not regress
   (new primitive code needs vitest coverage fed into the scan); Security Rating
   ≥ A (no hardcoded test IPs, `npm ci` discipline, Readonly props). Greptile
   driven to 5/5 via `/greploop`.

## Verification

Per the App CI gate (`.github/workflows/app.yml`) plus the new lint step:

```sh
cd app
npm ci
npm run lint            # NEW — hard gate
npm run build           # tsc typecheck + vite
npm run test            # vitest (+ coverage for Sonar)
npm run e2e             # Playwright chromium + webkit
(cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
```

All green + SonarCloud quality gate pass + Greptile 5/5 before merge.
