# izba app shadcn-native component system — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the izba Tauri GUI's ad-hoc Tailwind class strings with a shadcn-native component layer + CSS-variable token system + a hard ESLint consistency gate, then migrate all 21 components onto it with no behavioral or visual regression.

**Architecture:** Introduce shadcn/ui (Radix + CVA) primitives under `app/src/components/ui/`, backed by HSL CSS-variable tokens (Tailwind-v3 era) whose values equal the current izba hex palette (so the app looks identical on day one). An ESLint rule bans raw `<button>/<input>/<select>` in feature components and bans Tailwind arbitrary values, turning visual consistency into a grep-able build check. Components migrate one-per-task, preserving behavior tests and updating only style assertions.

**Tech Stack:** React 18, Vite 5, Tailwind CSS 3.4, TypeScript 5.5, vitest + @testing-library/react, Playwright, shadcn/ui, Radix UI, class-variance-authority, clsx, tailwind-merge, ESLint 9 (flat config) + eslint-plugin-tailwindcss.

## Global Constraints

- **Scope is `app/` only** — the Tauri GUI, which is `exclude`d from the cargo workspace. Do NOT touch `izba-core`/`izba-proto`/CLI.
- **Tailwind v3 era** — project is on `tailwindcss@^3.4.0`. Use HSL channel CSS vars + `hsl(var(--token))` in `tailwind.config.ts` + `darkMode: ["class"]`. NEVER the Tailwind-v4 `@theme`/oklch convention.
- **No visual change on day one** — every CSS var value equals the current izba hex (table below). The migration is vocabulary + structure only.
- **Token map (verbatim, izba → shadcn token = hex):** `accent #3b6fe0 → --primary` (+ `--ring`); `accent.weak #eaf0fd → --accent`; `ink #1b2230 → --foreground/--card-foreground/--popover-foreground`; `ink-2 #5a6473 → --muted-foreground`; `ink-3 #8a93a3 → --muted-foreground-2` (izba-extra); `surface #ffffff → --card/--popover`; `bg #f6f7f9 → --background`; `rail #fbfcfd → --sidebar`; `line #e4e7ec → --border/--input`; `hover #eef1f5 → --muted/--secondary`; `warn #d97706 → --destructive` (deliberately orange, not red); `ok #16a34a → --success` (izba-extra); `off #9aa3b2 → disabled/--muted-foreground-2`.
- **`accent`→`primary` rename** — shadcn's own `accent` token is the hover-highlight, not the brand color; izba brand becomes `primary`.
- **TDD always** — failing test first, minimal impl, green, commit. Frequent commits.
- **Behavior assertions are sacrosanct** — during migration, update ONLY style/class assertions in existing tests; never weaken a text/role/click/state assertion. A required behavior-test change is a red flag to surface, not silently edit.
- **Path alias** — `@/*` resolves to `app/src/*` (added in Task 1) in both tsconfig and vite; shadcn imports use it.
- **CI gate** — App CI (`.github/workflows/app.yml`) must stay green: `npm run lint` (new) + `npm run build` + `npm run test` + `npm run e2e` + `cargo fmt/clippy/test`. SonarCloud quality gate (coverage on new code, Security Rating ≥ A) + Greptile 5/5 before merge.
- **All paths below are relative to repo root** unless prefixed; component files live in `app/src/components/`, primitives in `app/src/components/ui/`.

---

## Phase 0 — Foundation

### Task 1: Scaffolding — deps, path alias, `cn()` util, `components.json`

**Files:**
- Modify: `app/package.json` (dependencies + `lint` script)
- Modify: `app/tsconfig.json` (path alias)
- Modify: `app/vite.config.ts` (resolve alias)
- Create: `app/components.json` (shadcn config)
- Create: `app/src/lib/utils.ts` (`cn()`)
- Test: `app/src/test/cn.test.ts`

**Interfaces:**
- Produces: `cn(...inputs: ClassValue[]): string` from `@/lib/utils` — clsx + tailwind-merge; every primitive uses it.
- Produces: `@/*` alias → `app/src/*`.

- [ ] **Step 1: Install runtime + dev deps**

```bash
cd app
npm install class-variance-authority clsx tailwind-merge tailwindcss-animate lucide-react
npm install -D @types/node
```

- [ ] **Step 2: Add path alias to `app/tsconfig.json`**

Add to `compilerOptions`:

```json
    "baseUrl": ".",
    "paths": { "@/*": ["./src/*"] }
```

- [ ] **Step 3: Add resolve alias to `app/vite.config.ts`**

Add the import and `resolve` block:

```ts
import { fileURLToPath, URL } from "node:url";
// ...inside defineConfig({ ... }):
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
```

- [ ] **Step 4: Create `app/components.json`** (Tailwind-v3 shadcn config; `cssVariables: true`)

```json
{
  "$schema": "https://ui.shadcn.com/schema.json",
  "style": "new-york",
  "rsc": false,
  "tsx": true,
  "tailwind": {
    "config": "tailwind.config.ts",
    "css": "src/theme.css",
    "baseColor": "slate",
    "cssVariables": true,
    "prefix": ""
  },
  "aliases": {
    "components": "@/components",
    "utils": "@/lib/utils",
    "ui": "@/components/ui",
    "lib": "@/lib",
    "hooks": "@/hooks"
  },
  "iconLibrary": "lucide"
}
```

- [ ] **Step 5: Write the failing test for `cn()`** — `app/src/test/cn.test.ts`

```ts
import { describe, it, expect } from "vitest";
import { cn } from "@/lib/utils";

describe("cn", () => {
  it("merges class names", () => {
    expect(cn("a", "b")).toBe("a b");
  });
  it("dedupes conflicting tailwind utilities (last wins)", () => {
    expect(cn("px-2", "px-4")).toBe("px-4");
  });
  it("drops falsy values", () => {
    expect(cn("a", false && "b", undefined, "c")).toBe("a c");
  });
});
```

- [ ] **Step 6: Run it, verify it fails**

Run: `cd app && npx vitest run src/test/cn.test.ts`
Expected: FAIL — cannot resolve `@/lib/utils`.

- [ ] **Step 7: Create `app/src/lib/utils.ts`**

```ts
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
```

- [ ] **Step 8: Run it, verify it passes**

Run: `cd app && npx vitest run src/test/cn.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 9: Add the `lint` script to `app/package.json`** (placeholder until Task 13 wires the config; keep it harmless now)

In `"scripts"` add: `"lint": "eslint . --max-warnings 0"`

- [ ] **Step 10: Verify build still green**

Run: `cd app && npm run build`
Expected: tsc + vite succeed (alias resolves).

- [ ] **Step 11: Commit**

```bash
git add app/package.json app/package-lock.json app/tsconfig.json app/vite.config.ts app/components.json app/src/lib/utils.ts app/src/test/cn.test.ts
git commit -m "feat(app): shadcn scaffolding — deps, @/ alias, cn() util, components.json"
```

---

### Task 2: Token foundation — HSL CSS vars + shadcn-native `tailwind.config.ts`

**Files:**
- Modify: `app/src/theme.css` (CSS variables + base layer)
- Modify: `app/tailwind.config.ts` (rewrite `colors` to `hsl(var(--token))`, add `darkMode`, `borderRadius`, animate plugin)
- Test: `app/src/test/tokens.test.ts`

**Interfaces:**
- Produces: Tailwind color tokens `primary`, `primary-foreground`, `secondary`, `secondary-foreground`, `destructive`, `destructive-foreground`, `muted`, `muted-foreground`, `muted-foreground-2`, `accent`, `accent-foreground`, `background`, `foreground`, `card`, `card-foreground`, `popover`, `popover-foreground`, `border`, `input`, `ring`, `success`, `sidebar`. Plus `rounded-lg/md/sm` driven by `--radius`.
- **HSL channel reference (values = current izba hex converted to `H S% L%`):**
  `--background: 220 16% 97%` (#f6f7f9); `--foreground: 222 27% 15%` (#1b2230); `--card/--popover: 0 0% 100%` (#fff); `--primary: 220 73% 55%` (#3b6fe0); `--primary-foreground: 0 0% 100%`; `--secondary/--muted: 220 22% 95%` (#eef1f5); `--muted-foreground: 215 13% 40%` (#5a6473); `--muted-foreground-2: 218 13% 59%` (#8a93a3); `--accent: 222 81% 95%` (#eaf0fd); `--accent-foreground: 220 73% 55%`; `--destructive: 32 95% 44%` (#d97706); `--destructive-foreground: 0 0% 100%`; `--border/--input: 220 19% 91%` (#e4e7ec); `--ring: 220 73% 55%`; `--success: 142 71% 37%` (#16a34a); `--sidebar: 210 33% 99%` (#fbfcfd); `--radius: 0.5rem`.

- [ ] **Step 1: Write the failing test** — `app/src/test/tokens.test.ts` (asserts the Tailwind config exposes the shadcn token names so later primitives can rely on them)

```ts
import { describe, it, expect } from "vitest";
import config from "../../tailwind.config";

describe("tailwind tokens", () => {
  const colors = (config.theme?.extend?.colors ?? {}) as Record<string, unknown>;
  it.each([
    "primary", "secondary", "destructive", "muted", "accent",
    "background", "foreground", "card", "popover", "border", "input", "ring",
    "success", "sidebar", "muted-foreground-2",
  ])("exposes the %s token", (name) => {
    expect(colors[name]).toBeDefined();
  });
  it("primary references the CSS variable, not a hex literal", () => {
    expect(JSON.stringify(colors.primary)).toContain("var(--primary)");
  });
});
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd app && npx vitest run src/test/tokens.test.ts`
Expected: FAIL — tokens like `primary` undefined (config still has the old `accent`/`ink` palette).

- [ ] **Step 3: Rewrite `app/src/theme.css`** — keep the tailwind directives, add the `:root`/`.dark` var blocks + base layer

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    --background: 220 16% 97%;
    --foreground: 222 27% 15%;
    --card: 0 0% 100%;
    --card-foreground: 222 27% 15%;
    --popover: 0 0% 100%;
    --popover-foreground: 222 27% 15%;
    --primary: 220 73% 55%;
    --primary-foreground: 0 0% 100%;
    --secondary: 220 22% 95%;
    --secondary-foreground: 222 27% 15%;
    --muted: 220 22% 95%;
    --muted-foreground: 215 13% 40%;
    --muted-foreground-2: 218 13% 59%;
    --accent: 222 81% 95%;
    --accent-foreground: 220 73% 55%;
    --destructive: 32 95% 44%;
    --destructive-foreground: 0 0% 100%;
    --border: 220 19% 91%;
    --input: 220 19% 91%;
    --ring: 220 73% 55%;
    --success: 142 71% 37%;
    --sidebar: 210 33% 99%;
    --radius: 0.5rem;
  }
  /* Dark-mode seam only; light-only ship. Values are placeholders to be tuned
     when dark mode is delivered (see spec non-goals). */
  .dark {
    --background: 222 27% 11%;
    --foreground: 0 0% 98%;
    --card: 222 27% 14%;
    --card-foreground: 0 0% 98%;
    --popover: 222 27% 14%;
    --popover-foreground: 0 0% 98%;
    --primary: 220 73% 60%;
    --primary-foreground: 0 0% 100%;
    --secondary: 222 20% 20%;
    --secondary-foreground: 0 0% 98%;
    --muted: 222 20% 20%;
    --muted-foreground: 215 13% 65%;
    --muted-foreground-2: 218 13% 55%;
    --accent: 222 30% 24%;
    --accent-foreground: 0 0% 98%;
    --destructive: 32 95% 50%;
    --destructive-foreground: 0 0% 100%;
    --border: 222 20% 24%;
    --input: 222 20% 24%;
    --ring: 220 73% 60%;
    --success: 142 60% 45%;
    --sidebar: 222 27% 13%;
  }
}

:root { color-scheme: light; }
html, body, #root { height: 100%; margin: 0; }
body {
  background: hsl(var(--background));
  color: hsl(var(--foreground));
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
  -webkit-font-smoothing: antialiased;
}
```

- [ ] **Step 4: Rewrite `app/tailwind.config.ts`** to the shadcn-native (Tailwind v3) convention

```ts
import type { Config } from "tailwindcss";
import animate from "tailwindcss-animate";

export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        "muted-foreground-2": "hsl(var(--muted-foreground-2))",
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        success: "hsl(var(--success))",
        sidebar: "hsl(var(--sidebar))",
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      keyframes: {
        "accordion-down": { from: { height: "0" }, to: { height: "var(--radix-accordion-content-height)" } },
        "accordion-up": { from: { height: "var(--radix-accordion-content-height)" }, to: { height: "0" } },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
      },
    },
  },
  plugins: [animate],
} satisfies Config;
```

- [ ] **Step 5: Run the test, verify it passes**

Run: `cd app && npx vitest run src/test/tokens.test.ts`
Expected: PASS.

- [ ] **Step 6: Verify the full build is green and nothing references dead tokens yet**

Run: `cd app && npm run build`
Expected: SUCCESS. (Components still use old `bg-accent`/`text-ink`/`border-line` classes — those Tailwind classes are now UNDEFINED, so they render as no-ops but DO NOT fail the build. The visual fix lands during migration; the build does not break.)

- [ ] **Step 7: Commit**

```bash
git add app/src/theme.css app/tailwind.config.ts app/src/test/tokens.test.ts
git commit -m "feat(app): shadcn-native HSL token system (values = current izba palette)"
```

> **Note for the executor:** after Task 2 the old class names (`bg-accent`, `text-ink-2`, `border-line`, `bg-warn`, `text-warn`, `bg-surface`, `bg-hover`, `bg-rail`, `text-ink-3`, `text-off`, `bg-bg`) no longer map to anything. The app will look unstyled in spots until each component is migrated (Phase 3). This is expected and temporary; do not "fix" it by re-adding the old tokens.

---

## Phase 1 — Primitives

> **Recipe for every primitive task:** (a) write the failing variant-mapping + contract test using `@/components/ui/<name>`; (b) run it, confirm fail; (c) create the primitive (adapted shadcn source — token classes from the map, `cn()` for overrides, `React.forwardRef`); (d) run, confirm pass; (e) commit. Variant tests assert on the resolved class string of the cva function; contract tests assert element/props/handlers via testing-library. Cap parallelism at ~3 (shared `cn()`/conventions).

### Task 3: `Button` primitive

**Files:**
- Create: `app/src/components/ui/button.tsx`
- Test: `app/src/test/ui/button.test.tsx`

**Interfaces:**
- Produces: `Button` (forwardRef `<button>`), `buttonVariants({ variant, size })`. Variants: `variant: "default" | "secondary" | "destructive" | "outline" | "ghost"`, `size: "default" | "sm" | "icon"`. `asChild?: boolean` via Radix Slot. Default `variant="default"` (primary), `size="default"`.

- [ ] **Step 1: Install Radix Slot**

```bash
cd app && npm install @radix-ui/react-slot
```

- [ ] **Step 2: Write the failing test** — `app/src/test/ui/button.test.tsx`

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Button, buttonVariants } from "@/components/ui/button";

describe("Button", () => {
  it("renders a <button> with children", () => {
    render(<Button>Save</Button>);
    expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
  });
  it("fires onClick", () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Go</Button>);
    fireEvent.click(screen.getByRole("button", { name: "Go" }));
    expect(onClick).toHaveBeenCalledOnce();
  });
  it("honors disabled", () => {
    render(<Button disabled>Nope</Button>);
    expect(screen.getByRole("button", { name: "Nope" })).toBeDisabled();
  });
  it("maps the destructive variant to the destructive token (single source of truth)", () => {
    expect(buttonVariants({ variant: "destructive" })).toContain("destructive");
  });
  it("default variant is primary", () => {
    expect(buttonVariants({})).toContain("bg-primary");
  });
  it("renders as child element when asChild", () => {
    render(<Button asChild><a href="/x">link</a></Button>);
    const link = screen.getByRole("link", { name: "link" });
    expect(link).toHaveClass("bg-primary");
  });
});
```

- [ ] **Step 3: Run it, verify it fails**

Run: `cd app && npx vitest run src/test/ui/button.test.tsx`
Expected: FAIL — `@/components/ui/button` missing.

- [ ] **Step 4: Create `app/src/components/ui/button.tsx`** (shadcn button, tokens from the map)

```tsx
import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground shadow-sm hover:bg-primary/90 font-semibold",
        secondary: "border border-input bg-transparent hover:bg-muted",
        destructive: "border border-destructive/40 text-destructive hover:bg-destructive/5",
        outline: "border border-input bg-transparent hover:bg-muted",
        ghost: "text-muted-foreground hover:bg-muted",
      },
      size: {
        default: "px-3 py-1.5",
        sm: "px-2 py-1 text-xs",
        icon: "h-8 w-8",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />
    );
  },
);
Button.displayName = "Button";

export { Button, buttonVariants };
```

- [ ] **Step 5: Run it, verify it passes**

Run: `cd app && npx vitest run src/test/ui/button.test.tsx`
Expected: PASS (6 tests).

- [ ] **Step 6: Commit**

```bash
git add app/src/components/ui/button.tsx app/src/test/ui/button.test.tsx app/package.json app/package-lock.json
git commit -m "feat(app): Button primitive (cva variants, single source of truth)"
```

---

### Task 4: `Input` + `Label` primitives

**Files:**
- Create: `app/src/components/ui/input.tsx`, `app/src/components/ui/label.tsx`
- Test: `app/src/test/ui/input.test.tsx`

**Interfaces:**
- Produces: `Input` (forwardRef `<input>`, full token styling), `Label` (forwardRef `<label>` on Radix Label).

- [ ] **Step 1: Install Radix Label**

```bash
cd app && npm install @radix-ui/react-label
```

- [ ] **Step 2: Write the failing test** — `app/src/test/ui/input.test.tsx`

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

describe("Input", () => {
  it("renders and accepts typing", () => {
    const onChange = vi.fn();
    render(<Input placeholder="name" onChange={onChange} />);
    const el = screen.getByPlaceholderText("name");
    fireEvent.change(el, { target: { value: "web" } });
    expect(onChange).toHaveBeenCalled();
  });
  it("honors disabled", () => {
    render(<Input placeholder="p" disabled />);
    expect(screen.getByPlaceholderText("p")).toBeDisabled();
  });
  it("uses the border token", () => {
    render(<Input placeholder="p" />);
    expect(screen.getByPlaceholderText("p").className).toContain("border-input");
  });
  it("Label associates with a control", () => {
    render(<><Label htmlFor="x">Name</Label><Input id="x" /></>);
    expect(screen.getByText("Name")).toHaveAttribute("for", "x");
  });
});
```

- [ ] **Step 3: Run it, verify it fails**

Run: `cd app && npx vitest run src/test/ui/input.test.tsx`
Expected: FAIL — modules missing.

- [ ] **Step 4: Create `app/src/components/ui/input.tsx`**

```tsx
import * as React from "react";
import { cn } from "@/lib/utils";

const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, type, ...props }, ref) => (
    <input
      type={type}
      ref={ref}
      className={cn(
        "w-full min-w-0 rounded-lg border border-input bg-card px-2 py-1.5 text-sm",
        "placeholder:text-muted-foreground-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        "disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";
export { Input };
```

- [ ] **Step 5: Create `app/src/components/ui/label.tsx`**

```tsx
import * as React from "react";
import * as LabelPrimitive from "@radix-ui/react-label";
import { cn } from "@/lib/utils";

const Label = React.forwardRef<
  React.ElementRef<typeof LabelPrimitive.Root>,
  React.ComponentPropsWithoutRef<typeof LabelPrimitive.Root>
>(({ className, ...props }, ref) => (
  <LabelPrimitive.Root
    ref={ref}
    className={cn("text-sm font-medium text-foreground", className)}
    {...props}
  />
));
Label.displayName = "Label";
export { Label };
```

- [ ] **Step 6: Run it, verify it passes**

Run: `cd app && npx vitest run src/test/ui/input.test.tsx`
Expected: PASS (4 tests).

- [ ] **Step 7: Commit**

```bash
git add app/src/components/ui/input.tsx app/src/components/ui/label.tsx app/src/test/ui/input.test.tsx app/package.json app/package-lock.json
git commit -m "feat(app): Input + Label primitives"
```

---

### Task 5: `Select` primitive

**Files:**
- Create: `app/src/components/ui/select.tsx`
- Test: `app/src/test/ui/select.test.tsx`

**Interfaces:**
- Produces: `Select`, `SelectTrigger`, `SelectValue`, `SelectContent`, `SelectItem` (Radix Select re-exports, token-styled).

- [ ] **Step 1: Install Radix Select + icons (already have lucide)**

```bash
cd app && npm install @radix-ui/react-select
```

- [ ] **Step 2: Write the failing test** — `app/src/test/ui/select.test.tsx`

```tsx
import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";

describe("Select", () => {
  it("renders a combobox trigger with the placeholder", () => {
    render(
      <Select>
        <SelectTrigger aria-label="kind"><SelectValue placeholder="pick" /></SelectTrigger>
        <SelectContent>
          <SelectItem value="a">A</SelectItem>
        </SelectContent>
      </Select>,
    );
    expect(screen.getByRole("combobox", { name: "kind" })).toBeInTheDocument();
    expect(screen.getByText("pick")).toBeInTheDocument();
  });
});
```

- [ ] **Step 3: Run it, verify it fails**

Run: `cd app && npx vitest run src/test/ui/select.test.tsx`
Expected: FAIL — module missing.

- [ ] **Step 4: Create `app/src/components/ui/select.tsx`** (standard shadcn select; replace `border-input`/`bg-popover`/`text-popover-foreground` tokens — they already match the map). Use the canonical shadcn `new-york` select implementation with `lucide-react` `Check`, `ChevronDown`, `ChevronUp` icons and `cn()`. Keep trigger classes: `"flex h-9 w-full items-center justify-between rounded-lg border border-input bg-card px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"`; content classes use `bg-popover text-popover-foreground border border-border`; item focus uses `focus:bg-muted`.

> Executor: generate the body from the current shadcn `select` (new-york) source, swapping only the color utility classes to the tokens named above. Do not introduce arbitrary values.

- [ ] **Step 5: Run it, verify it passes**

Run: `cd app && npx vitest run src/test/ui/select.test.tsx`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/src/components/ui/select.tsx app/src/test/ui/select.test.tsx app/package.json app/package-lock.json
git commit -m "feat(app): Select primitive (Radix)"
```

---

### Task 6: `Card` + `Badge` primitives

**Files:**
- Create: `app/src/components/ui/card.tsx`, `app/src/components/ui/badge.tsx`
- Test: `app/src/test/ui/card.test.tsx`

**Interfaces:**
- Produces: `Card`, `CardHeader`, `CardTitle`, `CardContent`, `CardFooter` (token-styled `<div>`s); `Badge` + `badgeVariants({ variant })` with `variant: "default" | "secondary" | "warning" | "success"`.

- [ ] **Step 1: Write the failing test** — `app/src/test/ui/card.test.tsx`

```tsx
import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { Card, CardTitle, CardContent } from "@/components/ui/card";
import { Badge, badgeVariants } from "@/components/ui/badge";

describe("Card + Badge", () => {
  it("renders card title and content", () => {
    render(<Card><CardTitle>Storage</CardTitle><CardContent>body</CardContent></Card>);
    expect(screen.getByText("Storage")).toBeInTheDocument();
    expect(screen.getByText("body")).toBeInTheDocument();
  });
  it("card uses the card surface token", () => {
    const { container } = render(<Card>x</Card>);
    expect(container.firstChild).toHaveClass("bg-card");
  });
  it("warning badge maps to the destructive/warn token", () => {
    expect(badgeVariants({ variant: "warning" })).toContain("destructive");
  });
  it("renders badge text", () => {
    render(<Badge>persistent</Badge>);
    expect(screen.getByText("persistent")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd app && npx vitest run src/test/ui/card.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Create `app/src/components/ui/card.tsx`**

```tsx
import * as React from "react";
import { cn } from "@/lib/utils";

const Card = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("rounded-lg border border-border bg-card text-card-foreground", className)} {...props} />
  ),
);
Card.displayName = "Card";

const CardHeader = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("flex flex-col gap-1 p-3", className)} {...props} />
  ),
);
CardHeader.displayName = "CardHeader";

const CardTitle = React.forwardRef<HTMLHeadingElement, React.HTMLAttributes<HTMLHeadingElement>>(
  ({ className, ...props }, ref) => (
    <h3 ref={ref} className={cn("font-semibold", className)} {...props} />
  ),
);
CardTitle.displayName = "CardTitle";

const CardContent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("p-3 pt-0", className)} {...props} />
  ),
);
CardContent.displayName = "CardContent";

const CardFooter = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
  ({ className, ...props }, ref) => (
    <div ref={ref} className={cn("flex items-center gap-2 p-3 pt-0", className)} {...props} />
  ),
);
CardFooter.displayName = "CardFooter";

export { Card, CardHeader, CardTitle, CardContent, CardFooter };
```

- [ ] **Step 4: Create `app/src/components/ui/badge.tsx`**

```tsx
import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded px-1.5 py-0.5 text-xs font-semibold",
  {
    variants: {
      variant: {
        default: "bg-muted text-foreground",
        secondary: "bg-muted text-muted-foreground font-mono",
        warning: "bg-destructive/10 text-destructive",
        success: "bg-success/10 text-success",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
```

- [ ] **Step 5: Run it, verify it passes**

Run: `cd app && npx vitest run src/test/ui/card.test.tsx`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add app/src/components/ui/card.tsx app/src/components/ui/badge.tsx app/src/test/ui/card.test.tsx
git commit -m "feat(app): Card + Badge primitives"
```

---

### Task 7: `Switch` primitive

**Files:**
- Create: `app/src/components/ui/switch.tsx`
- Test: `app/src/test/ui/switch.test.tsx`

**Interfaces:**
- Produces: `Switch` (Radix Switch, controlled via `checked`/`onCheckedChange`).

- [ ] **Step 1: Install Radix Switch**

```bash
cd app && npm install @radix-ui/react-switch
```

- [ ] **Step 2: Write the failing test** — `app/src/test/ui/switch.test.tsx`

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Switch } from "@/components/ui/switch";

describe("Switch", () => {
  it("renders a switch and toggles", () => {
    const onCheckedChange = vi.fn();
    render(<Switch aria-label="enforce" checked={false} onCheckedChange={onCheckedChange} />);
    fireEvent.click(screen.getByRole("switch", { name: "enforce" }));
    expect(onCheckedChange).toHaveBeenCalledWith(true);
  });
});
```

- [ ] **Step 3: Run it, verify it fails**

Run: `cd app && npx vitest run src/test/ui/switch.test.tsx`
Expected: FAIL.

- [ ] **Step 4: Create `app/src/components/ui/switch.tsx`** (canonical shadcn switch; tokens: track `data-[state=checked]:bg-primary data-[state=unchecked]:bg-input`, thumb `bg-card`). Generate from current shadcn `switch` source, swapping color classes to these tokens, `cn()` preserved, `forwardRef`.

- [ ] **Step 5: Run it, verify it passes**

Run: `cd app && npx vitest run src/test/ui/switch.test.tsx`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/src/components/ui/switch.tsx app/src/test/ui/switch.test.tsx app/package.json app/package-lock.json
git commit -m "feat(app): Switch primitive (Radix)"
```

---

### Task 8: `Dialog` primitive (highest-risk — Radix focus/Esc/portal)

**Files:**
- Create: `app/src/components/ui/dialog.tsx`
- Test: `app/src/test/ui/dialog.test.tsx`

**Interfaces:**
- Produces: `Dialog`, `DialogTrigger`, `DialogContent`, `DialogHeader`, `DialogTitle`, `DialogDescription`, `DialogFooter`, `DialogClose` (Radix Dialog). `DialogContent` sets `role="dialog"` + `aria-modal` automatically; Esc + overlay-click close via `onOpenChange`.

- [ ] **Step 1: Install Radix Dialog**

```bash
cd app && npm install @radix-ui/react-dialog
```

- [ ] **Step 2: Write the failing test** — `app/src/test/ui/dialog.test.tsx`

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Dialog, DialogContent, DialogTitle, DialogClose } from "@/components/ui/dialog";

describe("Dialog", () => {
  it("renders content with an accessible dialog role and title when open", () => {
    render(
      <Dialog open onOpenChange={() => {}}>
        <DialogContent><DialogTitle>Remove web?</DialogTitle></DialogContent>
      </Dialog>,
    );
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("Remove web?")).toBeInTheDocument();
  });
  it("requests close via DialogClose", () => {
    const onOpenChange = vi.fn();
    render(
      <Dialog open onOpenChange={onOpenChange}>
        <DialogContent>
          <DialogTitle>t</DialogTitle>
          <DialogClose>Cancel</DialogClose>
        </DialogContent>
      </Dialog>,
    );
    fireEvent.click(screen.getByText("Cancel"));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
```

- [ ] **Step 3: Run it, verify it fails**

Run: `cd app && npx vitest run src/test/ui/dialog.test.tsx`
Expected: FAIL.

- [ ] **Step 4: Create `app/src/components/ui/dialog.tsx`** (canonical shadcn dialog new-york source). Token swaps: overlay `bg-black/30`; content `bg-card border border-border rounded-xl p-5 shadow-xl`; close icon `text-muted-foreground`. Include the `lucide-react` `X` close button inside `DialogContent`. Keep all Radix portal/overlay/focus behavior unchanged.

> Executor: use the current shadcn `dialog` (new-york) implementation verbatim except for the color utility classes above. This preserves focus-trap, Esc, and scroll-lock behavior that the migrated `ConfirmDialog`/`SeedDialog`/`NewSandbox` rely on.

- [ ] **Step 5: Run it, verify it passes**

Run: `cd app && npx vitest run src/test/ui/dialog.test.tsx`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add app/src/components/ui/dialog.tsx app/src/test/ui/dialog.test.tsx app/package.json app/package-lock.json
git commit -m "feat(app): Dialog primitive (Radix, focus/Esc/portal preserved)"
```

---

### Task 9: `SegmentedControl` composite

**Files:**
- Create: `app/src/components/ui/segmented-control.tsx`
- Test: `app/src/test/ui/segmentedControl.test.tsx`

**Interfaces:**
- Produces: `SegmentedControl<T extends string>({ value, onChange, options, "aria-label" })` where `options: { value: T; label: string }[]`. One canonical height/active style for ALL segmented pickers (kills the `VolumeRowEditor` `py-1.5` vs `AccessPicker` `py-0.5` drift). Built on Radix `ToggleGroup` (single-select).

- [ ] **Step 1: Install Radix ToggleGroup**

```bash
cd app && npm install @radix-ui/react-toggle-group
```

- [ ] **Step 2: Write the failing test** — `app/src/test/ui/segmentedControl.test.tsx`

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { SegmentedControl } from "@/components/ui/segmented-control";

describe("SegmentedControl", () => {
  const opts = [{ value: "read", label: "read" }, { value: "read-write", label: "read-write" }];
  it("renders all options and marks the active one pressed", () => {
    render(<SegmentedControl aria-label="access" value="read" onChange={() => {}} options={opts} />);
    expect(screen.getByRole("radio", { name: "read" })).toHaveAttribute("data-state", "on");
  });
  it("fires onChange with the chosen value", () => {
    const onChange = vi.fn();
    render(<SegmentedControl aria-label="access" value="read" onChange={onChange} options={opts} />);
    fireEvent.click(screen.getByRole("radio", { name: "read-write" }));
    expect(onChange).toHaveBeenCalledWith("read-write");
  });
});
```

- [ ] **Step 3: Run it, verify it fails**

Run: `cd app && npx vitest run src/test/ui/segmentedControl.test.tsx`
Expected: FAIL.

- [ ] **Step 4: Create `app/src/components/ui/segmented-control.tsx`**

```tsx
import * as React from "react";
import * as ToggleGroup from "@radix-ui/react-toggle-group";
import { cn } from "@/lib/utils";

export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
}

export interface SegmentedControlProps<T extends string> {
  value: T;
  onChange: (value: T) => void;
  options: SegmentedOption<T>[];
  "aria-label": string;
  className?: string;
}

export function SegmentedControl<T extends string>({
  value,
  onChange,
  options,
  className,
  ...aria
}: SegmentedControlProps<T>) {
  return (
    <ToggleGroup.Root
      type="single"
      value={value}
      onValueChange={(v) => v && onChange(v as T)}
      aria-label={aria["aria-label"]}
      className={cn("inline-flex gap-1 rounded-lg border border-input p-0.5", className)}
    >
      {options.map((o) => (
        <ToggleGroup.Item
          key={o.value}
          value={o.value}
          className={cn(
            "rounded px-2 py-1 text-xs font-semibold transition-colors",
            "text-muted-foreground hover:bg-muted",
            "data-[state=on]:bg-primary data-[state=on]:text-primary-foreground",
          )}
        >
          {o.label}
        </ToggleGroup.Item>
      ))}
    </ToggleGroup.Root>
  );
}
```

- [ ] **Step 5: Run it, verify it passes**

Run: `cd app && npx vitest run src/test/ui/segmentedControl.test.tsx`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add app/src/components/ui/segmented-control.tsx app/src/test/ui/segmentedControl.test.tsx app/package.json app/package-lock.json
git commit -m "feat(app): SegmentedControl composite (one canonical picker style)"
```

---

### Task 10: `FieldRow` / `RowEditor` composite

**Files:**
- Create: `app/src/components/ui/row-editor.tsx`
- Test: `app/src/test/ui/rowEditor.test.tsx`

**Interfaces:**
- Produces:
  - `RowList({ children })` — vertical stack container for editable rows (`flex flex-col gap-2`).
  - `RowCard({ children, className })` — one row container (`flex items-center gap-2 rounded-lg border border-border p-2`).
  - `AddRowButton({ onClick, children, disabled })` — THE canonical add-row control (delegates to `Button variant="secondary" size="sm"` with `justify-self-start`); kills the thin-bar-vs-normal "add" drift.
  - `RemoveRowButton({ onClick, "aria-label" })` — THE canonical destructive remove control (delegates to `Button variant="destructive" size="sm"`); kills the orange-vs-gray "remove" drift.

- [ ] **Step 1: Write the failing test** — `app/src/test/ui/rowEditor.test.tsx`

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { RowList, RowCard, AddRowButton, RemoveRowButton } from "@/components/ui/row-editor";

describe("RowEditor", () => {
  it("AddRowButton fires onClick and renders its label", () => {
    const onClick = vi.fn();
    render(<AddRowButton onClick={onClick}>Add volume</AddRowButton>);
    fireEvent.click(screen.getByRole("button", { name: "Add volume" }));
    expect(onClick).toHaveBeenCalledOnce();
  });
  it("RemoveRowButton is destructive-styled and labelled", () => {
    const onClick = vi.fn();
    render(<RemoveRowButton aria-label="remove" onClick={onClick} />);
    const btn = screen.getByRole("button", { name: "remove" });
    expect(btn.className).toContain("destructive");
    fireEvent.click(btn);
    expect(onClick).toHaveBeenCalledOnce();
  });
  it("RowList + RowCard render children", () => {
    render(<RowList><RowCard>row-1</RowCard></RowList>);
    expect(screen.getByText("row-1")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd app && npx vitest run src/test/ui/rowEditor.test.tsx`
Expected: FAIL.

- [ ] **Step 3: Create `app/src/components/ui/row-editor.tsx`**

```tsx
import * as React from "react";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function RowList({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("flex flex-col gap-2", className)}>{children}</div>;
}

export function RowCard({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("flex items-center gap-2 rounded-lg border border-border p-2", className)}>
      {children}
    </div>
  );
}

export function AddRowButton({
  onClick,
  children,
  disabled,
}: {
  onClick: () => void;
  children: React.ReactNode;
  disabled?: boolean;
}) {
  return (
    <Button type="button" variant="secondary" size="sm" onClick={onClick} disabled={disabled} className="justify-self-start self-start">
      {children}
    </Button>
  );
}

export function RemoveRowButton({
  onClick,
  disabled,
  ...aria
}: {
  onClick: () => void;
  disabled?: boolean;
  "aria-label": string;
}) {
  return (
    <Button type="button" variant="destructive" size="sm" onClick={onClick} disabled={disabled} aria-label={aria["aria-label"]}>
      <X className="h-3.5 w-3.5" />
    </Button>
  );
}
```

- [ ] **Step 4: Run it, verify it passes**

Run: `cd app && npx vitest run src/test/ui/rowEditor.test.tsx`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add app/src/components/ui/row-editor.tsx app/src/test/ui/rowEditor.test.tsx
git commit -m "feat(app): RowEditor composite (canonical add/remove-row controls)"
```

---

## Phase 2 — Enforcement

### Task 11: ESLint flat config + consistency rules + CI gate

**Files:**
- Create: `app/eslint.config.js`
- Create: `app/eslint-rules/no-raw-control.js` (custom rule)
- Test: `app/src/test/eslint/no-raw-control.test.js`
- Modify: `app/package.json` (devDeps; `lint` script already added in Task 1)
- Modify: `.github/workflows/app.yml` (add lint step)

**Interfaces:**
- Produces: `npm run lint` failing (error) on raw `<button>/<input>/<select>` in `src/components/**` (except `src/components/ui/**` and `*.test.tsx`) and on Tailwind arbitrary values. Custom rule id: `izba/no-raw-control`.

- [ ] **Step 1: Install ESLint + plugins**

```bash
cd app && npm install -D eslint @eslint/js typescript-eslint eslint-plugin-react eslint-plugin-tailwindcss globals
```

- [ ] **Step 2: Write the failing RuleTester test** — `app/src/test/eslint/no-raw-control.test.js`

```js
import { RuleTester } from "eslint";
import parser from "@typescript-eslint/parser";
import { describe, it } from "vitest";
import rule from "../../../eslint-rules/no-raw-control.js";

const ruleTester = new RuleTester({
  languageOptions: { parser, parserOptions: { ecmaFeatures: { jsx: true } } },
});

describe("no-raw-control", () => {
  it("passes RuleTester cases", () => {
    ruleTester.run("no-raw-control", rule, {
      valid: [
        { code: "const x = <Button>ok</Button>;" },
        { code: "const x = <div className='a' />;" },
      ],
      invalid: [
        { code: "const x = <button>no</button>;", errors: [{ messageId: "rawControl" }] },
        { code: "const x = <input />;", errors: [{ messageId: "rawControl" }] },
        { code: "const x = <select />;", errors: [{ messageId: "rawControl" }] },
      ],
    });
  });
});
```

- [ ] **Step 3: Run it, verify it fails**

Run: `cd app && npx vitest run src/test/eslint/no-raw-control.test.js`
Expected: FAIL — rule module missing.

- [ ] **Step 4: Create `app/eslint-rules/no-raw-control.js`**

```js
const BANNED = new Set(["button", "input", "select"]);

/** @type {import("eslint").Rule.RuleModule} */
export default {
  meta: {
    type: "problem",
    docs: { description: "Disallow raw interactive elements; use @/components/ui/* primitives." },
    messages: {
      rawControl:
        "Use the shared @/components/ui primitive instead of a raw <{{name}}>. (escape hatch: // eslint-disable-next-line izba/no-raw-control -- <reason>)",
    },
    schema: [],
  },
  create(context) {
    return {
      JSXOpeningElement(node) {
        const el = node.name;
        if (el.type === "JSXIdentifier" && BANNED.has(el.name)) {
          context.report({ node, messageId: "rawControl", data: { name: el.name } });
        }
      },
    };
  },
};
```

- [ ] **Step 5: Run it, verify it passes**

Run: `cd app && npx vitest run src/test/eslint/no-raw-control.test.js`
Expected: PASS.

- [ ] **Step 6: Create `app/eslint.config.js`** (flat config; scopes the custom rule to feature components, exempts `ui/` + tests; enables tailwind arbitrary-value ban)

```js
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import react from "eslint-plugin-react";
import tailwind from "eslint-plugin-tailwindcss";
import globals from "globals";
import noRawControl from "./eslint-rules/no-raw-control.js";

export default tseslint.config(
  { ignores: ["dist", "coverage", "playwright-report", "src-tauri", "eslint-rules", "e2e"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser } },
    plugins: { react, tailwindcss: tailwind, izba: { rules: { "no-raw-control": noRawControl } } },
    settings: { tailwindcss: { config: "tailwind.config.ts", callees: ["cn", "cva"] } },
    rules: {
      "tailwindcss/no-arbitrary-value": "error",
      "tailwindcss/no-custom-classname": "off",
      "tailwindcss/classnames-order": "warn",
    },
  },
  {
    files: ["src/components/**/*.tsx"],
    ignores: ["src/components/ui/**", "**/*.test.tsx"],
    rules: { "izba/no-raw-control": "error" },
  },
);
```

- [ ] **Step 7: Confirm lint runs and FAILS loudly on the unmigrated app (this is the migration worklist)**

Run: `cd app && npm run lint`
Expected: FAIL — many `izba/no-raw-control` + `tailwindcss/no-arbitrary-value` errors across `src/components/*`. Capture the list; it drives Phase 3.

- [ ] **Step 8: Add the lint step to `.github/workflows/app.yml`** — insert between `npm ci` and `frontend build (tsc typecheck + vite)` in the `app-linux` job:

```yaml
      - name: frontend lint (consistency gate)
        working-directory: app
        run: npm run lint
```

- [ ] **Step 9: Commit**

```bash
git add app/eslint.config.js app/eslint-rules/no-raw-control.js app/src/test/eslint/no-raw-control.test.js app/package.json app/package-lock.json .github/workflows/app.yml
git commit -m "feat(app): ESLint consistency gate — ban raw controls + arbitrary values"
```

> **Note:** CI is now RED until Phase 3 completes. That is intended — the gate exists; the sweep makes it green. Do not push to a PR expecting green until Phase 3 + Task 28 are done. (Local pushes to the feature branch are fine.)

---

## Phase 3 — Migration sweep (subagent per component)

> **Migration recipe (applies to every Task 12–27):**
> 1. Read the current component file.
> 2. Replace raw `<button>` → `Button` (pick variant: primary CTA `default`; neutral/secondary `secondary`; destructive/remove `destructive`; bare text `ghost`; row remove → `RemoveRowButton`; row add → `AddRowButton`). Map `sm` size to the small `text-xs` buttons.
> 3. Replace raw `<input>` → `Input`; raw `<select>` → `Select*`; toggles → `Switch`; segmented pickers → `SegmentedControl`; badges/chips → `Badge`; section/row/dialog surfaces → `Card`/`RowCard`/`Dialog`.
> 4. Replace dead token classes with shadcn tokens: `bg-surface→bg-card`, `bg-bg→bg-background`, `bg-rail→bg-sidebar`, `text-ink→text-foreground`, `text-ink-2→text-muted-foreground`, `text-ink-3→text-muted-foreground-2`, `text-off→text-muted-foreground-2`, `border-line→border-border`, `bg-hover→bg-muted` / `hover:bg-hover→hover:bg-muted`, `bg-accent→bg-primary`, `text-white→text-primary-foreground` (on primary), `bg-warn→bg-destructive`, `text-warn→text-destructive`, `border-warn/40→border-destructive/40`, `bg-warn/10→bg-destructive/10`, `text-ok→text-success`, `accent.weak`/`bg-accent-weak→bg-accent`.
> 5. Remove now-redundant per-element style strings that the primitive already encodes; keep only layout classes (`flex`, `grid`, `gap-*`, width).
> 6. Run the component's existing test: `npx vitest run src/test/<name>.test.tsx`. Keep it green. Update ONLY style/class assertions; NEVER weaken behavior assertions (text/role/click/state). If a behavior assertion must change, STOP and surface it.
> 7. Run `npx eslint src/components/<File>.tsx` → 0 errors for that file.
> 8. Commit: `git commit -m "refactor(app): migrate <Component> to shadcn primitives"`.
>
> No arbitrary Tailwind values may be introduced. If a genuine one-off is unavoidable, use the documented escape hatch comment and note it in the task report.

### Task 12: Migrate leaf/shared components (`StatusDot`, `Spinner`, `Section`, `Rail`, `TopBar`)

**Files:** Modify `app/src/components/{StatusDot,Spinner,Section,Rail,TopBar}.tsx`; keep `app/src/test/{statusDot,section,rail,topbar}.test.tsx` green.

- [ ] **Step 1:** Apply the migration recipe to each of the five files. `Section` → `Card` surface; `Rail`/`TopBar` → `bg-sidebar`/`bg-card` + `Button variant="ghost"` for nav/icon actions; `StatusDot`/`Spinner` are color-token-only swaps (`text-ink-*`, `bg-ok`→`text-success`, etc.).
- [ ] **Step 2:** `cd app && npx vitest run src/test/statusDot.test.tsx src/test/section.test.tsx src/test/rail.test.tsx src/test/topbar.test.tsx` → PASS (style assertions updated only).
- [ ] **Step 3:** `cd app && npx eslint src/components/StatusDot.tsx src/components/Spinner.tsx src/components/Section.tsx src/components/Rail.tsx src/components/TopBar.tsx` → 0 errors.
- [ ] **Step 4:** Commit: `git commit -m "refactor(app): migrate leaf/shared components to shadcn primitives + tokens"`.

### Task 13: Migrate `ConfirmDialog` (worked example)

**Files:** Modify `app/src/components/ConfirmDialog.tsx`; keep `app/src/test/confirmDialog.test.tsx` green.

**Worked target** (apply recipe; the hand-rolled overlay/`<button>`s become `Dialog` + `Button`; `danger` chooses `destructive` vs `default`):

```tsx
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

interface Props {
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({ title, message, confirmLabel, danger, onConfirm, onCancel }: Props) {
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onCancel(); }}>
      <DialogContent className="w-[26rem] max-w-[90vw]" aria-label={title}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{message}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="ghost" onClick={onCancel}>Cancel</Button>
          </DialogClose>
          <Button variant={danger ? "destructive" : "default"} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
```

- [ ] **Step 1:** Apply the target above.
- [ ] **Step 2:** `cd app && npx vitest run src/test/confirmDialog.test.tsx` → PASS. (Existing test uses `getByRole("button", {name})` + text — both preserved. `getByRole("dialog")` still satisfied by Radix.) The destructive `confirmLabel="Remove"` button is now `<button>` still.
- [ ] **Step 3:** `cd app && npx eslint src/components/ConfirmDialog.tsx` → 0 errors.
- [ ] **Step 4:** Commit: `git commit -m "refactor(app): migrate ConfirmDialog to Dialog + Button primitives"`.

### Task 14: Migrate `AccessPicker` (worked example)

**Files:** Modify `app/src/components/AccessPicker.tsx`; `app/src/test/policy.test.ts` / `policyEditor.test.tsx` exercise it indirectly — keep green.

**Worked target:**

```tsx
import type { Access } from "../lib/types";
import { SegmentedControl } from "@/components/ui/segmented-control";

export function AccessPicker({ value, onChange }: { value: Access; onChange: (v: Access) => void }) {
  return (
    <SegmentedControl<Access>
      aria-label="access"
      value={value}
      onChange={onChange}
      options={[
        { value: "read", label: "read" },
        { value: "read-write", label: "read-write" },
      ]}
    />
  );
}
```

- [ ] **Step 1:** Apply the target.
- [ ] **Step 2:** `cd app && npx vitest run src/test/policyEditor.test.tsx` → PASS. NOTE: `policyEditor.test.tsx` is one of two files with class-string assertions — update any `read`/`read-write` button class assertions to the new `data-state` / role-based queries; keep the value-change behavior assertions.
- [ ] **Step 3:** `cd app && npx eslint src/components/AccessPicker.tsx` → 0 errors.
- [ ] **Step 4:** Commit: `git commit -m "refactor(app): migrate AccessPicker to SegmentedControl"`.

### Tasks 15–27: Migrate remaining feature components (one task each, apply the recipe)

Each task = apply the migration recipe to the named file, keep its existing test green (style assertions only), lint clean, commit `refactor(app): migrate <Component> to shadcn primitives`. Primitive guidance per file:

- [ ] **Task 15 — `VolumeRowEditor.tsx`** (`volumevalidate`/`detail` tests): `RowCard` + `Input` + `SegmentedControl` (volume type) + `RemoveRowButton`. Removes the bespoke segmented `py-1.5`.
- [ ] **Task 16 — `VolumesTab.tsx`** (`volumesTab.test.tsx`): `RowList` + `AddRowButton` + `RemoveRowButton` + `Badge` (persistent/ephemeral) + `Button variant="ghost"` for Undo/Detach. Unifies the detach (was warn) vs undo (was gray) styling via the canonical controls.
- [ ] **Task 17 — `PortsTab.tsx`** (`portsTab.test.tsx`): `Input` (`inputCls`) + `AddRowButton` (was full-width bar) + `RemoveRowButton` (× was gray → now destructive) + `Badge variant="warning"` (active-until-restart chip) + `Button variant="secondary" size="sm"` (Open/Make-persistent).
- [ ] **Task 18 — `PolicyEditor.tsx`** (`policyEditor.test.tsx` — has class assertions): `RowCard` + `Input` + `AddRowButton` (host/repo, were full-width) + `RemoveRowButton` (were warn) + `Button` (Save → `default`, now gets shadow via primitive) + inline port editor `AddRowButton`/`Badge`. Update class-string assertions; keep behavior.
- [ ] **Task 19 — `SeedDialog.tsx`** (`seedDialog.test.tsx`): `Dialog` shell + `Button` (Cancel `ghost`, Add `default`) + `Input`/`Select` for fields.
- [ ] **Task 20 — `NewSandbox.tsx`** (`newSandbox.test.tsx`): `Dialog` shell + `Input`/`Label` (name/cpu/mem/etc.) + `AddRowButton` (ports/volumes, were narrow pills) + `Button` (Cancel `ghost`, Create `default`, Browse `secondary`). Highest field count — verify all form behavior assertions pass unchanged.
- [ ] **Task 21 — `Detail.tsx`** (`detail.test.tsx`): `Button` for Start (`default`), Stop/Restart (`secondary`), Remove (`destructive`). Already mostly consistent; tokenize + primitivize.
- [ ] **Task 22 — `StorageView.tsx`** (`storageView.test.tsx`): `Card`/table surface + `Badge variant="secondary"` (volume ref) + `RemoveRowButton`/`Button variant="destructive" size="sm"` for delete (unify the conditional warn/gray disabled styling via `disabled` prop).
- [ ] **Task 23 — `NetlogView.tsx`** (`netlogView.test.tsx`): token swaps + `Badge` for verdict chips + `Button variant="ghost"/"secondary"` for controls.
- [ ] **Task 24 — `LogsView.tsx`** (`logsView.test.tsx`): token swaps + `Button` for any controls; mostly display.
- [ ] **Task 25 — `FirewallStatus.tsx`** (`firewallStatus.test.tsx`): token swaps + `Badge` for status + `Button` for actions.
- [ ] **Task 26 — `EnforceToggle.tsx`** (`enforceToggle.test.tsx`): `Switch` (was hand-rolled toggle) + `Label`. Verify `onCheckedChange` behavior maps to existing onChange assertion.
- [ ] **Task 27 — `About.tsx` + `ShellPanel.tsx`** (`about.test.tsx`, `shellPanel.test.tsx`): `About` token swaps + `Button`. `ShellPanel` is xterm-hosted — touch only the surrounding chrome (`Button`/tokens), DO NOT alter xterm wiring; `shellPanel.test.tsx` has class assertions — update style only.

---

## Phase 4 — Full gate

### Task 28: Green the whole gate + visual review

**Files:** none (verification + any final fixups).

- [ ] **Step 1: Lint clean across the whole app**

Run: `cd app && npm run lint`
Expected: 0 errors (the Task 11 worklist is now exhausted).

- [ ] **Step 2: Typecheck + build**

Run: `cd app && npm run build`
Expected: SUCCESS.

- [ ] **Step 3: Unit/component tests + coverage**

Run: `cd app && npm run test`
Expected: all PASS. Confirm new `ui/` primitives carry tests (Sonar new-code coverage).

- [ ] **Step 4: Playwright e2e (both engines)**

Run: `cd app && npm run e2e:install:chromium && npm run e2e` (webkit too if installable in env)
Expected: PASS — user flows behave identically.

- [ ] **Step 5: Tauri backend gates (unchanged, sanity)**

Run: `cd app/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: PASS.

- [ ] **Step 6: Visual review (the one remaining eyeball pass, over a now-uniform baseline)**

Run the app (`npm run dev` / Playwright screenshots) and confirm: add buttons uniform; remove buttons uniformly destructive-orange; inputs uniform radius/padding; dialogs behave (focus, Esc, overlay-click). Note any residual drift as follow-up; the spec's pixel-diff gate is the deferred mechanical guard.

- [ ] **Step 7: Final commit (if any fixups)**

```bash
git add -A app && git commit -m "chore(app): final consistency fixups; full App CI gate green"
```

---

## Self-review notes

- **Spec coverage:** token system (Task 2) ✓; full primitive inventory — Button/Input/Label/Select/Card/Badge/Switch/Dialog/SegmentedControl/RowEditor (Tasks 3–10) ✓; hard lint gate + escape hatch + CI wiring (Task 11) ✓; full 21-component migration (Tasks 12–27) ✓; TDD throughout ✓; no-visual-change (hex-equal vars) ✓; deferred pixel-diff explicitly out of scope ✓.
- **Behavior-assertion safety** is encoded in the recipe and called out per risky file (dialogs, EnforceToggle, the two class-assertion tests `policyEditor`/`shellPanel`).
- **CI-red-until-Phase-3** is flagged at Task 11 so the executor doesn't misdiagnose it.
- **No arbitrary values** constraint is repeated at the gate.
