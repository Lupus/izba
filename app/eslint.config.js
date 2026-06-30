import js from "@eslint/js";
import tseslint from "typescript-eslint";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import tailwind from "eslint-plugin-tailwindcss";
import globals from "globals";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";
import noRawControl from "./eslint-rules/no-raw-control.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export default tseslint.config(
  { ignores: ["dist", "coverage", "playwright-report", "src-tauri", "eslint-rules", "e2e"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser } },
    plugins: { react, "react-hooks": reactHooks, tailwindcss: tailwind, izba: { rules: { "no-raw-control": noRawControl } } },
    settings: { tailwindcss: { config: resolve(__dirname, "tailwind.config.ts"), callees: ["cn", "cva"] } },
    rules: {
      // Scope react-hooks to consistency-relevant rules only. The plugin is
      // registered so existing `// eslint-disable react-hooks/exhaustive-deps`
      // directives resolve to a defined rule (no unused-directive warnings); we
      // deliberately do NOT enable the broader `recommended` set (e.g.
      // `set-state-in-effect`), which would impose a new correctness regime on
      // pre-existing code (it flags legitimate polling in src/lib/store.ts).
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "tailwindcss/no-arbitrary-value": "error",
      "tailwindcss/no-custom-classname": "off",
      // "off" deliberately: the consistency gate is no-arbitrary-value +
      // izba/no-raw-control. classnames-order is cosmetic and would flag the
      // existing (un-reordered) class strings across migrated components under
      // --max-warnings 0; out of scope for this migration.
      "tailwindcss/classnames-order": "off",
    },
  },
  {
    files: ["src/components/**/*.tsx"],
    ignores: ["src/components/ui/**", "**/*.test.tsx"],
    rules: { "izba/no-raw-control": "error" },
  },
  // dogfood/ build scripts: Node ESM (.mjs) needs Node globals; the browser
  // IIFE + CommonJS dual-mode bridge (.js) needs browser + CommonJS globals.
  // Both are intentionally linted (not ignored) — just with the right env.
  {
    files: ["dogfood/*.mjs"],
    languageOptions: { globals: { ...globals.node } },
  },
  {
    files: ["dogfood/*.js"],
    languageOptions: { globals: { ...globals.browser, ...globals.commonjs } },
  },
);
