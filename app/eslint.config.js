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
      // "off": crashes under ESLint 10 + eslint-plugin-tailwindcss v3.x
      // (context.getSourceCode removed); re-enable when plugin gains v10 support.
      "tailwindcss/classnames-order": "off",
    },
  },
  {
    files: ["src/components/**/*.tsx"],
    ignores: ["src/components/ui/**", "**/*.test.tsx"],
    rules: { "izba/no-raw-control": "error" },
  },
);
