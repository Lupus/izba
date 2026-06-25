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
      ...reactHooks.configs.recommended.rules,
      "tailwindcss/no-arbitrary-value": "error",
      "tailwindcss/no-custom-classname": "off",
      "tailwindcss/classnames-order": "off",
    },
  },
  {
    files: ["src/components/**/*.tsx"],
    ignores: ["src/components/ui/**", "**/*.test.tsx"],
    rules: { "izba/no-raw-control": "error" },
  },
);
