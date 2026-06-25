import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { playwright } from "@vitest/browser-playwright";
import { fileURLToPath, URL } from "node:url";

const alias = { "@": fileURLToPath(new URL("./src", import.meta.url)) };

export default defineConfig({
  plugins: [react()],
  resolve: { alias },
  // Expose Tauri's build-time env vars (TAURI_ENV_*) to the toolchain.
  envPrefix: ["VITE_", "TAURI_ENV_"],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "es2021", outDir: "dist" },
  test: {
    globals: true,
    // Merged coverage across both projects (Sonar reads coverage/lcov.info).
    coverage: {
      provider: "v8",
      // lcov for SonarCloud ingestion; text for a local at-a-glance summary.
      reporter: ["text", "lcov"],
      reportsDirectory: "coverage",
      include: ["src/**/*.{ts,tsx}"],
      // Exclude things that aren't meaningful unit-coverage targets: type-only
      // modules, the test harness itself, and the app entrypoint/wiring.
      exclude: [
        "src/**/*.d.ts",
        "src/**/*.test.{ts,tsx}",
        "src/**/*.browser.test.tsx",
        "src/test/**",
        "src/main.tsx",
        "src/lib/types.ts",
      ],
    },
    // Two Vitest projects:
    //   unit   — jsdom, existing *.test.{ts,tsx} suite (excludes *.browser.test.tsx)
    //   browser — real Chromium via Playwright for Radix overlay interaction tests
    projects: [
      {
        plugins: [react()],
        resolve: { alias },
        test: {
          name: "unit",
          environment: "jsdom",
          globals: true,
          setupFiles: ["./src/test/setup.ts"],
          // Collect src/**/*.test.{ts,tsx} but NOT *.browser.test.tsx (those
          // use pointer-capture / ResizeObserver APIs jsdom can't reliably fake).
          include: ["src/**/*.test.{ts,tsx}"],
          exclude: ["src/**/*.browser.test.tsx"],
        },
      },
      {
        plugins: [react()],
        resolve: { alias },
        test: {
          name: "browser",
          globals: true,
          // Vitest 4 Browser Mode — Playwright provider, real Chromium.
          browser: {
            enabled: true,
            provider: playwright(),
            instances: [{ browser: "chromium" }],
            headless: true,
          },
          include: ["src/**/*.browser.test.tsx"],
        },
      },
    ],
  },
});
