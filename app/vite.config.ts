import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  // Expose Tauri's build-time env vars (TAURI_ENV_*) to the toolchain.
  envPrefix: ["VITE_", "TAURI_ENV_"],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "es2021", outDir: "dist" },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // Scope vitest to src/ unit+component tests. The Playwright e2e suite under
    // e2e/ (*.spec.ts) imports @playwright/test and must NOT be collected here;
    // Playwright runs it via its own testDir.
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
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
        "src/test/**",
        "src/main.tsx",
        "src/lib/types.ts",
      ],
    },
  },
});
