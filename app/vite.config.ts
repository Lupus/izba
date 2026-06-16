import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Expose Tauri's build-time env vars (TAURI_ENV_*) to the toolchain.
  envPrefix: ["VITE_", "TAURI_ENV_"],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "es2021", outDir: "dist" },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
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
