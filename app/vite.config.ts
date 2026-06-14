import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Expose Tauri's build-time env vars (TAURI_ENV_*) to the toolchain.
  envPrefix: ["VITE_", "TAURI_ENV_"],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "es2021", outDir: "dist" },
  test: { environment: "jsdom", globals: true, setupFiles: ["./src/test/setup.ts"] },
});
