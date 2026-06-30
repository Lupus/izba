// app/dogfood/inject.mjs
// Post-build step: make app/dist a *dogfood* build by loading the WS bridge
// before the app bundle, so __TAURI_INTERNALS__ is the real-bridge one.
import { readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const BRIDGE_TAG = '<script src="/real-bridge.js"></script>';

export function injectBridge(html) {
  if (html.includes(BRIDGE_TAG)) return html; // idempotent
  // Insert right after <head> (so it runs before any module script in <body>).
  if (html.includes("<head>")) return html.replace("<head>", "<head>" + BRIDGE_TAG);
  return BRIDGE_TAG + html;
}

// CLI: `node dogfood/inject.mjs <dist-dir>`
if (import.meta.url === `file://${process.argv[1]}`) {
  const dist = resolve(process.argv[2] || "dist");
  const indexPath = resolve(dist, "index.html");
  writeFileSync(indexPath, injectBridge(readFileSync(indexPath, "utf8")));
  copyFileSync(resolve(HERE, "real-bridge.js"), resolve(dist, "real-bridge.js"));
  console.log(`[dogfood] injected real-bridge.js into ${indexPath}`);
}
