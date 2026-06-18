import type { AllowEntry } from "./types";
import { WEB_DEFAULT_PORTS } from "./ports";

/** Expand the policy allow-list into a set of `host:port` keys.
 *  A bare-host string permits the web defaults (WEB_DEFAULT_PORTS);
 *  a scoped entry permits its exact ports.
 *  Shared by NetlogView and SeedDialog so SonarCloud never sees a duplicate. */
export function allowKeys(allow: AllowEntry[]): Set<string> {
  const s = new Set<string>();
  for (const e of allow) {
    if (typeof e === "string") {
      for (const p of WEB_DEFAULT_PORTS) s.add(`${e}:${p}`);
    } else {
      for (const p of e.ports) s.add(`${e.host}:${p}`);
    }
  }
  return s;
}
