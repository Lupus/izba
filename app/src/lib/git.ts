import type { Access, GitRule } from "./types";

/**
 * Detect whether a path corresponds to a git wire operation and extract the
 * repo glob.  Returns `null` for non-git paths or when host is null.
 *
 * Recognised suffixes (per Git HTTP backend protocol):
 *   /git-receive-pack   → push (write)
 *   /git-upload-pack    → clone/fetch (read)
 *   /info/refs          → negotiation prefix (read)
 *
 * Uses only linear string operations (endsWith / slice / startsWith / split)
 * to avoid backtracking-prone regex patterns (SonarCloud S5852).
 */
export function git_repo_from_row(host: string | null, path: string | null): string | null {
  if (!host || !path) return null;

  // Strip query string: take everything before the first '?'
  const bare = path.split("?")[0];

  // Determine which suffix the path ends with, then slice it off.
  const GIT_SUFFIXES = ["/info/refs", "/git-upload-pack", "/git-receive-pack"] as const;
  let repoPath: string | null = null;
  for (const suffix of GIT_SUFFIXES) {
    if (bare.endsWith(suffix)) {
      repoPath = bare.slice(0, bare.length - suffix.length);
      break;
    }
  }
  if (repoPath === null) return null;

  // Strip optional .git extension from the repo path
  if (repoPath.endsWith(".git")) {
    repoPath = repoPath.slice(0, repoPath.length - 4);
  }

  // Strip leading slashes
  while (repoPath.startsWith("/")) {
    repoPath = repoPath.slice(1);
  }

  return `${host}/${repoPath}`;
}

/** Returns "push" for write (git-receive-pack), "clone" for read, null for non-git. */
export function git_op_from_path(path: string | null): "push" | "clone" | null {
  if (!path) return null;
  const bare = path.split("?")[0];
  if (bare.endsWith("/git-receive-pack")) return "push";
  if (bare.endsWith("/git-upload-pack") || bare.endsWith("/info/refs")) return "clone";
  return null;
}

/** Segment-wise glob on `/`: `*` matches exactly one segment. No `**`. */
export function globMatch(pattern: string, value: string): boolean {
  const p = pattern.split("/");
  const v = value.split("/");
  if (p.length !== v.length) return false;
  return p.every((seg, i) => seg === "*" || seg === v[i]);
}

/** Strongest access a git ruleset grants this concrete repo, else null. */
export function git_access_for(repo: string, git: GitRule[]): Access | null {
  const host = repo.split("/")[0];
  let best: Access | null = null;
  for (const rule of git) {
    const matched = "repo" in rule ? globMatch(rule.repo, repo) : rule.host === host;
    if (!matched) continue;
    const a: Access = rule.access ?? "read";
    if (a === "read-write") return "read-write"; // strongest wins, short-circuit
    best = "read";
  }
  return best;
}
