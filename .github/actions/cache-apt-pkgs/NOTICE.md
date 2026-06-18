# cache-apt-pkgs (vendored fork)

This directory is a vendored, de-blobbed fork of the
[`cache-apt-pkgs-action`](https://github.com/awalsh128/cache-apt-pkgs-action)
GitHub Action.

- **Upstream:** https://github.com/awalsh128/cache-apt-pkgs-action
- **Forked at commit:** `681749ae568c81c2037cb9185e38b709b261bd2f` (tag `v1.6.1`)
- **Copyright:** © 2022 Andrew Walsh
- **License:** Apache License 2.0 — see [`LICENSE`](LICENSE) (full text).

## Why it's vendored

izba pins every external CI input by SHA and avoids running unpinned remote code
in CI (see the security program in `docs/security/`). The upstream action, on a
cache miss, did two things that conflict with that posture:

1. **Bootstrapped `apt-fast` via `curl -sL …/quick-install.sh | bash`** from an
   unpinned `master` URL — i.e. remote code execution at CI runtime.
2. **Shipped a 3.3 MB precompiled Go binary** (`apt_query-x86` / `apt_query-arm64`)
   committed to the repo, used only to normalize the package list into sorted
   `name=version` pairs.

Vendoring lets us remove both while keeping the action's real value: the
warm-cache `tar` restore that skips the package mirror entirely.

## Modifications from upstream

- **Removed the compiled `apt_query` binaries.** `get_normalized_package_list`
  in [`lib.sh`](lib.sh) is reimplemented in pure bash (`apt-cache show` +
  `awk` + `sort`). It fails loudly if any requested package does not resolve to
  exactly one `name=version` pair, so the cache key can never silently drift.
  Virtual-package resolution (an upstream feature) is intentionally dropped — the
  packages we cache are all concrete.
- **Removed the `apt-fast` / `curl | bash` bootstrap** in
  [`install_and_cache_pkgs.sh`](install_and_cache_pkgs.sh). Cold-cache installs
  use plain `apt-get`, which honors the `Acquire::Retries` / `Acquire::*::Timeout`
  hardening the workflow writes to `apt.conf.d`. (Cache hits restore via `tar`
  and never run this path.)
- **Pinned the sub-actions** `actions/cache/restore` and `actions/cache/save` to
  a commit SHA (`v5.0.5`) in [`action.yml`](action.yml).
- **Dropped the debug-only `actions/upload-artifact` step** so the action depends
  on one fewer external action.

Files `pre_cache_action.sh`, `post_cache_action.sh`, and `restore_pkgs.sh` are
vendored verbatim from upstream.
