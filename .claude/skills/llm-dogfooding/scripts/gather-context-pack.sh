#!/usr/bin/env bash
# gather-context-pack.sh — assemble the FAIR-TEST context pack: the only material
# the dogfooding swarm is allowed to know (README + recursive `--help`). This is
# the user-visible surface; it must NOT contain the spec, design docs, or source.
# If the swarm can't use a feature from this, that's a discoverability finding.
#
# Usage: gather-context-pack.sh <izba-bin> <repo-root> [out-file]
#   <izba-bin>   path to the built product binary (for --help)
#   <repo-root>  repo root (for README)
#   [out-file]   default: ./context-pack.md
#
# Recurses ONE level into nested command namespaces (e.g. `volume` ->
# `volume ls/attach/...`) so the swarm sees real verbs + signatures the way a
# user discovers them. Best-effort; bounded.
set -euo pipefail

BIN="${1:?usage: gather-context-pack.sh <izba-bin> <repo-root> [out-file]}"
ROOT="${2:?usage: gather-context-pack.sh <izba-bin> <repo-root> [out-file]}"
OUT="${3:-context-pack.md}"
TIMEOUT="${HELP_TIMEOUT:-8}"

command -v "$BIN" >/dev/null 2>&1 || [ -x "$BIN" ] || { echo "no executable at: $BIN" >&2; exit 1; }

# Extract subcommand names from a clap-style "Commands:" / "SUBCOMMANDS:" block.
# Portable across gawk/mawk: $1 of an indented "  name   desc" line is the name
# (no gawk-only 3-arg match()); the indent guard skips blanks and section headers.
parse_subcommands() {
  awk '
    /^[Cc]ommands:[[:space:]]*$/    { incmd=1; next }
    /^[Ss]ubcommands:[[:space:]]*$/ { incmd=1; next }
    /^[^[:space:]]/                 { incmd=0 }
    incmd && /^[[:space:]]+[a-z]/   { print $1 }
  ' | grep -vx help || true
}

help_of() { timeout "$TIMEOUT" "$BIN" "$@" --help 2>&1 || true; }

{
  echo "# Context pack — user-visible surface ONLY (fair-test boundary)"
  echo
  echo "> The swarm may use ONLY what is below. No spec/design/source. A feature"
  echo "> the swarm cannot use from this surface is a discoverability finding."
  echo

  if [ -f "$ROOT/README.md" ]; then
    echo "## README.md"
    echo
    echo '```markdown'
    cat "$ROOT/README.md"
    echo '```'
    echo
  fi

  echo "## CLI help (recursive)"
  echo
  top="$(help_of)"
  echo '```'
  echo "\$ $(basename "$BIN") --help"
  echo "$top"
  echo '```'
  echo
  # one level of nesting
  while read -r cmd; do
    [ -n "$cmd" ] || continue
    sub="$(help_of "$cmd")"
    echo '```'
    echo "\$ $(basename "$BIN") $cmd --help"
    echo "$sub"
    echo '```'
    echo
    while read -r nested; do
      [ -n "$nested" ] || continue
      echo '```'
      echo "\$ $(basename "$BIN") $cmd $nested --help"
      help_of "$cmd" "$nested"
      echo '```'
      echo
    done < <(printf '%s\n' "$sub" | parse_subcommands)
  done < <(printf '%s\n' "$top" | parse_subcommands)
} > "$OUT"

echo "wrote $OUT ($(wc -l < "$OUT") lines)"
