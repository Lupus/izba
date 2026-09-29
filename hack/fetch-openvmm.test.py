#!/usr/bin/env python3
# Tests for hack/fetch-openvmm.sh — the upstream-artifact fetch and its
# sha256-pinned mirror fallback. Runs the real script against a stubbed `gh`
# (first on PATH), in a scratch copy of the repo layout, with the pin rewritten
# to a known test payload. No network.
# Run: python3 hack/fetch-openvmm.test.py
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("fetch-openvmm.sh")
GOOD = b"MZ-the-pinned-openvmm"
GOOD_SHA = hashlib.sha256(GOOD).hexdigest()

# The stub's behaviour comes from env: UPSTREAM=ok|fail|fail-partial and
# MIRROR=ok|bad|missing. It writes files where the real `gh` would (-D DIR).
STUB_GH = r"""#!/usr/bin/env bash
set -eu
dest=""
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  [[ "${args[$i]}" == "-D" ]] && dest="${args[$((i+1))]}"
done
case "$1 $2" in
  "auth status") exit 0 ;;
  "run download")
    case "$UPSTREAM" in
      ok) mkdir -p "$dest"; printf '%s' "$GOOD" > "$dest/openvmm.exe"; exit 0 ;;
      # A partial extraction at a NESTED path — the mirror can't overwrite it,
      # so only searching the mirror's own dir keeps it from being picked.
      fail-partial) mkdir -p "$dest/partial"; printf 'truncat' > "$dest/partial/openvmm.exe"; exit 1 ;;
      *) echo "no valid artifacts found to download" >&2; exit 1 ;;
    esac ;;
  "release download")
    case "$MIRROR" in
      ok) mkdir -p "$dest"; printf '%s' "$GOOD" > "$dest/openvmm.exe"; exit 0 ;;
      bad) mkdir -p "$dest"; printf 'a-different-vmm' > "$dest/openvmm.exe"; exit 0 ;;
      *) echo "release not found" >&2; exit 1 ;;
    esac ;;
esac
echo "stub gh: unexpected: $*" >&2; exit 2
"""


class FetchOpenvmmTest(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        (self.root / "hack").mkdir()
        (self.root / "bin").mkdir()
        self.script = self.root / "hack" / "fetch-openvmm.sh"
        shutil.copy(SCRIPT, self.script)
        gh = self.root / "bin" / "gh"
        gh.write_text(STUB_GH)
        gh.chmod(0o755)

    def tearDown(self):
        shutil.rmtree(self.root)

    def pin(self, sha):
        text = self.script.read_text()
        text, n = re.subn(r'^SHA256="[0-9a-f]*"$', f'SHA256="{sha}"', text, flags=re.M)
        self.assertEqual(n, 1, "SHA256 pin line not found")
        self.script.write_text(text)

    def run_script(self, upstream, mirror):
        env = dict(os.environ)
        env.update(
            PATH=f"{self.root / 'bin'}:{env['PATH']}",
            UPSTREAM=upstream,
            MIRROR=mirror,
            GOOD=GOOD.decode(),
        )
        return subprocess.run(
            ["bash", str(self.script)], env=env, capture_output=True, text=True
        )

    def dist(self):
        return self.root / "dist" / "openvmm.exe"

    def test_upstream_ok(self):
        self.pin(GOOD_SHA)
        r = self.run_script("ok", "missing")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.dist().read_bytes(), GOOD)
        self.assertNotIn("falling back", r.stdout)

    def test_expired_upstream_falls_back_to_mirror(self):
        self.pin(GOOD_SHA)
        r = self.run_script("fail", "ok")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("falling back", r.stdout)
        self.assertEqual(self.dist().read_bytes(), GOOD)

    def test_partial_upstream_file_never_shadows_the_mirror(self):
        self.pin(GOOD_SHA)
        r = self.run_script("fail-partial", "ok")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.dist().read_bytes(), GOOD)

    def test_mirror_with_wrong_checksum_is_rejected(self):
        self.pin(GOOD_SHA)
        r = self.run_script("fail", "bad")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("sha256 mismatch", r.stderr)
        self.assertFalse(self.dist().exists())

    def test_no_fallback_while_recording_a_first_pin(self):
        self.pin("")
        r = self.run_script("fail", "ok")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no pinned sha256", r.stderr)
        self.assertFalse(self.dist().exists())

    def test_both_sources_unavailable_fails_loudly(self):
        self.pin(GOOD_SHA)
        r = self.run_script("fail", "missing")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("mirror is unavailable", r.stderr)
        self.assertFalse(self.dist().exists())


if __name__ == "__main__":
    sys.exit(unittest.main())
