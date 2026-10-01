# USB e2e: Windows/OpenVMM attach leg + installed-artifact path — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three USB coverage holes named in issue #191 — no Windows/OpenVMM attach in CI, no assertion that an installer carries both kernels, and no e2e path that resolves the USB kernel the way an installed build does.

**Architecture:** Three independent test/CI additions, no product code. (1) One payload verifier, `packaging/verify-payload.sh`, run against the built `.deb` and against the Windows installer's stage dir in every packaging workflow. (2) One new case in the existing Linux USB e2e that strips every boot-artifact override and boots from `<exe-dir>/../artifacts`, which CI now stages installer-shaped. (3) One PowerShell gate, `hack/ci/usb-attach-gate.ps1`, run as its own step in the `windows-whp` job: fake usbip server → grant → boot on `vmlinux-usb` resolved exe-relative → attach → node appears → bytes round-trip → detach.

**Tech Stack:** Rust integration tests (`crates/izba-cli/tests`), bash + Python `unittest` for the packaging script, PowerShell 7 for the Windows gate, GitHub Actions YAML.

**Spec:** GitHub issue [#191](https://github.com/Lupus/izba/issues/191) (What / Why / In Scope / Out of Scope / Acceptance Criteria). There is no separate design doc; the "Design decisions" section below records the choices the issue left open.

## Design decisions

- **Windows leg is a PowerShell gate, not the Rust suite.** Every Windows real-VM check in this repo is a PowerShell script (`hack/spike/validate-izba-windows.ps1`, `hack/ci/ttystorm-gate.ps1`) so it can also be run on the dev host through WSL interop against cross-built binaries. A standalone gate script (the `ttystorm-gate.ps1` shape) with its own data root keeps it runnable locally without touching the user's real `%LOCALAPPDATA%\izba`.
- **The Windows gate resolves artifacts the installed way too.** It removes `IZBA_KERNEL` / `IZBA_KERNEL_USB` / `IZBA_INITRAMFS` from its own environment before the first `izba` call (which is what spawns izbad), and uses a fresh data root with no `artifacts\` dir. The only place left to find a kernel is `<exe-dir>\..\artifacts`. So AC3 is covered on **both** platforms, including the one the feature exists for.
- **Windows installer payload is verified at the stage dir.** `izba.iss` installs `{#StageDir}\artifacts\*` by glob, so the stage dir *is* the installer's artifact payload; a missing file there is silently omitted by ISCC. Verifying it immediately before ISCC is the assertion. (Unpacking the built `.exe` would need `innoextract`, which lags Inno Setup releases.)
- **No real-usbipd-win job.** The issue marks it optional and it cannot run on hosted runners. Not added.

## Global Constraints

- No product code changes (`crates/*/src` non-test code is untouched). If the Windows gate exposes a product bug, STOP and report it to the controller — do not fix the datapath inside this plan.
- Unit tests never bind unix/vsock listeners.
- Conventional commits; every commit body carries `Refs #191`; every commit message ends with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Never `git add -A`; stage named files only and check `git status --short` before committing.
- Gates that must stay green (run from the repo root, after `[ -f .cargo-env ] && source .cargo-env`):
  `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`,
  `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
- A check that cannot run must FAIL loudly, never skip: a USB e2e that quietly passes because it never ran is the defect class this issue exists to close.
- Substring assertions on artifact names must not be satisfiable by a longer name: `vmlinux` is a prefix of `vmlinux-usb`.
- SonarCloud lints workflow YAML (no `npx`) and `.ps1` files; keep PowerShell free of unused variables and empty `catch` blocks without a comment.

## Review Focus

1. **`vmlinux` present only as `vmlinux-usb`** — a payload that ships the USB kernel but not the base one must fail verification, even though every `vmlinux` substring check passes. (Task 1 tests `test_deb_missing_base_kernel_is_not_masked_by_the_usb_kernel` / `test_stage_missing_base_kernel…`, and the tightened Rust guard.)
2. **A zero-byte kernel** — a failed download leaves an empty file that "exists". The verifier must reject it. (Task 1 `test_deb_with_an_empty_kernel_fails`, `test_stage_with_an_empty_kernel_fails`.)
3. **An artifact override leaking into the "installed" run** — if any one `izba` invocation in the installed-path case keeps `IZBA_KERNEL_USB`, the daemon it spawns inherits it and the case proves nothing. (Task 2: every invocation goes through `izba_as(Artifacts::Installed, …)`, the daemon-spawning call included; Task 3: the gate clears the variables process-wide before its first call and asserts they are gone.)
4. **Artifacts not staged** — the installed-path case must panic naming the missing file and the copy command, not skip. (Task 2 step 2 observes exactly this failure before staging.)
5. **A stale data-root `artifacts\` dir satisfying the lookup on a dev host** — the Windows gate must refuse to run against a data root that already has one. (Task 3 preflight check.)

---

### Task 1: Installer payload verifier

**Files:**
- Create: `packaging/verify-payload.sh`
- Create: `packaging/verify-payload.test.py`
- Modify: `crates/izba-core/src/artifacts.rs` (tests module, around the existing `every_kernel_variant_is_installed_by_the_debian_package`)
- Modify: `.github/workflows/ci.yml` (job `hack script tests`)
- Modify: `.github/workflows/devbuild.yml` (jobs `package-deb`, `package-windows`)
- Modify: `.github/workflows/release.yml` (jobs `package-deb`, `package-windows`, `smoke`)
- Modify: `packaging/windows/izba.iss` (header comment only)
- Modify: `hack/README.md` (Packaging section)

**Interfaces:**
- Produces: `packaging/verify-payload.sh deb <file.deb>` and `packaging/verify-payload.sh stage <StageDir>`. Exit 0 = complete; exit 1 = payload incomplete, one `MISSING: <path>` / `EMPTY: <path>` line per problem on stderr; exit 2 = usage error or unreadable target. The script's artifact list is the single bash array line `ARTIFACTS=(vmlinux vmlinux-usb initramfs.cpio.gz kasmvnc.erofs)`.

- [ ] **Step 1: Write the failing script tests**

Create `packaging/verify-payload.test.py`:

```python
#!/usr/bin/env python3
# Tests for packaging/verify-payload.sh — the check that an installer payload
# carries every file a sandbox needs to boot (#191). Builds real (tiny) .deb
# files with dpkg-deb and real stage dirs, then runs the real script. No network.
# Run: python3 packaging/verify-payload.test.py
import pathlib
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("verify-payload.sh")

DEB_FILES = [
    "usr/lib/izba/bin/izba",
    "usr/lib/izba/bin/libexec/cloud-hypervisor",
    "usr/lib/izba/bin/libexec/virtiofsd",
    "usr/lib/izba/artifacts/vmlinux",
    "usr/lib/izba/artifacts/vmlinux-usb",
    "usr/lib/izba/artifacts/initramfs.cpio.gz",
    "usr/lib/izba/artifacts/kasmvnc.erofs",
]
STAGE_FILES = [
    "bin/izba.exe",
    "bin/izba-jail-helper.exe",
    "bin/izba-app.exe",
    "bin/libexec/openvmm.exe",
    "bin/libexec/mkfs.erofs.exe",
    "artifacts/vmlinux",
    "artifacts/vmlinux-usb",
    "artifacts/initramfs.cpio.gz",
    "artifacts/kasmvnc.erofs",
]
CONTROL = (
    "Package: izba\nVersion: 0.0.0\nArchitecture: amd64\n"
    "Maintainer: test <test@example.invalid>\nDescription: test payload\n"
)


class VerifyPayloadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def run_script(self, *args):
        return subprocess.run(
            ["bash", str(SCRIPT), *args], capture_output=True, text=True
        )

    def make_deb(self, omit=(), empty=(), symlink=True):
        root = self.tmp / "debroot"
        if root.exists():
            shutil.rmtree(root)
        for rel in DEB_FILES:
            if rel in omit:
                continue
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"" if rel in empty else b"payload")
        if symlink:
            (root / "usr/bin").mkdir(parents=True, exist_ok=True)
            (root / "usr/bin/izba").symlink_to("../lib/izba/bin/izba")
        (root / "DEBIAN").mkdir(parents=True, exist_ok=True)
        (root / "DEBIAN/control").write_text(CONTROL)
        deb = self.tmp / "izba_0.0.0_amd64.deb"
        subprocess.run(
            ["dpkg-deb", "--root-owner-group", "--build", str(root), str(deb)],
            check=True,
            capture_output=True,
        )
        return deb

    def make_stage(self, omit=(), empty=()):
        stage = self.tmp / "stage"
        if stage.exists():
            shutil.rmtree(stage)
        for rel in STAGE_FILES:
            if rel in omit:
                continue
            p = stage / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"" if rel in empty else b"payload")
        return stage

    # --- deb mode ---------------------------------------------------------

    def test_complete_deb_passes(self):
        r = self.run_script("deb", str(self.make_deb()))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_deb_missing_the_usb_kernel_fails_and_names_it(self):
        r = self.run_script(
            "deb", str(self.make_deb(omit=["usr/lib/izba/artifacts/vmlinux-usb"]))
        )
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("MISSING: usr/lib/izba/artifacts/vmlinux-usb", r.stderr)

    def test_deb_missing_base_kernel_is_not_masked_by_the_usb_kernel(self):
        # `vmlinux` is a prefix of `vmlinux-usb`: a substring match on the
        # listing would pass this payload. It must not.
        r = self.run_script(
            "deb", str(self.make_deb(omit=["usr/lib/izba/artifacts/vmlinux"]))
        )
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("MISSING: usr/lib/izba/artifacts/vmlinux\n", r.stderr)
        self.assertNotIn("vmlinux-usb", r.stderr)

    def test_deb_with_an_empty_kernel_fails(self):
        r = self.run_script(
            "deb", str(self.make_deb(empty=["usr/lib/izba/artifacts/vmlinux-usb"]))
        )
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("EMPTY: usr/lib/izba/artifacts/vmlinux-usb", r.stderr)

    def test_deb_reports_every_problem_not_just_the_first(self):
        r = self.run_script(
            "deb",
            str(
                self.make_deb(
                    omit=[
                        "usr/lib/izba/artifacts/vmlinux-usb",
                        "usr/lib/izba/artifacts/kasmvnc.erofs",
                    ]
                )
            ),
        )
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("MISSING: usr/lib/izba/artifacts/vmlinux-usb", r.stderr)
        self.assertIn("MISSING: usr/lib/izba/artifacts/kasmvnc.erofs", r.stderr)

    def test_deb_without_the_usr_bin_symlink_fails(self):
        r = self.run_script("deb", str(self.make_deb(symlink=False)))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("usr/bin/izba", r.stderr)

    def test_a_deb_that_does_not_exist_is_a_usage_error(self):
        r = self.run_script("deb", str(self.tmp / "nope.deb"))
        self.assertEqual(r.returncode, 2, r.stderr)

    # --- stage mode -------------------------------------------------------

    def test_complete_stage_passes(self):
        r = self.run_script("stage", str(self.make_stage()))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_stage_missing_the_usb_kernel_fails_and_names_it(self):
        r = self.run_script(
            "stage", str(self.make_stage(omit=["artifacts/vmlinux-usb"]))
        )
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("MISSING: artifacts/vmlinux-usb", r.stderr)

    def test_stage_missing_base_kernel_is_not_masked_by_the_usb_kernel(self):
        r = self.run_script("stage", str(self.make_stage(omit=["artifacts/vmlinux"])))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("MISSING: artifacts/vmlinux\n", r.stderr)

    def test_stage_with_an_empty_kernel_fails(self):
        r = self.run_script(
            "stage", str(self.make_stage(empty=["artifacts/vmlinux-usb"]))
        )
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("EMPTY: artifacts/vmlinux-usb", r.stderr)

    def test_stage_missing_a_libexec_tool_fails(self):
        # izba.iss installs bin\libexec\* by glob too, so a missing VMM is
        # omitted from the installer just as silently as a missing kernel.
        r = self.run_script(
            "stage", str(self.make_stage(omit=["bin/libexec/openvmm.exe"]))
        )
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("MISSING: bin/libexec/openvmm.exe", r.stderr)

    def test_a_stage_dir_that_does_not_exist_is_a_usage_error(self):
        r = self.run_script("stage", str(self.tmp / "nope"))
        self.assertEqual(r.returncode, 2, r.stderr)

    # --- usage ------------------------------------------------------------

    def test_an_unknown_mode_is_a_usage_error(self):
        r = self.run_script("rpm", "x")
        self.assertEqual(r.returncode, 2, r.stderr)

    def test_a_missing_argument_is_a_usage_error(self):
        r = self.run_script("deb")
        self.assertEqual(r.returncode, 2, r.stderr)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `python3 packaging/verify-payload.test.py`
Expected: every test FAILS (the script does not exist: `bash: …/verify-payload.sh: No such file or directory`, return code 127, so each `assertEqual(r.returncode, …)` fails).

- [ ] **Step 3: Write the script**

Create `packaging/verify-payload.sh` and `chmod +x` it:

```bash
#!/usr/bin/env bash
# Assert that an installer payload carries every file a sandbox needs to boot.
#
#   packaging/verify-payload.sh deb   <izba_*.deb>   the built Debian package
#   packaging/verify-payload.sh stage <StageDir>     the Windows installer's input
#
# Why this exists (#189, #191): the USB kernel variant was added to the code and
# never to the packaging, and a fully green board shipped an installer that
# could not start a sandbox holding a device grant. Both installers take their
# boot artifacts from a directory — the .deb from build-deb.sh's stage, the
# Windows installer from `{#StageDir}\artifacts\*`, a GLOB that silently omits
# whatever is absent — so "is it in the payload" has to be asked explicitly.
#
# Exit: 0 complete; 1 incomplete (one MISSING:/EMPTY: line per problem on
# stderr, all of them, not just the first); 2 usage error / unreadable target.
set -euo pipefail

# The boot artifacts every installer ships. One line, space-separated: the
# guard test in crates/izba-core/src/artifacts.rs reads it and fails when
# `KernelVariant` grows a variant this list has not learned about.
ARTIFACTS=(vmlinux vmlinux-usb initramfs.cpio.gz kasmvnc.erofs)

usage() {
    echo "usage: $0 deb <izba_*.deb> | stage <StageDir>" >&2
    exit 2
}

[[ $# -eq 2 ]] || usage
mode="$1"
target="$2"
problems=0

problem() {
    echo "$1" >&2
    problems=$((problems + 1))
}

case "$mode" in
deb)
    [[ -f "$target" ]] || { echo "error: no such .deb: $target" >&2; exit 2; }
    listing="$(dpkg-deb --contents "$target")"
    # `<size> <path>` per entry. Field 3 is the size and field 6 the path in
    # dpkg-deb's tar-style listing; the leading `./` is dropped so paths read
    # the way build-deb.sh writes them.
    entries="$(awk '{ sub(/^\.\//, "", $6); print $3, $6 }' <<<"$listing")"
    required=(
        usr/lib/izba/bin/izba
        usr/lib/izba/bin/libexec/cloud-hypervisor
        usr/lib/izba/bin/libexec/virtiofsd
    )
    for a in "${ARTIFACTS[@]}"; do
        required+=("usr/lib/izba/artifacts/$a")
    done
    for p in "${required[@]}"; do
        # Whole-field match on the path: `vmlinux` must not be satisfied by
        # the `vmlinux-usb` entry.
        size="$(awk -v want="$p" '$2 == want { print $1; exit }' <<<"$entries")"
        if [[ -z "$size" ]]; then
            problem "MISSING: $p"
        elif [[ "$size" == 0 ]]; then
            problem "EMPTY: $p"
        fi
    done
    grep -qF './usr/bin/izba -> ../lib/izba/bin/izba' <<<"$listing" ||
        problem "MISSING: usr/bin/izba -> ../lib/izba/bin/izba (symlink)"
    ;;
stage)
    [[ -d "$target" ]] || { echo "error: no such stage dir: $target" >&2; exit 2; }
    required=(
        bin/izba.exe
        bin/izba-jail-helper.exe
        bin/izba-app.exe
        bin/libexec/openvmm.exe
        bin/libexec/mkfs.erofs.exe
    )
    for a in "${ARTIFACTS[@]}"; do
        required+=("artifacts/$a")
    done
    for p in "${required[@]}"; do
        if [[ ! -f "$target/$p" ]]; then
            problem "MISSING: $p"
        elif [[ ! -s "$target/$p" ]]; then
            problem "EMPTY: $p"
        fi
    done
    ;;
*)
    usage
    ;;
esac

if ((problems > 0)); then
    echo "error: $mode payload $target is incomplete ($problems problem(s)) — a sandbox installed from it cannot boot every configuration" >&2
    exit 1
fi
echo "payload OK: $mode $target"
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `chmod +x packaging/verify-payload.sh && python3 packaging/verify-payload.test.py`
Expected: `Ran 15 tests … OK`.

- [ ] **Step 5: Write the failing Rust guard tests**

In `crates/izba-core/src/artifacts.rs`, inside the existing `#[cfg(test)] mod tests`, first TIGHTEN the existing `every_kernel_variant_is_installed_by_the_debian_package`: its `script.contains(&dest)` is satisfied for `vmlinux` by the `vmlinux-usb` line. Replace the `for` loop body so the match includes the closing quote that ends the destination in `build-deb.sh` (`"$STAGE/usr/lib/izba/artifacts/vmlinux"`):

```rust
        for v in KernelVariant::ALL {
            // The closing quote is part of the needle: `vmlinux` is a prefix of
            // `vmlinux-usb`, so a bare substring match on the base kernel would
            // be satisfied by the USB kernel's line and prove nothing.
            let dest = format!("usr/lib/izba/artifacts/{}\"", v.image());
            assert!(
                script.contains(&dest),
                "packaging/build-deb.sh installs no {dest}: a sandbox needing the \
                 {:?} kernel cannot start from an installed build",
                v
            );
        }
```

Then add, directly after that test:

```rust
    /// The repo root, from this crate's manifest dir.
    fn repo_root() -> &'static std::path::Path {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
    }

    #[test]
    fn every_kernel_variant_is_checked_by_the_payload_verifier() {
        // #191: the packaging manifests and the check over them are separate
        // files, so the verifier's list is pinned to the enum the same way the
        // .deb manifest is — the next variant fails here until the verifier
        // (and therefore every installer build) demands it.
        let script = std::fs::read_to_string(repo_root().join("packaging/verify-payload.sh"))
            .expect("packaging/verify-payload.sh must be readable from the crate");
        let list = script
            .lines()
            .find_map(|l| l.strip_prefix("ARTIFACTS=(")?.strip_suffix(')'))
            .expect("packaging/verify-payload.sh must define ARTIFACTS=(...) on one line");
        // Whole tokens, not substrings: `vmlinux` must not be satisfied by
        // `vmlinux-usb`.
        let names: Vec<&str> = list.split_whitespace().collect();
        for v in KernelVariant::ALL {
            assert!(
                names.contains(&v.image()),
                "packaging/verify-payload.sh does not require {}: an installer \
                 missing the {:?} kernel would pass verification",
                v.image(),
                v
            );
        }
        assert!(
            names.contains(&"initramfs.cpio.gz"),
            "packaging/verify-payload.sh does not require initramfs.cpio.gz"
        );
    }

    #[test]
    fn every_installer_build_runs_the_payload_verifier() {
        // A verifier with a test and no call site is the defect class this
        // feature keeps producing: the rule exists, nothing invokes it. Both
        // workflows that build installers must run it in both modes.
        for wf in [".github/workflows/release.yml", ".github/workflows/devbuild.yml"] {
            let text = std::fs::read_to_string(repo_root().join(wf))
                .unwrap_or_else(|e| panic!("{wf} must be readable from the crate: {e}"));
            for mode in ["deb", "stage"] {
                let call = format!("packaging/verify-payload.sh {mode} ");
                assert!(
                    text.contains(&call),
                    "{wf} never runs `{call}…`: an installer missing a kernel \
                     would be built and uploaded unchecked"
                );
            }
        }
    }
```

- [ ] **Step 6: Run the guard tests and confirm the workflow one fails**

Run: `cargo test -p izba-core --lib artifacts::tests::every_ -- --nocapture`
Expected: `every_kernel_variant_is_installed_by_the_debian_package` PASS, `every_kernel_variant_is_checked_by_the_payload_verifier` PASS (the script from step 3 exists), `every_installer_build_runs_the_payload_verifier` FAIL with `.github/workflows/release.yml never runs \`packaging/verify-payload.sh deb …\``.

- [ ] **Step 7: Wire the verifier into the workflows**

`.github/workflows/devbuild.yml`, job `package-deb` — insert between the `Build the .deb` step and its `upload-artifact` step:

```yaml
      - name: Verify the .deb payload (both kernels, initramfs, VNC bundle, VMM tools)
        run: packaging/verify-payload.sh deb dist/izba_*_amd64.deb
```

`.github/workflows/devbuild.yml`, job `package-windows` — insert between `Stage openvmm.exe into libexec` and `Build installer with Inno Setup`:

```yaml
      - name: Verify the installer stage (both kernels, initramfs, VNC bundle, VMM tools)
        # izba.iss installs artifacts\* and bin\libexec\* by GLOB, so a file
        # missing here is silently omitted from the installer, not an error.
        shell: bash
        run: packaging/verify-payload.sh stage stage
```

`.github/workflows/release.yml` — the same two steps, at the same two positions in its `package-deb` and `package-windows` jobs (identical YAML).

`.github/workflows/release.yml`, job `smoke` — add a checkout as the FIRST step (the job currently only downloads artifacts and has no script to run):

```yaml
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
```

and in its `Verify .deb layout + symlink` step replace the hand-rolled `for p in … done` loop AND the following `echo "$contents" | grep -qF 'usr/bin/izba -> …'` check with one call, keeping the step-summary block above it and the final echo:

```yaml
          packaging/verify-payload.sh deb "$deb"
          echo "deb layout OK"
```

`.github/workflows/ci.yml`, job `hack script tests` — add after the existing `Run fetch-openvmm.sh fallback tests` step:

```yaml
      - name: Run installer payload verifier tests
        run: python3 packaging/verify-payload.test.py
```

- [ ] **Step 8: Run the guard tests and confirm they pass**

Run: `cargo test -p izba-core --lib artifacts::tests::every_ -- --nocapture`
Expected: 3 passed.

- [ ] **Step 9: Update the recipe comment and the packaging docs**

`packaging/windows/izba.iss` — in the header's "Expected stage layout" list add the line `;   <StageDir>\artifacts\kasmvnc.erofs` after the `initramfs.cpio.gz` line, then add after the list:

```
; The artifacts\ and bin\libexec\ entries below are GLOBS: a file missing from
; the stage is silently left out of the installer. Run
;   packaging/verify-payload.sh stage <StageDir>
; before iscc (the release and devbuild workflows do).
```

`hack/README.md` — in the `## Packaging (release installers)` section add a paragraph:

```markdown
`packaging/verify-payload.sh` asserts that an installer payload carries every
boot artifact and VMM tool: `verify-payload.sh deb <izba_*.deb>` reads the built
package's contents, `verify-payload.sh stage <StageDir>` checks the Windows
installer's input directory (which `izba.iss` installs by glob, so an absent
file would otherwise be omitted silently). Both packaging workflows run it on
every build; its own tests are `python3 packaging/verify-payload.test.py`.
```

- [ ] **Step 10: Run the gates**

Run:
```sh
[ -f .cargo-env ] && source .cargo-env
python3 packaging/verify-payload.test.py
cargo test -p izba-core --lib artifacts::
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```
Expected: all green.

- [ ] **Step 11: Commit**

```bash
git add packaging/verify-payload.sh packaging/verify-payload.test.py \
  crates/izba-core/src/artifacts.rs .github/workflows/ci.yml \
  .github/workflows/devbuild.yml .github/workflows/release.yml \
  packaging/windows/izba.iss hack/README.md
git status --short
git commit -m "test(packaging): fail an installer build that is missing a kernel

Refs #191

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Linux e2e resolves the USB kernel the way an installed build does

**Files:**
- Modify: `crates/izba-cli/tests/usb_attach_e2e.rs`
- Modify: `.github/workflows/e2e.yml` (job `linux-kvm`)
- Modify: `docs/testing.md` (new subsection under `## 5. Daemon e2e`, after `### VNC desktop exercise`)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `enum Artifacts { Injected, Installed }`, `fn izba_as<S: AsRef<OsStr>>(how: Artifacts, data: &Path, args: &[S]) -> Output`, `fn installed_artifacts_dir() -> PathBuf` in `usb_attach_e2e.rs`; CI stages `target/artifacts/{vmlinux,vmlinux-usb,initramfs.cpio.gz}` in `linux-kvm`.

**Background the implementer needs.** `izba_core::artifacts::locate` resolves the kernel + initramfs pair in this order: (1) `$IZBA_KERNEL_USB` (or `$IZBA_KERNEL` for a sandbox without grants) together with `$IZBA_INITRAMFS`; (2) `<exe-dir>/../artifacts/` — what a `.deb` or the Windows installer ships next to the binary; (3) `<data>/artifacts/`. Every existing case in this suite runs with the overrides of (1) set by CI, which is exactly the path an installed user never takes. `CARGO_BIN_EXE_izba` is `target/debug/izba`, so (2) is `target/artifacts/`. `izbad` is auto-spawned by the first `izba` call against a data root and inherits THAT call's environment, and the test's data root is a fresh tempdir with no `artifacts/` dir — so if every call in a test strips the overrides, (2) is the only place a kernel can come from.

- [ ] **Step 1: Write the failing test**

In `crates/izba-cli/tests/usb_attach_e2e.rs`:

Replace the existing `izba` helper with a mode-taking one plus a thin wrapper (all existing call sites keep compiling unchanged):

```rust
/// Where a run gets its boot artifacts from.
#[derive(Clone, Copy)]
enum Artifacts {
    /// Whatever the environment says — in CI, the `IZBA_KERNEL*` overrides.
    Injected,
    /// The way an installed build finds them: no overrides at all, so the
    /// kernel can only come from `<exe-dir>/../artifacts`.
    Installed,
}

/// Every environment variable that hands izba a boot artifact directly.
const ARTIFACT_OVERRIDES: [&str; 3] = ["IZBA_KERNEL", "IZBA_KERNEL_USB", "IZBA_INITRAMFS"];

/// The directory an installed build keeps its boot artifacts in, relative to
/// the binary under test: `<exe-dir>/../artifacts` (`/usr/lib/izba/artifacts`
/// for the .deb, `{app}\artifacts` for the Windows installer, and
/// `target/artifacts` here).
fn installed_artifacts_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_izba"))
        .parent()
        .and_then(Path::parent)
        .expect("the izba binary has a grandparent dir")
        .join("artifacts")
}

fn izba_as<S: AsRef<std::ffi::OsStr>>(how: Artifacts, data: &Path, args: &[S]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_izba"));
    cmd.env("IZBA_DATA_DIR", data).args(args);
    if matches!(how, Artifacts::Installed) {
        for var in ARTIFACT_OVERRIDES {
            cmd.env_remove(var);
        }
    }
    cmd.output().expect("run izba")
}

fn izba<S: AsRef<std::ffi::OsStr>>(data: &Path, args: &[S]) -> Output {
    izba_as(Artifacts::Injected, data, args)
}
```

Add this test after `a_granted_device_reaches_the_workload_and_carries_bytes_both_ways`:

```rust
#[test]
fn a_granted_device_attaches_on_the_kernel_an_installed_build_resolves() {
    // #191. Every other case here is handed its kernel through IZBA_KERNEL_USB
    // — precisely the path an installed user never takes, and the reason a
    // build that shipped no USB kernel at all (#189) passed a fully green
    // board. This case takes the overrides away: the data root is a fresh
    // tempdir with no `artifacts/`, so the ONLY place left to find a kernel is
    // next to the binary, where an installer puts it.
    //
    // EVERY izba invocation below goes through `Artifacts::Installed`. izbad is
    // spawned by the first one and inherits its environment; one stray call
    // with the overrides intact could hand the daemon a kernel and this would
    // prove nothing.
    let Some(env) = want() else { return };
    let staged = installed_artifacts_dir();
    for f in ["vmlinux-usb", "initramfs.cpio.gz"] {
        assert!(
            staged.join(f).is_file(),
            "IZBA_INTEGRATION=1 but {} is not staged — this case boots from the \
             installed layout, never from an override. Stage it with:\n  \
             mkdir -p {dir} && cp dist/vmlinux dist/vmlinux-usb dist/initramfs.cpio.gz {dir}/",
            staged.join(f).display(),
            dir = staged.display(),
        );
    }
    let fake = FakeUsbipd::start(&env);
    let data = tempfile::tempdir().unwrap();
    let how = Artifacts::Installed;
    let name = "usbinstalled";

    ok(
        &izba_as(how, data.path(), &["usb", "upstream", "set", &fake.addr]),
        "usb upstream set",
    );
    assert!(
        !data.path().join("artifacts").exists(),
        "the data root must hold no artifacts, or the lookup could be satisfied there"
    );
    ok(
        &izba_as(how, data.path(), &create_args(data.path(), name)),
        "create",
    );
    ok(
        &izba_as(
            how,
            data.path(),
            &[
                "usb",
                "allow",
                name,
                "--device",
                DEVICE,
                "--confirm",
                DEVICE,
            ],
        ),
        "usb allow",
    );
    ok(
        &izba_as(how, data.path(), &["start", name]),
        "start on the installed-layout USB kernel",
    );
    ok(
        &izba_as(how, data.path(), &["usb", "attach", name, "--device", DEVICE]),
        "usb attach",
    );

    // Behavioural, like the central case: the node exists in the container and
    // bytes come back, which only a kernel with vhci-hcd + cdc-acm can do.
    let echoed = {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let o = izba_as(
                how,
                data.path(),
                &[
                    "exec",
                    name,
                    "--",
                    "sh",
                    "-c",
                    "stty -F /dev/izba/ttyACM0 raw -echo && exec 3<>/dev/izba/ttyACM0 && \
                     printf hello >&3 && timeout 10 head -c5 <&3",
                ],
            );
            if o.status.success() || Instant::now() >= deadline {
                break o;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    ok(&echoed, "serial echo on the installed-layout kernel");
    assert_eq!(
        String::from_utf8_lossy(&echoed.stdout).trim(),
        "hello",
        "the bytes written must come back: {}",
        out(&echoed)
    );

    let _ = izba_as(how, data.path(), &["rm", "-f", name]);
}
```

Update the module doc comment's gating paragraph (lines 11–20) to mention the new requirement — append after the code block:

```rust
//!
//! One case, `a_granted_device_attaches_on_the_kernel_an_installed_build_resolves`,
//! runs with every one of those overrides REMOVED and needs the artifacts staged
//! where an installer puts them, next to the binary:
//!
//! ```text
//! mkdir -p target/artifacts
//! cp dist/vmlinux dist/vmlinux-usb dist/initramfs.cpio.gz target/artifacts/
//! ```
```

- [ ] **Step 2: Confirm it compiles on both targets and self-skips without the gate**

Run:
```sh
[ -f .cargo-env ] && source .cargo-env
cargo test -p izba-cli --test usb_attach_e2e -- --test-threads=1
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
cargo fmt --check
```
Expected: 8 tests "pass" by self-skipping (`SKIP: set IZBA_INTEGRATION=1 …`), clippy and fmt clean.

The real-VM RED/GREEN for this test (it must FAIL naming the missing staged file before `target/artifacts` is populated, then PASS after) needs KVM and is run by the controller outside the Bash sandbox — do not attempt it; report that it is pending.

- [ ] **Step 3: Stage the artifacts in the `linux-kvm` job**

In `.github/workflows/e2e.yml`, job `linux-kvm`, directly AFTER the existing step `Verify kasmvnc.erofs staged (fail loudly, never silently skip the VNC e2e)` add:

```yaml
      - name: Stage boot artifacts at the production exe-relative discovery path
        # #191: every other USB e2e case is handed its kernel through
        # IZBA_KERNEL_USB — the path an installed user never takes, and why a
        # build that shipped no USB kernel (#189) passed a green board. One case
        # runs with the overrides removed and must find the kernels where an
        # installer puts them: <exe-dir>/../artifacts (target/artifacts for
        # target/debug/izba). Installer-shaped on purpose: BOTH kernels + the
        # initramfs, exactly what packaging/build-deb.sh ships.
        #
        # ORDER IS LOAD-BEARING: after Swatinem/rust-cache, which replaces
        # target/ wholesale (see the kasmvnc staging step above).
        run: |
          mkdir -p target/artifacts
          cp dist/vmlinux dist/vmlinux-usb dist/initramfs.cpio.gz target/artifacts/
          for f in vmlinux vmlinux-usb initramfs.cpio.gz; do
            test -s "target/artifacts/$f" || { echo "target/artifacts/$f missing or empty" >&2; exit 1; }
          done
```

- [ ] **Step 4: Document the local run**

In `docs/testing.md`, add a subsection after `### VNC desktop exercise (`vnc_desktop_e2e`)` and before `## 5a. Code coverage`:

```markdown
### USB passthrough exercise (`usb_attach_e2e`)

Boots real microVMs on the USB kernel variant, attaches a device from a fake
usbip server over the real `vhci-hcd`-over-vsock-1028 path, and asserts the tty
appears inside the container and carries bytes both ways. Beyond the usual
artifacts it needs the USB kernel and the fake server (an excluded crate that
links libusb — `sudo apt install libusb-1.0-0-dev`):

```sh
cargo build --release --manifest-path hack/fake-usbipd/Cargo.toml
IZBA_INTEGRATION=1 IZBA_KERNEL=dist/vmlinux IZBA_KERNEL_USB=dist/vmlinux-usb \
  IZBA_INITRAMFS=dist/initramfs.cpio.gz \
  IZBA_FAKE_USBIPD=hack/fake-usbipd/target/release/fake-usbipd \
  cargo test -p izba-cli --test usb_attach_e2e -- --test-threads=1 --nocapture
```

With `IZBA_INTEGRATION=1` a missing artifact FAILS the suite rather than
skipping it. One case
(`a_granted_device_attaches_on_the_kernel_an_installed_build_resolves`) runs
with every `IZBA_KERNEL*` / `IZBA_INITRAMFS` override removed, so it resolves
the kernel the way a `.deb` or installer user does — from
`<exe-dir>/../artifacts`. Stage that directory first:

```sh
mkdir -p target/artifacts
cp dist/vmlinux dist/vmlinux-usb dist/initramfs.cpio.gz target/artifacts/
```

The Windows/OpenVMM counterpart is `hack/ci/usb-attach-gate.ps1` (§8).
```

- [ ] **Step 5: Run the gates and commit**

```bash
[ -f .cargo-env ] && source .cargo-env
cargo test -p izba-cli --test usb_attach_e2e
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
git add crates/izba-cli/tests/usb_attach_e2e.rs .github/workflows/e2e.yml docs/testing.md
git status --short
git commit -m "test(e2e): attach a USB device on the kernel an installed build resolves

Refs #191

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Windows/OpenVMM USB attach gate

**Files:**
- Create: `hack/ci/usb-attach-gate.ps1`
- Modify: `.github/workflows/e2e.yml` (job `windows-whp`)
- Modify: `crates/izba-core/src/artifacts.rs` (tests module — one guard test)
- Modify: `docs/testing.md` (`## 8. Windows validation`)
- Modify: `hack/README.md` (next to the `ci/ttystorm-gate.*` entry)

**Interfaces:**
- Consumes: the `repo_root()` test helper added to `artifacts.rs` tests in Task 1.
- Produces: `hack/ci/usb-attach-gate.ps1`. Env in: `IZBA_EXE` (required), `IZBA_FAKE_USBIPD` (required), `IZBA_IMAGE` (default `alpine:3.20`), `IZBA_DATA_DIR` (default `%TEMP%\izba-usb-<pid>`). Exit 0 and a final `ALL PASS` line when every check passed; exit 1 otherwise.

**Background the implementer needs.** On Windows the VMM is OpenVMM under WHP. The guest dials vsock CID 2 port 1028; OpenVMM's hybrid-vsock bridge turns that into a connect to the AF_UNIX socket `<data>\run\<hex8>\vsock.sock_1028`, which izbad binds only while the sandbox holds a grant and an upstream is configured. This path has never run end to end on OpenVMM. The fake server (`hack/fake-usbipd`) prints the address it bound as its first stdout line, then serves one CDC-ACM device `0403:6001` that echoes. `izba usb allow` needs `--confirm <vid:pid>` to run unattended. Hosted Windows runners intermittently stall a nested WHP boot before the guest prints anything; a retry absorbs it (see `Invoke-BootWithRetry` in `hack/spike/validate-izba-windows.ps1`).

- [ ] **Step 1: Write the failing guard test**

In `crates/izba-core/src/artifacts.rs` tests module, after `every_installer_build_runs_the_payload_verifier`:

```rust
    #[test]
    fn e2e_ci_attaches_a_usb_device_on_both_platforms() {
        // #191: Windows is the platform USB passthrough exists for (usbipd-win
        // lives there) and was the one platform with no e2e of it. Pin that the
        // real-VM workflow drives an attach on each: the Rust suite on KVM, the
        // PowerShell gate on WHP — fed the fake server it needs.
        let e2e = std::fs::read_to_string(repo_root().join(".github/workflows/e2e.yml"))
            .expect(".github/workflows/e2e.yml must be readable from the crate");
        assert!(
            e2e.contains("--test usb_attach_e2e"),
            "e2e.yml no longer runs the Linux/KVM USB attach suite"
        );
        assert!(
            e2e.contains("hack/ci/usb-attach-gate.ps1"),
            "e2e.yml runs no Windows/OpenVMM USB attach: the vsock-1028 plane \
             over OpenVMM's hybrid-vsock bridge would be taken on trust"
        );
        assert!(
            e2e.contains("fake-usbipd.exe"),
            "e2e.yml never hands the Windows gate a fake usbip server \
             (IZBA_FAKE_USBIPD=…\\fake-usbipd.exe)"
        );
        assert!(
            repo_root().join("hack/ci/usb-attach-gate.ps1").is_file(),
            "hack/ci/usb-attach-gate.ps1 is referenced by e2e.yml but missing"
        );
    }
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `cargo test -p izba-core --lib artifacts::tests::e2e_ci_attaches -- --nocapture`
Expected: FAIL with `e2e.yml runs no Windows/OpenVMM USB attach…`.

- [ ] **Step 3: Write the gate script**

Create `hack/ci/usb-attach-gate.ps1`:

```powershell
# USB passthrough gate (Windows/OpenVMM): a granted device must reach the
# workload over vhci -> vsock 1028 -> OpenVMM's hybrid-vsock bridge -> izbad ->
# TCP -> a usbip server, and carry bytes both ways (#191).
#
# Windows is the platform this feature exists for (usbipd-win runs here), so
# this is the counterpart of crates/izba-cli/tests/usb_attach_e2e.rs for the
# one VMM that suite cannot reach. The upstream is hack/fake-usbipd: one
# CDC-ACM device (0403:6001) that echoes what it is sent.
#
# It also resolves the kernel the way an INSTALLED build does. Every boot
# artifact override is removed from this process before the first izba call
# (the one that spawns izbad, which inherits our environment), and the data
# root is fresh, so the only place a kernel can come from is
# <exe-dir>\..\artifacts -- where the installer puts it. A build that ships no
# vmlinux-usb (#189) fails here instead of passing on an injected kernel.
#
# Env: IZBA_EXE, IZBA_FAKE_USBIPD (required); IZBA_IMAGE (default alpine:3.20);
#      IZBA_DATA_DIR (default: a per-run dir under %TEMP%).
$ErrorActionPreference = 'Continue'

$exe    = $env:IZBA_EXE
$fake   = $env:IZBA_FAKE_USBIPD
$image  = if ($env:IZBA_IMAGE) { $env:IZBA_IMAGE } else { 'alpine:3.20' }
$device = '0403:6001'
$name   = 'usbgate'
$tmp    = [System.IO.Path]::GetTempPath()
$data   = if ($env:IZBA_DATA_DIR) { $env:IZBA_DATA_DIR } else { Join-Path $tmp "izba-usb-$PID" }
$ws     = Join-Path $tmp "izba-usb-ws-$PID"
$fakeOut = Join-Path $tmp "izba-fake-usbipd-$PID.out"
$fails  = 0

function Check($what, $ok) {
    if ($ok) {
        Write-Output "PASS  $what"
    } else {
        [Console]::Error.WriteLine("FAIL  $what")
        $script:fails++
    }
}

function Fail-Preflight($why) {
    [Console]::Error.WriteLine("usb gate cannot run: $why")
    exit 1
}

# --- preflight: everything this needs, named when absent. A USB gate that
# quietly passes because it never ran is worse than no gate.
if (-not $exe -or -not (Test-Path $exe -PathType Leaf)) {
    Fail-Preflight "IZBA_EXE must point at izba.exe (got '$exe')"
}
if (-not $fake -or -not (Test-Path $fake -PathType Leaf)) {
    Fail-Preflight "IZBA_FAKE_USBIPD must point at the built hack/fake-usbipd binary (got '$fake')"
}

# Installed-layout resolution: no overrides, no data-root artifacts.
foreach ($var in 'IZBA_KERNEL', 'IZBA_KERNEL_USB', 'IZBA_INITRAMFS') {
    Remove-Item "Env:$var" -ErrorAction SilentlyContinue
    if (Test-Path "Env:$var") { Fail-Preflight "could not clear $var" }
}
$artifacts = Join-Path (Split-Path (Split-Path $exe -Parent) -Parent) 'artifacts'
foreach ($f in 'vmlinux-usb', 'initramfs.cpio.gz') {
    $p = Join-Path $artifacts $f
    if (-not (Test-Path $p -PathType Leaf)) {
        Fail-Preflight "$p is not staged -- this gate boots from the installed layout (<exe-dir>\..\artifacts), never from an override"
    }
}
if (Test-Path (Join-Path $data 'artifacts')) {
    Fail-Preflight "data root $data already has an artifacts dir -- the kernel lookup could be satisfied there instead of next to the binary"
}
New-Item -ItemType Directory -Path $data -Force | Out-Null
New-Item -ItemType Directory -Path $ws -Force | Out-Null
$env:IZBA_DATA_DIR = $data

function Show-Diagnostics {
    foreach ($log in @(
            (Join-Path $data "sandboxes\$name\logs\console.log"),
            (Join-Path $data "sandboxes\$name\logs\vmm.log"),
            (Join-Path $data 'daemon\daemon.log'))) {
        [Console]::Error.WriteLine("  --- tail $log ---")
        Get-Content $log -Tail 25 -ErrorAction SilentlyContinue |
            ForEach-Object { [Console]::Error.WriteLine("    $_") }
    }
}

# Boot an already-created sandbox, retrying the documented hosted-runner
# nested-WHP stall. Stop-only between attempts: the grant lives in the config
# and must survive.
function Start-WithRetry([int] $Attempts = 3) {
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        & $exe start $name | Out-Null
        if ($LASTEXITCODE -eq 0) { return $true }
        [Console]::Error.WriteLine("  start attempt $attempt/$Attempts failed (exit $LASTEXITCODE)")
        Show-Diagnostics
        & $exe stop $name 2>$null | Out-Null
    }
    return $false
}

$fakeProc = $null
try {
    # The server announces the address it bound as its first line; an ephemeral
    # port keeps a real usbipd on 3240 (this is a usbipd-win host) out of it.
    $fakeProc = Start-Process -FilePath $fake -ArgumentList '127.0.0.1:0' `
        -RedirectStandardOutput $fakeOut -NoNewWindow -PassThru
    $addr = $null
    $deadline = (Get-Date).AddSeconds(15)
    while (-not $addr -and (Get-Date) -lt $deadline) {
        $line = Get-Content $fakeOut -TotalCount 1 -ErrorAction SilentlyContinue
        if ($line -match '^\s*(127\.0\.0\.1:\d+)\s*$') { $addr = $Matches[1] }
        else { Start-Sleep -Milliseconds 200 }
    }
    Check 'fake usbip server announced its address' ($null -ne $addr)
    if ($null -eq $addr) { throw 'no upstream to attach from' }

    & $exe usb upstream set $addr | Out-Null
    Check 'usb upstream set exits 0' ($LASTEXITCODE -eq 0)

    & $exe create $ws --name $name --image $image | Out-Null
    Check 'create exits 0' ($LASTEXITCODE -eq 0)

    # The grant must exist BEFORE the start: it is what selects the USB kernel.
    & $exe usb allow $name --device $device --confirm $device | Out-Null
    Check 'usb allow exits 0' ($LASTEXITCODE -eq 0)

    $booted = Start-WithRetry
    Check 'sandbox boots on the USB kernel resolved from the installed layout' $booted
    if (-not $booted) { throw 'sandbox did not boot' }

    $state = Get-Content (Join-Path $data "sandboxes\$name\state.json") -Raw -ErrorAction SilentlyContinue |
        ConvertFrom-Json -ErrorAction SilentlyContinue
    Check 'state.json records the USB kernel as the one booted' ($null -ne $state -and $state.usb_kernel -eq $true)

    # izbad's half of the plane: the AF_UNIX listener OpenVMM bridges vsock
    # 1028 to. Enumerated, not Test-Path'd: an AF_UNIX socket is a reparse
    # point some APIs refuse to stat.
    $plane = @(Get-ChildItem (Join-Path $data 'run') -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'vsock.sock_1028' })
    Check 'izbad bound the USB plane (vsock.sock_1028)' ($plane.Count -ge 1)

    $attachOut = (& $exe usb attach $name --device $device 2>&1 | Out-String)
    $attachRc  = $LASTEXITCODE
    Check 'usb attach exits 0' ($attachRc -eq 0)
    if ($attachRc -ne 0) { [Console]::Error.WriteLine("  attach said: $($attachOut.Trim())") }

    # The node must appear inside the CONTAINER, not merely in the guest.
    $listing = ''
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $listing = (& $exe exec $name -- sh -c 'ls /dev/izba/' 2>&1 | Out-String)
        if ($listing -match 'ttyACM') { break }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    Check 'the device node appears inside the container (/dev/izba/ttyACM*)' ($listing -match 'ttyACM')

    # The behavioural assertion: bytes written come back. Raw mode first -- a
    # canonical tty holds input until a newline -- and `timeout` so a reply
    # that never arrives fails instead of hanging the job.
    $echo = (& $exe exec $name -- sh -c 'stty -F /dev/izba/ttyACM0 raw -echo && exec 3<>/dev/izba/ttyACM0 && printf hello >&3 && timeout 10 head -c5 <&3' 2>&1 | Out-String).Trim()
    $echoRc = $LASTEXITCODE
    Check 'bytes written to the device come back (hello)' ($echoRc -eq 0 -and $echo -eq 'hello')
    if ($echoRc -ne 0 -or $echo -ne 'hello') {
        [Console]::Error.WriteLine("  echo rc=$echoRc out='$echo'")
    }

    & $exe usb detach $name --device $device | Out-Null
    Check 'usb detach exits 0' ($LASTEXITCODE -eq 0)
    $gone = $false
    $deadline = (Get-Date).AddSeconds(15)
    do {
        & $exe exec $name -- sh -c 'ls /dev/izba/ttyACM0' 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { $gone = $true; break }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    Check 'the device node is gone after detach' $gone
}
catch {
    [Console]::Error.WriteLine("usb gate aborted: $($_.Exception.Message)")
    $fails++
}
finally {
    if ($fails -gt 0) { Show-Diagnostics }
    & $exe rm --force $name 2>$null | Out-Null
    & $exe daemon stop 2>$null | Out-Null
    if ($null -ne $fakeProc -and -not $fakeProc.HasExited) {
        Stop-Process -Id $fakeProc.Id -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $fakeOut -Force -ErrorAction SilentlyContinue
    Remove-Item $ws -Recurse -Force -ErrorAction SilentlyContinue
    # Keep the data root on failure: its logs are the evidence.
    if ($fails -eq 0) { Remove-Item $data -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Output '---'
if ($fails -eq 0) { Write-Output 'ALL PASS'; exit 0 }
[Console]::Error.WriteLine("$fails check(s) FAILED (data root kept at $data)")
exit 1
```

- [ ] **Step 4: Wire it into the `windows-whp` job**

In `.github/workflows/e2e.yml`, job `windows-whp`:

1. `needs:` becomes `[kernel, kernel-usb, initramfs, erofs-exe, kasmvnc-erofs]`.
2. After the existing `vmlinux` download step add:

```yaml
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: vmlinux-usb
          path: dist/
```

3. Directly after the step `Verify kasmvnc.erofs staged (fail loudly, never silently skip VNC)` add:

```yaml
      - name: Stage boot artifacts at the production exe-relative discovery path
        # #191: the USB gate boots with every IZBA_KERNEL*/IZBA_INITRAMFS
        # override removed, so it must find the kernels where the installer
        # puts them: <exe-dir>\..\artifacts (target\artifacts for
        # target\release\izba.exe). Installer-shaped: both kernels + initramfs.
        # ORDER IS LOAD-BEARING: after Swatinem/rust-cache (see above).
        shell: bash
        run: |
          mkdir -p target/artifacts
          cp dist/vmlinux dist/vmlinux-usb dist/initramfs.cpio.gz target/artifacts/
          for f in vmlinux vmlinux-usb initramfs.cpio.gz; do
            test -s "target/artifacts/$f" || { echo "target/artifacts/$f missing or empty" >&2; exit 1; }
          done
```

4. Directly after the step `ttystorm M0 churn gate` (and before `ConPTY environment diagnostics`) add:

```yaml
      # USB passthrough over OpenVMM's hybrid-vsock bridge (#191). The fake
      # usbip server is an EXCLUDED crate (it links libusb, vendored by
      # libusb1-sys on MSVC) built only here and in linux-kvm.
      - name: Build the fake usbip server (excluded crate)
        shell: bash
        run: cargo build --locked --release --manifest-path hack/fake-usbipd/Cargo.toml
      - name: USB passthrough gate (real vhci over vsock 1028, installed-layout kernel)
        env:
          IZBA_EXE: ${{ github.workspace }}\target\release\izba.exe
          IZBA_FAKE_USBIPD: ${{ github.workspace }}\hack\fake-usbipd\target\release\fake-usbipd.exe
          IZBA_DATA_DIR: ${{ runner.temp }}\usb-data
        run: pwsh -NoProfile -File hack/ci/usb-attach-gate.ps1
```

5. In the final `Upload sandbox logs on failure` step's `path:` list add two lines:

```yaml
            ${{ runner.temp }}\usb-data\sandboxes\*\logs\*
            ${{ runner.temp }}\usb-data\daemon\daemon.log
```

- [ ] **Step 5: Run the guard test and confirm it passes**

Run: `cargo test -p izba-core --lib artifacts::tests::e2e_ci_attaches -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Document it**

`hack/README.md` — after the `### ci/ttystorm-gate.sh / ci/ttystorm-gate.ps1` entry add:

```markdown
### `ci/usb-attach-gate.ps1`

The Windows/OpenVMM USB passthrough gate used by the `windows-whp` job: starts
`hack/fake-usbipd`, grants its device to a fresh sandbox, boots it, attaches,
and asserts `/dev/izba/ttyACM0` appears in the container and echoes bytes — the
vhci → vsock 1028 → OpenVMM hybrid-vsock → izbad → TCP path end to end. It
clears `IZBA_KERNEL` / `IZBA_KERNEL_USB` / `IZBA_INITRAMFS` and uses a fresh
data root, so the kernel is resolved from `<exe-dir>\..\artifacts` exactly as
an installed build does. Env: `IZBA_EXE`, `IZBA_FAKE_USBIPD` (required),
`IZBA_IMAGE` (default `alpine:3.20`), `IZBA_DATA_DIR` (default: a per-run dir
under `%TEMP%`).
```

`docs/testing.md` — at the end of `## 8. Windows validation (manual, spike host)`, before the `**Historical (pre-M1…` paragraph, add:

```markdown
**USB passthrough gate.** `hack/ci/usb-attach-gate.ps1` is a separate script
(its own step in the `windows-whp` job) and uses its own data root, so it never
touches `%LOCALAPPDATA%\izba`. It needs an installer-shaped layout —
`<root>\bin\izba.exe`, `<root>\bin\libexec\{openvmm.exe,mkfs.erofs.exe}`,
`<root>\artifacts\{vmlinux-usb,initramfs.cpio.gz}` — plus a Windows build of the
fake server:

```sh
cargo build --release --target x86_64-pc-windows-gnu --manifest-path hack/fake-usbipd/Cargo.toml
# Windows side:
#   $env:IZBA_EXE = '<root>\bin\izba.exe'
#   $env:IZBA_FAKE_USBIPD = '<path>\fake-usbipd.exe'
#   pwsh -NoProfile -File hack/ci/usb-attach-gate.ps1     # expect: ALL PASS
```
```

- [ ] **Step 7: Run the gates and commit**

```bash
[ -f .cargo-env ] && source .cargo-env
cargo test -p izba-core --lib artifacts::
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
git add hack/ci/usb-attach-gate.ps1 .github/workflows/e2e.yml \
  crates/izba-core/src/artifacts.rs docs/testing.md hack/README.md
git status --short
git commit -m "test(e2e): attach a USB device over OpenVMM on the windows-whp job

Refs #191

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

The real run of the gate (on the Windows host through WSL interop, then on the hosted runner through an `e2e.yml` dispatch) is done by the controller outside the Bash sandbox — do not attempt it; report that it is pending.

---

## Controller verification (not a subagent task)

1. **Linux real-VM RED/GREEN for Task 2** (unsandboxed, KVM): run `usb_attach_e2e` with `IZBA_INTEGRATION=1` before staging `target/artifacts` → the installed-path case must fail naming the missing file; stage → all 8 pass; remove only `target/artifacts/vmlinux-usb` → the case must fail again (this is the #189 class reproduced).
2. **Windows host run for Task 3** (PowerShell interop): cross-build `izba.exe`, `izba-jail-helper.exe`, `fake-usbipd.exe`; stage an installer-shaped tree under `%TEMP%`; run the gate → `ALL PASS`. Then delete the staged `vmlinux-usb` → the gate must fail in preflight.
3. **CI:** push, open the PR, dispatch `e2e.yml` on the branch (it does not run on `pull_request`) and `hack/devbuild.sh` (exercises the payload verifier in both packaging jobs).
