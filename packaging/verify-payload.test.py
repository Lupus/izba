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
