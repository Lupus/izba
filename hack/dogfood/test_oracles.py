"""Unit tests for the deterministic oracle harness (no model, no KVM)."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oracles import (  # noqa: E402
    Action,
    Candidate,
    expects_failure,
    functional_oracle,
    masks_success_with_trivial_fallback,
    implicit_oracle,
    latency_oracle,
    reconcile_seq_oracle,
    run_action,
)


def act(**kw):
    base = dict(
        intent="x",
        command="izba ls",
        exit_code=0,
        stdout_tail="",
        stderr_tail="",
        latency_ms=10,
        reconcile={"violations": []},
    )
    base.update(kw)
    return Action(**base)


class OracleTests(unittest.TestCase):
    def test_panic_in_stderr_is_candidate(self):
        c = implicit_oracle(act(stderr_tail="thread 'main' panicked at foo.rs:1"))
        self.assertTrue(any(x.kind == "implicit" for x in c))

    def test_clean_action_no_candidate(self):
        self.assertEqual(implicit_oracle(act()), [])

    def test_latency_over_budget_is_candidate(self):
        c = latency_oracle(act(latency_ms=99999), budget_ms=1000)
        self.assertTrue(any(x.kind == "latency" for x in c))

    def test_latency_under_budget_no_candidate(self):
        self.assertEqual(latency_oracle(act(latency_ms=10), budget_ms=1000), [])

    def test_assertion_failed_in_stdout_is_candidate(self):
        c = implicit_oracle(act(stdout_tail="assertion failed: x == y"))
        self.assertTrue(any(x.kind == "implicit" for x in c))

    def test_error_line_anchored_is_candidate(self):
        c = implicit_oracle(act(stderr_tail="ERROR: something went wrong"))
        self.assertTrue(any(x.kind == "implicit" for x in c))

    def test_word_error_midline_is_not_candidate(self):
        # "ERROR" only matches anchored at line start; the word "error" mid-text
        # (e.g. "no error occurred") must not trip the oracle.
        self.assertEqual(implicit_oracle(act(stderr_tail="no error occurred")), [])

    def test_exit_127_decoded_as_command_not_found(self):
        c = implicit_oracle(act(exit_code=127))
        self.assertTrue(any("CommandNotFound" in x.detail for x in c))

    def test_exit_signal_decoded(self):
        c = implicit_oracle(act(exit_code=139))  # 128 + 11 (SIGSEGV)
        self.assertTrue(any("Signal(11)" in x.detail for x in c))

    def test_candidate_carries_command_in_detail(self):
        c = implicit_oracle(act(command="izba foo", stderr_tail="panic"))
        self.assertTrue(c)
        self.assertIsInstance(c[0], Candidate)


class FunctionalOracleTests(unittest.TestCase):
    def test_expects_failure_detects_refusal_phrasing(self):
        for s in [
            "rejected with a clear grammar error and a nonzero exit",
            "the removal is refused with a clear in-use error",
            "starting B is refused with a clear single-writer error",
            "the request is denied",
            "create must not succeed",
        ]:
            self.assertTrue(expects_failure(s), s)

    def test_expects_failure_false_on_success_phrasing(self):
        for s in [
            "create succeeds (exit 0) and the volume is listed",
            "rm succeeds with no error",
            "the named volume is still listed after rm",
            "",
        ]:
            self.assertFalse(expects_failure(s), s)

    def test_success_step_nonzero_exit_is_candidate(self):
        c = functional_oracle("izba create x", 1, "create succeeds and is listed")
        self.assertTrue(any(x.kind == "functional" for x in c))

    def test_success_step_zero_exit_is_clean(self):
        self.assertEqual(functional_oracle("izba create x", 0, "create succeeds"), [])

    def test_failure_step_nonzero_exit_is_clean(self):
        # The whole point of the step is a refusal; a non-zero exit is the PASS.
        self.assertEqual(
            functional_oracle("izba create Bad:/d:1g", 1,
                              "rejected with a clear grammar error and nonzero exit"),
            [],
        )

    def test_failure_step_zero_exit_is_candidate(self):
        # A guard that should have fired but the command succeeded == real bug.
        c = functional_oracle("izba volume rm in-use", 0,
                              "the removal is refused with a clear in-use error")
        self.assertTrue(any(x.kind == "functional" for x in c))
        self.assertIn("unexpectedly succeeded", c[0].detail)

    def test_empty_expect_never_fires(self):
        self.assertEqual(functional_oracle("izba ls", 1, ""), [])

    def test_masked_probe_false_green_is_flagged(self):
        # izba#78: the `|| echo` arm makes the compound exit 0 even though the
        # file is gone, so exit 0 must NOT be credited as an expected success.
        c = functional_oracle(
            "izba exec vol -- sh -c 'test -f /data/hello.txt || echo \"file does not exist\"'",
            0, "the persisted file is still present after restart")
        self.assertTrue(any(x.kind == "masked_probe" for x in c))
        self.assertIn("unverifiable", c[0].detail)

    def test_masked_probe_does_not_flip_expected_failure(self):
        # A legit `cmd || true` on an expected-FAILURE step: the refusal path
        # owns exit 0 (silent success == bug) and masking must not double-count
        # or reclassify it. Exit non-zero here is the intended pass -> clean.
        self.assertEqual(
            functional_oracle("izba volume rm in-use || true", 1,
                              "the removal is refused with a clear in-use error"),
            [])

    def test_plain_success_command_unchanged(self):
        # No masking tail -> the ordinary expected-success path is untouched.
        self.assertEqual(
            functional_oracle("izba exec vol -- test -f /data/hello.txt", 0,
                              "the persisted file is still present"), [])
        c = functional_oracle("izba exec vol -- test -f /data/hello.txt", 1,
                              "the persisted file is still present")
        self.assertTrue(any(x.kind == "functional" for x in c))

    def test_masks_success_with_trivial_fallback_heuristic(self):
        for cmd in ("test -f x || echo gone", "cmd || true", "cmd || :",
                    "cmd || printf no"):
            self.assertTrue(masks_success_with_trivial_fallback(cmd), cmd)
        for cmd in ("test -f x", "cmd || grep foo", "cmd || echoserver",
                    "cmd && echo ok", "cmd || izba status"):
            self.assertFalse(masks_success_with_trivial_fallback(cmd), cmd)

    def test_candidate_is_dataclass_with_ref(self):
        c = functional_oracle("izba x", 1, "succeeds",
                              source="spec §1", ref={"journey_id": "j", "action_index": 2})
        self.assertIsInstance(c[0], Candidate)
        self.assertEqual(c[0].trajectory_ref["journey_id"], "j")
        self.assertEqual(c[0].source, "spec §1")


class ExpectExitOracleTests(unittest.TestCase):
    def test_expect_exit_nonzero_pass(self):
        # A declared expected-failure that actually failed -> PASS (no candidate).
        self.assertEqual(
            functional_oracle("izba ssh x -- false", 1, "", expect_exit="nonzero"),
            [],
        )

    def test_expect_exit_nonzero_fail(self):
        # Declared expected-failure that SUCCEEDED (exit 0) -> candidate.
        c = functional_oracle("izba ssh x -- false", 0, "", expect_exit="nonzero")
        self.assertTrue(any(x.kind == "functional" for x in c))
        self.assertIn("unexpectedly succeeded", c[0].detail)

    def test_expect_exit_specific_int_pass(self):
        self.assertEqual(
            functional_oracle("cmd", 1, "", expect_exit=1), [])

    def test_expect_exit_specific_int_fail(self):
        c = functional_oracle("cmd", 2, "", expect_exit=1)
        self.assertTrue(any(x.kind == "functional" for x in c))
        self.assertIn("exited 2", c[0].detail)

    def test_expect_exit_none_falls_back_to_keyword_path(self):
        # expect_exit absent -> the existing English-keyword `expect` path governs.
        self.assertTrue(functional_oracle(
            "izba create x", 1, "create succeeds", expect_exit=None))
        self.assertEqual(functional_oracle(
            "izba create x", 0, "create succeeds", expect_exit=None), [])
        # A True bool must NOT be read as exit code 1 -> still falls back.
        self.assertTrue(functional_oracle(
            "izba create x", 1, "create succeeds", expect_exit=True))


class ExitCodeMappingTests(unittest.TestCase):
    def test_exit_255_is_transport_failure_not_signal_127(self):
        c = implicit_oracle(act(exit_code=255, command="ssh izba-box -- false"))
        self.assertTrue(c)
        detail = " ".join(x.detail for x in c)
        self.assertNotIn("Signal(127)", detail)
        self.assertTrue("transport" in detail or "connection" in detail, detail)
        # ssh/scp family is named.
        self.assertIn("ssh", detail)

    def test_exit_139_still_maps_to_signal_11(self):
        c = implicit_oracle(act(exit_code=139))  # 128 + 11 (SIGSEGV)
        self.assertTrue(any("Signal(11)" in x.detail for x in c))


class ReconcileSeqOracleTests(unittest.TestCase):
    def snap(self, **kw):
        base = dict(name="box", status_daemon="running", status_disk="running",
                    vmm={"pid": 100, "starttime": 5})
        base.update(kw)
        return base

    def test_pid_reused_without_starttime_change_is_candidate(self):
        prev = {"sandboxes": [self.snap(vmm={"pid": 100, "starttime": 5})]}
        cur = {"sandboxes": [self.snap(vmm={"pid": 100, "starttime": 5},
                                       status_disk="running")]}
        # same pid+starttime across a restart-shaped transition is fine on its own;
        # the violation is when pid is reused but starttime is unchanged AND the
        # sandbox was reported stopped in between is not modeled here — instead we
        # test the monotonic-restart shape: pid reused, starttime must differ.
        # Build the violating case: prev stopped, cur running, identical identity.
        prev = {"sandboxes": [self.snap(status_daemon="stopped",
                                        status_disk="stopped",
                                        vmm={"pid": 100, "starttime": 5})]}
        cur = {"sandboxes": [self.snap(status_daemon="running",
                                       status_disk="running",
                                       vmm={"pid": 100, "starttime": 5})]}
        c = reconcile_seq_oracle(prev, cur)
        self.assertTrue(any(x.kind == "reconcile_seq" for x in c))

    def test_restart_with_new_starttime_is_clean(self):
        prev = {"sandboxes": [self.snap(status_daemon="stopped",
                                        status_disk="stopped",
                                        vmm={"pid": 100, "starttime": 5})]}
        cur = {"sandboxes": [self.snap(status_daemon="running",
                                       status_disk="running",
                                       vmm={"pid": 100, "starttime": 9})]}
        self.assertEqual(reconcile_seq_oracle(prev, cur), [])

    def test_removed_to_running_without_create_is_candidate(self):
        prev = {"sandboxes": []}  # box not present at all == removed/absent
        # cur shows it running, but we model "removed->running" via an explicit
        # status transition: prev had it removed, cur running.
        prev = {"sandboxes": [self.snap(status_daemon="removed",
                                        status_disk="stopped")]}
        cur = {"sandboxes": [self.snap(status_daemon="running",
                                       status_disk="running",
                                       vmm={"pid": 200, "starttime": 9})]}
        c = reconcile_seq_oracle(prev, cur)
        self.assertTrue(any(x.kind == "reconcile_seq" for x in c))

    def test_no_sandboxes_is_clean(self):
        self.assertEqual(reconcile_seq_oracle({"sandboxes": []},
                                              {"sandboxes": []}), [])

    def test_missing_sandboxes_key_is_clean(self):
        self.assertEqual(reconcile_seq_oracle({}, {}), [])


def _write_stub(d, body):
    """Write a stub `izba` (named `izba`, so it resolves on PATH) with BODY."""
    stub = os.path.join(d, "izba")
    with open(stub, "w") as f:
        f.write("#!/bin/sh\n"
                'if [ "$1" = "__reconcile" ]; then echo \'{"violations":[],"sandboxes":[]}\'; exit 0; fi\n'
                + body)
    os.chmod(stub, 0o755)
    return stub


class RunActionTests(unittest.TestCase):
    def test_run_action_runs_via_shell_with_izba_on_path(self):
        # The Actor command is a real shell line; izba resolves on PATH.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub(d, "echo hello; exit 0\n")
            a = run_action("izba ls", izba_bin=stub, workdir=d, data_dir=d,
                           timeout_s=10, intent="list")
            self.assertEqual(a.exit_code, 0)
            self.assertIn("hello", a.stdout_tail)
            self.assertGreaterEqual(a.latency_ms, 0)
            self.assertEqual(a.reconcile, {"violations": [], "sandboxes": []})
            self.assertEqual(a.command, "izba ls")

    def test_run_action_supports_real_shell_file_ops(self):
        # Faithful "user at a shell": heredocs/redirects/pipes work; the Actor
        # can write files (e.g. a policy.yaml) — not just call one binary.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub(d, "echo ok; exit 0\n")
            a = run_action("printf 'hi\\n' > note.txt && cat note.txt",
                           izba_bin=stub, workdir=d, data_dir=d, timeout_s=10)
            self.assertEqual(a.exit_code, 0)
            self.assertIn("hi", a.stdout_tail)
            self.assertTrue(os.path.exists(os.path.join(d, "note.txt")))

    def test_run_action_timeout_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub(d, "sleep 30\n")
            a = run_action("izba hang", izba_bin=stub, workdir=d, data_dir=d,
                           timeout_s=1, intent="hang")
            # report-only: timeout must not raise; exit_code reflects the timeout.
            self.assertNotEqual(a.exit_code, 0)

    def test_capture_state_evidence_snapshots_policy_and_netlog(self):
        from oracles import capture_state_evidence
        with tempfile.TemporaryDirectory() as d:
            # Stub: reconcile reports one sandbox; policy/netlog echo identifiable text.
            stub = os.path.join(d, "izba")
            with open(stub, "w") as f:
                f.write(
                    "#!/bin/sh\n"
                    'if [ "$1" = "__reconcile" ]; then echo \'{"sandboxes":[{"name":"sb1"}]}\'; exit 0; fi\n'
                    'if [ "$1" = "policy" ]; then echo "enforce: on"; exit 0; fi\n'
                    'if [ "$1" = "netlog" ]; then echo "ALLOW example.com"; exit 0; fi\n'
                    "exit 0\n")
            os.chmod(stub, 0o755)
            ev = capture_state_evidence(stub, d, timeout_s=10)
            self.assertEqual(ev["sandboxes"], ["sb1"])
            self.assertIn("enforce: on", ev["per_sandbox"]["sb1"]["policy_show"]["stdout"])
            self.assertIn("ALLOW", ev["per_sandbox"]["sb1"]["netlog"]["stdout"])

    def test_run_action_cwd_file_persists_across_two_calls(self):
        # With a cwd_file, `cd sub` in one action must persist so a command in the
        # next action runs inside sub — a real shell session, not fresh each time.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub(d, "echo ok; exit 0\n")
            cwd_file = os.path.join(d, ".cwd")
            os.mkdir(os.path.join(d, "sub"))
            a1 = run_action("cd sub", izba_bin=stub, workdir=d, data_dir=d,
                            timeout_s=10, cwd_file=cwd_file)
            self.assertEqual(a1.exit_code, 0)
            a2 = run_action("pwd", izba_bin=stub, workdir=d, data_dir=d,
                            timeout_s=10, cwd_file=cwd_file)
            self.assertTrue(a2.stdout_tail.strip().endswith("/sub"),
                            a2.stdout_tail)

    def test_run_action_cwd_file_preserves_command_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub(d, "echo ok; exit 0\n")
            cwd_file = os.path.join(d, ".cwd")
            a = run_action("exit 3", izba_bin=stub, workdir=d, data_dir=d,
                           timeout_s=10, cwd_file=cwd_file)
            self.assertEqual(a.exit_code, 3)  # the command's own rc, not the writeback's

    def test_run_action_cwd_file_tolerates_background_and_comment(self):
        # greptile P1: the cwd-persistence wrapper terminates the brace group with
        # a NEWLINE, not `;`. A trailing `&` (background/keep-alive) or a trailing
        # `# comment` must run as product behavior, NOT become a bash syntax error.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub(d, "echo ok; exit 0\n")
            cwd_file = os.path.join(d, ".cwd")
            os.mkdir(os.path.join(d, "sub"))
            # Trailing background job: `{ true & ; }` would be a syntax error.
            a = run_action("true &", izba_bin=stub, workdir=d, data_dir=d,
                           timeout_s=10, cwd_file=cwd_file)
            self.assertEqual(a.exit_code, 0, a.stderr_tail)
            self.assertNotIn("syntax error", a.stderr_tail)
            # Trailing comment must not swallow the closing brace; cwd still persists.
            b = run_action("cd sub  # jump into sub", izba_bin=stub, workdir=d,
                           data_dir=d, timeout_s=10, cwd_file=cwd_file)
            self.assertEqual(b.exit_code, 0, b.stderr_tail)
            c = run_action("pwd", izba_bin=stub, workdir=d, data_dir=d,
                           timeout_s=10, cwd_file=cwd_file)
            self.assertTrue(c.stdout_tail.strip().endswith("/sub"), c.stdout_tail)

    def test_run_action_cwd_file_none_does_not_persist(self):
        # Default (cwd_file=None): each action starts fresh in workdir, so a `cd`
        # in one call does NOT leak into the next — unchanged legacy behavior.
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub(d, "echo ok; exit 0\n")
            os.mkdir(os.path.join(d, "sub"))
            run_action("cd sub", izba_bin=stub, workdir=d, data_dir=d, timeout_s=10)
            a2 = run_action("pwd", izba_bin=stub, workdir=d, data_dir=d, timeout_s=10)
            self.assertFalse(a2.stdout_tail.strip().endswith("/sub"), a2.stdout_tail)
            self.assertFalse(os.path.exists(os.path.join(d, ".cwd")))

    def test_action_round_trips_to_dict(self):
        a = act()
        d = a.to_dict()
        self.assertEqual(json.loads(json.dumps(d))["command"], "izba ls")
        self.assertIn("reconcile", d)


class ReconcileVisibilityTests(unittest.TestCase):
    def test_snapshot_failure_has_error_key(self):
        import oracles
        # A binary that is not there -> OSError path.
        snap = oracles._snapshot_reconcile(
            "/nonexistent/izba", "/tmp", 5,
            oracles._shell_env("/nonexistent/izba", "/tmp"))
        self.assertIn("error", snap)
        self.assertEqual(snap["violations"], [])

    def test_seq_oracle_skips_error_snapshots(self):
        import oracles
        prev = {"error": "boom", "violations": [], "sandboxes": []}
        cur = {"violations": [], "sandboxes": [
            {"name": "s", "status_disk": "running",
             "vmm": {"pid": 1, "starttime": 2}}]}
        self.assertEqual(oracles.reconcile_seq_oracle(prev, cur), [])
        self.assertEqual(oracles.reconcile_seq_oracle(cur, prev), [])


class GuestConsoleTests(unittest.TestCase):
    def _stub(self, d, names=("web",)):
        import json as _json
        stub = os.path.join(d, "izba")
        sandboxes = _json.dumps([{"name": n} for n in names])
        with open(stub, "w") as f:
            f.write(
                "#!/bin/sh\n"
                'if [ "$1" = "__reconcile" ]; then\n'
                f"  echo '{{\"violations\":[],\"sandboxes\":{sandboxes}}}'\n"
                "  exit 0\nfi\n"
                "echo ok\nexit 0\n")
        os.chmod(stub, 0o755)
        return stub

    def test_console_tail_captured_and_panic_flagged(self):
        import oracles
        with tempfile.TemporaryDirectory() as d:
            stub = self._stub(d)
            logdir = os.path.join(d, "sandboxes", "web", "logs")
            os.makedirs(logdir)
            with open(os.path.join(logdir, "console.log"), "w") as f:
                f.write("boot ok\nthread 'main' panicked at init.rs:42\n")
            ev = oracles.capture_state_evidence(stub, d, 5)
            self.assertIn("panicked", ev["per_sandbox"]["web"]["console_tail"])
            cands = oracles.guest_console_oracle(
                ev, {"journey_id": "j", "action_index": -1})
            self.assertEqual(len(cands), 1)
            self.assertEqual(cands[0].kind, "guest_console")

    def test_clean_console_emits_nothing(self):
        import oracles
        with tempfile.TemporaryDirectory() as d:
            stub = self._stub(d)
            logdir = os.path.join(d, "sandboxes", "web", "logs")
            os.makedirs(logdir)
            with open(os.path.join(logdir, "console.log"), "w") as f:
                f.write("boot ok\ninit: reached target\n")
            ev = oracles.capture_state_evidence(stub, d, 5)
            self.assertEqual(oracles.guest_console_oracle(
                ev, {"journey_id": "j", "action_index": -1}), [])

    def test_missing_console_is_empty_not_error(self):
        import oracles
        with tempfile.TemporaryDirectory() as d:
            stub = self._stub(d)
            ev = oracles.capture_state_evidence(stub, d, 5)
            self.assertEqual(ev["per_sandbox"]["web"]["console_tail"], "")


class TimeoutConsoleEvidenceTest(unittest.TestCase):
    def test_timeout_appends_console_tails(self):
        import oracles
        with tempfile.TemporaryDirectory() as td:
            logdir = os.path.join(td, "sandboxes", "webbox", "logs")
            os.makedirs(logdir)
            with open(os.path.join(logdir, "console.log"), "w") as f:
                f.write("guest kernel: mounting /dev/vda\nBOOT STALLED HERE\n")
            a = oracles.run_action(
                "sleep 5", izba_bin="/bin/false", workdir=td,
                data_dir=td, timeout_s=0.2)
        self.assertEqual(a.exit_code, 124)
        self.assertIn("timed out", a.stderr_tail)
        self.assertIn("console.log tail (webbox)", a.stderr_tail)
        self.assertIn("BOOT STALLED HERE", a.stderr_tail)

    def test_timeout_without_console_logs_is_clean(self):
        import oracles
        with tempfile.TemporaryDirectory() as td:
            a = oracles.run_action(
                "sleep 5", izba_bin="/bin/false", workdir=td,
                data_dir=td, timeout_s=0.2)
        self.assertEqual(a.exit_code, 124)
        self.assertNotIn("console.log tail", a.stderr_tail)


class TeardownTests(unittest.TestCase):
    def test_teardown_invokes_rm_force_and_daemon_stop(self):
        import oracles
        with tempfile.TemporaryDirectory() as d:
            calls = os.path.join(d, "calls.log")
            stub = os.path.join(d, "izba")
            with open(stub, "w") as f:
                f.write(f'#!/bin/sh\necho "$@" >> {calls}\nexit 0\n')
            os.chmod(stub, 0o755)
            oracles.teardown_journey(stub, d, 5, ["web", "db"])
            with open(calls) as f:
                lines = f.read().splitlines()
            self.assertIn("rm web --force", lines)
            self.assertIn("rm db --force", lines)
            self.assertIn("daemon stop", lines)

    def test_teardown_never_raises(self):
        import oracles
        oracles.teardown_journey("/nonexistent/izba", "/tmp", 1, ["x"])


if __name__ == "__main__":
    unittest.main()
