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

    def test_candidate_is_dataclass_with_ref(self):
        c = functional_oracle("izba x", 1, "succeeds",
                              source="spec §1", ref={"journey_id": "j", "action_index": 2})
        self.assertIsInstance(c[0], Candidate)
        self.assertEqual(c[0].trajectory_ref["journey_id"], "j")
        self.assertEqual(c[0].source, "spec §1")


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

    def test_action_round_trips_to_dict(self):
        a = act()
        d = a.to_dict()
        self.assertEqual(json.loads(json.dumps(d))["command"], "izba ls")
        self.assertIn("reconcile", d)


if __name__ == "__main__":
    unittest.main()
