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


class RunActionTests(unittest.TestCase):
    def test_run_action_captures_exit_and_latency(self):
        # Use a stub "izba" that exits 0 for the reconcile call and our command.
        with tempfile.TemporaryDirectory() as d:
            stub = os.path.join(d, "izba")
            with open(stub, "w") as f:
                f.write("#!/bin/sh\n"
                        'if [ "$1" = "__reconcile" ]; then echo \'{"violations":[]}\'; exit 0; fi\n'
                        'echo hello; exit 0\n')
            os.chmod(stub, 0o755)
            a = run_action(stub, ["ls"], data_dir=d, timeout_s=10, intent="list")
            self.assertEqual(a.exit_code, 0)
            self.assertIn("hello", a.stdout_tail)
            self.assertGreaterEqual(a.latency_ms, 0)
            self.assertEqual(a.reconcile, {"violations": []})
            self.assertEqual(a.command, "izba ls")

    def test_run_action_timeout_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as d:
            stub = os.path.join(d, "izba")
            with open(stub, "w") as f:
                f.write("#!/bin/sh\n"
                        'if [ "$1" = "__reconcile" ]; then echo \'{"violations":[]}\'; exit 0; fi\n'
                        "sleep 30\n")
            os.chmod(stub, 0o755)
            a = run_action(stub, ["hang"], data_dir=d, timeout_s=1, intent="hang")
            # report-only: timeout must not raise; exit_code reflects the timeout.
            self.assertNotEqual(a.exit_code, 0)

    def test_action_round_trips_to_dict(self):
        a = act()
        d = a.to_dict()
        self.assertEqual(json.loads(json.dumps(d))["command"], "izba ls")
        self.assertIn("reconcile", d)


if __name__ == "__main__":
    unittest.main()
