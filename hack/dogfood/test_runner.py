"""Unit tests for the Actor loop, caps, and runner entrypoint (no model, no KVM).

Everything here runs with a FakeModel and a stub ``izba`` binary, so it needs
neither an API key nor KVM.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_journeys  # noqa: E402
from model import FakeModel  # noqa: E402


def _write_stub_izba(d):
    """A stub `izba` that succeeds for known subcommands and 'fails' for bogus ones."""
    stub = os.path.join(d, "izba")
    with open(stub, "w") as f:
        f.write(
            "#!/bin/sh\n"
            'if [ "$1" = "__reconcile" ]; then echo \'{"violations":[],"sandboxes":[]}\'; exit 0; fi\n'
            'if [ "$1" = "bogus-subcommand" ]; then echo "error: unrecognized subcommand" 1>&2; exit 2; fi\n'
            'if [ "$1" = "panicky" ]; then echo "thread \'main\' panicked at x.rs:1" 1>&2; exit 101; fi\n'
            "echo ok\n"
            "exit 0\n"
        )
    os.chmod(stub, 0o755)
    return stub


def _journeys_file(d, journeys):
    p = os.path.join(d, "journeys.json")
    with open(p, "w") as f:
        json.dump({"feature": "test-feature", "journeys": journeys}, f)
    return p


class ShardSelectionTests(unittest.TestCase):
    def test_shard_selects_modulo(self):
        js = [{"journey_id": f"j{i}", "rationale": "", "source": {},
               "steps": []} for i in range(5)]
        sel = run_journeys.select_shard(js, shard=0, shards=2)
        self.assertEqual([j["journey_id"] for j in sel], ["j0", "j2", "j4"])
        sel = run_journeys.select_shard(js, shard=1, shards=2)
        self.assertEqual([j["journey_id"] for j in sel], ["j1", "j3"])


class RunnerTests(unittest.TestCase):
    def test_failing_command_produces_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "panics",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "do a panicky thing", "expect": "no panic"}],
            }])
            out = os.path.join(d, "traj.json")
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([{"command": "izba panicky"}, {"done": True}]),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "10", "--max-usd", "5",
            ])
            self.assertEqual(rc, 0)  # report-only
            with open(out) as _f:
                bundle = json.load(_f)
            self.assertEqual(bundle["shard"], 0)
            self.assertEqual(bundle["feature"], "test-feature")
            res = bundle["results"][0]
            self.assertTrue(any(c["kind"] == "implicit" for c in res["candidates"]),
                            res["candidates"])

    def test_step_cap_halts_runaway_loop(self):
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "runaway",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "loop forever", "expect": "bounded"}],
            }])
            out = os.path.join(d, "traj.json")
            # A model that NEVER says done and issues a fresh unique command each time.
            script = [{"command": f"izba run-{i}"} for i in range(1000)]
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "5", "--action-timeout-s", "10",
                "--max-turns", "1000", "--max-usd", "5",
            ])
            self.assertEqual(rc, 0)
            with open(out) as _f:
                bundle = json.load(_f)
            actions = bundle["results"][0]["actions"]
            self.assertLessEqual(len(actions), 5, f"step cap not enforced: {len(actions)}")

    def test_loop_dedup_short_circuits_repeat_command(self):
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "dedup",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "repeat", "expect": "bounded"}],
            }])
            out = os.path.join(d, "traj.json")
            # Same command over and over; dedup must stop the journey.
            script = [{"command": "izba ls"} for _ in range(50)]
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "25", "--action-timeout-s", "10",
                "--max-turns", "50", "--max-usd", "5",
            ])
            self.assertEqual(rc, 0)
            with open(out) as _f:
                bundle = json.load(_f)
            actions = bundle["results"][0]["actions"]
            # The repeat is detected after the first run -> at most one real action.
            self.assertLessEqual(len(actions), 1, f"dedup failed: {len(actions)}")

    def test_max_turns_caps_actions(self):
        with tempfile.TemporaryDirectory() as d:
            stub = _write_stub_izba(d)
            jf = _journeys_file(d, [{
                "journey_id": "turns",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "x", "expect": "y"}],
            }])
            out = os.path.join(d, "traj.json")
            script = [{"command": f"izba run-{i}"} for i in range(1000)]
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", stub, "--data-dir", d, "--out", out,
                "--fake-model", json.dumps(script),
                "--step-cap", "100", "--action-timeout-s", "10",
                "--max-turns", "3", "--max-usd", "5",
            ])
            self.assertEqual(rc, 0)
            with open(out) as _f:
                bundle = json.load(_f)
            actions = bundle["results"][0]["actions"]
            self.assertLessEqual(len(actions), 3, f"max-turns not enforced: {len(actions)}")

    def test_infra_error_does_not_raise(self):
        # Point at a non-existent izba binary; the run must still complete and
        # write a bundle (report-only).
        with tempfile.TemporaryDirectory() as d:
            jf = _journeys_file(d, [{
                "journey_id": "infra",
                "rationale": "r",
                "source": {"kind": "spec", "ref": "x"},
                "steps": [{"intent": "x", "expect": "y"}],
            }])
            out = os.path.join(d, "traj.json")
            rc = run_journeys.main([
                "--journeys", jf, "--shard", "0", "--shards", "1",
                "--izba-bin", os.path.join(d, "does-not-exist"),
                "--data-dir", d, "--out", out,
                "--fake-model", json.dumps([{"command": "izba ls"}, {"done": True}]),
                "--step-cap", "25", "--action-timeout-s", "5",
                "--max-turns", "5", "--max-usd", "5",
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))


class FakeModelTests(unittest.TestCase):
    def test_pops_scripted_replies_in_order(self):
        m = FakeModel([{"command": "izba ls"}, {"done": True}])
        self.assertEqual(m.next_command({}, {}, [])["command"], "izba ls")
        self.assertTrue(m.next_command({}, {}, []).get("done"))

    def test_exhausted_script_signals_done(self):
        m = FakeModel([])
        self.assertTrue(m.next_command({}, {}, []).get("done"))

    def test_fake_model_cost_is_zero(self):
        m = FakeModel([{"command": "izba ls"}])
        m.next_command({}, {}, [])
        self.assertEqual(m.last_cost_usd, 0.0)


if __name__ == "__main__":
    unittest.main()
