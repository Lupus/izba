import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


class SummarizeTests(unittest.TestCase):
    def test_summary_table(self):
        bundle = {"shard": 1, "feature": "f", "results": [
            {"journey_id": "good", "actions": [{"command": "x", "exit_code": 0}],
             "candidates": []},
            {"journey_id": "dead", "actions": [], "candidates": [
                {"kind": "infra", "detail": "d", "violated_expectation": "",
                 "source": "", "trajectory_ref": {"journey_id": "dead",
                                                  "action_index": -1}}]},
            {"journey_id": "shallow", "actions": [], "candidates": [
                {"kind": "unreached_decisive", "detail": "d",
                 "violated_expectation": "", "source": "",
                 "trajectory_ref": {"journey_id": "shallow",
                                    "action_index": -1}}]},
        ]}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "traj-1.json")
            with open(p, "w") as f:
                json.dump(bundle, f)
            out = subprocess.run(
                [sys.executable, os.path.join(HERE, "summarize_bundle.py"), p],
                capture_output=True, text=True, check=True).stdout
        self.assertIn("| journeys | positive | flipping | infra | unreached | soft |", out)
        self.assertIn("| 3 | 1 | 2 | 1 | 1 | 0 |", out)
        self.assertIn("dead", out)      # per-journey verdict lines
        self.assertIn("unreached", out)


if __name__ == "__main__":
    unittest.main()
