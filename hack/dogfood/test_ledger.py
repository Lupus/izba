"""append-ledger.py: one JSON line per run into hack/dogfood/ledger.jsonl."""
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_script():
    repo_root = os.path.dirname(os.path.dirname(HERE))
    path = os.path.join(repo_root, ".claude", "skills", "llm-dogfooding",
                        "scripts", "append-ledger.py")
    if not os.path.isfile(path):
        return None
    spec = importlib.util.spec_from_file_location("append_ledger", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class LedgerTests(unittest.TestCase):
    def test_appends_one_json_line(self):
        mod = _load_script()
        if mod is None:
            self.skipTest("append-ledger.py not present")
        with tempfile.TemporaryDirectory() as d:
            collected = os.path.join(d, "collected.json")
            json.dump({"totals": {"journeys": 8, "candidates": 5,
                                  "flipping_candidates": 2, "soft_candidates": 3,
                                  "positive_journeys": 6, "infra_journeys": 0,
                                  "unreached_journeys": 1,
                                  "by_kind": {"functional": 5}}},
                      open(collected, "w"))
            verdict = os.path.join(d, "verdict.json")
            json.dump({"feature": "f", "findings": [],
                       "counts": {"kept": 1, "refuted": 1}}, open(verdict, "w"))
            ledger = os.path.join(d, "ledger.jsonl")
            rc = mod.main(["--collected", collected, "--verdict", verdict,
                           "--feature", "f", "--tier", "smoke",
                           "--ledger", ledger])
            self.assertEqual(rc, 0)
            rc = mod.main(["--collected", collected, "--feature", "f",
                           "--tier", "core", "--ledger", ledger])
            self.assertEqual(rc, 0)
            lines = [json.loads(x) for x in open(ledger).read().splitlines()]
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[0]["feature"], "f")
            self.assertEqual(lines[0]["tier"], "smoke")
            self.assertEqual(lines[0]["totals"]["journeys"], 8)
            self.assertEqual(lines[0]["skeptic"]["kept"], 1)
            self.assertNotIn("skeptic", lines[1])  # verdict optional
            self.assertIn("date", lines[0])
