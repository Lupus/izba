"""The committed smoke corpus must stay schema-valid and novice-shaped:
goal-achievement oracles only, no gui journeys (the weekly cron runs the CLI
smoke), every journey shallow (<= 4 steps)."""
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "journeys", "smoke-core-cli.json")


class SmokeCorpusTests(unittest.TestCase):
    def _load(self):
        with open(CORPUS) as f:
            return json.load(f)

    def test_validates_against_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        with open(os.path.join(HERE, "schema", "journeys.schema.json")) as f:
            schema = json.load(f)
        jsonschema.validate(self._load(), schema)

    def test_novice_shape(self):
        doc = self._load()
        self.assertGreaterEqual(len(doc["journeys"]), 9)
        for j in doc["journeys"]:
            self.assertNotEqual(j.get("modality"), "gui", j["journey_id"])
            self.assertLessEqual(len(j["steps"]), 4, j["journey_id"])

    def test_nonzero_expects_declare_expect_exit(self):
        """A step whose `expect` prose asserts a non-zero exit as the CORRECT
        outcome must also declare `expect_exit` — prose alone does not
        reliably trip the functional oracle's expected-failure regex (see
        oracles._EXPECT_FAILURE_RE), so an under-specified step silently
        stops being graded as a refusal and flips false-negative forever on
        the weekly cron (no skeptic there to catch it)."""
        doc = self._load()
        for j in doc["journeys"]:
            for step in j["steps"]:
                if re.search(r"non-?zero", step["expect"], re.I):
                    self.assertIn(
                        "expect_exit", step,
                        f"{j['journey_id']!r} step {step['intent']!r} asserts "
                        "a non-zero exit in prose but has no expect_exit",
                    )
