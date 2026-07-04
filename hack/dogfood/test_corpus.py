"""The committed smoke corpus must stay schema-valid and novice-shaped:
goal-achievement oracles only, no gui journeys (the weekly cron runs the CLI
smoke), every journey shallow (<= 4 steps)."""
import json
import os
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
        self.assertGreaterEqual(len(doc["journeys"]), 7)
        for j in doc["journeys"]:
            self.assertNotEqual(j.get("modality"), "gui", j["journey_id"])
            self.assertLessEqual(len(j["steps"]), 4, j["journey_id"])
