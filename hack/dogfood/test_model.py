"""Tests for the OpenRouter model layer: retries, error surfacing, cost.

The HTTP boundary is faked by monkeypatching urllib.request.urlopen — no
network, no API key. This was previously the only untested module."""
import io
import json
import os
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import model  # noqa: E402
from model import OpenRouterModel, _parse_reply  # noqa: E402


def _raw_response(body):
    raw = json.dumps(body).encode("utf-8")

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    return _Resp(raw)


def _ok_response(content, usage=None):
    body = {"choices": [{"message": {"content": content}}]}
    if usage is not None:
        body["usage"] = usage
    return _raw_response(body)


JOURNEY = {"journey_id": "j"}
STEP = {"intent": "i", "expect": "e"}


class ParseReplyTests(unittest.TestCase):
    def test_valid_command(self):
        self.assertEqual(_parse_reply('{"command": "izba ls"}'),
                         {"command": "izba ls"})

    def test_done(self):
        self.assertEqual(_parse_reply('{"done": true}'), {"done": True})

    def test_json_embedded_in_prose(self):
        out = _parse_reply('Sure!\n```json\n{"command": "izba ls"}\n```')
        self.assertEqual(out, {"command": "izba ls"})

    def test_malformed_is_error_not_done(self):
        out = _parse_reply("I think you should run izba ls")
        self.assertIn("error", out)
        self.assertNotIn("done", out)

    def test_wrong_shape_is_error_not_done(self):
        out = _parse_reply('{"commands": ["a", "b"]}')
        self.assertIn("error", out)


class NextCommandTests(unittest.TestCase):
    def _model(self, **kw):
        kw.setdefault("retry_backoff_s", 0.0)
        return OpenRouterModel("key", "some/model", **kw)

    def test_success_first_try(self):
        with mock.patch.object(model.urllib.request, "urlopen",
                               return_value=_ok_response('{"command": "izba ls"}')):
            out = self._model().next_command(JOURNEY, STEP, [])
        self.assertEqual(out, {"command": "izba ls"})

    def test_retry_then_success(self):
        calls = {"n": 0}

        def flaky(req, timeout):
            calls["n"] += 1
            if calls["n"] == 1:
                raise urllib.error.URLError("boom")
            return _ok_response('{"done": true}')

        with mock.patch.object(model.urllib.request, "urlopen", side_effect=flaky):
            out = self._model().next_command(JOURNEY, STEP, [])
        self.assertEqual(out, {"done": True})
        self.assertEqual(calls["n"], 2)

    def test_retry_exhaustion_is_error_not_done(self):
        err = urllib.error.URLError("connection refused")
        with mock.patch.object(model.urllib.request, "urlopen", side_effect=err):
            out = self._model(max_retries=1).next_command(JOURNEY, STEP, [])
        self.assertIn("error", out)
        self.assertNotIn("done", out)
        self.assertIn("connection refused", out["error"])

    def test_null_content_is_error(self):
        # choices[0].message.content = None survives the subscript chain and
        # flows through `content or ""` into _parse_reply("") -> error. This
        # covers the null-content path, NOT the missing-key except branch.
        with mock.patch.object(model.urllib.request, "urlopen",
                               return_value=_ok_response(None)):
            out = self._model().next_command(JOURNEY, STEP, [])
        self.assertIn("error", out)

    def test_missing_content_is_error(self):
        # choices is empty -> IndexError in the subscript chain -> the
        # except (KeyError, IndexError, TypeError) branch.
        with mock.patch.object(model.urllib.request, "urlopen",
                               return_value=_raw_response({"choices": []})):
            out = self._model().next_command(JOURNEY, STEP, [])
        self.assertIn("error", out)
        self.assertNotIn("done", out)
        self.assertIn("missing choices[0].message.content", out["error"])

    def test_cost_prefers_usage_cost(self):
        resp = _ok_response('{"done": true}', usage={"cost": 0.0123,
                                                     "total_tokens": 999999})
        with mock.patch.object(model.urllib.request, "urlopen", return_value=resp):
            m = self._model()
            m.next_command(JOURNEY, STEP, [])
        self.assertAlmostEqual(m.last_cost_usd, 0.0123)

    def test_cost_falls_back_to_tokens(self):
        resp = _ok_response('{"done": true}', usage={"total_tokens": 2_000_000})
        with mock.patch.object(model.urllib.request, "urlopen", return_value=resp):
            m = self._model()
            m.next_command(JOURNEY, STEP, [])
        self.assertAlmostEqual(m.last_cost_usd,
                               2.0 * model.APPROX_USD_PER_1M_TOKENS)


if __name__ == "__main__":
    unittest.main()
