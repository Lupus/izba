import json
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.driver import (FakeDriver, Mark, _validate_args, action_to_argv,
                        parse_snapshot, render_marks)


def test_parse_snapshot_text_form():
    raw = '- heading "Sandboxes" [ref=e1] [level=1]\n- button "Create sandbox" [ref=e2]\n- textbox "Name" [ref=e3]'
    marks = parse_snapshot(raw)
    assert marks == [
        Mark(ref="@e1", role="heading", name="Sandboxes"),
        Mark(ref="@e2", role="button", name="Create sandbox"),
        Mark(ref="@e3", role="textbox", name="Name"),
    ]


def test_parse_snapshot_json_form():
    raw = '{"elements":[{"ref":"e2","role":"button","name":"Create sandbox"}]}'
    assert parse_snapshot(raw) == [Mark(ref="@e2", role="button", name="Create sandbox")]


def test_parse_snapshot_garbage_is_empty():
    assert parse_snapshot("not a snapshot") == []


def test_render_marks_caps_chars():
    marks = [Mark(ref=f"@e{i}", role="button", name="x" * 50) for i in range(100)]
    out = render_marks(marks, cap_chars=200)
    assert len(out) <= 200
    assert out.startswith('[@e0] button "')


def test_action_to_argv_click_and_fill():
    assert action_to_argv({"click": "@e2"}) == ["click", "@e2"]
    assert action_to_argv({"fill": "@e3", "text": "web"}) == ["fill", "@e3", "web"]
    assert action_to_argv({"press": "Enter"}) == ["press", "Enter"]
    assert action_to_argv({"select": "@e9", "option": "alpine"}) == ["select", "@e9", "alpine"]


def test_action_to_argv_read_and_done_are_none():
    assert action_to_argv({"read": True}) is None
    assert action_to_argv({"done": True}) is None
    assert action_to_argv({"bogus": 1}) is None


# The exact `agent-browser snapshot -i --json` payload captured from
# agent-browser v0.31.1 in CI (against example.com). The marks come from the
# `data.refs` dict; `data.snapshot` is the aria-text fallback.
_REAL_AB_JSON = (
    '{"success":true,"data":{"lifecycle":{"reused":true},'
    '"origin":"https://example.com/",'
    '"refs":{"e1":{"name":"Example Domain","role":"heading"},'
    '"e2":{"name":"Learn more","role":"link"}},'
    '"snapshot":"- heading \\"Example Domain\\" [level=1, ref=e1]\\n'
    '- link \\"Learn more\\" [ref=e2]"}}'
)


def test_parse_snapshot_real_agent_browser_json():
    marks = parse_snapshot(_REAL_AB_JSON)
    assert marks == [
        Mark(ref="@e1", role="heading", name="Example Domain"),
        Mark(ref="@e2", role="link", name="Learn more"),
    ]


def test_parse_snapshot_real_aria_text_with_leading_attrs():
    # ref is NOT first in the bracket (`[level=1, ref=e1]`) — must still parse.
    raw = ('- heading "Example Domain" [level=1, ref=e1]\n'
           '- link "Learn more" [ref=e2]')
    assert parse_snapshot(raw) == [
        Mark(ref="@e1", role="heading", name="Example Domain"),
        Mark(ref="@e2", role="link", name="Learn more"),
    ]


def test_parse_snapshot_json_snapshot_string_fallback():
    # A JSON object whose only usable field is the aria-text `snapshot` string
    # (no `refs`/`elements`) still yields marks via the text fallback.
    doc = '{"success":true,"data":{"snapshot":"- button \\"Go\\" [ref=e5]"}}'
    assert parse_snapshot(doc) == [Mark(ref="@e5", role="button", name="Go")]


# --- _validate_args ---

def test_validate_args_rejects_bogus_subcommand():
    assert _validate_args(["rm", "-rf", "/"]) is not None
    assert _validate_args(["bogus_cmd"]) is not None
    assert _validate_args([]) is not None


def test_validate_args_accepts_known_subcommands():
    for subcmd in ("open", "snapshot", "click", "fill", "press",
                   "select", "eval", "screenshot", "close", "wait", "get"):
        # Basic call with no extra args must pass the subcommand check
        assert _validate_args([subcmd]) is None


def test_validate_args_ref_subcmds_reject_bad_ref():
    # click / fill / select with an invalid ref must be rejected
    assert _validate_args(["click", "not-a-ref"]) is not None
    assert _validate_args(["fill", "evil;cmd"]) is not None
    assert _validate_args(["select", "../../etc"]) is not None


def test_validate_args_ref_subcmds_accept_good_ref():
    # Both '@eN' and bare 'eN' forms are valid
    assert _validate_args(["click", "@e1"]) is None
    assert _validate_args(["click", "e42"]) is None
    assert _validate_args(["fill", "@e3", "some text"]) is None
    assert _validate_args(["select", "@e9", "alpine"]) is None


# --- _eval_json ---

def _stub_driver(stdout):
    """AgentBrowserDriver whose _run returns canned stdout (no subprocess)."""
    from gui.driver import ActResult, AgentBrowserDriver
    d = AgentBrowserDriver("agent-browser", http_port=0, ws_port=0)
    d._run = lambda args: ActResult(exit_code=0, stdout=stdout, stderr="",
                                    latency_ms=0)
    return d


def test_eval_json_unwraps_real_agent_browser_envelope_string_result():
    # Real `agent-browser eval --json` output: the value sits under
    # data.result as a JSON string (probed on 0.25.4; same envelope family as
    # snapshot's data.refs on 0.31.1). The old code returned the whole
    # envelope dict, so read_invoke_log() was [] on every real run.
    out = ('{"success":true,"data":{"origin":"http://127.0.0.1:1",'
           '"result":"[{\\"cmd\\":\\"list_sandboxes\\",\\"ok\\":true,'
           '\\"error\\":\\"\\"}]"},"error":null}')
    d = _stub_driver(out)
    assert d.read_invoke_log() == [
        {"cmd": "list_sandboxes", "ok": True, "error": ""}]


def test_eval_json_unwraps_real_agent_browser_envelope_raw_result():
    out = ('{"success":true,"data":{"origin":"http://127.0.0.1:1",'
           '"result":[{"cmd":"a","ok":true}]},"error":null}')
    d = _stub_driver(out)
    assert d._eval_json("whatever") == [{"cmd": "a", "ok": True}]


def test_eval_json_still_handles_legacy_top_level_result():
    d = _stub_driver('{"result": "[1, 2]"}')
    assert d._eval_json("whatever") == [1, 2]


def test_eval_json_bare_value_and_garbage():
    assert _stub_driver('["x"]')._eval_json("e") == ["x"]
    assert _stub_driver("not json")._eval_json("e") is None


def test_read_console_errors_through_real_envelope():
    out = ('{"success":true,"data":{"origin":"o",'
           '"result":"[\\"boom\\"]"},"error":null}')
    assert _stub_driver(out).read_console_errors() == ["boom"]


# --- read_page_text (Fix 2) ---

def test_read_page_text_through_real_envelope():
    # JSON.stringify(document.body.innerText||'') round-trips like the other
    # eval calls: data.result carries a JSON-encoded string of the JS value.
    out = ('{"success":true,"data":{"origin":"o",'
           '"result":"\\"Promoted 1 change(s).\\""},"error":null}')
    assert _stub_driver(out).read_page_text() == "Promoted 1 change(s)."


def test_read_page_text_caps_and_marks_truncation():
    long_text = "x" * 5000
    out_json = json.dumps(json.dumps(long_text))
    out = ('{"success":true,"data":{"origin":"o","result":' + out_json + '},"error":null}')
    text = _stub_driver(out).read_page_text(cap_chars=100)
    assert len(text) == 100 + len("...[truncated]")
    assert text.endswith("...[truncated]")
    assert text.startswith("x" * 100)


def test_read_page_text_garbage_is_empty_string():
    assert _stub_driver("not json").read_page_text() == ""


def test_fake_driver_read_page_text_pops_scripted_values_and_caps():
    d = FakeDriver(page_texts=["short text", "y" * 10])
    assert d.read_page_text() == "short text"
    assert d.read_page_text(cap_chars=5) == "yyyyy...[truncated]"
    assert d.read_page_text() == ""  # exhausted -> empty, never raises
