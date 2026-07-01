import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.driver import parse_snapshot, render_marks, action_to_argv, Mark


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
