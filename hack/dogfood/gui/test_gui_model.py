import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gui.gui_model import parse_gui_reply, build_gui_user_message, GUI_SYSTEM_PROMPT


def test_parse_gui_reply_variants():
    assert parse_gui_reply('{"click": "@e2"}') == {"click": "@e2"}
    assert parse_gui_reply('{"fill": "@e3", "text": "web"}') == {"fill": "@e3", "text": "web"}
    assert parse_gui_reply('noise {"press":"Enter"} tail') == {"press": "Enter"}
    assert parse_gui_reply('{"done": true}') == {"done": True}


def test_parse_gui_reply_garbage_is_done():
    assert parse_gui_reply("totally not json") == {"done": True}
    assert parse_gui_reply('{"unknown": 1}') == {"done": True}


def test_user_message_includes_marks_and_intent():
    msg = build_gui_user_message(
        {"journey_id": "j1"},
        {"intent": "create a sandbox", "expect": "it appears in the list"},
        [{"action": "click @e2", "marks": '[@e9] button "Create"'}],
    )
    assert "create a sandbox" in msg
    assert "it appears in the list" in msg
    assert "@e9" in msg


def test_system_prompt_is_ui_actor_and_leaks_nothing_internal():
    assert "click" in GUI_SYSTEM_PROMPT.lower()
    # fair-test: the prompt must not name source/spec/testid scaffolding.
    for banned in ("data-testid", "src/components", "spec"):
        assert banned not in GUI_SYSTEM_PROMPT.lower()
