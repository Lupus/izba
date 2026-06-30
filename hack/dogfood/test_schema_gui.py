import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    with open(os.path.join(HERE, "schema", name)) as f:
        return json.load(f)


def test_journey_allows_modality_enum():
    schema = _load("journeys.schema.json")
    modality = schema["definitions"]["journey"]["properties"]["modality"]
    assert modality["enum"] == ["cli", "gui"]


def test_journey_modality_is_optional():
    # modality is NOT in the journey's required list (absent ⇒ cli).
    schema = _load("journeys.schema.json")
    assert "modality" not in schema["definitions"]["journey"]["required"]


def test_candidate_kind_includes_gui_oracles():
    schema = _load("trajectory.schema.json")
    enum = schema["definitions"]["candidate"]["properties"]["kind"]["enum"]
    for k in ("functional", "latency", "implicit", "reconcile_seq",
              "console", "ui_daemon_diff", "silent_failure", "dom_expect"):
        assert k in enum, k


def test_action_allows_optional_gui_fields():
    schema = _load("trajectory.schema.json")
    props = schema["definitions"]["action"]["properties"]
    for k in ("snapshot", "console_errors", "screenshot_ref"):
        assert k in props, k
    # GUI fields are optional — required list is unchanged (CLI fields only).
    assert "snapshot" not in schema["definitions"]["action"]["required"]


def test_gui_skeleton_journeys_are_gui_and_anchored():
    with open(os.path.join(HERE, "fixtures", "journeys.gui-skeleton.json")) as f:
        doc = json.load(f)
    assert len(doc["journeys"]) == 5
    for j in doc["journeys"]:
        assert j["modality"] == "gui"
        assert j["source"]["ref"]
        assert j["steps"] and all(s["intent"] and s["expect"] for s in j["steps"])
