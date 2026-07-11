import json
import os

import pytest

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


def test_journey_result_allows_workspace():
    # Task 10: the GUI runner's per-journey workspace path, recorded for the
    # Phase-3 skeptic — optional (journey_result is additionalProperties:
    # false, so the field must be declared, but CLI results never set it).
    schema = _load("trajectory.schema.json")
    jr = schema["definitions"]["journey_result"]
    assert jr["properties"]["workspace"]["type"] == "string"
    assert "workspace" not in jr["required"]


def test_gui_skeleton_journeys_are_gui_and_anchored():
    with open(os.path.join(HERE, "fixtures", "journeys.gui-skeleton.json")) as f:
        doc = json.load(f)
    assert len(doc["journeys"]) == 5
    for j in doc["journeys"]:
        assert j["modality"] == "gui"
        assert j["source"]["ref"]
        assert j["steps"] and all(s["intent"] and s["expect"] for s in j["steps"])


def test_step_allows_core_and_expect_exit():
    # The decisive-step + declarative-exit fields (Parts A/B) are optional
    # additions to the step object.
    schema = _load("journeys.schema.json")
    step = schema["definitions"]["step"]["properties"]
    assert step["core"]["type"] == "boolean"
    # expect_exit is an int OR the literal string "nonzero".
    any_of = step["expect_exit"]["anyOf"]
    assert {"type": "integer"} in any_of
    assert any(o.get("enum") == ["nonzero"] for o in any_of)
    # Both stay optional (absent required list unchanged: intent+expect only).
    assert schema["definitions"]["step"]["required"] == ["intent", "expect"]


def test_journey_allows_seed_files():
    # Precondition seeding (Part E): relpath -> content string map.
    schema = _load("journeys.schema.json")
    seed = schema["definitions"]["journey"]["properties"]["seed_files"]
    assert seed["type"] == "object"
    assert seed["additionalProperties"]["type"] == "string"
    assert "seed_files" not in schema["definitions"]["journey"]["required"]


def test_step_allows_seed_files():
    # Step-level seed_files (mid-journey drift, Task 9): same shape as the
    # journey-level field, optional.
    schema = _load("journeys.schema.json")
    seed = schema["definitions"]["step"]["properties"]["seed_files"]
    assert seed["type"] == "object"
    assert seed["additionalProperties"]["type"] == "string"
    assert schema["definitions"]["step"]["required"] == ["intent", "expect"]


def _minimal_journey_doc(step_extra):
    step = {"intent": "do a thing", "expect": "it works"}
    step.update(step_extra)
    return {
        "feature": "test-feature",
        "journeys": [{
            "journey_id": "j1",
            "rationale": "r",
            "source": {"kind": "spec", "ref": "x"},
            "steps": [step],
        }],
    }


def test_step_seed_files_accepted():
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load("journeys.schema.json")
    doc = _minimal_journey_doc({"seed_files": {"izba.yml": "spec:\n  image: alpine\n"}})
    jsonschema.validate(doc, schema)  # must not raise


def test_step_seed_files_rejects_non_object():
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load("journeys.schema.json")
    doc = _minimal_journey_doc({"seed_files": "not-an-object"})
    with pytest.raises(jsonschema.exceptions.ValidationError):
        jsonschema.validate(doc, schema)


def test_candidate_allows_decisive():
    # The collector reads `decisive` to decide whether a functional candidate may
    # flip a journey negative (Part A).
    schema = _load("trajectory.schema.json")
    assert schema["definitions"]["candidate"]["properties"]["decisive"]["type"] == "boolean"


def test_deep_seeded_fixture_shape():
    with open(os.path.join(HERE, "fixtures", "journeys.deep-seeded-cli.json")) as f:
        doc = json.load(f)
    assert len(doc["journeys"]) == 2
    for j in doc["journeys"]:
        assert j["tier"] == "deep"
        # Every deep-seeded journey ships a valid-manifest precondition...
        assert "izba.yml" in j["seed_files"]
        assert "apiVersion: izba.dev/v1alpha1" in j["seed_files"]["izba.yml"]
        # ...and marks exactly one decisive (core) step.
        assert sum(1 for s in j["steps"] if s.get("core")) == 1
    # The TOCTOU journey declares an expected-failure via the new declarative field.
    stale = next(j for j in doc["journeys"] if j["journey_id"] == "review-gate-refuses-stale-token")
    core_step = next(s for s in stale["steps"] if s.get("core"))
    assert core_step["expect_exit"] == "nonzero"


def test_all_cli_fixtures_validate_against_schema():
    # Guarded: jsonschema is the same validator dispatch-swarm.sh uses to reject a
    # malformed journeys.json before a swarm; skip cleanly if it isn't installed.
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load("journeys.schema.json")
    for name in ("journeys.example.json", "journeys.smoke-core-cli.json",
                 "journeys.deep-seeded-cli.json"):
        with open(os.path.join(HERE, "fixtures", name)) as f:
            jsonschema.validate(json.load(f), schema)
