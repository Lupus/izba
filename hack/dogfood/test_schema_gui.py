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
