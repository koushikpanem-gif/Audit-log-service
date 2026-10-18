import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "docs" / "schemas"
FIXTURES = Path(__file__).parent / "fixtures" / "bundle_vectors"


def _validator(name: str) -> Draft202012Validator:
    resources = []
    for path in SCHEMAS.glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        resources.append((path.name, Resource.from_contents(schema)))
        resources.append((schema["$id"], Resource.from_contents(schema)))
    registry: Registry[Any] = Registry().with_resources(resources)
    schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=registry)


def _load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return data


@pytest.mark.parametrize("name", ["gapped.json", "partial.json", "empty.json"])
def test_golden_fixtures_satisfy_bundle_schema(name: str) -> None:
    _validator("bundle.schema.json").validate(_load(name))


def test_minimal_example_matches_empty_fixture() -> None:
    example = SCHEMAS / "examples" / "minimal-valid-bundle.json"
    _validator("bundle.schema.json").validate(
        json.loads(example.read_text(encoding="utf-8"))
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.update(surprise=1),
        lambda b: b.pop("selection"),
        lambda b: b.update(format="audit-export-bundle/v2"),
        lambda b: b.update(exportedAt="2030-01-01T00:00:01Z"),
        lambda b: b.update(recordCount=9007199254740992),
        lambda b: b["selection"].pop("seqTo"),
        lambda b: b["completeness"].update(assurance="PROVEN"),
        lambda b: b["signer"].update(keyId="ABC"),
        lambda b: b["records"][0].pop("disclosedLeaves"),
        lambda b: b.update(signature="short"),
    ],
)
def test_schema_rejects_malformed_bundle(mutate: Any) -> None:
    bundle = copy.deepcopy(_load("gapped.json"))
    mutate(bundle)
    assert list(_validator("bundle.schema.json").iter_errors(bundle))


def test_diagnostics_schema_is_valid() -> None:
    Draft202012Validator.check_schema(
        json.loads((SCHEMAS / "diagnostics.schema.json").read_text(encoding="utf-8"))
    )
