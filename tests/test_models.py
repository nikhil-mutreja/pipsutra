import json
from pathlib import Path

from pipsutra.models import Dependency, Inventory, ScanReport


def test_dependency_is_normalized_by_discovery_not_model() -> None:
    dependency = Dependency(
        name="Example_Package",
        normalized_name="example-package",
        source="requirements.txt:1",
    )
    assert dependency.normalized_name == "example-package"


def test_inventory_serializes_to_json() -> None:
    report = Inventory(
        project_path="/tmp/project",
        environment_path="/tmp/environment",
    )
    payload = report.model_dump_json()
    assert '"schema_version":"1.0"' in payload


def test_published_scan_schema_matches_models() -> None:
    schema_path = (
        Path(__file__).parents[1] / "docs" / "schemas" / "scan-report.schema.json"
    )
    saved_schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert saved_schema == ScanReport.model_json_schema()
