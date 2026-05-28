from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MANIFEST_VERSION = "0.1"
ALLOWED_AUTHORITIES = {"live_aws", "fixture", "manual", "synthetic"}
ALLOWED_CONFIDENCE = {"high", "medium", "low"}
ALLOWED_DEFECT_CLASSES = {
    "artifact_insufficient",
    "dishonest_degradation",
    "false_admin_claim",
    "semantic_mismatch",
}
REQUIRED_ARTIFACT_KEYS = {
    "scenario_json",
    "findings_json",
    "run_log",
    "scenario_validate_txt",
}
OPTIONAL_ARTIFACT_KEYS = {
    "binding_metadata_json",
    "expected_findings_json",
}


def load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def dump_json(path: str | Path, payload: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def resolve_path(repo_root: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path
    return repo_root / path
