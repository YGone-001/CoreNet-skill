"""Strict contract validation for the EPC Dedicated Bearer timeline artifact."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    ROOT
    / "skills"
    / "domain"
    / "epc-procedures"
    / "schemas"
    / "epc-dedicated-bearer-timeline-analysis.schema.json"
)
ANALYSIS_NAME = "epc-dedicated-bearer-timeline"
SUPPORTED_MAJOR_VERSION = "1"

_SCHEMA_CACHE: dict[str, Any] | None = None


class ContractValidationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _schema() -> dict[str, Any]:
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is None:
        try:
            _SCHEMA_CACHE = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ContractValidationError(
                "SCHEMA_UNAVAILABLE", f"timeline schema is unreadable: {exc}"
            ) from exc
    return _SCHEMA_CACHE


def _validator():
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:  # pragma: no cover - dependency boundary
        raise ContractValidationError(
            "SCHEMA_VALIDATOR_UNAVAILABLE",
            "the jsonschema package is required to validate the timeline artifact",
        ) from exc
    return Draft202012Validator(_schema())


def _first_error(instance: Any, validator) -> str:
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if not errors:
        raise AssertionError("iter_errors() produced no error")
    error = errors[0]
    path = "/".join(str(part) for part in error.absolute_path) or "<document>"
    return f"{path}: {error.message}"


def validate_artifact(document: Any) -> None:
    if not isinstance(document, dict):
        raise ContractValidationError("SUPPLIED_ARTIFACT_INVALID", "timeline artifact is not an object")
    version = document.get("analysis_version")
    if not isinstance(version, str) or not version:
        raise ContractValidationError("MISSING_ANALYSIS_VERSION", "timeline artifact has no version")
    if version.split(".", 1)[0] != SUPPORTED_MAJOR_VERSION:
        raise ContractValidationError(
            "UNSUPPORTED_ANALYSIS_VERSION", f"timeline version {version} is not supported"
        )
    validator = _validator()
    if not validator.is_valid(document):
        raise ContractValidationError(
            "SCHEMA_VIOLATION",
            f"timeline artifact violates the accepted Domain schema: {_first_error(document, validator)}",
        )

    entries = document.get("timeline_entries")
    declared = document.get("timeline_entry_count")
    omitted = document.get("timeline_entries_omitted")
    if not isinstance(entries, list) or isinstance(declared, bool) or not isinstance(declared, int):
        raise ContractValidationError("COUNT_INTEGRITY", "timeline entries/count are invalid")
    if not isinstance(omitted, bool) and isinstance(omitted, int):
        pass
    else:
        raise ContractValidationError("COUNT_INTEGRITY", "timeline omitted count is invalid")
    if declared != len(entries) + omitted:
        raise ContractValidationError(
            "COUNT_INTEGRITY",
            f"timeline_entry_count ({declared}) does not equal published ({len(entries)}) + omitted ({omitted})",
        )
    if declared < 0 or omitted < 0:
        raise ContractValidationError("COUNT_INTEGRITY", "timeline counts must be non-negative")

    counts = document.get("association_status_counts")
    if not isinstance(counts, dict):
        raise ContractValidationError("COUNT_INTEGRITY", "association status counts are missing")
    total = 0
    for value in counts.values():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ContractValidationError("COUNT_INTEGRITY", "association status counts must be integers")
        total += value
    if total != declared:
        raise ContractValidationError(
            "COUNT_INTEGRITY",
            f"association status counts total {total} but timeline_entry_count is {declared}",
        )

    for entry in entries:
        if not isinstance(entry, dict):
            raise ContractValidationError("SCHEMA_VIOLATION", "timeline entry is not an object")
        for key in ("observed_nas_esm_references", "observed_s1ap_erab_references"):
            references = entry.get(key)
            if not isinstance(references, list):
                raise ContractValidationError("SCHEMA_VIOLATION", f"{key} is not a list")
            for reference in references:
                if not isinstance(reference, dict):
                    raise ContractValidationError("SCHEMA_VIOLATION", f"{key} contains a non-object")
                frame = reference.get("frame_number")
                if isinstance(frame, bool) or not isinstance(frame, int) or frame < 1:
                    raise ContractValidationError(
                        "SCHEMA_VIOLATION", f"{key} contains an invalid frame anchor"
                    )