"""Strict contract validation for the Dedicated Bearer attribution artifact."""

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
    / "epc-dedicated-bearer-attribution-analysis.schema.json"
)
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
            raise ContractValidationError("SCHEMA_UNAVAILABLE", f"attribution schema is unreadable: {exc}") from exc
    return _SCHEMA_CACHE


def _validator():
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:  # pragma: no cover - dependency boundary
        raise ContractValidationError(
            "SCHEMA_VALIDATOR_UNAVAILABLE",
            "the jsonschema package is required to validate the attribution artifact",
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
        raise ContractValidationError("SUPPLIED_ARTIFACT_INVALID", "attribution artifact is not an object")
    version = document.get("analysis_version")
    if not isinstance(version, str) or not version:
        raise ContractValidationError("MISSING_ANALYSIS_VERSION", "attribution artifact has no version")
    if version.split(".", 1)[0] != SUPPORTED_MAJOR_VERSION:
        raise ContractValidationError(
            "UNSUPPORTED_ANALYSIS_VERSION", f"attribution version {version} is not supported"
        )
    validator = _validator()
    if not validator.is_valid(document):
        raise ContractValidationError(
            "SCHEMA_VIOLATION",
            f"attribution artifact violates the accepted Domain schema: {_first_error(document, validator)}",
        )
    entries = document.get("attribution_entries")
    declared = document.get("attribution_entry_count")
    omitted = document.get("attribution_entries_omitted")
    if not isinstance(entries, list) or isinstance(declared, bool) or not isinstance(declared, int):
        raise ContractValidationError("COUNT_INTEGRITY", "attribution entries/count are invalid")
    if isinstance(omitted, bool) or not isinstance(omitted, int) or omitted < 0:
        raise ContractValidationError("COUNT_INTEGRITY", "attribution omitted count is invalid")
    if declared != len(entries) + omitted:
        raise ContractValidationError(
            "COUNT_INTEGRITY",
            f"attribution_entry_count ({declared}) does not equal published ({len(entries)}) + omitted ({omitted})",
        )
    for key in (
        "control_session_status_counts",
        "session_access_status_counts",
        "nas_access_status_counts",
        "s1ap_access_status_counts",
        "overall_status_counts",
    ):
        counts = document.get(key)
        if not isinstance(counts, dict):
            raise ContractValidationError("COUNT_INTEGRITY", f"{key} is missing")
        total = 0
        for value in counts.values():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractValidationError("COUNT_INTEGRITY", f"{key} contains a non-integer count")
            total += value
        if total != declared:
            raise ContractValidationError(
                "COUNT_INTEGRITY", f"{key} totals {total} but attribution_entry_count is {declared}"
            )
    for entry in entries:
        if not isinstance(entry, dict):
            raise ContractValidationError("SCHEMA_VIOLATION", "attribution entry is not an object")
        control = entry.get("control_session")
        nas = entry.get("nas_access")
        s1ap = entry.get("s1ap_access")
        overall = entry.get("overall_status")
        if not isinstance(control, dict) or not isinstance(nas, dict) or not isinstance(s1ap, dict):
            raise ContractValidationError("SCHEMA_VIOLATION", "attribution sub-status is missing")
        if overall == "ESTABLISHED_BY_EVIDENCE":
            if control.get("status") != "ESTABLISHED_BY_EVIDENCE":
                raise ContractValidationError(
                    "ATTRIBUTION_OVERSTATED", "overall attribution cannot be established without an established control-to-session link"
                )
            if nas.get("status") != "ESTABLISHED_BY_EVIDENCE" or s1ap.get("status") != "ESTABLISHED_BY_EVIDENCE":
                raise ContractValidationError(
                    "ATTRIBUTION_OVERSTATED", "overall attribution cannot be established without established NAS and S1AP evidence"
                )
        if s1ap.get("status") == "ENDPOINT_CORRESPONDENCE_ONLY" and entry.get("overall_status") == "ESTABLISHED_BY_EVIDENCE":
            raise ContractValidationError(
                "ATTRIBUTION_OVERSTATED", "endpoint correspondence was promoted to established UE identity"
            )