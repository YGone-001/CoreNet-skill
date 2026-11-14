"""Strict contract validation for the accepted Dedicated Bearer Control artifact.

Unified EPC and the EPC Evidence Review Pack both consume this optional Domain
artifact. Validation is shared so that a malformed, schema-incomplete or
count-inconsistent document can never be published as successful analysis by
either consumer.
"""

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
    / "epc-dedicated-bearer-control-analysis.schema.json"
)

ARTIFACT_FILENAME = "epc-dedicated-bearer-control-analysis.json"
ANALYSIS_NAME = "epc-dedicated-bearer-control"
SUPPORTED_MAJOR_VERSION = "1"

COLLECTIONS = (
    ("control_transactions", "control_transaction_count", "control_transactions_omitted"),
    ("bearer_item_observations", "bearer_item_observation_count", "bearer_item_observations_omitted"),
    ("item_associations", "item_association_count", "item_associations_omitted"),
)

OUTCOME_COLLECTIONS = (
    ("transaction_classification_counts", "control_transaction_count"),
    ("message_outcome_counts", "control_transaction_count"),
    ("item_outcome_counts", "bearer_item_observation_count"),
    ("item_association_status_counts", "item_association_count"),
)

_SCHEMA_CACHE: dict[str, Any] | None = None


class ContractValidationError(Exception):
    """A deterministic, operator-readable artifact contract failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _strict_count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None


def _schema() -> dict[str, Any]:
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is None:
        try:
            _SCHEMA_CACHE = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ContractValidationError(
                "SCHEMA_UNAVAILABLE",
                f"accepted Dedicated Bearer Domain schema is unreadable: {exc}",
            ) from exc
    return _SCHEMA_CACHE


def _validator():
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:  # pragma: no cover - dependency boundary
        raise ContractValidationError(
            "SCHEMA_VALIDATOR_UNAVAILABLE",
            "the jsonschema package is required to validate the Dedicated Bearer artifact",
        ) from exc
    return Draft202012Validator(_schema())


def _schema_error(instance: Any, validator) -> str:
    for error in sorted(
        validator.iter_errors(instance),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    ):
        path = "/".join(str(part) for part in error.absolute_path) or "<document>"
        return f"{path}: {error.message}"
    raise AssertionError("iter_errors() produced no error")


def validate_artifact(document: Any) -> None:
    """Raise ContractValidationError unless the artifact satisfies the full contract."""
    if not isinstance(document, dict):
        raise ContractValidationError(
            "SUPPLIED_ARTIFACT_INVALID", "Dedicated Bearer artifact is not an object"
        )

    version = document.get("analysis_version")
    if not isinstance(version, str) or not version:
        raise ContractValidationError(
            "MISSING_ANALYSIS_VERSION", "Dedicated Bearer artifact has no analysis version"
        )
    if version.split(".", 1)[0] != SUPPORTED_MAJOR_VERSION:
        raise ContractValidationError(
            "UNSUPPORTED_ANALYSIS_VERSION",
            f"Dedicated Bearer analysis version {version} is not supported",
        )

    validator = _validator()
    if not validator.is_valid(document):
        raise ContractValidationError(
            "SCHEMA_VIOLATION",
            f"Dedicated Bearer artifact violates the accepted Domain schema: {_schema_error(document, validator)}",
        )

    for collection_key, declared_key, omitted_key in COLLECTIONS:
        published = document.get(collection_key)
        declared = _strict_count(document.get(declared_key))
        omitted = _strict_count(document.get(omitted_key))
        if not isinstance(published, list):
            raise ContractValidationError(
                "COUNT_INTEGRITY",
                f"{collection_key} is not a published collection",
            )
        if declared is None or omitted is None:
            raise ContractValidationError(
                "COUNT_INTEGRITY",
                f"{declared_key} and {omitted_key} must be non-negative integers",
            )
        if declared != len(published) + omitted:
            raise ContractValidationError(
                "COUNT_INTEGRITY",
                f"{declared_key} ({declared}) does not equal the published collection "
                f"({len(published)}) plus {omitted_key} ({omitted})",
            )

    outcome_summary = document.get("outcome_summary")
    if isinstance(outcome_summary, dict):
        for outcome_key, declared_key in OUTCOME_COLLECTIONS:
            counts = outcome_summary.get(outcome_key)
            if not isinstance(counts, dict):
                continue
            total = 0
            for value in counts.values():
                strict = _strict_count(value)
                if strict is None:
                    raise ContractValidationError(
                        "COUNT_INTEGRITY",
                        f"outcome_summary.{outcome_key} contains a non-integer count",
                    )
                total += strict
            declared = _strict_count(document.get(declared_key))
            if declared is None or total != declared:
                raise ContractValidationError(
                    "COUNT_INTEGRITY",
                    f"outcome_summary.{outcome_key} totals {total} but {declared_key} is {declared}",
                )

    limits = document.get("limits")
    if isinstance(limits, dict):
        for collection_key, _declared_key, _omitted_key in COLLECTIONS:
            limit_key = {
                "control_transactions": "control_transactions",
                "bearer_item_observations": "bearer_items",
                "item_associations": "item_associations",
            }[collection_key]
            limit = _strict_count(limits.get(limit_key))
            if limit is None or limit < 1:
                raise ContractValidationError(
                    "BOUNDEDNESS_INVALID",
                    f"limits.{limit_key} must be a positive integer",
                )
            if len(document.get(collection_key) or []) > limit:
                raise ContractValidationError(
                    "BOUNDEDNESS_INVALID",
                    f"{collection_key} exceeds its declared limit of {limit}",
                )