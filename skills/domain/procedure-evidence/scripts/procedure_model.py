#!/usr/bin/env python3
"""Shared, standalone helpers for the procedure evidence framework.

This package defines the common evidence model future Domain/Procedure
Skills consume: expected observation points, observed evidence, missing
evidence, stage representation, and evidence confidence. It never
decodes protocols, never handles subscriber or session identity, and
never issues success, failure, or root-cause verdicts. Missing evidence
stays missing evidence under the observation boundary; it is never
converted into failure.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

EXIT_MALFORMED_INPUT = 5
EXIT_NO_RECORDS = 6
EXIT_OUTPUT_FAILURE = 7

BASIS_OBSERVED = "OBSERVED"
BASIS_DERIVED = "DERIVED"
EVIDENCE_BASES = (BASIS_OBSERVED, BASIS_DERIVED)

CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"
CONFIDENCE_LEVELS = (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW)

# Verdict vocabulary that must never enter or leave this framework.
FORBIDDEN_VERDICT_PATTERN = re.compile(r"(?i)\b(?:success(?:ful)?|failed|root[ _-]?cause)\b")

STAGE_FIELDS = ("stage_id", "stage_name", "expected_protocols", "expected_message_types")
RECORD_FIELDS = (
    "procedure_name",
    "procedure_version",
    "observation_group",
    "stage",
    "expected_evidence",
    "observed_evidence",
    "missing_evidence",
    "evidence_basis",
    "confidence",
    "limitations",
)


class InputError(ValueError):
    """Raised when a procedure evidence record cannot be accepted."""


def _string_list(value: object, field: str, procedure: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise InputError(f"{procedure}: {field} must be a list of non-empty strings")
    return list(value)


def _verdict_scan(items: list[str], field: str, procedure: str) -> None:
    for item in items:
        match = FORBIDDEN_VERDICT_PATTERN.search(item)
        if match:
            raise InputError(
                f"{procedure}: {field} contains verdict wording '{match.group(0)}'; "
                "this framework reports evidence, never outcomes or causes"
            )


def validate_record(record: object, index: int) -> dict[str, object]:
    """Validate one procedure evidence record and return it unchanged.

    Records carry procedure-level context, one stage (an expected
    observation point), and its evidence lists. Protocol semantics are
    never interpreted here; protocol references in expected/observed
    lists are opaque strings supplied by the record author.
    """
    if not isinstance(record, dict):
        raise InputError(f"record {index} is not a JSON object")
    for field in ("procedure_name", "procedure_version", "observation_group"):
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            raise InputError(f"record {index} lacks a valid {field}")
    procedure = str(record["procedure_name"])

    stage = record.get("stage")
    if not isinstance(stage, dict):
        raise InputError(f"record {index} ({procedure}): stage must be an object")
    for field in ("stage_id", "stage_name"):
        if not isinstance(stage.get(field), str) or not str(stage[field]).strip():
            raise InputError(f"record {index} ({procedure}): stage.{field} must be a non-empty string")
    for field in ("expected_protocols", "expected_message_types"):
        if not isinstance(stage[field], list) or any(not isinstance(item, str) or not item.strip() for item in stage[field]):
            raise InputError(f"record {index} ({procedure}): stage.{field} must be a list of non-empty strings")

    for field in ("expected_evidence", "observed_evidence", "missing_evidence", "limitations"):
        _string_list(record.get(field), field, procedure)

    basis = record.get("evidence_basis")
    if basis not in EVIDENCE_BASES:
        raise InputError(f"record {index} ({procedure}): evidence_basis must be OBSERVED or DERIVED")
    confidence = record.get("confidence")
    if confidence not in CONFIDENCE_LEVELS:
        raise InputError(f"record {index} ({procedure}): confidence must be HIGH, MEDIUM, or LOW")

    for field in ("expected_evidence", "observed_evidence", "missing_evidence", "limitations"):
        _verdict_scan(list(record[field]), field, procedure)
    for field in ("stage_name", "procedure_name"):
        text = str(stage[field]) if field == "stage_name" else procedure
        match = FORBIDDEN_VERDICT_PATTERN.search(text)
        if match:
            raise InputError(
                f"record {index}: {field} contains verdict wording '{match.group(0)}'"
            )
    return record


def load_records(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name} at line {line_number}: {exc.msg}") from exc
            records.append(validate_record(record, len(records)))
    if not records:
        raise InputError("no procedure evidence records found")
    return records


def timeline_entries(records: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    """Project records into timeline entries; input order is preserved."""
    entries = []
    for record in records:
        stage = record["stage"]
        entries.append({
            "procedure_name": record["procedure_name"],
            "procedure_version": record["procedure_version"],
            "observation_group": record["observation_group"],
            "stage_id": stage["stage_id"],
            "stage_name": stage["stage_name"],
            "expected_protocols": list(stage["expected_protocols"]),
            "expected_message_types": list(stage["expected_message_types"]),
            "expected_evidence": list(record["expected_evidence"]),
            "observed_evidence": list(record["observed_evidence"]),
            "missing_evidence": list(record["missing_evidence"]),
            "evidence_basis": record["evidence_basis"],
            "confidence": record["confidence"],
            "limitations": list(record["limitations"]),
        })
    return entries


def render_text(entries: list[dict[str, object]]) -> str:
    lines: list[str] = []
    for entry in entries:
        lines.append(
            f"stage={entry['stage_id']} [{entry['observation_group']}] {entry['stage_name']} "
            f"({entry['procedure_name']} {entry['procedure_version']}) "
            f"basis={entry['evidence_basis']} confidence={entry['confidence']}"
        )
        if entry["expected_protocols"]:
            lines.append(f"  expected protocols: {', '.join(entry['expected_protocols'])}")
        if entry["expected_message_types"]:
            lines.append(f"  expected message types: {', '.join(entry['expected_message_types'])}")
        for item in entry["expected_evidence"]:
            lines.append(f"  expected evidence: {item}")
        for item in entry["observed_evidence"]:
            lines.append(f"  observed evidence: {item}")
        for item in entry["missing_evidence"]:
            lines.append(f"  missing evidence: {item}")
        for item in entry["limitations"]:
            lines.append(f"  limitation: {item}")
    return "\n".join(lines) + "\n"


def render_json(entries: list[dict[str, object]]) -> str:
    return json.dumps({"timeline": entries}, sort_keys=True, indent=2) + "\n"
