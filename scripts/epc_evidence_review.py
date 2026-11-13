"""Deterministic EPC Evidence Review Pack builder.

Consumes already-published EPC analysis artifacts, or a Review Pack produced from
an explicitly supplied local capture replay. The module never decodes packets,
never re-derives session identity, bearer lifecycle, release narrative or audit
semantics, and never rewrites a producer count. It publishes only safe, bounded,
reference-oriented evidence views and keeps every unresolved claim explicit.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EPC_SCRIPTS = ROOT / "skills" / "domain" / "epc-procedures" / "scripts"
UNIFIED_CLI = ROOT / "scripts" / "corenet-analyze.py"

REVIEW_SCHEMA_VERSION = "1.0"
REVIEW_NAME = "epc-evidence-review"
REVIEW_VERSION = "1.0"

ARTIFACT_SESSION_IDENTITY = "session_identity"
ARTIFACT_BEARER_LIFECYCLE = "bearer_lifecycle"
ARTIFACT_RELEASE_NARRATIVE = "release_narrative"
ARTIFACT_S1U = "s1u_observation"
ARTIFACT_AUDIT = "evidence_audit"
ARTIFACT_DEDICATED_BEARER = "dedicated_bearer_control"

ARTIFACT_SPECS = (
    (ARTIFACT_SESSION_IDENTITY, "epc-session-identity-analysis.json", "epc-session-identity", True),
    (ARTIFACT_BEARER_LIFECYCLE, "epc-bearer-lifecycle-analysis.json", "epc-bearer-lifecycle", True),
    (ARTIFACT_RELEASE_NARRATIVE, "epc-release-narrative-analysis.json", "epc-release-narrative", True),
    (ARTIFACT_S1U, "epc-s1u-observation.json", "epc-s1u-observation", False),
    (ARTIFACT_AUDIT, "epc-evidence-audit-analysis.json", "epc-evidence-audit", False),
    (
        ARTIFACT_DEDICATED_BEARER,
        "epc-dedicated-bearer-control-analysis.json",
        "epc-dedicated-bearer-control",
        False,
    ),
)

MAX_CONTEXTS = 16
MAX_RELEASES = 32
MAX_GENERATIONS = 32
MAX_STREAMS = 32
MAX_OBSERVATIONS = 32
MAX_BINDINGS = 32
MAX_CANDIDATES = 32
MAX_FINDINGS = 48
MAX_REFERENCES = 64
MAX_LIST_ITEMS = 16
MAX_DEDICATED_TRANSACTIONS = 32
MAX_DEDICATED_ITEMS = 64
MAX_DEDICATED_ASSOCIATIONS = 64
MAX_TEXT = 240

CLASSIFICATION_OBSERVED = "OBSERVED"
CLASSIFICATION_DERIVED = "DERIVED"
CLASSIFICATION_AUDIT = "AUDIT_FINDING"
CLASSIFICATION_UNRESOLVED = "UNRESOLVED_CLAIM"
CLASSIFICATION_UNSUPPORTED = "UNSUPPORTED_CONCLUSION"

REPLAY_COMPLETED = "COMPLETED"
REPLAY_PARTIAL = "PARTIAL"
REPLAY_FAILED = "FAILED"
REPLAY_NOT_EXECUTED = "NOT_EXECUTED"

COMPARE_IDENTICAL = "IDENTICAL"
COMPARE_DIFFERENT = "DIFFERENT"
COMPARE_MISSING = "MISSING_OUTPUT"
COMPARE_SCHEMA = "SCHEMA_VERSION_MISMATCH"
COMPARE_CAPTURE = "INPUT_CAPTURE_MISMATCH"
COMPARE_UNSUPPORTED = "UNSUPPORTED_COMPARISON"

COMPARISON_EXIT_CODES = {
    COMPARE_IDENTICAL: 0,
    COMPARE_DIFFERENT: 1,
    COMPARE_MISSING: 5,
    COMPARE_SCHEMA: 5,
    COMPARE_CAPTURE: 5,
    COMPARE_UNSUPPORTED: 5,
}


def comparison_exit_code(status: Any) -> int:
    return COMPARISON_EXIT_CODES.get(status, 5)

FORBIDDEN_TEXT_PATTERNS = (
    re.compile(r"\b\d{9,}\b"),
    re.compile(r"[\w.+-]+@[\w.-]+"),
    re.compile(r"\b(?:imsi|msisdn|imei|apn)\b", re.IGNORECASE),
)

SAFE_CAPTURE_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


class ReviewInputError(Exception):
    """A deterministic, operator-readable review input failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _text(value: Any, limit: int = MAX_TEXT) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    if not text:
        return None
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    if any(pattern.search(text) for pattern in FORBIDDEN_TEXT_PATTERNS):
        return None
    return text


def safe_capture(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    name = Path(value).name
    name = SAFE_CAPTURE_PATTERN.sub("_", name)
    return name[:120] or None


def _safe_reference(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    if not text:
        return None
    return text[:160]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReviewInputError("MISSING_SOURCE_ARTIFACT", f"missing source artifact: {path.name}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ReviewInputError("INVALID_SOURCE_JSON", f"unreadable source artifact {path.name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ReviewInputError("INVALID_SOURCE_JSON", f"source artifact {path.name} is not an object")
    return payload


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            if isinstance(payload, dict):
                events.append(payload)
    except FileNotFoundError as exc:
        raise ReviewInputError("MISSING_DETAILED_EVIDENCE", f"missing detailed evidence: {path.name}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ReviewInputError("INVALID_DETAILED_EVIDENCE", f"unreadable detailed evidence {path.name}: {exc}") from exc
    return events


def _validate_version(document: dict[str, Any], artifact: str) -> None:
    version = document.get("analysis_version")
    if not isinstance(version, str):
        raise ReviewInputError("UNSUPPORTED_SCHEMA_VERSION", f"{artifact} has no analysis version")
    major = version.split(".", 1)[0]
    if major != "1":
        raise ReviewInputError(
            "UNSUPPORTED_SCHEMA_VERSION",
            f"{artifact} analysis version {version} is not supported",
        )


def _recompute_audit(
    identity: dict[str, Any],
    lifecycle: dict[str, Any],
    narrative: dict[str, Any],
    s1u: dict[str, Any] | None,
    gtpv2_events: list[dict[str, Any]] | None,
    gtpu_events: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    if str(EPC_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(EPC_SCRIPTS))
    import epc_evidence_audit_model as audit_model

    try:
        return audit_model.analyze(
            identity,
            lifecycle,
            narrative,
            s1u=s1u,
            gtpv2_events=gtpv2_events,
            gtpu_events=gtpu_events,
            provenance={
                "session_identity": "epc-session-identity-analysis.json",
                "lifecycle": "epc-bearer-lifecycle-analysis.json",
                "release_narrative": "epc-release-narrative-analysis.json",
                "s1u_observation": "epc-s1u-observation.json" if s1u is not None else None,
                    "gtpv2_events": "gtpv2-events.jsonl" if gtpv2_events is not None else None,
                "gtpv2_event_count": len(gtpv2_events) if gtpv2_events is not None else None,
                "gtpu_events": "gtpu-events.jsonl" if gtpu_events is not None else None,
                "gtpu_event_count": len(gtpu_events) if gtpu_events is not None else None,
            },
        )
    except Exception as exc:  # pragma: no cover - defensive boundary
        raise ReviewInputError("AUDIT_FAILED", f"existing evidence audit could not run: {exc}") from exc


def load_artifacts(
    artifacts_dir: Path,
    *,
    gtpv2_events: Path | None = None,
    gtpu_events: Path | None = None,
) -> dict[str, Any]:
    if not artifacts_dir.is_dir():
        raise ReviewInputError("MISSING_ARTIFACTS_DIR", f"artifacts directory not found: {artifacts_dir.name}")

    documents: dict[str, dict[str, Any] | None] = {}
    sources: list[dict[str, Any]] = []
    for artifact, filename, analysis_name, required in ARTIFACT_SPECS:
        path = artifacts_dir / filename
        if not path.is_file():
            if required:
                raise ReviewInputError(
                    "MISSING_SOURCE_ARTIFACT", f"required source artifact is missing: {filename}"
                )
            documents[artifact] = None
            sources.append(
                {
                    "artifact_type": artifact,
                    "artifact_name": filename,
                    "analysis_name": analysis_name,
                    "analysis_version": None,
                    "sha256": None,
                    "supplied": False,
                    "completeness_status": None,
                }
            )
            continue
        document = read_json(path)
        if document.get("analysis_name") != analysis_name:
            raise ReviewInputError(
                "INVALID_SOURCE_ARTIFACT",
                f"{filename} is not a {analysis_name} artifact",
            )
        _validate_version(document, filename)
        documents[artifact] = document
        completeness_status = None
        if artifact == ARTIFACT_DEDICATED_BEARER:
            completeness_status = _dict(document.get("source_completeness")).get("status")
        sources.append(
            {
                "artifact_type": artifact,
                "artifact_name": filename,
                "analysis_name": analysis_name,
                "analysis_version": document.get("analysis_version"),
                "sha256": sha256_file(path),
                "supplied": True,
                "completeness_status": completeness_status,
            }
        )

    gtpv2 = read_jsonl(gtpv2_events) if gtpv2_events is not None else None
    gtpu = read_jsonl(gtpu_events) if gtpu_events is not None else None

    if documents[ARTIFACT_AUDIT] is None:
        documents[ARTIFACT_AUDIT] = _recompute_audit(
            documents[ARTIFACT_SESSION_IDENTITY] or {},
            documents[ARTIFACT_BEARER_LIFECYCLE] or {},
            documents[ARTIFACT_RELEASE_NARRATIVE] or {},
            documents[ARTIFACT_S1U],
            gtpv2,
            gtpu,
        )

    audit = documents[ARTIFACT_AUDIT] or {}
    inventory = {
        item.get("analysis_name"): item for item in _list(audit.get("source_artifacts"))
    }
    for source in sources:
        item = inventory.get(source["analysis_name"])
        if isinstance(item, dict):
            source["completeness_status"] = item.get("completeness_status")

    return {
        "documents": documents,
        "sources": sources,
        "gtpv2_events": gtpv2,
        "gtpu_events": gtpu,
        "detailed_gtpv2_supplied": gtpv2 is not None,
        "detailed_gtpu_supplied": gtpu is not None,
    }


def _append_missing(missing: list[dict[str, Any]], entry: dict[str, Any]) -> None:
    missing.append(entry)


def _ordered_counts(values: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        if not isinstance(value, str):
            continue
        counts[value] = counts.get(value, 0) + 1
    return {key: counts[key] for key in sorted(counts)}


def _capture_set(documents: dict[str, Any]) -> list[str]:
    captures: set[str] = set()
    identity = _dict(documents.get(ARTIFACT_SESSION_IDENTITY))
    lifecycle = _dict(documents.get(ARTIFACT_BEARER_LIFECYCLE))
    narrative = _dict(documents.get(ARTIFACT_RELEASE_NARRATIVE))
    s1u = _dict(documents.get(ARTIFACT_S1U))
    audit = _dict(documents.get(ARTIFACT_AUDIT))
    for key in ("hop_local_contexts", "release_session_bindings", "session_identity_links"):
        for item in _list(identity.get(key)):
            capture = safe_capture(_dict(item).get("capture_file"))
            if capture:
                captures.add(capture)
    for item in _list(identity.get("session_to_generation_links")):
        capture = safe_capture(_dict(item).get("capture_file"))
        if capture:
            captures.add(capture)
    for item in _list(identity.get("generation_closure_candidates")):
        capture = safe_capture(_dict(item).get("capture_file"))
        if capture:
            captures.add(capture)
    for key in ("lifecycle_subjects", "generation_boundary_evidence", "generation_scoped_s1u_observations"):
        for item in _list(lifecycle.get(key)):
            capture = safe_capture(_dict(item).get("capture_file"))
            if capture:
                captures.add(capture)
    for key in ("narrative_subjects", "release_narratives", "temporal_observations"):
        for item in _list(narrative.get(key)):
            capture = safe_capture(_dict(item).get("capture_file"))
            if capture:
                captures.add(capture)
    for item in _list(s1u.get("stream_observations")):
        capture = safe_capture(_dict(item).get("capture_file"))
        if capture:
            captures.add(capture)
    dedicated = _dict(documents.get(ARTIFACT_DEDICATED_BEARER))
    for item in _list(dedicated.get("control_transactions")):
        capture = safe_capture(_dict(item).get("capture"))
        if capture:
            captures.add(capture)
    for item in _list(dedicated.get("bearer_item_observations")):
        capture = safe_capture(_dict(item).get("capture"))
        if capture:
            captures.add(capture)
    for item in _list(dedicated.get("item_associations")):
        capture = safe_capture(_dict(item).get("capture"))
        if capture:
            captures.add(capture)
    for item in _list(audit.get("audit_records")):
        capture = safe_capture(_dict(item).get("capture_file"))
        if capture:
            captures.add(capture)
    return sorted(captures)


def _duplicate_values(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = item.get(key)
        if isinstance(value, str):
            counts[value] = counts.get(value, 0) + 1
    return {key_value: count for key_value, count in counts.items() if count > 1}


def _dedicated_item_projection(
    item: dict[str, Any],
    transaction: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Project one Domain item without recomputing or copying its outcome."""
    cause = _dict(item.get("cause"))
    return {
        "item_reference": item.get("item_reference"),
        "transaction_reference": item.get("transaction_reference"),
        "side": item.get("side"),
        "frame_number": item.get("frame_number"),
        "message_occurrence": item.get("message_occurrence"),
        "item_index": item.get("item_index"),
        "ebi": item.get("ebi"),
        "ebi_valid": item.get("ebi_valid"),
        "ebi_status": item.get("ebi_status"),
        "item_outcome": item.get("item_outcome"),
        "cause_code": cause.get("cause_code"),
        "cause_scope": cause.get("scope"),
        "qos_present": isinstance(item.get("qos"), dict),
        "tft_present": bool(_dict(item.get("tft")).get("present")),
        "evidence_limitations": (item.get("evidence_limitations") or [])[:MAX_LIST_ITEMS],
    }


def _dedicated_summary(dedicated: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(dedicated, dict):
        return {
            "status": "NOT_SUPPLIED",
            "source_artifact": None,
            "analysis_name": None,
            "analysis_version": None,
            "control_transaction_count": 0,
            "bearer_item_observation_count": 0,
            "item_association_count": 0,
            "transaction_family_counts": {},
            "correlation_status_counts": {},
            "transaction_outcome_counts": {},
            "message_outcome_counts": {},
            "item_outcome_counts": {},
            "item_association_status_counts": {},
            "source_completeness_status": None,
            "omitted_counts": {},
            "evidence_limitations": [],
            "not_confirmed": [],
        }
    transactions = [
        item for item in _list(dedicated.get("control_transactions")) if isinstance(item, dict)
    ]
    items = [
        item
        for item in _list(dedicated.get("bearer_item_observations"))
        if isinstance(item, dict)
    ]
    associations = [
        item for item in _list(dedicated.get("item_associations")) if isinstance(item, dict)
    ]
    family_counts = {"create-bearer": 0, "update-bearer": 0, "delete-bearer": 0}
    for transaction in transactions:
        family = transaction.get("procedure_family")
        if family in family_counts:
            family_counts[family] += 1
    completeness = _dict(dedicated.get("source_completeness"))
    return {
        "status": "EXECUTED" if transactions else "NOT_OBSERVED_IN_CAPTURE",
        "source_artifact": "epc-dedicated-bearer-control-analysis.json",
        "analysis_name": dedicated.get("analysis_name"),
        "analysis_version": dedicated.get("analysis_version"),
        "control_transaction_count": len(transactions),
        "bearer_item_observation_count": len(items),
        "item_association_count": len(associations),
        "transaction_family_counts": family_counts,
        "correlation_status_counts": _ordered_counts(
            [item.get("correlation_status") for item in transactions]
        ),
        "transaction_outcome_counts": _ordered_counts(
            [item.get("transaction_outcome") for item in transactions]
        ),
        "message_outcome_counts": _ordered_counts(
            [_dict(item.get("message_outcome")).get("status") for item in transactions]
        ),
        "item_outcome_counts": _ordered_counts([item.get("item_outcome") for item in items]),
        "item_association_status_counts": _ordered_counts(
            [item.get("status") for item in associations]
        ),
        "source_completeness_status": completeness.get("status"),
        "omitted_counts": {
            "control_transactions": dedicated.get("control_transactions_omitted", 0),
            "bearer_items": dedicated.get("bearer_item_observations_omitted", 0),
            "item_associations": dedicated.get("item_associations_omitted", 0),
        },
        "evidence_limitations": (dedicated.get("evidence_limitations") or [])[:MAX_LIST_ITEMS],
        "not_confirmed": (dedicated.get("not_confirmed") or [])[:MAX_LIST_ITEMS],
    }


def build_index(documents: dict[str, Any]) -> dict[str, Any]:
    identity = _dict(documents.get(ARTIFACT_SESSION_IDENTITY))
    lifecycle = _dict(documents.get(ARTIFACT_BEARER_LIFECYCLE))
    narrative = _dict(documents.get(ARTIFACT_RELEASE_NARRATIVE))
    s1u = _dict(documents.get(ARTIFACT_S1U))
    audit = _dict(documents.get(ARTIFACT_AUDIT))
    dedicated = _dict(documents.get(ARTIFACT_DEDICATED_BEARER))

    contexts = sorted(
        [_dict(item) for item in _list(identity.get("hop_local_contexts"))],
        key=lambda item: str(item.get("session_context_reference")),
    )
    bindings = sorted(
        [_dict(item) for item in _list(identity.get("release_session_bindings"))],
        key=lambda item: (
            str(item.get("capture_file")),
            str(item.get("source_subject_reference")),
            str(item.get("target_subject_reference")),
        ),
    )
    generation_links = sorted(
        [_dict(item) for item in _list(identity.get("session_to_generation_links"))],
        key=lambda item: (
            str(item.get("capture_file")),
            str(item.get("source_subject_reference")),
            str(item.get("target_subject_reference")),
        ),
    )
    candidates = sorted(
        [_dict(item) for item in _list(identity.get("generation_closure_candidates"))],
        key=lambda item: str(item.get("generation_closure_candidate_reference")),
    )
    identity_links = sorted(
        [_dict(item) for item in _list(identity.get("session_identity_links"))],
        key=lambda item: (
            str(item.get("capture_file")),
            str(item.get("source_subject_reference")),
            str(item.get("target_subject_reference")),
        ),
    )
    subjects = sorted(
        [_dict(item) for item in _list(lifecycle.get("lifecycle_subjects"))],
        key=lambda item: str(item.get("generation_reference")),
    )
    forced_streams = sorted(
        [_dict(item) for item in _list(lifecycle.get("generation_scoped_s1u_observations"))],
        key=lambda item: (
            str(item.get("generation_reference")),
            str(item.get("source_stream_reference")),
        ),
    )
    releases = sorted(
        [_dict(item) for item in _list(narrative.get("release_narratives"))],
        key=lambda item: str(item.get("release_narrative_reference")),
    )
    observations = sorted(
        [_dict(item) for item in _list(narrative.get("temporal_observations"))],
        key=lambda item: str(item.get("temporal_observation_reference")),
    )
    streams = sorted(
        [_dict(item) for item in _list(s1u.get("stream_observations"))],
        key=lambda item: str(item.get("stream_reference")),
    )
    audit_records = sorted(
        [_dict(item) for item in _list(audit.get("audit_records"))],
        key=lambda item: str(item.get("audit_record_reference")),
    )
    dedicated_transactions = sorted(
        [_dict(item) for item in _list(dedicated.get("control_transactions"))],
        key=lambda item: str(item.get("transaction_reference")),
    )
    dedicated_items = sorted(
        [_dict(item) for item in _list(dedicated.get("bearer_item_observations"))],
        key=lambda item: str(item.get("item_reference")),
    )
    dedicated_associations = sorted(
        [_dict(item) for item in _list(dedicated.get("item_associations"))],
        key=lambda item: str(item.get("association_reference")),
    )

    captures = _capture_set(documents)
    missing: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []

    def add_missing(kind: str, reference: Any, capture: str, context: str) -> None:
        safe = _safe_reference(reference)
        if safe is None:
            return
        _append_missing(
            missing,
            {
                "capture": capture,
                "kind": kind,
                "reference": safe,
                "context": context,
                "limitation": f"a published {kind.lower()} reference does not resolve in its capture scope",
            },
        )

    by_capture: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for capture in captures:
        by_capture[capture] = {
            "contexts": [item for item in contexts if safe_capture(item.get("capture_file")) == capture],
            "bindings": [item for item in bindings if safe_capture(item.get("capture_file")) == capture],
            "generation_links": [item for item in generation_links if safe_capture(item.get("capture_file")) == capture],
            "candidates": [item for item in candidates if safe_capture(item.get("capture_file")) == capture],
            "identity_links": [item for item in identity_links if safe_capture(item.get("capture_file")) == capture],
            "subjects": [item for item in subjects if safe_capture(item.get("capture_file")) == capture],
            "forced_streams": [item for item in forced_streams if safe_capture(item.get("capture_file")) == capture],
            "releases": [item for item in releases if safe_capture(item.get("capture_file")) == capture],
            "observations": [item for item in observations if safe_capture(item.get("capture_file")) == capture],
            "streams": [item for item in streams if safe_capture(item.get("capture_file")) == capture],
            "audit": [item for item in audit_records if safe_capture(item.get("capture_file")) == capture],
            "dedicated_transactions": [
                item
                for item in dedicated_transactions
                if safe_capture(item.get("capture")) == capture
            ],
            "dedicated_items": [
                item
                for item in dedicated_items
                if safe_capture(item.get("capture")) == capture
            ],
            "dedicated_associations": [
                item
                for item in dedicated_associations
                if safe_capture(item.get("capture")) == capture
            ],
        }
        for kind, key in (
            ("session_context", "hop_local_contexts"),
            ("release_narrative", "release_narratives"),
            ("temporal_observation", "temporal_observations"),
            ("s1u_stream", "stream_observations"),
            ("bearer_generation", "lifecycle_subjects"),
        ):
            source = {
                "session_context": by_capture[capture]["contexts"],
                "release_narrative": by_capture[capture]["releases"],
                "temporal_observation": by_capture[capture]["observations"],
                "s1u_stream": by_capture[capture]["streams"],
                "bearer_generation": by_capture[capture]["subjects"],
            }[kind]
            reference_key = {
                "session_context": "session_context_reference",
                "release_narrative": "release_narrative_reference",
                "temporal_observation": "temporal_observation_reference",
                "s1u_stream": "stream_reference",
                "bearer_generation": "generation_reference",
            }[kind]
            for reference, count in _duplicate_values(source, reference_key).items():
                ambiguous.append(
                    {
                        "capture": capture,
                        "kind": kind,
                        "reference": reference,
                        "occurrences": count,
                        "limitation": "equal textual references inside one capture are ambiguous and are not selected",
                    }
                )
        by_capture[capture]["_keys"] = {
            "session_context": {
                str(item.get("session_context_reference")): item for item in by_capture[capture]["contexts"]
            },
            "release_narrative": {
                str(item.get("release_narrative_reference")): item for item in by_capture[capture]["releases"]
            },
            "temporal_observation": {
                str(item.get("temporal_observation_reference")): item for item in by_capture[capture]["observations"]
            },
            "s1u_stream": {
                str(item.get("stream_reference")): item for item in by_capture[capture]["streams"]
            },
            "bearer_generation": {
                str(item.get("generation_reference")): item for item in by_capture[capture]["subjects"]
            },
            "closure_candidate": {
                str(item.get("generation_closure_candidate_reference")): item for item in by_capture[capture]["candidates"]
            },
        }

    cross_capture_collisions: list[dict[str, Any]] = []
    for kind, key, collection in (
        ("temporal_observation", "temporal_observation_reference", observations),
        ("s1u_stream", "stream_reference", streams),
        ("bearer_generation", "generation_reference", subjects),
        ("session_context", "session_context_reference", contexts),
        ("release_narrative", "release_narrative_reference", releases),
    ):
        values: dict[str, set[str]] = {}
        for item in collection:
            capture = safe_capture(item.get("capture_file"))
            value = item.get(key)
            if capture and isinstance(value, str):
                values.setdefault(value, set()).add(capture)
        for value, seen in sorted(values.items()):
            if len(seen) > 1:
                cross_capture_collisions.append(
                    {
                        "kind": kind,
                        "reference": value,
                        "captures": sorted(seen),
                        "limitation": "the same textual reference appears in multiple captures and stays capture-scoped",
                    }
                )

    capture_nodes: list[dict[str, Any]] = []
    for capture in captures:
        bucket = by_capture[capture]
        keys = bucket["_keys"]
        context_nodes = [
            {
                "session_context_reference": item.get("session_context_reference"),
                "interface_class": item.get("interface_class"),
                "association_status": item.get("association_status"),
                "allocation_outcome_status": item.get("allocation_outcome_status"),
                "transaction_references": [_safe_reference(value) for value in _list(item.get("member_transaction_references")) if _safe_reference(value)],
            }
            for item in bucket["contexts"][:MAX_CONTEXTS]
        ]
        generation_nodes: list[dict[str, Any]] = []
        for item in bucket["subjects"][:MAX_GENERATIONS]:
            generation_reference = item.get("generation_reference")
            scoped_references: list[str] = []
            for scoped in bucket["forced_streams"]:
                if scoped.get("generation_reference") != generation_reference:
                    continue
                stream_reference = _safe_reference(scoped.get("source_stream_reference"))
                if stream_reference is None:
                    continue
                scoped_references.append(stream_reference)
                if stream_reference not in keys["s1u_stream"]:
                    add_missing(
                        "S1U_STREAM",
                        stream_reference,
                        capture,
                        f"generation:{generation_reference}",
                    )
            generation_nodes.append(
                {
                    "generation_reference": generation_reference,
                    "receiving_endpoint_role": item.get("receiving_endpoint_role"),
                    "receiving_endpoint_address": item.get("receiving_endpoint_address"),
                    "receiving_endpoint_teid": item.get("receiving_endpoint_teid"),
                    "reviewed_interface_type": item.get("reviewed_interface_type"),
                    "generation_state": item.get("generation_state"),
                    "scoped_stream_references": sorted(set(scoped_references)),
                }
            )
        stream_nodes = [
            {
                "stream_reference": item.get("stream_reference"),
                "direction": item.get("direction"),
                "outer_source": item.get("outer_source"),
                "outer_destination": item.get("outer_destination"),
                "teid": item.get("teid"),
                "association_status": item.get("association_status"),
                "observed_g_pdu_packet_count": item.get("observed_g_pdu_packet_count"),
                "observed_payload_byte_count": item.get("observed_payload_byte_count"),
                "first_frame": item.get("first_frame"),
                "last_frame": item.get("last_frame"),
            }
            for item in bucket["streams"][:MAX_STREAMS]
        ]
        observation_nodes: list[dict[str, Any]] = []
        for item in bucket["observations"][:MAX_OBSERVATIONS]:
            observation_reference = item.get("temporal_observation_reference")
            release_reference = item.get("release_narrative_reference")
            stream_reference = item.get("stream_reference")
            if release_reference not in keys["release_narrative"]:
                add_missing("RELEASE_NARRATIVE", release_reference, capture, f"temporal:{observation_reference}")
            if stream_reference not in keys["s1u_stream"]:
                add_missing("S1U_STREAM", stream_reference, capture, f"temporal:{observation_reference}")
            observation_nodes.append(
                {
                    "temporal_observation_reference": observation_reference,
                    "release_narrative_reference": release_reference,
                    "stream_reference": stream_reference,
                    "generation_reference": item.get("generation_reference"),
                    "temporal_placement_status": item.get("temporal_placement_status"),
                    "partition_scope": item.get("partition_scope"),
                    "partition_conserved": item.get("partition_conserved"),
                    "duplicate_frame_ownership": bool(item.get("duplicate_frame_ownership")),
                    "observed_g_pdu_count": item.get("observed_g_pdu_count"),
                    "observed_payload_octets": item.get("observed_payload_octets"),
                    "first_observed_frame": item.get("first_observed_frame"),
                    "last_observed_frame": item.get("last_observed_frame"),
                }
            )
        known: set[str] = set()
        for namespace in keys.values():
            known.update(namespace.keys())
        for item in bucket["contexts"]:
            known.add(str(item.get("session_context_reference")))
        for item in bucket["releases"]:
            known.update(
                str(item.get(key))
                for key in (
                    "release_narrative_reference",
                    "release_transaction_reference",
                    "narrative_subject_reference",
                    "narrative_group_reference",
                    "session_context_reference",
                )
            )
        for item in bucket["subjects"]:
            known.update(
                str(item.get(key))
                for key in ("generation_reference", "transaction_reference")
            )
            boundary = _dict(item.get("generation_boundary"))
            if boundary.get("transaction_reference") is not None:
                known.add(str(boundary.get("transaction_reference")))
        for item in bucket["bindings"]:
            known.update(
                str(item.get(key))
                for key in ("source_subject_reference", "target_subject_reference")
            )
        for item in bucket["generation_links"]:
            known.update(
                str(item.get(key))
                for key in ("source_subject_reference", "target_subject_reference")
            )
        for item in bucket["candidates"]:
            known.update(
                str(item.get(key))
                for key in (
                    "generation_closure_candidate_reference",
                    "session_context_reference",
                    "release_transaction_reference",
                    "bearer_endpoint_reference",
                )
            )
        for item in bucket["identity_links"]:
            known.update(
                str(item.get(key))
                for key in ("source_subject_reference", "target_subject_reference")
            )
        for item in bucket["forced_streams"]:
            known.update(
                str(item.get(key))
                for key in ("source_stream_reference", "generation_reference")
            )
        for item in bucket["streams"]:
            known.add(str(item.get("stream_reference")))
        for item in bucket["observations"]:
            known.update(
                str(item.get(key))
                for key in (
                    "temporal_observation_reference",
                    "release_narrative_reference",
                    "stream_reference",
                    "generation_reference",
                )
            )
        for item in bucket["audit"]:
            known.add(str(item.get("audit_record_reference")))
        known = {value for value in known if value and value != "None"}
        audit_nodes: list[dict[str, Any]] = []
        for item in bucket["audit"][:MAX_FINDINGS]:
            source_subject = item.get("source_subject_reference")
            target_subject = item.get("target_subject_reference")
            if isinstance(source_subject, str) and source_subject not in known:
                add_missing("AUDIT_SUBJECT", source_subject, capture, str(item.get("audit_record_reference")))
            if isinstance(target_subject, str) and target_subject not in known:
                add_missing("AUDIT_SUBJECT", target_subject, capture, str(item.get("audit_record_reference")))
            audit_nodes.append(
                {
                    "audit_record_reference": item.get("audit_record_reference"),
                    "audit_category": item.get("audit_category"),
                    "audit_status": item.get("audit_status"),
                    "relationship_type": item.get("relationship_type"),
                    "source_subject_reference": source_subject,
                    "target_subject_reference": target_subject,
                    "proof_sufficiency_status": item.get("proof_sufficiency_status"),
                    "candidate_completeness_status": item.get("candidate_completeness_status"),
                    "failed_checks": sorted(
                        check.get("check")
                        for check in _list(item.get("consistency_checks"))
                        if _dict(check).get("result") == "FAIL" and isinstance(check.get("check"), str)
                    ),
                    "limitation": _text((_list(item.get("limitations")) or [None])[0]),
                }
            )
        release_nodes: list[dict[str, Any]] = []
        for item in bucket["releases"][:MAX_RELEASES]:
            release_reference = item.get("release_narrative_reference")
            context_reference = item.get("session_context_reference")
            if context_reference not in keys["session_context"]:
                add_missing("SESSION_CONTEXT", context_reference, capture, f"release:{release_reference}")
            proved_generations: list[dict[str, Any]] = []
            for proved in _list(item.get("proved_generations")):
                proved = _dict(proved)
                generation_reference = proved.get("generation_reference")
                resolved = generation_reference in keys["bearer_generation"]
                if not resolved:
                    add_missing("BEARER_GENERATION", generation_reference, capture, f"release:{release_reference}")
                closure_candidate = proved.get("closure_candidate_reference")
                candidate_resolved = closure_candidate in keys["closure_candidate"]
                if isinstance(closure_candidate, str) and not candidate_resolved:
                    add_missing("CLOSURE_CANDIDATE", closure_candidate, capture, f"release:{release_reference}")
                proved_generations.append(
                    {
                        "generation_reference": generation_reference,
                        "closure_candidate_reference": closure_candidate,
                        "generation_resolved": resolved,
                        "closure_candidate_resolved": candidate_resolved if isinstance(closure_candidate, str) else None,
                        "receiving_endpoint_role": proved.get("receiving_endpoint_role"),
                        "receiving_endpoint_address": proved.get("receiving_endpoint_address"),
                        "receiving_endpoint_teid": proved.get("receiving_endpoint_teid"),
                        "reviewed_interface_type": proved.get("reviewed_interface_type"),
                    }
                )
            temporal_references = [
                _safe_reference(value)
                for value in _list(item.get("temporal_observation_references"))
                if _safe_reference(value)
            ]
            for temporal_reference in temporal_references:
                if temporal_reference not in keys["temporal_observation"]:
                    add_missing("TEMPORAL_OBSERVATION", temporal_reference, capture, f"release:{release_reference}")
            binding = next(
                (
                    candidate
                    for candidate in bucket["bindings"]
                    if candidate.get("source_subject_reference") == item.get("release_transaction_reference")
                    and candidate.get("target_subject_reference") == context_reference
                ),
                None,
            )
            if binding is None:
                add_missing(
                    "RELEASE_SESSION_BINDING",
                    item.get("release_transaction_reference"),
                    capture,
                    f"release:{release_reference}",
                )
            release_nodes.append(
                {
                    "release_narrative_reference": release_reference,
                    "release_transaction_reference": item.get("release_transaction_reference"),
                    "session_context_reference": context_reference,
                    "session_context_resolved": context_reference in keys["session_context"],
                    "release_outcome_status": item.get("release_outcome_status"),
                    "release_session_binding_status": item.get("release_session_binding_status"),
                    "generation_closure_status": item.get("generation_closure_status"),
                    "binding_resolved": binding is not None,
                    "binding_status": _dict(binding).get("association_status") if binding else None,
                    "proved_generations": proved_generations,
                    "temporal_observation_references": temporal_references,
                }
            )
        dedicated_tx_nodes = [
            {
                "transaction_reference": item.get("transaction_reference"),
                "procedure_family": item.get("procedure_family"),
                "correlation_status": item.get("correlation_status"),
                "transaction_outcome": item.get("transaction_outcome"),
                "message_outcome_status": _dict(item.get("message_outcome")).get("status"),
                "request_frame": _dict(item.get("frame_anchors")).get("request_frame"),
                "response_frame": _dict(item.get("frame_anchors")).get("response_frame"),
                "request_item_references": (
                    item.get("request_bearer_item_references") or []
                )[:MAX_REFERENCES],
                "response_item_references": (
                    item.get("response_bearer_item_references") or []
                )[:MAX_REFERENCES],
            }
            for item in bucket["dedicated_transactions"][:MAX_DEDICATED_TRANSACTIONS]
        ]
        dedicated_item_nodes = [
            _dedicated_item_projection(item) for item in bucket["dedicated_items"][:MAX_DEDICATED_ITEMS]
        ]
        dedicated_assoc_nodes = [
            {
                "association_reference": item.get("association_reference"),
                "transaction_reference": item.get("transaction_reference"),
                "request_item_reference": item.get("request_item_reference"),
                "response_item_reference": item.get("response_item_reference"),
                "request_top_level_ebi_reference": item.get(
                    "request_top_level_ebi_reference"
                ),
                "ebi": item.get("ebi"),
                "status": item.get("status"),
                "limitations": (item.get("limitations") or [])[:MAX_LIST_ITEMS],
            }
            for item in bucket["dedicated_associations"][:MAX_DEDICATED_ASSOCIATIONS]
        ]
        dedicated_tx_refs = {
            str(item.get("transaction_reference"))
            for item in bucket["dedicated_transactions"]
            if isinstance(item.get("transaction_reference"), str)
        }
        dedicated_item_refs = {
            str(item.get("item_reference"))
            for item in bucket["dedicated_items"]
            if isinstance(item.get("item_reference"), str)
        }
        for item in bucket["dedicated_items"]:
            transaction_reference = item.get("transaction_reference")
            if isinstance(transaction_reference, str) and transaction_reference not in dedicated_tx_refs:
                add_missing(
                    "DEDICATED_BEARER_TRANSACTION",
                    transaction_reference,
                    capture,
                    f"item:{item.get('item_reference')}",
                )
        for item in bucket["dedicated_associations"]:
            transaction_reference = item.get("transaction_reference")
            if isinstance(transaction_reference, str) and transaction_reference not in dedicated_tx_refs:
                add_missing(
                    "DEDICATED_BEARER_TRANSACTION",
                    transaction_reference,
                    capture,
                    f"association:{item.get('association_reference')}",
                )
            for key in ("request_item_reference", "response_item_reference"):
                reference = item.get(key)
                if isinstance(reference, str) and reference not in dedicated_item_refs:
                    add_missing(
                        "DEDICATED_BEARER_ITEM",
                        reference,
                        capture,
                        f"association:{item.get('association_reference')}",
                    )
        capture_nodes.append(
            {
                "capture": capture,
                "session_contexts": context_nodes,
                "release_narratives": release_nodes,
                "bearer_generations": generation_nodes,
                "s1u_streams": stream_nodes,
                "temporal_observations": observation_nodes,
                "audit_findings": audit_nodes,
                "dedicated_bearer_control": {
                    "transactions": dedicated_tx_nodes,
                    "items": dedicated_item_nodes,
                    "associations": dedicated_assoc_nodes,
                },
                "counts": {
                    "session_contexts": len(bucket["contexts"]),
                    "release_narratives": len(bucket["releases"]),
                    "bearer_generations": len(bucket["subjects"]),
                    "s1u_streams": len(bucket["streams"]),
                    "temporal_observations": len(bucket["observations"]),
                    "audit_findings": len(bucket["audit"]),
                    "dedicated_control_transactions": len(bucket["dedicated_transactions"]),
                    "dedicated_bearer_items": len(bucket["dedicated_items"]),
                    "dedicated_item_associations": len(bucket["dedicated_associations"]),
                    "session_to_generation_links": len(bucket["generation_links"]),
                    "identity_links": len(bucket["identity_links"]),
                },
                "omitted": {
                    "session_contexts": max(0, len(bucket["contexts"]) - MAX_CONTEXTS),
                    "release_narratives": max(0, len(bucket["releases"]) - MAX_RELEASES),
                    "bearer_generations": max(0, len(bucket["subjects"]) - MAX_GENERATIONS),
                    "s1u_streams": max(0, len(bucket["streams"]) - MAX_STREAMS),
                    "temporal_observations": max(0, len(bucket["observations"]) - MAX_OBSERVATIONS),
                    "audit_findings": max(0, len(bucket["audit"]) - MAX_FINDINGS),
                    "dedicated_control_transactions": max(
                        0, len(bucket["dedicated_transactions"]) - MAX_DEDICATED_TRANSACTIONS
                    ),
                    "dedicated_bearer_items": max(
                        0, len(bucket["dedicated_items"]) - MAX_DEDICATED_ITEMS
                    ),
                    "dedicated_item_associations": max(
                        0, len(bucket["dedicated_associations"]) - MAX_DEDICATED_ASSOCIATIONS
                    ),
                },
            }
        )

    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "index_name": REVIEW_NAME,
        "captures": capture_nodes,
        "missing_references": missing[:MAX_REFERENCES],
        "missing_reference_count": len(missing),
        "ambiguous_references": ambiguous[:MAX_REFERENCES],
        "ambiguous_reference_count": len(ambiguous),
        "cross_capture_references": cross_capture_collisions[:MAX_REFERENCES],
        "cross_capture_reference_count": len(cross_capture_collisions),
        "reference_counts": {
            "session_context": len(contexts),
            "release_narrative": len(releases),
            "bearer_generation": len(subjects),
            "s1u_stream": len(streams),
            "temporal_observation": len(observations),
            "audit_record": len(audit_records),
            "session_to_generation_link": len(generation_links),
            "identity_link": len(identity_links),
            "closure_candidate": len(candidates),
            "dedicated_control_transaction": len(dedicated_transactions),
            "dedicated_bearer_item": len(dedicated_items),
            "dedicated_item_association": len(dedicated_associations),
        },
        "bounded_limits": {
            "session_contexts": MAX_CONTEXTS,
            "release_narratives": MAX_RELEASES,
            "bearer_generations": MAX_GENERATIONS,
            "s1u_streams": MAX_STREAMS,
            "temporal_observations": MAX_OBSERVATIONS,
            "audit_findings": MAX_FINDINGS,
            "references": MAX_REFERENCES,
            "dedicated_control_transactions": MAX_DEDICATED_TRANSACTIONS,
            "dedicated_bearer_items": MAX_DEDICATED_ITEMS,
            "dedicated_item_associations": MAX_DEDICATED_ASSOCIATIONS,
        },
    }


def _completeness_status(audit: dict[str, Any]) -> str:
    return str(_dict(audit.get("source_completeness")).get("status") or "UNKNOWN")


def _strict_count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None


def _audit_completeness(audit: dict[str, Any]) -> dict[str, Any]:
    completeness = _dict(audit.get("source_completeness"))
    status = completeness.get("status")
    exhaustive = completeness.get("exhaustive_coverage_proven")
    collections = [_dict(entry) for entry in _list(completeness.get("collections"))]
    source_metadata_valid = isinstance(exhaustive, bool)
    collections_complete = all(
        entry.get("status") in (None, "COMPLETE") for entry in collections
    )
    source_collections_complete = (
        status == "COMPLETE" and exhaustive is True and collections_complete
    )
    supplied = _list(audit.get("audit_records"))
    declared = _strict_count(audit.get("audit_record_count"))
    omitted = _strict_count(audit.get("audit_records_omitted"))
    ledger_metadata_valid = (
        declared is not None
        and omitted is not None
        and declared == len(supplied) + omitted
    )
    ledger_complete = ledger_metadata_valid and omitted == 0
    return {
        "source_completeness_status": status if isinstance(status, str) else None,
        "exhaustive_coverage_proven": exhaustive if isinstance(exhaustive, bool) else None,
        "source_metadata_valid": source_metadata_valid,
        "source_collections_complete": source_collections_complete,
        "audit_record_count_declared": declared,
        "audit_records_supplied": len(supplied),
        "audit_records_omitted": omitted,
        "audit_ledger_metadata_valid": ledger_metadata_valid,
        "audit_ledger_complete": ledger_complete,
        "audit_results_truncated": (
            not source_metadata_valid
            or not source_collections_complete
            or not ledger_metadata_valid
            or not ledger_complete
        ),
    }


def _audit_truncated(audit: dict[str, Any]) -> bool:
    return bool(_audit_completeness(audit)["audit_results_truncated"])


def build_manifest(
    artifacts: dict[str, Any],
    *,
    mode: str,
    local_pcap_replayed: bool,
    replay_status: str,
    review_artifact_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
    documents = artifacts["documents"]
    audit = _dict(documents.get(ARTIFACT_AUDIT))
    sources = []
    for source in artifacts["sources"]:
        sources.append(
            {
                "artifact_type": source["artifact_type"],
                "artifact_name": source["artifact_name"],
                "analysis_name": source["analysis_name"],
                "analysis_version": source["analysis_version"],
                "sha256": source["sha256"],
                "supplied": source["supplied"],
                "completeness_status": source["completeness_status"],
            }
        )
    limitations = []
    for value in _list(audit.get("evidence_limitations")):
        safe = _text(value)
        if safe:
            limitations.append(safe)
    completeness = _audit_completeness(audit)
    review_published = min(len(_list(audit.get("audit_records"))), MAX_FINDINGS)
    review_omitted = max(0, len(_list(audit.get("audit_records"))) - MAX_FINDINGS)
    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "review_name": REVIEW_NAME,
        "review_version": REVIEW_VERSION,
        "mode": mode,
        "capture_identities": _capture_set(documents),
        "source_artifacts": sources,
        "detailed_gtpv2_supplied": bool(artifacts["detailed_gtpv2_supplied"]),
        "detailed_gtpu_supplied": bool(artifacts["detailed_gtpu_supplied"]),
        "local_pcap_replayed": bool(local_pcap_replayed),
        "replay_status": replay_status,
        "source_completeness_status": completeness["source_completeness_status"],
        "exhaustive_coverage_proven": completeness["exhaustive_coverage_proven"],
        "source_collections_complete": completeness["source_collections_complete"],
        "audit_ledger_metadata_valid": completeness["audit_ledger_metadata_valid"],
        "audit_ledger_complete": completeness["audit_ledger_complete"],
        "audit_record_count_declared": completeness["audit_record_count_declared"],
        "audit_records_supplied": completeness["audit_records_supplied"],
        "audit_records_omitted": completeness["audit_records_omitted"],
        "review_audit_records_published": review_published,
        "review_audit_records_omitted": review_omitted,
        "review_display_complete": review_omitted == 0,
        "audit_results_truncated": completeness["audit_results_truncated"],
        "evidence_limitations": limitations[:MAX_REFERENCES],
        "review_artifact_hashes": review_artifact_hashes or {},
        "provenance": {
            "session_identity": "epc-session-identity-analysis.json",
            "bearer_lifecycle": "epc-bearer-lifecycle-analysis.json",
            "release_narrative": "epc-release-narrative-analysis.json",
            "s1u_observation": next(
                (
                    source["artifact_name"]
                    for source in artifacts["sources"]
                    if source["artifact_type"] == ARTIFACT_S1U and source["supplied"]
                ),
                None,
            ),
            "evidence_audit": "epc-evidence-audit-analysis.json",
            "dedicated_bearer_control": next(
                (
                    source["artifact_name"]
                    for source in artifacts["sources"]
                    if source["artifact_type"] == ARTIFACT_DEDICATED_BEARER
                    and source["supplied"]
                ),
                None,
            ),
        },
    }


def build_review(documents: dict[str, Any], index: dict[str, Any]) -> dict[str, Any]:
    identity = _dict(documents.get(ARTIFACT_SESSION_IDENTITY))
    lifecycle = _dict(documents.get(ARTIFACT_BEARER_LIFECYCLE))
    narrative = _dict(documents.get(ARTIFACT_RELEASE_NARRATIVE))
    s1u = _dict(documents.get(ARTIFACT_S1U))
    audit = _dict(documents.get(ARTIFACT_AUDIT))
    dedicated_document = documents.get(ARTIFACT_DEDICATED_BEARER)
    if not isinstance(dedicated_document, dict):
        dedicated_document = None
    dedicated = _dict(dedicated_document)

    contexts = sorted(
        [_dict(item) for item in _list(identity.get("hop_local_contexts"))],
        key=lambda item: str(item.get("session_context_reference")),
    )
    generations = sorted(
        [_dict(item) for item in _list(lifecycle.get("lifecycle_subjects"))],
        key=lambda item: str(item.get("generation_reference")),
    )
    streams = sorted(
        [_dict(item) for item in _list(s1u.get("stream_observations"))],
        key=lambda item: str(item.get("stream_reference")),
    )
    releases = sorted(
        [_dict(item) for item in _list(narrative.get("release_narratives"))],
        key=lambda item: str(item.get("release_narrative_reference")),
    )
    observations = sorted(
        [_dict(item) for item in _list(narrative.get("temporal_observations"))],
        key=lambda item: str(item.get("temporal_observation_reference")),
    )
    audit_records = sorted(
        [_dict(item) for item in _list(audit.get("audit_records"))],
        key=lambda item: str(item.get("audit_record_reference")),
    )
    dedicated = _dict(dedicated_document)
    dedicated_transactions = sorted(
        [_dict(item) for item in _list(dedicated.get("control_transactions"))],
        key=lambda item: str(item.get("transaction_reference")),
    )
    dedicated_items = sorted(
        [_dict(item) for item in _list(dedicated.get("bearer_item_observations"))],
        key=lambda item: str(item.get("item_reference")),
    )
    dedicated_associations = sorted(
        [_dict(item) for item in _list(dedicated.get("item_associations"))],
        key=lambda item: str(item.get("association_reference")),
    )
    dedicated_transactions_by_ref = {
        str(item.get("transaction_reference")): item
        for item in dedicated_transactions
        if isinstance(item.get("transaction_reference"), str)
    }
    completeness = _audit_completeness(audit)
    review_published = min(len(audit_records), MAX_FINDINGS)
    review_omitted = max(0, len(audit_records) - MAX_FINDINGS)

    sections: dict[str, Any] = {}
    sections["capture_and_session_context_overview"] = [
        {
            "classification": CLASSIFICATION_DERIVED,
            "capture": safe_capture(item.get("capture_file")),
            "session_context_reference": item.get("session_context_reference"),
            "interface_class": item.get("interface_class"),
            "association_status": item.get("association_status"),
            "allocation_outcome_status": item.get("allocation_outcome_status"),
            "source_references": [item.get("session_context_reference")],
        }
        for item in contexts[:MAX_CONTEXTS]
    ]
    sections["release_outcome_summary"] = [
        {
            "classification": CLASSIFICATION_DERIVED,
            "capture": safe_capture(item.get("capture_file")),
            "release_narrative_reference": item.get("release_narrative_reference"),
            "release_transaction_reference": item.get("release_transaction_reference"),
            "release_outcome_status": item.get("release_outcome_status"),
            "generation_closure_status": item.get("generation_closure_status"),
            "proved_generation_count": len(_list(item.get("proved_generations"))),
            "source_references": [item.get("release_narrative_reference")],
        }
        for item in releases[:MAX_RELEASES]
    ]
    sections["release_binding_summary"] = [
        {
            "classification": CLASSIFICATION_DERIVED,
            "capture": safe_capture(item.get("capture_file")),
            "release_narrative_reference": item.get("release_narrative_reference"),
            "session_context_reference": item.get("session_context_reference"),
            "release_session_binding_status": item.get("release_session_binding_status"),
            "source_references": [item.get("release_narrative_reference")],
        }
        for item in releases[:MAX_RELEASES]
    ]
    sections["bearer_generation_closure_summary"] = [
        {
            "classification": CLASSIFICATION_DERIVED,
            "capture": safe_capture(item.get("capture_file")),
            "generation_reference": item.get("generation_reference"),
            "generation_state": item.get("generation_state"),
            "receiving_endpoint_role": item.get("receiving_endpoint_role"),
            "receiving_endpoint_address": item.get("receiving_endpoint_address"),
            "receiving_endpoint_teid": item.get("receiving_endpoint_teid"),
            "source_references": [item.get("generation_reference")],
        }
        for item in generations[:MAX_GENERATIONS]
    ]
    sections["s1u_observation_summary"] = [
        {
            "classification": CLASSIFICATION_DERIVED,
            "capture": safe_capture(item.get("capture_file")),
            "stream_reference": item.get("stream_reference"),
            "direction": item.get("direction"),
            "teid": item.get("teid"),
            "association_status": item.get("association_status"),
            "observed_g_pdu_packet_count": item.get("observed_g_pdu_packet_count"),
            "observed_payload_byte_count": item.get("observed_payload_byte_count"),
            "source_references": [item.get("stream_reference")],
        }
        for item in streams[:MAX_STREAMS]
    ]
    dedicated_summary = _dedicated_summary(dedicated_document)
    sections["dedicated_bearer_control_summary"] = [
        {
            "classification": (
                CLASSIFICATION_DERIVED
                if dedicated_summary["status"] != "NOT_SUPPLIED"
                else CLASSIFICATION_UNSUPPORTED
            ),
            **dedicated_summary,
            "source_references": (
                [dedicated_summary["source_artifact"]]
                if dedicated_summary["source_artifact"]
                else []
            ),
            "limitation": (
                None
                if dedicated_summary["status"] != "NOT_SUPPLIED"
                else "the optional Dedicated Bearer Control artifact was not supplied; the existing Review Pack remains valid"
            ),
        }
    ]
    sections["dedicated_bearer_control_transactions"] = [
        {
            "classification": CLASSIFICATION_DERIVED,
            "capture": safe_capture(item.get("capture")),
            "transaction_reference": item.get("transaction_reference"),
            "procedure_family": item.get("procedure_family"),
            "correlation_status": item.get("correlation_status"),
            "transaction_outcome": item.get("transaction_outcome"),
            "message_outcome_status": _dict(item.get("message_outcome")).get("status"),
            "evidence_limitations": (item.get("evidence_limitations") or [])[:MAX_LIST_ITEMS],
            "source_references": [item.get("transaction_reference")],
        }
        for item in dedicated_transactions[:MAX_DEDICATED_TRANSACTIONS]
    ]
    sections["dedicated_bearer_control_items"] = [
        {
            "classification": (
                CLASSIFICATION_UNRESOLVED
                if item.get("item_outcome")
                in ("ITEM_OUTCOME_UNRESOLVED", "ITEM_OUTCOME_NOT_OBSERVED")
                else CLASSIFICATION_DERIVED
            ),
            "capture": safe_capture(item.get("capture")),
            **_dedicated_item_projection(
                item, dedicated_transactions_by_ref.get(str(item.get("transaction_reference")))
            ),
            "source_references": [item.get("item_reference")],
        }
        for item in dedicated_items[:MAX_DEDICATED_ITEMS]
    ]
    sections["dedicated_bearer_control_associations"] = [
        {
            "classification": (
                CLASSIFICATION_DERIVED
                if item.get("status") == "ITEM_ASSOCIATION_ESTABLISHED"
                else CLASSIFICATION_UNRESOLVED
            ),
            "capture": safe_capture(item.get("capture")),
            "association_reference": item.get("association_reference"),
            "transaction_reference": item.get("transaction_reference"),
            "request_item_reference": item.get("request_item_reference"),
            "response_item_reference": item.get("response_item_reference"),
            "request_top_level_ebi_reference": item.get(
                "request_top_level_ebi_reference"
            ),
            "ebi": item.get("ebi"),
            "status": item.get("status"),
            "limitations": (item.get("limitations") or [])[:MAX_LIST_ITEMS],
            "source_references": [
                value
                for value in (
                    item.get("request_item_reference"),
                    item.get("response_item_reference"),
                    item.get("request_top_level_ebi_reference"),
                )
                if isinstance(value, str)
            ],
        }
        for item in dedicated_associations[:MAX_DEDICATED_ASSOCIATIONS]
    ]

    sections["temporal_placement_summary"] = [
        {
            "classification": CLASSIFICATION_DERIVED,
            "capture": safe_capture(item.get("capture_file")),
            "temporal_observation_reference": item.get("temporal_observation_reference"),
            "release_narrative_reference": item.get("release_narrative_reference"),
            "stream_reference": item.get("stream_reference"),
            "temporal_placement_status": item.get("temporal_placement_status"),
            "partition_scope": item.get("partition_scope"),
            "partition_conserved": item.get("partition_conserved"),
            "observed_g_pdu_count": item.get("observed_g_pdu_count"),
            "observed_payload_octets": item.get("observed_payload_octets"),
            "source_references": [item.get("temporal_observation_reference")],
        }
        for item in observations[:MAX_OBSERVATIONS]
    ]
    conflicted = [
        item
        for item in observations
        if item.get("duplicate_frame_ownership")
        or any(
            _dict(record).get("audit_category") == "TEMPORAL_FRAME_PARTITION"
            and _dict(record).get("source_subject_reference") == item.get("temporal_observation_reference")
            and _dict(record).get("capture_file") == item.get("capture_file")
            and any(
                _dict(check).get("check") == "frame_ownership_exclusive"
                and _dict(check).get("result") == "FAIL"
                for check in _list(_dict(record).get("consistency_checks"))
            )
            for record in audit_records
        )
    ]
    sections["conflicting_or_ambiguous_ownership"] = [
        {
            "classification": CLASSIFICATION_UNRESOLVED,
            "capture": safe_capture(item.get("capture_file")),
            "temporal_observation_reference": item.get("temporal_observation_reference"),
            "stream_reference": item.get("stream_reference"),
            "duplicate_frame_ownership": bool(item.get("duplicate_frame_ownership")),
            "source_references": [item.get("temporal_observation_reference")],
            "limitation": "duplicate frame ownership is visible, scoped to its actual claimants and never resolved by selecting an owner",
        }
        for item in conflicted[:MAX_OBSERVATIONS]
    ]
    for duplicate in index["ambiguous_references"]:
        sections["conflicting_or_ambiguous_ownership"].append(
            {
                "classification": CLASSIFICATION_UNRESOLVED,
                "capture": duplicate.get("capture"),
                "temporal_observation_reference": None,
                "stream_reference": None,
                "duplicate_frame_ownership": False,
                "source_references": [duplicate.get("reference")],
                "limitation": duplicate.get("limitation"),
            }
        )
    completeness_entries = []
    for entry in _list(_dict(audit.get("source_completeness")).get("collections")):
        entry = _dict(entry)
        if entry.get("status") == "COMPLETE":
            continue
        completeness_entries.append(
            {
                "classification": CLASSIFICATION_AUDIT,
                "document": entry.get("document"),
                "collection": entry.get("collection"),
                "status": entry.get("status"),
                "declared_count": entry.get("declared_count"),
                "published_count": entry.get("published_count"),
                "omitted_count": entry.get("omitted_count"),
                "source_references": [entry.get("collection")],
            }
        )
    for source in _list(audit.get("source_artifacts")):
        source = _dict(source)
        if source.get("supplied") is False:
            completeness_entries.append(
                {
                    "classification": CLASSIFICATION_UNSUPPORTED,
                    "document": source.get("analysis_name"),
                    "collection": source.get("artifact"),
                    "status": "NOT_SUPPLIED",
                    "declared_count": source.get("declared_count"),
                    "published_count": source.get("record_count"),
                    "omitted_count": None,
                    "source_references": [source.get("artifact")],
                }
            )
    if not completeness["source_metadata_valid"]:
        completeness_entries.append(
            {
                "classification": CLASSIFICATION_AUDIT,
                "document": "epc-evidence-audit",
                "collection": "source_completeness.exhaustive_coverage_proven",
                "status": "INVALID_METADATA",
                "declared_count": None,
                "published_count": None,
                "omitted_count": None,
                "source_references": ["source_completeness"],
            }
        )
    elif completeness["exhaustive_coverage_proven"] is False:
        completeness_entries.append(
            {
                "classification": CLASSIFICATION_AUDIT,
                "document": "epc-evidence-audit",
                "collection": "source_completeness.exhaustive_coverage_proven",
                "status": "NOT_EXHAUSTIVE",
                "declared_count": None,
                "published_count": None,
                "omitted_count": None,
                "source_references": ["source_completeness"],
            }
        )
    if not completeness["audit_ledger_metadata_valid"]:
        completeness_entries.append(
            {
                "classification": CLASSIFICATION_AUDIT,
                "document": "epc-evidence-audit",
                "collection": "audit_ledger_count",
                "status": "INVALID_METADATA",
                "declared_count": completeness["audit_record_count_declared"],
                "published_count": completeness["audit_records_supplied"],
                "omitted_count": completeness["audit_records_omitted"],
                "source_references": ["audit_record_count"],
            }
        )
    elif (completeness["audit_records_omitted"] or 0) > 0:
        completeness_entries.append(
            {
                "classification": CLASSIFICATION_AUDIT,
                "document": "epc-evidence-audit",
                "collection": "audit_records",
                "status": "TRUNCATED",
                "declared_count": completeness["audit_record_count_declared"],
                "published_count": completeness["audit_records_supplied"],
                "omitted_count": completeness["audit_records_omitted"],
                "source_references": ["audit_records"],
            }
        )
    if review_omitted:
        completeness_entries.append(
            {
                "classification": CLASSIFICATION_UNRESOLVED,
                "document": "epc-evidence-review",
                "collection": "review_display",
                "status": "DISPLAY_TRUNCATED",
                "declared_count": len(audit_records),
                "published_count": review_published,
                "omitted_count": review_omitted,
                "source_references": ["evidence_audit_findings"],
            }
        )
    sections["source_completeness_limitations"] = completeness_entries[:MAX_FINDINGS]
    sections["missing_cross_artifact_references"] = [
        {
            "classification": CLASSIFICATION_UNRESOLVED,
            "capture": item.get("capture"),
            "kind": item.get("kind"),
            "reference": item.get("reference"),
            "context": item.get("context"),
            "source_references": [item.get("reference")],
            "limitation": item.get("limitation"),
        }
        for item in index["missing_references"]
    ]
    findings = []
    for record in audit_records[:MAX_FINDINGS]:
        record = _dict(record)
        findings.append(
            {
                "classification": CLASSIFICATION_AUDIT,
                "capture": safe_capture(record.get("capture_file")),
                "audit_record_reference": record.get("audit_record_reference"),
                "audit_category": record.get("audit_category"),
                "audit_status": record.get("audit_status"),
                "proof_sufficiency_status": record.get("proof_sufficiency_status"),
                "source_subject_reference": record.get("source_subject_reference"),
                "target_subject_reference": record.get("target_subject_reference"),
                "source_references": [
                    value
                    for value in (
                        record.get("source_subject_reference"),
                        record.get("target_subject_reference"),
                    )
                    if isinstance(value, str)
                ],
            }
        )
    sections["evidence_audit_findings"] = findings
    not_established = []
    for observation in observations[:MAX_OBSERVATIONS]:
        if observation.get("temporal_placement_status") != "ESTABLISHED":
            not_established.append(
                {
                    "classification": CLASSIFICATION_UNSUPPORTED,
                    "capture": safe_capture(observation.get("capture_file")),
                    "subject": observation.get("temporal_observation_reference"),
                    "status": observation.get("temporal_placement_status"),
                    "source_references": [observation.get("temporal_observation_reference")],
                }
            )
    for record in audit_records[:MAX_FINDINGS]:
        if _dict(record).get("audit_status") in (
            "INCONSISTENT",
            "AMBIGUOUS",
            "SOURCE_TRUNCATED",
            "NOT_INDEPENDENTLY_VERIFIABLE",
        ):
            not_established.append(
                {
                    "classification": CLASSIFICATION_UNRESOLVED,
                    "capture": safe_capture(_dict(record).get("capture_file")),
                    "subject": _dict(record).get("audit_record_reference"),
                    "status": _dict(record).get("audit_status"),
                    "source_references": [
                        value
                        for value in (
                            _dict(record).get("source_subject_reference"),
                            _dict(record).get("target_subject_reference"),
                        )
                        if isinstance(value, str)
                    ],
                }
            )
    sections["not_established_or_not_verifiable"] = not_established[:MAX_FINDINGS]
    additional = []
    for value in _list(audit.get("additional_evidence_needed")):
        safe = _text(value)
        if safe:
            additional.append(
                {
                    "classification": CLASSIFICATION_UNSUPPORTED,
                    "need": safe,
                    "source_references": ["epc-evidence-audit"],
                }
            )
    sections["additional_evidence_needed"] = additional[:MAX_REFERENCES]

    audit_summary = _dict(audit.get("audit_summary"))
    coverage = {
        "capture_count": len(index["captures"]),
        "session_context_count": len(contexts),
        "release_narrative_count": len(releases),
        "bearer_generation_count": len(generations),
        "s1u_stream_count": len(streams),
        "temporal_observation_count": len(observations),
        "audit_record_count": len(audit_records),
        "dedicated_source_supplied": dedicated_document is not None,
        "dedicated_status": dedicated_summary.get("status"),
        "dedicated_control_transaction_count": len(dedicated_transactions),
        "dedicated_bearer_item_count": len(dedicated_items),
        "dedicated_item_association_count": len(dedicated_associations),
        "published": {
            "session_contexts": min(len(contexts), MAX_CONTEXTS),
            "release_narratives": min(len(releases), MAX_RELEASES),
            "bearer_generations": min(len(generations), MAX_GENERATIONS),
            "s1u_streams": min(len(streams), MAX_STREAMS),
            "temporal_observations": min(len(observations), MAX_OBSERVATIONS),
            "audit_findings": min(len(audit_records), MAX_FINDINGS),
            "dedicated_control_transactions": min(
                len(dedicated_transactions), MAX_DEDICATED_TRANSACTIONS
            ),
            "dedicated_bearer_items": min(len(dedicated_items), MAX_DEDICATED_ITEMS),
            "dedicated_item_associations": min(
                len(dedicated_associations), MAX_DEDICATED_ASSOCIATIONS
            ),
        },
        "omitted": {
            "session_contexts": max(0, len(contexts) - MAX_CONTEXTS),
            "release_narratives": max(0, len(releases) - MAX_RELEASES),
            "bearer_generations": max(0, len(generations) - MAX_GENERATIONS),
            "s1u_streams": max(0, len(streams) - MAX_STREAMS),
            "temporal_observations": max(0, len(observations) - MAX_OBSERVATIONS),
            "audit_findings": max(0, len(audit_records) - MAX_FINDINGS),
            "dedicated_control_transactions": max(
                0, len(dedicated_transactions) - MAX_DEDICATED_TRANSACTIONS
            ),
            "dedicated_bearer_items": max(
                0, len(dedicated_items) - MAX_DEDICATED_ITEMS
            ),
            "dedicated_item_associations": max(
                0, len(dedicated_associations) - MAX_DEDICATED_ASSOCIATIONS
            ),
        },
        "source_completeness_status": completeness["source_completeness_status"],
        "exhaustive_coverage_proven": completeness["exhaustive_coverage_proven"],
        "source_collections_complete": completeness["source_collections_complete"],
        "audit_ledger_metadata_valid": completeness["audit_ledger_metadata_valid"],
        "audit_ledger_complete": completeness["audit_ledger_complete"],
        "audit_record_count_declared": completeness["audit_record_count_declared"],
        "audit_records_supplied": completeness["audit_records_supplied"],
        "audit_records_omitted": completeness["audit_records_omitted"],
        "review_audit_records_published": review_published,
        "review_audit_records_omitted": review_omitted,
        "review_display_complete": review_omitted == 0,
        "audit_results_truncated": completeness["audit_results_truncated"],
        "detailed_gtpv2_supplied": audit.get("source_artifact_count") is not None
        and any(
            _dict(source).get("artifact") == "gtpv2-c-events"
            for source in _list(audit.get("source_artifacts"))
        ),
        "detailed_gtpu_supplied": any(
            _dict(source).get("artifact") == "gtp-u-events"
            for source in _list(audit.get("source_artifacts"))
        ),
        "overall_audit_status": audit_summary.get("overall_status"),
        "inconsistent_count": audit_summary.get("inconsistent_count"),
        "ambiguous_count": audit_summary.get("ambiguous_count"),
        "source_truncated_count": audit_summary.get("source_truncated_count"),
        "not_independently_verifiable_count": audit_summary.get(
            "not_independently_verifiable_count"
        ),
        "verified_count": audit_summary.get("verified_count"),
        "temporal_integrity_summary": audit.get("temporal_integrity_summary"),
        "accounting_integrity_summary": audit.get("accounting_integrity_summary"),
    }
    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "review_name": REVIEW_NAME,
        "review_version": REVIEW_VERSION,
        "review_scope": {
            "mode": "DERIVED_FROM_ACCEPTED_ARTIFACTS",
            "capture_identities": index_capture_list(index),
            "bounded": True,
            "limits": index["bounded_limits"],
        },
        "coverage": coverage,
        "sections": sections,
        "section_counts": {name: len(value) for name, value in sections.items()},
        "not_confirmed": [
            "reference consistency is not packet delivery, UE reachability or application success",
            "an audit inconsistency is not a confirmed network failure or a root cause",
            "a proved bearer generation closure is not a forwarding-stop instant",
            "a replay-completed workflow is not a successful subscriber procedure",
        ],
        "non_goals": [
            "no protocol decoding or temporal attribution is reimplemented",
            "no ambiguous reference is resolved by selecting one candidate",
            "no producer accounting count is rewritten",
            "no root cause is inferred",
        ],
    }


def index_capture_list(index: dict[str, Any]) -> list[str]:
    return sorted(
        str(item.get("capture"))
        for item in _list(index.get("captures"))
        if isinstance(item.get("capture"), str)
    )


def _markdown_listing(lines: list[str], items: list[Any], formatter: Any) -> None:
    if not items:
        lines.append("- none published")
        return
    for item in items:
        lines.append(formatter(item))


def render_markdown(
    manifest: dict[str, Any],
    index: dict[str, Any],
    review: dict[str, Any],
) -> str:
    lines: list[str] = []
    lines.append("# EPC Evidence Review Pack")
    lines.append("")
    lines.append("## 1. Review Scope")
    lines.append("")
    lines.append(f"- mode: {manifest.get('mode')}")
    lines.append(f"- captures: {', '.join(_list(manifest.get('capture_identities'))) or 'none'}")
    lines.append(f"- source artifacts: {len(_list(manifest.get('source_artifacts')))}")
    lines.append(f"- local PCAP replayed: {manifest.get('local_pcap_replayed')}")
    lines.append(f"- source completeness: {_dict(review.get('coverage')).get('source_completeness_status')}")
    lines.append(
        f"- detailed GTPv2-C supplied: {manifest.get('detailed_gtpv2_supplied')}; "
        f"detailed GTP-U supplied: {manifest.get('detailed_gtpu_supplied')}"
    )
    lines.append("")
    lines.append("## 2. Source Artifact Inventory")
    lines.append("")
    for source in _list(manifest.get("source_artifacts")):
        lines.append(
            f"- {source.get('artifact_name')}: {source.get('analysis_name')} "
            f"{source.get('analysis_version')} supplied={source.get('supplied')} "
            f"completeness={source.get('completeness_status')} sha256={source.get('sha256')}"
        )
    lines.append("")
    lines.append("## 3. Evidence Coverage")
    lines.append("")
    coverage = _dict(review.get("coverage"))
    for key in (
        "capture_count",
        "session_context_count",
        "release_narrative_count",
        "bearer_generation_count",
        "s1u_stream_count",
        "temporal_observation_count",
        "audit_record_count",
    ):
        lines.append(f"- {key}: {coverage.get(key)}")
    lines.append(f"- omitted: {json.dumps(coverage.get('omitted'), sort_keys=True)}")
    lines.append(
        f"- source collections complete: {coverage.get('source_collections_complete')}; "
        f"exhaustive coverage proven: {coverage.get('exhaustive_coverage_proven')}"
    )
    lines.append(
        f"- audit ledger complete: {coverage.get('audit_ledger_complete')}; metadata valid: "
        f"{coverage.get('audit_ledger_metadata_valid')}"
    )
    lines.append(
        f"- audit records: supplied {coverage.get('audit_records_supplied')}, declared "
        f"{coverage.get('audit_record_count_declared')}, omitted "
        f"{coverage.get('audit_records_omitted')}"
    )
    lines.append(
        f"- review display: published {coverage.get('review_audit_records_published')}, "
        f"omitted {coverage.get('review_audit_records_omitted')}, complete "
        f"{coverage.get('review_display_complete')}"
    )
    lines.append(f"- overall audit status: {coverage.get('overall_audit_status')}")
    lines.append("")
    sections = _dict(review.get("sections"))

    def simple(section: str, label: str, fields: tuple[str, ...]) -> None:
        lines.append(f"## {label}")
        lines.append("")
        items = _list(sections.get(section))
        _markdown_listing(
            lines,
            items,
            lambda item: "- "
            + "; ".join(
                f"{field}={_dict(item).get(field)}" for field in fields
            )
            + f" [refs: {', '.join(_list(_dict(item).get('source_references'))) or 'none'}]",
        )
        lines.append("")

    simple(
        "capture_and_session_context_overview",
        "4. Capture and Session Context Overview",
        ("capture", "session_context_reference", "interface_class", "association_status"),
    )
    simple(
        "release_outcome_summary",
        "5. Release Outcome Summary",
        ("capture", "release_narrative_reference", "release_transaction_reference", "release_outcome_status"),
    )
    simple(
        "release_binding_summary",
        "6. Release Binding Summary",
        ("capture", "release_narrative_reference", "release_session_binding_status"),
    )
    simple(
        "bearer_generation_closure_summary",
        "7. Bearer Generation Closure Summary",
        ("capture", "generation_reference", "generation_state"),
    )
    simple(
        "s1u_observation_summary",
        "8. S1-U Observation Summary",
        ("capture", "stream_reference", "direction", "teid", "association_status"),
    )
    simple(
        "temporal_placement_summary",
        "9. Temporal Placement Summary",
        ("capture", "temporal_observation_reference", "temporal_placement_status", "partition_scope"),
    )
    lines.append("## 9A. Dedicated Bearer Control Evidence")
    lines.append("")
    dedicated_summaries = [
        _dict(item)
        for item in _list(sections.get("dedicated_bearer_control_summary"))
        if _dict(item).get("status") != "NOT_SUPPLIED"
    ]
    if not dedicated_summaries:
        lines.append("- no Dedicated Bearer Control source was supplied")
    for item in dedicated_summaries:
        lines.append(
            f"- status={item.get('status')}; source={item.get('source_artifact')}; "
            f"transactions={item.get('control_transaction_count')}; "
            f"bearer items={item.get('bearer_item_observation_count')}; "
            f"associations={item.get('item_association_count')}; "
            f"source completeness={item.get('source_completeness_status')}"
        )
        lines.append(
            f"  - family counts: {json.dumps(item.get('transaction_family_counts') or {}, sort_keys=True)}; "
            f"correlation: {json.dumps(item.get('correlation_status_counts') or {}, sort_keys=True)}"
        )
        lines.append(
            f"  - message outcomes: {json.dumps(item.get('message_outcome_counts') or {}, sort_keys=True)}; "
            f"transaction outcomes: {json.dumps(item.get('transaction_outcome_counts') or {}, sort_keys=True)}"
        )
        lines.append(
            f"  - item outcomes: {json.dumps(item.get('item_outcome_counts') or {}, sort_keys=True)}; "
            f"associations: {json.dumps(item.get('item_association_status_counts') or {}, sort_keys=True)}"
        )
        lines.append(
            f"  - omitted: {json.dumps(item.get('omitted_counts') or {}, sort_keys=True)}; "
            f"limitation={item.get('limitation')}"
        )
        for limitation in _list(item.get("evidence_limitations"))[:MAX_LIST_ITEMS]:
            lines.append(f"  - limitation: {limitation}")
        if item.get("status") != "NOT_SUPPLIED":
            lines.append(
                "  - observed GTPv2-C dedicated-bearer control outcomes do not prove "
                "end-to-end dedicated-bearer activation"
            )
    dedicated_transactions = _list(sections.get("dedicated_bearer_control_transactions"))
    if dedicated_transactions:
        lines.append("- bounded control transactions:")
        for item in dedicated_transactions[:MAX_LIST_ITEMS]:
            item = _dict(item)
            lines.append(
                f"  - {item.get('transaction_reference')} {item.get('procedure_family')} "
                f"{item.get('correlation_status')} message={item.get('message_outcome_status')} "
                f"transaction={item.get('transaction_outcome')}"
            )
    dedicated_associations = _list(sections.get("dedicated_bearer_control_associations"))
    if dedicated_associations:
        lines.append("- bounded item associations:")
        for item in dedicated_associations[:MAX_LIST_ITEMS]:
            item = _dict(item)
            lines.append(
                f"  - ebi={item.get('ebi')} status={item.get('status')} "
                f"request={item.get('request_item_reference')} "
                f"response={item.get('response_item_reference')}"
            )
    lines.append("")

    simple(
        "conflicting_or_ambiguous_ownership",
        "10. Conflicting or Ambiguous Ownership",
        ("capture", "temporal_observation_reference", "limitation"),
    )
    simple(
        "source_completeness_limitations",
        "11. Source Completeness Limitations",
        ("document", "collection", "status"),
    )
    simple(
        "missing_cross_artifact_references",
        "12. Missing Cross-Artifact References",
        ("capture", "kind", "reference", "context"),
    )
    simple(
        "evidence_audit_findings",
        "13. Evidence Audit Findings",
        ("capture", "audit_record_reference", "audit_category", "audit_status", "proof_sufficiency_status"),
    )

    lines.append("## 14. Evidence References for Manual Inspection")
    lines.append("")
    references = _dict(index.get("reference_counts"))
    for key in sorted(references):
        lines.append(f"- {key}: {references.get(key)}")
    lines.append(f"- missing references: {index.get('missing_reference_count')}")
    lines.append(f"- ambiguous references: {index.get('ambiguous_reference_count')}")
    lines.append(f"- cross-capture equal textual references: {index.get('cross_capture_reference_count')}")
    lines.append("")
    simple(
        "not_established_or_not_verifiable",
        "15. Not Established or Not Independently Verifiable",
        ("capture", "subject", "status"),
    )

    lines.append("## 16. Additional Evidence Needed")
    lines.append("")
    _markdown_listing(
        lines,
        _list(sections.get("additional_evidence_needed")),
        lambda item: f"- {_dict(item).get('need')}",
    )
    lines.append("")
    lines.append("## 17. Replay and Reproducibility Status")
    lines.append("")
    lines.append(f"- replay status: {manifest.get('replay_status')}")
    lines.append(f"- local PCAP replayed: {manifest.get('local_pcap_replayed')}")
    lines.append(
        f"- deterministic artifact hashes: {json.dumps(manifest.get('review_artifact_hashes'), sort_keys=True)}"
    )
    lines.append("")
    lines.append("## 18. Non-Goals and Safety Limitations")
    lines.append("")
    for item in _list(review.get("non_goals")):
        lines.append(f"- {item}")
    lines.append("")
    lines.append("### Not confirmed")
    lines.append("")
    for item in _list(review.get("not_confirmed")):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines) + "\n"


def build_replay_verification(
    *,
    mode: str,
    status: str,
    steps: list[dict[str, Any]] | None = None,
    capture_name: str | None = None,
    capture_sha256: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "mode": mode,
        "overall_status": status,
        "replayed": status == REPLAY_COMPLETED,
        "capture": capture_name,
        "capture_sha256": capture_sha256,
        "steps": steps or [],
    }


def _replay_paths(invocation_root: Path) -> tuple[Path, Path]:
    """Return non-overlapping sibling scratch and CLI-output directories."""
    return invocation_root / "scratch", invocation_root / "cli-output"


def _current_run_candidates(scratch_root: Path) -> list[Path]:
    runs = scratch_root / "epc" / "runs"
    if not runs.is_dir():
        return []
    return sorted(
        (path for path in runs.iterdir() if path.is_dir()),
        key=lambda path: path.name,
    )


def _select_current_run(candidates: list[Path]) -> Path | None:
    if len(candidates) != 1:
        return None
    return candidates[0]


def run_local_replay(
    capture: Path,
    *,
    work_dir: Path | None = None,
    timeout: int = 900,
) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any]]:
    capture_name = safe_capture(capture.name)
    steps: list[dict[str, Any]] = []
    if not capture.exists() or not capture.is_file():
        steps.append({"step": "capture_input", "status": "FAILED", "detail": "capture file not found"})
        return (
            build_replay_verification(
                mode="LOCAL_PCAP_REPLAY", status=REPLAY_FAILED, steps=steps
            ),
            None,
            {},
        )
    if capture.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
        steps.append({"step": "capture_input", "status": "FAILED", "detail": "unsupported capture format"})
        return (
            build_replay_verification(
                mode="LOCAL_PCAP_REPLAY", status=REPLAY_FAILED, steps=steps
            ),
            None,
            {},
        )
    capture_hash = sha256_file(capture)
    steps.append({"step": "capture_input", "status": "PASSED", "detail": safe_capture(capture.name)})

    if shutil.which("tshark") is None:
        steps.append({"step": "toolchain_check", "status": "FAILED", "detail": "tshark is not available"})
        return (
            build_replay_verification(
                mode="LOCAL_PCAP_REPLAY",
                status=REPLAY_FAILED,
                steps=steps,
                capture_name=capture_name,
                capture_sha256=capture_hash,
            ),
            None,
            {},
        )
    steps.append({"step": "toolchain_check", "status": "PASSED", "detail": "tshark available"})

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if work_dir is None:
        temporary = tempfile.TemporaryDirectory(prefix="epc-review-replay-")
        work_root = Path(temporary.name)
    else:
        work_root = work_dir
        work_root.mkdir(parents=True, exist_ok=True)
    invocation_root = work_root / f"epc-review-run-{uuid.uuid4().hex[:16]}"
    invocation_root.mkdir(parents=True, exist_ok=False)
    scratch, cli_output = _replay_paths(invocation_root)
    scratch.mkdir(parents=True, exist_ok=False)
    command = [
        sys.executable,
        str(UNIFIED_CLI),
        "--capture",
        str(capture),
        "--domains",
        "epc",
        "--work-dir",
        str(scratch),
        "--output-dir",
        str(cli_output),
        "--force",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        steps.append(
            {
                "step": "unified_pipeline",
                "status": "PASSED" if completed.returncode in (0, 3) else "FAILED",
                "detail": f"exit={completed.returncode}",
            }
        )
        if completed.returncode not in (0, 3):
            return (
                build_replay_verification(
                    mode="LOCAL_PCAP_REPLAY",
                    status=REPLAY_FAILED,
                    steps=steps,
                    capture_name=capture_name,
                    capture_sha256=capture_hash,
                ),
                None,
                {},
            )
        cli_status: str | None = None
        report_path = cli_output / "analysis.json"
        if report_path.is_file():
            try:
                report_payload = json.loads(report_path.read_text(encoding="utf-8"))
                if isinstance(report_payload, dict):
                    cli_status = report_payload.get("overall_execution_status")
            except (OSError, json.JSONDecodeError):
                cli_status = None
        steps.append(
            {
                "step": "unified_execution_status",
                "status": "PASSED" if isinstance(cli_status, str) else "NOT_AVAILABLE",
                "detail": cli_status,
            }
        )
        candidates = _current_run_candidates(scratch)
        run_dir = _select_current_run(candidates)
        if run_dir is None:
            steps.append(
                {
                    "step": "current_run_selection",
                    "status": "FAILED",
                    "detail": f"{len(candidates)} current-run directories; no unique current run",
                }
            )
            return (
                build_replay_verification(
                    mode="LOCAL_PCAP_REPLAY",
                    status=REPLAY_FAILED,
                    steps=steps,
                    capture_name=capture_name,
                    capture_sha256=capture_hash,
                ),
                None,
                {},
            )
        steps.append(
            {
                "step": "current_run_selection",
                "status": "PASSED",
                "detail": run_dir.name,
            }
        )
        required = {
            ARTIFACT_SESSION_IDENTITY: "epc-session-identity-analysis.json",
            ARTIFACT_BEARER_LIFECYCLE: "epc-bearer-lifecycle-analysis.json",
            ARTIFACT_RELEASE_NARRATIVE: "epc-release-narrative-analysis.json",
        }
        missing = [name for name in required.values() if not (run_dir / name).is_file()]
        steps.append(
            {
                "step": "artifact_publication",
                "status": "PASSED" if not missing else "FAILED",
                "detail": "all required artifacts published" if not missing else ", ".join(missing),
            }
        )
        if missing:
            return (
                build_replay_verification(
                    mode="LOCAL_PCAP_REPLAY",
                    status=REPLAY_FAILED,
                    steps=steps,
                    capture_name=capture_name,
                    capture_sha256=capture_hash,
                ),
                None,
                {},
            )

        gtpu_path = run_dir / "gtpu-events.jsonl"
        gtpv2_path = run_dir / "gtpv2-events.jsonl"
        gtpu_events = gtpu_path if gtpu_path.is_file() and gtpu_path.stat().st_size else None
        gtpv2_events = gtpv2_path if gtpv2_path.is_file() and gtpv2_path.stat().st_size else None
        try:
            artifacts = load_artifacts(
                run_dir,
                gtpv2_events=gtpv2_events,
                gtpu_events=gtpu_events,
            )
        except ReviewInputError as exc:
            steps.append({"step": "artifact_load", "status": "FAILED", "detail": exc.message})
            return (
                build_replay_verification(
                    mode="LOCAL_PCAP_REPLAY",
                    status=REPLAY_FAILED,
                    steps=steps,
                    capture_name=capture_name,
                    capture_sha256=capture_hash,
                ),
                None,
                {},
            )
        observed_captures = _capture_set(artifacts["documents"])
        expected_capture = safe_capture(capture.name)
        if not observed_captures or observed_captures != [expected_capture]:
            steps.append(
                {
                    "step": "capture_provenance",
                    "status": "FAILED",
                    "detail": f"expected {expected_capture}; observed {observed_captures}",
                }
            )
            return (
                build_replay_verification(
                    mode="LOCAL_PCAP_REPLAY",
                    status=REPLAY_FAILED,
                    steps=steps,
                    capture_name=capture_name,
                    capture_sha256=capture_hash,
                ),
                None,
                {},
            )
        steps.append(
            {
                "step": "capture_provenance",
                "status": "PASSED",
                "detail": expected_capture,
            }
        )
        steps.append(
            {
                "step": "capture_sha256",
                "status": "PASSED",
                "detail": capture_hash,
                "published_by_pipeline": False,
            }
        )
        audit = _dict(artifacts["documents"].get(ARTIFACT_AUDIT))
        steps.append(
            {
                "step": "evidence_audit",
                "status": "PASSED",
                "detail": str(_dict(audit.get("audit_summary")).get("overall_status")),
            }
        )
        if completed.returncode == 3 or cli_status == "PARTIAL":
            status = REPLAY_PARTIAL
        elif completed.returncode == 0 and cli_status == "COMPLETED":
            status = REPLAY_COMPLETED
        else:
            status = REPLAY_PARTIAL
        steps.append(
            {
                "step": "review_pack",
                "status": "PASSED",
                "detail": status,
            }
        )
        return (
            build_replay_verification(
                mode="LOCAL_PCAP_REPLAY",
                status=status,
                steps=steps,
                capture_name=capture_name,
                capture_sha256=capture_hash,
            ),
            artifacts,
            {"capture_sha256": capture_hash, "run_dir": run_dir.name},
        )
    except subprocess.TimeoutExpired:
        steps.append({"step": "unified_pipeline", "status": "FAILED", "detail": "pipeline timed out"})
        return (
            build_replay_verification(
                mode="LOCAL_PCAP_REPLAY",
                status=REPLAY_FAILED,
                steps=steps,
                capture_name=capture_name,
                capture_sha256=capture_hash,
            ),
            None,
            {},
        )
    finally:
        if temporary is not None:
            temporary.cleanup()


def _read_comparison_input(directory: Path) -> dict[str, Any]:
    required = ("manifest.json", "evidence-index.json", "evidence-review.json")
    missing = [name for name in required if not (directory / name).is_file()]
    if missing:
        raise ReviewInputError("MISSING_COMPARISON_INPUT", ", ".join(missing))
    manifest = read_json(directory / "manifest.json")
    index = read_json(directory / "evidence-index.json")
    review = read_json(directory / "evidence-review.json")
    replay_path = directory / "replay-verification.json"
    replay = read_json(replay_path) if replay_path.is_file() else {}
    return {"manifest": manifest, "index": index, "review": review, "replay": replay}


def compare_runs(run_a: Path, run_b: Path) -> dict[str, Any]:
    try:
        first = _read_comparison_input(run_a)
    except ReviewInputError as exc:
        return {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "mode": "COMPARISON",
            "overall_status": COMPARE_MISSING,
            "differences": [f"first run: {exc.message}"],
        }
    try:
        second = _read_comparison_input(run_b)
    except ReviewInputError as exc:
        return {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "mode": "COMPARISON",
            "overall_status": COMPARE_MISSING,
            "differences": [f"second run: {exc.message}"],
        }

    schema_a = first["manifest"].get("schema_version")
    schema_b = second["manifest"].get("schema_version")
    if not isinstance(schema_a, str) or not isinstance(schema_b, str):
        return {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "mode": "COMPARISON",
            "overall_status": COMPARE_UNSUPPORTED,
            "schema_versions": [schema_a, schema_b],
            "differences": ["a review manifest does not publish a string schema version"],
        }
    if not isinstance(first["index"].get("captures"), list) or not isinstance(
        second["index"].get("captures"), list
    ):
        return {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "mode": "COMPARISON",
            "overall_status": COMPARE_UNSUPPORTED,
            "differences": ["a review evidence index does not publish a capture list"],
        }
    if not isinstance(first["review"].get("sections"), dict) or not isinstance(
        second["review"].get("sections"), dict
    ):
        return {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "mode": "COMPARISON",
            "overall_status": COMPARE_UNSUPPORTED,
            "differences": ["a review document does not publish sections"],
        }
    if schema_a != schema_b:
        return {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "mode": "COMPARISON",
            "overall_status": COMPARE_SCHEMA,
            "schema_versions": [schema_a, schema_b],
            "differences": ["review manifest schema versions differ"],
        }
    if schema_a.split(".", 1)[0] != "1":
        return {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "mode": "COMPARISON",
            "overall_status": COMPARE_UNSUPPORTED,
            "schema_versions": [schema_a, schema_b],
            "differences": ["review manifest schema version is not supported"],
        }
    captures_a = sorted(_list(first["manifest"].get("capture_identities")))
    captures_b = sorted(_list(second["manifest"].get("capture_identities")))
    if captures_a != captures_b:
        return {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "mode": "COMPARISON",
            "overall_status": COMPARE_CAPTURE,
            "captures": [captures_a, captures_b],
            "differences": ["capture identities differ"],
        }
    capture_a = _dict(first["replay"]).get("capture_sha256")
    capture_b = _dict(second["replay"]).get("capture_sha256")
    if (
        capture_a != capture_b
        and (isinstance(capture_a, str) or isinstance(capture_b, str))
    ):
        return {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "mode": "COMPARISON",
            "overall_status": COMPARE_CAPTURE,
            "captures": [capture_a, capture_b],
            "differences": ["replayed capture hashes differ"],
        }

    differences: list[str] = []
    if json.dumps(first["index"], sort_keys=True) != json.dumps(second["index"], sort_keys=True):
        differences.append("evidence-index.json differs")
    if json.dumps(first["review"], sort_keys=True) != json.dumps(second["review"], sort_keys=True):
        differences.append("evidence-review.json differs")
    for key in (
        "mode",
        "capture_identities",
        "detailed_gtpv2_supplied",
        "detailed_gtpu_supplied",
        "local_pcap_replayed",
        "source_collections_complete",
        "audit_results_truncated",
    ):
        if first["manifest"].get(key) != second["manifest"].get(key):
            differences.append(f"manifest.{key} differs")
    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "mode": "COMPARISON",
        "overall_status": COMPARE_DIFFERENT if differences else COMPARE_IDENTICAL,
        "differences": differences,
        "provenance_note": "source artifact hashes are provenance and reordered equivalent inputs keep identical evidence",
    }


def _check_output_path(output_dir: Path, artifacts_dir: Path | None) -> Path:
    output = output_dir.resolve()
    if artifacts_dir is not None:
        source = artifacts_dir.resolve()
        if output == source or source in output.parents:
            raise ReviewInputError(
                "UNSAFE_OUTPUT_PATH",
                "output directory must not be the source directory or inside it",
            )
    if output_dir.is_symlink():
        raise ReviewInputError("UNSAFE_OUTPUT_PATH", "output directory must not be a symlink")
    if output.exists() and not output.is_dir():
        raise ReviewInputError("UNSAFE_OUTPUT_PATH", "output path exists and is not a directory")
    return output


def write_pack(
    output_dir: Path,
    files: dict[str, str],
    *,
    artifacts_dir: Path | None = None,
    force: bool = False,
) -> None:
    output = _check_output_path(output_dir, artifacts_dir)
    if output.exists():
        if not force and any((output / name).exists() for name in files):
            raise ReviewInputError(
                "OUTPUT_EXISTS", "review pack outputs already exist; use --force to replace them"
            )
    else:
        output.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        target = output / name
        if target.exists() and not force:
            raise ReviewInputError("OUTPUT_EXISTS", f"output already exists: {name}")
        temporary = output / f".{name}.tmp"
        temporary.write_text(content, encoding="utf-8", newline="\n")
        os.replace(temporary, target)


def build_review_pack(
    artifacts: dict[str, Any],
    *,
    mode: str,
    replay_verification: dict[str, Any],
) -> dict[str, str]:
    index = build_index(artifacts["documents"])
    review = build_review(artifacts["documents"], index)
    replay_status = replay_verification.get("overall_status", REPLAY_NOT_EXECUTED)
    preliminary_manifest = build_manifest(
        artifacts,
        mode=mode,
        local_pcap_replayed=replay_status == REPLAY_COMPLETED,
        replay_status=replay_status,
    )
    markdown = render_markdown(preliminary_manifest, index, review)
    hashes = {
        "evidence-index.json": hashlib.sha256(
            (json.dumps(index, indent=2, sort_keys=True) + "\n").encode("utf-8")
        ).hexdigest(),
        "evidence-review.json": hashlib.sha256(
            (json.dumps(review, indent=2, sort_keys=True) + "\n").encode("utf-8")
        ).hexdigest(),
        "evidence-review.md": hashlib.sha256(markdown.encode("utf-8")).hexdigest(),
        "replay-verification.json": hashlib.sha256(
            (json.dumps(replay_verification, indent=2, sort_keys=True) + "\n").encode("utf-8")
        ).hexdigest(),
    }
    manifest = build_manifest(
        artifacts,
        mode=mode,
        local_pcap_replayed=replay_status == REPLAY_COMPLETED,
        replay_status=replay_status,
        review_artifact_hashes=hashes,
    )
    return {
        "manifest.json": json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        "evidence-review.json": json.dumps(review, indent=2, sort_keys=True) + "\n",
        "evidence-review.md": markdown,
        "evidence-index.json": json.dumps(index, indent=2, sort_keys=True) + "\n",
        "replay-verification.json": json.dumps(replay_verification, indent=2, sort_keys=True) + "\n",
    }


def existing_artifact_pack(
    artifacts_dir: Path,
    *,
    gtpv2_events: Path | None = None,
    gtpu_events: Path | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    artifacts = load_artifacts(
        artifacts_dir,
        gtpv2_events=gtpv2_events,
        gtpu_events=gtpu_events,
    )
    replay = build_replay_verification(
        mode="EXISTING_ARTIFACTS",
        status=REPLAY_NOT_EXECUTED,
    )
    return artifacts, build_review_pack(
        artifacts,
        mode="EXISTING_ARTIFACTS",
        replay_verification=replay,
    )