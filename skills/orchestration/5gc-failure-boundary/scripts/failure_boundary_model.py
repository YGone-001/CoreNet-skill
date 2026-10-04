#!/usr/bin/env python3
"""Standalone engine for 5GC failure-boundary orchestration.

Consumes already-produced Domain analysis JSON only:
- 5gc-registration-mobility analysis summaries (>=0.2.0)
- 5gc-pdu-session analysis summaries (>=0.4.0)

Produces:
- a bounded 5gc-failure-boundary analysis summary (JSON) that forms evidence-safe
  diagnostic groups across related Domain instances and identifies the earliest
  safely orderable abnormal evidence boundary per group.

Strictly bounded: candidates come only from deviations already emitted by a
Domain Skill, with machine-readable evidence_refs as the sole provenance
contract. Human-readable description and limitation text are
presentation only and is never parsed for identity or ordering. Ordering relies
on evidence provenance (exact frames, bounded observation windows, source
stage order), never severity; no root cause, network-function blame, vendor
defect, or implementation cause is ever produced.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ANALYSIS_NAME = "5gc-failure-boundary"
ANALYSIS_VERSION = "0.1.0"

EXIT_MALFORMED_INPUT = 5
EXIT_NO_INPUT = 6
EXIT_OUTPUT_FAILURE = 7

SUPPORTED_DOMAINS = ("5gc-registration-mobility", "5gc-pdu-session")

# Minimum source Domain output contracts exposing structured deviation
# provenance. Older versions fail loudly; there is no prose-parsing fallback.
REGISTRATION_VERSION_FLOOR = (0, 2, 0)
PDU_SESSION_VERSION_FLOOR = (0, 4, 0)

# Deviation types that may become abnormal-boundary candidates (Domain-emitted
# vocabulary, mapped exactly; never renamed).
ELIGIBLE_DEVIATION_TYPES = frozenset({
    "PROTOCOL_REJECT_OBSERVED",
    "UNSUCCESSFUL_OUTCOME_OBSERVED",
    "PROTOCOL_NEGATIVE_OUTCOME_OBSERVED",
    "RESOURCE_FAILED_ITEM_OBSERVED",
    "DELIVERY_FAILURE_NOTIFICATION_OBSERVED",
    "MISSING_EXPECTED_COUNTERPART",
    "FIELD_CONFLICT",
})

# Deviation types that describe evidence quality or association limitations.
EVIDENCE_LIMITATION_TYPES = frozenset({
    "PARTIAL_CAPTURE",
    "CORRELATION_AMBIGUITY",
    "CORRELATION_CONFLICT",
    "LIFECYCLE_AMBIGUITY",
    "PROTECTED_OR_UNAVAILABLE_PAYLOAD",
    "PROTECTED_INNER_MESSAGE_UNAVAILABLE",
    "OUT_OF_ORDER_EVIDENCE",
    "DUPLICATE_OR_RETRANSMITTED_EVIDENCE",
})

SUPPORTING_ANOMALY_TYPES = frozenset({
    "UNKNOWN_OR_RESERVED_PROTOCOL_VALUE",
})

SELECTION_SELECTED = "SELECTED"
SELECTION_NO_ABNORMAL = "NO_ABNORMAL_BOUNDARY_OBSERVED"
SELECTION_AMBIGUOUS = "AMBIGUOUS_FIRST_BOUNDARY"
SELECTION_INSUFFICIENT = "INSUFFICIENT_COMPARABLE_EVIDENCE"

RELATION_OBSERVED_AFTER_BOUNDARY = "OBSERVED_AFTER_BOUNDARY"
RELATION_OBSERVED_BEFORE_BOUNDARY = "OBSERVED_BEFORE_BOUNDARY"

NOT_CONFIRMED_STATEMENTS = (
    "implementation cause not assessed",
    "network-function blame not established",
    "vendor defect not established",
    "end-to-end root cause not established",
)

FORBIDDEN_OUTPUT_PATTERN = re.compile(
    r"(?i)\b(?:root[ _-]?cause|culprit|responsible[ _-]?nf|vendor[ _-]?fault|"
    r"implementation[ _-]?(?:failure|bug|blame)|bug[ _-]?location)\b"
)

ANALYSIS_OUTPUT_LIMITATIONS = (
    "Analysis is bounded to the Domain analysis JSON supplied as input; no raw protocol events are interpreted",
    "Boundary candidates come only from deviations already emitted by the source Domain Skills",
    "First means the earliest safely orderable abnormal evidence boundary, never the most serious abnormality",
    "Boundary confidence expresses confidence in the boundary selection and ordering, never causal confidence",
    "No implementation-specific source code or network function internal state is inferred",
)


class InputError(ValueError):
    """Raised when Domain analysis input or configuration is invalid."""


def sanitize_output(document: Any) -> Any:
    """Ensure no forbidden causal or verdict wording is present in the document.

    The fixed not-confirmed disclaimer statements are allowed verbatim; any
    other occurrence of forbidden wording fails the analysis loudly.
    """
    text = json.dumps(document, sort_keys=True)
    cleaned = text
    for disclaimer in NOT_CONFIRMED_STATEMENTS:
        cleaned = cleaned.replace(disclaimer, "")
    match = FORBIDDEN_OUTPUT_PATTERN.search(cleaned)
    if match:
        raise InputError(f"analysis output contains forbidden verdict wording: {match.group(0)}")
    return document


def _load_json(path: Path) -> Any:
    if not path.is_file():
        raise InputError(f"file does not exist: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in {path.name}: {exc.msg}") from exc


def _require_mapping(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{what} must be a JSON object")
    return value


def _require_list(value: Any, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise InputError(f"{what} must be a JSON array")
    return value


def _parse_version(value: Any, what: str) -> tuple[int, int, int] | None:
    if not isinstance(value, str):
        return None
    parts = value.split(".")
    if len(parts) != 3:
        return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None


def _enforce_version(actual: Any, floor: tuple[int, int, int], domain: str, file_name: str) -> None:
    version = _parse_version(actual, "version")
    if version is None:
        raise InputError(
            f"{file_name}: source Domain version field is missing or malformed; "
            f"{domain} >= {'.'.join(str(n) for n in floor)} with structured deviation "
            "provenance is required by 5gc-failure-boundary"
        )
    if version < floor:
        raise InputError(
            f"{file_name}: {domain} procedure_version {actual} lacks the structured deviation "
            f"provenance required by 5gc-failure-boundary {ANALYSIS_VERSION}; "
            f"{'.'.join(str(n) for n in floor)} or newer is required"
        )


def _deviation_evidence_refs(deviation: dict[str, Any], what: str) -> list[dict[str, Any]]:
    refs = deviation.get("evidence_refs")
    if not isinstance(refs, list):
        raise InputError(f"{what}: deviation {deviation.get('type')} lacks structured evidence_refs")
    for ref in refs:
        if not isinstance(ref, dict) or ref.get("kind") not in ("EVENT", "FIELD_FINDING", "OBSERVATION_WINDOW", "STAGE"):
            raise InputError(f"{what}: deviation {deviation.get('type')} carries a malformed evidence ref")
    return refs


def _event_ref_frame(refs: list[dict[str, Any]]) -> tuple[int, str | None, str | None, str | None] | None:
    """The structured EVENT reference with frame provenance, if present."""
    for ref in refs:
        if ref.get("kind") == "EVENT" and isinstance(ref.get("frame_number"), int):
            return (
                ref["frame_number"],
                ref.get("timestamp") if isinstance(ref.get("timestamp"), str) else None,
                ref.get("protocol") if isinstance(ref.get("protocol"), str) else None,
                ref.get("message_type") if isinstance(ref.get("message_type"), str) else None,
            )
    return None


def _window_ref_bounds(refs: list[dict[str, Any]]) -> tuple[int, int] | None:
    for ref in refs:
        if ref.get("kind") == "OBSERVATION_WINDOW" and isinstance(ref.get("window_first_frame"), int):
            lo = ref["window_first_frame"]
            hi = ref.get("window_last_frame")
            hi = hi if isinstance(hi, int) else lo
            return (lo, hi)
    return None


def _association_equivalent(a: Any, b: Any) -> bool:
    """Compare SCTP association identifiers across the two Domain contracts.

    5gc-registration-mobility emits "sctp-assoc-<id>" strings while
    5gc-pdu-session emits the numeric association id. Equality of the numeric
    forms is an exact common-context comparison, never a heuristic.
    """
    if a is None or b is None:
        return False
    if a == b:
        return True

    def numeric(value: Any) -> int | None:
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if isinstance(value, str):
            match = re.match(r"sctp-assoc-(\d+)$", value)
            if match:
                return int(match.group(1))
        return None

    na, nb = numeric(a), numeric(b)
    return na is not None and nb is not None and na == nb


def _window_of(lo: Any, hi: Any) -> tuple[int, int] | None:
    if isinstance(lo, int) and not isinstance(lo, bool) and isinstance(hi, int) and not isinstance(hi, bool):
        return (lo, hi)
    return None


class SourceInstance:
    """One procedure instance from one Domain analysis output."""

    def __init__(
        self,
        source_domain: str,
        source_file: str,
        instance_id: str,
        capture_file: str | None,
        sctp_association: Any,
        ran_ue_ngap_id: Any,
        amf_ue_ngap_id: Any,
        observation_window: tuple[int, int] | None,
        terminal: dict[str, Any],
        deviations: list[dict[str, Any]],
        extra_identity: dict[str, Any],
    ) -> None:
        self.source_domain = source_domain
        self.source_file = source_file
        self.instance_id = instance_id
        self.capture_file = capture_file
        self.sctp_association = sctp_association
        self.ran_ue_ngap_id = ran_ue_ngap_id
        self.amf_ue_ngap_id = amf_ue_ngap_id
        self.observation_window = observation_window
        self.terminal = terminal
        self.deviations = deviations
        self.extra_identity = extra_identity
        self.stage_order: dict[str, int] = {}
        self.attempt_entries: list[dict[str, Any]] = []
        self.identity_hash = hashlib.sha256(
            json.dumps({
                "source_domain": source_domain,
                "instance_id": instance_id,
                "capture_file": capture_file,
                "terminal": terminal,
                "deviations": deviations,
                "extra_identity": extra_identity,
            }, sort_keys=True).encode("utf-8")
        ).hexdigest()

    def context_key(self) -> tuple[Any, Any, Any, Any] | None:
        """Exact cross-domain subject key: capture + SCTP association + both
        NGAP UE identifiers, all present and equal. A missing component never
        links (single numeric UE identifiers never join)."""
        if not self.capture_file or self.sctp_association is None:
            return None
        if self.ran_ue_ngap_id is None or self.amf_ue_ngap_id is None:
            return None
        return (self.capture_file, self.sctp_association, self.ran_ue_ngap_id, self.amf_ue_ngap_id)

    def reference(self) -> dict[str, Any]:
        ref = {
            "source_domain": self.source_domain,
            "source_instance_id": self.instance_id,
            "source_file": self.source_file,
            "capture_file": self.capture_file,
        }
        ref.update(self.extra_identity)
        return ref


def _registration_instances(path: Path) -> list[SourceInstance]:
    doc = _require_mapping(_load_json(path), f"{path.name}")
    if doc.get("procedure_family") != "5gc-registration-mobility":
        raise InputError(f"{path.name} is not a 5gc-registration-mobility analysis summary")
    _enforce_version(doc.get("analysis_version"), REGISTRATION_VERSION_FLOOR,
                     "5gc-registration-mobility", path.name)
    instances: list[SourceInstance] = []
    for index, analysis in enumerate(_require_list(doc.get("analyses"), f"{path.name} analyses")):
        analysis = _require_mapping(analysis, f"{path.name} analyses[{index}]")
        instance_id = analysis.get("instance_id")
        if not isinstance(instance_id, str):
            raise InputError(f"{path.name} analyses[{index}] lacks instance_id")
        context = _require_mapping(analysis.get("context"), f"{path.name} analyses[{index}] context")
        capture_file = context.get("capture_file")
        association = context.get("association")
        ngap_context = _require_mapping(context.get("ngap_context"), f"{path.name} analyses[{index}] ngap_context")
        window_obj = _require_mapping(analysis.get("observation_window"), f"{path.name} analyses[{index}] observation_window")
        window = _window_of(window_obj.get("first_frame"), window_obj.get("last_frame"))
        terminal = _require_mapping(analysis.get("terminal"), f"{path.name} analyses[{index}] terminal")

        stage_order = {
            record.get("stage", {}).get("stage_id"): position
            for position, record in enumerate(analysis.get("stage_records", []) or [])
            if isinstance(record, dict) and isinstance(record.get("stage"), dict) and isinstance(record["stage"].get("stage_id"), str)
        }
        record = SourceInstance(
            source_domain="5gc-registration-mobility",
            source_file=path.name,
            instance_id=instance_id,
            capture_file=capture_file if isinstance(capture_file, str) else None,
            sctp_association=association,
            ran_ue_ngap_id=ngap_context.get("ran_ue_ngap_id"),
            amf_ue_ngap_id=ngap_context.get("amf_ue_ngap_id"),
            observation_window=window,
            terminal=terminal,
            deviations=_require_list(analysis.get("deviations"), f"{path.name} analyses[{index}] deviations"),
            extra_identity={},
        )
        record.stage_order = stage_order
        instances.append(record)
    return instances


def _pdu_session_instances(path: Path) -> list[SourceInstance]:
    doc = _require_mapping(_load_json(path), f"{path.name}")
    if doc.get("procedure_name") != "5gc-pdu-session":
        raise InputError(f"{path.name} is not a 5gc-pdu-session analysis summary")
    _enforce_version(doc.get("procedure_version"), PDU_SESSION_VERSION_FLOOR,
                     "5gc-pdu-session", path.name)
    instances: list[SourceInstance] = []
    for index, instance in enumerate(_require_list(doc.get("instances"), f"{path.name} instances")):
        instance = _require_mapping(instance, f"{path.name} instances[{index}]")
        instance_id = instance.get("instance_id")
        if not isinstance(instance_id, str):
            raise InputError(f"{path.name} instances[{index}] lacks instance_id")
        ue_context = _require_mapping(instance.get("ue_context"), f"{path.name} instances[{index}] ue_context")
        terminal = _require_mapping(instance.get("terminal_observation"), f"{path.name} instances[{index}] terminal_observation")
        capture_file = instance.get("capture_file")
        if not isinstance(capture_file, str):
            raise InputError(
                f"{path.name} instances[{index}] lacks the structured capture_file required by "
                "5gc-failure-boundary; capture provenance is never recovered from instance_id strings"
            )
        window_obj = instance.get("observation_window")
        window = None
        if isinstance(window_obj, dict):
            window = _window_of(window_obj.get("first_frame"), window_obj.get("last_frame"))

        extra = {
            "pdu_session_id": instance.get("pdu_session_id"),
            "session_generation": instance.get("session_generation"),
            "reuse_status": instance.get("reuse_status"),
            "lifecycle_boundary_basis": instance.get("lifecycle_boundary_basis"),
            "previous_generation": instance.get("previous_generation"),
        }
        record = SourceInstance(
            source_domain="5gc-pdu-session",
            source_file=path.name,
            instance_id=instance_id,
            capture_file=capture_file,
            sctp_association=ue_context.get("sctp_association"),
            ran_ue_ngap_id=ue_context.get("ran_ue_ngap_id"),
            amf_ue_ngap_id=ue_context.get("amf_ue_ngap_id"),
            observation_window=window,
            terminal=terminal,
            deviations=_require_list(instance.get("deviations"), f"{path.name} instances[{index}] deviations"),
            extra_identity={k: v for k, v in extra.items() if v is not None},
        )
        record.stage_order = {
            stage.get("stage_id"): position
            for position, stage in enumerate(instance.get("stages", []) or [])
            if isinstance(stage, dict) and isinstance(stage.get("stage_id"), str)
        }
        attempt_entries: list[dict[str, Any]] = []
        for attempt_kind in ("modification_attempts", "release_attempts"):
            for attempt in instance.get(attempt_kind, []) or []:
                if not isinstance(attempt, dict):
                    continue
                attempt_id = attempt.get("attempt_id")
                obs = attempt.get("observation_window")
                win = _window_of(obs.get("window_start_frame"), obs.get("window_end_frame")) if isinstance(obs, dict) else None
                attempt_partial = any(
                    isinstance(d, dict) and d.get("type") == "PARTIAL_CAPTURE"
                    for d in attempt.get("deviations", []) or []
                )
                stage_order = {
                    stage.get("stage_id"): position
                    for position, stage in enumerate(attempt.get("stages", []) or [])
                    if isinstance(stage, dict) and isinstance(stage.get("stage_id"), str)
                }
                for deviation in attempt.get("deviations", []) or []:
                    attempt_entries.append({
                        "deviation": deviation,
                        "attempt_id": attempt_id,
                        "window": win,
                        "attempt_partial": attempt_partial,
                        "stage_order": stage_order,
                    })
        record.attempt_entries = attempt_entries
        instances.append(record)
    return instances


def load_domain_instances(paths: list[tuple[str, Path]]) -> list[SourceInstance]:
    """Load and deduplicate Domain analysis inputs.

    Identical input content (for example the same file supplied twice) is
    processed once so duplicate candidates never appear.
    """
    instances: list[SourceInstance] = []
    seen_hashes: set[tuple[str, str]] = set()
    for domain, path in paths:
        if domain == "5gc-registration-mobility":
            loaded = _registration_instances(path)
        elif domain == "5gc-pdu-session":
            loaded = _pdu_session_instances(path)
        else:
            raise InputError(f"unsupported Domain input kind: {domain}")
        for instance in loaded:
            dedup_key = (domain, instance.identity_hash)
            if dedup_key in seen_hashes:
                continue
            seen_hashes.add(dedup_key)
            instances.append(instance)
    return instances


def _link_instances(instances: list[SourceInstance]) -> list[list[SourceInstance]]:
    """Form diagnostic groups by exact common context.

    Two source instances link only when capture_file, SCTP association
    (contract-equivalent), RAN-UE-NGAP-ID, and AMF-UE-NGAP-ID are all present
    and equal. Timestamp proximity, same numeric PDU Session ID, or similar
    procedure sequences never link.
    """
    n = len(instances)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri

    keys = [inst.context_key() for inst in instances]
    for i in range(n):
        for j in range(i + 1, n):
            ki, kj = keys[i], keys[j]
            if ki is None or kj is None:
                continue
            if ki[0] != kj[0]:
                continue
            if not _association_equivalent(ki[1], kj[1]):
                continue
            if ki[2] != kj[2] or ki[3] != kj[3]:
                continue
            union(i, j)

    groups: dict[int, list[SourceInstance]] = {}
    for i, inst in enumerate(instances):
        groups.setdefault(find(i), []).append(inst)
    for group in groups.values():
        group.sort(key=lambda inst: (inst.source_domain, inst.instance_id))
    return sorted(
        groups.values(),
        key=lambda group: tuple((inst.source_domain, inst.instance_id) for inst in group),
    )


class Candidate:
    """One selectable abnormal-boundary candidate from a Domain deviation."""

    def __init__(
        self,
        source: SourceInstance,
        deviation: dict[str, Any],
        refs: list[dict[str, Any]],
        origin_attempt_id: str | None,
        frame_number: int | None,
        timestamp: str | None,
        protocol: str | None,
        message_type: str | None,
        window: tuple[int, int] | None,
        stage_position: int | None,
        blocked: bool,
    ) -> None:
        self.source = source
        self.deviation = deviation
        self.refs = refs
        self.origin_attempt_id = origin_attempt_id
        self.frame_number = frame_number
        self.timestamp = timestamp
        self.protocol = protocol
        self.message_type = message_type
        self.window = window
        self.stage_position = stage_position
        self.blocked = blocked
        self.sort_key = (
            source.source_domain,
            source.instance_id,
            origin_attempt_id or "",
            deviation.get("type", ""),
            deviation.get("description") or "",
        )

    @property
    def evidence_level(self) -> str:
        return str(self.deviation.get("evidence_level") or "DERIVED")

    def to_json(self, candidate_id: str) -> dict[str, Any]:
        return {
            "candidate_id": candidate_id,
            "source_domain": self.source.source_domain,
            "source_instance_id": self.source.instance_id,
            "source_attempt_id": self.origin_attempt_id,
            "procedure_family": self.source.source_domain,
            "procedure_stage": self.deviation.get("stage_id"),
            "deviation_type": self.deviation.get("type"),
            "description": self.deviation.get("description"),
            "evidence_level": self.evidence_level,
            "boundary_anchor": {
                "capture_file": self.source.capture_file,
                "frame_number": self.frame_number,
                "timestamp": self.timestamp,
                "protocol": self.protocol,
                "message_type": self.message_type,
            },
            "supporting_evidence": {
                "evidence_refs": self.refs,
                "source_deviation": self.deviation,
                "source_observation_window": (
                    {"first_frame": self.source.observation_window[0], "last_frame": self.source.observation_window[1]}
                    if self.source.observation_window else None
                ),
                "source_terminal": self.source.terminal,
            },
            "ordering_basis": {
                "frame_number": self.frame_number,
                "observation_window": (
                    {"start_frame": self.window[0], "end_frame": self.window[1]} if self.window else None
                ),
                "stage_position": self.stage_position,
            },
            "selectability": "BLOCKED_BY_PARTIAL_CAPTURE" if self.blocked else "SELECTABLE",
            "limitations": [self.deviation.get("limitation")] if self.deviation.get("limitation") else [],
        }


def _candidate_provenance(refs: list[dict[str, Any]], what: str, deviation_type: str) -> tuple[int | None, str | None, str | None, str | None, tuple[int, int] | None]:
    """Extract ordering provenance from structured evidence refs only.

    An OBSERVED deviation must carry an EVENT ref with frame provenance; a
    DERIVED deviation may carry an OBSERVATION_WINDOW ref. Prose is never
    consulted; a boundary-eligible deviation without either anchor fails
    loudly rather than falling back to heuristics.
    """
    event = _event_ref_frame(refs)
    window = _window_ref_bounds(refs)
    if event is not None:
        frame, timestamp, protocol, message_type = event
        return frame, timestamp, protocol, message_type, window
    if window is not None:
        return None, None, None, None, window
    raise InputError(
        f"{what}: boundary-eligible deviation {deviation_type} carries no structured EVENT frame or "
        "OBSERVATION_WINDOW provenance; the source Domain contract is insufficient for safe ordering"
    )


def _candidates_for_instance(source: SourceInstance) -> tuple[list[Candidate], list[dict[str, Any]], list[dict[str, Any]]]:
    candidates: list[Candidate] = []
    limitations: list[dict[str, Any]] = []
    supporting: list[dict[str, Any]] = []

    instance_partial = any(
        isinstance(d, dict) and d.get("type") == "PARTIAL_CAPTURE" for d in source.deviations
    )

    def add(deviation: dict[str, Any], origin_attempt_id: str | None,
            window: tuple[int, int] | None, stage_position: int | None,
            stage_order: dict[str, int], blocked_by_partial: bool) -> None:
        dtype = deviation.get("type")
        entry = {
            "source_domain": source.source_domain,
            "source_instance_id": source.instance_id,
            "source_attempt_id": origin_attempt_id,
            "type": dtype,
            "stage_id": deviation.get("stage_id"),
            "description": deviation.get("description"),
            "evidence_level": deviation.get("evidence_level"),
        }
        if dtype in EVIDENCE_LIMITATION_TYPES:
            entry["_refs"] = deviation.get("evidence_refs", []) if isinstance(deviation.get("evidence_refs"), list) else []
            limitations.append(entry)
            return
        if dtype in SUPPORTING_ANOMALY_TYPES:
            entry["_refs"] = deviation.get("evidence_refs", []) if isinstance(deviation.get("evidence_refs"), list) else []
            supporting.append(entry)
            return
        if dtype not in ELIGIBLE_DEVIATION_TYPES:
            entry["_refs"] = deviation.get("evidence_refs", []) if isinstance(deviation.get("evidence_refs"), list) else []
            limitations.append(entry)
            return
        what = f"{source.source_file} {source.instance_id}"
        refs = _deviation_evidence_refs(deviation, what)
        frame_number, timestamp, protocol, message_type, ref_window = _candidate_provenance(refs, what, str(dtype))
        if window is None:
            window = ref_window
        if window is None:
            window = source.observation_window
        stage_id = deviation.get("stage_id")
        if stage_position is None and isinstance(stage_id, str):
            stage_position = stage_order.get(stage_id)
        blocked = dtype == "MISSING_EXPECTED_COUNTERPART" and blocked_by_partial
        candidates.append(Candidate(
            source=source,
            deviation=deviation,
            refs=refs,
            origin_attempt_id=origin_attempt_id,
            frame_number=frame_number,
            timestamp=timestamp,
            protocol=protocol,
            message_type=message_type,
            window=window,
            stage_position=stage_position,
            blocked=blocked,
        ))

    for deviation in source.deviations:
        add(deviation, None, None, None, source.stage_order, instance_partial)

    for entry in source.attempt_entries:
        blocked_by_partial = instance_partial or bool(entry.get("attempt_partial"))
        add(entry["deviation"], entry.get("attempt_id"), entry.get("window"), None,
            entry.get("stage_order") or {}, blocked_by_partial)

    return candidates, limitations, supporting


def _relation(a: Candidate, b: Candidate) -> str:
    """Ordering relation between two candidates within one diagnostic group.

    Returns "before", "after", "tie", or "none" (no safe ordering basis).
    Ordering relies on evidence provenance only; severity is never consulted.
    Same-frame observed candidates tie (no deterministic source relationship
    invents an order at one instant).
    """
    if a.source.capture_file != b.source.capture_file:
        return "none"
    a_framed = a.frame_number is not None
    b_framed = b.frame_number is not None
    if a_framed and b_framed:
        if a.frame_number < b.frame_number:
            return "before"
        if a.frame_number > b.frame_number:
            return "after"
        return "tie"
    if a_framed and not b_framed and b.window is not None:
        return _frame_vs_window(a, b, a.frame_number, b.window)
    if b_framed and not a_framed and a.window is not None:
        return _invert(_frame_vs_window(b, a, b.frame_number, a.window))
    if a.window is not None and b.window is not None:
        a_lo, a_hi = a.window
        b_lo, b_hi = b.window
        if a_hi < b_lo:
            return "before"
        if b_hi < a_lo:
            return "after"
        return _stage_order_tiebreak(a, b)
    return _stage_order_tiebreak(a, b)


def _frame_vs_window(framed: Candidate, windowed: Candidate, frame: int, window: tuple[int, int]) -> str:
    """Relation from the framed candidate's perspective against a windowed one.

    An observed frame inside the absence window cannot be temporally ordered
    against the absence claim; the source Domain stage order decides only when
    both candidates share the same source scope with distinct known stages.
    """
    lo, hi = window
    if frame < lo:
        return "before"
    if frame > hi:
        return "after"
    stage_rel = _stage_order_tiebreak(framed, windowed)
    if stage_rel != "tie":
        return stage_rel
    return "tie"


def _stage_order_tiebreak(a: Candidate, b: Candidate) -> str:
    """Source Domain stage order decides only within one source scope.

    The stage order is an explicit part of the Domain output contract
    (stage_records / stages arrays); it is never a severity or preference.
    """
    if (
        a.stage_position is not None
        and b.stage_position is not None
        and a.source.instance_id == b.source.instance_id
        and a.origin_attempt_id == b.origin_attempt_id
    ):
        if a.stage_position < b.stage_position:
            return "before"
        if a.stage_position > b.stage_position:
            return "after"
    return "tie"


def _invert(rel: str) -> str:
    return {"before": "after", "after": "before"}.get(rel, rel)


def _confidence_of(selected: Candidate, used_window_ordering: bool) -> str:
    """Boundary-selection confidence, explicitly not causal confidence."""
    if selected.evidence_level == "OBSERVED" and selected.frame_number is not None:
        return "HIGH"
    if selected.evidence_level == "DERIVED" and selected.window is not None:
        return "MEDIUM"
    if used_window_ordering:
        return "MEDIUM"
    return "LOW"


def _select_earliest(relations: dict[tuple[int, int], str], count: int) -> tuple[str, list[int]]:
    """Candidate-centric earliest-boundary selection over pairwise relations.

    Returns (selection_status, earliest_candidate_indexes). A candidate is the
    unique earliest when it is proven before every other selectable candidate;
    the relative ordering among later candidates is irrelevant. Ties at the
    earliest position are AMBIGUOUS; mutual incomparability among every
    earliest candidate is INSUFFICIENT_COMPARABLE_EVIDENCE.
    """
    earliest_set = [
        index for index in range(count)
        if not any(_perspective_rel(relations, index, other) == "after"
                   for other in range(count) if other != index)
    ]
    if len(earliest_set) == 1:
        return SELECTION_SELECTED, earliest_set
    if not earliest_set:
        return SELECTION_INSUFFICIENT, earliest_set
    for i in range(len(earliest_set)):
        for j in range(i + 1, len(earliest_set)):
            if _perspective_rel(relations, earliest_set[i], earliest_set[j]) == "tie":
                return SELECTION_AMBIGUOUS, earliest_set
    return SELECTION_INSUFFICIENT, earliest_set


def analyze_group(group: list[SourceInstance], group_index: int) -> dict[str, Any]:
    """Evaluate one diagnostic group and select its first abnormal boundary."""
    all_candidates: list[Candidate] = []
    limitations: list[dict[str, Any]] = []
    supporting: list[dict[str, Any]] = []
    for source in group:
        cands, lims, sups = _candidates_for_instance(source)
        all_candidates.extend(cands)
        limitations.extend(lims)
        supporting.extend(sups)

    all_candidates.sort(key=lambda c: c.sort_key)
    # Collapse duplicate candidates that describe the same concrete boundary:
    # same source instance, same deviation type, same exact observed frame.
    # Distinct derived absence claims are never collapsed.
    deduped: list[Candidate] = []
    seen_concrete: set[tuple[str, str, int]] = set()
    for candidate in all_candidates:
        if candidate.frame_number is not None and candidate.evidence_level == "OBSERVED":
            key = (candidate.source.instance_id, str(candidate.deviation.get("type")), candidate.frame_number)
            if key in seen_concrete:
                continue
            seen_concrete.add(key)
        deduped.append(candidate)
    all_candidates = deduped
    candidate_ids: dict[str, str] = {}
    for position, candidate in enumerate(all_candidates, start=1):
        candidate_ids[id(candidate)] = f"{group_index}-cand-{position}"
    candidate_json = [c.to_json(candidate_ids[id(c)]) for c in all_candidates]

    selectable = [c for c in all_candidates if not c.blocked]
    blocked = [c for c in all_candidates if c.blocked]

    selection_status: str
    selected: dict[str, Any] | None = None
    confidence: str | None = None
    additional: list[dict[str, str]] = []
    downstream: list[dict[str, Any]] = []
    earlier: list[dict[str, Any]] = []

    if not selectable:
        if blocked:
            selection_status = SELECTION_INSUFFICIENT
            for candidate in blocked:
                additional.append({
                    "reason": "MISSING_EXPECTED_COUNTERPART candidate is not orderable because the source Domain marks the observation window as partial",
                    "requirement": "a capture covering the expected response is required",
                    "candidate_id": candidate_ids[id(candidate)],
                })
        else:
            selection_status = SELECTION_NO_ABNORMAL
    else:
        # Candidate-centric earliest test: C is selected when C is proven
        # before every other selectable candidate. The relative ordering among
        # later candidates is irrelevant; ties at the earliest position are
        # ambiguous; incomparability involving every earliest candidate is
        # insufficient comparable evidence.
        relations: dict[tuple[int, int], str] = {}
        used_window_ordering = False
        for i in range(len(selectable)):
            for j in range(i + 1, len(selectable)):
                rel = _relation(selectable[i], selectable[j])
                if selectable[i].frame_number is None or selectable[j].frame_number is None:
                    used_window_ordering = True
                relations[(i, j)] = rel

        selection_status, earliest_set = _select_earliest(relations, len(selectable))
        if selection_status == SELECTION_AMBIGUOUS:
            for index in earliest_set:
                for other in earliest_set:
                    if index >= other:
                        continue
                    if _perspective_rel(relations, index, other) == "tie":
                        additional.append({
                            "reason": "candidates resolve to the same position with no deterministic source relationship ordering them",
                            "requirement": "exact frame or stage provenance that separates the tied candidates is required",
                            "candidate_id": candidate_ids[id(selectable[index])],
                            "second_candidate_id": candidate_ids[id(selectable[other])],
                        })
        elif selection_status == SELECTION_INSUFFICIENT:
            for index in earliest_set:
                for other in range(len(selectable)):
                    if other == index:
                        continue
                    rel = _perspective_rel(relations, index, other)
                    if rel == "none":
                        additional.append({
                            "reason": "no safe ordering basis exists between these candidates",
                            "requirement": "exact frame provenance or a bounded source observation window is required for both candidates",
                            "candidate_id": candidate_ids[id(selectable[index])],
                            "second_candidate_id": candidate_ids[id(selectable[other])],
                        })
        if len(earliest_set) == 1:
            selection_status = SELECTION_SELECTED
            selected_candidate = selectable[earliest_set[0]]
            confidence = _confidence_of(selected_candidate, used_window_ordering)
            selected = {"candidate_id": candidate_ids[id(selected_candidate)]}
            selected_ref = next(c for c in candidate_json if c["candidate_id"] == candidate_ids[id(selected_candidate)])
            boundary_frame = selected_ref["boundary_anchor"]["frame_number"]
            for candidate in selectable:
                if candidate is selected_candidate:
                    continue
                rel = _relation(selected_candidate, candidate)
                if rel == "before":
                    target, relation = downstream, RELATION_OBSERVED_AFTER_BOUNDARY
                elif rel == "after":
                    target, relation = earlier, RELATION_OBSERVED_BEFORE_BOUNDARY
                else:
                    continue
                target.append({
                    "relation": relation,
                    "candidate_id": candidate_ids[id(candidate)],
                    "source_domain": candidate.source.source_domain,
                    "source_instance_id": candidate.source.instance_id,
                    "deviation_type": candidate.deviation.get("type"),
                    "description": candidate.deviation.get("description"),
                    "evidence_level": candidate.evidence_level,
                })
            if boundary_frame is not None:
                for source in group:
                    terminal = source.terminal
                    terminal_frame = terminal.get("frame_number")
                    if not isinstance(terminal_frame, int) or terminal.get("evidence_level") != "OBSERVED":
                        continue
                    if terminal_frame == boundary_frame:
                        continue
                    entry = {
                        "relation": RELATION_OBSERVED_BEFORE_BOUNDARY if terminal_frame < boundary_frame else RELATION_OBSERVED_AFTER_BOUNDARY,
                        "source_domain": source.source_domain,
                        "source_instance_id": source.instance_id,
                        "kind": "terminal_observation",
                        "observation": terminal.get("observation"),
                        "message_type": terminal.get("message_type"),
                        "frame_number": terminal_frame,
                    }
                    (earlier if terminal_frame < boundary_frame else downstream).append(entry)
                for entry in limitations + supporting:
                    entry_refs = entry.get("_refs") or []
                    window_bounds = _window_ref_bounds(entry_refs)
                    entry_frame = None
                    event = _event_ref_frame(entry_refs)
                    if event is not None:
                        entry_frame = event[0]
                    elif window_bounds is not None:
                        entry_frame = window_bounds[0]
                    if entry_frame is not None:
                        target = downstream if entry_frame > boundary_frame else earlier
                        target.append({
                            "relation": RELATION_OBSERVED_AFTER_BOUNDARY if entry_frame > boundary_frame else RELATION_OBSERVED_BEFORE_BOUNDARY,
                            "source_domain": entry.get("source_domain"),
                            "source_instance_id": entry.get("source_instance_id"),
                            "kind": "evidence_limitation" if entry in limitations else "supporting_anomaly",
                            "deviation_type": entry.get("type"),
                            "description": entry.get("description"),
                        })
            if selected_ref["evidence_level"] == "DERIVED":
                additional.append({
                    "reason": "selected boundary is derived missing evidence bounded by the source observation window",
                    "requirement": "a capture covering the expected counterpart would strengthen the boundary selection",
                    "candidate_id": candidate_ids[id(selected_candidate)],
                })

    capture_files = sorted({s.capture_file for s in group if s.capture_file})
    if len(group) == 1:
        subject_link = {
            "strength": "UNBOUND",
            "basis": "no_cross_domain_link_single_source",
            "source_contexts": [_context_of(s) for s in group],
        }
    else:
        subject_link = {
            "strength": "STRONG",
            "basis": "capture_sctp_association_and_ngap_ue_context_exact_match",
            "source_contexts": [_context_of(s) for s in group],
        }

    selected_boundary: dict[str, Any] | None = None
    if selection_status == SELECTION_SELECTED and selected is not None:
        selected_boundary = {
            "candidate_id": selected["candidate_id"],
            "boundary_ref": next(c for c in candidate_json if c["candidate_id"] == selected["candidate_id"]),
        }

    # Private provenance keys are presentation-internal and stay in the group
    # output only for these context entries; consumers read evidence_refs.
    group_id = f"diag-{group_index}"
    return {
        "diagnostic_id": group_id,
        "subject_link": subject_link,
        "source_domain_instances": [s.reference() for s in group],
        "observation_scope": {
            "capture_files": capture_files,
            "source_count": len(group),
        },
        "candidate_boundaries": candidate_json,
        "selection_status": selection_status,
        "selected_boundary": selected_boundary,
        "boundary_confidence": confidence,
        "earlier_context": earlier,
        "downstream_observations": downstream,
        "evidence_limitations": limitations,
        "additional_evidence_needed": additional,
        "supporting_anomalies": supporting,
        "not_confirmed": list(NOT_CONFIRMED_STATEMENTS),
        "limitations": [
            "No severity ranking is applied: first means earliest safely orderable boundary",
            "Downstream observations are not caused by the selected boundary",
            "NO_ABNORMAL_BOUNDARY_OBSERVED never means network or procedure success",
        ],
    }


def _perspective_rel(relations: dict[tuple[int, int], str], i: int, j: int) -> str:
    rel = relations.get((min(i, j), max(i, j)), "tie")
    if i > j:
        rel = _invert(rel)
    return rel


def _context_of(source: SourceInstance) -> dict[str, Any]:
    return {
        "source_domain": source.source_domain,
        "source_instance_id": source.instance_id,
        "capture_file": source.capture_file,
        "sctp_association": source.sctp_association,
        "ran_ue_ngap_id": source.ran_ue_ngap_id,
        "amf_ue_ngap_id": source.amf_ue_ngap_id,
    }


def analyze(
    registration_paths: list[Path],
    pdu_session_paths: list[Path],
) -> dict[str, Any]:
    """Run bounded failure-boundary orchestration over Domain analysis JSON."""
    paths: list[tuple[str, Path]] = []
    for path in registration_paths:
        paths.append(("5gc-registration-mobility", path))
    for path in pdu_session_paths:
        paths.append(("5gc-pdu-session", path))
    if not paths:
        raise InputError("no Domain analysis input supplied")

    instances = load_domain_instances(paths)
    groups = _link_instances(instances)

    diagnostic_groups = []
    unbound: list[dict[str, Any]] = []
    for index, group in enumerate(groups, start=1):
        group_doc = analyze_group(group, index)
        diagnostic_groups.append(group_doc)
        if group_doc["subject_link"]["strength"] == "UNBOUND":
            for source in group:
                unbound.append({
                    "source_domain": source.source_domain,
                    "source_instance_id": source.instance_id,
                    "source_file": source.source_file,
                    "reason": "no evidence-safe cross-domain subject link exists for this analysis",
                })

    summary = {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "diagnostic_groups": diagnostic_groups,
        "unbound_domain_analyses": unbound,
        "limitations": list(ANALYSIS_OUTPUT_LIMITATIONS),
    }
    return sanitize_output(summary)
