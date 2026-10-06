#!/usr/bin/env python3
"""Standalone engine for bounded 5GC handover/path-switch Domain analysis.

The engine consumes already-extracted structured evidence — NGAP detailed
events (ngap >=0.3.0 Skill), PFCP detailed events (pfcp Skill), GTP-U
detailed events (gtpu Skill), SBI-HTTP2 detailed events (sbi-http2 Skill),
and an optional 5gc-pdu-session analysis summary — and produces a bounded
analysis summary with two separate attempt families:

- handover_attempts[]  — N2 handover procedure evidence (Handover
  Preparation, Handover Resource Allocation, Handover Notification,
  Handover Cancel);
- path_switch_attempts[] — Path Switch procedure evidence.

A Path Switch attempt stays independent unless a safe, documented
relationship to a handover attempt exists. Neither family is mandatory for
the other: a Path Switch without N2 handover evidence is a valid independent
attempt (it may for example belong to an Xn handover whose Xn signaling this
Skill does not own), and a HandoverNotify without Path Switch evidence is
never a missing Path Switch.

The engine never decodes protocols, never decodes NGAP opaque mobility
transfer bytes, never derives N3 tunnel identity from NGAP, never merges
source and target associations by timestamp or identifier equality alone,
never treats AMF-UE-NGAP-ID as a global identity, and never emits success,
failure, root-cause, vendor, or implementation verdicts. Missing evidence
stays missing evidence under the observation boundary; all boundary-eligible
deviations carry machine-readable evidence_refs for Analysis Orchestration.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

EXIT_MALFORMED_INPUT = 5
EXIT_NO_EVENTS = 6
EXIT_OUTPUT_FAILURE = 7

ANALYSIS_NAME = "5gc-handover-mobility"
ANALYSIS_VERSION = "0.1.0"
PROCEDURE_FAMILY = "5gc-handover-mobility"

FORBIDDEN_OUTPUT_PATTERN = re.compile(
    r"(?i)\b(?:root[ _-]?cause|culprit|responsible[ _-]?nf|radio[ _-]?fault|"
    r"implementation[ _-]?(?:failure|bug|blame)|upf[ _-]?relocation[ _-]?(?:success|complete))\b"
)

# Deviation vocabulary (bounded, neutral, compatible with the current
# Domain -> Orchestration contract).
DEVIATION_NEGATIVE_OUTCOME = "PROTOCOL_NEGATIVE_OUTCOME_OBSERVED"
DEVIATION_RESOURCE_FAILED = "RESOURCE_FAILED_ITEM_OBSERVED"
DEVIATION_MISSING_COUNTERPART = "MISSING_EXPECTED_COUNTERPART"
DEVIATION_FIELD_CONFLICT = "FIELD_CONFLICT"
DEVIATION_PARTIAL_CAPTURE = "PARTIAL_CAPTURE"
DEVIATION_CORRELATION_AMBIGUITY = "CORRELATION_AMBIGUITY"
DEVIATION_CORRELATION_CONFLICT = "CORRELATION_CONFLICT"
DEVIATION_LIFECYCLE_AMBIGUITY = "LIFECYCLE_AMBIGUITY"
DEVIATION_OUT_OF_ORDER = "OUT_OF_ORDER_EVIDENCE"
DEVIATION_DUPLICATE = "DUPLICATE_OR_RETRANSMITTED_EVIDENCE"
DEVIATION_UNKNOWN_VALUE = "UNKNOWN_OR_RESERVED_PROTOCOL_VALUE"

# NGAP mobility message identities (owned by ngap >=0.3.0; never re-decoded).
HANDOVER_REQUIRED = "HandoverRequired"
HANDOVER_COMMAND = "HandoverCommand"
HANDOVER_PREPARATION_FAILURE = "HandoverPreparationFailure"
HANDOVER_REQUEST = "HandoverRequest"
HANDOVER_REQUEST_ACK = "HandoverRequestAcknowledge"
HANDOVER_FAILURE = "HandoverFailure"
HANDOVER_NOTIFY = "HandoverNotify"
HANDOVER_CANCEL = "HandoverCancel"
HANDOVER_CANCEL_ACK = "HandoverCancelAcknowledge"
PATH_SWITCH_REQUEST = "PathSwitchRequest"
PATH_SWITCH_ACK = "PathSwitchRequestAcknowledge"
PATH_SWITCH_FAILURE = "PathSwitchRequestFailure"

HANDOVER_SOURCE_MESSAGES = {
    HANDOVER_REQUIRED, HANDOVER_COMMAND, HANDOVER_PREPARATION_FAILURE,
    HANDOVER_CANCEL, HANDOVER_CANCEL_ACK,
}
HANDOVER_TARGET_MESSAGES = {
    HANDOVER_REQUEST, HANDOVER_REQUEST_ACK, HANDOVER_FAILURE, HANDOVER_NOTIFY,
}
HANDOVER_MESSAGES = HANDOVER_SOURCE_MESSAGES | HANDOVER_TARGET_MESSAGES
PATH_SWITCH_MESSAGES = {PATH_SWITCH_REQUEST, PATH_SWITCH_ACK, PATH_SWITCH_FAILURE}
MOBILITY_MESSAGES = HANDOVER_MESSAGES | PATH_SWITCH_MESSAGES

# Branch-aware mandatory counterparts (TS 38.413 elementary procedures; the
# reviewed basis carries no message-level Cause for PathSwitchRequestFailure
# and no mandatory counterpart for progress evidence such as HandoverNotify).
MANDATORY_COUNTERPARTS = {
    HANDOVER_REQUIRED: {HANDOVER_COMMAND, HANDOVER_PREPARATION_FAILURE},
    HANDOVER_REQUEST: {HANDOVER_REQUEST_ACK, HANDOVER_FAILURE},
    HANDOVER_CANCEL: {HANDOVER_CANCEL_ACK},
    PATH_SWITCH_REQUEST: {PATH_SWITCH_ACK, PATH_SWITCH_FAILURE},
}

# Terminal observation vocabulary (never HANDOVER_SUCCESS / PATH_SWITCH_SUCCESS).
TERMINAL_BY_MESSAGE = {
    HANDOVER_PREPARATION_FAILURE: "HANDOVER_PREPARATION_FAILURE_OBSERVED",
    HANDOVER_FAILURE: "HANDOVER_RESOURCE_FAILURE_OBSERVED",
    HANDOVER_COMMAND: "HANDOVER_COMMAND_OBSERVED",
    HANDOVER_NOTIFY: "HANDOVER_NOTIFY_OBSERVED",
    HANDOVER_CANCEL: "HANDOVER_CANCEL_OBSERVED",
    HANDOVER_CANCEL_ACK: "HANDOVER_CANCEL_ACK_OBSERVED",
    PATH_SWITCH_ACK: "PATH_SWITCH_ACK_OBSERVED",
    PATH_SWITCH_FAILURE: "PATH_SWITCH_FAILURE_OBSERVED",
}
TERMINAL_NONE = "NO_TERMINAL_MOBILITY_OBSERVATION"
TERMINAL_PARTIAL = "PARTIAL_CAPTURE"

# HandoverType domain scope (reviewed ngap mapping: 0 intra5gs; 1..3 inter-system).
HANDOVER_TYPE_INTRA = "INTRA_5GS"
HANDOVER_TYPE_INTER_SYSTEM = "INTER_SYSTEM_OR_OTHER"
SCOPE_SUPPORTED = "SUPPORTED_FOR_DOMAIN_PROCEDURE"
SCOPE_UNSUPPORTED = "UNSUPPORTED_HANDOVER_TYPE_FOR_DOMAIN_PROCEDURE"

# Stage vocabulary. Stages are conditional: a stage only appears when its
# trigger evidence exists, and no universal total ordering is implied.
STAGE_HANDOVER_INITIATION = "HANDOVER_INITIATION"
STAGE_PREPARATION_OUTCOME = "HANDOVER_PREPARATION_OUTCOME"
STAGE_TARGET_ALLOCATION = "TARGET_RESOURCE_ALLOCATION"
STAGE_EXECUTION_NOTIFICATION = "HANDOVER_EXECUTION_NOTIFICATION"
STAGE_CANCELLATION = "HANDOVER_CANCELLATION"
STAGE_PATH_SWITCH_REQUEST = "PATH_SWITCH_REQUEST"
STAGE_PATH_SWITCH_OUTCOME = "PATH_SWITCH_OUTCOME"
STAGE_SESSION_CONTROL_UPDATE = "SESSION_CONTROL_UPDATE"
STAGE_CONTROL_PLANE_UPDATE = "CONTROL_PLANE_UPDATE"
STAGE_USER_PLANE_CONTROL_UPDATE = "USER_PLANE_CONTROL_UPDATE"
STAGE_USER_PLANE_OBSERVATION = "USER_PLANE_OBSERVATION"

# Supporting-plane message identities (owned by the pfcp / gtpu / sbi-http2
# Skills; consumed as bounded supporting evidence only).
PFCP_MODIFICATION_MESSAGES = {
    "PFCP Session Modification Request", "PFCP Session Modification Response",
}
GTPU_GPDU = "G-PDU"
GTPU_END_MARKER = "End Marker"
GTPU_ERROR_INDICATION = "Error Indication"
SBI_SERVICE_NSMF = "Nsmf_PDUSession"
SBI_OPERATION_UPDATE_SM_CONTEXT = "UpdateSMContext"

# PFCP cause: codes >= 64 are the reviewed TS 29.244 rejection range
# (1 = Request accepted; 64+ = request rejected (rejection cause values)).
PFCP_CAUSE_ACCEPTED_MAX = 1

# Association strengths (documented in references/source-target-association.md).
STRENGTH_STRONG = "STRONG"
STRENGTH_SUPPORTED = "SUPPORTED"
STRENGTH_AMBIGUOUS = "AMBIGUOUS"
STRENGTH_UNBOUND = "UNBOUND"

# Neutral tunnel labels: a mobility path role (old/new path) requires safely
# established tunnel lifecycle context, which v0.1.0 does not establish.
TUNNEL_LABELS = ("TUNNEL_A", "TUNNEL_B", "TUNNEL_C", "TUNNEL_D")

LIMIT_NOT_ROOT_CAUSE = (
    "A procedure-local deviation is protocol evidence; it never attributes "
    "blame to any network element, implementation, or radio layer"
)


class InputError(ValueError):
    """Raised when lower-layer evidence cannot be accepted."""


def _evidence_ref(
    kind: str,
    evidence_level: str,
    capture_file: str | None = None,
    frame_number: int | None = None,
    timestamp: str | None = None,
    protocol: str | None = None,
    message_type: str | None = None,
    stage_id: str | None = None,
    field_name: str | None = None,
    window_first_frame: int | None = None,
    window_last_frame: int | None = None,
) -> dict[str, object]:
    """One machine-readable evidence reference (Analysis Orchestration contract)."""
    return {
        "kind": kind,
        "evidence_level": evidence_level,
        "capture_file": capture_file,
        "frame_number": frame_number,
        "timestamp": timestamp,
        "protocol": protocol,
        "message_type": message_type,
        "stage_id": stage_id,
        "field_name": field_name,
        "window_first_frame": window_first_frame,
        "window_last_frame": window_last_frame,
    }


def _event_ref(event: dict[str, object], stage_id: str | None = None,
               field_name: str | None = None) -> dict[str, object]:
    return _evidence_ref(
        "EVENT", "OBSERVED",
        capture_file=_safe_str(event.get("capture_file")),
        frame_number=event["frame_number"] if isinstance(event.get("frame_number"), int) else None,
        timestamp=_safe_str(event.get("timestamp")),
        protocol=_safe_str(event.get("protocol")),
        message_type=_safe_str(event.get("message_type")),
        stage_id=stage_id,
        field_name=field_name,
    )


def _window_ref(capture_file: str | None, first_frame: int | None, last_frame: int | None,
                stage_id: str | None = None) -> dict[str, object]:
    return _evidence_ref(
        "OBSERVATION_WINDOW", "DERIVED",
        capture_file=capture_file,
        stage_id=stage_id,
        window_first_frame=first_frame,
        window_last_frame=last_frame,
    )


def _safe_str(value: object) -> str | None:
    return str(value) if value is not None else None


def _association_of(event: dict[str, object]) -> str:
    sctp = event.get("sctp")
    if isinstance(sctp, dict) and sctp.get("association_id") is not None:
        return f"sctp-assoc-{sctp['association_id']}"
    parts = []
    for role in ("source", "destination"):
        endpoint = event.get(role)
        if isinstance(endpoint, dict):
            parts.append(f"{endpoint.get('address')}:{endpoint.get('port')}")
    if parts:
        return "endpoint-pair-" + "<->".join(sorted(parts))
    return "no-association"


def _amf_endpoint_of(event: dict[str, object]) -> str | None:
    """The observed AMF-side endpoint address of an NGAP mobility event.

    HandoverRequired/Cancel are sent toward the AMF (destination endpoint);
    HandoverRequest is sent from the AMF (source endpoint) on the target
    association; the target-side outcomes travel toward the AMF (destination).
    The address is association-context evidence only and never maps to a
    network-function role.
    """
    message = _safe_str(event.get("message_type"))
    if message == HANDOVER_REQUEST:
        endpoint = event.get("source")
    else:
        endpoint = event.get("destination")
    if isinstance(endpoint, dict):
        return _safe_str(endpoint.get("address"))
    return None


def _event_sort_key(event: dict[str, object]) -> tuple:
    return (
        str(event.get("timestamp") or ""),
        int(event["frame_number"]) if isinstance(event.get("frame_number"), int) else 0,
        str(event.get("protocol") or ""),
        int(event.get("input_order", 0)),
    )


def _require_event_fields(record: object, index: int, kind: str) -> dict[str, object]:
    if not isinstance(record, dict):
        raise InputError(f"{kind} record {index} is not a JSON object")
    for field in ("timestamp", "frame_number", "capture_file"):
        if field not in record:
            raise InputError(f"{kind} record {index} lacks required provenance field: {field}")
    frame = record["frame_number"]
    if not isinstance(frame, int) or isinstance(frame, bool) or frame < 1:
        raise InputError(f"{kind} record {index} frame_number must be a positive integer")
    return record


def _read_jsonl(path: Path, kind: str, extra_check=None) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    if not path.is_file():
        raise InputError(f"file does not exist: {path}")
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name} at line {line_number}: {exc.msg}") from exc
            record = _require_event_fields(record, len(events), kind)
            if extra_check is not None:
                extra_check(record, len(events), path.name)
            events.append(record)
    return events


def load_ngap_events(path: Path) -> list[dict[str, object]]:
    def check(record: dict[str, object], index: int, name: str) -> None:
        if not isinstance(record.get("message_type"), str):
            raise InputError(f"NGAP record {index} in {name} lacks a message_type")
    return _read_jsonl(path, "NGAP", check)


def load_pfcp_events(path: Path) -> list[dict[str, object]]:
    def check(record: dict[str, object], index: int, name: str) -> None:
        if not isinstance(record.get("header"), dict):
            raise InputError(f"PFCP record {index} in {name} lacks a header object")
    return _read_jsonl(path, "PFCP", check)


def load_gtpu_events(path: Path) -> list[dict[str, object]]:
    def check(record: dict[str, object], index: int, name: str) -> None:
        if not isinstance(record.get("header"), dict) or not isinstance(record.get("outer"), dict):
            raise InputError(f"GTP-U record {index} in {name} lacks header or outer object")
    return _read_jsonl(path, "GTP-U", check)


def load_sbi_events(path: Path) -> list[dict[str, object]]:
    def check(record: dict[str, object], index: int, name: str) -> None:
        if not isinstance(record.get("sbi"), dict):
            raise InputError(f"SBI record {index} in {name} lacks an sbi object")
    return _read_jsonl(path, "SBI-HTTP2", check)


def load_pdu_session_context(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise InputError(f"file does not exist: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in {path.name}: {exc.msg}") from exc
    if not isinstance(document, dict) or document.get("procedure_name") != "5gc-pdu-session":
        raise InputError(f"{path.name} is not a 5gc-pdu-session analysis summary")
    version = document.get("procedure_version")
    if not isinstance(version, str) or tuple(int(part) for part in version.split(".")) < (0, 4, 0):
        raise InputError(
            f"{path.name}: 5gc-pdu-session procedure_version {version} lacks the lifecycle "
            "context contract required by 5gc-handover-mobility; 0.4.0 or newer is required"
        )
    if not isinstance(document.get("instances"), list):
        raise InputError(f"{path.name} lacks an instances array")
    return document


def _protocol_tag(event: dict[str, object], protocol: str) -> dict[str, object]:
    tagged = dict(event)
    tagged["protocol"] = protocol
    return tagged


# --------------------------------------------------------------------------
# N2 half-attempt formation
# --------------------------------------------------------------------------

def _new_half(attempt_key: tuple, capture: str, association: str, event: dict[str, object],
              side: str, ran_id: int | None, amf_id: int | None) -> dict[str, object]:
    return {
        "capture": capture,
        "association": association,
        "ran_ue_ngap_id": ran_id,
        "amf_ue_ngap_id": amf_id,
        "amf_endpoint": _amf_endpoint_of(event),
        "side": side,
        "initiation": event,
        "events": [event],
        "key": attempt_key,
    }


def _context_grouping_key(event: dict[str, object], capture: str, association: str) -> tuple:
    ran_id = event.get("ran_ue_ngap_id") if isinstance(event.get("ran_ue_ngap_id"), int) else None
    return (capture, association, ran_id)


def build_ngap_halves(ngap_events: list[dict[str, object]]) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    """Split NGAP mobility events into source halves, target halves, leftovers.

    Two-pass formation keeps input-order robustness: reviewed initiation
    messages (HandoverRequired, HandoverRequest) open halves; every other
    same-side mobility event attaches to the latest same-context half whose
    initiation precedes it, and events without such a half form bounded
    partial halves (the capture may begin mid-procedure). Same-signature
    initiation repeats stay in the same half as duplicate evidence. Source
    and target roles come from the reviewed message identity only; RAN
    UE ID equality across associations never merges halves.
    """
    source_halves: list[dict[str, object]] = []
    target_halves: list[dict[str, object]] = []
    pending: dict[str, list[dict[str, object]]] = {"source": [], "target": []}
    unbound: list[dict[str, object]] = []
    for order, raw_event in enumerate(ngap_events):
        event = _protocol_tag(raw_event, "NGAP")
        event["input_order"] = order
        message = _safe_str(event.get("message_type"))
        capture = str(event["capture_file"])
        association = _association_of(event)
        ran_id = event.get("ran_ue_ngap_id") if isinstance(event.get("ran_ue_ngap_id"), int) else None
        amf_id = event.get("amf_ue_ngap_id") if isinstance(event.get("amf_ue_ngap_id"), int) else None
        if message in HANDOVER_SOURCE_MESSAGES:
            side, initiation_message = "source", HANDOVER_REQUIRED
        elif message in HANDOVER_TARGET_MESSAGES:
            side, initiation_message = "target", HANDOVER_REQUEST
        else:
            unbound.append(event)
            continue
        halves = source_halves if side == "source" else target_halves
        if message == initiation_message:
            duplicate = False
            for half in halves:
                if half["key"][0] == capture and half["key"][1] == association                         and half["key"][2] == ran_id                         and half["initiation"]["frame_number"] == event["frame_number"]                         and str(half["initiation"].get("timestamp")) == str(event.get("timestamp")):
                    half["events"].append(event)
                    duplicate = True
                    break
            if not duplicate:
                halves.append(_new_half((capture, association, ran_id), capture, association,
                                        event, side, ran_id, amf_id))
        else:
            pending[side].append(event)

    for side, halves in (("source", source_halves), ("target", target_halves)):
        for event in pending[side]:
            capture = str(event["capture_file"])
            association = _association_of(event)
            ran_id = event.get("ran_ue_ngap_id") if isinstance(event.get("ran_ue_ngap_id"), int) else None
            amf_id = event.get("amf_ue_ngap_id") if isinstance(event.get("amf_ue_ngap_id"), int) else None
            key = (capture, association, ran_id)
            candidates = [
                half for half in halves
                if half["key"] == key and _event_sort_key(half["initiation"]) <= _event_sort_key(event)
            ]
            if candidates:
                best = max(candidates, key=lambda half: _event_sort_key(half["initiation"]))
                best["events"].append(event)
                continue
            orphan = _new_half(key, capture, association, event, side, ran_id, amf_id)
            halves.append(orphan)
    for half in source_halves + target_halves:
        half["events"].sort(key=_event_sort_key)
    return source_halves, target_halves, unbound


def build_path_switch_attempts(ps_events: list[dict[str, object]]) -> list[dict[str, object]]:
    """Group Path Switch events into attempts; PSR opens, Ack/Failure attach.

    A PathSwitchRequestAcknowledge observed without a visible Request forms a
    bounded partial attempt; the Request is never fabricated. Same-signature
    initiation repeats stay in the same attempt as duplicate evidence.
    """
    attempts: list[dict[str, object]] = []
    pending: list[dict[str, object]] = []
    for order, raw_event in enumerate(ps_events):
        event = _protocol_tag(raw_event, "NGAP")
        event["input_order"] = order
        message = _safe_str(event.get("message_type"))
        capture = str(event["capture_file"])
        association = _association_of(event)
        if message == PATH_SWITCH_REQUEST:
            duplicate = False
            for attempt in attempts:
                if attempt["capture"] == capture and attempt["association"] == association                         and attempt["initiation"]["frame_number"] == event["frame_number"]                         and str(attempt["initiation"].get("timestamp")) == str(event.get("timestamp")):
                    attempt["events"].append(event)
                    duplicate = True
                    break
            if not duplicate:
                ran_id = event.get("ran_ue_ngap_id") if isinstance(event.get("ran_ue_ngap_id"), int) else None
                amf_id = event.get("amf_ue_ngap_id") if isinstance(event.get("amf_ue_ngap_id"), int) else None
                attempts.append({
                    "capture": capture,
                    "association": association,
                    "ran_ue_ngap_id": ran_id,
                    "amf_ue_ngap_id": amf_id,
                    "amf_endpoint": _amf_endpoint_of(event),
                    "initiation": event,
                    "events": [event],
                    "partial": False,
                })
        else:
            pending.append(event)
    for event in pending:
        capture = str(event["capture_file"])
        association = _association_of(event)
        ran_id = event.get("ran_ue_ngap_id") if isinstance(event.get("ran_ue_ngap_id"), int) else None
        amf_id = event.get("amf_ue_ngap_id") if isinstance(event.get("amf_ue_ngap_id"), int) else None
        candidates = [
            attempt for attempt in attempts
            if attempt["capture"] == capture and attempt["association"] == association
            and attempt["ran_ue_ngap_id"] == ran_id
            and _event_sort_key(attempt["initiation"]) <= _event_sort_key(event)
        ]
        if candidates:
            best = max(candidates, key=lambda attempt: _event_sort_key(attempt["initiation"]))
            best["events"].append(event)
            continue
        attempts.append({
            "capture": capture,
            "association": association,
            "ran_ue_ngap_id": ran_id,
            "amf_ue_ngap_id": amf_id,
            "amf_endpoint": _amf_endpoint_of(event),
            "initiation": event,
            "events": [event],
            "partial": True,
        })
    for attempt in attempts:
        attempt["events"].sort(key=_event_sort_key)
    return attempts


def _scoped_amf_context(half: dict[str, object]) -> tuple | None:
    """Association scope for pairing: capture + AMF-UE-NGAP-ID.

    AMF-UE-NGAP-ID is an AMF-allocated NGAP UE-associated identifier scoped
    to one NG interface instance; pairing is bounded to one capture. It is
    never treated as subscriber, permanent-UE, cross-AMF, or cross-capture
    identity. Halves without an AMF-UE-NGAP-ID are not pairable by this rule.
    """
    if half.get("amf_ue_ngap_id") is None:
        return None
    return (half["capture"], half["amf_ue_ngap_id"])


def _endpoint_compatible(a: str | None, b: str | None) -> bool:
    if a is None or b is None:
        return True  # endpoint context incomplete; never used to reject
    return a == b


def pair_source_target(
    source_halves: list[dict[str, object]],
    target_halves: list[dict[str, object]],
) -> tuple[dict[int, list[int]], dict[int, list[int]], list[dict[str, object]]]:
    """Deterministic source/target pairing within scoped AMF UE contexts.

    Compatibility requires: same capture, same scoped AMF-UE-NGAP-ID,
    compatible observed AMF endpoint context, and temporal sanity (the
    target half must start after the source initiation and within the
    source's active window, which ends when the next source initiation for
    the same scoped context begins). Equal RAN-UE-NGAP-IDs, close timestamps
    alone, and PDU Session IDs never pair anything.

    Returns (source -> target candidates, target -> source candidates,
    ambiguity records).
    """
    by_context: dict[tuple, dict[str, list[int]]] = {}
    for index, half in enumerate(source_halves):
        context = _scoped_amf_context(half)
        if context is not None:
            by_context.setdefault(context, {"source": [], "target": []})["source"].append(index)
    for index, half in enumerate(target_halves):
        context = _scoped_amf_context(half)
        if context is not None:
            by_context.setdefault(context, {"source": [], "target": []})["target"].append(index)

    source_candidates: dict[int, list[int]] = {}
    target_candidates: dict[int, list[int]] = {}
    ambiguities: list[dict[str, object]] = []

    for context, groups in by_context.items():
        sources = sorted(groups["source"], key=lambda i: _event_sort_key(source_halves[i]["initiation"]))
        for position, source_index in enumerate(sources):
            source_half = source_halves[source_index]
            window_end = (
                _event_sort_key(source_halves[sources[position + 1]]["initiation"])
                if position + 1 < len(sources) else None
            )
            for target_index in groups["target"]:
                target_half = target_halves[target_index]
                if not _endpoint_compatible(source_half.get("amf_endpoint"), target_half.get("amf_endpoint")):
                    continue
                if _event_sort_key(target_half["initiation"]) < _event_sort_key(source_half["initiation"]):
                    continue
                if window_end is not None and _event_sort_key(target_half["initiation"]) >= window_end:
                    continue
                source_candidates.setdefault(source_index, []).append(target_index)
                target_candidates.setdefault(target_index, []).append(source_index)

        for source_index in list(source_candidates):
            if source_halves[source_index]["capture"] != context[0]:
                continue
            candidates = source_candidates.get(source_index, [])
            if len(candidates) > 1:
                ambiguities.append({
                    "scope": "source_target",
                    "capture_file": source_halves[source_index]["capture"],
                    "amf_ue_ngap_id": source_halves[source_index]["amf_ue_ngap_id"],
                    "context": "A source handover context is compatible with multiple target candidates; no nearest-in-time selection is made",
                    "source_initiation_frame": source_halves[source_index]["initiation"]["frame_number"],
                    "target_candidate_frames": [
                        target_halves[index]["initiation"]["frame_number"] for index in candidates
                    ],
                })
        for target_index in list(target_candidates):
            if target_halves[target_index]["capture"] != context[0]:
                continue
            candidates = target_candidates.get(target_index, [])
            if len(candidates) > 1:
                ambiguities.append({
                    "scope": "target_source",
                    "capture_file": target_halves[target_index]["capture"],
                    "amf_ue_ngap_id": target_halves[target_index]["amf_ue_ngap_id"],
                    "context": "A target handover context is compatible with multiple source candidates; no nearest-in-time selection is made",
                    "target_initiation_frame": target_halves[target_index]["initiation"]["frame_number"],
                    "source_candidate_frames": [
                        source_halves[index]["initiation"]["frame_number"] for index in candidates
                    ],
                })
    return source_candidates, target_candidates, ambiguities


def _half_context_ref(half: dict[str, object], role: str) -> dict[str, object]:
    return {
        "capture_file": half["capture"],
        "association": half["association"],
        "ran_ue_ngap_id": half["ran_ue_ngap_id"],
        "amf_ue_ngap_id": half["amf_ue_ngap_id"],
        "role": role,
    }


def _handover_type_of(events: list[dict[str, object]]) -> dict[str, object]:
    value: int | None = None
    name: str | None = None
    for event in events:
        mobility = event.get("mobility")
        if isinstance(mobility, dict) and mobility.get("handover_type_value") is not None:
            value = mobility.get("handover_type_value")
            name = mobility.get("handover_type_name")
            break
    if value == 0:
        scope, status = HANDOVER_TYPE_INTRA, SCOPE_SUPPORTED
    elif value is not None:
        scope, status = HANDOVER_TYPE_INTER_SYSTEM, SCOPE_UNSUPPORTED
    else:
        scope, status = None, None
    return {"value": value, "name": name, "domain_scope": scope, "scope_status": status}


# --------------------------------------------------------------------------
# Supporting-plane association
# --------------------------------------------------------------------------

def _psi_set(attempt_events: list[dict[str, object]]) -> dict[int, list[dict[str, object]]]:
    """PDU Session IDs observed in the attempt's NGAP resource items."""
    sessions: dict[int, list[dict[str, object]]] = {}
    for event in attempt_events:
        resources = event.get("pdu_session_resources")
        if not isinstance(resources, list):
            continue
        for item in resources:
            if isinstance(item, dict) and isinstance(item.get("pdu_session_id"), int):
                sessions.setdefault(item["pdu_session_id"], []).append(event)
    return sessions


def _after_start(event: dict[str, object], window: object) -> bool:
    """Lower temporal bound for supporting-plane candidacy.

    Supporting evidence must not precede the attempt. The upper bound, when
    one safely exists, is applied separately through the candidate windows
    derived from sequentially established attempts in the same scoped UE
    context. The association is never made by timestamp alone.
    """
    start = window.get("first_timestamp") if isinstance(window, dict) else None
    if start is None:
        return False
    return start <= str(event.get("timestamp") or "")


def _in_candidate_window(event: dict[str, object], attempt: dict[str, object],
                         window_end: str | None) -> bool:
    """Lower and (when safely established) upper temporal bounds.

    The upper bound comes only from the next independently established
    attempt in the same scoped UE context; when no such attempt exists the
    bound stays open and identity keys (not time) carry the association.
    """
    if not _after_start(event, attempt["window"]):
        return False
    if window_end is not None and str(event.get("timestamp") or "") >= window_end:
        return False
    return True


# N2 SM Information Type values that the reviewed lower SBI contract owns and
# that directly identify a mobility control operation. The sbi-http2 Skill
# passes n2SmInfoType through verbatim and its reviewed contract exposes no
# handover/path-switch N2 SM Information Type vocabulary, so this set is
# deliberately empty: N11 UpdateSMContext evidence therefore never binds to a
# mobility attempt in v0.1.0 (PDU Session ID + capture + time alone are never
# sufficient). When a lower contract version exposes reviewed mobility values,
# they are added here without changing this Skill's version.
MOBILITY_N2_SM_INFO_TYPES: frozenset[str] = frozenset()

SUPPORTING_REF_PROTOCOLS = ("SBI-HTTP2", "PFCP", "GTP-U")


def _supporting_ref(event: dict[str, object]) -> tuple[str, str, int]:
    """Stable supporting-event reference used for the ownership invariant."""
    return (str(event.get("protocol")), str(event.get("capture_file")), int(event["frame_number"]))


def _assert_exclusive_ownership(bound: dict[int, list[dict[str, object]]]) -> None:
    """Runtime invariant: one supporting event owns at most one attempt.

    Fails loudly if the same (protocol, capture_file, frame_number)
    reference is claimed by two mobility attempts, across or within the
    handover and Path Switch families. This is a runtime guarantee, not a
    test-only check.
    """
    owners: dict[tuple[str, str, int], set[int]] = {}
    for index, events in bound.items():
        for event in events:
            owners.setdefault(_supporting_ref(event), set()).add(index)
    duplicated = {ref: sorted(indices) for ref, indices in owners.items() if len(indices) > 1}
    if duplicated:
        raise InputError(
            "supporting-event ownership invariant violated; one event claimed by multiple "
            f"mobility attempts: {duplicated}"
        )


def _bounded_supporting_events(
    events: list[dict[str, object]],
    protocol: str,
    candidate_fn,
) -> tuple[dict[int, list[dict[str, object]]], list[dict[str, object]], list[dict[str, object]]]:
    """Shared global candidate evaluation for one supporting plane.

    Every event is evaluated against ALL mobility attempts at once. The
    result is exactly one of BOUND (exactly one compatible attempt),
    AMBIGUOUS (two or more compatible attempts; no first or nearest
    selection), or UNBOUND (no sufficiently safe attempt). ``candidate_fn``
    returns (candidates, reason) with the reason always documenting why an
    event is unbound when no candidate survives. The plane's protocol label
    is attached in memory; normalized extractor events carry no protocol
    field. Returns (bound by attempt index, ambiguous records, unbound
    records).
    """
    bound: dict[int, list[dict[str, object]]] = {}
    ambiguous: list[dict[str, object]] = []
    unbound: list[dict[str, object]] = []
    for order, raw_event in enumerate(events):
        event = dict(raw_event)
        event["protocol"] = protocol
        event["input_order"] = order
        candidates, reason = candidate_fn(event)
        if len(candidates) == 1:
            bound.setdefault(candidates[0], []).append(event)
        elif len(candidates) > 1:
            ambiguous.append({
                "event": event,
                "reason": "multiple mobility attempts remain compatible; no first or nearest selection is made",
                "candidates": sorted(candidates),
            })
        else:
            unbound.append({"event": event, "reason": reason, "candidates": []})
    return bound, ambiguous, unbound


def associate_n11(
    sbi_events: list[dict[str, object]],
    attempts: list[dict[str, object]],
    window_ends: dict[int, str | None],
) -> tuple[dict[int, list[dict[str, object]]], list[dict[str, object]], list[dict[str, object]]]:
    """Globally evaluate Nsmf_PDUSession UpdateSMContext evidence.

    A PDU Session ID identifies a PDU Session context, never a mobility
    attempt. Binding additionally requires a reviewed mobility-specific N2
    SM Information Type from the lower SBI contract; the sbi-http2 contract
    currently exposes no such reviewed vocabulary (MOBILITY_N2_SM_INFO_TYPES
    is empty), so UpdateSMContext evidence stays UNBOUND in this version.
    PDU Session ID + capture + temporal position alone never bind N11, and
    no per-attempt isolated association pass exists.
    """

    def candidates_for(event: dict[str, object]) -> tuple[list[int], str]:
        sbi = event.get("sbi") or {}
        if _safe_str(sbi.get("service_name")) != SBI_SERVICE_NSMF \
                or _safe_str(sbi.get("operation")) != SBI_OPERATION_UPDATE_SM_CONTEXT:
            return [], "not an Nsmf_PDUSession UpdateSMContext observation"
        n2_sm_info_type = _safe_str((event.get("session_management") or {}).get("n2_sm_info_type"))
        if n2_sm_info_type not in MOBILITY_N2_SM_INFO_TYPES:
            return [], (
                "no reviewed mobility-specific N2 SM Information Type is exposed by the lower "
                "sbi-http2 contract; PDU Session identity, capture, and time never bind N11"
            )
        psi = (event.get("session_management") or {}).get("pdu_session_id")
        if not isinstance(psi, int):
            return [], "no PDU Session ID supplied (for example privacy-redacted evidence)"
        candidates = [
            index for index, attempt in enumerate(attempts)
            if attempt["capture"] == str(event["capture_file"])
            and psi in attempt["psi_set"]
            and _in_candidate_window(event, attempt, window_ends.get(index))
        ]
        return candidates, "no unique compatible mobility attempt"

    return _bounded_supporting_events(sbi_events, "SBI-HTTP2", candidates_for)


def _pfcp_endpoint_pair(event: dict[str, object]) -> tuple[str, ...]:
    """Undirected PFCP endpoint pair of one event (order-normalized).

    A PFCP session's Request and Response travel between the same endpoint
    pair in opposite directions, so the session key uses the order-normalized
    pair. SEIDs are endpoint/session scoped: the same numeric SEID under a
    different endpoint pair is a different PFCP session, never the same one.
    """
    parts = []
    for role in ("source", "destination"):
        endpoint = event.get(role)
        if isinstance(endpoint, dict):
            parts.append(f"{endpoint.get('address')}:{endpoint.get('port')}")
    return tuple(sorted(parts)) if parts else ("no-endpoints",)


def _pfcp_seid_context(
    pdu_session_context: dict[str, object] | None,
) -> tuple[dict[tuple[str, int], dict[int, list[tuple[int, int]]]], dict[tuple[str, int], set[tuple[int, str | None]]]]:
    """Endpoint-scoped context mapping: (capture, header SEID) -> PDU Session
    instances with their observation windows, plus the context F-TEIDs used
    to disambiguate endpoint-pair groups when the same numeric SEID appears
    under several PFCP endpoint pairs."""
    seid_context: dict[tuple[str, int], dict[int, list[tuple[int, int]]]] = {}
    context_f_teids: dict[tuple[str, int], set[tuple[int, str | None]]] = {}
    if pdu_session_context is not None:
        for instance in pdu_session_context.get("instances", []):
            psi = instance.get("pdu_session_id")
            capture = _safe_str(instance.get("capture_file"))
            bindings = instance.get("plane_bindings") or {}
            n4 = bindings.get("n4") if isinstance(bindings, dict) else None
            header_seid = n4.get("header_seid") if isinstance(n4, dict) else None
            window = instance.get("observation_window") or {}
            first_frame = window.get("first_frame") if isinstance(window, dict) else None
            last_frame = window.get("last_frame") if isinstance(window, dict) else None
            if isinstance(psi, int) and capture is not None and isinstance(header_seid, int)                     and isinstance(first_frame, int) and isinstance(last_frame, int):
                seid_context.setdefault((capture, header_seid), {}).setdefault(psi, []).append((first_frame, last_frame))
                f_teid = n4.get("f_teid") if isinstance(n4.get("f_teid"), dict) else None
                if isinstance(f_teid, dict) and isinstance(f_teid.get("teid"), int):
                    context_f_teids.setdefault((capture, header_seid), set()).add(
                        (f_teid["teid"], _safe_str(f_teid.get("ipv4"))))
    return seid_context, context_f_teids


def _pfcp_psi_attribution(
    attempts: list[dict[str, object]],
    bound_n4: dict[int, list[dict[str, object]]],
    pdu_session_context: dict[str, object] | None,
) -> dict[int, dict[int, dict[str, object]]]:
    """Per-attempt PDU Session attribution for BOUND PFCP events, derived
    from the same endpoint-scoped context mapping used for association."""
    seid_context, _f_teids = _pfcp_seid_context(pdu_session_context)
    attribution: dict[int, dict[int, dict[str, object]]] = {}
    for index, events in bound_n4.items():
        if index >= len(attempts):
            continue
        attempt = attempts[index]
        for event in events:
            seid = (event.get("header") or {}).get("seid")
            mapping = seid_context.get((str(event["capture_file"]), seid), {}) if isinstance(seid, int) else {}
            for psi in sorted(set(mapping) & set(attempt["psi_set"])):
                attribution.setdefault(index, {}).setdefault(psi, {
                    "association_basis": "pdu_session_context_header_seid",
                    "header_seid": seid,
                })
    return attribution


def associate_n4(
    pfcp_events: list[dict[str, object]],
    attempts: list[dict[str, object]],
    window_ends: dict[int, str | None],
    pdu_session_context: dict[str, object] | None,
) -> tuple[dict[int, list[dict[str, object]]], list[dict[str, object]], list[dict[str, object]]]:
    """Globally evaluate PFCP Session Modification evidence.

    PFCP carries no UE identity and a modification may belong to any PDU
    Session change, so attribution stays conservative:

    - PFCP session identity is endpoint scoped: (capture, order-normalized
      endpoint pair, header SEID). The same numeric SEID under a different
      endpoint pair is never the same session.
    - The only bridge to a mobility attempt is the optional PDU Session
      Domain context binding that SEID to a PDU Session instance (same
      capture) whose window overlaps the attempt and whose PDU Session ID is
      in the attempt's resource set. When the same (capture, SEID) spans
      several endpoint-pair groups, the context cannot select one; groups
      are kept apart and only a group whose FAR outer-header F-TEID matches
      the context instance's F-TEID may become the candidate group. Anything
      else stays AMBIGUOUS or UNBOUND. Timestamp proximity alone never
      associates PFCP evidence.
    """
    seid_context: dict[tuple[str, int], dict[int, list[tuple[int, int]]]] = {}
    context_f_teids: dict[tuple[str, int], set[tuple[int, str | None]]] = {}
    if pdu_session_context is not None:
        for instance in pdu_session_context.get("instances", []):
            psi = instance.get("pdu_session_id")
            capture = _safe_str(instance.get("capture_file"))
            bindings = instance.get("plane_bindings") or {}
            n4 = bindings.get("n4") if isinstance(bindings, dict) else None
            header_seid = n4.get("header_seid") if isinstance(n4, dict) else None
            window = instance.get("observation_window") or {}
            first_frame = window.get("first_frame") if isinstance(window, dict) else None
            last_frame = window.get("last_frame") if isinstance(window, dict) else None
            if isinstance(psi, int) and capture is not None and isinstance(header_seid, int) \
                    and isinstance(first_frame, int) and isinstance(last_frame, int):
                seid_context.setdefault((capture, header_seid), {}).setdefault(psi, []).append((first_frame, last_frame))
                f_teid = n4.get("f_teid") if isinstance(n4.get("f_teid"), dict) else None
                if isinstance(f_teid, dict) and isinstance(f_teid.get("teid"), int):
                    context_f_teids.setdefault((capture, header_seid), set()).add(
                        (f_teid["teid"], _safe_str(f_teid.get("ipv4"))))

    tagged: list[dict[str, object]] = []
    group_members: dict[tuple[str, int, tuple[str, ...]], list[int]] = {}
    for order, raw_event in enumerate(pfcp_events):
        event = dict(raw_event)
        event["input_order"] = order
        tagged.append(event)
        header = event.get("header") or {}
        seid = header.get("seid")
        if isinstance(seid, int):
            group_members.setdefault((str(event["capture_file"]), seid, _pfcp_endpoint_pair(event)), []).append(order)

    group_events: dict[tuple[str, int, tuple[str, ...]], list[dict[str, object]]] = {}
    for key, members in group_members.items():
        group_events[key] = [tagged[index] for index in members]

    def _far_keys(event: dict[str, object]) -> set[tuple[int, str | None]]:
        keys: set[tuple[int, str | None]] = set()
        rule_operations = event.get("rule_operations")
        fars = rule_operations.get("fars") if isinstance(rule_operations, dict) else None
        for far in fars or []:
            if not isinstance(far, dict):
                continue
            outer = far.get("outer_header_creation")
            if isinstance(outer, dict) and outer.get("present") and isinstance(outer.get("teid"), int):
                keys.add((outer["teid"], _safe_str(outer.get("ipv4"))))
        return keys

    def candidates_for(event: dict[str, object]) -> tuple[list[int], str]:
        header = event.get("header") or {}
        message = _safe_str(header.get("message_type"))
        if message not in PFCP_MODIFICATION_MESSAGES:
            return [], "not a PFCP Session Modification observation"
        seid = header.get("seid")
        capture = str(event["capture_file"])
        if not isinstance(seid, int) or (capture, seid) not in seid_context:
            return [], (
                "no PDU Session Domain context binds this endpoint-scoped PFCP session; "
                "PSI, SEID, and time alone never attribute a modification to mobility"
            )
        pair = _pfcp_endpoint_pair(event)
        groups_for_seid = [key for key in group_events if key[0] == capture and key[1] == seid]
        if len(groups_for_seid) > 1:
            f_teids = context_f_teids.get((capture, seid), set())
            matching_groups = [
                key for key in groups_for_seid
                if any(_far_keys(item) & f_teids for item in group_events[key])
            ]
            if len(matching_groups) != 1 or (capture, seid, pair) not in matching_groups:
                return [], (
                    "the same header SEID appears under several PFCP endpoint pairs and the "
                    "available context cannot scope this event to one session"
                )
        psi_windows = seid_context[(capture, seid)]
        candidates: list[int] = []
        for index, attempt in enumerate(attempts):
            if attempt["capture"] != capture:
                continue
            attempt_frames = (attempt["window"].get("first_frame"), attempt["window"].get("last_frame"))
            overlap = False
            for psi, windows in psi_windows.items():
                if psi not in attempt["psi_set"]:
                    continue
                for first_frame, last_frame in windows:
                    if first_frame <= (attempt_frames[1] if attempt_frames[1] is not None else first_frame) \
                            and last_frame >= (attempt_frames[0] if attempt_frames[0] is not None else last_frame):
                        overlap = True
                        break
                if overlap:
                    break
            if overlap and _in_candidate_window(event, attempt, window_ends.get(index)):
                candidates.append(index)
        return candidates, (
            "no mobility attempt satisfies the endpoint-scoped session, PDU Session lifecycle, "
            "and candidate-window requirements"
        )

    return _bounded_supporting_events(tagged, "PFCP", candidates_for)


def _gtpu_outer_pair(event: dict[str, object]) -> tuple[str | None, str | None]:
    outer = event.get("outer") or {}
    return _safe_str(outer.get("source_address")), _safe_str(outer.get("destination_address"))


def associate_n3(
    gtpu_events: list[dict[str, object]],
    attempts: list[dict[str, object]],
    window_ends: dict[int, str | None],
    bound_n4: dict[int, list[dict[str, object]]],
) -> tuple[dict[int, list[dict[str, object]]], list[dict[str, object]], list[dict[str, object]]]:
    """Globally evaluate GTP-U observations through directed tunnel context.

    Binding requires TEID equality plus the correct directed endpoint role:
    a PFCP FAR Outer Header Creation names the encapsulation destination, so
    the matching packet must carry that TEID toward that address
    (destination role). A packet with the same TEID whose source is that
    address is the reverse direction and never binds through the same rule.
    Tunnels are derived only from attempt-owned (BOUND) PFCP events; an
    unbound PFCP event never creates owning tunnel context. Tunnel contexts
    that expose TEID + address without a safe direction role (for example
    the PDU Session Domain context F-TEID entries) are not registered for
    ownership at all. TEID alone is never sufficient, tunnel roles stay
    neutral (TUNNEL_A/TUNNEL_B...), and NGAP opaque transfer bytes are never
    parsed for TEIDs.
    """
    known_tunnels: dict[int, list[dict[str, object]]] = {}
    for index, events in bound_n4.items():
        for event in events:
            rule_operations = event.get("rule_operations")
            fars = rule_operations.get("fars") if isinstance(rule_operations, dict) else None
            for far in fars or []:
                if not isinstance(far, dict):
                    continue
                outer = far.get("outer_header_creation")
                if isinstance(outer, dict) and outer.get("present") and isinstance(outer.get("teid"), int):
                    known_tunnels.setdefault(outer["teid"], []).append({
                        "attempt_index": index,
                        "endpoint": _safe_str(outer.get("ipv4")),
                        "role": "DESTINATION",
                        "basis": "pfcp_far_outer_header_destination",
                    })

    def candidates_for(event: dict[str, object]) -> tuple[list[int], str]:
        header = event.get("header") or {}
        message = _safe_str(header.get("message_type"))
        if message not in (GTPU_GPDU, GTPU_END_MARKER, GTPU_ERROR_INDICATION):
            return [], "not a reviewed GTP-U mobility observation"
        teid = header.get("teid")
        error_indication = event.get("error_indication")
        if isinstance(error_indication, dict) and isinstance(error_indication.get("affected_teid"), int):
            # An Error Indication's header TEID is zero by definition; the
            # affected tunnel TEID is the matching key.
            teid = error_indication["affected_teid"]
        source_address, destination_address = _gtpu_outer_pair(event)
        if not isinstance(teid, int):
            return [], "no TEID observed"
        candidates: list[int] = []
        for info in known_tunnels.get(teid, []):
            expected = info.get("endpoint")
            if expected is None:
                continue
            if info.get("role") == "DESTINATION":
                if destination_address != expected:
                    # Same TEID in the reverse direction, or a different
                    # endpoint pair: never bound through this tunnel rule.
                    continue
            else:
                continue  # unknown-direction tunnel context never owns events
            attempt_index = info["attempt_index"]
            if attempts[attempt_index]["capture"] == str(event["capture_file"]) \
                    and _in_candidate_window(event, attempts[attempt_index], window_ends.get(attempt_index)):
                candidates.append(attempt_index)
        if not candidates and any(teid == info_teid for info_teid in known_tunnels):
            return [], (
                "TEID observed but no bound tunnel context matches the required directed "
                "endpoint role for this packet"
            )
        return candidates, "no bound tunnel context with the required directed endpoint role matches this packet"

    bound, ambiguous, unbound = _bounded_supporting_events(gtpu_events, "GTP-U", candidates_for)

    tunnel_labels: dict[tuple, str] = {}
    tunnels: dict[int, dict[str, dict[str, object]]] = {}
    for index, events in bound.items():
        for event in events:
            header = event.get("header") or {}
            teid = header.get("teid")
            source_address, destination_address = _gtpu_outer_pair(event)
            label_key = (teid, source_address, destination_address)
            if label_key not in tunnel_labels:
                tunnel_labels[label_key] = TUNNEL_LABELS[len(tunnel_labels) % len(TUNNEL_LABELS)]
            tunnels.setdefault(index, {})[str(label_key)] = {
                "label": tunnel_labels[label_key],
                "teid": teid,
                "endpoint_pair": f"{source_address}<->{destination_address}",
                "direction": "toward_far_outer_header_destination",
                "role": "NEUTRAL_TUNNEL_LABEL",
                "basis": "teid_plus_directed_endpoint",
            }
    return bound, ambiguous, unbound


# --------------------------------------------------------------------------
# Attempt assembly
# --------------------------------------------------------------------------

def _stage_record(stage_id: str, stage_name: str, observed: list[dict[str, object]],
                  missing: list[str]) -> dict[str, object]:
    if observed and not missing:
        status = "OBSERVED"
    elif observed:
        status = "PARTIALLY_OBSERVED"
    else:
        status = "NOT_APPLICABLE"
    return {
        "stage_id": stage_id,
        "stage_name": stage_name,
        "status": status,
        "observed": observed,
        "missing": missing,
    }


def _observed_entries(events: list[dict[str, object]], stage_id: str) -> list[dict[str, object]]:
    return [
        {
            "protocol": _safe_str(event.get("protocol")),
            "message_type": _safe_str(event.get("message_type")),
            "frame_number": event["frame_number"],
            "timestamp": _safe_str(event.get("timestamp")),
            "capture_file": _safe_str(event.get("capture_file")),
            "cause": event.get("cause") if isinstance(event.get("cause"), dict) else None,
            "evidence_level": "OBSERVED",
        }
        for event in sorted(events, key=_event_sort_key)
    ]


def _message_stage_map(family: str) -> dict[str, str]:
    if family == "handover":
        return {
            HANDOVER_REQUIRED: STAGE_HANDOVER_INITIATION,
            HANDOVER_COMMAND: STAGE_PREPARATION_OUTCOME,
            HANDOVER_PREPARATION_FAILURE: STAGE_PREPARATION_OUTCOME,
            HANDOVER_REQUEST: STAGE_TARGET_ALLOCATION,
            HANDOVER_REQUEST_ACK: STAGE_TARGET_ALLOCATION,
            HANDOVER_FAILURE: STAGE_TARGET_ALLOCATION,
            HANDOVER_NOTIFY: STAGE_EXECUTION_NOTIFICATION,
            HANDOVER_CANCEL: STAGE_CANCELLATION,
            HANDOVER_CANCEL_ACK: STAGE_CANCELLATION,
        }
    return {
        PATH_SWITCH_REQUEST: STAGE_PATH_SWITCH_REQUEST,
        PATH_SWITCH_ACK: STAGE_PATH_SWITCH_OUTCOME,
        PATH_SWITCH_FAILURE: STAGE_PATH_SWITCH_OUTCOME,
    }


def _window_of(events: list[dict[str, object]]) -> dict[str, object]:
    frames = [int(event["frame_number"]) for event in events if isinstance(event.get("frame_number"), int)]
    timestamps = [str(event["timestamp"]) for event in events if event.get("timestamp") is not None]
    return {
        "first_timestamp": min(timestamps) if timestamps else None,
        "last_timestamp": max(timestamps) if timestamps else None,
        "first_frame": min(frames) if frames else None,
        "last_frame": max(frames) if frames else None,
    }


def _collect_resource_findings(
    attempt_events: list[dict[str, object]],
    attempt_window_frames: tuple[int | None, int | None],
    capture: str,
    pdu_session_context: dict[str, object] | None,
    n11_events: list[dict[str, object]],
    n4_events: list[dict[str, object]],
    gtpu_events: list[dict[str, object]],
    n4_ps: dict[int, dict[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    """Item-scoped per-PSI findings; mixed outcomes are never collapsed."""
    findings: dict[int, dict[str, object]] = {}
    deviations: list[dict[str, object]] = []
    for event in sorted(attempt_events, key=_event_sort_key):
        resources = event.get("pdu_session_resources")
        if not isinstance(resources, list):
            continue
        for item in resources:
            if not isinstance(item, dict) or not isinstance(item.get("pdu_session_id"), int):
                continue
            psi = item["pdu_session_id"]
            finding = findings.setdefault(psi, {
                "pdu_session_id": psi,
                "lifecycle_generation": None,
                "n2_roles": [],
                "n2_outcomes": [],
                "n11_evidence": [],
                "n4_evidence": [],
                "n3_observations": [],
                "limitations": [],
            })
            role_entry = {
                "message_type": _safe_str(event.get("message_type")),
                "frame_number": event["frame_number"],
                "resource_operation": _safe_str(item.get("resource_operation")),
                "resource_list_role": _safe_str(item.get("resource_list_role")),
                "evidence_level": "OBSERVED",
            }
            finding["n2_roles"].append(role_entry)
            if _safe_str(item.get("resource_list_role")) == "FAILED":
                finding["n2_outcomes"].append({
                    "outcome": "RESOURCE_FAILED_ITEM_OBSERVED",
                    "message_type": _safe_str(event.get("message_type")),
                    "frame_number": event["frame_number"],
                    "cause": item.get("cause") if isinstance(item.get("cause"), dict) else None,
                    "evidence_level": "OBSERVED",
                })
                deviations.append({
                    "type": DEVIATION_RESOURCE_FAILED,
                    "stage_id": None,
                    "description": (
                        f"PDU Session {psi} carried a FAILED resource item in "
                        f"{_safe_str(event.get('message_type'))} at frame {event['frame_number']}"
                    ),
                    "evidence_level": "OBSERVED",
                    "limitation": (
                        "A failed resource item is item-scoped protocol evidence; the attempt "
                        "is not reduced to a complete failure and no network element is blamed"
                    ),
                    "evidence_refs": [_event_ref(event, field_name=f"pdu_session_resources[{psi}]")],
                })
            elif _safe_str(item.get("resource_list_role")) in ("ADMITTED", "SWITCHED", "RELEASED"):
                finding["n2_outcomes"].append({
                    "outcome": f"{_safe_str(item.get('resource_list_role'))}_ROLE_OBSERVED",
                    "message_type": _safe_str(event.get("message_type")),
                    "frame_number": event["frame_number"],
                    "evidence_level": "OBSERVED",
                })

    # Field conflicts: a PSI observed FAILED in one message and ADMITTED or
    # SWITCHED in another within the same attempt. Both stay preserved.
    for psi, finding in findings.items():
        roles = {entry["resource_list_role"] for entry in finding["n2_roles"]}
        if "FAILED" in roles and roles & {"ADMITTED", "SWITCHED"}:
            conflicting = [entry for entry in finding["n2_roles"] if entry["resource_list_role"] in ("FAILED", "ADMITTED", "SWITCHED")]
            deviations.append({
                "type": DEVIATION_FIELD_CONFLICT,
                "stage_id": None,
                "description": (
                    f"PDU Session {psi} carries conflicting resource roles across safely "
                    f"associated stage evidence ({', '.join(sorted(role for role in roles if role))})"
                ),
                "evidence_level": "DERIVED",
                "limitation": "Both observations are preserved; this engine does not adjudicate them",
                "evidence_refs": [
                    _evidence_ref("FIELD_FINDING", "DERIVED",
                                  capture_file=capture,
                                  frame_number=entry["frame_number"],
                                  protocol="NGAP",
                                  message_type=entry["message_type"],
                                  field_name="resource_list_role")
                    for entry in conflicting
                ],
            })

    # N11 / N4 / N3 evidence attaches to the matching per-PSI findings.
    for event in n11_events:
        psi = (event.get("session_management") or {}).get("pdu_session_id")
        if isinstance(psi, int) and psi in findings:
            findings[psi]["n11_evidence"].append({
                "operation": _safe_str((event.get("sbi") or {}).get("operation")),
                "http_status": (event.get("http2") or {}).get("status"),
                "sm_context_ref": _safe_str((event.get("sbi") or {}).get("sm_context_ref")),
                "n2_sm_info_type": _safe_str((event.get("session_management") or {}).get("n2_sm_info_type")),
                "frame_number": event["frame_number"],
                "evidence_level": "OBSERVED",
            })
    n4_ps_keys = set(n4_ps) if isinstance(n4_ps, dict) else set()
    for event in n4_events:
        seid = (event.get("header") or {}).get("seid")
        for psi in sorted(set(findings) & n4_ps_keys):
            findings[psi]["n4_evidence"].append({
                "message_type": _safe_str((event.get("header") or {}).get("message_type")),
                "header_seid": seid,
                "cause": event.get("cause") if isinstance(event.get("cause"), dict) else None,
                "association_basis": (n4_ps.get(psi) or {}).get("association_basis"),
                "frame_number": event["frame_number"],
                "evidence_level": "OBSERVED",
            })
    for event in gtpu_events:
        header = event.get("header") or {}
        observation = {
            "message_type": _safe_str(header.get("message_type")),
            "teid": header.get("teid"),
            "end_marker_present": isinstance(event.get("end_marker"), dict),
            "error_indication_present": isinstance(event.get("error_indication"), dict),
            "frame_number": event["frame_number"],
            "evidence_level": "OBSERVED",
        }
        for finding in findings.values():
            if finding["n4_evidence"]:
                finding["n3_observations"].append(dict(observation))
    for psi, finding in findings.items():
        if n4_events and not finding["n4_evidence"]:
            finding["limitations"].append(
                "N4 evidence was associated with the attempt but not to this PDU Session resource; "
                "no session-level attribution was invented"
            )
        if gtpu_events and not finding["n4_evidence"]:
            finding["limitations"].append(
                "GTP-U evidence was bound to the attempt but not to this PDU Session resource; "
                "no tunnel-to-session attribution was invented"
            )

    # Lifecycle generation from the optional PDU Session Domain context.
    if pdu_session_context is not None:
        first_frame, last_frame = attempt_window_frames
        for psi, finding in findings.items():
            candidates = []
            for instance in pdu_session_context.get("instances", []):
                if instance.get("pdu_session_id") != psi:
                    continue
                window = instance.get("observation_window") or {}
                inst_first = window.get("first_frame")
                inst_last = window.get("last_frame")
                if not isinstance(inst_first, int) or not isinstance(inst_last, int):
                    continue
                if inst_first <= (last_frame if last_frame is not None else inst_first) and \
                        inst_last >= (first_frame if first_frame is not None else inst_last):
                    candidates.append(instance)
            if len(candidates) == 1:
                instance = candidates[0]
                finding["lifecycle_generation"] = {
                    "instance_id": _safe_str(instance.get("instance_id")),
                    "session_generation": instance.get("session_generation"),
                    "reuse_status": instance.get("reuse_status"),
                }
            elif len(candidates) > 1:
                finding["limitations"].append(
                    "multiple PDU Session lifecycle generations overlap this attempt window; "
                    "mobility evidence is not attached to one generation without further evidence"
                )
                deviations.append({
                    "type": DEVIATION_LIFECYCLE_AMBIGUITY,
                    "stage_id": None,
                    "description": f"Multiple lifecycle generations overlap the attempt window for PDU Session {psi}",
                    "evidence_level": "DERIVED",
                    "limitation": "Generation identity is preserved as ambiguous; no wrong generation is attached",
                    "evidence_refs": [_window_ref(capture, first_frame, last_frame)],
                })

    ordered = [findings[psi] for psi in sorted(findings)]
    return ordered, deviations, list(findings.values())


def _terminal_observation(events: list[dict[str, object]], partial: bool) -> dict[str, object]:
    terminal_capable = [
        event for event in events
        if _safe_str(event.get("message_type")) in TERMINAL_BY_MESSAGE
    ]
    if partial:
        return {
            "observation": TERMINAL_PARTIAL,
            "message_type": None,
            "frame_number": None,
            "timestamp": None,
            "evidence_level": "DERIVED",
        }
    if terminal_capable:
        last = sorted(terminal_capable, key=_event_sort_key)[-1]
        return {
            "observation": TERMINAL_BY_MESSAGE[_safe_str(last.get("message_type"))],
            "message_type": _safe_str(last.get("message_type")),
            "frame_number": last["frame_number"],
            "timestamp": _safe_str(last.get("timestamp")),
            "evidence_level": "OBSERVED",
        }
    return {
        "observation": TERMINAL_NONE,
        "message_type": None,
        "frame_number": None,
        "timestamp": None,
        "evidence_level": "DERIVED",
    }


def _earliest_deviation(deviations: list[dict[str, object]]) -> dict[str, object] | None:
    best = None
    best_key = None
    for deviation in deviations:
        keys = []
        for ref in deviation.get("evidence_refs", []):
            if ref.get("kind") in ("EVENT", "FIELD_FINDING") and ref.get("frame_number") is not None:
                keys.append((0 if ref.get("evidence_level") == "OBSERVED" else 1,
                             str(ref.get("capture_file")), int(ref["frame_number"])))
        if not keys:
            continue
        key = min(keys)
        if best_key is None or key < best_key:
            best_key = key
            best = deviation
    return best


def assemble_handover_attempt(
    source_half: dict[str, object] | None,
    target_half: dict[str, object] | None,
    association: dict[str, object],
    sequence: int,
    pdu_session_context: dict[str, object] | None,
    n11_events: list[dict[str, object]],
    n4_events: list[dict[str, object]],
    gtpu_events: list[dict[str, object]],
    n4_ps: dict[int, dict[str, object]],
    ambiguity_records: list[dict[str, object]],
    out_of_order_captures: set[str] | None = None,
) -> dict[str, object]:
    events: list[dict[str, object]] = []
    if source_half is not None:
        events.extend(source_half["events"])
    if target_half is not None:
        events.extend(target_half["events"])
    events.sort(key=_event_sort_key)

    deviations: list[dict[str, object]] = []
    field_findings: list[dict[str, object]] = []
    limitations: list[str] = [LIMIT_NOT_ROOT_CAUSE]
    window = _window_of(events)
    frames = (window["first_frame"], window["last_frame"])
    capture = (source_half or target_half)["capture"]

    partial = (source_half is None or source_half["initiation"]["message_type"] != HANDOVER_REQUIRED) \
        and (target_half is None or target_half["initiation"]["message_type"] != HANDOVER_REQUEST)
    if source_half is None or _safe_str(source_half["initiation"].get("message_type")) != HANDOVER_REQUIRED:
        limitations.append(
            "No source-side handover initiation (HandoverRequired) was observed for this attempt; "
            "the capture may begin mid-procedure or the attempt may be target-side only"
        )
        if source_half is None:
            deviations.append({
                "type": DEVIATION_PARTIAL_CAPTURE,
                "stage_id": STAGE_HANDOVER_INITIATION,
                "description": "The attempt starts from target-side evidence without an observed HandoverRequired",
                "evidence_level": "DERIVED",
                "limitation": "Earlier handover stages may exist outside the capture; no initiation evidence is fabricated",
                "evidence_refs": [_window_ref(capture, frames[0], frames[1], stage_id=STAGE_HANDOVER_INITIATION)],
            })
    if target_half is None:
        limitations.append(
            "No target-side handover evidence was observed for this attempt; the target context "
            "stays unknown and is never guessed from timestamps or identifier equality"
        )

    # Out-of-order and duplicate input evidence.
    if out_of_order_captures and capture in out_of_order_captures:
        deviations.append({
            "type": DEVIATION_OUT_OF_ORDER,
            "stage_id": None,
            "description": "Input evidence was not chronological; ordering was normalized by timestamp and frame",
            "evidence_level": "DERIVED",
            "limitation": "Original provenance preserved",
            "evidence_refs": [_window_ref(capture, frames[0], frames[1])],
        })
    seen: set[tuple] = set()
    for event in events:
        signature = (str(event.get("capture_file")), int(event["frame_number"]),
                     str(event.get("protocol")), str(event.get("message_type")))
        if signature in seen:
            deviations.append({
                "type": DEVIATION_DUPLICATE,
                "stage_id": None,
                "description": (
                    f"Repeated {event.get('protocol')} {event.get('message_type')} observation at "
                    f"frame {event['frame_number']}; preserved as duplicate or retransmission evidence"
                ),
                "evidence_level": "DERIVED",
                "limitation": "Retransmission versus a repeated procedure is not distinguished without further context",
                "evidence_refs": [_event_ref(event)],
            })
        seen.add(signature)

    # Branch-aware stage evaluation.
    stage_map = _message_stage_map("handover")
    stage_events: dict[str, list[dict[str, object]]] = {}
    for event in events:
        stage_id = stage_map.get(_safe_str(event.get("message_type")))
        if stage_id is not None:
            stage_events.setdefault(stage_id, []).append(event)

    cancel_observed = bool(stage_events.get(STAGE_CANCELLATION))
    stages: list[dict[str, object]] = []
    stage_specs = [
        (STAGE_HANDOVER_INITIATION, "Handover initiation (HandoverRequired)"),
        (STAGE_PREPARATION_OUTCOME, "Handover preparation outcome (HandoverCommand or HandoverPreparationFailure)"),
        (STAGE_TARGET_ALLOCATION, "Target resource allocation (HandoverRequest, Acknowledge, or Failure)"),
        (STAGE_EXECUTION_NOTIFICATION, "Handover execution notification (HandoverNotify)"),
        (STAGE_CANCELLATION, "Handover cancellation (HandoverCancel, HandoverCancelAcknowledge)"),
        (STAGE_CONTROL_PLANE_UPDATE, "Control-plane session update (N11 UpdateSMContext, safely associated)"),
        (STAGE_USER_PLANE_CONTROL_UPDATE, "User-plane control update (PFCP Session Modification, safely associated)"),
        (STAGE_USER_PLANE_OBSERVATION, "User-plane observation (GTP-U, safely bound)"),
    ]
    for stage_id, stage_name in stage_specs:
        observed = _observed_entries(stage_events.get(stage_id, []), stage_id)
        if stage_id == STAGE_CONTROL_PLANE_UPDATE:
            observed = _observed_entries(n11_events, stage_id)
        elif stage_id == STAGE_USER_PLANE_CONTROL_UPDATE:
            observed = _observed_entries(n4_events, stage_id)
        elif stage_id == STAGE_USER_PLANE_OBSERVATION:
            observed = _observed_entries(gtpu_events, stage_id)
        missing: list[str] = []
        if stage_id == STAGE_HANDOVER_INITIATION and not observed:
            continue  # conditional stage; the partial-capture deviation records it
        if stage_id == STAGE_PREPARATION_OUTCOME and stage_events.get(STAGE_HANDOVER_INITIATION) \
                and not stage_events.get(STAGE_PREPARATION_OUTCOME) and not cancel_observed:
            missing.append(
                "Neither HandoverCommand nor HandoverPreparationFailure was observed within the "
                "available observation window; capture termination may explain the missing evidence"
            )
            deviations.append({
                "type": DEVIATION_MISSING_COUNTERPART,
                "stage_id": stage_id,
                "description": "Handover preparation outcome (HandoverCommand or HandoverPreparationFailure) was not observed",
                "evidence_level": "DERIVED",
                "limitation": "Capture termination may explain the missing evidence; no outcome is invented",
                "evidence_refs": [_window_ref(capture, frames[0], frames[1], stage_id=stage_id)],
            })
        if stage_id == STAGE_TARGET_ALLOCATION and stage_events.get(STAGE_TARGET_ALLOCATION):
            messages = {_safe_str(event.get("message_type")) for event in stage_events[STAGE_TARGET_ALLOCATION]}
            if HANDOVER_REQUEST in messages and not (messages & {HANDOVER_REQUEST_ACK, HANDOVER_FAILURE}):
                missing.append(
                    "Neither HandoverRequestAcknowledge nor HandoverFailure was observed within the "
                    "available observation window; capture termination may explain the missing evidence"
                )
                deviations.append({
                    "type": DEVIATION_MISSING_COUNTERPART,
                    "stage_id": stage_id,
                    "description": "Target resource allocation outcome was not observed",
                    "evidence_level": "DERIVED",
                    "limitation": "Capture termination may explain the missing evidence; no outcome is invented",
                    "evidence_refs": [_window_ref(capture, frames[0], frames[1], stage_id=stage_id)],
                })
        if observed or missing:
            stages.append(_stage_record(stage_id, stage_name, observed, missing))

    # Mandatory counterpart checks that do not map onto a single stage record.
    if stage_events.get(STAGE_CANCELLATION):
        messages = {_safe_str(event.get("message_type")) for event in stage_events[STAGE_CANCELLATION]}
        if HANDOVER_CANCEL in messages and HANDOVER_CANCEL_ACK not in messages:
            deviations.append({
                "type": DEVIATION_MISSING_COUNTERPART,
                "stage_id": STAGE_CANCELLATION,
                "description": "HandoverCancelAcknowledge was not observed within the available observation window",
                "evidence_level": "DERIVED",
                "limitation": "Capture termination may explain the missing evidence; cancellation itself is not a failure verdict",
                "evidence_refs": [_window_ref(capture, frames[0], frames[1], stage_id=STAGE_CANCELLATION)],
            })

    # Protocol negative outcomes and unsupported values.
    for event in events:
        if event.get("pdu_type") == "unsuccessfulOutcome":
            deviations.append({
                "type": DEVIATION_NEGATIVE_OUTCOME,
                "stage_id": stage_map.get(_safe_str(event.get("message_type"))),
                "description": (
                    f"NGAP unsuccessful outcome observed: {event.get('message_type')} at frame {event['frame_number']}"
                ),
                "evidence_level": "OBSERVED",
                "limitation": LIMIT_NOT_ROOT_CAUSE,
                "evidence_refs": [_event_ref(event)],
            })
        if event.get("support_status") in ("UNSUPPORTED", "UNKNOWN"):
            deviations.append({
                "type": DEVIATION_UNKNOWN_VALUE,
                "stage_id": None,
                "description": (
                    f"{event.get('protocol')} {event.get('message_type')} at frame {event['frame_number']} "
                    f"was reported {event.get('support_status')} by the lower layer; procedure interpretation is limited"
                ),
                "evidence_level": "OBSERVED",
                "limitation": "No semantics are invented for the unsupported or unknown message",
                "evidence_refs": [_event_ref(event)],
            })
        cause = event.get("cause")
        if isinstance(cause, dict) and cause.get("category") is not None:
            field_findings.append({
                "protocol": _safe_str(event.get("protocol")),
                "message_type": _safe_str(event.get("message_type")),
                "field_name": "NGAP cause",
                "observed_value": cause,
                "normalized_value": f"{cause.get('category')}:{cause.get('value')}" if cause.get("value") is not None else str(cause.get("category")),
                "frame_number": event["frame_number"],
                "capture_file": _safe_str(event.get("capture_file")),
                "evidence_level": "OBSERVED",
                "interpretation": "NGAP cause carried by the observed message; procedure evidence, never attribution",
                "limitations": [],
            })

    # HandoverType scope boundary.
    handover_type = _handover_type_of(events)
    if handover_type["scope_status"] == SCOPE_UNSUPPORTED:
        limitations.append(
            "An inter-system or other non-intra-5GS HandoverType was observed; inter-system and "
            "5GS-EPS mobility procedure semantics are outside this Domain version's scope"
        )

    # PFCP negative cause at the user-plane control stage.
    for event in n4_events:
        if _safe_str((event.get("header") or {}).get("message_type")) == "PFCP Session Modification Response":
            cause = event.get("cause") or {}
            code = cause.get("code") if isinstance(cause, dict) else None
            if isinstance(code, int) and code > PFCP_CAUSE_ACCEPTED_MAX:
                deviations.append({
                    "type": DEVIATION_NEGATIVE_OUTCOME,
                    "stage_id": STAGE_USER_PLANE_CONTROL_UPDATE,
                    "description": (
                        f"PFCP Session Modification Response with negative cause ({cause.get('name') or code}) "
                        f"at frame {event['frame_number']}"
                    ),
                    "evidence_level": "OBSERVED",
                    "limitation": (
                        "A negative PFCP cause is bounded user-plane control evidence; it never attributes "
                        "blame to the UPF, the SMF, or the handover"
                    ),
                    "evidence_refs": [_event_ref(event, stage_id=STAGE_USER_PLANE_CONTROL_UPDATE)],
                })

    # Ambiguity records touching this attempt.
    for record in ambiguity_records:
        deviations.append({
            "type": DEVIATION_CORRELATION_AMBIGUITY,
            "stage_id": None,
            "description": record["context"],
            "evidence_level": "DERIVED",
            "limitation": "All compatible candidates are preserved; no nearest-in-time selection is made",
            "evidence_refs": [
                _evidence_ref("FIELD_FINDING", "DERIVED",
                              capture_file=record["capture_file"],
                              frame_number=record.get("source_initiation_frame")
                              or record.get("target_initiation_frame"),
                              protocol="NGAP",
                              field_name="source_target_association")
            ],
        })

    # Association-scope fields.
    source_context = _half_context_ref(source_half, "source") if source_half else None
    if source_context is not None and target_half is not None:
        source_context["side"] = "SOURCE_AND_TARGET"
    elif source_context is not None:
        source_context["side"] = "SOURCE_ONLY"
    target_context = _half_context_ref(target_half, "target") if target_half else None
    if target_context is not None and source_half is None:
        target_context["side"] = "TARGET_ONLY"
    if target_context is not None and source_context is not None:
        target_context["side"] = "SOURCE_AND_TARGET"

    resource_findings, resource_deviations, _ = _collect_resource_findings(
        events, frames, capture, pdu_session_context, n11_events, n4_events, gtpu_events, n4_ps,
    )
    deviations.extend(resource_deviations)

    attempt_id = f"5gc-ho:{capture}:{(source_half or target_half)['association']}:" \
                 f"r{(source_half or target_half)['ran_ue_ngap_id'] if (source_half or target_half)['ran_ue_ngap_id'] is not None else '?'}:{sequence}"
    return {
        "attempt_id": attempt_id,
        "attempt_id_basis": (
            "DERIVED display reference 5gc-ho:<capture>:<association>:<ran-id>:<sequence>; consumers "
            "must read the structured source_context/target_context fields, never parse this string"
        ),
        "family": "handover",
        "handover_type": handover_type,
        "source_context": source_context,
        "target_context": target_context,
        "association": association,
        "stages": stages,
        "events": [
            {
                "protocol": _safe_str(event.get("protocol")),
                "message_type": _safe_str(event.get("message_type")),
                "pdu_type": _safe_str(event.get("pdu_type")),
                "frame_number": event["frame_number"],
                "timestamp": _safe_str(event.get("timestamp")),
                "capture_file": _safe_str(event.get("capture_file")),
                "association": _association_of(event),
                "ran_ue_ngap_id": event.get("ran_ue_ngap_id") if isinstance(event.get("ran_ue_ngap_id"), int) else None,
                "amf_ue_ngap_id": event.get("amf_ue_ngap_id") if isinstance(event.get("amf_ue_ngap_id"), int) else None,
                "role": "source" if _safe_str(event.get("message_type")) in HANDOVER_SOURCE_MESSAGES else "target",
                "cause": event.get("cause") if isinstance(event.get("cause"), dict) else None,
                "handover_type": (event.get("mobility") or {}).get("handover_type_name")
                    if isinstance(event.get("mobility"), dict) else None,
                "pdu_session_ids": sorted(item.get("pdu_session_id") for item in event.get("pdu_session_resources", [])
                                          if isinstance(item, dict) and isinstance(item.get("pdu_session_id"), int)),
                "resource_roles": [
                    {"pdu_session_id": item.get("pdu_session_id"), "role": item.get("resource_list_role")}
                    for item in event.get("pdu_session_resources", []) if isinstance(item, dict)
                ],
            }
            for event in events
        ],
        "pdu_session_resources": resource_findings,
        "terminal_observation": _terminal_observation(events, partial),
        "deviations": deviations,
        "earliest_observed_deviation": _earliest_deviation(deviations),
        "field_findings": field_findings,
        "event_ownership": {
            "owned_event_refs": [
                {
                    "protocol": _safe_str(event.get("protocol")),
                    "capture_file": _safe_str(event.get("capture_file")),
                    "frame_number": event["frame_number"],
                }
                for event in sorted(n11_events + n4_events + gtpu_events, key=_event_sort_key)
            ],
        },
        "plane_bindings": {
            "n11": [
                {
                    "operation": _safe_str((event.get("sbi") or {}).get("operation")),
                    "http_status": (event.get("http2") or {}).get("status"),
                    "pdu_session_id": (event.get("session_management") or {}).get("pdu_session_id"),
                    "sm_context_ref": _safe_str((event.get("sbi") or {}).get("sm_context_ref")),
                    "frame_number": event["frame_number"],
                    "association_basis": "mobility_n2_sm_info_type_and_unique_attempt",
                    "association_strength": "STRONG",
                    "note": "An HTTP 2xx response is observed evidence and never a mobility success",
                }
                for event in sorted(n11_events, key=_event_sort_key)
            ],
            "n4": [
                {
                    "message_type": _safe_str((event.get("header") or {}).get("message_type")),
                    "header_seid": (event.get("header") or {}).get("seid"),
                    "cause": event.get("cause") if isinstance(event.get("cause"), dict) else None,
                    "frame_number": event["frame_number"],
                    "association_basis": "pdu_session_context_header_seid_with_endpoint_scope",
                    "association_strength": "SUPPORTED",
                    "note": "PFCP modification acceptance never becomes handover or Path Switch success",
                }
                for event in sorted(n4_events, key=_event_sort_key)
            ],
            "n3": [
                {
                    "message_type": _safe_str((event.get("header") or {}).get("message_type")),
                    "teid": (event.get("header") or {}).get("teid"),
                    "endpoint_pair": "<->".join(str(part) for part in _gtpu_outer_pair(event)),
                    "frame_number": event["frame_number"],
                    "binding_basis": "teid_plus_directed_endpoint",
                    "association_strength": "SUPPORTED",
                    "note": "Capture-point observation only; never user-plane success",
                }
                for event in sorted(gtpu_events, key=_event_sort_key)
            ],
        },
        "unbound_evidence": [],
        "limitations": limitations,
        "observation_window": window,
    }


def assemble_path_switch_attempt(
    attempt: dict[str, object],
    related: tuple[str | None, str | None, str | None],
    sequence: int,
    pdu_session_context: dict[str, object] | None,
    n11_events: list[dict[str, object]],
    n4_events: list[dict[str, object]],
    gtpu_events: list[dict[str, object]],
    n4_ps: dict[int, dict[str, object]],
    out_of_order_captures: set[str] | None = None,
) -> dict[str, object]:
    events = sorted(attempt["events"], key=_event_sort_key)
    deviations: list[dict[str, object]] = []
    field_findings: list[dict[str, object]] = []
    limitations: list[str] = [LIMIT_NOT_ROOT_CAUSE]
    window = _window_of(events)
    frames = (window["first_frame"], window["last_frame"])
    capture = attempt["capture"]
    psi_set = _psi_set(events)

    if attempt.get("partial"):
        deviations.append({
            "type": DEVIATION_PARTIAL_CAPTURE,
            "stage_id": STAGE_PATH_SWITCH_REQUEST,
            "description": "The attempt starts from outcome evidence without an observed PathSwitchRequest",
            "evidence_level": "DERIVED",
            "limitation": "Earlier Path Switch stages may exist outside the capture; no initiation evidence is fabricated",
            "evidence_refs": [_window_ref(capture, frames[0], frames[1], stage_id=STAGE_PATH_SWITCH_REQUEST)],
        })
        limitations.append(
            "No PathSwitchRequest was observed for this attempt; the capture may begin mid-procedure"
        )

    stage_map = _message_stage_map("path-switch")
    stage_events: dict[str, list[dict[str, object]]] = {}
    for event in events:
        stage_id = stage_map.get(_safe_str(event.get("message_type")))
        if stage_id is not None:
            stage_events.setdefault(stage_id, []).append(event)

    stages: list[dict[str, object]] = []
    for stage_id, stage_name in (
        (STAGE_PATH_SWITCH_REQUEST, "Path Switch request (PathSwitchRequest)"),
        (STAGE_PATH_SWITCH_OUTCOME, "Path Switch outcome (PathSwitchRequestAcknowledge or PathSwitchRequestFailure)"),
        (STAGE_SESSION_CONTROL_UPDATE, "Session control update (N11 UpdateSMContext, safely associated)"),
        (STAGE_USER_PLANE_CONTROL_UPDATE, "User-plane control update (PFCP Session Modification, safely associated)"),
        (STAGE_USER_PLANE_OBSERVATION, "Post-switch user-plane observation (GTP-U, safely bound)"),
    ):
        observed = _observed_entries(stage_events.get(stage_id, []), stage_id)
        if stage_id == STAGE_SESSION_CONTROL_UPDATE:
            observed = _observed_entries(n11_events, stage_id)
        elif stage_id == STAGE_USER_PLANE_CONTROL_UPDATE:
            observed = _observed_entries(n4_events, stage_id)
        elif stage_id == STAGE_USER_PLANE_OBSERVATION:
            observed = _observed_entries(gtpu_events, stage_id)
        missing: list[str] = []
        if stage_id == STAGE_PATH_SWITCH_REQUEST and not observed:
            continue
        if stage_id == STAGE_PATH_SWITCH_REQUEST and stage_events.get(stage_id):
            messages = {_safe_str(event.get("message_type")) for event in stage_events[stage_id]}
            outcome_messages = {
                _safe_str(event.get("message_type")) for event in stage_events.get(STAGE_PATH_SWITCH_OUTCOME, [])
            }
            if PATH_SWITCH_REQUEST in messages and not (outcome_messages & {PATH_SWITCH_ACK, PATH_SWITCH_FAILURE}):
                missing.append(
                    "Neither PathSwitchRequestAcknowledge nor PathSwitchRequestFailure was observed within "
                    "the available observation window; capture termination may explain the missing evidence"
                )
                deviations.append({
                    "type": DEVIATION_MISSING_COUNTERPART,
                    "stage_id": stage_id,
                    "description": "Path Switch outcome was not observed",
                    "evidence_level": "DERIVED",
                    "limitation": "Capture termination may explain the missing evidence; no outcome is invented",
                    "evidence_refs": [_window_ref(capture, frames[0], frames[1], stage_id=stage_id)],
                })
        if observed or missing:
            stages.append(_stage_record(stage_id, stage_name, observed, missing))

    for event in events:
        if event.get("pdu_type") == "unsuccessfulOutcome":
            deviations.append({
                "type": DEVIATION_NEGATIVE_OUTCOME,
                "stage_id": stage_map.get(_safe_str(event.get("message_type"))),
                "description": (
                    f"NGAP unsuccessful outcome observed: {event.get('message_type')} at frame {event['frame_number']}"
                ),
                "evidence_level": "OBSERVED",
                "limitation": (
                    "PathSwitchRequestFailure is bounded protocol evidence; the reviewed basis defines no "
                    "message-level Cause for it and no Cause is invented from released-item presence"
                ),
                "evidence_refs": [_event_ref(event)],
            })
        if event.get("support_status") in ("UNSUPPORTED", "UNKNOWN"):
            deviations.append({
                "type": DEVIATION_UNKNOWN_VALUE,
                "stage_id": None,
                "description": (
                    f"{event.get('protocol')} {event.get('message_type')} at frame {event['frame_number']} "
                    f"was reported {event.get('support_status')} by the lower layer"
                ),
                "evidence_level": "OBSERVED",
                "limitation": "No semantics are invented for the unsupported or unknown message",
                "evidence_refs": [_event_ref(event)],
            })
        cause = event.get("cause")
        if isinstance(cause, dict) and cause.get("category") is not None:
            field_findings.append({
                "protocol": _safe_str(event.get("protocol")),
                "message_type": _safe_str(event.get("message_type")),
                "field_name": "NGAP cause",
                "observed_value": cause,
                "normalized_value": f"{cause.get('category')}:{cause.get('value')}" if cause.get("value") is not None else str(cause.get("category")),
                "frame_number": event["frame_number"],
                "capture_file": _safe_str(event.get("capture_file")),
                "evidence_level": "OBSERVED",
                "interpretation": "NGAP cause carried by the observed message; procedure evidence, never attribution",
                "limitations": [],
            })

    for event in n4_events:
        if _safe_str((event.get("header") or {}).get("message_type")) == "PFCP Session Modification Response":
            cause = event.get("cause") or {}
            code = cause.get("code") if isinstance(cause, dict) else None
            if isinstance(code, int) and code > PFCP_CAUSE_ACCEPTED_MAX:
                deviations.append({
                    "type": DEVIATION_NEGATIVE_OUTCOME,
                    "stage_id": STAGE_USER_PLANE_CONTROL_UPDATE,
                    "description": (
                        f"PFCP Session Modification Response with negative cause ({cause.get('name') or code}) "
                        f"at frame {event['frame_number']}"
                    ),
                    "evidence_level": "OBSERVED",
                    "limitation": "A negative PFCP cause is bounded user-plane control evidence; it never attributes blame to the UPF or the SMF",
                    "evidence_refs": [_event_ref(event, stage_id=STAGE_USER_PLANE_CONTROL_UPDATE)],
                })

    if out_of_order_captures and capture in out_of_order_captures:
        deviations.append({
            "type": DEVIATION_OUT_OF_ORDER,
            "stage_id": None,
            "description": "Input evidence was not chronological; ordering was normalized by timestamp and frame",
            "evidence_level": "DERIVED",
            "limitation": "Original provenance preserved",
            "evidence_refs": [_window_ref(capture, frames[0], frames[1])],
        })

    related_id, relationship_basis, relationship_strength = related
    serving_context = {
        "capture_file": capture,
        "association": attempt["association"],
        "ran_ue_ngap_id": attempt["ran_ue_ngap_id"],
        "amf_ue_ngap_id": attempt["amf_ue_ngap_id"],
        "role": "serving",
        "side": None,
    }

    resource_findings, resource_deviations, _ = _collect_resource_findings(
        events, frames, capture, pdu_session_context, n11_events, n4_events, gtpu_events, n4_ps,
    )
    deviations.extend(resource_deviations)

    attempt_id = f"5gc-ps:{capture}:{attempt['association']}:" \
                 f"r{attempt['ran_ue_ngap_id'] if attempt['ran_ue_ngap_id'] is not None else '?'}:{sequence}"
    return {
        "attempt_id": attempt_id,
        "attempt_id_basis": (
            "DERIVED display reference 5gc-ps:<capture>:<association>:<ran-id>:<sequence>; consumers "
            "must read the structured serving_context fields, never parse this string"
        ),
        "family": "path-switch",
        "serving_context": serving_context,
        "related_handover_attempt_id": related_id,
        "relationship_basis": relationship_basis,
        "relationship_strength": relationship_strength,
        "stages": stages,
        "events": [
            {
                "protocol": _safe_str(event.get("protocol")),
                "message_type": _safe_str(event.get("message_type")),
                "pdu_type": _safe_str(event.get("pdu_type")),
                "frame_number": event["frame_number"],
                "timestamp": _safe_str(event.get("timestamp")),
                "capture_file": _safe_str(event.get("capture_file")),
                "association": _association_of(event),
                "ran_ue_ngap_id": event.get("ran_ue_ngap_id") if isinstance(event.get("ran_ue_ngap_id"), int) else None,
                "amf_ue_ngap_id": event.get("amf_ue_ngap_id") if isinstance(event.get("amf_ue_ngap_id"), int) else None,
                "role": "serving",
                "cause": event.get("cause") if isinstance(event.get("cause"), dict) else None,
                "handover_type": None,
                "pdu_session_ids": sorted(item.get("pdu_session_id") for item in event.get("pdu_session_resources", [])
                                          if isinstance(item, dict) and isinstance(item.get("pdu_session_id"), int)),
                "resource_roles": [
                    {"pdu_session_id": item.get("pdu_session_id"), "role": item.get("resource_list_role")}
                    for item in event.get("pdu_session_resources", []) if isinstance(item, dict)
                ],
            }
            for event in events
        ],
        "pdu_session_resources": resource_findings,
        "terminal_observation": _terminal_observation(events, attempt.get("partial", False)),
        "deviations": deviations,
        "earliest_observed_deviation": _earliest_deviation(deviations),
        "field_findings": field_findings,
        "event_ownership": {
            "owned_event_refs": [
                {
                    "protocol": _safe_str(event.get("protocol")),
                    "capture_file": _safe_str(event.get("capture_file")),
                    "frame_number": event["frame_number"],
                }
                for event in sorted(n11_events + n4_events + gtpu_events, key=_event_sort_key)
            ],
        },
        "plane_bindings": {
            "n11": [
                {
                    "operation": _safe_str((event.get("sbi") or {}).get("operation")),
                    "http_status": (event.get("http2") or {}).get("status"),
                    "pdu_session_id": (event.get("session_management") or {}).get("pdu_session_id"),
                    "sm_context_ref": _safe_str((event.get("sbi") or {}).get("sm_context_ref")),
                    "frame_number": event["frame_number"],
                    "association_basis": "mobility_n2_sm_info_type_and_unique_attempt",
                    "association_strength": "STRONG",
                    "note": "An HTTP 2xx response is observed evidence and never a mobility success",
                }
                for event in sorted(n11_events, key=_event_sort_key)
            ],
            "n4": [
                {
                    "message_type": _safe_str((event.get("header") or {}).get("message_type")),
                    "header_seid": (event.get("header") or {}).get("seid"),
                    "cause": event.get("cause") if isinstance(event.get("cause"), dict) else None,
                    "frame_number": event["frame_number"],
                    "association_basis": "pdu_session_context_header_seid_with_endpoint_scope",
                    "association_strength": "SUPPORTED",
                    "note": "PFCP modification acceptance never becomes handover or Path Switch success",
                }
                for event in sorted(n4_events, key=_event_sort_key)
            ],
            "n3": [
                {
                    "message_type": _safe_str((event.get("header") or {}).get("message_type")),
                    "teid": (event.get("header") or {}).get("teid"),
                    "endpoint_pair": "<->".join(str(part) for part in _gtpu_outer_pair(event)),
                    "frame_number": event["frame_number"],
                    "binding_basis": "teid_plus_directed_endpoint",
                    "association_strength": "SUPPORTED",
                    "note": "Capture-point observation only; never user-plane success",
                }
                for event in sorted(gtpu_events, key=_event_sort_key)
            ],
        },
        "unbound_evidence": [],
        "limitations": limitations,
        "observation_window": window,
    }


# --------------------------------------------------------------------------
# Top-level analysis
# --------------------------------------------------------------------------

def _ngap_event_refs(events: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "capture_file": _safe_str(event.get("capture_file")),
            "frame_number": event["frame_number"],
            "timestamp": _safe_str(event.get("timestamp")),
            "protocol": "NGAP",
            "message_type": _safe_str(event.get("message_type")),
            "support_status": event.get("support_status"),
        }
        for event in events
    ]


def analyze(
    ngap_events: list[dict[str, object]],
    pfcp_events: list[dict[str, object]],
    gtpu_events: list[dict[str, object]],
    sbi_events: list[dict[str, object]],
    pdu_session_context: dict[str, object] | None,
) -> dict[str, object]:
    ngap_tagged = [_protocol_tag(event, "NGAP") for event in ngap_events]
    for order, event in enumerate(ngap_tagged):
        event["input_order"] = order

    out_of_order_captures: set[str] = set()
    seen_input: dict[str, list[str]] = {}
    for event in ngap_tagged:
        seen_input.setdefault(str(event["capture_file"]), []).append(str(event.get("timestamp")))
    for capture, timestamps in seen_input.items():
        if timestamps != sorted(timestamps):
            out_of_order_captures.add(capture)

    source_halves, target_halves, leftover = build_ngap_halves(ngap_tagged)
    ps_events = [event for event in leftover if _safe_str(event.get("message_type")) in PATH_SWITCH_MESSAGES]
    other_ngap = [event for event in leftover if _safe_str(event.get("message_type")) not in PATH_SWITCH_MESSAGES]
    ps_attempts = build_path_switch_attempts(ps_events)

    source_candidates, target_candidates, ambiguity_records = pair_source_target(source_halves, target_halves)

    # Assemble handover attempts, then supporting planes per attempt.
    handover_inputs: list[tuple[dict[str, object] | None, dict[str, object] | None, dict[str, object]]] = []
    for index, source_half in enumerate(source_halves):
        candidates = source_candidates.get(index, [])
        if len(candidates) == 1:
            target_half = target_halves[candidates[0]]
            strength = STRENGTH_STRONG
            if _safe_str(source_half["initiation"].get("message_type")) != HANDOVER_REQUIRED:
                strength = STRENGTH_SUPPORTED
            association = {
                "strength": strength,
                "basis": "same capture, same scoped AMF-UE-NGAP-ID context, compatible AMF endpoint context, and verified normative role sequence with a unique counterpart",
                "candidates": [],
            }
        elif len(candidates) > 1:
            target_half = None
            association = {
                "strength": STRENGTH_AMBIGUOUS,
                "basis": "multiple target candidates are simultaneously compatible; no nearest-in-time selection is made",
                "candidates": [_half_context_ref(target_halves[index], "target") for index in candidates],
            }
        else:
            target_half = None
            association = {
                "strength": STRENGTH_UNBOUND,
                "basis": "no target-side evidence within the same scoped AMF-UE-NGAP-ID context satisfies the reviewed association rule",
                "candidates": [],
            }
        handover_inputs.append((source_half, target_half, association))
    paired_targets = {candidates[0] for candidates in source_candidates.values() if len(candidates) == 1}
    for index, target_half in enumerate(target_halves):
        if index in paired_targets:
            continue
        candidates = target_candidates.get(index, [])
        if len(candidates) > 1:
            association = {
                "strength": STRENGTH_AMBIGUOUS,
                "basis": "multiple source candidates are simultaneously compatible; no nearest-in-time selection is made",
                "candidates": [_half_context_ref(source_halves[index], "source") for index in candidates],
            }
        else:
            association = {
                "strength": STRENGTH_UNBOUND,
                "basis": "no source-side evidence within the same scoped AMF-UE-NGAP-ID context satisfies the reviewed association rule",
                "candidates": [],
            }
        handover_inputs.append((None, target_half, association))

    # Global supporting-plane candidate evaluation: every supporting event is
    # evaluated against ALL mobility attempts (handover + Path Switch) before
    # ownership is assigned. No per-attempt isolated association pass exists.
    provisional: list[dict[str, object]] = []
    for source_half, target_half, association in handover_inputs:
        events = []
        if source_half is not None:
            events.extend(source_half["events"])
        if target_half is not None:
            events.extend(target_half["events"])
        anchor = source_half or target_half
        provisional.append({
            "capture": anchor["capture"],
            "psi_set": _psi_set(events),
            "window": _window_of(events),
            "amf_context": (anchor["capture"], anchor["amf_ue_ngap_id"]) if anchor.get("amf_ue_ngap_id") is not None else None,
            "start_sort": min((_event_sort_key(event) for event in events), default=None),
        })
    for ps_attempt in ps_attempts:
        provisional.append({
            "capture": ps_attempt["capture"],
            "psi_set": _psi_set(ps_attempt["events"]),
            "window": _window_of(ps_attempt["events"]),
            "amf_context": (ps_attempt["capture"], ps_attempt["amf_ue_ngap_id"]) if ps_attempt.get("amf_ue_ngap_id") is not None else None,
            "start_sort": min((_event_sort_key(event) for event in ps_attempt["events"]), default=None),
        })

    # Candidate windows: the next independently established attempt in the
    # same scoped UE context bounds the previous attempt's supporting window.
    # When no such attempt exists the upper bound stays open; strict identity
    # keys, never time, carry the association.
    window_ends: dict[int, str | None] = {}
    for index, attempt in enumerate(provisional):
        window_end = None
        context = attempt.get("amf_context")
        start = attempt.get("start_sort")
        if context is not None and start is not None:
            for other_index, other in enumerate(provisional):
                if other_index == index or other.get("amf_context") != context:
                    continue
                other_start = other.get("start_sort")
                if other_start is not None and other_start > start:
                    candidate_end = other["window"].get("first_timestamp")
                    if candidate_end is not None and (window_end is None or candidate_end < window_end):
                        window_end = candidate_end
        window_ends[index] = window_end

    n11_bound, n11_ambiguous, n11_unbound = associate_n11(sbi_events, provisional, window_ends)
    n4_bound, n4_ambiguous, n4_unbound = associate_n4(pfcp_events, provisional, window_ends, pdu_session_context)
    n3_bound, n3_ambiguous, n3_unbound = associate_n3(gtpu_events, provisional, window_ends, n4_bound)

    # Runtime ownership invariant across the whole analysis (all families).
    _assert_exclusive_ownership(n11_bound)
    _assert_exclusive_ownership(n4_bound)
    _assert_exclusive_ownership(n3_bound)

    # Per-attempt PDU Session attribution for bound N4 events, derived from
    # the same endpoint-scoped context mapping used for association.
    n4_ps = _pfcp_psi_attribution(provisional, n4_bound, pdu_session_context)

    handover_attempts = []
    for index, (source_half, target_half, association) in enumerate(handover_inputs):
        handover_attempts.append(assemble_handover_attempt(
            source_half, target_half, association, index + 1, pdu_session_context,
            n11_bound.get(index, []), n4_bound.get(index, []), n3_bound.get(index, []),
            n4_ps.get(index, {}), ambiguity_records, out_of_order_captures,
        ))

    # Handover <-> Path Switch relationship: the current lower-layer contracts
    # expose no deterministic bridge beyond common UE context and temporal
    # order, and an Xn handover can produce a Path Switch with no N2 handover
    # evidence at all. Common AMF-UE-NGAP-ID context plus time therefore never
    # creates the relationship; it stays explicitly UNBOUND.
    relationship = (
        None,
        "no deterministic bridge between this Path Switch attempt and any handover attempt is "
        "exposed by the current lower-layer contracts; common AMF-UE-NGAP-ID context and temporal "
        "order never establish the relationship",
        "UNBOUND",
    )

    path_switch_attempts = []
    for offset, ps_attempt in enumerate(ps_attempts):
        index = len(handover_inputs) + offset
        path_switch_attempts.append(assemble_path_switch_attempt(
            ps_attempt,
            relationship,
            offset + 1,
            pdu_session_context,
            n11_bound.get(index, []), n4_bound.get(index, []), n3_bound.get(index, []),
            n4_ps.get(index, {}), out_of_order_captures,
        ))

    # Unbound mobility evidence: NGAP mobility events outside every attempt
    # (including lower-layer UNSUPPORTED/UNKNOWN reports) plus supporting-plane
    # events that stayed unbound everywhere.
    unbound_mobility_evidence: list[dict[str, object]] = []
    consumed_ngap = set()
    for source_half, target_half, _association in handover_inputs:
        for event in (source_half["events"] if source_half else []) + (target_half["events"] if target_half else []):
            consumed_ngap.add(id(event))
    for ps_attempt in ps_attempts:
        for event in ps_attempt["events"]:
            consumed_ngap.add(id(event))
    for event in other_ngap:
        message = _safe_str(event.get("message_type"))
        procedure_name = _safe_str(event.get("procedure_name"))
        status = event.get("support_status")
        mobility_relevant = (
            message in MOBILITY_MESSAGES
            or (isinstance(procedure_name, str) and (procedure_name.startswith("Handover") or procedure_name.startswith("PathSwitch")))
            or status in ("UNSUPPORTED", "UNKNOWN")
        )
        if not mobility_relevant:
            continue  # non-mobility NGAP evidence belongs to other Domain Skills
        unbound_mobility_evidence.append({
            "protocol": "NGAP",
            "reason": (
                f"reported {status} by the lower layer; no mobility semantics are invented"
                if status in ("UNSUPPORTED", "UNKNOWN") and message not in MOBILITY_MESSAGES
                else "no safely associated mobility attempt context could be derived for this event"
            ),
            "message_type": message,
            "frame_number": event["frame_number"],
            "timestamp": _safe_str(event.get("timestamp")),
            "capture_file": _safe_str(event.get("capture_file")),
            "support_status": status,
        })
    attempt_ids = [attempt["attempt_id"] for attempt in handover_attempts] +                   [attempt["attempt_id"] for attempt in path_switch_attempts]

    def _supporting_entry(record: dict[str, object], strength: str) -> dict[str, object]:
        event = record["event"]
        return {
            "protocol": _safe_str(event.get("protocol")),
            "reason": record["reason"],
            "message_type": _supporting_message_label(event),
            "frame_number": event["frame_number"],
            "timestamp": _safe_str(event.get("timestamp")),
            "capture_file": _safe_str(event.get("capture_file")),
            "candidate_attempt_ids": [attempt_ids[index] for index in record.get("candidates", [])
                                      if isinstance(index, int) and index < len(attempt_ids)],
            "association_strength": strength,
        }

    for record in n11_ambiguous + n4_ambiguous + n3_ambiguous:
        unbound_mobility_evidence.append(_supporting_entry(record, "AMBIGUOUS"))
    for record in n11_unbound + n4_unbound + n3_unbound:
        unbound_mobility_evidence.append(_supporting_entry(record, "UNBOUND"))

    return sanitize_output({
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "procedure_family": PROCEDURE_FAMILY,
        "handover_attempts": handover_attempts,
        "path_switch_attempts": path_switch_attempts,
        "unbound_mobility_evidence": unbound_mobility_evidence,
        "limitations": [
            LIMIT_NOT_ROOT_CAUSE,
            "Handover and Path Switch are separate attempt families; neither is required for the other",
            "Source/target association requires the same capture, a scoped AMF-UE-NGAP-ID context, "
            "compatible roles, and temporal sanity; timestamp proximity alone never associates anything",
            "N11/N4/N3 supporting evidence is associated only through safe session/tunnel context; "
            "an HTTP 2xx or PFCP accepted response never becomes mobility success, and missing N11/N4/N3 "
            "evidence never becomes mobility failure",
            "Supporting-plane association is evaluated globally across all mobility attempts and one "
            "N11/PFCP/GTP-U event belongs to at most one attempt; ambiguous events stay unbound",
            "PDU Session identity is not mobility attempt identity: N11 UpdateSMContext evidence binds "
            "only through reviewed mobility-specific N2 SM Information Types, which the current lower "
            "SBI contract does not expose",
            "PFCP SEIDs are endpoint/session scoped; GTP-U binding is direction sensitive; and an N2 "
            "handover to Path Switch relationship is never inferred from common AMF context and time",
            "GTP-U observations prove capture-point observation only; tunnel roles stay neutral because "
            "reviewed tunnel lifecycle context is not established in this version",
            "Inter-system HandoverTypes are preserved with a scope limitation; no inter-system or "
            "5GS-EPS mobility semantics are applied",
            "This analysis is bounded to the supplied evidence files; absence of evidence is never "
            "reported as network absence",
        ],
    })


def _supporting_message_label(event: dict[str, object]) -> str | None:
    header = event.get("header")
    if isinstance(header, dict) and header.get("message_type") is not None:
        return _safe_str(header.get("message_type"))
    sbi = event.get("sbi")
    if isinstance(sbi, dict) and sbi.get("operation") is not None:
        return _safe_str(sbi.get("operation"))
    return _safe_str(event.get("message_type"))


def _supporting_plane_refs(events: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "capture_file": _safe_str(event.get("capture_file")),
            "frame_number": event["frame_number"],
            "timestamp": _safe_str(event.get("timestamp")),
            "protocol": _safe_str(event.get("protocol")),
            "message_type": _supporting_message_label(event),
        }
        for event in events
    ]


def build_stage_records(document: dict[str, object]) -> list[dict[str, object]]:
    """Project attempt stages into generic procedure-evidence records (JSONL).

    The projection adds no semantics: expected evidence is derived from the
    reviewed branch definitions, observed/missing statements come from the
    attempt's own stage records, and missing evidence stays evidence-bounded.
    """
    records: list[dict[str, object]] = []
    expected_by_stage = {
        STAGE_HANDOVER_INITIATION: ("NGAP", HANDOVER_REQUIRED),
        STAGE_PREPARATION_OUTCOME: ("NGAP", "HandoverCommand or HandoverPreparationFailure"),
        STAGE_TARGET_ALLOCATION: ("NGAP", "HandoverRequest with HandoverRequestAcknowledge or HandoverFailure"),
        STAGE_EXECUTION_NOTIFICATION: ("NGAP", HANDOVER_NOTIFY),
        STAGE_CANCELLATION: ("NGAP", "HandoverCancel with HandoverCancelAcknowledge"),
        STAGE_PATH_SWITCH_REQUEST: ("NGAP", PATH_SWITCH_REQUEST),
        STAGE_PATH_SWITCH_OUTCOME: ("NGAP", "PathSwitchRequestAcknowledge or PathSwitchRequestFailure"),
        STAGE_CONTROL_PLANE_UPDATE: ("SBI-HTTP2", "Nsmf_PDUSession UpdateSMContext (safely associated)"),
        STAGE_SESSION_CONTROL_UPDATE: ("SBI-HTTP2", "Nsmf_PDUSession UpdateSMContext (safely associated)"),
        STAGE_USER_PLANE_CONTROL_UPDATE: ("PFCP", "PFCP Session Modification (safely associated)"),
        STAGE_USER_PLANE_OBSERVATION: ("GTP-U", "G-PDU / End Marker / Error Indication (safely bound)"),
    }
    attempts = [
        (attempt, "handover") for attempt in document.get("handover_attempts", [])
    ] + [
        (attempt, "path-switch") for attempt in document.get("path_switch_attempts", [])
    ]
    for attempt, family in attempts:
        for stage in attempt.get("stages", []):
            protocol, expected = expected_by_stage.get(stage["stage_id"], ("NGAP", stage["stage_name"]))
            observed = stage.get("observed", [])
            missing = stage.get("missing", [])
            basis = "OBSERVED" if observed else "DERIVED"
            confidence = "HIGH" if observed and not missing else ("MEDIUM" if observed else "LOW")
            records.append({
                "procedure_name": attempt["attempt_id"],
                "procedure_version": ANALYSIS_VERSION,
                "observation_group": (attempt.get("source_context") or attempt.get("serving_context") or {}).get("capture_file"),
                "stage": {
                    "stage_id": stage["stage_id"],
                    "stage_name": stage["stage_name"],
                    "expected_protocols": [protocol],
                    "expected_message_types": [expected],
                },
                "expected_evidence": [f"{protocol} {expected}"] if stage["status"] != "NOT_APPLICABLE" else [],
                "observed_evidence": [
                    f"{entry.get('protocol')} {entry.get('message_type')} observed at frame {entry.get('frame_number')}"
                    for entry in observed
                ],
                "missing_evidence": missing,
                "evidence_basis": basis,
                "confidence": confidence,
                "limitations": list(attempt.get("limitations", []))[:1] or [],
            })
    return records


def sanitize_output(document: object) -> object:
    text = json.dumps(document, sort_keys=True)
    match = FORBIDDEN_OUTPUT_PATTERN.search(text)
    if match:
        raise InputError(f"analysis output contains forbidden verdict wording: {match.group(0)}")
    return document
