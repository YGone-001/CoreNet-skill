#!/usr/bin/env python3
"""Bounded IMS SDP Offer/Answer signaling evidence model.

This Domain consumes accepted SIP Event, IMS Session Analysis and SDP Analysis
artifacts. It does not decode SIP packets, rebuild transactions or dialogs, or
parse SDP bodies again. Associations are established only through exact,
capture-scoped SIP Event references and accepted branch identity.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SKILLS = HERE.parents[2]
SIP_SCRIPTS = SKILLS / "protocol" / "sip" / "scripts"
SDP_SCRIPTS = SKILLS / "protocol" / "sdp-rtp" / "scripts"
IMS_SESSION_SCRIPTS = HERE.parents[1] / "ims-session" / "scripts"
for path in (SIP_SCRIPTS, SDP_SCRIPTS, IMS_SESSION_SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import ims_session_model  # noqa: E402
import sdp_model  # noqa: E402
import sip_model  # noqa: E402

ANALYSIS_NAME = "ims-media-signaling"
ANALYSIS_VERSION = "0.2.0"
DOMAIN = "ims-media-signaling"
CAPABILITY = "bounded IMS SDP offer/answer signaling evidence"

SIP_EVENT_SCHEMA_VERSION = sip_model.EVENT_SCHEMA_VERSION
SDP_ANALYSIS_NAME = sdp_model.ANALYSIS_NAME
SDP_ANALYSIS_VERSION = sdp_model.ANALYSIS_VERSION
SDP_EVENT_SCHEMA_VERSION = sdp_model.EVENT_SCHEMA_VERSION
SDP_PARSER_VERSION = getattr(sdp_model, "PARSER_VERSION", "0.1.0")
IMS_SESSION_ANALYSIS_VERSION = ims_session_model.ANALYSIS_VERSION

EVENT_REFERENCE_PATTERN = re.compile(r"^sip-event:.+:[0-9]+\.[0-9]+$")
SDP_REFERENCE_PATTERN = re.compile(r"^[a-z][a-z0-9-]*:.+:[0-9]+\.[0-9]+$")
FRAME_REFERENCE_PATTERN = re.compile(r"^frame-([0-9]+)$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

MAX_EXCHANGES = 64
MAX_UNBOUND = 64

ASSOCIATION_STATUSES = (
    "ESTABLISHED",
    "NOT_ESTABLISHED",
    "INSUFFICIENT_EVIDENCE",
    "AMBIGUOUS",
    "OUT_OF_SCOPE",
)
BRANCH_IDENTITY_STATUSES = (
    "ESTABLISHED",
    "AMBIGUOUS",
    "INSUFFICIENT_EVIDENCE",
    "NOT_ESTABLISHED",
)
INITIAL_SDP_STATES = (
    "ABSENT",
    "OBSERVED_VALID",
    "OBSERVED_INCOMPLETE",
    "OBSERVED_INVALID",
    "UNRESOLVED",
    "OUT_OF_SCOPE",
)
EXCHANGE_TYPES = (
    "INITIAL_INVITE_SDP_OFFER",
    "INITIAL_INVITE_OFFER_ANSWER",
    "INITIAL_INVITE_WITHOUT_SDP",
    "INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE",
    "LATE_OFFER_ANSWER",
)
BRANCH_SCOPED_EXCHANGE_TYPES = ("INITIAL_INVITE_OFFER_ANSWER", "LATE_OFFER_ANSWER")
OBSERVATION_TYPES = (
    "PROVISIONAL_SDP_UNINTERPRETED",
    "UNSUPPORTED_SDP_OBSERVATION",
    "UNBOUND_SIP_SDP_EVENT",
    "UNMATCHED_SDP_MESSAGE",
)
SDP_EVIDENCE_STATUSES = ("OBSERVED", "INCOMPLETE", "AMBIGUOUS", "UNSUPPORTED", "INVALID")
OUT_OF_SCOPE_METHODS = frozenset(
    {"UPDATE", "PRACK", "INFO", "MESSAGE", "REFER", "BYE", "CANCEL", "ACK", "NOTIFY", "SUBSCRIBE"}
)
STATUS_PRECEDENCE = {
    "ESTABLISHED": 0,
    "INSUFFICIENT_EVIDENCE": 1,
    "NOT_ESTABLISHED": 2,
    "AMBIGUOUS": 3,
    "OUT_OF_SCOPE": 4,
}

PRIVATE_BODY_MARKERS = (
    "sdp_body",
    "raw_sdp",
    "call_id",
    "from_tag",
    "to_tag",
    "sip_uri",
    "ice_password",
    "fingerprint_value",
    "authorization",
)

BASE_LIMITATIONS = (
    "Association evidence is limited to exact capture-scoped SIP Event references supplied by the accepted SIP Protocol Skill",
    "SDP structural evidence is consumed from the accepted sdp-rtp analysis contract and is not reparsed here",
    "An established offer/answer pair requires accepted Dialog and branch identity; missing identity is never promoted",
    "An observed offer/answer pair does not prove SDP negotiation compatibility, media delivery, two-way audio or IMS service success",
    "Reliable provisional response evidence (100rel, RSeq, RAck) is not exposed by the accepted SIP Event contract and is not interpreted",
    "Provisional SDP in the same branch keeps a final-response answer role unresolved instead of assuming a unique final answer",
    "PRACK, re-INVITE, UPDATE, INFO and arbitrary multipart bodies remain outside the supported initial Offer/Answer scope",
    "The SIP Event contract does not publish an independent capture SHA-256; the SIP Event file SHA-256 and the capture SHA-256 are distinct identities",
    "The accepted SDP contract does not define a canonical frame_reference format; only presence and frame-<n> consistency are validated",
)

NOT_CONFIRMED = (
    "SDP_NEGOTIATION_COMPATIBILITY",
    "MEDIA_DELIVERY",
    "RTP_DELIVERY",
    "TWO_WAY_AUDIO",
    "EARLY_MEDIA_DELIVERY",
    "IMS_CALL_SUCCESS",
    "SESSION_MODIFICATION",
    "MEDIA_QOS",
    "IMS_MEDIA_SESSION",
    "RELIABLE_PROVISIONAL_OFFER_ANSWER",
)


class InputError(ValueError):
    """Deterministic, reportable input contract failure."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        raise InputError(f"{label} could not be read") from None
    except json.JSONDecodeError as exc:
        raise InputError(f"{label} is not valid JSON: {exc}") from None
    if not isinstance(document, dict):
        raise InputError(f"{label} must be a JSON object")
    return document


def _reference_suffix(reference: str) -> str:
    marker = reference.find(":")
    return reference[marker + 1 :]


def _parse_reference(reference: str, label: str) -> tuple[str, int, int]:
    try:
        _, rest = reference.split(":", 1)
        capture, frame_occurrence = rest.rsplit(":", 1)
        frame_text, occurrence_text = frame_occurrence.split(".", 1)
        return capture, int(frame_text), int(occurrence_text)
    except (ValueError, AttributeError):
        raise InputError(f"{label} source reference is malformed") from None


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _merge_status(left: str, right: str) -> str:
    return left if STATUS_PRECEDENCE[left] >= STATUS_PRECEDENCE[right] else right


def load_events(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        raise InputError("SIP events could not be read") from None
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputError(f"SIP event line {line_number} is not valid JSON: {exc}") from None
        if not isinstance(event, dict):
            raise InputError(f"SIP event line {line_number} is not an object")
        _validate_event(event, line_number)
        events.append(event)
    if not events:
        raise InputError("SIP events artifact contains no events")
    references = [event["source_reference"] for event in events]
    if len(set(references)) != len(references):
        raise InputError("SIP Event source references are not unique")
    captures = {event["capture_file"] for event in events}
    if len(captures) != 1:
        raise InputError("SIP Events mix capture identity")
    return events


def _validate_event(event: dict[str, Any], line_number: int) -> None:
    for key in (
        "event_schema_version",
        "capture_file",
        "frame_number",
        "message_occurrence",
        "source_reference",
        "message_type",
        "method",
        "status_code",
        "status_code_valid",
        "headers",
        "body_present",
        "message_completeness",
        "extraction_status",
    ):
        if key not in event:
            raise InputError(f"SIP event line {line_number} is missing {key}")
    if event["event_schema_version"] != SIP_EVENT_SCHEMA_VERSION:
        raise InputError("SIP Event schema version is not accepted")
    if not isinstance(event["source_reference"], str) or not EVENT_REFERENCE_PATTERN.fullmatch(
        event["source_reference"]
    ):
        raise InputError(f"SIP event line {line_number} has an invalid source reference")
    if event["source_reference"].split(":", 2)[1] != event["capture_file"]:
        raise InputError("SIP Event source reference capture identity is inconsistent")
    if not isinstance(event["capture_file"], str) or not event["capture_file"]:
        raise InputError("SIP Event capture_file is invalid")
    if isinstance(event["frame_number"], bool) or not isinstance(event["frame_number"], int) or event["frame_number"] < 1:
        raise InputError("SIP Event frame_number is invalid")
    if (
        isinstance(event["message_occurrence"], bool)
        or not isinstance(event["message_occurrence"], int)
        or event["message_occurrence"] < 1
    ):
        raise InputError("SIP Event message_occurrence is invalid")
    if event["message_type"] not in {"REQUEST", "RESPONSE", "UNKNOWN"}:
        raise InputError("SIP Event message_type is invalid")
    headers = event["headers"]
    if not isinstance(headers, dict) or not isinstance(headers.get("content_type"), (str, type(None))):
        raise InputError("SIP Event headers are invalid")
    if not isinstance(event["body_present"], bool):
        raise InputError("SIP Event body_present is invalid")
    if not isinstance(event["status_code_valid"], bool):
        raise InputError("SIP Event status_code_valid is invalid")
    if event["message_completeness"] not in {"COMPLETE", "INCOMPLETE", "MALFORMED", "TRUNCATED", "UNKNOWN"}:
        raise InputError("SIP Event message completeness is invalid")
    if event["extraction_status"] not in {"OBSERVED", "PARTIAL", "MALFORMED", "UNSUPPORTED"}:
        raise InputError("SIP Event extraction status is invalid")


def load_session_analysis(path: Path, event_references: set[str]) -> dict[str, Any]:
    document = _load_json(path, "IMS Session analysis")
    try:
        ims_session_model.validate_analysis(document, event_references=event_references)
    except ims_session_model.InputError as exc:
        raise InputError(f"IMS Session analysis is not accepted: {exc}") from None
    if document.get("analysis_version") != IMS_SESSION_ANALYSIS_VERSION:
        raise InputError("IMS Session analysis_version is not accepted")
    return document


def _validate_sdp_message_provenance(
    message: dict[str, Any], root_capture: str, root_sha256: str
) -> None:
    reference = message.get("source_reference")
    if not isinstance(reference, str) or not SDP_REFERENCE_PATTERN.fullmatch(reference):
        raise InputError("an SDP source reference is invalid")
    if message.get("capture_file") != root_capture:
        raise InputError("an SDP message capture_file disagrees with the SDP root capture identity")
    if message.get("capture_sha256") != root_sha256:
        raise InputError("an SDP message capture_sha256 disagrees with the SDP root capture SHA-256")
    frame_number = message.get("frame_number")
    if isinstance(frame_number, bool) or not isinstance(frame_number, int) or frame_number < 1:
        raise InputError("an SDP message frame_number is invalid")
    occurrence = message.get("message_occurrence")
    if isinstance(occurrence, bool) or not isinstance(occurrence, int) or occurrence < 1:
        raise InputError("an SDP message message_occurrence is invalid")
    capture, reference_frame, reference_occurrence = _parse_reference(reference, "SDP message")
    if capture != message.get("capture_file"):
        raise InputError("an SDP source reference capture identity disagrees with capture_file")
    if reference_frame != frame_number:
        raise InputError("an SDP source reference frame disagrees with frame_number")
    if reference_occurrence != occurrence:
        raise InputError("an SDP source reference occurrence disagrees with message_occurrence")
    frame_reference = message.get("frame_reference")
    if not isinstance(frame_reference, str) or not frame_reference:
        raise InputError("an SDP message frame_reference is missing")
    match = FRAME_REFERENCE_PATTERN.fullmatch(frame_reference)
    if match is not None and int(match.group(1)) != frame_number:
        raise InputError("an SDP message frame_reference disagrees with frame_number")
    if message.get("evidence_status") not in SDP_EVIDENCE_STATUSES:
        raise InputError("an SDP message has an invalid evidence status")


def load_sdp_analysis(path: Path) -> dict[str, Any]:
    document = _load_json(path, "SDP analysis")
    try:
        sdp_model.validate_analysis(document)
    except sdp_model.InputError as exc:
        raise InputError(f"SDP analysis is not accepted: {exc}") from None
    if document.get("analysis_name") != SDP_ANALYSIS_NAME:
        raise InputError("SDP analysis_name is not accepted")
    if document.get("analysis_version") != SDP_ANALYSIS_VERSION:
        raise InputError("SDP analysis_version is not accepted")
    if document.get("event_schema_version") != SDP_EVENT_SCHEMA_VERSION:
        raise InputError("SDP event schema version is not accepted")
    messages = document.get("messages")
    if not isinstance(messages, list) or not messages:
        raise InputError("SDP analysis must publish at least one message")
    if document.get("message_count") != len(messages):
        raise InputError("SDP message_count does not match the message array")
    provenance = document.get("input_provenance")
    if not isinstance(provenance, dict):
        raise InputError("SDP analysis input_provenance is missing")
    captures = provenance.get("capture_files")
    if not isinstance(captures, list) or len(captures) != 1 or not isinstance(captures[0], str) or not captures[0]:
        raise InputError("SDP analysis must publish exactly one capture identity")
    root_capture = captures[0]
    root_sha256 = provenance.get("capture_sha256")
    if not isinstance(root_sha256, str) or not SHA256_PATTERN.fullmatch(root_sha256):
        raise InputError("SDP analysis root capture_sha256 is malformed")
    if provenance.get("message_count") != len(messages):
        raise InputError("SDP input_provenance message_count does not match the message array")
    references: list[str] = []
    for message in messages:
        if not isinstance(message, dict):
            raise InputError("an SDP message is not an object")
        if message.get("parser_version") not in (None, SDP_PARSER_VERSION):
            raise InputError("an SDP message parser_version is not accepted")
        _validate_sdp_message_provenance(message, root_capture, root_sha256)
        references.append(message["source_reference"])
    if len(set(references)) != len(references):
        raise InputError("SDP source references are not unique")
    return document


def _collect_references(value: Any, prefix: str) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        if value.startswith(prefix):
            found.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            found.extend(_collect_references(item, prefix))
    elif isinstance(value, list):
        for item in value:
            found.extend(_collect_references(item, prefix))
    return found


def verify_provenance(
    events: list[dict[str, Any]],
    session: dict[str, Any],
    sdp: dict[str, Any],
    *,
    events_path: Path,
    session_path: Path,
    sdp_path: Path,
) -> dict[str, Any]:
    capture = events[0]["capture_file"]
    event_sha256 = _sha256(events_path)
    event_references = {event["source_reference"] for event in events}
    if set(_collect_references(session, "sip-event:")) - event_references:
        raise InputError("IMS Session analysis references a missing SIP Event")
    session_provenance = session.get("input_provenance") or {}
    session_captures = session_provenance.get("capture_files") or []
    if session_captures != [capture]:
        raise InputError("IMS Session analysis capture identity does not match the SIP Events")
    if session_provenance.get("event_source_name") != events_path.name:
        raise InputError("IMS Session event source name does not match the supplied SIP Events")
    if session_provenance.get("event_sha256") != event_sha256:
        raise InputError("IMS Session event SHA-256 does not match the supplied SIP Events")
    if session_provenance.get("event_schema_version") != SIP_EVENT_SCHEMA_VERSION:
        raise InputError("IMS Session event schema version is not accepted")
    sdp_provenance = sdp.get("input_provenance") or {}
    sdp_captures = sdp_provenance.get("capture_files") or []
    if sdp_captures != [capture]:
        raise InputError("SDP analysis capture identity does not match the SIP Events")
    root_sha256 = sdp_provenance.get("capture_sha256")
    for message in sdp.get("messages") or []:
        if message.get("capture_file") != capture:
            raise InputError("an SDP message mixes capture identity")
        message_capture = message.get("source_reference", "").split(":", 1)[1].rsplit(":", 1)[0]
        if message_capture != capture:
            raise InputError("an SDP source reference capture identity is inconsistent")
        if message.get("capture_sha256") != root_sha256:
            raise InputError("an SDP message capture SHA-256 is inconsistent with the SDP root")
    return {
        "capture_files": [capture],
        "sip_event_source_name": events_path.name,
        "sip_event_sha256": event_sha256,
        "sip_event_schema_version": SIP_EVENT_SCHEMA_VERSION,
        "ims_session_source_name": session_path.name,
        "ims_session_sha256": _sha256(session_path),
        "ims_session_analysis_version": session.get("analysis_version"),
        "sdp_analysis_source_name": sdp_path.name,
        "sdp_analysis_sha256": _sha256(sdp_path),
        "sdp_analysis_version": sdp.get("analysis_version"),
        "sdp_event_schema_version": sdp.get("event_schema_version"),
        "sdp_capture_sha256": root_sha256,
        "capture_identity_source": "SIP_EVENT_CAPTURE_FILE",
        "input_status": "ACCEPTED",
    }


def _sdp_result(
    event_reference: str,
    events_by_reference: dict[str, dict[str, Any]],
    sdp_by_reference: dict[str, dict[str, Any]],
    capture: str,
) -> tuple[str, str | None, dict[str, Any] | None]:
    event = events_by_reference.get(event_reference)
    if event is None:
        return ("NOT_ESTABLISHED", "SIP_EVENT_NOT_FOUND", None)
    if event.get("capture_file") != capture:
        return ("NOT_ESTABLISHED", "CAPTURE_IDENTITY_MISMATCH", None)
    message = sdp_by_reference.get(event_reference)
    if message is not None:
        if message.get("frame_number") != event.get("frame_number"):
            return ("NOT_ESTABLISHED", "FRAME_REFERENCE_MISMATCH", None)
        if message.get("message_occurrence") != event.get("message_occurrence"):
            return ("NOT_ESTABLISHED", "MESSAGE_OCCURRENCE_MISMATCH", None)
    if not event.get("body_present"):
        return ("NOT_ESTABLISHED", "SIP_BODY_NOT_PRESENT", None)
    content_type = (event.get("headers") or {}).get("content_type")
    if not isinstance(content_type, str) or content_type.strip().lower() != "application/sdp":
        return ("NOT_ESTABLISHED", "SIP_CONTENT_TYPE_NOT_SDP", None)
    if event.get("message_completeness") != "COMPLETE" or event.get("extraction_status") != "OBSERVED":
        return ("INSUFFICIENT_EVIDENCE", "SIP_MESSAGE_INCOMPLETE", None)
    if message is None:
        return ("INSUFFICIENT_EVIDENCE", "SDP_MESSAGE_NOT_OBSERVED", None)
    status = message.get("evidence_status")
    if status == "INCOMPLETE":
        return ("INSUFFICIENT_EVIDENCE", "SDP_MESSAGE_INCOMPLETE", message)
    if status == "INVALID":
        return ("INSUFFICIENT_EVIDENCE", "SDP_MESSAGE_INVALID", message)
    if status == "UNSUPPORTED":
        return ("OUT_OF_SCOPE", "SDP_MESSAGE_UNSUPPORTED", message)
    if status != "OBSERVED":
        return ("INSUFFICIENT_EVIDENCE", "SDP_MESSAGE_NOT_OBSERVED", message)
    return ("ESTABLISHED", None, message)


def _classify_initial_sdp(
    reference: str,
    events_by_reference: dict[str, dict[str, Any]],
    sdp_by_reference: dict[str, dict[str, Any]],
    capture: str,
) -> tuple[str, str | None, dict[str, Any] | None]:
    event = events_by_reference.get(reference)
    if event is None:
        return ("UNRESOLVED", "SIP_EVENT_NOT_FOUND", None)
    if event.get("capture_file") != capture:
        return ("UNRESOLVED", "CAPTURE_IDENTITY_MISMATCH", None)
    if not _is_invite(event):
        return ("UNRESOLVED", "INITIAL_INVITE_INVALID", None)
    message = sdp_by_reference.get(reference)
    headers = event.get("headers") or {}
    body_present = bool(event.get("body_present"))
    content_type = headers.get("content_type")
    declares_sdp = isinstance(content_type, str) and content_type.strip().lower() == "application/sdp"
    if not body_present:
        if message is not None:
            return ("UNRESOLVED", "SDP_SOURCE_REFERENCE_MISMATCH", message)
        if event.get("message_completeness") != "COMPLETE" or event.get("extraction_status") != "OBSERVED":
            return ("UNRESOLVED", "SIP_MESSAGE_INCOMPLETE", None)
        if headers.get("content_length") != 0:
            return ("UNRESOLVED", "SIP_BODY_LENGTH_NOT_PROVEN", None)
        body_length = headers.get("body_length")
        if body_length is not None and body_length != 0:
            return ("UNRESOLVED", "SIP_BODY_LENGTH_NOT_PROVEN", None)
        return ("ABSENT", None, None)
    if not declares_sdp:
        return ("OUT_OF_SCOPE", "SIP_CONTENT_TYPE_NOT_SDP", message)
    if event.get("message_completeness") != "COMPLETE" or event.get("extraction_status") != "OBSERVED":
        return ("OBSERVED_INCOMPLETE", "SIP_MESSAGE_INCOMPLETE", message)
    if message is None:
        return ("UNRESOLVED", "SDP_MESSAGE_NOT_OBSERVED", None)
    if message.get("frame_number") != event.get("frame_number"):
        return ("UNRESOLVED", "FRAME_REFERENCE_MISMATCH", message)
    if message.get("message_occurrence") != event.get("message_occurrence"):
        return ("UNRESOLVED", "MESSAGE_OCCURRENCE_MISMATCH", message)
    status = message.get("evidence_status")
    if status == "OBSERVED":
        return ("OBSERVED_VALID", None, message)
    if status == "INCOMPLETE":
        return ("OBSERVED_INCOMPLETE", "SDP_MESSAGE_INCOMPLETE", message)
    if status == "INVALID":
        return ("OBSERVED_INVALID", "SDP_MESSAGE_INVALID", message)
    if status == "UNSUPPORTED":
        return ("OUT_OF_SCOPE", "SDP_MESSAGE_UNSUPPORTED", message)
    return ("UNRESOLVED", "SDP_MESSAGE_NOT_OBSERVED", message)


def _response_role_status(event: dict[str, Any] | None) -> tuple[bool, str | None]:
    if event is None:
        return (False, "SIP_EVENT_NOT_FOUND")
    if event.get("message_type") != "RESPONSE":
        return (False, "RESPONSE_MESSAGE_TYPE_INVALID")
    if event.get("status_code_valid") is not True:
        return (False, "RESPONSE_STATUS_INVALID")
    status = event.get("status_code")
    if not isinstance(status, int) or isinstance(status, bool) or not 200 <= status < 300:
        return (False, "RESPONSE_STATUS_INVALID")
    headers = event.get("headers") or {}
    if (headers.get("cseq") or {}).get("method") != "INVITE":
        return (False, "RESPONSE_CSEQ_METHOD_NOT_INVITE")
    if event.get("message_completeness") != "COMPLETE" or event.get("extraction_status") != "OBSERVED":
        return (False, "SIP_MESSAGE_INCOMPLETE")
    return (True, None)


def _branch_gate(
    branch: dict[str, Any],
    response_reference: str,
    owners: dict[str, set[int]],
) -> tuple[str, list[str], list[str]]:
    missing: list[str] = []
    conflicts: list[str] = []
    branch_reference = branch.get("branch_reference")
    if not isinstance(branch_reference, str) or not branch_reference:
        missing.append("BRANCH_REFERENCE_MISSING")
    dialog_reference = branch.get("dialog_reference")
    dialog_state = branch.get("dialog_state")
    if not isinstance(dialog_reference, str) or not dialog_reference or dialog_state != "CONFIRMED":
        missing.append("DIALOG_IDENTITY_NOT_ESTABLISHED")
    identity_status = branch.get("identity_status")
    if identity_status == "ESTABLISHED":
        pass
    elif identity_status == "AMBIGUOUS":
        missing.append("BRANCH_IDENTITY_NOT_ESTABLISHED")
        conflicts.append("COMPETING_BRANCH_OWNERSHIP")
    else:
        missing.append("BRANCH_IDENTITY_NOT_ESTABLISHED")
    if response_reference not in (branch.get("response_event_references") or []):
        missing.append("BRANCH_RESPONSE_OWNERSHIP_UNPROVEN")
    if len(owners.get(response_reference) or ()) > 1:
        conflicts.append("COMPETING_BRANCH_OWNERSHIP")
    status = "ESTABLISHED"
    if conflicts:
        status = "AMBIGUOUS"
    elif missing:
        status = "INSUFFICIENT_EVIDENCE"
    return (status, missing, conflicts)


def _exchange(
    reference: str,
    attempt: dict[str, Any],
    exchange_type: str,
    association_status: str,
    initial_sdp_state: str,
    *,
    branch: dict[str, Any] | None = None,
    offer_event_reference: str | None = None,
    offer_sdp_reference: str | None = None,
    answer_event_reference: str | None = None,
    answer_sdp_reference: str | None = None,
    branch_identity_status: str | None = None,
    missing: list[str] | None = None,
    conflicts: list[str] | None = None,
) -> dict[str, Any]:
    established = association_status == "ESTABLISHED"
    return {
        "exchange_reference": reference,
        "attempt_reference": attempt["attempt_reference"],
        "initial_invite_transaction_reference": attempt["initial_invite_transaction_reference"],
        "branch_reference": branch.get("branch_reference") if branch else None,
        "dialog_reference": branch.get("dialog_reference") if branch else None,
        "branch_identity_status": branch_identity_status,
        "exchange_type": exchange_type,
        "initial_sdp_state": initial_sdp_state,
        "association_status": association_status,
        "offer_event_reference": offer_event_reference,
        "offer_sdp_reference": offer_sdp_reference,
        "offer_role": "OFFERER" if established and offer_event_reference else None,
        "answer_event_reference": answer_event_reference,
        "answer_sdp_reference": answer_sdp_reference,
        "answer_role": "ANSWERER" if established and answer_event_reference else None,
        "negotiation_compatibility": "NOT_EVALUATED",
        "missing_evidence": _unique(missing or [])[:16],
        "conflict_findings": _unique(conflicts or [])[:16],
        "evidence_class": "DERIVED",
    }


def _observation(
    reference: str,
    observation_type: str,
    association_status: str,
    reason: str,
    *,
    sip_event_reference: str | None = None,
    sdp_reference: str | None = None,
    attempt: dict[str, Any] | None = None,
    branch: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "observation_reference": reference,
        "observation_type": observation_type,
        "association_status": association_status,
        "reason_code": reason,
        "sip_event_reference": sip_event_reference,
        "sdp_reference": sdp_reference,
        "attempt_reference": attempt.get("attempt_reference") if attempt else None,
        "branch_reference": branch.get("branch_reference") if branch else None,
        "dialog_reference": branch.get("dialog_reference") if branch else None,
        "evidence_class": "DERIVED",
    }


def _is_invite(event: dict[str, Any] | None) -> bool:
    if event is None:
        return False
    headers = event.get("headers") or {}
    cseq_method = (headers.get("cseq") or {}).get("method")
    return (
        event.get("message_type") == "REQUEST"
        and event.get("method") == "INVITE"
        and cseq_method == "INVITE"
    )


def _is_ack(event: dict[str, Any] | None) -> bool:
    if event is None:
        return False
    headers = event.get("headers") or {}
    cseq_method = (headers.get("cseq") or {}).get("method")
    return (
        event.get("message_type") == "REQUEST"
        and event.get("method") == "ACK"
        and cseq_method == "ACK"
    )


def _status(event: dict[str, Any] | None) -> int | None:
    if event is None:
        return None
    value = event.get("status_code")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _to_tagged(event: dict[str, Any] | None) -> bool:
    if event is None:
        return False
    return bool((event.get("headers") or {}).get("to", {}).get("tag_present"))


def _branch_exchange_reference(
    attempt: dict[str, Any],
    branch: dict[str, Any],
    candidates: list[str],
    events_by_reference: dict[str, dict[str, Any]],
) -> str:
    dialog = branch.get("dialog_reference")
    if isinstance(dialog, str) and dialog:
        return f"{ANALYSIS_NAME}:{_reference_suffix(dialog)}"
    for reference in candidates:
        if reference in events_by_reference:
            return f"{ANALYSIS_NAME}:{_reference_suffix(reference)}"
    return f"{ANALYSIS_NAME}:{_reference_suffix(attempt['initial_invite_event_reference'])}"


def _branch_owners(session: dict[str, Any]) -> dict[str, set[int]]:
    owners: dict[str, set[int]] = {}
    for attempt in session.get("session_attempts") or []:
        for branch in attempt.get("branches") or []:
            for reference in list(branch.get("response_event_references") or []) + list(
                branch.get("ack_event_references") or []
            ):
                owners.setdefault(reference, set()).add(id(branch))
    return owners


def build_analysis(
    events: list[dict[str, Any]],
    session: dict[str, Any],
    sdp: dict[str, Any],
    *,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    capture = events[0]["capture_file"]
    events_by_reference = {event["source_reference"]: event for event in events}
    sdp_by_reference = {message["source_reference"]: message for message in sdp.get("messages") or []}
    owners = _branch_owners(session)
    exchanges: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    consumed: set[str] = set()
    exchange_references: set[str] = set()

    def publish(exchange: dict[str, Any]) -> None:
        reference = exchange["exchange_reference"]
        if reference in exchange_references:
            observations.append(
                _observation(
                    reference,
                    "UNSUPPORTED_SDP_OBSERVATION",
                    "AMBIGUOUS",
                    "BRANCH_ASSOCIATION_AMBIGUOUS",
                    sip_event_reference=exchange.get("offer_event_reference"),
                    sdp_reference=exchange.get("offer_sdp_reference"),
                )
            )
            return
        exchange_references.add(reference)
        exchanges.append(exchange)

    def observe_branch_answer(
        attempt: dict[str, Any],
        branch: dict[str, Any],
        reference: str,
        status: str,
        reason: str,
        suffix: str,
    ) -> None:
        observations.append(
            _observation(
                f"{ANALYSIS_NAME}:{_reference_suffix(reference)}-{suffix}",
                "UNBOUND_SIP_SDP_EVENT",
                status if status in ASSOCIATION_STATUSES else "INSUFFICIENT_EVIDENCE",
                reason,
                sip_event_reference=reference,
                sdp_reference=reference,
                attempt=attempt,
                branch=branch,
            )
        )

    for attempt in session.get("session_attempts") or []:
        initial_reference = attempt["initial_invite_event_reference"]
        state, initial_reason, initial_message = _classify_initial_sdp(
            initial_reference, events_by_reference, sdp_by_reference, capture
        )
        offer_event_reference: str | None = None
        offer_sdp_reference: str | None = None
        allow_late_offer = False
        if state == "ABSENT":
            publish(
                _exchange(
                    f"{ANALYSIS_NAME}:{_reference_suffix(initial_reference)}",
                    attempt,
                    "INITIAL_INVITE_WITHOUT_SDP",
                    "NOT_ESTABLISHED",
                    state,
                )
            )
            allow_late_offer = True
        elif state == "OBSERVED_VALID":
            offer_event_reference = initial_reference
            offer_sdp_reference = initial_reference
            consumed.add(initial_reference)
        else:
            status = "OUT_OF_SCOPE" if state == "OUT_OF_SCOPE" else "INSUFFICIENT_EVIDENCE"
            if initial_message is not None:
                offer_event_reference = initial_reference
                offer_sdp_reference = initial_reference
                consumed.add(initial_reference)
            publish(
                _exchange(
                    f"{ANALYSIS_NAME}:{_reference_suffix(initial_reference)}",
                    attempt,
                    "INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE",
                    status,
                    state,
                    offer_event_reference=offer_event_reference,
                    offer_sdp_reference=offer_sdp_reference,
                    missing=[initial_reason] if initial_reason else [],
                )
            )
            observations.append(
                _observation(
                    f"{ANALYSIS_NAME}:{_reference_suffix(initial_reference)}-offer",
                    "UNSUPPORTED_SDP_OBSERVATION",
                    status,
                    initial_reason or "SDP_MESSAGE_NOT_OBSERVED",
                    sip_event_reference=initial_reference,
                    sdp_reference=initial_reference if initial_message is not None else None,
                    attempt=attempt,
                )
            )

        if state not in ("ABSENT", "OBSERVED_VALID"):
            for branch in attempt.get("branches") or []:
                for reference in branch.get("response_event_references") or []:
                    branch_status, _reason, _message = _sdp_result(
                        reference, events_by_reference, sdp_by_reference, capture
                    )
                    if branch_status == "ESTABLISHED":
                        consumed.add(reference)
                        observe_branch_answer(
                            attempt,
                            branch,
                            reference,
                            "INSUFFICIENT_EVIDENCE",
                            "INITIAL_SDP_EVIDENCE_UNUSABLE",
                            "initial-unusable",
                        )
            continue

        attempt_exchange_floor = len(exchanges)

        for branch in attempt.get("branches") or []:
            response_references = list(branch.get("response_event_references") or [])
            accepted_candidates: list[str] = []
            provisional_candidates: list[str] = []
            rejected_candidates: list[str] = []
            for reference in response_references:
                status = _status(events_by_reference.get(reference))
                branch_status, _reason, _message = _sdp_result(
                    reference, events_by_reference, sdp_by_reference, capture
                )
                if branch_status != "ESTABLISHED":
                    continue
                consumed.add(reference)
                if status is not None and 100 <= status < 200:
                    provisional_candidates.append(reference)
                elif status is not None and 200 <= status < 300:
                    accepted_candidates.append(reference)
                else:
                    rejected_candidates.append(reference)
            for reference in provisional_candidates:
                observations.append(
                    _observation(
                        f"{ANALYSIS_NAME}:{_reference_suffix(reference)}-provisional",
                        "PROVISIONAL_SDP_UNINTERPRETED",
                        "OUT_OF_SCOPE",
                        "PROVISIONAL_SDP_RELIABILITY_NOT_PROVEN",
                        sip_event_reference=reference,
                        sdp_reference=reference,
                        attempt=attempt,
                        branch=branch,
                    )
                )
            for reference in rejected_candidates:
                observations.append(
                    _observation(
                        f"{ANALYSIS_NAME}:{_reference_suffix(reference)}-non2xx",
                        "UNSUPPORTED_SDP_OBSERVATION",
                        "OUT_OF_SCOPE",
                        "NON_2XX_FINAL_SDP_OUT_OF_SCOPE",
                        sip_event_reference=reference,
                        sdp_reference=reference,
                        attempt=attempt,
                        branch=branch,
                    )
                )

            if branch.get("outcome") != "ACCEPTED_2XX":
                continue
            exchange_reference = _branch_exchange_reference(
                attempt, branch, accepted_candidates + response_references, events_by_reference
            )
            exchange_type = "INITIAL_INVITE_OFFER_ANSWER" if state == "OBSERVED_VALID" else "LATE_OFFER_ANSWER"

            if state == "OBSERVED_VALID":
                if not accepted_candidates:
                    gate_status, gate_missing, gate_conflicts = _branch_gate(
                        branch, response_references[-1] if response_references else initial_reference, owners
                    )
                    publish(
                        _exchange(
                            exchange_reference,
                            attempt,
                            exchange_type,
                            "INSUFFICIENT_EVIDENCE",
                            state,
                            branch=branch,
                            offer_event_reference=offer_event_reference,
                            offer_sdp_reference=offer_sdp_reference,
                            branch_identity_status=gate_status,
                            missing=_unique(gate_missing + ["SDP_ANSWER_NOT_OBSERVED"]),
                            conflicts=gate_conflicts,
                        )
                    )
                    continue
                if len(accepted_candidates) > 1:
                    publish(
                        _exchange(
                            exchange_reference,
                            attempt,
                            exchange_type,
                            "AMBIGUOUS",
                            state,
                            branch=branch,
                            offer_event_reference=offer_event_reference,
                            offer_sdp_reference=offer_sdp_reference,
                            branch_identity_status="AMBIGUOUS",
                            missing=["SDP_ANSWER_NOT_UNIQUE"],
                            conflicts=["COMPETING_SDP_CANDIDATES"],
                        )
                    )
                    continue
                answer_reference = accepted_candidates[0]
                ok, role_reason = _response_role_status(events_by_reference.get(answer_reference))
                gate_status, gate_missing, gate_conflicts = _branch_gate(branch, answer_reference, owners)
                if not ok:
                    gate_status = _merge_status(gate_status, "INSUFFICIENT_EVIDENCE")
                    gate_missing = gate_missing + [role_reason or "RESPONSE_STATUS_INVALID"]
                if provisional_candidates:
                    gate_status = _merge_status(gate_status, "AMBIGUOUS")
                    gate_conflicts = gate_conflicts + ["PROVISIONAL_FINAL_SDP_ROLE_UNRESOLVED"]
                status = "ESTABLISHED" if gate_status == "ESTABLISHED" else gate_status
                publish(
                    _exchange(
                        exchange_reference,
                        attempt,
                        exchange_type,
                        status,
                        state,
                        branch=branch,
                        offer_event_reference=offer_event_reference,
                        offer_sdp_reference=offer_sdp_reference,
                        answer_event_reference=answer_reference if status == "ESTABLISHED" else None,
                        answer_sdp_reference=answer_reference if status == "ESTABLISHED" else None,
                        branch_identity_status=gate_status,
                        missing=gate_missing,
                        conflicts=gate_conflicts,
                    )
                )
                if status != "ESTABLISHED":
                    observe_branch_answer(
                        attempt,
                        branch,
                        answer_reference,
                        status,
                        (gate_missing + gate_conflicts + ["BRANCH_IDENTITY_NOT_ESTABLISHED"])[0],
                        "branch",
                    )
                continue

            if not accepted_candidates:
                continue
            if len(accepted_candidates) > 1:
                publish(
                    _exchange(
                        exchange_reference,
                        attempt,
                        exchange_type,
                        "AMBIGUOUS",
                        state,
                        branch=branch,
                        conflicts=["COMPETING_SDP_CANDIDATES"],
                    )
                )
                continue
            late_offer_reference = accepted_candidates[0]
            late_ok, late_reason = _response_role_status(events_by_reference.get(late_offer_reference))
            gate_status, gate_missing, gate_conflicts = _branch_gate(branch, late_offer_reference, owners)
            if not late_ok:
                gate_status = _merge_status(gate_status, "INSUFFICIENT_EVIDENCE")
                gate_missing = gate_missing + [late_reason or "RESPONSE_STATUS_INVALID"]
            ack_candidates: list[str] = []
            for reference in branch.get("ack_event_references") or []:
                ack_status, _reason, _message = _sdp_result(
                    reference, events_by_reference, sdp_by_reference, capture
                )
                if ack_status == "ESTABLISHED" and _is_ack(events_by_reference.get(reference)):
                    ack_candidates.append(reference)
            if len(ack_candidates) > 1:
                gate_status = _merge_status(gate_status, "AMBIGUOUS")
                gate_conflicts = gate_conflicts + ["COMPETING_SDP_CANDIDATES"]
            if provisional_candidates:
                gate_status = _merge_status(gate_status, "AMBIGUOUS")
                gate_conflicts = gate_conflicts + ["PROVISIONAL_FINAL_SDP_ROLE_UNRESOLVED"]
            for reference in ack_candidates:
                consumed.add(reference)
            if not ack_candidates:
                gate_status = _merge_status(gate_status, "INSUFFICIENT_EVIDENCE")
                gate_missing = gate_missing + ["LATE_OFFER_ACK_NOT_OBSERVED"]
            status = "ESTABLISHED" if gate_status == "ESTABLISHED" else gate_status
            publish(
                _exchange(
                    exchange_reference,
                    attempt,
                    exchange_type,
                    status,
                    state,
                    branch=branch,
                    offer_event_reference=late_offer_reference,
                    offer_sdp_reference=late_offer_reference,
                    answer_event_reference=ack_candidates[0] if status == "ESTABLISHED" else None,
                    answer_sdp_reference=ack_candidates[0] if status == "ESTABLISHED" else None,
                    branch_identity_status=gate_status,
                    missing=gate_missing,
                    conflicts=gate_conflicts,
                )
            )
            if status != "ESTABLISHED":
                observe_branch_answer(
                    attempt,
                    branch,
                    late_offer_reference,
                    status,
                    (gate_missing + gate_conflicts + ["BRANCH_IDENTITY_NOT_ESTABLISHED"])[0],
                    "branch",
                )

        if (
            state == "OBSERVED_VALID"
            and offer_event_reference is not None
            and len(exchanges) == attempt_exchange_floor
        ):
            publish(
                _exchange(
                    f"{ANALYSIS_NAME}:{_reference_suffix(initial_reference)}",
                    attempt,
                    "INITIAL_INVITE_SDP_OFFER",
                    "ESTABLISHED",
                    state,
                    offer_event_reference=offer_event_reference,
                    offer_sdp_reference=offer_sdp_reference,
                )
            )

    for event in events:
        reference = event["source_reference"]
        if reference in consumed:
            continue
        if event.get("capture_file") != capture:
            continue
        body_present = bool(event.get("body_present"))
        content_type = (event.get("headers") or {}).get("content_type")
        declares_sdp = isinstance(content_type, str) and content_type.strip().lower() == "application/sdp"
        if not body_present and not declares_sdp:
            continue
        has_sdp = reference in sdp_by_reference
        if not declares_sdp and not has_sdp:
            continue
        status = _status(event)
        method = event.get("method")
        if declares_sdp and not has_sdp:
            observations.append(
                _observation(
                    f"{ANALYSIS_NAME}:{_reference_suffix(reference)}-unbound",
                    "UNBOUND_SIP_SDP_EVENT",
                    "INSUFFICIENT_EVIDENCE",
                    "SDP_MESSAGE_NOT_OBSERVED",
                    sip_event_reference=reference,
                )
            )
            continue
        if not declares_sdp:
            observations.append(
                _observation(
                    f"{ANALYSIS_NAME}:{_reference_suffix(reference)}-unbound",
                    "UNBOUND_SIP_SDP_EVENT",
                    "INSUFFICIENT_EVIDENCE",
                    "SIP_CONTENT_TYPE_NOT_SDP",
                    sip_event_reference=reference,
                    sdp_reference=reference,
                )
            )
            continue
        if status is not None and 100 <= status < 200:
            observations.append(
                _observation(
                    f"{ANALYSIS_NAME}:{_reference_suffix(reference)}-unbound",
                    "PROVISIONAL_SDP_UNINTERPRETED",
                    "OUT_OF_SCOPE",
                    "PROVISIONAL_SDP_RELIABILITY_NOT_PROVEN",
                    sip_event_reference=reference,
                    sdp_reference=reference,
                )
            )
            continue
        if method in OUT_OF_SCOPE_METHODS or (method == "INVITE" and _to_tagged(event)):
            observations.append(
                _observation(
                    f"{ANALYSIS_NAME}:{_reference_suffix(reference)}-unbound",
                    "UNSUPPORTED_SDP_OBSERVATION",
                    "OUT_OF_SCOPE",
                    "IN_DIALOG_SDP_OUT_OF_SCOPE",
                    sip_event_reference=reference,
                    sdp_reference=reference,
                )
            )
            continue
        if status is not None and not 200 <= status < 300:
            observations.append(
                _observation(
                    f"{ANALYSIS_NAME}:{_reference_suffix(reference)}-unbound",
                    "UNSUPPORTED_SDP_OBSERVATION",
                    "OUT_OF_SCOPE",
                    "NON_2XX_FINAL_SDP_OUT_OF_SCOPE",
                    sip_event_reference=reference,
                    sdp_reference=reference,
                )
            )
            continue
        observations.append(
            _observation(
                f"{ANALYSIS_NAME}:{_reference_suffix(reference)}-unbound",
                "UNBOUND_SIP_SDP_EVENT",
                "AMBIGUOUS",
                "BRANCH_ASSOCIATION_AMBIGUOUS",
                sip_event_reference=reference,
                sdp_reference=reference,
            )
        )

    for message in sdp.get("messages") or []:
        reference = message["source_reference"]
        if reference not in events_by_reference:
            observations.append(
                _observation(
                    f"{ANALYSIS_NAME}:{_reference_suffix(reference)}-unmatched",
                    "UNMATCHED_SDP_MESSAGE",
                    "NOT_ESTABLISHED",
                    "SIP_EVENT_NOT_FOUND",
                    sdp_reference=reference,
                )
            )

    observations.sort(key=lambda item: (item["observation_reference"], item["reason_code"]))
    published_exchanges = exchanges[:MAX_EXCHANGES]
    published_observations = observations[:MAX_UNBOUND]
    established = sum(1 for item in published_exchanges if item["association_status"] == "ESTABLISHED")
    incomplete = sum(
        1 for item in published_exchanges if item["association_status"] == "INSUFFICIENT_EVIDENCE"
    )
    ambiguous = sum(1 for item in published_exchanges if item["association_status"] == "AMBIGUOUS")
    not_established = sum(
        1 for item in published_exchanges if item["association_status"] == "NOT_ESTABLISHED"
    )
    out_of_scope = sum(
        1 for item in published_observations if item["association_status"] == "OUT_OF_SCOPE"
    )
    matched = sum(1 for message in sdp.get("messages") or [] if message["source_reference"] in events_by_reference)
    supplied = len(sdp.get("messages") or [])
    return {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "domain": DOMAIN,
        "capability": CAPABILITY,
        "input_provenance": provenance,
        "exchange_count": len(published_exchanges),
        "exchanges": published_exchanges,
        "unbound_observation_count": len(published_observations),
        "unbound_observations": published_observations,
        "completeness": {
            "supplied_sdp_message_count": supplied,
            "matched_sip_event_count": matched,
            "unmatched_sdp_message_count": supplied - matched,
            "observed_offer_count": sum(1 for item in published_exchanges if item["offer_sdp_reference"]),
            "observed_answer_count": sum(1 for item in published_exchanges if item["answer_sdp_reference"]),
            "established_exchange_count": established,
            "not_established_exchange_count": not_established,
            "incomplete_exchange_count": incomplete,
            "ambiguous_exchange_count": ambiguous,
            "out_of_scope_observation_count": out_of_scope,
            "omitted_observation_count": (len(exchanges) - len(published_exchanges))
            + (len(observations) - len(published_observations)),
        },
        "limitations": list(BASE_LIMITATIONS),
        "not_confirmed": list(NOT_CONFIRMED),
    }


def validate_analysis(
    document: dict[str, Any],
    *,
    event_references: set[str] | None = None,
    sdp_references: set[str] | None = None,
) -> None:
    if not isinstance(document, dict):
        raise InputError("IMS media signaling analysis must be an object")
    if document.get("analysis_name") != ANALYSIS_NAME:
        raise InputError("analysis_name is not accepted")
    if document.get("analysis_version") != ANALYSIS_VERSION:
        raise InputError("analysis_version is not accepted")
    if document.get("domain") != DOMAIN:
        raise InputError("domain is not accepted")
    known_events = event_references or set()
    known_sdp = sdp_references or set()
    exchanges = document.get("exchanges")
    observations = document.get("unbound_observations")
    if not isinstance(exchanges, list) or not isinstance(observations, list):
        raise InputError("exchanges and unbound observations must be arrays")
    if document.get("exchange_count") != len(exchanges):
        raise InputError("exchange_count does not match the exchange array")
    if document.get("unbound_observation_count") != len(observations):
        raise InputError("unbound_observation_count does not match the observation array")
    references: set[str] = set()
    for exchange in exchanges:
        reference = exchange.get("exchange_reference")
        if not isinstance(reference, str) or not SDP_REFERENCE_PATTERN.fullmatch(reference):
            raise InputError("an exchange reference is invalid")
        if reference in references:
            raise InputError("exchange references are not unique")
        references.add(reference)
        if exchange.get("exchange_type") not in EXCHANGE_TYPES:
            raise InputError("an exchange type is not accepted")
        if exchange.get("initial_sdp_state") not in INITIAL_SDP_STATES:
            raise InputError("an initial SDP state is not accepted")
        if exchange.get("association_status") not in ASSOCIATION_STATUSES:
            raise InputError("an exchange association status is not accepted")
        branch_identity = exchange.get("branch_identity_status")
        if branch_identity is not None and branch_identity not in BRANCH_IDENTITY_STATUSES:
            raise InputError("a branch identity status is not accepted")
        if exchange.get("negotiation_compatibility") != "NOT_EVALUATED":
            raise InputError("negotiation compatibility cannot be claimed")
        if exchange.get("evidence_class") != "DERIVED":
            raise InputError("exchange evidence_class must be DERIVED")
        if exchange["association_status"] == "ESTABLISHED":
            if exchange["exchange_type"] in ("INITIAL_INVITE_WITHOUT_SDP", "INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE"):
                raise InputError("an absent or unusable SDP exchange cannot be established")
            if not exchange.get("offer_sdp_reference"):
                raise InputError("an established exchange requires an observed offer")
            if exchange["exchange_type"] in BRANCH_SCOPED_EXCHANGE_TYPES:
                if not exchange.get("answer_sdp_reference"):
                    raise InputError("an established offer/answer exchange requires an observed answer")
                if not exchange.get("branch_reference"):
                    raise InputError("an established branch-scoped exchange requires a branch reference")
                if not exchange.get("dialog_reference"):
                    raise InputError("an established branch-scoped exchange requires a Dialog reference")
                if branch_identity != "ESTABLISHED":
                    raise InputError("an established branch-scoped exchange requires established branch identity")
            if exchange["exchange_type"] == "INITIAL_INVITE_OFFER_ANSWER" and exchange["initial_sdp_state"] != "OBSERVED_VALID":
                raise InputError("an established initial pair requires an accepted initial SDP offer")
            if exchange["exchange_type"] == "LATE_OFFER_ANSWER" and exchange["initial_sdp_state"] != "ABSENT":
                raise InputError("an established late pair requires proven initial SDP absence")
        if exchange["association_status"] != "ESTABLISHED":
            if exchange.get("offer_role") is not None or exchange.get("answer_role") is not None:
                raise InputError("an unestablished exchange cannot claim an offer or answer role")
        if exchange["association_status"] == "OUT_OF_SCOPE" and exchange["exchange_type"] != "INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE":
            raise InputError("only an unusable initial SDP exchange can be out of scope")
        if exchange["exchange_type"] in ("INITIAL_INVITE_WITHOUT_SDP", "INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE"):
            if exchange["association_status"] == "ESTABLISHED":
                raise InputError("initial SDP absence or unusability cannot be established")
            if exchange.get("answer_sdp_reference") is not None:
                raise InputError("an initial-only exchange cannot publish an answer")
        if exchange["exchange_type"] == "INITIAL_INVITE_WITHOUT_SDP" and exchange["initial_sdp_state"] != "ABSENT":
            raise InputError("INITIAL_INVITE_WITHOUT_SDP requires proven SDP absence")
        for key in ("attempt_reference", "initial_invite_transaction_reference"):
            if not isinstance(exchange.get(key), str):
                raise InputError(f"an exchange is missing {key}")
        for key in ("offer_event_reference", "answer_event_reference"):
            value = exchange.get(key)
            if value is not None and known_events and value not in known_events:
                raise InputError("an exchange references a missing SIP event")
        for key in ("offer_sdp_reference", "answer_sdp_reference"):
            value = exchange.get(key)
            if value is not None and known_sdp and value not in known_sdp:
                raise InputError("an exchange references a missing SDP message")
    for observation in observations:
        if observation.get("observation_type") not in OBSERVATION_TYPES:
            raise InputError("an observation type is not accepted")
        if observation.get("association_status") not in ASSOCIATION_STATUSES:
            raise InputError("an observation association status is not accepted")
        if not isinstance(observation.get("reason_code"), str):
            raise InputError("an observation is missing a reason code")
        if observation.get("evidence_class") != "DERIVED":
            raise InputError("observation evidence_class must be DERIVED")
        event_reference = observation.get("sip_event_reference")
        if event_reference is not None and known_events and event_reference not in known_events:
            raise InputError("an observation references a missing SIP event")
        sdp_reference = observation.get("sdp_reference")
        if sdp_reference is not None and known_sdp and sdp_reference not in known_sdp:
            raise InputError("an observation references a missing SDP message")
    completeness = document.get("completeness") or {}
    supplied = completeness.get("supplied_sdp_message_count")
    matched = completeness.get("matched_sip_event_count")
    unmatched = completeness.get("unmatched_sdp_message_count")
    if not isinstance(supplied, int) or not isinstance(matched, int) or not isinstance(unmatched, int):
        raise InputError("SDP completeness counters are required")
    if supplied != matched + unmatched:
        raise InputError("SDP message count conservation failed")
    if completeness.get("established_exchange_count") != sum(
        1 for item in exchanges if item["association_status"] == "ESTABLISHED"
    ):
        raise InputError("established exchange count does not match")
    if completeness.get("incomplete_exchange_count") != sum(
        1 for item in exchanges if item["association_status"] == "INSUFFICIENT_EVIDENCE"
    ):
        raise InputError("incomplete exchange count does not match")
    if completeness.get("ambiguous_exchange_count") != sum(
        1 for item in exchanges if item["association_status"] == "AMBIGUOUS"
    ):
        raise InputError("ambiguous exchange count does not match")
    if completeness.get("out_of_scope_observation_count") != sum(
        1 for item in observations if item["association_status"] == "OUT_OF_SCOPE"
    ):
        raise InputError("out-of-scope observation count does not match")
    if completeness.get("observed_offer_count") != sum(
        1 for item in exchanges if item["offer_sdp_reference"]
    ):
        raise InputError("observed offer count does not match")
    if completeness.get("observed_answer_count") != sum(
        1 for item in exchanges if item["answer_sdp_reference"]
    ):
        raise InputError("observed answer count does not match")
    for forbidden in PRIVATE_BODY_MARKERS:
        if forbidden in document:
            raise InputError(f"forbidden raw field published: {forbidden}")