#!/usr/bin/env python3
"""Branch-scoped IMS media transport evidence composition.

This Domain composes four already-accepted artifacts:

    IMS Session Analysis
    IMS Media Signaling Analysis
    SDP Analysis
    SDP/RTP Transport Correlation

It does not decode SIP or RTP, parse SDP, read a capture, use the HMAC key,
reconstruct Dialog identity, or claim media delivery, temporal association,
codec compatibility or IMS call success.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SKILL = HERE.parents[1]
SKILLS = HERE.parents[2]
for path in (
    SKILLS / "protocol" / "sdp-rtp" / "scripts",
    SKILLS / "domain" / "ims-session" / "scripts",
    SKILLS / "domain" / "ims-media-signaling" / "scripts",
    SKILLS / "correlation" / "sdp-rtp-transport" / "scripts",
):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import ims_media_signaling_model  # noqa: E402
import ims_session_model  # noqa: E402
import sdp_model  # noqa: E402
import sdp_rtp_transport_model  # noqa: E402
from endpoint_reference import (  # noqa: E402
    is_context_reference,
    is_endpoint_reference,
)

ANALYSIS_NAME = "ims-media-session"
ANALYSIS_VERSION = "0.1.0"
DOMAIN = "ims-media-session"
CAPABILITY = "branch-scoped IMS media transport evidence composition"

IMS_SESSION_ANALYSIS_VERSION = ims_session_model.ANALYSIS_VERSION
IMS_MEDIA_SIGNALING_ANALYSIS_VERSION = ims_media_signaling_model.ANALYSIS_VERSION
SDP_ANALYSIS_VERSION = sdp_model.ANALYSIS_VERSION
SDP_EVENT_SCHEMA_VERSION = sdp_model.EVENT_SCHEMA_VERSION
SDP_PARSER_VERSION = sdp_model.PARSER_VERSION
TRANSPORT_CORRELATION_ANALYSIS_VERSION = (
    sdp_rtp_transport_model.ANALYSIS_VERSION
)
RTP_ANALYSIS_VERSION = sdp_rtp_transport_model.RTP_ANALYSIS_VERSION
RTP_EVENT_SCHEMA_VERSION = sdp_rtp_transport_model.RTP_EVENT_SCHEMA_VERSION

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
CAPTURE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ +-]{0,127}$")
ATTEMPT_REFERENCE_PATTERN = re.compile(r"^ims-session:.+:[0-9]+\.[0-9]+$")
DIALOG_REFERENCE_PATTERN = re.compile(r"^sip-dialog:.+:[0-9]+\.[0-9]+$")
EXCHANGE_REFERENCE_PATTERN = re.compile(
    r"^ims-media-signaling:.+:[0-9]+\.[0-9]+$"
)
CORRELATION_REFERENCE_PATTERN = re.compile(
    r"^sdp-rtp-transport:.+:[0-9]+\.[0-9]+\.[0-9]+$"
)
OBSERVATION_REFERENCE_PATTERN = re.compile(
    r"^ims-media-session:.+:[0-9]+\.[0-9]+\.[0-9]+$"
)
STREAM_REFERENCE_PATTERN = re.compile(r"^rtp-udp-stream:.+:[0-9]+$")
SDP_REFERENCE_PATTERN = re.compile(
    r"^[a-z][a-z0-9-]*:.+:[0-9]+\.[0-9]+$"
)
EVENT_REFERENCE_PATTERN = re.compile(r"^sip-event:.+:[0-9]+\.[0-9]+$")
TRANSACTION_REFERENCE_PATTERN = re.compile(
    r"^sip-transaction:.+:(?:request|response):[0-9]+\.[0-9]+$"
)

MAX_ATTEMPTS = 64
MAX_BRANCHES = 512
MAX_EXCHANGES = 64
MAX_OBSERVATIONS = 512
MAX_UNBOUND = 64
MAX_UNMATCHED_STREAMS = 1024
MAX_LIST_ITEMS = 64
MAX_FINDINGS = 16

BINDING_SCOPES = ("ATTEMPT", "BRANCH", "AMBIGUOUS", "UNBOUND")
BINDING_STATUSES = (
    "ESTABLISHED",
    "AMBIGUOUS",
    "INSUFFICIENT_EVIDENCE",
    "NOT_ESTABLISHED",
)
BINDING_ROLES = ("OFFER", "ANSWER", "UNRESOLVED")


class InputError(ValueError):
    """Raised when an accepted input artifact is contradictory or malformed."""


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError(f"{label} could not be read: {exc}") from None
    except json.JSONDecodeError as exc:
        raise InputError(f"{label} is not valid JSON: {exc}") from None
    if not isinstance(document, dict):
        raise InputError(f"{label} must be an object")
    return document


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _unique(values: list[Any]) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for value in values:
        key = json.dumps(value, sort_keys=True) if isinstance(value, dict) else value
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _capture(document: dict[str, Any], label: str) -> tuple[str, dict[str, Any]]:
    provenance = document.get("input_provenance")
    if not isinstance(provenance, dict):
        raise InputError(f"{label} input_provenance is missing")
    captures = provenance.get("capture_files")
    if (
        not isinstance(captures, list)
        or len(captures) != 1
        or not isinstance(captures[0], str)
        or not CAPTURE_NAME_PATTERN.fullmatch(captures[0])
    ):
        raise InputError(f"{label} must publish one privacy-safe capture basename")
    return captures[0], provenance


def _suffix(reference: str) -> str:
    return reference.split(":", 1)[1] if ":" in reference else reference


def _finding(value: str) -> str:
    return value if len(value) <= 80 else value[:77] + "..."


def load_session(path: Path) -> dict[str, Any]:
    document = _load_json(path, "IMS Session analysis")
    try:
        ims_session_model.validate_analysis(document)
    except ims_session_model.InputError as exc:
        raise InputError(f"IMS Session analysis is not accepted: {exc}") from None
    if document.get("analysis_name") != ims_session_model.ANALYSIS_NAME:
        raise InputError("IMS Session analysis_name is not accepted")
    if document.get("analysis_version") != IMS_SESSION_ANALYSIS_VERSION:
        raise InputError("IMS Session analysis_version is not accepted")
    return document


def load_media_signaling(path: Path, sdp_references: set[str]) -> dict[str, Any]:
    document = _load_json(path, "IMS Media Signaling analysis")
    try:
        ims_media_signaling_model.validate_analysis(
            document, sdp_references=sdp_references
        )
    except ims_media_signaling_model.InputError as exc:
        raise InputError(
            f"IMS Media Signaling analysis is not accepted: {exc}"
        ) from None
    if document.get("analysis_name") != ims_media_signaling_model.ANALYSIS_NAME:
        raise InputError("IMS Media Signaling analysis_name is not accepted")
    if (
        document.get("analysis_version")
        != IMS_MEDIA_SIGNALING_ANALYSIS_VERSION
    ):
        raise InputError("IMS Media Signaling analysis_version is not accepted")
    return document


def load_sdp(path: Path) -> dict[str, Any]:
    document = _load_json(path, "SDP analysis")
    try:
        sdp_model.validate_analysis(document)
    except sdp_model.InputError as exc:
        raise InputError(f"SDP analysis is not accepted: {exc}") from None
    if document.get("analysis_name") != sdp_model.ANALYSIS_NAME:
        raise InputError("SDP analysis_name is not accepted")
    if document.get("analysis_version") != SDP_ANALYSIS_VERSION:
        raise InputError("SDP analysis_version is not accepted")
    if document.get("event_schema_version") != SDP_EVENT_SCHEMA_VERSION:
        raise InputError("SDP event_schema_version is not accepted")
    provenance = document.get("input_provenance") or {}
    if provenance.get("parser_version") != SDP_PARSER_VERSION:
        raise InputError("SDP parser_version is not accepted")
    return document


def load_correlation(path: Path) -> dict[str, Any]:
    document = _load_json(path, "SDP/RTP transport correlation")
    try:
        sdp_rtp_transport_model.validate_analysis(document)
    except sdp_rtp_transport_model.InputError as exc:
        raise InputError(
            f"SDP/RTP transport correlation is not accepted: {exc}"
        ) from None
    if document.get("analysis_name") != sdp_rtp_transport_model.ANALYSIS_NAME:
        raise InputError("transport correlation analysis_name is not accepted")
    if (
        document.get("analysis_version")
        != TRANSPORT_CORRELATION_ANALYSIS_VERSION
    ):
        raise InputError("transport correlation analysis_version is not accepted")
    provenance = document.get("input_provenance") or {}
    if provenance.get("sdp_analysis_version") != SDP_ANALYSIS_VERSION:
        raise InputError("transport correlation SDP analysis version is not accepted")
    if provenance.get("sdp_event_schema_version") != SDP_EVENT_SCHEMA_VERSION:
        raise InputError("transport correlation SDP schema version is not accepted")
    if provenance.get("rtp_rtcp_analysis_version") != RTP_ANALYSIS_VERSION:
        raise InputError("transport correlation RTP analysis version is not accepted")
    if (
        provenance.get("rtp_rtcp_event_schema_version")
        != RTP_EVENT_SCHEMA_VERSION
    ):
        raise InputError("transport correlation RTP schema version is not accepted")
    rtp_sha = provenance.get("rtp_rtcp_analysis_sha256")
    if not isinstance(rtp_sha, str) or not SHA256_PATTERN.fullmatch(rtp_sha):
        raise InputError("transport correlation RTP analysis SHA-256 is malformed")
    root_context = document.get("endpoint_context_reference")
    if root_context is not None and root_context != provenance.get(
        "endpoint_context_reference"
    ):
        raise InputError("transport correlation endpoint context references disagree")
    return document


def _validate_endpoint_context(
    sdp: dict[str, Any], correlation: dict[str, Any]
) -> str | None:
    sdp_context = (sdp.get("input_provenance") or {}).get(
        "endpoint_context_reference"
    )
    correlation_context = (correlation.get("input_provenance") or {}).get(
        "endpoint_context_reference"
    )
    for value in (sdp_context, correlation_context):
        if value is not None and not is_context_reference(value):
            raise InputError("an endpoint context reference is malformed")
    if sdp_context != correlation_context:
        raise InputError("SDP and transport-correlation endpoint contexts differ")
    return sdp_context


def _validate_session_identity(session: dict[str, Any]) -> tuple[
    dict[str, dict[str, Any]], dict[str, dict[str, Any]]
]:
    attempts: dict[str, dict[str, Any]] = {}
    branches: dict[str, dict[str, Any]] = {}
    dialogs: set[str] = set()
    for attempt in session.get("session_attempts") or []:
        reference = attempt.get("attempt_reference")
        if not isinstance(reference, str) or not ATTEMPT_REFERENCE_PATTERN.fullmatch(
            reference
        ):
            raise InputError("an IMS Session attempt reference is invalid")
        if reference in attempts:
            raise InputError("IMS Session attempt references are not unique")
        attempts[reference] = attempt
        transaction = attempt.get("initial_invite_transaction_reference")
        if not isinstance(transaction, str) or not TRANSACTION_REFERENCE_PATTERN.fullmatch(
            transaction
        ):
            raise InputError("an IMS Session initial INVITE transaction is invalid")
        for branch in attempt.get("branches") or []:
            branch_reference = branch.get("branch_reference")
            if not isinstance(branch_reference, str) or not branch_reference:
                raise InputError("an IMS Session branch reference is invalid")
            if branch_reference in branches:
                raise InputError("IMS Session branch references are not unique")
            branches[branch_reference] = branch
            dialog = branch.get("dialog_reference")
            if dialog is not None and (
                not isinstance(dialog, str)
                or not DIALOG_REFERENCE_PATTERN.fullmatch(dialog)
            ):
                raise InputError("an IMS Session Dialog reference is invalid")
            if isinstance(dialog, str):
                if dialog in dialogs:
                    raise InputError("IMS Session Dialog references are not unique")
                dialogs.add(dialog)
    return (attempts, branches)


def _validate_media_ownership(
    session: dict[str, Any],
    media: dict[str, Any],
    attempts: dict[str, dict[str, Any]],
    branches: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    exchanges: dict[str, dict[str, Any]] = {}
    for exchange in media.get("exchanges") or []:
        reference = exchange.get("exchange_reference")
        if not isinstance(reference, str) or not EXCHANGE_REFERENCE_PATTERN.fullmatch(
            reference
        ):
            raise InputError("an IMS Media Signaling exchange reference is invalid")
        if reference in exchanges:
            raise InputError("IMS Media Signaling exchange references are not unique")
        exchanges[reference] = exchange
        attempt_reference = exchange.get("attempt_reference")
        attempt = attempts.get(attempt_reference)
        if attempt is None:
            raise InputError("an exchange references a missing IMS Session attempt")
        if exchange.get("initial_invite_transaction_reference") != attempt.get(
            "initial_invite_transaction_reference"
        ):
            raise InputError("an exchange initial INVITE transaction disagrees")
        branch_reference = exchange.get("branch_reference")
        dialog_reference = exchange.get("dialog_reference")
        if branch_reference is None:
            if dialog_reference is not None:
                raise InputError("an exchange publishes a Dialog without a branch")
            continue
        if not isinstance(branch_reference, str) or branch_reference not in branches:
            raise InputError("an exchange references a missing Dialog branch")
        branch = branches[branch_reference]
        if not any(
            item is branch for item in attempt.get("branches") or []
        ):
            raise InputError("an exchange branch is not owned by its attempt")
        if (branch.get("dialog_reference") or None) != (dialog_reference or None):
            raise InputError("an exchange Dialog reference disagrees with its branch")
        if (
            exchange.get("branch_identity_status") == "ESTABLISHED"
            and branch.get("identity_status") != "ESTABLISHED"
        ):
            raise InputError(
                "an exchange claims established identity for a non-established branch"
            )
        if exchange.get("association_status") == "ESTABLISHED" and (
            exchange.get("branch_identity_status") != "ESTABLISHED"
            or branch.get("identity_status") != "ESTABLISHED"
            or dialog_reference is None
        ):
            raise InputError("an established exchange lacks established branch identity")
    return exchanges


def _validate_sdp_bindings(
    sdp: dict[str, Any], correlation: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    messages: dict[str, dict[str, Any]] = {}
    root_capture = (sdp.get("input_provenance") or {}).get("capture_files")
    root_sha = (sdp.get("input_provenance") or {}).get("capture_sha256")
    capture = root_capture[0] if isinstance(root_capture, list) and root_capture else None
    for message in sdp.get("messages") or []:
        reference = message.get("source_reference")
        if not isinstance(reference, str) or not SDP_REFERENCE_PATTERN.fullmatch(
            reference
        ):
            raise InputError("an SDP message source reference is invalid")
        if reference in messages:
            raise InputError("SDP message references are not unique")
        if message.get("capture_file") != capture or message.get("capture_sha256") != root_sha:
            raise InputError("an SDP message disagrees with the SDP capture provenance")
        if reference.split(":", 2)[1:2] != [capture]:
            raise InputError("an SDP source reference disagrees with the capture")
        messages[reference] = message
    correlation_references: set[str] = set()
    for item in correlation.get("correlations") or []:
        reference = item.get("correlation_reference")
        if (
            not isinstance(reference, str)
            or not CORRELATION_REFERENCE_PATTERN.fullmatch(reference)
        ):
            raise InputError("a transport correlation reference is invalid")
        if reference in correlation_references:
            raise InputError("transport correlation references are not unique")
        correlation_references.add(reference)
        bindings: set[tuple[str, int]] = set()
        for section in item.get("sdp_media_sections") or []:
            message_reference = section.get("message_reference")
            media_index = section.get("media_index")
            message = messages.get(message_reference)
            if message is None:
                raise InputError("a correlation references a missing SDP message")
            if (
                isinstance(media_index, bool)
                or not isinstance(media_index, int)
                or media_index < 0
            ):
                raise InputError("a correlation media-section index is invalid")
            media_sections = message.get("media_sections") or []
            if media_index >= len(media_sections):
                raise InputError("a correlation media-section index is out of range")
            key = (message_reference, media_index)
            if key in bindings:
                raise InputError("a correlation repeats a media-section binding")
            bindings.add(key)
            media = media_sections[media_index]
            if section.get("mid") != media.get("mid"):
                raise InputError("a correlation MID disagrees with the SDP media section")
        message_references = item.get("sdp_message_references") or []
        if set(message_references) != {reference for reference, _ in bindings}:
            raise InputError(
                "a correlation SDP message references disagree with its media bindings"
            )
        for stream_reference in item.get("rtp_udp_stream_references") or []:
            if not STREAM_REFERENCE_PATTERN.fullmatch(stream_reference):
                raise InputError("a correlation RTP UDP stream reference is invalid")
        for endpoint in item.get("endpoint_references") or []:
            if not is_endpoint_reference(endpoint):
                raise InputError("a correlation endpoint reference is malformed")
    return messages


def verify_provenance(
    session: dict[str, Any],
    media: dict[str, Any],
    sdp: dict[str, Any],
    correlation: dict[str, Any],
    *,
    session_path: Path,
    media_path: Path,
    sdp_path: Path,
    correlation_path: Path,
) -> dict[str, Any]:
    session_capture, session_provenance = _capture(session, "IMS Session")
    media_capture, media_provenance = _capture(media, "IMS Media Signaling")
    sdp_capture, sdp_provenance = _capture(sdp, "SDP")
    correlation_capture, correlation_provenance = _capture(
        correlation, "transport correlation"
    )
    captures = {session_capture, media_capture, sdp_capture, correlation_capture}
    if len(captures) != 1:
        raise InputError("the four artifacts describe different captures")

    sdp_capture_sha = sdp_provenance.get("capture_sha256")
    if not isinstance(sdp_capture_sha, str) or not SHA256_PATTERN.fullmatch(
        sdp_capture_sha
    ):
        raise InputError("SDP capture SHA-256 is malformed")
    if media_provenance.get("sdp_capture_sha256") != sdp_capture_sha:
        raise InputError("IMS Media Signaling SDP capture SHA-256 disagrees")
    if correlation_provenance.get("capture_sha256") != sdp_capture_sha:
        raise InputError("transport correlation capture SHA-256 disagrees")

    actual_sdp_sha = _sha256(sdp_path)
    if media_provenance.get("sdp_analysis_sha256") != actual_sdp_sha:
        raise InputError("IMS Media Signaling SDP analysis SHA-256 is wrong")
    if correlation_provenance.get("sdp_analysis_sha256") != actual_sdp_sha:
        raise InputError("transport correlation SDP analysis SHA-256 is wrong")
    actual_session_sha = _sha256(session_path)
    if media_provenance.get("ims_session_sha256") != actual_session_sha:
        raise InputError("IMS Media Signaling IMS Session SHA-256 is wrong")
    if media_provenance.get("ims_session_analysis_version") != (
        IMS_SESSION_ANALYSIS_VERSION
    ):
        raise InputError("IMS Media Signaling IMS Session version is not accepted")
    if media_provenance.get("sdp_analysis_version") != SDP_ANALYSIS_VERSION:
        raise InputError("IMS Media Signaling SDP analysis version is not accepted")
    if media_provenance.get("sdp_event_schema_version") != (
        SDP_EVENT_SCHEMA_VERSION
    ):
        raise InputError("IMS Media Signaling SDP schema version is not accepted")
    endpoint_context = _validate_endpoint_context(sdp, correlation)
    return {
        "capture_files": [sdp_capture],
        "capture_sha256": sdp_capture_sha,
        "ims_session_source_name": session_path.name,
        "ims_session_sha256": actual_session_sha,
        "ims_session_analysis_version": IMS_SESSION_ANALYSIS_VERSION,
        "ims_media_signaling_source_name": media_path.name,
        "ims_media_signaling_sha256": _sha256(media_path),
        "ims_media_signaling_analysis_version": IMS_MEDIA_SIGNALING_ANALYSIS_VERSION,
        "sdp_analysis_source_name": sdp_path.name,
        "sdp_analysis_sha256": actual_sdp_sha,
        "sdp_analysis_version": SDP_ANALYSIS_VERSION,
        "sdp_event_schema_version": SDP_EVENT_SCHEMA_VERSION,
        "transport_correlation_source_name": correlation_path.name,
        "transport_correlation_sha256": _sha256(correlation_path),
        "transport_correlation_analysis_version": (
            TRANSPORT_CORRELATION_ANALYSIS_VERSION
        ),
        "endpoint_context_reference": endpoint_context,
        "input_status": "ACCEPTED",
    }


def _initial_offer_messages(
    exchanges: list[dict[str, Any]],
) -> set[str]:
    offers: set[str] = set()
    for exchange in exchanges:
        if exchange.get("exchange_type") in (
            "INITIAL_INVITE_SDP_OFFER",
            "INITIAL_INVITE_OFFER_ANSWER",
        ):
            reference = exchange.get("offer_sdp_reference")
            if isinstance(reference, str):
                offers.add(reference)
    return offers


def _ownership(
    bindings: list[dict[str, Any]],
    exchange_map: dict[str, dict[str, Any]],
    exchanges_by_offer: dict[str, list[dict[str, Any]]],
    exchanges_by_answer: dict[str, list[dict[str, Any]]],
    branches: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    candidate_exchanges: list[dict[str, Any]] = []
    for binding in bindings:
        message_reference = binding["message_reference"]
        candidate_exchanges.extend(exchanges_by_offer.get(message_reference, []))
        candidate_exchanges.extend(exchanges_by_answer.get(message_reference, []))
    candidate_exchanges = [
        exchange_map[item["exchange_reference"]]
        for item in {item["exchange_reference"]: item for item in candidate_exchanges}.values()
    ]
    candidate_attempts = _unique(
        [
            item.get("attempt_reference")
            for item in candidate_exchanges
            if isinstance(item.get("attempt_reference"), str)
        ]
    )
    candidate_branches = _unique(
        [
            item.get("branch_reference")
            for item in candidate_exchanges
            if isinstance(item.get("branch_reference"), str)
        ]
    )
    base = {
        "candidate_attempt_references": candidate_attempts,
        "candidate_branch_references": candidate_branches,
        "exchange_references": [
            item["exchange_reference"]
            for item in sorted(
                candidate_exchanges, key=lambda item: item["exchange_reference"]
            )
        ],
    }
    if not candidate_exchanges:
        return {
            **base,
            "binding_scope": "UNBOUND",
            "binding_status": "NOT_ESTABLISHED",
            "attempt_reference": None,
            "branch_reference": None,
            "dialog_reference": None,
            "missing": ["NO_SIGNALING_EXCHANGE_OWNER"],
            "conflicts": [],
        }
    if len(candidate_attempts) != 1:
        return {
            **base,
            "binding_scope": "AMBIGUOUS",
            "binding_status": "AMBIGUOUS",
            "attempt_reference": None,
            "branch_reference": None,
            "dialog_reference": None,
            "missing": [],
            "conflicts": ["MULTIPLE_ATTEMPT_OWNERS"],
        }
    attempt_reference = candidate_attempts[0]
    attempt_exchanges = [
        item for item in candidate_exchanges if item["attempt_reference"] == attempt_reference
    ]
    initial_offers = _initial_offer_messages(attempt_exchanges)
    all_initial = all(
        binding["message_reference"] in initial_offers for binding in bindings
    )
    if all_initial:
        return {
            **base,
            "binding_scope": "ATTEMPT",
            "binding_status": "ESTABLISHED",
            "attempt_reference": attempt_reference,
            "branch_reference": None,
            "dialog_reference": None,
            "missing": [],
            "conflicts": [],
        }
    established_branches: set[str] = set()
    other_branches: set[str] = set()
    for exchange in attempt_exchanges:
        branch_reference = exchange.get("branch_reference")
        if not isinstance(branch_reference, str):
            continue
        branch = branches.get(branch_reference)
        valid = (
            exchange.get("association_status") == "ESTABLISHED"
            and exchange.get("branch_identity_status") == "ESTABLISHED"
            and branch is not None
            and branch.get("identity_status") == "ESTABLISHED"
            and isinstance(exchange.get("dialog_reference"), str)
            and exchange.get("dialog_reference") == branch.get("dialog_reference")
        )
        if valid:
            established_branches.add(branch_reference)
        else:
            other_branches.add(branch_reference)
    if len(established_branches) == 1 and other_branches <= established_branches:
        branch_reference = next(iter(established_branches))
        branch = branches[branch_reference]
        return {
            **base,
            "binding_scope": "BRANCH",
            "binding_status": "ESTABLISHED",
            "attempt_reference": attempt_reference,
            "branch_reference": branch_reference,
            "dialog_reference": branch.get("dialog_reference"),
            "missing": [],
            "conflicts": [],
        }
    if len(established_branches) > 1:
        return {
            **base,
            "binding_scope": "AMBIGUOUS",
            "binding_status": "AMBIGUOUS",
            "attempt_reference": attempt_reference,
            "branch_reference": None,
            "dialog_reference": None,
            "missing": [],
            "conflicts": ["MULTIPLE_BRANCH_OWNERS"],
        }
    if established_branches and other_branches - established_branches:
        return {
            **base,
            "binding_scope": "AMBIGUOUS",
            "binding_status": "AMBIGUOUS",
            "attempt_reference": attempt_reference,
            "branch_reference": None,
            "dialog_reference": None,
            "missing": [],
            "conflicts": ["COMPETING_BRANCH_OWNERS"],
        }
    if other_branches:
        return {
            **base,
            "binding_scope": "UNBOUND",
            "binding_status": "INSUFFICIENT_EVIDENCE",
            "attempt_reference": attempt_reference,
            "branch_reference": None,
            "dialog_reference": None,
            "missing": ["BRANCH_IDENTITY_NOT_ESTABLISHED"],
            "conflicts": [],
        }
    return {
        **base,
        "binding_scope": "UNBOUND",
        "binding_status": "INSUFFICIENT_EVIDENCE",
        "attempt_reference": attempt_reference,
        "branch_reference": None,
        "dialog_reference": None,
        "missing": ["SIGNALING_EXCHANGE_NOT_ESTABLISHED"],
        "conflicts": [],
    }


def _build_observation(
    correlation: dict[str, Any],
    messages: dict[str, dict[str, Any]],
    exchange_map: dict[str, dict[str, Any]],
    exchanges_by_offer: dict[str, list[dict[str, Any]]],
    exchanges_by_answer: dict[str, list[dict[str, Any]]],
    branches: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    bindings: list[dict[str, Any]] = []
    for section in correlation.get("sdp_media_sections") or []:
        message_reference = section["message_reference"]
        media_index = section["media_index"]
        message = messages[message_reference]
        media = message["media_sections"][media_index]
        roles: list[str] = []
        if message_reference in exchanges_by_offer:
            roles.append("OFFER")
        if message_reference in exchanges_by_answer:
            roles.append("ANSWER")
        if not roles:
            roles = ["UNRESOLVED"]
        bindings.append(
            {
                "message_reference": message_reference,
                "media_index": media_index,
                "mid": media.get("mid"),
                "media_type": media.get("media_type"),
                "protocol": media.get("protocol"),
                "roles": roles,
            }
        )
    ownership = _ownership(
        bindings,
        exchange_map,
        exchanges_by_offer,
        exchanges_by_answer,
        branches,
    )
    correlation_reference = correlation["correlation_reference"]
    missing = _unique(
        list(correlation.get("missing_evidence") or []) + ownership["missing"]
    )[:MAX_FINDINGS]
    conflicts = _unique(
        list(correlation.get("conflict_findings") or []) + ownership["conflicts"]
    )[:MAX_FINDINGS]
    return {
        "observation_reference": f"{ANALYSIS_NAME}:{_suffix(correlation_reference)}",
        "correlation_reference": correlation_reference,
        "binding_scope": ownership["binding_scope"],
        "binding_status": ownership["binding_status"],
        "attempt_reference": ownership["attempt_reference"],
        "branch_reference": ownership["branch_reference"],
        "dialog_reference": ownership["dialog_reference"],
        "candidate_attempt_references": ownership["candidate_attempt_references"][
            :MAX_LIST_ITEMS
        ],
        "candidate_branch_references": ownership["candidate_branch_references"][
            :MAX_LIST_ITEMS
        ],
        "exchange_references": ownership["exchange_references"][:MAX_LIST_ITEMS],
        "sdp_message_bindings": bindings[:MAX_LIST_ITEMS],
        "correlation_type": correlation.get("correlation_type"),
        "bundle_references": list(correlation.get("bundle_references") or [])[
            :MAX_LIST_ITEMS
        ],
        "original_association_status": correlation.get("association_status"),
        "original_correlation_strength": correlation.get(
            "correlation_strength"
        ),
        "endpoint_references": list(correlation.get("endpoint_references") or [])[
            :MAX_LIST_ITEMS
        ],
        "rtp_udp_stream_references": list(
            correlation.get("rtp_udp_stream_references") or []
        )[:MAX_LIST_ITEMS],
        "rtp_event_references": list(
            correlation.get("rtp_event_references") or []
        )[:MAX_LIST_ITEMS],
        "match_directions": list(correlation.get("match_directions") or [])[
            :MAX_LIST_ITEMS
        ],
        "missing_evidence": missing,
        "conflict_findings": conflicts,
        "temporal_association_status": "NOT_EVALUATED",
        "association_scope": "CAPTURE_WIDE_ENDPOINT_CORRESPONDENCE_ONLY",
        "evidence_class": "DERIVED",
    }


def _build_attempts(
    session: dict[str, Any],
    media: dict[str, Any],
    attempts: dict[str, dict[str, Any]],
    branches: dict[str, dict[str, Any]],
    observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    observations_by_attempt: dict[str, list[str]] = {}
    observations_by_branch: dict[str, list[str]] = {}
    for observation in observations:
        if observation["binding_scope"] == "ATTEMPT" and observation.get(
            "attempt_reference"
        ):
            observations_by_attempt.setdefault(
                observation["attempt_reference"], []
            ).append(observation["observation_reference"])
        if observation["binding_scope"] == "BRANCH" and observation.get(
            "branch_reference"
        ):
            observations_by_branch.setdefault(
                observation["branch_reference"], []
            ).append(observation["observation_reference"])
    exchanges_by_branch: dict[str, list[str]] = {}
    for exchange in media.get("exchanges") or []:
        reference = exchange.get("branch_reference")
        if isinstance(reference, str):
            exchanges_by_branch.setdefault(reference, []).append(
                exchange["exchange_reference"]
            )
    result: list[dict[str, Any]] = []
    for attempt_reference in sorted(attempts):
        attempt = attempts[attempt_reference]
        shared = sorted(observations_by_attempt.get(attempt_reference, []))
        branch_records: list[dict[str, Any]] = []
        for branch in attempt.get("branches") or []:
            branch_reference = branch["branch_reference"]
            branch_records.append(
                {
                    "branch_reference": branch_reference,
                    "dialog_reference": branch.get("dialog_reference"),
                    "fork_reference": branch.get("fork_branch_reference"),
                    "identity_status": branch.get("identity_status"),
                    "dialog_state": branch.get("dialog_state"),
                    "observed_lifecycle_status": branch.get(
                        "observed_lifecycle_status"
                    ),
                    "invite_outcome": branch.get("outcome"),
                    "release_outcome": (branch.get("release") or {}).get(
                        "outcome"
                    ),
                    "exchange_references": sorted(
                        exchanges_by_branch.get(branch_reference, [])
                    ),
                    "branch_transport_observation_references": sorted(
                        observations_by_branch.get(branch_reference, [])
                    ),
                    "shared_initial_offer_observation_references": list(shared),
                    "missing_evidence": list(branch.get("missing_evidence") or [])[
                        :MAX_FINDINGS
                    ],
                    "conflict_findings": list(
                        branch.get("conflict_findings") or []
                    )[:MAX_FINDINGS],
                    "evidence_class": "DERIVED",
                }
            )
        result.append(
            {
                "attempt_reference": attempt_reference,
                "initial_invite_transaction_reference": attempt.get(
                    "initial_invite_transaction_reference"
                ),
                "initial_invite_event_reference": attempt.get(
                    "initial_invite_event_reference"
                ),
                "invite_outcome": attempt.get("invite_outcome"),
                "shared_initial_offer_observation_references": shared,
                "branch_count": len(branch_records),
                "branches": branch_records,
                "missing_evidence": list(attempt.get("missing_evidence") or [])[
                    :MAX_FINDINGS
                ],
                "conflict_findings": list(
                    attempt.get("conflict_findings") or []
                )[:MAX_FINDINGS],
                "evidence_class": "DERIVED",
            }
        )
    return result


def _build_exchanges(
    media: dict[str, Any], observations: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_exchange: dict[str, list[str]] = {}
    for observation in observations:
        for exchange_reference in observation.get("exchange_references") or []:
            by_exchange.setdefault(exchange_reference, []).append(
                observation["observation_reference"]
            )
    result: list[dict[str, Any]] = []
    for exchange in media.get("exchanges") or []:
        reference = exchange["exchange_reference"]
        observations_for_exchange = sorted(by_exchange.get(reference, []))
        missing = list(exchange.get("missing_evidence") or [])
        if (
            exchange.get("association_status") == "ESTABLISHED"
            and not observations_for_exchange
        ):
            missing.append("TRANSPORT_CORRELATION_NOT_OBSERVED")
        result.append(
            {
                "exchange_reference": reference,
                "exchange_type": exchange.get("exchange_type"),
                "association_status": exchange.get("association_status"),
                "offer_sdp_reference": exchange.get("offer_sdp_reference"),
                "answer_sdp_reference": exchange.get("answer_sdp_reference"),
                "offer_role": exchange.get("offer_role"),
                "answer_role": exchange.get("answer_role"),
                "transport_observation_references": observations_for_exchange,
                "missing_evidence": _unique(missing)[:MAX_FINDINGS],
                "conflict_findings": list(
                    exchange.get("conflict_findings") or []
                )[:MAX_FINDINGS],
                "evidence_class": "DERIVED",
            }
        )
    result.sort(key=lambda item: item["exchange_reference"])
    return result


def _build_unbound_signaling(media: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for observation in media.get("unbound_observations") or []:
        result.append(
            {
                "observation_reference": observation.get("observation_reference"),
                "observation_type": observation.get("observation_type"),
                "association_status": observation.get("association_status"),
                "reason_code": observation.get("reason_code"),
                "sdp_reference": observation.get("sdp_reference"),
                "attempt_reference": observation.get("attempt_reference"),
                "branch_reference": observation.get("branch_reference"),
                "dialog_reference": observation.get("dialog_reference"),
                "evidence_class": "DERIVED",
            }
        )
    result.sort(key=lambda item: item["observation_reference"])
    return result


def _build_unmatched_streams(correlation: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for stream in correlation.get("unmatched_streams") or []:
        result.append(
            {
                "rtp_udp_stream_reference": stream["rtp_udp_stream_reference"],
                "rtp_event_references": list(
                    stream.get("rtp_event_references") or []
                )[:MAX_LIST_ITEMS],
                "packet_count": stream.get("packet_count"),
                "first_frame_number": stream.get("first_frame_number"),
                "last_frame_number": stream.get("last_frame_number"),
                "observed_ssrc_references": list(
                    stream.get("observed_ssrc_references") or []
                )[:MAX_LIST_ITEMS],
                "source_endpoint_references": list(
                    stream.get("source_endpoint_references") or []
                )[:MAX_LIST_ITEMS],
                "destination_endpoint_references": list(
                    stream.get("destination_endpoint_references") or []
                )[:MAX_LIST_ITEMS],
                "endpoint_evidence_status": stream.get("endpoint_evidence_status"),
                "missing_evidence": list(stream.get("missing_evidence") or [])[
                    :MAX_FINDINGS
                ],
                "conflict_findings": list(
                    stream.get("conflict_findings") or []
                )[:MAX_FINDINGS],
                "evidence_class": "DERIVED",
            }
        )
    result.sort(key=lambda item: item["rtp_udp_stream_reference"])
    return result


def build_analysis(
    session: dict[str, Any],
    media: dict[str, Any],
    sdp: dict[str, Any],
    correlation: dict[str, Any],
    *,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    attempts, branches = _validate_session_identity(session)
    exchange_map = _validate_media_ownership(
        session, media, attempts, branches
    )
    messages = _validate_sdp_bindings(sdp, correlation)
    exchanges_by_offer: dict[str, list[dict[str, Any]]] = {}
    exchanges_by_answer: dict[str, list[dict[str, Any]]] = {}
    for exchange in exchange_map.values():
        offer = exchange.get("offer_sdp_reference")
        if isinstance(offer, str):
            exchanges_by_offer.setdefault(offer, []).append(exchange)
        answer = exchange.get("answer_sdp_reference")
        if isinstance(answer, str):
            exchanges_by_answer.setdefault(answer, []).append(exchange)

    observations = [
        _build_observation(
            item,
            messages,
            exchange_map,
            exchanges_by_offer,
            exchanges_by_answer,
            branches,
        )
        for item in sorted(
            correlation.get("correlations") or [],
            key=lambda item: item["correlation_reference"],
        )
    ]
    observations.sort(key=lambda item: item["observation_reference"])
    observation_references = {
        item["observation_reference"] for item in observations
    }
    if len(observation_references) != len(observations):
        raise InputError("Domain transport observation references are not unique")
    published_observations = observations[:MAX_OBSERVATIONS]
    attempt_records = _build_attempts(
        session, media, attempts, branches, published_observations
    )
    published_attempts = attempt_records[:MAX_ATTEMPTS]
    exchanges = _build_exchanges(media, published_observations)
    unbound_signaling = _build_unbound_signaling(media)
    published_unbound = unbound_signaling[:MAX_UNBOUND]
    unmatched = _build_unmatched_streams(correlation)
    published_unmatched = unmatched[:MAX_UNMATCHED_STREAMS]

    source_scope = {
        "ATTEMPT": sum(
            1 for item in published_observations if item["binding_scope"] == "ATTEMPT"
        ),
        "BRANCH": sum(
            1 for item in published_observations if item["binding_scope"] == "BRANCH"
        ),
        "AMBIGUOUS": sum(
            1
            for item in published_observations
            if item["binding_scope"] == "AMBIGUOUS"
        ),
        "UNBOUND": sum(
            1 for item in published_observations if item["binding_scope"] == "UNBOUND"
        ),
    }
    branch_total = sum(len(item.get("branches") or []) for item in attempt_records)
    established_exchanges = sum(
        1 for item in exchanges if item["association_status"] == "ESTABLISHED"
    )
    completeness = {
        "ims_session_attempt_count": len(attempts),
        "published_attempt_count": len(published_attempts),
        "attempts_omitted": len(attempts) - len(published_attempts),
        "dialog_branch_count": len(branches),
        "published_branch_count": branch_total
        if len(published_attempts) == len(attempt_records)
        else sum(len(item.get("branches") or []) for item in published_attempts),
        "branches_omitted": len(branches)
        - (
            branch_total
            if len(published_attempts) == len(attempt_records)
            else sum(len(item.get("branches") or []) for item in published_attempts)
        ),
        "signaling_exchange_count": len(exchange_map),
        "published_exchange_count": len(exchanges),
        "established_exchange_count": established_exchanges,
        "non_established_exchange_count": len(exchanges) - established_exchanges,
        "transport_correlation_count": len(correlation.get("correlations") or []),
        "transport_observation_count": len(published_observations),
        "transport_correlations_omitted": len(observations)
        - len(published_observations),
        "attempt_bound_observation_count": source_scope["ATTEMPT"],
        "branch_bound_observation_count": source_scope["BRANCH"],
        "ambiguous_observation_count": source_scope["AMBIGUOUS"],
        "unbound_observation_count": source_scope["UNBOUND"],
        "supplied_unbound_signaling_observation_count": len(unbound_signaling),
        "unbound_signaling_observation_count": len(published_unbound),
        "unbound_signaling_observations_omitted": len(unbound_signaling)
        - len(published_unbound),
        "supplied_unmatched_rtp_stream_count": len(unmatched),
        "unmatched_rtp_stream_count": len(published_unmatched),
        "unmatched_rtp_streams_omitted": len(unmatched) - len(published_unmatched),
    }
    return {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "domain": DOMAIN,
        "capability": CAPABILITY,
        "input_provenance": provenance,
        "temporal_association_status": "NOT_EVALUATED",
        "association_scope": "CAPTURE_WIDE_ENDPOINT_CORRESPONDENCE_ONLY",
        "attempt_count": len(published_attempts),
        "attempts": published_attempts,
        "exchange_count": len(exchanges),
        "exchanges": exchanges,
        "transport_observation_count": len(published_observations),
        "transport_observations": published_observations,
        "unbound_signaling_observation_count": len(published_unbound),
        "unbound_signaling_observations": published_unbound,
        "unmatched_rtp_stream_count": len(published_unmatched),
        "unmatched_rtp_streams": published_unmatched,
        "completeness": completeness,
        "limitations": [
            "The Domain composes accepted IMS Session, IMS Media Signaling, SDP and SDP/RTP transport-correlation artifacts; it decodes no SIP or RTP and parses no SDP",
            "Endpoint correspondence is capture-wide; temporal association between RTP packets and the INVITE-to-BYE lifetime is NOT_EVALUATED",
            "A transport observation is not an IMS session identity, media-delivery proof, two-way-audio proof, codec-negotiation verdict or QoS measurement",
            "BUNDLE transport is preserved as one shared observation; RTP header-extension MID demultiplexing is not implemented",
            "ICE, NAT, STUN, TURN, DTLS and SRTP are not interpreted",
            "Provisional SDP and PRACK reliable Offer/Answer remain outside this milestone",
            "No timestamp proximity is used to create or select an association",
            "A later BYE does not prove RTP teardown, resource release or media-session success",
        ],
        "not_confirmed": [
            "MEDIA_DELIVERY",
            "TWO_WAY_AUDIO",
            "IMS_MEDIA_SESSION_SUCCESS",
            "TEMPORAL_MEDIA_ASSOCIATION",
            "RTP_TEARDOWN_AFTER_BYE",
            "CODEC_COMPATIBILITY",
            "MEDIA_QOS",
            "MOS",
            "ICE_CONNECTIVITY",
            "NAT_MAPPING",
        ],
    }


def validate_analysis(document: dict[str, Any]) -> None:
    if not isinstance(document, dict):
        raise InputError("IMS media session analysis must be an object")
    if document.get("analysis_name") != ANALYSIS_NAME:
        raise InputError("analysis_name is not accepted")
    if document.get("analysis_version") != ANALYSIS_VERSION:
        raise InputError("analysis_version is not accepted")
    if document.get("domain") != DOMAIN:
        raise InputError("domain is not accepted")
    if document.get("temporal_association_status") != "NOT_EVALUATED":
        raise InputError("temporal association cannot be claimed")
    if document.get("association_scope") != (
        "CAPTURE_WIDE_ENDPOINT_CORRESPONDENCE_ONLY"
    ):
        raise InputError("association_scope is not accepted")
    attempts = document.get("attempts")
    observations = document.get("transport_observations")
    exchanges = document.get("exchanges")
    unbound = document.get("unbound_signaling_observations")
    streams = document.get("unmatched_rtp_streams")
    for name, value in (
        ("attempts", attempts),
        ("transport_observations", observations),
        ("exchanges", exchanges),
        ("unbound_signaling_observations", unbound),
        ("unmatched_rtp_streams", streams),
    ):
        if not isinstance(value, list):
            raise InputError(f"{name} must be an array")
    if document.get("attempt_count") != len(attempts):
        raise InputError("attempt_count does not match the attempt array")
    if document.get("attempt_count") != (document.get("completeness") or {}).get(
        "published_attempt_count"
    ):
        raise InputError("published attempt count disagrees with the attempt array")
    if document.get("exchange_count") != len(exchanges):
        raise InputError("exchange_count does not match the exchange array")
    if document.get("transport_observation_count") != len(observations):
        raise InputError("transport_observation_count does not match the array")
    if document.get("unbound_signaling_observation_count") != len(unbound):
        raise InputError("unbound signaling observation count does not match")
    if document.get("unmatched_rtp_stream_count") != len(streams):
        raise InputError("unmatched RTP stream count does not match")
    attempt_references: set[str] = set()
    branch_references: set[str] = set()
    branch_total = 0
    for attempt in attempts:
        reference = attempt.get("attempt_reference")
        if not isinstance(reference, str) or not ATTEMPT_REFERENCE_PATTERN.fullmatch(
            reference
        ):
            raise InputError("an attempt reference is invalid")
        if reference in attempt_references:
            raise InputError("attempt references are not unique")
        attempt_references.add(reference)
        if attempt.get("branch_count") != len(attempt.get("branches") or []):
            raise InputError("an attempt branch_count disagrees")
        branch_total += len(attempt.get("branches") or [])
        for branch in attempt.get("branches") or []:
            branch_reference = branch.get("branch_reference")
            if not isinstance(branch_reference, str) or not branch_reference:
                raise InputError("a branch reference is invalid")
            if branch_reference in branch_references:
                raise InputError("branch references are not unique")
            branch_references.add(branch_reference)
            for key in (
                "branch_transport_observation_references",
                "shared_initial_offer_observation_references",
            ):
                for value in branch.get(key) or []:
                    if value not in {
                        item["observation_reference"] for item in observations
                    }:
                        raise InputError("a branch references a missing observation")
    if branch_total != (document.get("completeness") or {}).get(
        "published_branch_count"
    ):
        raise InputError("published branch count disagrees with the branch arrays")
    observation_references: set[str] = set()
    correlation_references: set[str] = set()
    for observation in observations:
        reference = observation.get("observation_reference")
        if (
            not isinstance(reference, str)
            or not OBSERVATION_REFERENCE_PATTERN.fullmatch(reference)
        ):
            raise InputError("a transport observation reference is invalid")
        if reference in observation_references:
            raise InputError("transport observation references are not unique")
        observation_references.add(reference)
        correlation = observation.get("correlation_reference")
        if (
            not isinstance(correlation, str)
            or not CORRELATION_REFERENCE_PATTERN.fullmatch(correlation)
        ):
            raise InputError("a transport correlation reference is invalid")
        if correlation in correlation_references:
            raise InputError("a transport correlation reference is duplicated")
        correlation_references.add(correlation)
        if observation.get("binding_scope") not in BINDING_SCOPES:
            raise InputError("a binding scope is invalid")
        if observation.get("binding_status") not in BINDING_STATUSES:
            raise InputError("a binding status is invalid")
        if observation.get("temporal_association_status") != "NOT_EVALUATED":
            raise InputError("temporal association cannot be claimed")
        if observation.get("association_scope") != (
            "CAPTURE_WIDE_ENDPOINT_CORRESPONDENCE_ONLY"
        ):
            raise InputError("association_scope is not accepted")
        if observation.get("evidence_class") != "DERIVED":
            raise InputError("observation evidence_class must be DERIVED")
        if not observation.get("sdp_message_bindings"):
            raise InputError("a transport observation has no SDP binding")
        for binding in observation["sdp_message_bindings"]:
            if not binding.get("roles"):
                raise InputError("an SDP binding has no role")
            for role in binding["roles"]:
                if role not in BINDING_ROLES:
                    raise InputError("an SDP binding role is invalid")
        for value in observation.get("endpoint_references") or []:
            if not is_endpoint_reference(value):
                raise InputError("an observation endpoint reference is malformed")
        for value in observation.get("rtp_udp_stream_references") or []:
            if not STREAM_REFERENCE_PATTERN.fullmatch(value):
                raise InputError("an observation stream reference is invalid")
        for value in observation.get("bundle_references") or []:
            if not isinstance(value, str) or not value.startswith("sdp-bundle:"):
                raise InputError("an observation bundle reference is invalid")
        for value in observation.get("exchange_references") or []:
            if not EXCHANGE_REFERENCE_PATTERN.fullmatch(value):
                raise InputError("an observation exchange reference is invalid")
    exchange_references: set[str] = set()
    for exchange in exchanges:
        reference = exchange.get("exchange_reference")
        if not isinstance(reference, str) or not EXCHANGE_REFERENCE_PATTERN.fullmatch(
            reference
        ):
            raise InputError("an exchange reference is invalid")
        if reference in exchange_references:
            raise InputError("exchange references are not unique")
        exchange_references.add(reference)
        for value in exchange.get("transport_observation_references") or []:
            if value not in observation_references:
                raise InputError("an exchange references a missing observation")
    unbound_references: set[str] = set()
    for observation in unbound:
        reference = observation.get("observation_reference")
        if not isinstance(reference, str) or not reference:
            raise InputError("an unbound signaling observation reference is invalid")
        if reference in unbound_references:
            raise InputError("unbound signaling observation references are not unique")
        unbound_references.add(reference)
    stream_references: set[str] = set()
    for stream in streams:
        reference = stream.get("rtp_udp_stream_reference")
        if not isinstance(reference, str) or not STREAM_REFERENCE_PATTERN.fullmatch(
            reference
        ):
            raise InputError("an unmatched RTP stream reference is invalid")
        if reference in stream_references:
            raise InputError("unmatched RTP stream references are not unique")
        stream_references.add(reference)
    completeness = document.get("completeness") or {}
    if completeness.get("ims_session_attempt_count") != (
        completeness.get("published_attempt_count", 0)
        + completeness.get("attempts_omitted", 0)
    ):
        raise InputError("attempt count conservation failed")
    if completeness.get("dialog_branch_count") != (
        completeness.get("published_branch_count", 0)
        + completeness.get("branches_omitted", 0)
    ):
        raise InputError("branch count conservation failed")
    if completeness.get("signaling_exchange_count") != (
        completeness.get("established_exchange_count", 0)
        + completeness.get("non_established_exchange_count", 0)
    ):
        raise InputError("exchange count conservation failed")
    if completeness.get("published_exchange_count") != len(exchanges):
        raise InputError("published exchange count disagrees with the exchange array")
    if completeness.get("transport_correlation_count") != (
        completeness.get("transport_observation_count", 0)
        + completeness.get("transport_correlations_omitted", 0)
    ):
        raise InputError("transport correlation count conservation failed")
    if completeness.get("transport_observation_count") != (
        completeness.get("attempt_bound_observation_count", 0)
        + completeness.get("branch_bound_observation_count", 0)
        + completeness.get("ambiguous_observation_count", 0)
        + completeness.get("unbound_observation_count", 0)
    ):
        raise InputError("transport observation scope count conservation failed")
    if completeness.get("supplied_unbound_signaling_observation_count") != (
        completeness.get("unbound_signaling_observation_count", 0)
        + completeness.get("unbound_signaling_observations_omitted", 0)
    ):
        raise InputError("unbound signaling count conservation failed")
    if completeness.get("supplied_unmatched_rtp_stream_count") != (
        completeness.get("unmatched_rtp_stream_count", 0)
        + completeness.get("unmatched_rtp_streams_omitted", 0)
    ):
        raise InputError("unmatched stream count conservation failed")
    context = (document.get("input_provenance") or {}).get(
        "endpoint_context_reference"
    )
    if context is None and any(
        item.get("endpoint_references") for item in observations
    ):
        raise InputError("endpoint references are present without a context reference")
    for forbidden in (
        "source_address",
        "destination_address",
        "source_port",
        "destination_port",
        "call_id",
        "from_tag",
        "to_tag",
        "sip_uri",
        "sdp_body",
        "rtp_payload",
        "hmac_key",
        "endpoint_key",
        "key_path",
    ):
        if forbidden in document:
            raise InputError(f"forbidden raw field published: {forbidden}")