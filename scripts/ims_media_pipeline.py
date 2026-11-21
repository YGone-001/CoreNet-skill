#!/usr/bin/env python3
"""Application-level IMS media pipeline used by the unified workflow.

This module is orchestration glue, not a CoreNet Skill. It executes the already
accepted SIP/SDP/RTP and IMS media Skills in dependency order, keeps every stage
independent, and publishes bounded evidence summaries. Raw SIP/SDP bodies and
RTP payloads are never published; the private SDP adapter retains bodies only in
memory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ims_call_diagnostics  # noqa: E402
SDP_BODY_ADAPTER = ROOT / "scripts" / "extract-sdp-bodies.py"
IMS_MEDIA_SIGNALING = ROOT / "skills" / "domain" / "ims-media-signaling" / "scripts" / "analyze-ims-media-signaling.py"
RTP_RTCP_EXTRACT = ROOT / "skills" / "protocol" / "sdp-rtp" / "scripts" / "extract-rtp-rtcp.py"
RTP_STREAM = ROOT / "skills" / "protocol" / "rtp-stream" / "scripts" / "reconstruct-rtp-streams.py"
SDP_RTP_TRANSPORT = ROOT / "skills" / "correlation" / "sdp-rtp-transport" / "scripts" / "correlate-sdp-rtp-transport.py"
IMS_MEDIA_SESSION = ROOT / "skills" / "domain" / "ims-media-session" / "scripts" / "analyze-ims-media-session.py"

MAX_LIST_ITEMS = 32
MAX_EXCHANGES = 32
MAX_STREAMS = 16
MAX_CORRELATIONS = 32
MAX_OBSERVATIONS = 32
MAX_CALLS = 64
MAX_DIAGNOSTIC_ITEMS = 16
KEY_SIZE = 32

MEDIA_STATUSES = (
    "SUCCESS",
    "PARTIAL",
    "INSUFFICIENT_EVIDENCE",
    "UNSUPPORTED",
    "FAILED",
)
STAGE_STATUSES = (
    "SUCCESS",
    "NOT_OBSERVED_IN_CAPTURE",
    "SKIPPED",
    "FAILED",
)
PATH_PATTERN = re.compile(r"(?:/[\w.@+-]+){2,}")
REFERENCE_FRAME_PATTERN = re.compile(r":([0-9]+)\.[0-9]+(?:\.[0-9]+)?$")


class MediaError(ValueError):
    """Raised when the media orchestration contract cannot be satisfied."""


Runner = Callable[..., Any]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load(path: Path) -> dict[str, Any] | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _count_lines(path: Path) -> int:
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except OSError:
        return 0


def _detail(text: str | None) -> str:
    if not text:
        return ""
    line = text.strip().splitlines()[0] if text.strip() else ""
    line = PATH_PATTERN.sub("<path>", line)
    return line[:240]


def _run(command: list[str], runner: Runner, label: str) -> tuple[str, str | None]:
    try:
        completed = runner(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        return "FAILED", f"{label} could not start: {_detail(str(exc))}"
    code = int(completed.returncode)
    if code == 0:
        return "SUCCESS", None
    if code == 3:
        return "NOT_OBSERVED_IN_CAPTURE", _detail(completed.stderr or completed.stdout) or f"{label} found no evidence"
    return "FAILED", _detail(completed.stderr or completed.stdout) or f"{label} exited with {code}"


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _validate_key(path: Path) -> bytes:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise MediaError("endpoint key file is missing or unreadable") from exc
    if os.name == "posix" and mode & 0o077:
        raise MediaError("endpoint key file must be owner-only (0600)")
    material = path.read_bytes()
    if len(material) != KEY_SIZE:
        raise MediaError("endpoint key file must contain exactly 32 bytes")
    return material


def _resolve_key(
    capture_sha256: str,
    endpoint_key_file: Path | None,
) -> tuple[Path, str]:
    if endpoint_key_file is not None:
        if _inside(endpoint_key_file, ROOT):
            raise MediaError("endpoint key file must not live inside the repository")
        _validate_key(endpoint_key_file)
        return endpoint_key_file, "SUPPLIED"
    key_dir = Path(
        os.environ.get(
            "CORENET_ENDPOINT_KEY_DIR",
            str(Path.home() / ".local/share/corenet-skill" / "endpoint-keys"),
        )
    )
    if _inside(key_dir, ROOT):
        raise MediaError("endpoint key directory must not live inside the repository")
    key_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(key_dir, 0o700)
    key_path = key_dir / f"{capture_sha256}.key"
    if key_path.exists():
        _validate_key(key_path)
        return key_path, "REUSED"
    descriptor: int | None = None
    try:
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        material = secrets.token_bytes(KEY_SIZE)
        written = 0
        while written < KEY_SIZE:
            written += os.write(descriptor, material[written:])
        os.close(descriptor)
        descriptor = None
        if os.name == "posix":
            os.chmod(key_path, 0o600)
        if len(_validate_key(key_path)) != KEY_SIZE:
            raise MediaError("endpoint key creation did not produce 32 bytes")
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        key_path.unlink(missing_ok=True)
        raise MediaError(f"endpoint key creation failed: {_detail(str(exc))}") from exc
    return key_path, "CREATED"


def _artifact(path: Path, label: str, count: int | None) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return {
        "label": label,
        "file_name": path.name,
        "sha256": _sha256(path),
        "record_count": count,
    }


def _media_types(messages: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for message in messages:
        for media in message.get("media_sections") or []:
            if not isinstance(media, dict):
                continue
            media_type = media.get("media_type")
            key = media_type if isinstance(media_type, str) and media_type else "UNKNOWN"
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _direction_counts(messages: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for message in messages:
        for media in message.get("media_sections") or []:
            if not isinstance(media, dict):
                continue
            direction = media.get("direction") or "UNSPECIFIED"
            counts[direction] = counts.get(direction, 0) + 1
    return dict(sorted(counts.items()))


def _sdp_summary(document: dict[str, Any] | None) -> dict[str, Any]:
    if document is None:
        return {"analysis_status": "NOT_OBSERVED_IN_CAPTURE", "message_count": 0}
    messages = [item for item in document.get("messages") or [] if isinstance(item, dict)]
    media_sections = sum(len(item.get("media_sections") or []) for item in messages)
    completeness = document.get("completeness") or {}
    return {
        "analysis_status": "COMPLETED" if messages else "INSUFFICIENT_EVIDENCE",
        "message_count": len(messages),
        "media_section_count": media_sections,
        "media_type_counts": _media_types(messages),
        "direction_counts": _direction_counts(messages),
        "mid_present_count": sum(
            1
            for item in messages
            for media in item.get("media_sections") or []
            if isinstance(media, dict) and media.get("mid")
        ),
        "observed_message_count": completeness.get("observed_message_count", len(messages)),
        "incomplete_message_count": completeness.get("incomplete_message_count", 0),
        "unsupported_message_count": completeness.get("unsupported_message_count", 0),
        "ambiguous_message_count": completeness.get("ambiguous_message_count", 0),
        "limitations": list(document.get("limitations") or [])[:MAX_LIST_ITEMS],
        "not_confirmed": list(document.get("not_confirmed") or [])[:MAX_LIST_ITEMS],
    }


def _signaling_summary(document: dict[str, Any] | None) -> dict[str, Any]:
    if document is None:
        return {"analysis_status": "NOT_OBSERVED_IN_CAPTURE", "exchange_count": 0}
    completeness = document.get("completeness") or {}
    exchanges = []
    for item in (document.get("exchanges") or [])[:MAX_EXCHANGES]:
        if not isinstance(item, dict):
            continue
        exchanges.append(
            {
                "exchange_reference": item.get("exchange_reference"),
                "exchange_type": item.get("exchange_type"),
                "association_status": item.get("association_status"),
                "initial_sdp_state": item.get("initial_sdp_state"),
                "branch_identity_status": item.get("branch_identity_status"),
                "branch_reference": item.get("branch_reference"),
                "offer_reference": (item.get("offer") or {}).get("sip_event_reference")
                if isinstance(item.get("offer"), dict) else None,
                "answer_reference": (item.get("answer") or {}).get("sip_event_reference")
                if isinstance(item.get("answer"), dict) else None,
                "missing_evidence": list(item.get("missing_evidence") or [])[:MAX_LIST_ITEMS],
            }
        )
    return {
        "analysis_status": "COMPLETED" if exchanges else "INSUFFICIENT_EVIDENCE",
        "exchange_count": int(document.get("exchange_count") or len(exchanges)),
        "supplied_sdp_message_count": completeness.get("supplied_sdp_message_count", 0),
        "matched_sip_event_count": completeness.get("matched_sip_event_count", 0),
        "observed_offer_count": completeness.get("observed_offer_count", 0),
        "observed_answer_count": completeness.get("observed_answer_count", 0),
        "established_exchange_count": completeness.get("established_exchange_count", 0),
        "incomplete_exchange_count": completeness.get("incomplete_exchange_count", 0),
        "ambiguous_exchange_count": completeness.get("ambiguous_exchange_count", 0),
        "out_of_scope_observation_count": completeness.get("out_of_scope_observation_count", 0),
        "exchanges": exchanges,
        "limitations": list(document.get("limitations") or [])[:MAX_LIST_ITEMS],
    }


def _rtp_summary(
    document: dict[str, Any] | None, stream_document: dict[str, Any] | None
) -> dict[str, Any]:
    if document is None:
        return {"analysis_status": "NOT_OBSERVED_IN_CAPTURE", "rtp_packet_count": 0}
    rtp_events = [
        event for event in document.get("events") or []
        if isinstance(event, dict) and event.get("protocol") == "RTP"
    ]
    rtcp_events = [
        event for event in document.get("events") or []
        if isinstance(event, dict) and event.get("protocol") == "RTCP"
    ]
    streams = [item for item in (stream_document or {}).get("source_streams") or [] if isinstance(item, dict)]
    sequence_summary = {
        "source_stream_count": (stream_document or {}).get("source_stream_count", 0),
        "validated_stream_count": sum(
            1 for item in streams if item.get("sequence_validation_status") == "VALIDATED"
        ),
        "probation_stream_count": sum(
            1 for item in streams if item.get("sequence_validation_status") == "PROBATION"
        ),
        "ambiguous_stream_count": sum(
            1 for item in streams if item.get("sequence_validation_status") == "AMBIGUOUS"
        ),
        "insufficient_stream_count": sum(
            1 for item in streams if item.get("sequence_validation_status") == "INSUFFICIENT_EVIDENCE"
        ),
        "sequence_wrap_count": sum(int(item.get("sequence_wrap_count") or 0) for item in streams),
        "duplicate_observation_count": sum(
            int(item.get("duplicate_sequence_observation_count") or 0) for item in streams
        ),
        "out_of_order_observation_count": sum(
            int(item.get("out_of_order_packet_count") or 0) for item in streams
        ),
        "sequence_gap_count": sum(
            int(item.get("observed_sequence_gap_count") or 0) for item in streams
        ),
        "unobserved_sequence_number_slot_count": sum(
            int(item.get("unobserved_sequence_number_slot_count") or 0) for item in streams
        ),
        "restart_pattern_count": sum(
            int(item.get("restart_pattern_count") or 0) for item in streams
        ),
        "streams": [
            {
                "source_stream_reference": item.get("source_stream_reference"),
                "sequence_validation_status": item.get("sequence_validation_status"),
                "rtp_packet_count": item.get("rtp_packet_count"),
                "first_frame_number": item.get("first_frame_number"),
                "last_frame_number": item.get("last_frame_number"),
                "sequence_wrap_count": item.get("sequence_wrap_count"),
                "duplicate_sequence_observation_count": item.get(
                    "duplicate_sequence_observation_count"
                ),
                "out_of_order_packet_count": item.get("out_of_order_packet_count"),
                "observed_sequence_gap_count": item.get("observed_sequence_gap_count"),
                "unobserved_sequence_number_slot_count": item.get(
                    "unobserved_sequence_number_slot_count"
                ),
                "restart_pattern_count": item.get("restart_pattern_count"),
                "endpoint_evidence_status": item.get("endpoint_evidence_status"),
                "missing_evidence": list(item.get("missing_evidence") or [])[:MAX_LIST_ITEMS],
            }
            for item in streams[:MAX_STREAMS]
        ],
        "rtcp_event_count": (stream_document or {}).get("rtcp_event_count", len(rtcp_events)),
        "rtcp_observation_status": (stream_document or {}).get(
            "rtcp_observation_status", "NOT_INTERPRETED_FOR_RTP_STREAM_ASSOCIATION"
        ),
    }
    frames = [
        event.get("frame_number")
        for event in rtp_events
        if isinstance(event.get("frame_number"), int)
    ]
    return {
        "analysis_status": "COMPLETED" if rtp_events else "INSUFFICIENT_EVIDENCE",
        "rtp_packet_count": len(rtp_events),
        "rtcp_component_count": len(rtcp_events),
        "udp_stream_count": len(
            {event.get("udp_stream") for event in rtp_events if event.get("udp_stream") is not None}
        ),
        "ssrc_reference_count": len(
            {event.get("ssrc_reference") for event in rtp_events if event.get("ssrc_reference")}
        ),
        "first_frame_number": min(frames) if frames else None,
        "last_frame_number": max(frames) if frames else None,
        "sequence": sequence_summary,
        "limitations": list((stream_document or {}).get("limitations") or [])[:MAX_LIST_ITEMS],
        "not_confirmed": list((stream_document or {}).get("not_confirmed") or [])[:MAX_LIST_ITEMS],
    }


def _correlation_summary(document: dict[str, Any] | None) -> dict[str, Any]:
    if document is None:
        return {"analysis_status": "NOT_OBSERVED_IN_CAPTURE", "correlation_count": 0}
    correlations = [
        item for item in document.get("correlations") or [] if isinstance(item, dict)
    ]
    completeness = document.get("completeness") or {}
    matched = [item for item in correlations if item.get("association_status") in (
        "MATCHED_ENDPOINT", "BUNDLE_TRANSPORT_MATCHED"
    )]
    return {
        "analysis_status": "COMPLETED" if correlations else "INSUFFICIENT_EVIDENCE",
        "correlation_count": len(correlations),
        "matched_correlation_count": completeness.get("matched_correlation_count", len(matched)),
        "bundle_matched_correlation_count": completeness.get("bundle_matched_correlation_count", 0),
        "ambiguous_correlation_count": completeness.get("ambiguous_correlation_count", 0),
        "insufficient_correlation_count": completeness.get("insufficient_correlation_count", 0),
        "unmatched_correlation_count": completeness.get("unmatched_correlation_count", 0),
        "out_of_scope_correlation_count": completeness.get("out_of_scope_correlation_count", 0),
        "unmatched_stream_count": document.get("unmatched_stream_count", 0),
        "matched_correlations": [
            {
                "correlation_reference": item.get("correlation_reference"),
                "association_status": item.get("association_status"),
                "correlation_strength": item.get("correlation_strength"),
                "sdp_message_references": list(item.get("sdp_message_references") or [])[:MAX_LIST_ITEMS],
                "rtp_udp_stream_references": list(item.get("rtp_udp_stream_references") or [])[:MAX_LIST_ITEMS],
                "match_directions": list(item.get("match_directions") or [])[:MAX_LIST_ITEMS],
                "missing_evidence": list(item.get("missing_evidence") or [])[:MAX_LIST_ITEMS],
                "conflict_findings": list(item.get("conflict_findings") or [])[:MAX_LIST_ITEMS],
            }
            for item in matched[:MAX_CORRELATIONS]
        ],
        "limitations": list(document.get("limitations") or [])[:MAX_LIST_ITEMS],
    }


def _media_session_summary(document: dict[str, Any] | None) -> dict[str, Any]:
    if document is None:
        return {"analysis_status": "NOT_OBSERVED_IN_CAPTURE", "attempt_count": 0}
    completeness = document.get("completeness") or {}
    observations = [
        item for item in document.get("transport_observations") or [] if isinstance(item, dict)
    ]
    associated = [
        item for item in observations
        if item.get("association_scope") in ("ATTEMPT", "BRANCH")
        and item.get("association_status") == "ESTABLISHED"
    ]
    return {
        "analysis_status": "COMPLETED" if observations else "INSUFFICIENT_EVIDENCE",
        "attempt_count": int(document.get("attempt_count") or 0),
        "exchange_count": int(document.get("exchange_count") or 0),
        "established_exchange_count": completeness.get("established_exchange_count", 0),
        "non_established_exchange_count": completeness.get("non_established_exchange_count", 0),
        "ambiguous_observation_count": completeness.get("ambiguous_observation_count", 0),
        "attempt_bound_observation_count": completeness.get("attempt_bound_observation_count", 0),
        "branch_bound_observation_count": completeness.get("branch_bound_observation_count", 0),
        "transport_observation_count": int(document.get("transport_observation_count") or 0),
        "unbound_signaling_observation_count": int(
            document.get("unbound_signaling_observation_count") or 0
        ),
        "unmatched_rtp_stream_count": int(document.get("unmatched_rtp_stream_count") or 0),
        "temporal_association_status": document.get("temporal_association_status"),
        "associated_observations": [
            {
                "observation_reference": item.get("observation_reference"),
                "association_scope": item.get("association_scope"),
                "association_status": item.get("association_status"),
                "attempt_reference": item.get("attempt_reference"),
                "dialog_branch_reference": item.get("dialog_branch_reference"),
                "offer_answer_exchange_reference": item.get("offer_answer_exchange_reference"),
                "correlation_references": list(item.get("correlation_references") or [])[:MAX_LIST_ITEMS],
                "rtp_udp_stream_references": list(item.get("rtp_udp_stream_references") or [])[:MAX_LIST_ITEMS],
                "missing_evidence": list(item.get("missing_evidence") or [])[:MAX_LIST_ITEMS],
            }
            for item in associated[:MAX_OBSERVATIONS]
        ],
        "limitations": list(document.get("limitations") or [])[:MAX_LIST_ITEMS],
        "not_confirmed": list(document.get("not_confirmed") or [])[:MAX_LIST_ITEMS],
    }


def _last_evidence(
    sip_last_frame: int | None,
    sdp_summary: dict[str, Any],
    rtp_summary: dict[str, Any],
    correlation: dict[str, Any],
    media_session: dict[str, Any],
) -> dict[str, Any] | None:
    candidates: list[tuple[int, dict[str, Any]]] = []
    if sip_last_frame is not None:
        candidates.append((sip_last_frame, {"stage": "SIP", "reference": f"frame:{sip_last_frame}", "frame_number": sip_last_frame}))
    for item in sdp_summary.get("messages") or []:
        frame = item.get("frame_number")
        reference = item.get("source_reference")
        if isinstance(frame, int) and isinstance(reference, str):
            candidates.append((frame, {"stage": "SDP", "reference": reference, "frame_number": frame}))
    if isinstance(rtp_summary.get("last_frame_number"), int):
        frame = rtp_summary["last_frame_number"]
        candidates.append((frame, {"stage": "RTP", "reference": f"frame:{frame}", "frame_number": frame}))
    for item in media_session.get("associated_observations") or []:
        reference = item.get("observation_reference")
        match = REFERENCE_FRAME_PATTERN.search(reference) if isinstance(reference, str) else None
        if match:
            frame = int(match.group(1))
            candidates.append((frame, {"stage": "IMS_MEDIA", "reference": reference, "frame_number": frame}))
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], item[1]["reference"]))[1]


def _media_status(
    stages: dict[str, str],
    sdp_summary: dict[str, Any],
    rtp_summary: dict[str, Any],
    correlation: dict[str, Any],
    media_session: dict[str, Any],
    signaling: dict[str, Any],
) -> tuple[str, list[str]]:
    basis: list[str] = []
    failed = [name for name, status in stages.items() if status == "FAILED"]
    if failed:
        basis.append("STAGE_FAILURE:" + ",".join(sorted(failed)))
        if sdp_summary.get("analysis_status") == "COMPLETED" or rtp_summary.get("analysis_status") == "COMPLETED":
            return "PARTIAL", basis
        return "FAILED", basis
    if sdp_summary.get("analysis_status") != "COMPLETED" and rtp_summary.get(
        "analysis_status"
    ) != "COMPLETED":
        basis.append("NO_SDP_OR_RTP_EVIDENCE")
        return "INSUFFICIENT_EVIDENCE", basis
    if signaling.get("observed_offer_count", 0) == 0 and rtp_summary.get(
        "rtp_packet_count", 0
    ) == 0:
        basis.append("NO_INVITE_OR_MEDIA_OBSERVED")
        return "INSUFFICIENT_EVIDENCE", basis
    if correlation.get("matched_correlation_count", 0) == 0:
        basis.append("SDP_RTP_CORRELATION_NOT_MATCHED")
        if sdp_summary.get("analysis_status") == "COMPLETED" and rtp_summary.get(
            "analysis_status"
        ) == "COMPLETED":
            return "PARTIAL", basis
        return "INSUFFICIENT_EVIDENCE", basis
    if signaling.get("observed_offer_count", 0) and not signaling.get(
        "observed_answer_count", 0
    ):
        basis.append("SDP_ANSWER_NOT_OBSERVED")
        return "PARTIAL", basis
    if media_session.get(
        "established_exchange_count", 0
    ) == 0 and media_session.get("attempt_bound_observation_count", 0) == 0 and media_session.get(
        "branch_bound_observation_count", 0
    ) == 0:
        basis.append("IMS_MEDIA_ASSOCIATION_NOT_ESTABLISHED")
        return "PARTIAL", basis
    basis.append("SDP_RTP_AND_IMS_MEDIA_ASSOCIATION_OBSERVED")
    return "SUCCESS", basis


def execute_media_pipeline(
    *,
    capture: Path,
    run_dir: Path,
    sip_events: Path,
    ims_session: Path,
    capture_sha256: str,
    offline: bool,
    endpoint_key_file: Path | None = None,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Execute the media skills and return one bounded media evidence summary."""
    runner = runner or subprocess.run
    media_dir = run_dir / "media"
    media_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(media_dir, 0o700)
    sdp_path = media_dir / "sdp-analysis.json"
    sdp_report = media_dir / "sdp-report.txt"
    signaling_path = media_dir / "ims-media-signaling.json"
    signaling_report = media_dir / "ims-media-signaling-report.txt"
    rtp_path = media_dir / "rtp-rtcp-analysis.json"
    rtp_report = media_dir / "rtp-rtcp-report.txt"
    stream_path = media_dir / "rtp-stream-analysis.json"
    stream_report = media_dir / "rtp-stream-report.txt"
    correlation_path = media_dir / "sdp-rtp-transport.json"
    correlation_report = media_dir / "sdp-rtp-transport-report.txt"
    media_session_path = media_dir / "ims-media-session.json"
    media_session_report = media_dir / "ims-media-session-report.txt"

    stages: dict[str, str] = {}
    errors: dict[str, str] = {}
    key_status = "NOT_REQUIRED"
    key_path: Path | None = None

    try:
        key_path, key_status = _resolve_key(capture_sha256, endpoint_key_file)
    except MediaError as exc:
        stages["endpoint_key"] = "FAILED"
        errors["endpoint_key"] = str(exc)

    if sdp_path.exists() is False and stages.get("endpoint_key") != "FAILED":
        stages["sdp_extraction"], error = _run(
            [
                sys.executable,
                str(SDP_BODY_ADAPTER),
                "--capture",
                str(capture),
                "--sip-events",
                str(sip_events),
                "--endpoint-key-file",
                str(key_path),
                "--output",
                str(sdp_path),
                "--report",
                str(sdp_report),
                "--force",
            ],
            runner,
            "SDP extraction",
        )
        if error:
            errors["sdp_extraction"] = error
    elif stages.get("endpoint_key") == "FAILED":
        stages["sdp_extraction"] = "SKIPPED"
    sdp_document = _load(sdp_path)
    sdp_summary = _sdp_summary(sdp_document)

    if sdp_summary["analysis_status"] == "COMPLETED" and ims_session.is_file():
        stages["ims_media_signaling"], error = _run(
            [
                sys.executable,
                str(IMS_MEDIA_SIGNALING),
                "--sip-events",
                str(sip_events),
                "--ims-session",
                str(ims_session),
                "--sdp-analysis",
                str(sdp_path),
                "--output",
                str(signaling_path),
                "--report",
                str(signaling_report),
                "--force",
            ],
            runner,
            "IMS media signaling",
        )
        if error:
            errors["ims_media_signaling"] = error
    else:
        stages["ims_media_signaling"] = "SKIPPED"
    signaling_document = _load(signaling_path)
    signaling_summary = _signaling_summary(signaling_document)

    if stages.get("endpoint_key") != "FAILED":
        stages["rtp_extraction"], error = _run(
            [
                sys.executable,
                str(RTP_RTCP_EXTRACT),
                "--input",
                str(capture),
                "--input-format",
                "capture",
                "--output",
                str(rtp_path),
                "--report",
                str(rtp_report),
                "--endpoint-key-file",
                str(key_path),
                "--force",
            ],
            runner,
            "RTP/RTCP extraction",
        )
        if error:
            errors["rtp_extraction"] = error
    else:
        stages["rtp_extraction"] = "SKIPPED"
    rtp_document = _load(rtp_path)

    if rtp_document is not None:
        stages["rtp_stream"], error = _run(
            [
                sys.executable,
                str(RTP_STREAM),
                "--rtp-rtcp-analysis",
                str(rtp_path),
                "--output",
                str(stream_path),
                "--report",
                str(stream_report),
                "--force",
            ],
            runner,
            "RTP source-stream reconstruction",
        )
        if error:
            errors["rtp_stream"] = error
    else:
        stages["rtp_stream"] = "SKIPPED"
    stream_document = _load(stream_path)
    rtp_summary = _rtp_summary(rtp_document, stream_document)

    if sdp_document is not None and rtp_document is not None:
        stages["sdp_rtp_transport"], error = _run(
            [
                sys.executable,
                str(SDP_RTP_TRANSPORT),
                "--sdp-analysis",
                str(sdp_path),
                "--rtp-rtcp-analysis",
                str(rtp_path),
                "--output",
                str(correlation_path),
                "--report",
                str(correlation_report),
                "--force",
            ],
            runner,
            "SDP/RTP transport correlation",
        )
        if error:
            errors["sdp_rtp_transport"] = error
    else:
        stages["sdp_rtp_transport"] = "SKIPPED"
    correlation_document = _load(correlation_path)
    correlation_summary = _correlation_summary(correlation_document)

    if (
        ims_session.is_file()
        and signaling_document is not None
        and sdp_document is not None
        and correlation_document is not None
    ):
        stages["ims_media_session"], error = _run(
            [
                sys.executable,
                str(IMS_MEDIA_SESSION),
                "--ims-session-analysis",
                str(ims_session),
                "--ims-media-signaling-analysis",
                str(signaling_path),
                "--sdp-analysis",
                str(sdp_path),
                "--transport-correlation",
                str(correlation_path),
                "--output",
                str(media_session_path),
                "--report",
                str(media_session_report),
                "--force",
            ],
            runner,
            "IMS media session",
        )
        if error:
            errors["ims_media_session"] = error
    else:
        stages["ims_media_session"] = "SKIPPED"
    media_session_document = _load(media_session_path)
    media_session_summary = _media_session_summary(media_session_document)

    diagnostics_path = media_dir / "ims-call-diagnostics.json"
    call_diagnostics: dict[str, Any] = {}
    if sip_events.is_file() and ims_session.is_file():
        try:
            call_diagnostics = ims_call_diagnostics.build_diagnostics(
                capture=capture,
                capture_sha256=capture_sha256,
                sip_events_path=sip_events,
                ims_session_path=ims_session,
                media_signaling_path=signaling_path,
                sdp_path=sdp_path,
                correlation_path=correlation_path,
                rtp_rtcp_path=rtp_path,
                rtp_stream_path=stream_path,
            )
            temporary = diagnostics_path.with_suffix(".json.tmp")
            temporary.write_text(
                json.dumps(call_diagnostics, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.replace(temporary, diagnostics_path)
            os.chmod(diagnostics_path, 0o600)
            stages["per_call_diagnostics"] = "SUCCESS"
        except Exception as exc:  # pragma: no cover - defensive orchestration guard
            errors["per_call_diagnostics"] = _detail(str(exc))
            stages["per_call_diagnostics"] = "FAILED"
            call_diagnostics = {}
    else:
        stages["per_call_diagnostics"] = "SKIPPED"

    # The bounded last-evidence record needs SDP message frames.
    sdp_for_last = {
        "messages": list((sdp_document or {}).get("messages") or [])
    }
    sip_last_frame = None
    try:
        for line in sip_events.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            frame = event.get("frame_number")
            if isinstance(frame, int) and not isinstance(frame, bool):
                sip_last_frame = frame if sip_last_frame is None else max(sip_last_frame, frame)
    except (OSError, json.JSONDecodeError):
        sip_last_frame = None

    endpoint_contexts = {
        value
        for value in (
            ((sdp_document or {}).get("input_provenance") or {}).get("endpoint_context_reference"),
            ((rtp_document or {}).get("input_provenance") or {}).get("endpoint_context_reference"),
        )
        if isinstance(value, str)
    }
    if len({value for value in endpoint_contexts if value}) > 1:
        stages["endpoint_context"] = "FAILED"
        errors["endpoint_context"] = "SDP and RTP endpoint contexts differ"

    media_status, basis = _media_status(
        stages,
        sdp_summary,
        rtp_summary,
        correlation_summary,
        media_session_summary,
        signaling_summary,
    )
    if not offline:
        basis.append("OFFLINE_MODE_NOT_REQUESTED")
    if endpoint_contexts:
        basis.append("SHARED_ENDPOINT_CONTEXT_PRESENT")
    call_summary = call_diagnostics.get("call_evidence_summary") or {}
    logical_ownership = call_diagnostics.get("logical_call_ownership_counts") or {}
    logical_total = sum(logical_ownership.values())
    logical_owned = logical_ownership.get("LOGICAL_CALL_MEDIA_OWNED", 0)
    if logical_total:
        if logical_owned == logical_total:
            basis.append("LOGICAL_CALL_MEDIA_OWNERSHIP_UNIFORM")
        else:
            if media_status == "SUCCESS":
                media_status = "PARTIAL"
            basis.append("PER_CALL_MEDIA_EVIDENCE_NOT_UNIFORMLY_SUPPORTED")
        if logical_owned == 0:
            basis.append("PER_CALL_MEDIA_OWNERSHIP_AMBIGUOUS")
            basis.append(
                "CAPTURE_WIDE_MEDIA_STATUS_DOES_NOT_IMPLY_PER_CALL_OWNERSHIP"
            )
    elif call_summary.get("attempt_count"):
        if not call_summary.get("all_attempts_supported"):
            if media_status == "SUCCESS":
                media_status = "PARTIAL"
            basis.append("PER_CALL_MEDIA_EVIDENCE_NOT_UNIFORMLY_SUPPORTED")
        if call_summary.get("supported_attempt_count") == 0 and call_summary.get(
            "ambiguous_attempt_count", 0
        ):
            basis.append("PER_CALL_MEDIA_OWNERSHIP_AMBIGUOUS")
            basis.append(
                "CAPTURE_WIDE_MEDIA_STATUS_DOES_NOT_IMPLY_PER_CALL_OWNERSHIP"
            )

    observed: list[str] = []
    missing: list[str] = []
    ambiguous: list[str] = []
    unsupported: list[str] = []
    if sip_last_frame is not None:
        observed.append(f"SIP events observed through frame {sip_last_frame}")
    if sdp_summary.get("message_count"):
        observed.append(
            f"{sdp_summary['message_count']} SDP message(s), "
            f"{sdp_summary['media_section_count']} media section(s)"
        )
    if rtp_summary.get("rtp_packet_count"):
        observed.append(
            f"{rtp_summary['rtp_packet_count']} RTP packet(s), "
            f"{rtp_summary['rtcp_component_count']} RTCP component(s)"
        )
    if rtp_summary.get("sequence", {}).get("source_stream_count"):
        sequence = rtp_summary["sequence"]
        observed.append(
            f"{sequence['source_stream_count']} RTP source stream(s), "
            f"{sequence['duplicate_observation_count']} duplicate and "
            f"{sequence['out_of_order_observation_count']} out-of-order observation(s)"
        )
    if correlation_summary.get("matched_correlation_count"):
        observed.append(
            f"{correlation_summary['matched_correlation_count']} SDP/RTP endpoint correlation(s) matched"
        )
    if media_session_summary.get("establishment_count", 0) or media_session_summary.get(
        "attempt_bound_observation_count", 0
    ) or media_session_summary.get("branch_bound_observation_count", 0):
        observed.append("IMS media association evidence is available")

    if signaling_summary.get("observed_offer_count", 0) and not signaling_summary.get(
        "observed_answer_count", 0
    ):
        missing.append("SDP_ANSWER_NOT_OBSERVED")
    if rtp_summary.get("rtp_packet_count", 0) == 0:
        missing.append("RTP_NOT_OBSERVED")
    if correlation_summary.get("correlation_count", 0) and not correlation_summary.get(
        "matched_correlation_count", 0
    ):
        missing.append("SDP_RTP_ENDPOINT_MATCH_NOT_ESTABLISHED")
    if media_session_summary.get("transport_observation_count", 0) and not (
        media_session_summary.get("attempt_bound_observation_count", 0)
        or media_session_summary.get("branch_bound_observation_count", 0)
    ):
        missing.append("IMS_MEDIA_ASSOCIATION_NOT_ESTABLISHED")
    if rtp_summary.get("rtcp_component_count", 0) == 0:
        missing.append("RTCP_NOT_OBSERVED")
    if rtp_summary.get("sequence", {}).get("unobserved_sequence_number_slot_count", 0):
        missing.append("UNOBSERVED_SEQUENCE_NUMBER_SLOTS")
    if correlation_summary.get("ambiguous_correlation_count", 0):
        ambiguous.append(
            f"{correlation_summary['ambiguous_correlation_count']} ambiguous SDP/RTP correlation(s)"
        )
    if signaling_summary.get("ambiguous_exchange_count", 0):
        ambiguous.append(
            f"{signaling_summary['ambiguous_exchange_count']} ambiguous SDP exchange(s)"
        )
    if media_session_summary.get("ambiguous_observation_count", 0):
        ambiguous.append(
            f"{media_session_summary['ambiguous_observation_count']} ambiguous IMS media observation(s)"
        )
    if sdp_summary.get("unsupported_message_count", 0):
        unsupported.append(
            f"{sdp_summary['unsupported_message_count']} unsupported SDP message(s)"
        )
    if signaling_summary.get("out_of_scope_observation_count", 0):
        unsupported.append(
            f"{signaling_summary['out_of_scope_observation_count']} out-of-scope SDP observation(s)"
        )
    if errors.get("sdp_extraction"):
        unsupported.append(errors["sdp_extraction"])

    last_evidence = _last_evidence(
        sip_last_frame,
        {**sdp_summary, **sdp_for_last},
        rtp_summary,
        correlation_summary,
        media_session_summary,
    )
    diagnostics = {
        "observed": observed[:MAX_DIAGNOSTIC_ITEMS],
        "missing": missing[:MAX_DIAGNOSTIC_ITEMS],
        "ambiguous": ambiguous[:MAX_DIAGNOSTIC_ITEMS],
        "unsupported": unsupported[:MAX_DIAGNOSTIC_ITEMS],
        "last_supported_evidence": last_evidence,
        "additional_evidence_needed": (
            [
                "Provide a capture path that exposes the missing SDP answer, RTP transport or media association evidence.",
                "Encrypted or IPsec traffic remains inaccessible and is never decrypted by this workflow.",
            ]
            if media_status in ("PARTIAL", "INSUFFICIENT_EVIDENCE")
            else []
        ),
    }

    artifacts = [
        item
        for item in (
            _artifact(sdp_path, "SDP analysis", sdp_summary.get("message_count")),
            _artifact(signaling_path, "IMS media signaling analysis", signaling_summary.get("exchange_count")),
            _artifact(rtp_path, "RTP/RTCP analysis", (rtp_summary.get("rtp_packet_count", 0) + rtp_summary.get("rtcp_component_count", 0))),
            _artifact(stream_path, "RTP source-stream analysis", rtp_summary.get("sequence", {}).get("source_stream_count")),
            _artifact(correlation_path, "SDP/RTP transport correlation", correlation_summary.get("correlation_count")),
            _artifact(media_session_path, "IMS media session analysis", media_session_summary.get("transport_observation_count")),
            _artifact(diagnostics_path, "IMS per-call diagnostics", call_summary.get("attempt_count")),
        )
        if item is not None
    ]

    limitations = [
        "The media pipeline composes accepted Protocol, Correlation and Domain artifacts; it never decodes SIP/RTP or parses SDP itself",
        "Raw SIP/SDP bodies are retained only in memory by the private adapter and are never published",
        "SDP/RTP endpoint correspondence is not IMS session identity, media delivery, two-way audio or call success",
        "RTCP components are observed but never associated with an RTP stream",
        "Unobserved RTP sequence slots are not confirmed network packet loss",
        "Temporal association between RTP packets and the INVITE-to-BYE lifetime is NOT_EVALUATED",
        "IPsec/encrypted media remains inaccessible and is not decrypted",
    ]
    limitations.extend(call_diagnostics.get("limitations") or [])
    not_confirmed = [
        "IMS_CALL_SUCCESS",
        "RTP_DELIVERY",
        "TWO_WAY_AUDIO",
        "CONFIRMED_NETWORK_PACKET_LOSS",
        "MEDIA_QOS",
        "MOS",
        "RTCP_TO_RTP_STREAM_ASSOCIATION",
        "TEMPORAL_MEDIA_ASSOCIATION",
        "IMS_MEDIA_SESSION_IDENTITY",
        "CODEC_NEGOTIATION_COMPATIBILITY",
    ]
    not_confirmed.extend(call_diagnostics.get("not_confirmed") or [])
    return {
        "requested": True,
        "offline": bool(offline),
        "network_required": False,
        "media_status": media_status,
        "media_status_basis": basis,
        "stage_statuses": dict(sorted(stages.items())),
        "stage_errors": dict(sorted(errors.items())),
        "endpoint_key_status": key_status,
        "endpoint_context_reference": next(iter(endpoint_contexts), None) if len(endpoint_contexts) == 1 else None,
        "sdp": sdp_summary,
        "media_signaling": signaling_summary,
        "rtp_rtcp": rtp_summary,
        "transport_correlation": correlation_summary,
        "ims_media_session": media_session_summary,
        "call_evidence_summary": call_summary,
        "call_diagnostics": call_diagnostics,
        "per_call_attempts": (call_diagnostics.get("attempts") or [])[:MAX_CALLS],
        "per_call_branches": (call_diagnostics.get("branches") or [])[:MAX_CALLS],
        "logical_calls": (call_diagnostics.get("logical_calls") or [])[:MAX_CALLS],
        "logical_call_grouping": call_diagnostics.get("logical_call_grouping") or {},
        "logical_call_ownership_counts": call_diagnostics.get(
            "logical_call_ownership_counts"
        ) or {},
        "logical_call_boundary_classification_counts": call_diagnostics.get(
            "logical_call_boundary_classification_counts"
        ) or {},
        "logical_call_diagnostic_completeness_counts": call_diagnostics.get(
            "logical_call_diagnostic_completeness_counts"
        ) or {},
        "logical_call_outcome_counts": call_diagnostics.get(
            "logical_call_outcome_counts"
        ) or {},
        "sip_outcome_classification_counts": call_diagnostics.get(
            "sip_outcome_classification_counts"
        ) or {},
        "accepted_logical_call_count": call_diagnostics.get(
            "accepted_logical_call_count", 0
        ),
        "capture_visibility_limited": call_diagnostics.get(
            "capture_visibility_limited", False
        ),
        "duplicate_observation_investigation": call_diagnostics.get(
            "duplicate_observation_investigation"
        ) or {},
        "temporal_association": call_diagnostics.get("temporal_association") or {},
        "rtcp_association": call_diagnostics.get("rtcp_association") or {},
        "ambiguity_inventory": (call_diagnostics.get("ambiguity_inventory") or [])[:MAX_LIST_ITEMS],
        "missing_evidence_inventory": (call_diagnostics.get("missing_evidence_inventory") or [])[:MAX_LIST_ITEMS],
        "diagnostics": diagnostics,
        "artifacts": artifacts,
        "limitations": limitations,
        "not_confirmed": not_confirmed,
    }