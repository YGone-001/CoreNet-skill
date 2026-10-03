#!/usr/bin/env python3
"""Shared, standalone engine for 5GC PDU Session procedure analysis.

Consumes already-extracted structured evidence from:
- N1: NAS-5GS (nas-5gs Skill, >=0.2.0)
- N2: NGAP (ngap Skill, >=0.2.0)
- N3: GTP-U (gtpu Skill, >=0.1.0)
- N4: PFCP (pfcp Skill, >=0.1.0)
- N11: SBI-HTTP2 (sbi-http2 Skill, >=0.2.0)
- Correlation: cross-protocol-evidence (optional, >=0.1.0)

Produces:
A. generic procedure-evidence stage records (JSONL, conforming to procedure-evidence.schema.json)
B. bounded 5GC PDU session analysis summary (JSON, conforming to 5gc-pdu-session-analysis.schema.json)

Strictly non-causal: reports observed signaling facts, stage outcomes, procedure-local deviations,
field findings, and explicit association strength. Never decodes raw packets, never maps to source
code or vendors, and never emits verdicts of success, failure, or root cause.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ANALYSIS_VERSION = "0.2.0"
PROCEDURE_NAME = "5gc-pdu-session"

EXIT_MALFORMED_INPUT = 5
EXIT_NO_EVENTS = 6
EXIT_OUTPUT_FAILURE = 7

FORBIDDEN_OUTPUT_PATTERN = re.compile(
    r"(?i)\b(?:root[ _-]?cause|culprit|implementation[ _-]?(?:bug|blame|failure)|vendor[ _-]?bug)\b"
)

DEVIATION_PROTOCOL_REJECT = "PROTOCOL_REJECT_OBSERVED"
DEVIATION_NEGATIVE_OUTCOME = "PROTOCOL_NEGATIVE_OUTCOME_OBSERVED"
DEVIATION_RESOURCE_FAILED = "RESOURCE_FAILED_ITEM_OBSERVED"
DEVIATION_DELIVERY_FAILURE = "DELIVERY_FAILURE_NOTIFICATION_OBSERVED"
DEVIATION_MISSING_COUNTERPART = "MISSING_EXPECTED_COUNTERPART"
DEVIATION_CORRELATION_AMBIGUITY = "CORRELATION_AMBIGUITY"
DEVIATION_CORRELATION_CONFLICT = "CORRELATION_CONFLICT"
DEVIATION_FIELD_CONFLICT = "FIELD_CONFLICT"
DEVIATION_OUT_OF_ORDER = "OUT_OF_ORDER_EVIDENCE"
DEVIATION_PARTIAL_CAPTURE = "PARTIAL_CAPTURE"
DEVIATION_PROTECTED_UNAVAILABLE = "PROTECTED_OR_UNAVAILABLE_PAYLOAD"
DEVIATION_UNKNOWN_VALUE = "UNKNOWN_OR_RESERVED_PROTOCOL_VALUE"
DEVIATION_DUPLICATE = "DUPLICATE_OR_RETRANSMITTED_EVIDENCE"

# Establishment Terminal Observations
TERMINAL_ACCEPT = "ESTABLISHMENT_ACCEPT_OBSERVED"
TERMINAL_REJECT = "ESTABLISHMENT_REJECT_OBSERVED"
TERMINAL_NONE = "NO_N1_TERMINAL_OBSERVATION"
TERMINAL_PARTIAL = "PARTIAL_CAPTURE"

# Modification Terminal Observations
TERMINAL_MOD_COMPLETE = "MODIFICATION_COMPLETE_OBSERVED"
TERMINAL_MOD_REJECT = "MODIFICATION_REJECT_OBSERVED"
TERMINAL_MOD_COMMAND_REJECT = "MODIFICATION_COMMAND_REJECT_OBSERVED"
TERMINAL_MOD_NONE = "NO_N1_TERMINAL_OBSERVATION"
TERMINAL_MOD_PARTIAL = "PARTIAL_CAPTURE"

TRIGGER_UE_REQUESTED = "UE_REQUESTED"
TRIGGER_NETWORK_REQUESTED = "NETWORK_REQUESTED"
TRIGGER_UNKNOWN = "UNKNOWN"

STAGES_ORDER = [
    "session_request",
    "sm_context_control",
    "user_plane_control",
    "access_resource_control",
    "n1_n2_delivery",
    "session_decision",
    "user_plane_observation",
]

STAGE_NAMES = {
    "session_request": "Session Request",
    "sm_context_control": "SM Context Control",
    "user_plane_control": "User Plane Control",
    "access_resource_control": "Access Resource Control",
    "n1_n2_delivery": "N1/N2 Delivery",
    "session_decision": "Session Decision",
    "user_plane_observation": "User Plane Observation",
}

STAGE_EXPECTED_PROTOCOLS = {
    "session_request": ["NAS-5GS"],
    "sm_context_control": ["3GPP-SBI"],
    "user_plane_control": ["PFCP"],
    "access_resource_control": ["NGAP"],
    "n1_n2_delivery": ["3GPP-SBI"],
    "session_decision": ["NAS-5GS"],
    "user_plane_observation": ["GTP-U"],
}

STAGE_EXPECTED_MESSAGES = {
    "session_request": ["PduSessionEstablishmentRequest"],
    "sm_context_control": ["CreateSMContext", "UpdateSMContext"],
    "user_plane_control": ["SessionEstablishmentRequest", "SessionEstablishmentResponse"],
    "access_resource_control": ["PDUSessionResourceSetupRequest", "PDUSessionResourceSetupResponse", "InitialContextSetupRequest", "InitialContextSetupResponse"],
    "n1_n2_delivery": ["N1N2MessageTransfer", "N1N2Transfer Failure Notification"],
    "session_decision": ["PduSessionEstablishmentAccept", "PduSessionEstablishmentReject"],
    "user_plane_observation": ["G-PDU", "EchoRequest", "EchoResponse", "ErrorIndication", "EndMarker"],
}

MOD_STAGES_ORDER = [
    "modification_initiation",
    "sm_context_update",
    "user_plane_control_update",
    "access_resource_update",
    "n1_n2_delivery",
    "modification_completion",
    "post_modification_observation",
]

MOD_STAGE_NAMES = {
    "modification_initiation": "Modification Initiation",
    "sm_context_update": "SM Context Update",
    "user_plane_control_update": "User Plane Control Update",
    "access_resource_update": "Access Resource Update",
    "n1_n2_delivery": "N1/N2 Delivery",
    "modification_completion": "Modification Completion",
    "post_modification_observation": "Post-Modification Observation",
}

MOD_STAGE_EXPECTED_PROTOCOLS = {
    "modification_initiation": ["NAS-5GS"],
    "sm_context_update": ["3GPP-SBI"],
    "user_plane_control_update": ["PFCP"],
    "access_resource_update": ["NGAP"],
    "n1_n2_delivery": ["3GPP-SBI"],
    "modification_completion": ["NAS-5GS"],
    "post_modification_observation": ["GTP-U"],
}

MOD_STAGE_EXPECTED_MESSAGES = {
    "modification_initiation": ["PduSessionModificationRequest", "PduSessionModificationCommand"],
    "sm_context_update": ["UpdateSMContext"],
    "user_plane_control_update": ["SessionModificationRequest", "SessionModificationResponse"],
    "access_resource_update": ["PDUSessionResourceModifyRequest", "PDUSessionResourceModifyResponse"],
    "n1_n2_delivery": ["N1N2MessageTransfer", "N1N2Transfer Failure Notification"],
    "modification_completion": ["PduSessionModificationComplete", "PduSessionModificationReject", "PduSessionModificationCommandReject"],
    "post_modification_observation": ["G-PDU", "EchoRequest", "EchoResponse", "ErrorIndication", "EndMarker"],
}


class InputError(ValueError):
    """Raised when lower-layer evidence or analysis configuration is invalid."""


def _require_common_fields(record: Any, index: int, protocol_name: str) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise InputError(f"{protocol_name} record {index} is not a JSON object")
    for key in ("timestamp", "frame_number", "capture_file"):
        if key not in record:
            raise InputError(f"{protocol_name} record {index} lacks required field: {key}")
    frame = record["frame_number"]
    if not isinstance(frame, int) or isinstance(frame, bool) or frame < 1:
        raise InputError(f"{protocol_name} record {index} frame_number must be a positive integer")
    return record


def load_nas_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.is_file():
        raise InputError(f"file does not exist: {path}")
    with path.open("r", encoding="utf-8") as handle:
        for line_num, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name} at line {line_num}: {exc.msg}") from exc
            record = _require_common_fields(data, len(events), "NAS-5GS")
            events.append(record)
    return events


def load_ngap_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.is_file():
        raise InputError(f"file does not exist: {path}")
    with path.open("r", encoding="utf-8") as handle:
        for line_num, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name} at line {line_num}: {exc.msg}") from exc
            record = _require_common_fields(data, len(events), "NGAP")
            if not isinstance(record.get("message_type"), str):
                raise InputError(f"NGAP record {len(events)} in {path.name} lacks message_type string")
            events.append(record)
    return events


def load_pfcp_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.is_file():
        raise InputError(f"file does not exist: {path}")
    with path.open("r", encoding="utf-8") as handle:
        for line_num, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name} at line {line_num}: {exc.msg}") from exc
            record = _require_common_fields(data, len(events), "PFCP")
            if not isinstance(record.get("header"), dict):
                raise InputError(f"PFCP record {len(events)} in {path.name} lacks header object")
            events.append(record)
    return events


def load_gtpu_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.is_file():
        raise InputError(f"file does not exist: {path}")
    with path.open("r", encoding="utf-8") as handle:
        for line_num, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name} at line {line_num}: {exc.msg}") from exc
            record = _require_common_fields(data, len(events), "GTP-U")
            if not isinstance(record.get("header"), dict) or not isinstance(record.get("outer"), dict):
                raise InputError(f"GTP-U record {len(events)} in {path.name} lacks header or outer object")
            events.append(record)
    return events


def load_sbi_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not path.is_file():
        raise InputError(f"file does not exist: {path}")
    with path.open("r", encoding="utf-8") as handle:
        for line_num, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name} at line {line_num}: {exc.msg}") from exc
            record = _require_common_fields(data, len(events), "SBI-HTTP2")
            events.append(record)
    return events


def load_correlation_events(path: Path) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    if not path.is_file():
        raise InputError(f"file does not exist: {path}")
    with path.open("r", encoding="utf-8") as handle:
        for line_num, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name} at line {line_num}: {exc.msg}") from exc
            if not isinstance(data, dict):
                raise InputError(f"correlation record at line {line_num} is not an object")
            groups.append(data)
    return groups


def _event_sort_key(event: dict[str, Any]) -> tuple[str, int]:
    return (str(event.get("timestamp", "")), int(event.get("frame_number", 0)))


def build_instance_id(capture_file: str, ran_ue_ngap_id: int | None, amf_ue_ngap_id: int | None, pdu_session_id: int) -> str:
    ran_part = f"ran{ran_ue_ngap_id}" if ran_ue_ngap_id is not None else "ran?"
    amf_part = f"amf{amf_ue_ngap_id}" if amf_ue_ngap_id is not None else "amf?"
    clean_capture = Path(capture_file).name
    return f"5gc-pdu-session:{clean_capture}:{ran_part}-{amf_part}:psi{pdu_session_id}"


def _make_generic_stage_record(
    instance_id: str,
    capture_file: str,
    stage_id: str,
    stage_name: str,
    expected_protocols: list[str],
    expected_message_types: list[str],
    expected_evidence: list[str],
    observed_evidence: list[str],
    missing_evidence: list[str],
    evidence_basis: str,
    confidence: str,
    limitations: list[str],
) -> dict[str, Any]:
    return {
        "procedure_name": instance_id,
        "procedure_version": ANALYSIS_VERSION,
        "observation_group": capture_file,
        "stage": {
            "stage_id": stage_id,
            "stage_name": stage_name,
            "expected_protocols": expected_protocols,
            "expected_message_types": expected_message_types,
        },
        "expected_evidence": expected_evidence,
        "observed_evidence": observed_evidence,
        "missing_evidence": missing_evidence,
        "evidence_basis": evidence_basis,
        "confidence": confidence,
        "limitations": limitations,
    }


def evaluate_modification_attempts(
    inst: dict[str, Any],
    est_context: dict[str, Any],
    capture_file: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Evaluate repeated modification attempts for an established PDU Session instance.

    Returns (modification_attempts, generic_stage_records).
    """
    psi = inst["pdu_session_id"]
    inst_id = inst["instance_id"]
    nas_evs = sorted(inst.get("nas_events", []), key=_event_sort_key)
    ngap_evs = sorted(inst.get("ngap_events", []), key=_event_sort_key)
    pfcp_evs = sorted(inst.get("pfcp_events", []), key=_event_sort_key)
    gtpu_evs = sorted(inst.get("gtpu_events", []), key=_event_sort_key)
    sbi_evs = sorted(inst.get("sbi_events", []), key=_event_sort_key)

    nas_mod_msgs = {
        "PduSessionModificationRequest",
        "PduSessionModificationCommand",
        "PduSessionModificationComplete",
        "PduSessionModificationReject",
        "PduSessionModificationCommandReject",
    }
    nas_mod = [
        e for e in nas_evs
        if e.get("message_type") in nas_mod_msgs
        or (e.get("security", {}).get("inner_message_available") is False and "modification" in str(e).lower())
        or e.get("plain_payload_unavailable") is True
    ]

    sbi_update_evs = [
        e for e in sbi_evs
        if (
            e.get("sbi", {}).get("operation") == "UpdateSMContext"
            or "update-sm-context" in str(e.get("http2", {}).get("path", "")).lower()
            or "/modify" in str(e.get("http2", {}).get("path", "")).lower()
            or (e.get("tls_encrypted") and "modify" in str(e.get("capture_file", "")).lower())
        )
    ]

    pfcp_mod = [
        e for e in pfcp_evs
        if "Modification" in str(e.get("header", {}).get("message_type", ""))
        or e.get("header", {}).get("message_type") in (52, 53)
    ]

    ngap_mod = [
        e for e in ngap_evs
        if "ResourceModify" in str(e.get("message_type", ""))
    ]

    if not nas_mod and not sbi_update_evs and not pfcp_mod and not ngap_mod:
        return [], []

    # Find earliest frame of modification signaling
    all_mod_core_frames = [
        e["frame_number"] for e in (nas_mod + sbi_update_evs + pfcp_mod + ngap_mod)
        if e.get("frame_number") is not None
    ]
    min_mod_frame = min(all_mod_core_frames) if all_mod_core_frames else 0

    sbi_mod = list(sbi_update_evs)
    for e in sbi_evs:
        op = e.get("sbi", {}).get("operation")
        if op in ("N1N2MessageTransfer", "N1N2Transfer Failure Notification"):
            # Check if this delivery event occurs during or after modification initiation
            if e.get("frame_number", 0) >= min_mod_frame and e not in sbi_mod:
                sbi_mod.append(e)

    # Cluster events into modification attempts
    attempts_data: list[dict[str, Any]] = []

    if nas_mod:
        for ev in nas_mod:
            mtype = ev.get("message_type")
            sm = ev.get("session_management", {}) if isinstance(ev.get("session_management"), dict) else {}
            pti = sm.get("procedure_transaction_identity") if sm.get("procedure_transaction_identity") is not None else sm.get("pti")
            f_num = ev.get("frame_number", 0)

            if mtype == "PduSessionModificationRequest":
                active_same_pti = next((a for a in attempts_data if not a["is_completed"] and a["pti"] is not None and a["pti"] == pti), None)
                if active_same_pti:
                    has_req = any(e.get("message_type") == "PduSessionModificationRequest" for e in active_same_pti["nas_events"])
                    if has_req:
                        active_same_pti["nas_events"].append(ev)
                        active_same_pti["is_duplicate"] = True
                        active_same_pti["end_frame"] = max(active_same_pti["end_frame"], f_num)
                    else:
                        active_same_pti["nas_events"].append(ev)
                        active_same_pti["end_frame"] = max(active_same_pti["end_frame"], f_num)
                else:
                    active_any = [a for a in attempts_data if not a["is_completed"]]
                    is_ambig = any(a["pti"] == pti for a in active_any)
                    attempts_data.append({
                        "attempt_idx": len(attempts_data) + 1,
                        "trigger_type": TRIGGER_UE_REQUESTED,
                        "pti": pti,
                        "nas_events": [ev],
                        "sbi_events": [],
                        "pfcp_events": [],
                        "ngap_events": [],
                        "gtpu_events": [],
                        "is_ambiguous": is_ambig,
                        "is_duplicate": False,
                        "is_late_capture": False,
                        "is_completed": False,
                        "start_frame": f_num,
                        "end_frame": f_num,
                    })

            elif mtype == "PduSessionModificationCommand":
                active = next((a for a in attempts_data if not a["is_completed"] and (a["pti"] == pti or (a["pti"] is not None and (pti == 0 or pti is None)))), None)
                if not active:
                    active = next((a for a in attempts_data if not a["is_completed"] and not any(e.get("message_type") == "PduSessionModificationCommand" for e in a["nas_events"])), None)
                if active:
                    active["nas_events"].append(ev)
                    active["end_frame"] = max(active["end_frame"], f_num)
                else:
                    attempts_data.append({
                        "attempt_idx": len(attempts_data) + 1,
                        "trigger_type": TRIGGER_NETWORK_REQUESTED,
                        "pti": pti,
                        "nas_events": [ev],
                        "sbi_events": [],
                        "pfcp_events": [],
                        "ngap_events": [],
                        "gtpu_events": [],
                        "is_ambiguous": False,
                        "is_duplicate": False,
                        "is_late_capture": False,
                        "is_completed": False,
                        "start_frame": f_num,
                        "end_frame": f_num,
                    })

            elif mtype in ("PduSessionModificationComplete", "PduSessionModificationReject", "PduSessionModificationCommandReject"):
                active = next((a for a in attempts_data if not a["is_completed"] and (a["pti"] == pti or a["pti"] is None or pti == 0 or pti is None)), None)
                if not active:
                    active = next((a for a in attempts_data if not a["is_completed"]), None)
                if active:
                    active["nas_events"].append(ev)
                    active["is_completed"] = True
                    active["end_frame"] = max(active["end_frame"], f_num)
                else:
                    attempts_data.append({
                        "attempt_idx": len(attempts_data) + 1,
                        "trigger_type": TRIGGER_UNKNOWN,
                        "pti": pti,
                        "nas_events": [ev],
                        "sbi_events": [],
                        "pfcp_events": [],
                        "ngap_events": [],
                        "gtpu_events": [],
                        "is_ambiguous": False,
                        "is_duplicate": False,
                        "is_late_capture": True,
                        "is_completed": True,
                        "start_frame": f_num,
                        "end_frame": f_num,
                    })

            else:
                active = next((a for a in attempts_data if not a["is_completed"]), None)
                if active:
                    active["nas_events"].append(ev)
                    active["end_frame"] = max(active["end_frame"], f_num)
                else:
                    attempts_data.append({
                        "attempt_idx": len(attempts_data) + 1,
                        "trigger_type": TRIGGER_UNKNOWN,
                        "pti": pti,
                        "nas_events": [ev],
                        "sbi_events": [],
                        "pfcp_events": [],
                        "ngap_events": [],
                        "gtpu_events": [],
                        "is_ambiguous": False,
                        "is_duplicate": False,
                        "is_late_capture": False,
                        "is_completed": False,
                        "start_frame": f_num,
                        "end_frame": f_num,
                    })
    else:
        attempts_data.append({
            "attempt_idx": 1,
            "trigger_type": TRIGGER_NETWORK_REQUESTED,
            "pti": None,
            "nas_events": [],
            "sbi_events": [],
            "pfcp_events": [],
            "ngap_events": [],
            "gtpu_events": [],
            "is_ambiguous": False,
            "is_duplicate": False,
            "is_late_capture": False,
            "is_completed": False,
            "start_frame": 1,
            "end_frame": 1000000,
        })

    # Associate other plane events
    if len(attempts_data) == 1:
        attempts_data[0]["sbi_events"].extend(sbi_mod)
        attempts_data[0]["pfcp_events"].extend(pfcp_mod)
        attempts_data[0]["ngap_events"].extend(ngap_mod)
    else:
        for ev in sbi_mod + pfcp_mod + ngap_mod:
            f = ev.get("frame_number", 0)
            ev_pti = None
            if "pti" in ev:
                ev_pti = ev["pti"]
            elif "session_management" in ev and isinstance(ev["session_management"], dict):
                ev_pti = ev["session_management"].get("pti")
            matched_att = None
            if ev_pti is not None:
                matched_att = next((a for a in attempts_data if a["pti"] == ev_pti), None)
            if not matched_att:
                for a in attempts_data:
                    if a["start_frame"] <= f <= a["end_frame"]:
                        matched_att = a
                        break
            if not matched_att:
                preceding = [a for a in attempts_data if a["start_frame"] <= f]
                if preceding:
                    matched_att = max(preceding, key=lambda a: a["start_frame"])
                else:
                    matched_att = attempts_data[0]

            if ev in sbi_mod:
                matched_att["sbi_events"].append(ev)
            elif ev in pfcp_mod:
                matched_att["pfcp_events"].append(ev)
            elif ev in ngap_mod:
                matched_att["ngap_events"].append(ev)

    for att in attempts_data:
        att["gtpu_events"] = [e for e in gtpu_evs if e.get("frame_number", 0) >= att["start_frame"]]

    modification_attempts: list[dict[str, Any]] = []
    mod_generic_stages: list[dict[str, Any]] = []

    has_release = (
        any("release" in str(e.get("message_type", "")).lower() for e in nas_evs)
        or any("deletion" in str(e.get("header", {}).get("message_type", "")).lower() for e in pfcp_evs)
        or any("release" in str(e.get("message_type", "")).lower() for e in ngap_evs)
    )

    for att in attempts_data:
        att_idx = att["attempt_idx"]
        att_id = f"mod-{att_idx}"
        trigger_type = att["trigger_type"]
        pti = att["pti"]
        att_nas = sorted(att["nas_events"], key=_event_sort_key)
        att_sbi = sorted(att["sbi_events"], key=_event_sort_key)
        att_pfcp = sorted(att["pfcp_events"], key=_event_sort_key)
        att_ngap = sorted(att["ngap_events"], key=_event_sort_key)
        att_gtpu = sorted(att["gtpu_events"], key=_event_sort_key)

        deviations: list[dict[str, Any]] = []
        field_findings: list[dict[str, Any]] = []
        stages_summary: list[dict[str, Any]] = []
        att_limitations: list[str] = [
            "Bounded to observed modification signaling in capture window",
            "No source code or network function internal execution state analyzed",
        ]
        if has_release:
            att_limitations.append("PDU session release signaling observed but release procedure analysis is deferred in this version")

        # --- Stage 1: modification_initiation ---
        init_ev = next((e for e in att_nas if e.get("message_type") in ("PduSessionModificationRequest", "PduSessionModificationCommand")), None)
        if trigger_type == TRIGGER_UE_REQUESTED:
            req_ev = next((e for e in att_nas if e.get("message_type") == "PduSessionModificationRequest"), None)
            if req_ev:
                st_init_status = "OBSERVED"
                st_init_obs = [f"PduSessionModificationRequest observed at frame {req_ev['frame_number']} (PTI={pti})"]
                st_init_miss: list[str] = []
                st_init_lim: list[str] = []
            else:
                st_init_status = "MISSING"
                st_init_obs = []
                st_init_miss = ["PduSessionModificationRequest not observed within capture window"]
                st_init_lim = ["Capture window began after modification initiation"]
                deviations.append({
                    "type": DEVIATION_PARTIAL_CAPTURE,
                    "stage_id": "modification_initiation",
                    "description": "Modification request not captured; observation window begins mid-procedure",
                    "evidence_level": "DERIVED",
                    "limitation": "Initiating signaling not available in capture",
                })
        elif trigger_type == TRIGGER_NETWORK_REQUESTED:
            cmd_ev = next((e for e in att_nas if e.get("message_type") == "PduSessionModificationCommand"), None)
            if cmd_ev:
                st_init_status = "OBSERVED"
                st_init_obs = [f"Network-initiated modification via PduSessionModificationCommand observed at frame {cmd_ev['frame_number']}"]
                st_init_miss = []
                st_init_lim = []
            elif att_sbi or att_pfcp or att_ngap:
                st_init_status = "OBSERVED"
                st_init_obs = ["Network-initiated modification control signaling observed"]
                st_init_miss = []
                st_init_lim = []
            else:
                st_init_status = "MISSING"
                st_init_obs = []
                st_init_miss = ["Network-initiated modification signaling not observed"]
                st_init_lim = ["No initiation signaling observed"]
        else:
            if init_ev:
                st_init_status = "OBSERVED"
                st_init_obs = [f"Modification initiation message {init_ev.get('message_type')} observed at frame {init_ev['frame_number']}"]
                st_init_miss = []
                st_init_lim = []
            else:
                st_init_status = "MISSING"
                st_init_obs = []
                st_init_miss = ["Modification initiation not observed"]
                st_init_lim = ["Capture window began after initiation"]
                if att.get("is_late_capture"):
                    deviations.append({
                        "type": DEVIATION_PARTIAL_CAPTURE,
                        "stage_id": "modification_initiation",
                        "description": "Procedure response observed before initiation request; capture begins late",
                        "evidence_level": "DERIVED",
                        "limitation": "Earlier procedure stages exist outside the capture",
                    })

        if att.get("is_duplicate"):
            deviations.append({
                "type": DEVIATION_DUPLICATE,
                "stage_id": "modification_initiation",
                "description": f"Duplicate or retransmitted PduSessionModificationRequest observed (PTI={pti})",
                "evidence_level": "OBSERVED",
                "limitation": "Signaling retransmission observed; likely response delay or packet duplication",
            })

        prot_nas = next((e for e in att_nas if e.get("security", {}).get("inner_message_available") is False or e.get("ciphered") is True or e.get("plain_payload_unavailable") is True), None)
        if prot_nas:
            deviations.append({
                "type": DEVIATION_PROTECTED_UNAVAILABLE,
                "stage_id": "modification_initiation",
                "description": f"NAS message at frame {prot_nas['frame_number']} is ciphered and inner payload is unavailable",
                "evidence_level": "OBSERVED",
                "limitation": "Plaintext NAS payload unavailable without security context deciphering",
            })

        stages_summary.append({
            "stage_id": "modification_initiation",
            "stage_name": MOD_STAGE_NAMES["modification_initiation"],
            "status": st_init_status,
            "expected_evidence": ["NAS-5GS PduSessionModificationRequest", "NAS-5GS PduSessionModificationCommand"],
            "observed_evidence": st_init_obs,
            "missing_evidence": st_init_miss,
            "limitations": st_init_lim,
        })

        # --- Stage 2: sm_context_update ---
        upd_ev = next((e for e in att_sbi if e.get("sbi", {}).get("operation") == "UpdateSMContext" or "update-sm-context" in str(e.get("http2", {}).get("path", "")).lower() or "/modify" in str(e.get("http2", {}).get("path", "")).lower()), None)
        tls_sbi = next((e for e in att_sbi if e.get("tls_encrypted")), None)

        if tls_sbi:
            st_upd_status = "MISSING"
            st_upd_obs = []
            st_upd_miss = ["UpdateSMContext payload encrypted under TLS without key material"]
            st_upd_lim = ["TLS encryption prevents cleartext inspection"]
            deviations.append({
                "type": DEVIATION_PROTECTED_UNAVAILABLE,
                "stage_id": "sm_context_update",
                "description": f"SBI HTTP/2 frame at frame {tls_sbi['frame_number']} is encrypted under TLS without key material",
                "evidence_level": "OBSERVED",
                "limitation": "TLS encryption prevents application layer inspection",
            })
        elif upd_ev:
            status_code = upd_ev.get("http2", {}).get("status")
            prob = upd_ev.get("problem_details")
            if (status_code is not None and status_code >= 400) or prob is not None:
                st_upd_status = "OBSERVED"
                prob_cause = prob.get("cause") if isinstance(prob, dict) else f"HTTP {status_code}"
                st_upd_obs = [f"Nsmf_PDUSession UpdateSMContext returned HTTP {status_code} at frame {upd_ev['frame_number']} with ProblemDetails ({prob_cause})"]
                st_upd_miss = []
                st_upd_lim = ["SM context update rejected by SMF"]
                deviations.append({
                    "type": DEVIATION_NEGATIVE_OUTCOME,
                    "stage_id": "sm_context_update",
                    "description": f"Nsmf_PDUSession UpdateSMContext returned HTTP {status_code} with ProblemDetails cause {prob_cause}",
                    "evidence_level": "OBSERVED",
                    "limitation": "Protocol failure at AMF-SMF interface; internal SMF or PCF decision basis not observable",
                })
            else:
                st_upd_status = "OBSERVED"
                st_upd_obs = [f"Nsmf_PDUSession UpdateSMContext accepted (HTTP {status_code}) at frame {upd_ev['frame_number']}"]
                st_upd_miss = []
                st_upd_lim = []
        else:
            st_upd_status = "MISSING"
            st_upd_obs = []
            st_upd_miss = ["Nsmf_PDUSession UpdateSMContext not observed within capture window"]
            st_upd_lim = ["SBI signaling absent or encrypted under TLS without key material"]

        stages_summary.append({
            "stage_id": "sm_context_update",
            "stage_name": MOD_STAGE_NAMES["sm_context_update"],
            "status": st_upd_status,
            "expected_evidence": ["3GPP-SBI UpdateSMContext"],
            "observed_evidence": st_upd_obs,
            "missing_evidence": st_upd_miss,
            "limitations": st_upd_lim,
        })

        # --- Stage 3: user_plane_control_update ---
        pfcp_resp = next((e for e in att_pfcp if "Response" in str(e.get("header", {}).get("message_type", ""))), None)
        pfcp_reqs = [e for e in att_pfcp if "Request" in str(e.get("header", {}).get("message_type", ""))]
        pfcp_req = pfcp_reqs[0] if pfcp_reqs else None

        if len(pfcp_reqs) > 1:
            seqs = [e.get("header", {}).get("sequence_number") for e in pfcp_reqs]
            if len(seqs) != len(set(seqs)) or len(pfcp_reqs) > 1:
                deviations.append({
                    "type": DEVIATION_DUPLICATE,
                    "stage_id": "user_plane_control_update",
                    "description": f"Duplicate PFCP Session Modification Request observed (seq_no={seqs[0]})",
                    "evidence_level": "OBSERVED",
                    "limitation": "PFCP transaction retransmission observed",
                })

        if pfcp_resp is not None or pfcp_req is not None:
            cause_obj = pfcp_resp.get("cause") if isinstance(pfcp_resp, dict) else None
            cause_code = cause_obj.get("code") if isinstance(cause_obj, dict) else None
            cause_name = cause_obj.get("name") if isinstance(cause_obj, dict) else str(cause_code)

            if cause_code is not None and cause_code != 1:
                st_upc_status = "OBSERVED"
                st_upc_obs = [f"PFCP Session Modification Response at frame {pfcp_resp['frame_number']} reported non-accepted cause {cause_name} (code {cause_code})"]
                st_upc_miss = []
                st_upc_lim = ["PFCP modification rejected by UPF"]
                deviations.append({
                    "type": DEVIATION_NEGATIVE_OUTCOME,
                    "stage_id": "user_plane_control_update",
                    "description": f"PFCP Session Modification Response reported non-accepted cause {cause_name} (code {cause_code})",
                    "evidence_level": "OBSERVED",
                    "limitation": "UPF control-plane rejection; internal UPF decision basis not determined",
                })
            elif pfcp_resp is None and pfcp_req is not None:
                st_upc_status = "OBSERVED"
                st_upc_obs = [f"PFCP Session Modification Request observed at frame {pfcp_req['frame_number']}"]
                st_upc_miss = ["PFCP Session Modification Response not observed within capture window"]
                st_upc_lim = ["Capture window truncated before PFCP response arrived"]
                deviations.append({
                    "type": DEVIATION_MISSING_COUNTERPART,
                    "stage_id": "user_plane_control_update",
                    "description": f"PFCP Session Modification Request at frame {pfcp_req['frame_number']} missing expected Response",
                    "evidence_level": "DERIVED",
                    "limitation": "Capture window ended before PFCP response arrived or response lost in transit",
                })
            else:
                st_upc_status = "OBSERVED"
                st_upc_obs = [f"PFCP Session Modification accepted at frame {pfcp_resp['frame_number']}"]
                st_upc_miss = []
                st_upc_lim = []
        else:
            st_upc_status = "MISSING"
            st_upc_obs = []
            st_upc_miss = ["PFCP Session Modification signaling not observed within capture window"]
            st_upc_lim = ["N4 interface traffic not captured at this vantage point"]

        stages_summary.append({
            "stage_id": "user_plane_control_update",
            "stage_name": MOD_STAGE_NAMES["user_plane_control_update"],
            "status": st_upc_status,
            "expected_evidence": ["PFCP SessionModificationResponse"],
            "observed_evidence": st_upc_obs,
            "missing_evidence": st_upc_miss,
            "limitations": st_upc_lim,
        })

        # --- Stage 4: access_resource_update ---
        ngap_resp = next((e for e in att_ngap if "ResourceModifyResponse" in str(e.get("message_type", "")) or "ResourceModifyConfirm" in str(e.get("message_type", ""))), None)
        ngap_req = next((e for e in att_ngap if "ResourceModifyRequest" in str(e.get("message_type", "")) or "ResourceModifyIndication" in str(e.get("message_type", ""))), None)

        if ngap_resp is not None or ngap_req is not None:
            target_item_failed = False
            target_cause_str = "unspecified"
            target_item_found = False

            if ngap_resp:
                for res in ngap_resp.get("pdu_session_resources", []):
                    if res.get("pdu_session_id") == psi:
                        target_item_found = True
                        st = str(res.get("item_status", "")).upper()
                        if st in ("FAILED", "UNSUCCESSFUL") or "failed" in str(res).lower() or res.get("cause"):
                            target_item_failed = True
                            target_cause_str = res.get("cause", {}).get("name") if isinstance(res.get("cause"), dict) else str(res.get("cause", "unspecified"))

            if target_item_failed:
                st_aru_status = "OBSERVED"
                st_aru_obs = [f"NGAP PDUSessionResourceModifyResponse at frame {ngap_resp['frame_number']} reported failed resource item for PDU Session ID {psi} ({target_cause_str})"]
                st_aru_miss = []
                st_aru_lim = ["RAN-side resource modification failed"]
                deviations.append({
                    "type": DEVIATION_RESOURCE_FAILED,
                    "stage_id": "access_resource_update",
                    "description": f"NGAP PDUSessionResourceModifyResponse reported failed resource item for PDU Session ID {psi} ({target_cause_str})",
                    "evidence_level": "OBSERVED",
                    "limitation": "RAN-side resource modification failed; radio admission or configuration cause reported by gNB",
                })
            elif ngap_resp is None and ngap_req is not None:
                st_aru_status = "OBSERVED"
                st_aru_obs = [f"NGAP PDUSessionResourceModifyRequest observed at frame {ngap_req['frame_number']}"]
                st_aru_miss = ["NGAP PDUSessionResourceModifyResponse not observed within capture window"]
                st_aru_lim = ["Capture window truncated before NGAP response arrived"]
                deviations.append({
                    "type": DEVIATION_MISSING_COUNTERPART,
                    "stage_id": "access_resource_update",
                    "description": f"NGAP PDUSessionResourceModifyRequest at frame {ngap_req['frame_number']} missing expected Response",
                    "evidence_level": "DERIVED",
                    "limitation": "Capture window ended before NGAP response arrived",
                })
            else:
                st_aru_status = "OBSERVED"
                f_num = ngap_resp["frame_number"] if ngap_resp else ngap_req["frame_number"]
                st_aru_obs = [f"NGAP PDUSessionResourceModify confirmed at frame {f_num} for PDU Session ID {psi}"]
                st_aru_miss = []
                st_aru_lim = []
        else:
            st_aru_status = "MISSING"
            st_aru_obs = []
            st_aru_miss = ["NGAP PDU Session Resource Modify signaling not observed within capture window"]
            st_aru_lim = ["N2 interface traffic not captured at this vantage point"]

        stages_summary.append({
            "stage_id": "access_resource_update",
            "stage_name": MOD_STAGE_NAMES["access_resource_update"],
            "status": st_aru_status,
            "expected_evidence": ["NGAP PDUSessionResourceModifyResponse"],
            "observed_evidence": st_aru_obs,
            "missing_evidence": st_aru_miss,
            "limitations": st_aru_lim,
        })

        # --- Stage 5: n1_n2_delivery ---
        fn_ev = next((e for e in att_sbi if e.get("sbi", {}).get("operation") == "N1N2Transfer Failure Notification" or "failure-notify" in str(e.get("http2", {}).get("path", "")).lower()), None)
        tr_ev = next((e for e in att_sbi if e.get("sbi", {}).get("operation") == "N1N2MessageTransfer" or "n1-n2-messages" in str(e.get("http2", {}).get("path", "")).lower()), None)

        if fn_ev:
            st_del_status = "OBSERVED"
            fn_cause = fn_ev.get("cause") or fn_ev.get("sbi", {}).get("cause") or "delivery_failed"
            st_del_obs = [f"Namf_Communication N1N2Transfer Failure Notification observed at frame {fn_ev['frame_number']} ({fn_cause})"]
            st_del_miss = []
            st_del_lim = ["AMF reported N1/N2 delivery failure to UE/RAN"]
            deviations.append({
                "type": DEVIATION_DELIVERY_FAILURE,
                "stage_id": "n1_n2_delivery",
                "description": f"Namf_Communication N1N2Transfer Failure Notification reported delivery failure ({fn_cause})",
                "evidence_level": "OBSERVED",
                "limitation": "AMF reported N1/N2 delivery failure; communication transfer aborted",
            })
        elif tr_ev:
            st_code = tr_ev.get("http2", {}).get("status")
            if st_code == 202:
                st_del_status = "PENDING"
                st_del_obs = [f"Namf_Communication N1N2MessageTransfer accepted asynchronously (HTTP 202) at frame {tr_ev['frame_number']}"]
                st_del_miss = []
                st_del_lim = ["N1/N2 message transfer accepted asynchronously (HTTP 202); delivery not yet confirmed"]
            elif st_code is not None and st_code >= 400:
                st_del_status = "OBSERVED"
                st_del_obs = [f"Namf_Communication N1N2MessageTransfer returned HTTP {st_code} at frame {tr_ev['frame_number']}"]
                st_del_miss = []
                st_del_lim = ["N1/N2 transfer rejected by AMF"]
                deviations.append({
                    "type": DEVIATION_NEGATIVE_OUTCOME,
                    "stage_id": "n1_n2_delivery",
                    "description": f"Namf_Communication N1N2MessageTransfer returned HTTP {st_code}",
                    "evidence_level": "OBSERVED",
                    "limitation": "N1/N2 transfer rejected by AMF",
                })
            else:
                st_del_status = "OBSERVED"
                st_del_obs = [f"Namf_Communication N1N2MessageTransfer accepted (HTTP {st_code}) at frame {tr_ev['frame_number']}"]
                st_del_miss = []
                st_del_lim = []
        else:
            st_del_status = "NOT_APPLICABLE"
            st_del_obs = []
            st_del_miss = []
            st_del_lim = ["N1/N2 transfer service operation not utilized in this modification branch"]

        stages_summary.append({
            "stage_id": "n1_n2_delivery",
            "stage_name": MOD_STAGE_NAMES["n1_n2_delivery"],
            "status": st_del_status,
            "expected_evidence": ["3GPP-SBI N1N2MessageTransfer"],
            "observed_evidence": st_del_obs,
            "missing_evidence": st_del_miss,
            "limitations": st_del_lim,
        })

        # --- Stage 6: modification_completion ---
        comp_ev = next((e for e in att_nas if e.get("message_type") == "PduSessionModificationComplete"), None)
        rej_ev = next((e for e in att_nas if e.get("message_type") == "PduSessionModificationReject"), None)
        cmd_rej_ev = next((e for e in att_nas if e.get("message_type") == "PduSessionModificationCommandReject"), None)

        if comp_ev:
            st_comp_status = "OBSERVED"
            st_comp_obs = [f"PduSessionModificationComplete observed at frame {comp_ev['frame_number']}"]
            st_comp_miss = []
            st_comp_lim = []
            terminal_obs = {
                "observation": TERMINAL_MOD_COMPLETE,
                "protocol_observations": ["PduSessionModificationComplete observed"],
                "message_type": "PduSessionModificationComplete",
                "frame_number": comp_ev["frame_number"],
                "timestamp": comp_ev["timestamp"],
                "evidence_level": "OBSERVED",
            }
        elif rej_ev:
            st_comp_status = "OBSERVED"
            r_cause = rej_ev.get("cause")
            c_name = r_cause.get("name") if isinstance(r_cause, dict) else str(r_cause)
            st_comp_obs = [f"PduSessionModificationReject observed at frame {rej_ev['frame_number']} with cause {c_name}"]
            st_comp_miss = []
            st_comp_lim = ["5GSM procedure rejected by network"]
            deviations.append({
                "type": DEVIATION_PROTOCOL_REJECT,
                "stage_id": "modification_completion",
                "description": f"NAS PduSessionModificationReject observed with cause {c_name}",
                "evidence_level": "OBSERVED",
                "limitation": "5GSM procedure rejected by network; session remains in established state with prior parameters",
            })
            terminal_obs = {
                "observation": TERMINAL_MOD_REJECT,
                "protocol_observations": [f"PduSessionModificationReject observed with cause {c_name}"],
                "message_type": "PduSessionModificationReject",
                "frame_number": rej_ev["frame_number"],
                "timestamp": rej_ev["timestamp"],
                "evidence_level": "OBSERVED",
            }
        elif cmd_rej_ev:
            st_comp_status = "OBSERVED"
            r_cause = cmd_rej_ev.get("cause")
            c_name = r_cause.get("name") if isinstance(r_cause, dict) else str(r_cause)
            st_comp_obs = [f"PduSessionModificationCommandReject observed at frame {cmd_rej_ev['frame_number']} with cause {c_name}"]
            st_comp_miss = []
            st_comp_lim = ["5GSM command rejected by UE"]
            deviations.append({
                "type": DEVIATION_PROTOCOL_REJECT,
                "stage_id": "modification_completion",
                "description": f"NAS PduSessionModificationCommandReject observed with cause {c_name}",
                "evidence_level": "OBSERVED",
                "limitation": "5GSM command rejected by UE; session remains in established state with prior parameters",
            })
            terminal_obs = {
                "observation": TERMINAL_MOD_COMMAND_REJECT,
                "protocol_observations": [f"PduSessionModificationCommandReject observed with cause {c_name}"],
                "message_type": "PduSessionModificationCommandReject",
                "frame_number": cmd_rej_ev["frame_number"],
                "timestamp": cmd_rej_ev["timestamp"],
                "evidence_level": "OBSERVED",
            }
        else:
            st_comp_status = "MISSING"
            st_comp_obs = []
            st_comp_miss = ["Terminal NAS modification response (Complete / Reject / CommandReject) not observed within capture window"]
            st_comp_lim = ["Capture ended before procedure completion or terminal NAS frame dropped"]
            req_ev = next((e for e in att_nas if e.get("message_type") in ("PduSessionModificationRequest", "PduSessionModificationCommand")), None)
            if req_ev:
                deviations.append({
                    "type": DEVIATION_MISSING_COUNTERPART,
                    "stage_id": "modification_completion",
                    "description": f"Modification initiated at frame {req_ev['frame_number']} but no terminal NAS completion or reject message observed within capture window",
                    "evidence_level": "DERIVED",
                    "limitation": "Capture window truncated before modification completion",
                })
            terminal_obs = {
                "observation": TERMINAL_MOD_NONE,
                "protocol_observations": ["No terminal N1 modification response observed within capture window"],
                "message_type": None,
                "frame_number": None,
                "timestamp": None,
                "evidence_level": "DERIVED",
            }

        stages_summary.append({
            "stage_id": "modification_completion",
            "stage_name": MOD_STAGE_NAMES["modification_completion"],
            "status": st_comp_status,
            "expected_evidence": ["NAS-5GS PduSessionModificationComplete", "NAS-5GS PduSessionModificationReject"],
            "observed_evidence": st_comp_obs,
            "missing_evidence": st_comp_miss,
            "limitations": st_comp_lim,
        })

        # --- Stage 7: post_modification_observation ---
        traffic_observed = any(
            e.get("message_type") == "G-PDU" or e.get("header", {}).get("message_type") == 255
            for e in att_gtpu
        )
        end_marker_observed = any(
            "EndMarker" in str(e.get("message_type", "")) or e.get("header", {}).get("message_type") == 254
            for e in att_gtpu
        )
        error_indication_observed = any(
            "ErrorIndication" in str(e.get("message_type", "")) or e.get("header", {}).get("message_type") == 26
            for e in att_gtpu
        )

        post_tunnel = None
        if att_gtpu:
            first_gt = att_gtpu[0]
            post_tunnel = {
                "teid": first_gt.get("header", {}).get("teid"),
                "ip_address": first_gt.get("outer", {}).get("destination_address"),
            }

        post_qfis: list[int] = []
        for e in att_gtpu:
            q = e.get("header", {}).get("qfi") if isinstance(e.get("header"), dict) else e.get("qfi")
            if q is not None and q not in post_qfis:
                post_qfis.append(q)

        if traffic_observed:
            st_pmo_status = "OBSERVED"
            st_pmo_obs = [f"Post-modification GTP-U user-plane packets observed: {len(att_gtpu)} packets"]
            st_pmo_miss = []
            st_pmo_lim = []
        else:
            st_pmo_status = "MISSING"
            st_pmo_obs = ["No matching GTP-U user-plane packets observed in capture window after modification"]
            st_pmo_miss = ["No post-modification GTP-U user-plane traffic observed"]
            st_pmo_lim = ["User plane traffic idle or vantage point does not observe N3 interface post-modification"]

        stages_summary.append({
            "stage_id": "post_modification_observation",
            "stage_name": MOD_STAGE_NAMES["post_modification_observation"],
            "status": st_pmo_status,
            "expected_evidence": ["GTP-U G-PDU"],
            "observed_evidence": st_pmo_obs,
            "missing_evidence": st_pmo_miss,
            "limitations": st_pmo_lim,
        })

        # Generic stage records for this attempt
        for st_rec in stages_summary:
            st_id = st_rec["stage_id"]
            mod_generic_stages.append(_make_generic_stage_record(
                f"{inst_id}:mod{att_idx}",
                capture_file,
                f"mod{att_idx}_{st_id}",
                f"Attempt {att_idx} {MOD_STAGE_NAMES[st_id]}",
                MOD_STAGE_EXPECTED_PROTOCOLS[st_id],
                MOD_STAGE_EXPECTED_MESSAGES[st_id],
                st_rec["expected_evidence"],
                st_rec["observed_evidence"],
                st_rec["missing_evidence"],
                "OBSERVED",
                "HIGH" if st_rec["status"] == "OBSERVED" else "LOW",
                st_rec["limitations"],
            ))

        # --- Field Findings & Conflict Detection ---
        nas_mod_qfi: int | None = None
        for ev in att_nas:
            sm = ev.get("session_management", {})
            if isinstance(sm, dict):
                qdesc = sm.get("qos_flow_descriptions", {})
                if isinstance(qdesc, dict) and qdesc.get("qfi_values"):
                    nas_mod_qfi = qdesc["qfi_values"][0]
                    field_findings.append({
                        "plane": "N1",
                        "field_name": "qfi",
                        "observed_value": nas_mod_qfi,
                        "frame_number": ev["frame_number"],
                        "capture_file": ev["capture_file"],
                        "evidence_level": "OBSERVED",
                        "interpretation": "Modified QoS Flow Identifier on N1",
                        "limitations": [],
                    })
            if isinstance(ev.get("cause"), dict) and ev.get("cause", {}).get("code") is not None:
                field_findings.append({
                    "plane": "N1",
                    "field_name": "cause",
                    "observed_value": ev["cause"],
                    "frame_number": ev["frame_number"],
                    "capture_file": ev["capture_file"],
                    "evidence_level": "OBSERVED",
                    "interpretation": "5GSM modification cause code",
                    "limitations": [],
                })

        ngap_mod_qfi: int | None = None
        for ev in att_ngap:
            for item in ev.get("pdu_session_resources", []):
                if item.get("pdu_session_id") == psi:
                    q = item.get("qos_flow_per_tnl_information", {}).get("qfi") or item.get("qfi")
                    if q is not None:
                        ngap_mod_qfi = q
                        field_findings.append({
                            "plane": "N2",
                            "field_name": "qfi",
                            "observed_value": ngap_mod_qfi,
                            "frame_number": ev["frame_number"],
                            "capture_file": ev["capture_file"],
                            "evidence_level": "OBSERVED",
                            "interpretation": "Modified QoS Flow Identifier on N2",
                            "limitations": [],
                        })
                    tli = item.get("transport_layer_information") or item.get("up_transport_layer_information")
                    if isinstance(tli, dict):
                        new_teid = tli.get("g_tp_teid") or tli.get("teid")
                        old_teid = est_context.get("established_tunnel", {}).get("teid") if isinstance(est_context.get("established_tunnel"), dict) else None
                        if new_teid is not None and old_teid is not None and new_teid != old_teid:
                            field_findings.append({
                                "plane": "N2",
                                "field_name": "f_teid",
                                "observed_value": f"Old: {old_teid} -> New: {new_teid}",
                                "frame_number": ev["frame_number"],
                                "capture_file": ev["capture_file"],
                                "evidence_level": "OBSERVED",
                                "interpretation": "F-TEID tunnel endpoint updated in modification",
                                "limitations": [],
                            })

        pfcp_mod_qfi: int | None = None
        for ev in att_pfcp:
            rules = ev.get("rule_operations")
            if isinstance(rules, dict):
                for op_name in ("create_pdr", "create_far", "create_qer", "create_urr", "update_far", "update_qer", "update_pdr", "remove_pdr", "remove_far", "remove_qer"):
                    if rules.get(op_name):
                        field_findings.append({
                            "plane": "N4",
                            "field_name": f"rule_operation_{op_name}",
                            "observed_value": rules[op_name],
                            "frame_number": ev["frame_number"],
                            "capture_file": ev["capture_file"],
                            "evidence_level": "OBSERVED",
                            "interpretation": f"PFCP rule operation {op_name}",
                            "limitations": [],
                        })
                for qer in rules.get("qers", []):
                    q = qer.get("qfi")
                    if q is not None:
                        pfcp_mod_qfi = q
                        field_findings.append({
                            "plane": "N4",
                            "field_name": "qfi",
                            "observed_value": pfcp_mod_qfi,
                            "frame_number": ev["frame_number"],
                            "capture_file": ev["capture_file"],
                            "evidence_level": "OBSERVED",
                            "interpretation": "Modified QoS Flow Identifier on N4",
                            "limitations": [],
                        })
            if isinstance(ev.get("cause"), dict):
                field_findings.append({
                    "plane": "N4",
                    "field_name": "cause",
                    "observed_value": ev["cause"],
                    "frame_number": ev["frame_number"],
                    "capture_file": ev["capture_file"],
                    "evidence_level": "OBSERVED",
                    "interpretation": "PFCP modification response cause",
                    "limitations": [],
                })

        for ev in att_sbi:
            prob = ev.get("problem_details")
            if isinstance(prob, dict):
                field_findings.append({
                    "plane": "N11",
                    "field_name": "problem_details",
                    "observed_value": prob,
                    "frame_number": ev["frame_number"],
                    "capture_file": ev["capture_file"],
                    "evidence_level": "OBSERVED",
                    "interpretation": "3GPP ProblemDetails payload in modification",
                    "limitations": [],
                })

        # Cross-plane QFI conflict check
        if nas_mod_qfi is not None and ngap_mod_qfi is not None and nas_mod_qfi != ngap_mod_qfi:
            field_findings.append({
                "plane": "N1",
                "field_name": "qfi",
                "observed_value": f"NAS: {nas_mod_qfi} vs NGAP: {ngap_mod_qfi}",
                "frame_number": None,
                "capture_file": capture_file,
                "evidence_level": "DERIVED",
                "interpretation": "FIELD_CONFLICT: NAS authorized QFI differs from NGAP configured QFI in modification",
                "limitations": ["Cross-plane QoS flow identifier mismatch observed"],
            })
            deviations.append({
                "type": DEVIATION_FIELD_CONFLICT,
                "stage_id": "access_resource_update",
                "description": f"Conflicting QFI: NAS authorized QFI {nas_mod_qfi} while NGAP configured QFI {ngap_mod_qfi}",
                "evidence_level": "DERIVED",
                "limitation": "QFI mismatch across N1 and N2 planes in modification",
            })

        if nas_mod_qfi is not None and pfcp_mod_qfi is not None and nas_mod_qfi != pfcp_mod_qfi:
            field_findings.append({
                "plane": "N1",
                "field_name": "qfi",
                "observed_value": f"NAS: {nas_mod_qfi} vs PFCP: {pfcp_mod_qfi}",
                "frame_number": None,
                "capture_file": capture_file,
                "evidence_level": "DERIVED",
                "interpretation": "FIELD_CONFLICT: NAS authorized QFI differs from PFCP provisioned QFI in modification",
                "limitations": ["Cross-plane QoS flow identifier mismatch observed"],
            })
            deviations.append({
                "type": DEVIATION_FIELD_CONFLICT,
                "stage_id": "user_plane_control_update",
                "description": f"Conflicting QFI: NAS authorized QFI {nas_mod_qfi} while PFCP provisioned QFI {pfcp_mod_qfi}",
                "evidence_level": "DERIVED",
                "limitation": "QFI mismatch across N1 and N4 planes in modification",
            })

        # Ambiguity check
        if att.get("is_ambiguous"):
            deviations.append({
                "type": DEVIATION_CORRELATION_AMBIGUITY,
                "stage_id": "modification_initiation",
                "description": "Concurrent modification attempts for same PDU Session without distinct transaction identity",
                "evidence_level": "DERIVED",
                "limitation": "Signaling overlap prevents deterministic correlation",
            })

        # Earliest observed deviation
        earliest_dev: dict[str, Any] | None = None
        if deviations:
            def mod_dev_sort_key(d: dict[str, Any]) -> tuple[int, int]:
                s_id = d.get("stage_id")
                idx = MOD_STAGES_ORDER.index(s_id) if s_id in MOD_STAGES_ORDER else len(MOD_STAGES_ORDER)
                return (idx, 0)
            earliest_dev = sorted(deviations, key=mod_dev_sort_key)[0]

        # Association strength
        if att.get("is_ambiguous"):
            att_assoc_strength = "AMBIGUOUS"
            att_assoc_basis = "ambiguous_overlapping_requests"
        elif att_nas and (att_sbi or att_pfcp or att_ngap):
            att_assoc_strength = "STRONG"
            att_assoc_basis = "established_context_and_pti" if pti is not None else "established_context_and_control_signaling"
        elif att_nas or att_sbi or att_pfcp or att_ngap:
            att_assoc_strength = "SUPPORTED"
            att_assoc_basis = "established_context_and_pti" if pti is not None else "established_context_and_control_signaling"
        else:
            att_assoc_strength = "UNBOUND"
            att_assoc_basis = "no_safely_associated_signaling"

        plane_bindings = {
            "n1": {
                "strength": "STRONG" if att_nas else "UNBOUND",
                "basis": "ue_context_pdu_session_id_pti",
                "event_count": len(att_nas),
                "message_types": [e.get("message_type") for e in att_nas],
            } if att_nas else None,
            "n2": {
                "strength": "STRONG" if att_ngap else "UNBOUND",
                "basis": "ue_context_and_pdu_session_id",
                "event_count": len(att_ngap),
                "message_types": [e.get("message_type") for e in att_ngap],
            } if att_ngap else None,
            "n3": {
                "strength": "STRONG" if traffic_observed else "UNBOUND",
                "basis": "f_teid_matching",
                "event_count": len(att_gtpu),
                "traffic_observed": traffic_observed,
            } if att_gtpu else None,
            "n4": {
                "strength": "SUPPORTED" if att_pfcp else "UNBOUND",
                "basis": "pfcp_session_seid_continuity",
                "event_count": len(att_pfcp),
                "message_types": [e.get("header", {}).get("message_type") for e in att_pfcp],
            } if att_pfcp else None,
            "n11": {
                "strength": "SUPPORTED" if att_sbi else "UNBOUND",
                "basis": "sm_context_ref_continuity",
                "event_count": len(att_sbi),
                "operations": [e.get("sbi", {}).get("operation") for e in att_sbi if e.get("sbi", {}).get("operation")],
            } if att_sbi else None,
        }

        modification_attempts.append({
            "attempt_id": att_id,
            "trigger_type": trigger_type,
            "procedure_transaction_identity": pti,
            "association_basis": att_assoc_basis,
            "association_strength": att_assoc_strength,
            "stages": stages_summary,
            "terminal_observation": terminal_obs,
            "deviations": deviations,
            "earliest_observed_deviation": earliest_dev,
            "field_findings": field_findings,
            "plane_bindings": plane_bindings,
            "pre_modification_context": {
                "pdu_session_id": psi,
                "established_qfi_values": est_context.get("established_qfi_values", []),
                "established_tunnel": est_context.get("established_tunnel"),
                "sm_context_ref": est_context.get("sm_context_ref"),
                "pfcp_seid": est_context.get("pfcp_seid"),
            },
            "post_modification_observations": {
                "traffic_observed": traffic_observed,
                "qfi_values": post_qfis,
                "tunnel": post_tunnel,
                "end_marker_observed": end_marker_observed,
                "error_indication_observed": error_indication_observed,
            },
            "unbound_evidence": [],
            "limitations": att_limitations,
        })

    return modification_attempts, mod_generic_stages


def analyze(
    nas_events: list[dict[str, Any]],
    ngap_events: list[dict[str, Any]],
    pfcp_events: list[dict[str, Any]],
    gtpu_events: list[dict[str, Any]],
    sbi_events: list[dict[str, Any]],
    correlation_groups: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Execute bounded 5GC PDU Session Establishment analysis.

    Returns:
    - analysis_summary dict conforming to 5gc-pdu-session-analysis.schema.json
    - stage_records list of dicts conforming to procedure-evidence.schema.json
    """
    if correlation_groups is None:
        correlation_groups = []

    # 1. Discover and bind NGAP UE contexts
    # context key: (capture_file, sctp_assoc, ran_id) or (capture_file, sctp_assoc, amf_id)
    ngap_contexts: list[dict[str, Any]] = []
    ran_to_context: dict[tuple[str, Any, int], dict[str, Any]] = {}
    amf_to_context: dict[tuple[str, Any, int], dict[str, Any]] = {}

    for event in sorted(ngap_events, key=_event_sort_key):
        capture = event["capture_file"]
        sctp_assoc = event.get("sctp", {}).get("association_id") if isinstance(event.get("sctp"), dict) else None
        ran_id = event.get("ran_ue_ngap_id")
        amf_id = event.get("amf_ue_ngap_id")

        ctx: dict[str, Any] | None = None
        if ran_id is not None and (capture, sctp_assoc, ran_id) in ran_to_context:
            ctx = ran_to_context[(capture, sctp_assoc, ran_id)]
        elif amf_id is not None and (capture, sctp_assoc, amf_id) in amf_to_context:
            ctx = amf_to_context[(capture, sctp_assoc, amf_id)]

        if ctx is None:
            ctx = {
                "capture_file": capture,
                "sctp_association": sctp_assoc,
                "ran_ue_ngap_id": ran_id,
                "amf_ue_ngap_id": amf_id,
                "events": [],
            }
            ngap_contexts.append(ctx)
        else:
            if ctx["ran_ue_ngap_id"] is None and ran_id is not None:
                ctx["ran_ue_ngap_id"] = ran_id
            if ctx["amf_ue_ngap_id"] is None and amf_id is not None:
                ctx["amf_ue_ngap_id"] = amf_id

        if ctx["ran_ue_ngap_id"] is not None:
            ran_to_context[(capture, sctp_assoc, ctx["ran_ue_ngap_id"])] = ctx
        if ctx["amf_ue_ngap_id"] is not None:
            amf_to_context[(capture, sctp_assoc, ctx["amf_ue_ngap_id"])] = ctx
        ctx["events"].append(event)

    # 2. Join NAS events to NGAP UE contexts via frame provenance or correlation groups
    frame_to_context: dict[tuple[str, int], dict[str, Any]] = {}
    for ctx in ngap_contexts:
        for ev in ctx["events"]:
            frame_to_context[(ev["capture_file"], ev["frame_number"])] = ctx

    # Also map via correlation groups
    for group in correlation_groups:
        gevents = group.get("events", [])
        c_frames = {(item.get("capture_file"), item.get("frame_number")) for item in gevents}
        matched_ctx = next((frame_to_context.get(f) for f in c_frames if f in frame_to_context), None)
        if matched_ctx:
            for f in c_frames:
                if f not in frame_to_context and f[0] and f[1]:
                    frame_to_context[f] = matched_ctx

    nas_with_ctx: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    for nas_ev in sorted(nas_events, key=_event_sort_key):
        key = (nas_ev["capture_file"], nas_ev["frame_number"])
        ctx = frame_to_context.get(key)
        if ctx is None and len(ngap_contexts) == 1 and ngap_contexts[0]["capture_file"] == nas_ev["capture_file"]:
            ctx = ngap_contexts[0]
        nas_with_ctx.append((nas_ev, ctx))

    # 3. Identify Candidate Procedure Instances: (capture, ue_context, pdu_session_id)
    # Track candidate instance keys: (capture_file, ran_id, amf_id, sctp_assoc, psi)
    discovered_instances: dict[tuple[str, Any, Any, Any, int], dict[str, Any]] = {}

    def get_or_create_instance(capture: str, ran_id: Any, amf_id: Any, sctp_assoc: Any, psi: int) -> dict[str, Any]:
        inst_key = (capture, ran_id, amf_id, sctp_assoc, psi)
        if inst_key not in discovered_instances:
            discovered_instances[inst_key] = {
                "capture_file": capture,
                "ran_ue_ngap_id": ran_id,
                "amf_ue_ngap_id": amf_id,
                "sctp_association": sctp_assoc,
                "pdu_session_id": psi,
                "instance_id": build_instance_id(capture, ran_id, amf_id, psi),
                "nas_events": [],
                "ngap_events": [],
                "pfcp_events": [],
                "gtpu_events": [],
                "sbi_events": [],
            }
        return discovered_instances[inst_key]

    # Discover instances from NAS events
    for nas_ev, ctx in nas_with_ctx:
        sm = nas_ev.get("session_management")
        psi = sm.get("pdu_session_id") if isinstance(sm, dict) else None
        if psi is not None:
            capture = nas_ev["capture_file"]
            ran_id = ctx.get("ran_ue_ngap_id") if ctx else None
            amf_id = ctx.get("amf_ue_ngap_id") if ctx else None
            sctp_assoc = ctx.get("sctp_association") if ctx else None
            inst = get_or_create_instance(capture, ran_id, amf_id, sctp_assoc, psi)
            inst["nas_events"].append(nas_ev)

    # Discover instances from NGAP resource items
    for ctx in ngap_contexts:
        for ngap_ev in ctx["events"]:
            resources = ngap_ev.get("pdu_session_resources", [])
            for res in resources:
                psi = res.get("pdu_session_id")
                if psi is not None:
                    inst = get_or_create_instance(
                        ctx["capture_file"],
                        ctx["ran_ue_ngap_id"],
                        ctx["amf_ue_ngap_id"],
                        ctx["sctp_association"],
                        psi,
                    )
                    if ngap_ev not in inst["ngap_events"]:
                        inst["ngap_events"].append(ngap_ev)

    # If no instances discovered yet, check if there's any single capture candidate
    # (e.g. partial capture with only PFCP or NGAP without explicit resource list)
    if not discovered_instances and (nas_events or ngap_events or pfcp_events or sbi_events):
        first_capture = next(
            (e["capture_file"] for e in (nas_events + ngap_events + pfcp_events + sbi_events) if "capture_file" in e),
            "capture.pcap",
        )
        # Find any PSI in SBI or PFCP or NAS
        found_psi = 1
        for ev in sbi_events:
            sm = ev.get("session_management")
            if isinstance(sm, dict) and sm.get("pdu_session_id") is not None:
                found_psi = sm["pdu_session_id"]
                break
        ctx = ngap_contexts[0] if ngap_contexts else {}
        inst = get_or_create_instance(
            first_capture,
            ctx.get("ran_ue_ngap_id"),
            ctx.get("amf_ue_ngap_id"),
            ctx.get("sctp_association"),
            found_psi,
        )

    # Attach any NGAP events carrying bound NAS messages to the respective instance
    for inst in discovered_instances.values():
        nas_frames = {(e["capture_file"], e["frame_number"]) for e in inst["nas_events"]}
        for ngap_ev in ngap_events:
            if (ngap_ev["capture_file"], ngap_ev["frame_number"]) in nas_frames:
                if ngap_ev not in inst["ngap_events"]:
                    inst["ngap_events"].append(ngap_ev)

    # Sort instances deterministically
    sorted_instances = sorted(discovered_instances.values(), key=lambda x: str(x["instance_id"]))

    # 4. SBI-HTTP2 Binding and Multi-UE Ambiguity Detection
    unbound_sbi: list[dict[str, Any]] = []
    ambiguous_events: list[dict[str, Any]] = []

    for sbi_ev in sorted(sbi_events, key=_event_sort_key):
        sm = sbi_ev.get("session_management")
        psi = sm.get("pdu_session_id") if isinstance(sm, dict) else None
        if psi is None:
            unbound_sbi.append(sbi_ev)
            continue

        # Find matching instances with the same capture_file and psi
        matching_insts = [
            inst for inst in sorted_instances
            if inst["capture_file"] == sbi_ev["capture_file"] and inst["pdu_session_id"] == psi
        ]

        if len(matching_insts) == 1:
            matching_insts[0]["sbi_events"].append(sbi_ev)
        elif len(matching_insts) > 1:
            # Ambiguity: multiple UEs share PDU Session ID, identities sanitized
            ambiguous_record = dict(sbi_ev)
            ambiguous_record["ambiguity_reason"] = (
                f"CORRELATION_AMBIGUITY: Multiple concurrent UE instances share PDU Session ID {psi}; "
                "redacted subscriber identities prevent deterministic assignment"
            )
            ambiguous_events.append(ambiguous_record)
            unbound_sbi.append(ambiguous_record)
        else:
            unbound_sbi.append(sbi_ev)

    # 5. PFCP Binding
    unbound_pfcp: list[dict[str, Any]] = []

    for pfcp_ev in sorted(pfcp_events, key=_event_sort_key):
        bound = False
        # Extract UE IP from PFCP rule operations
        pfcp_ue_ips: set[str] = set()
        rules = pfcp_ev.get("rule_operations")
        if isinstance(rules, dict):
            for pdr in rules.get("pdrs", []):
                ue_ip = pdr.get("ue_ip")
                if isinstance(ue_ip, dict):
                    if ue_ip.get("ipv4"):
                        pfcp_ue_ips.add(ue_ip["ipv4"])
                    if ue_ip.get("ipv6"):
                        pfcp_ue_ips.add(ue_ip["ipv6"])

        # Method A: match NAS accepted pdu_address
        for inst in sorted_instances:
            for nas_ev in inst["nas_events"]:
                sm = nas_ev.get("session_management")
                if isinstance(sm, dict) and sm.get("pdu_address"):
                    if sm["pdu_address"] in pfcp_ue_ips:
                        inst["pfcp_events"].append(pfcp_ev)
                        bound = True
                        break
            if bound:
                break

        # Method B: correlation groups
        if not bound and correlation_groups:
            pfcp_key = (pfcp_ev["capture_file"], pfcp_ev["frame_number"])
            for inst in sorted_instances:
                inst_frames = {(e["capture_file"], e["frame_number"]) for e in inst["nas_events"] + inst["ngap_events"]}
                for group in correlation_groups:
                    g_frames = {(it.get("capture_file"), it.get("frame_number")) for it in group.get("events", [])}
                    if pfcp_key in g_frames and any(f in g_frames for f in inst_frames):
                        inst["pfcp_events"].append(pfcp_ev)
                        bound = True
                        break
                if bound:
                    break

        # Method C: Unambiguous single procedure instance in capture
        if not bound and len(sorted_instances) == 1:
            inst = sorted_instances[0]
            if inst["capture_file"] == pfcp_ev["capture_file"]:
                inst["pfcp_events"].append(pfcp_ev)
                bound = True

        if not bound:
            unbound_pfcp.append(pfcp_ev)

    # 6. GTP-U Binding via provisioned PFCP F-TEID
    unbound_gtpu: list[dict[str, Any]] = []

    for gtpu_ev in sorted(gtpu_events, key=_event_sort_key):
        teid = gtpu_ev.get("header", {}).get("teid")
        outer = gtpu_ev.get("outer", {})
        dst_ip = outer.get("destination_address")
        src_ip = outer.get("source_address")

        bound = False
        teid_matched_but_ip_differed = False

        for inst in sorted_instances:
            # Check provisioned F-TEIDs from bound PFCP events
            for pfcp_ev in inst["pfcp_events"]:
                rules = pfcp_ev.get("rule_operations")
                if isinstance(rules, dict):
                    # Check PDR f_teid
                    for pdr in rules.get("pdrs", []):
                        f_teid = pdr.get("f_teid")
                        if isinstance(f_teid, dict) and f_teid.get("teid") == teid:
                            f_ip = f_teid.get("ipv4") or f_teid.get("ipv6")
                            if f_ip in (dst_ip, src_ip):
                                inst["gtpu_events"].append(gtpu_ev)
                                bound = True
                                break
                            else:
                                teid_matched_but_ip_differed = True
                    if bound:
                        break
                    # Check FAR outer_header_creation
                    for far in rules.get("fars", []):
                        ohc = far.get("outer_header_creation")
                        if isinstance(ohc, dict) and ohc.get("teid") == teid:
                            ohc_ip = ohc.get("ipv4") or ohc.get("ipv6")
                            if ohc_ip in (dst_ip, src_ip):
                                inst["gtpu_events"].append(gtpu_ev)
                                bound = True
                                break
                            else:
                                teid_matched_but_ip_differed = True
                    if bound:
                        break
            if bound:
                break

        if not bound:
            rec = dict(gtpu_ev)
            if teid_matched_but_ip_differed:
                rec["limitation"] = "TEID reuse on different endpoint: outer IP does not match provisioned F-TEID IP"
            unbound_gtpu.append(rec)

    # 7. Evaluate Each Instance
    instance_analyses: list[dict[str, Any]] = []
    all_generic_stages: list[dict[str, Any]] = []

    for inst in sorted_instances:
        inst_id = inst["instance_id"]
        capture_file = inst["capture_file"]
        psi = inst["pdu_session_id"]
        nas_evs = sorted(inst["nas_events"], key=_event_sort_key)
        ngap_evs = sorted(inst["ngap_events"], key=_event_sort_key)
        pfcp_evs = sorted(inst["pfcp_events"], key=_event_sort_key)
        gtpu_evs = sorted(inst["gtpu_events"], key=_event_sort_key)
        sbi_evs = sorted(inst["sbi_events"], key=_event_sort_key)

        deviations: list[dict[str, Any]] = []
        field_findings: list[dict[str, Any]] = []
        stages_summary: list[dict[str, Any]] = []
        sm_ref: str | None = None
        inst_limitations: list[str] = [
            "Bounded to observed signaling window in capture artifact",
            "No source code or network function internal execution state analyzed",
        ]

        # Check for multi-UE ambiguity affecting this instance
        ambiguous_for_psi = [a for a in ambiguous_events if a.get("session_management", {}).get("pdu_session_id") == psi]
        if ambiguous_for_psi and not sbi_evs:
            deviations.append({
                "type": DEVIATION_CORRELATION_AMBIGUITY,
                "stage_id": "sm_context_control",
                "description": (
                    f"SBI transaction for PDU Session ID {psi} observed across multiple concurrent UEs "
                    "with sanitized subscriber identities; N11 evidence remains unbound to prevent false association"
                ),
                "evidence_level": "DERIVED",
                "limitation": "Redacted subscriber identity in SBI HTTP/2 prevents unique association",
            })

        # --- Stage 1: session_request (N1 NAS-5GS) ---
        req_event = next((e for e in nas_evs if e.get("message_type") == "PduSessionEstablishmentRequest"), None)
        if req_event is not None:
            sr_status = "OBSERVED"
            sr_obs = [f"PduSessionEstablishmentRequest observed at frame {req_event['frame_number']} for PDU Session ID {psi}"]
            sr_miss = []
            sr_lim: list[str] = []
        else:
            sr_status = "MISSING"
            sr_obs = []
            sr_miss = ["PduSessionEstablishmentRequest not observed within capture window"]
            sr_lim = ["Observation window begins after session initiation or request was not captured"]
            deviations.append({
                "type": DEVIATION_PARTIAL_CAPTURE,
                "stage_id": "session_request",
                "description": "The observation window begins after the procedure's initiation evidence; capture starts mid-procedure",
                "evidence_level": "DERIVED",
                "limitation": "Earlier procedure stages may exist outside the capture",
            })

        stages_summary.append({
            "stage_id": "session_request",
            "stage_name": STAGE_NAMES["session_request"],
            "status": sr_status,
            "expected_evidence": ["NAS-5GS PduSessionEstablishmentRequest"],
            "observed_evidence": sr_obs,
            "missing_evidence": sr_miss,
            "limitations": sr_lim,
        })
        all_generic_stages.append(_make_generic_stage_record(
            inst_id, capture_file, "session_request", STAGE_NAMES["session_request"],
            STAGE_EXPECTED_PROTOCOLS["session_request"], STAGE_EXPECTED_MESSAGES["session_request"],
            ["NAS-5GS PduSessionEstablishmentRequest"], sr_obs, sr_miss, "OBSERVED",
            "HIGH" if sr_status == "OBSERVED" else "LOW", sr_lim,
        ))

        # --- Stage 2: sm_context_control (N11 SBI-HTTP2) ---
        create_sm_ev = next(
            (e for e in sbi_evs if (e.get("sbi", {}).get("operation") == "CreateSMContext" or "/sm-contexts" in str(e.get("http2", {}).get("path", "")))),
            None,
        )
        if create_sm_ev is not None:
            status_code = create_sm_ev.get("http2", {}).get("status")
            prob = create_sm_ev.get("problem_details")
            sm_ref = create_sm_ev.get("sbi", {}).get("sm_context_ref")

            if (status_code is not None and status_code >= 400) or prob is not None:
                sm_status = "OBSERVED"
                prob_cause = prob.get("cause") if isinstance(prob, dict) else f"HTTP {status_code}"
                sm_obs = [f"Nsmf_PDUSession CreateSMContext returned HTTP {status_code} at frame {create_sm_ev['frame_number']} with ProblemDetails ({prob_cause})"]
                sm_miss = []
                sm_lim: list[str] = ["SM context creation rejected by SMF; subsequent session setup aborted"]
                deviations.append({
                    "type": DEVIATION_NEGATIVE_OUTCOME,
                    "stage_id": "sm_context_control",
                    "description": f"Nsmf_PDUSession CreateSMContext returned HTTP {status_code} with ProblemDetails cause {prob_cause}",
                    "evidence_level": "OBSERVED",
                    "limitation": "Protocol failure at AMF-SMF interface; internal SMF or PCF decision basis not observable",
                })
            else:
                sm_status = "OBSERVED"
                sm_obs = [f"Nsmf_PDUSession CreateSMContext accepted (HTTP {status_code}) at frame {create_sm_ev['frame_number']}" + (f" with reference {sm_ref}" if sm_ref else "")]
                sm_miss = []
                sm_lim = []
        else:
            sm_status = "MISSING"
            sm_obs = []
            sm_miss = ["Nsmf_PDUSession CreateSMContext not observed within capture window"]
            sm_lim = ["SBI signaling absent or encrypted under TLS without key material"]

        stages_summary.append({
            "stage_id": "sm_context_control",
            "stage_name": STAGE_NAMES["sm_context_control"],
            "status": sm_status,
            "expected_evidence": ["3GPP-SBI CreateSMContext"],
            "observed_evidence": sm_obs,
            "missing_evidence": sm_miss,
            "limitations": sm_lim,
        })
        all_generic_stages.append(_make_generic_stage_record(
            inst_id, capture_file, "sm_context_control", STAGE_NAMES["sm_context_control"],
            STAGE_EXPECTED_PROTOCOLS["sm_context_control"], STAGE_EXPECTED_MESSAGES["sm_context_control"],
            ["3GPP-SBI CreateSMContext"], sm_obs, sm_miss, "OBSERVED",
            "HIGH" if sm_status == "OBSERVED" else "LOW", sm_lim,
        ))

        # --- Stage 3: user_plane_control (N4 PFCP) ---
        pfcp_resp = next(
            (e for e in pfcp_evs if "Response" in str(e.get("header", {}).get("message_type", ""))),
            None,
        )
        pfcp_req = next(
            (e for e in pfcp_evs if "Request" in str(e.get("header", {}).get("message_type", ""))),
            None,
        )
        if pfcp_resp is not None or pfcp_req is not None:
            cause_obj = pfcp_resp.get("cause") if isinstance(pfcp_resp, dict) else None
            cause_code = cause_obj.get("code") if isinstance(cause_obj, dict) else None
            cause_name = cause_obj.get("name") if isinstance(cause_obj, dict) else str(cause_code)

            if cause_code is not None and cause_code != 1:
                upc_status = "OBSERVED"
                upc_obs = [f"PFCP Session Establishment Response at frame {pfcp_resp['frame_number']} reported non-accepted cause {cause_name} (code {cause_code})"]
                upc_miss = []
                upc_lim = ["PFCP Session rejected by UPF; user plane not established"]
                deviations.append({
                    "type": DEVIATION_NEGATIVE_OUTCOME,
                    "stage_id": "user_plane_control",
                    "description": f"PFCP Session Establishment Response reported non-accepted cause {cause_name} (code {cause_code})",
                    "evidence_level": "OBSERVED",
                    "limitation": "UPF control-plane rejection; internal UPF decision basis not determined",
                })
            else:
                upc_status = "OBSERVED"
                f_num = pfcp_resp["frame_number"] if pfcp_resp else pfcp_req["frame_number"]
                upc_obs = [f"PFCP Session Establishment accepted at frame {f_num}"]
                upc_miss = []
                upc_lim = []
        else:
            upc_status = "MISSING"
            upc_obs = []
            upc_miss = ["PFCP Session Establishment signaling not observed within capture window"]
            upc_lim = ["N4 interface traffic not captured at this vantage point"]

        stages_summary.append({
            "stage_id": "user_plane_control",
            "stage_name": STAGE_NAMES["user_plane_control"],
            "status": upc_status,
            "expected_evidence": ["PFCP SessionEstablishmentResponse"],
            "observed_evidence": upc_obs,
            "missing_evidence": upc_miss,
            "limitations": upc_lim,
        })
        all_generic_stages.append(_make_generic_stage_record(
            inst_id, capture_file, "user_plane_control", STAGE_NAMES["user_plane_control"],
            STAGE_EXPECTED_PROTOCOLS["user_plane_control"], STAGE_EXPECTED_MESSAGES["user_plane_control"],
            ["PFCP SessionEstablishmentResponse"], upc_obs, upc_miss, "OBSERVED",
            "HIGH" if upc_status == "OBSERVED" else "LOW", upc_lim,
        ))

        # --- Stage 4: access_resource_control (N2 NGAP) ---
        psi_resource_items: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for ev in ngap_evs:
            for item in ev.get("pdu_session_resources", []):
                if item.get("pdu_session_id") == psi:
                    psi_resource_items.append((item, ev))

        failed_item_ev = next(((it, ev) for it, ev in psi_resource_items if it.get("resource_list_role") == "FAILED"), None)
        success_item_ev = next(((it, ev) for it, ev in psi_resource_items if it.get("resource_list_role") == "SUCCESS"), None)
        any_item_ev = psi_resource_items[-1] if psi_resource_items else None

        if failed_item_ev is not None:
            target_res_item, target_ngap_ev = failed_item_ev
        elif success_item_ev is not None:
            target_res_item, target_ngap_ev = success_item_ev
        elif any_item_ev is not None:
            target_res_item, target_ngap_ev = any_item_ev
        else:
            target_res_item, target_ngap_ev = None, None

        if target_res_item is not None and target_ngap_ev is not None:
            role = target_res_item.get("resource_list_role")
            cause = target_res_item.get("cause")
            cause_str = (
                f"{cause.get('category')}:{cause.get('value')}"
                if isinstance(cause, dict) and cause.get("category")
                else "unspecified"
            )
            if role == "FAILED":
                arc_status = "OBSERVED"
                arc_obs = [f"NGAP {target_ngap_ev['message_type']} at frame {target_ngap_ev['frame_number']} reported PDU Session ID {psi} in failed list with cause {cause_str}"]
                arc_miss = []
                arc_lim = ["Access radio/transport resource setup rejected by gNB"]
                deviations.append({
                    "type": DEVIATION_RESOURCE_FAILED,
                    "stage_id": "access_resource_control",
                    "description": f"NGAP resource setup failed for PDU Session ID {psi} with cause {cause_str}",
                    "evidence_level": "OBSERVED",
                    "limitation": "RAN resource allocation failure; external radio or transport condition not observable",
                })
            else:
                arc_status = "OBSERVED"
                arc_obs = [f"NGAP {target_ngap_ev['message_type']} at frame {target_ngap_ev['frame_number']} reported PDU Session ID {psi} in setup/successful list"]
                arc_miss = []
                arc_lim = []
        elif ngap_evs:
            arc_status = "OBSERVED"
            arc_obs = [f"NGAP signaling observed for UE context across {len(ngap_evs)} events"]
            arc_miss = []
            arc_lim = []
        else:
            arc_status = "MISSING"
            arc_obs = []
            arc_miss = ["NGAP PDU Session Resource Setup signaling not observed within capture window"]
            arc_lim = ["N2 signaling absent from capture"]

        stages_summary.append({
            "stage_id": "access_resource_control",
            "stage_name": STAGE_NAMES["access_resource_control"],
            "status": arc_status,
            "expected_evidence": ["NGAP PDUSessionResourceSetupResponse"],
            "observed_evidence": arc_obs,
            "missing_evidence": arc_miss,
            "limitations": arc_lim,
        })
        all_generic_stages.append(_make_generic_stage_record(
            inst_id, capture_file, "access_resource_control", STAGE_NAMES["access_resource_control"],
            STAGE_EXPECTED_PROTOCOLS["access_resource_control"], STAGE_EXPECTED_MESSAGES["access_resource_control"],
            ["NGAP PDUSessionResourceSetupResponse"], arc_obs, arc_miss, "OBSERVED",
            "HIGH" if arc_status == "OBSERVED" else "LOW", arc_lim,
        ))

        # --- Stage 5: n1_n2_delivery (N11 SBI-HTTP2) ---
        transfer_ev = next(
            (e for e in sbi_evs if "n1-n2-messages" in str(e.get("http2", {}).get("path", "")) or e.get("sbi", {}).get("operation") == "N1N2MessageTransfer"),
            None,
        )
        fail_notif_ev = next(
            (e for e in sbi_evs if e.get("sbi", {}).get("operation") == "N1N2TransferFailureNotification" or "failure-notify" in str(e.get("http2", {}).get("path", "")) or (isinstance(e.get("namf_communication"), dict) and e.get("namf_communication", {}).get("failure_cause"))),
            None,
        )

        if fail_notif_ev is not None:
            f_cause = fail_notif_ev.get("namf_communication", {}).get("failure_cause") if isinstance(fail_notif_ev.get("namf_communication"), dict) else "TRANSFER_FAILED"
            n1n2_status = "OBSERVED"
            n1n2_obs = [f"Namf_Communication N1N2 transfer failure notification observed at frame {fail_notif_ev['frame_number']} with cause {f_cause}"]
            n1n2_miss = []
            n1n2_lim = ["Delivery failure reported by AMF; radio reachability or paging failure indicated"]
            deviations.append({
                "type": DEVIATION_DELIVERY_FAILURE,
                "stage_id": "n1_n2_delivery",
                "description": f"Namf_Communication reported delivery failure notification with cause {f_cause}",
                "evidence_level": "OBSERVED",
                "limitation": "AMF reported failure to reach UE; radio coverage or UE power state not directly verified",
            })
        elif transfer_ev is not None:
            status_code = transfer_ev.get("http2", {}).get("status")
            t_cause = transfer_ev.get("namf_communication", {}).get("transfer_cause") if isinstance(transfer_ev.get("namf_communication"), dict) else None
            if status_code == 202:
                n1n2_status = "PENDING"
                n1n2_obs = [f"Namf_Communication N1N2MessageTransfer returned HTTP 202 Accepted (pending) at frame {transfer_ev['frame_number']}" + (f" with cause {t_cause}" if t_cause else "")]
                n1n2_miss = ["N1/N2 delivery completion signaling not observed; transfer remains pending"]
                n1n2_lim = ["HTTP 202 indicates asynchronous transfer initiated; delivery success cannot be confirmed"]
            else:
                n1n2_status = "OBSERVED"
                n1n2_obs = [f"Namf_Communication N1N2MessageTransfer accepted (HTTP {status_code}) at frame {transfer_ev['frame_number']}"]
                n1n2_miss = []
                n1n2_lim = []
        else:
            if ngap_evs and nas_evs:
                n1n2_status = "NOT_APPLICABLE"
                n1n2_obs = ["N1/N2 signaling directly observed on radio/access interfaces without N11 transfer evidence"]
                n1n2_miss = []
                n1n2_lim = ["SBI N11 communication interface was not monitored in this capture"]
            else:
                n1n2_status = "MISSING"
                n1n2_obs = []
                n1n2_miss = ["Namf_Communication N1N2 message transfer not observed within capture window"]
                n1n2_lim = ["Asynchronous delivery signaling absent from capture"]

        stages_summary.append({
            "stage_id": "n1_n2_delivery",
            "stage_name": STAGE_NAMES["n1_n2_delivery"],
            "status": n1n2_status,
            "expected_evidence": ["3GPP-SBI N1N2MessageTransfer"],
            "observed_evidence": n1n2_obs,
            "missing_evidence": n1n2_miss,
            "limitations": n1n2_lim,
        })
        all_generic_stages.append(_make_generic_stage_record(
            inst_id, capture_file, "n1_n2_delivery", STAGE_NAMES["n1_n2_delivery"],
            STAGE_EXPECTED_PROTOCOLS["n1_n2_delivery"], STAGE_EXPECTED_MESSAGES["n1_n2_delivery"],
            ["3GPP-SBI N1N2MessageTransfer"], n1n2_obs, n1n2_miss, "OBSERVED",
            "HIGH" if n1n2_status in ("OBSERVED", "PENDING") else "LOW", n1n2_lim,
        ))

        # --- Stage 6: session_decision (N1 NAS-5GS) ---
        accept_ev = next((e for e in nas_evs if e.get("message_type") == "PduSessionEstablishmentAccept"), None)
        reject_ev = next((e for e in nas_evs if e.get("message_type") == "PduSessionEstablishmentReject"), None)

        if reject_ev is not None:
            dec_status = "OBSERVED"
            cause = reject_ev.get("cause", {})
            c_code = cause.get("code") if isinstance(cause, dict) else None
            c_name = cause.get("name") if isinstance(cause, dict) else str(c_code)
            dec_obs = [f"PduSessionEstablishmentReject observed at frame {reject_ev['frame_number']} with 5GSM cause {c_name} ({c_code})"]
            dec_miss = []
            dec_lim = ["Terminal rejection delivered to UE over N1"]
            deviations.append({
                "type": DEVIATION_PROTOCOL_REJECT,
                "stage_id": "session_decision",
                "description": f"PDU Session Establishment Reject observed with 5GSM cause {c_name} (code {c_code})",
                "evidence_level": "OBSERVED",
                "limitation": "Terminal rejection signaling on N1; external trigger for rejection not proven",
            })
            terminal_obs = {
                "observation": TERMINAL_REJECT,
                "protocol_observations": [f"PduSessionEstablishmentReject observed with 5GSM cause {c_name} ({c_code})"],
                "message_type": "PduSessionEstablishmentReject",
                "frame_number": reject_ev["frame_number"],
                "timestamp": reject_ev["timestamp"],
                "evidence_level": "OBSERVED",
            }
        elif accept_ev is not None:
            dec_status = "OBSERVED"
            sm = accept_ev.get("session_management", {})
            pdu_addr = sm.get("pdu_address") if isinstance(sm, dict) else None
            dec_obs = [f"PduSessionEstablishmentAccept observed at frame {accept_ev['frame_number']}" + (f" with PDU address {pdu_addr}" if pdu_addr else "")]
            dec_miss = []
            dec_lim = []
            terminal_obs = {
                "observation": TERMINAL_ACCEPT,
                "protocol_observations": ["PduSessionEstablishmentAccept observed"],
                "message_type": "PduSessionEstablishmentAccept",
                "frame_number": accept_ev["frame_number"],
                "timestamp": accept_ev["timestamp"],
                "evidence_level": "OBSERVED",
            }
        else:
            dec_status = "MISSING"
            dec_obs = []
            dec_miss = ["Terminal PDU Session Establishment decision (Accept or Reject) not observed within capture window"]
            dec_lim = ["Capture terminated before terminal decision signaling was recorded"]
            has_partial = any(d["type"] == DEVIATION_PARTIAL_CAPTURE for d in deviations)
            terminal_obs = {
                "observation": TERMINAL_PARTIAL if has_partial else TERMINAL_NONE,
                "protocol_observations": ["No terminal N1 session decision observed within capture window"],
                "message_type": None,
                "frame_number": None,
                "timestamp": None,
                "evidence_level": "DERIVED",
            }

        stages_summary.append({
            "stage_id": "session_decision",
            "stage_name": STAGE_NAMES["session_decision"],
            "status": dec_status,
            "expected_evidence": ["NAS-5GS PduSessionEstablishmentAccept", "NAS-5GS PduSessionEstablishmentReject"],
            "observed_evidence": dec_obs,
            "missing_evidence": dec_miss,
            "limitations": dec_lim,
        })
        all_generic_stages.append(_make_generic_stage_record(
            inst_id, capture_file, "session_decision", STAGE_NAMES["session_decision"],
            STAGE_EXPECTED_PROTOCOLS["session_decision"], STAGE_EXPECTED_MESSAGES["session_decision"],
            ["NAS-5GS PduSessionEstablishmentAccept", "NAS-5GS PduSessionEstablishmentReject"],
            dec_obs, dec_miss, "OBSERVED",
            "HIGH" if dec_status == "OBSERVED" else "LOW", dec_lim,
        ))

        # --- Stage 7: user_plane_observation (N3 GTP-U) ---
        if gtpu_evs:
            upo_status = "OBSERVED"
            total_bytes = sum(e.get("header", {}).get("message_length", 0) for e in gtpu_evs)
            first_gtpu = gtpu_evs[0]
            teid_val = first_gtpu.get("header", {}).get("teid")
            dst_addr = first_gtpu.get("outer", {}).get("destination_address")
            upo_obs = [f"GTP-U G-PDU traffic observed: {len(gtpu_evs)} packets, {total_bytes} bytes for TEID {teid_val} to endpoint {dst_addr}"]
            upo_miss = []
            upo_lim = ["User-plane traffic observed at capture vantage point; end-to-end application delivery not verified"]
        else:
            upo_status = "MISSING"
            upo_obs = []
            upo_miss = ["no matching N3 G-PDU evidence observed within the available capture window"]
            upo_lim = ["No matching N3 user-plane traffic was observed within the capture window; traffic may be idle, delayed, or outside the capture point"]

        stages_summary.append({
            "stage_id": "user_plane_observation",
            "stage_name": STAGE_NAMES["user_plane_observation"],
            "status": upo_status,
            "expected_evidence": ["GTP-U G-PDU"],
            "observed_evidence": upo_obs,
            "missing_evidence": upo_miss,
            "limitations": upo_lim,
        })
        all_generic_stages.append(_make_generic_stage_record(
            inst_id, capture_file, "user_plane_observation", STAGE_NAMES["user_plane_observation"],
            STAGE_EXPECTED_PROTOCOLS["user_plane_observation"], STAGE_EXPECTED_MESSAGES["user_plane_observation"],
            ["GTP-U G-PDU"], upo_obs, upo_miss, "OBSERVED",
            "HIGH" if upo_status == "OBSERVED" else "LOW", upo_lim,
        ))

        # --- Plane Bindings Construction ---
        # N1 binding
        if nas_evs:
            n1_binding: dict[str, Any] | None = {
                "strength": "STRONG",
                "basis": "frame_provenance_ngap_nas_join",
                "event_count": len(nas_evs),
                "message_types": [e.get("message_type") for e in nas_evs],
            }
        else:
            n1_binding = None

        # N2 binding
        if ngap_evs:
            n2_binding: dict[str, Any] | None = {
                "strength": "STRONG",
                "basis": "ngap_ue_context_and_resource_matching",
                "event_count": len(ngap_evs),
                "message_types": [e.get("message_type") for e in ngap_evs],
            }
        else:
            n2_binding = None

        # N3 binding
        if gtpu_evs:
            first_g = gtpu_evs[0]
            n3_binding: dict[str, Any] | None = {
                "strength": "STRONG",
                "basis": "f_teid_endpoint_and_teid_match",
                "teid": first_g.get("header", {}).get("teid"),
                "endpoint": first_g.get("outer", {}).get("destination_address"),
                "packet_count": len(gtpu_evs),
                "byte_count": sum(e.get("header", {}).get("message_length", 0) for e in gtpu_evs),
                "qfi_values": sorted(list({
                    e.get("pdu_session_container", {}).get("qfi")
                    for e in gtpu_evs
                    if isinstance(e.get("pdu_session_container"), dict) and e.get("pdu_session_container", {}).get("qfi") is not None
                })),
            }
        else:
            n3_binding = None

        # N4 binding
        if pfcp_evs:
            first_p = pfcp_evs[0]
            header_seid = first_p.get("header", {}).get("seid")
            cp_fseid = first_p.get("session", {}).get("cp_f_seid")
            up_fseid = first_p.get("session", {}).get("up_f_seid")
            # Extract UE IP from PDR
            p_ue_ip: str | None = None
            f_teid_obj: dict[str, Any] | None = None
            pfcp_qfis: list[int] = []
            rules = first_p.get("rule_operations")
            if isinstance(rules, dict):
                for pdr in rules.get("pdrs", []):
                    if isinstance(pdr.get("ue_ip"), dict):
                        p_ue_ip = pdr["ue_ip"].get("ipv4") or pdr["ue_ip"].get("ipv6")
                    if isinstance(pdr.get("f_teid"), dict):
                        f_teid_obj = pdr["f_teid"]
                    if isinstance(pdr.get("qfi_values"), list):
                        pfcp_qfis.extend(pdr["qfi_values"])
            n4_binding: dict[str, Any] | None = {
                "strength": "SUPPORTED" if accept_ev else "SUPPORTED",
                "basis": "ue_ip_address_exact_match" if accept_ev else "unambiguous_capture_candidate",
                "header_seid": header_seid,
                "cp_fseid": cp_fseid,
                "up_fseid": up_fseid,
                "ue_ip_address": p_ue_ip,
                "f_teid": f_teid_obj,
                "qfi_values": pfcp_qfis,
            }
        else:
            n4_binding = None

        # N11 binding
        if sbi_evs:
            n11_binding: dict[str, Any] | None = {
                "strength": "SUPPORTED",
                "basis": "unambiguous_candidate_psi_and_dnn",
                "operations": [e.get("sbi", {}).get("operation") or e.get("http2", {}).get("path") for e in sbi_evs],
                "status_codes": [e.get("http2", {}).get("status") for e in sbi_evs if e.get("http2", {}).get("status") is not None],
            }
        else:
            n11_binding = None

        # --- Field Findings & Field Conflicts Detection ---
        # N1 fields
        nas_pdu_address: str | None = None
        nas_qfi: int | None = None
        nas_dnn: str | None = None
        for ev in nas_evs:
            sm = ev.get("session_management")
            if isinstance(sm, dict):
                if sm.get("pdu_session_id") is not None:
                    field_findings.append({
                        "plane": "N1",
                        "field_name": "pdu_session_id",
                        "observed_value": sm["pdu_session_id"],
                        "frame_number": ev["frame_number"],
                        "capture_file": ev["capture_file"],
                        "evidence_level": "OBSERVED",
                        "interpretation": "PDU Session ID allocated by UE",
                        "limitations": [],
                    })
                if sm.get("pdu_address") is not None:
                    nas_pdu_address = sm["pdu_address"]
                    field_findings.append({
                        "plane": "N1",
                        "field_name": "pdu_address",
                        "observed_value": sm["pdu_address"],
                        "frame_number": ev["frame_number"],
                        "capture_file": ev["capture_file"],
                        "evidence_level": "OBSERVED",
                        "interpretation": "Accepted UE PDU IP address",
                        "limitations": [],
                    })
                if sm.get("dnn") is not None:
                    nas_dnn = sm["dnn"]
                    field_findings.append({
                        "plane": "N1",
                        "field_name": "dnn",
                        "observed_value": sm["dnn"],
                        "frame_number": ev["frame_number"],
                        "capture_file": ev["capture_file"],
                        "evidence_level": "OBSERVED",
                        "interpretation": "Requested/assigned Data Network Name",
                        "limitations": [],
                    })
                qfi_desc = sm.get("qos_flow_descriptions")
                if isinstance(qfi_desc, dict) and qfi_desc.get("qfi_values"):
                    nas_qfi = qfi_desc["qfi_values"][0]
                    field_findings.append({
                        "plane": "N1",
                        "field_name": "qfi",
                        "observed_value": nas_qfi,
                        "frame_number": ev["frame_number"],
                        "capture_file": ev["capture_file"],
                        "evidence_level": "OBSERVED",
                        "interpretation": "Authorized QoS Flow Identifier on N1",
                        "limitations": [],
                    })
            if isinstance(ev.get("cause"), dict) and ev.get("cause", {}).get("code") is not None:
                field_findings.append({
                    "plane": "N1",
                    "field_name": "cause",
                    "observed_value": ev["cause"],
                    "frame_number": ev["frame_number"],
                    "capture_file": ev["capture_file"],
                    "evidence_level": "OBSERVED",
                    "interpretation": "5GSM cause code",
                    "limitations": [],
                })

        # N2 fields
        ngap_qfi: int | None = None
        for ev in ngap_evs:
            for item in ev.get("pdu_session_resources", []):
                if item.get("pdu_session_id") == psi:
                    if item.get("qfi_values"):
                        ngap_qfi = item["qfi_values"][0]
                        field_findings.append({
                            "plane": "N2",
                            "field_name": "qfi",
                            "observed_value": ngap_qfi,
                            "frame_number": ev["frame_number"],
                            "capture_file": ev["capture_file"],
                            "evidence_level": "OBSERVED",
                            "interpretation": "Configured QoS Flow Identifier on N2",
                            "limitations": [],
                        })
                    if item.get("cause"):
                        field_findings.append({
                            "plane": "N2",
                            "field_name": "cause",
                            "observed_value": item["cause"],
                            "frame_number": ev["frame_number"],
                            "capture_file": ev["capture_file"],
                            "evidence_level": "OBSERVED",
                            "interpretation": "NGAP resource setup cause",
                            "limitations": [],
                        })

        # N4 fields
        pfcp_ue_ip: str | None = None
        pfcp_net_inst: str | None = None
        for ev in pfcp_evs:
            rules = ev.get("rule_operations")
            if isinstance(rules, dict):
                for pdr in rules.get("pdrs", []):
                    ue_ip = pdr.get("ue_ip")
                    if isinstance(ue_ip, dict):
                        pfcp_ue_ip = ue_ip.get("ipv4") or ue_ip.get("ipv6")
                        field_findings.append({
                            "plane": "N4",
                            "field_name": "ue_ip_address",
                            "observed_value": pfcp_ue_ip,
                            "frame_number": ev["frame_number"],
                            "capture_file": ev["capture_file"],
                            "evidence_level": "OBSERVED",
                            "interpretation": "Allocated UE IP address in PFCP PDR",
                            "limitations": [],
                        })
                    if pdr.get("network_instance"):
                        pfcp_net_inst = pdr["network_instance"]
                        field_findings.append({
                            "plane": "N4",
                            "field_name": "network_instance",
                            "observed_value": pfcp_net_inst,
                            "frame_number": ev["frame_number"],
                            "capture_file": ev["capture_file"],
                            "evidence_level": "OBSERVED",
                            "interpretation": "Network instance provisioned in PFCP PDR",
                            "limitations": [],
                        })
                    if pdr.get("f_teid"):
                        field_findings.append({
                            "plane": "N4",
                            "field_name": "f_teid",
                            "observed_value": pdr["f_teid"],
                            "frame_number": ev["frame_number"],
                            "capture_file": ev["capture_file"],
                            "evidence_level": "OBSERVED",
                            "interpretation": "Fully Qualified Tunnel Endpoint Identifier provisioned in PFCP PDR",
                            "limitations": [],
                        })
            if isinstance(ev.get("cause"), dict):
                field_findings.append({
                    "plane": "N4",
                    "field_name": "cause",
                    "observed_value": ev["cause"],
                    "frame_number": ev["frame_number"],
                    "capture_file": ev["capture_file"],
                    "evidence_level": "OBSERVED",
                    "interpretation": "PFCP transaction response cause",
                    "limitations": [],
                })

        # N3 fields
        if gtpu_evs:
            first_g = gtpu_evs[0]
            field_findings.append({
                "plane": "N3",
                "field_name": "teid",
                "observed_value": first_g.get("header", {}).get("teid"),
                "frame_number": first_g["frame_number"],
                "capture_file": first_g["capture_file"],
                "evidence_level": "OBSERVED",
                "interpretation": "Observed GTP-U tunnel endpoint identifier",
                "limitations": [],
            })

        # N11 fields
        for ev in sbi_evs:
            status_code = ev.get("http2", {}).get("status")
            if status_code is not None:
                field_findings.append({
                    "plane": "N11",
                    "field_name": "status",
                    "observed_value": status_code,
                    "frame_number": ev["frame_number"],
                    "capture_file": ev["capture_file"],
                    "evidence_level": "OBSERVED",
                    "interpretation": "HTTP/2 response status code",
                    "limitations": [],
                })
            sm_ref = ev.get("sbi", {}).get("sm_context_ref")
            if sm_ref:
                field_findings.append({
                    "plane": "N11",
                    "field_name": "sm_context_ref",
                    "observed_value": sm_ref,
                    "frame_number": ev["frame_number"],
                    "capture_file": ev["capture_file"],
                    "evidence_level": "OBSERVED",
                    "interpretation": "SM Context resource URI assigned by SMF",
                    "limitations": [],
                })
            prob = ev.get("problem_details")
            if isinstance(prob, dict):
                field_findings.append({
                    "plane": "N11",
                    "field_name": "problem_details",
                    "observed_value": prob,
                    "frame_number": ev["frame_number"],
                    "capture_file": ev["capture_file"],
                    "evidence_level": "OBSERVED",
                    "interpretation": "3GPP ProblemDetails payload",
                    "limitations": [],
                })

        # Conflict Detection:
        # 1. UE IP conflict: NAS pdu_address vs PFCP ue_ip_address
        if nas_pdu_address and pfcp_ue_ip and nas_pdu_address != pfcp_ue_ip:
            field_findings.append({
                "plane": "N1",
                "field_name": "pdu_address",
                "observed_value": f"NAS: {nas_pdu_address} vs PFCP: {pfcp_ue_ip}",
                "frame_number": None,
                "capture_file": capture_file,
                "evidence_level": "DERIVED",
                "interpretation": "FIELD_CONFLICT: NAS accepted PDU address differs from PFCP allocated UE IP address",
                "limitations": ["Cross-plane semantic attribute mismatch observed"],
            })
            deviations.append({
                "type": DEVIATION_CORRELATION_CONFLICT,
                "stage_id": "user_plane_control",
                "description": f"Conflicting UE IP address: NAS accepted {nas_pdu_address} while PFCP allocated {pfcp_ue_ip}",
                "evidence_level": "DERIVED",
                "limitation": "Addresses observed across planes differ; possible multi-session confusion or misallocation",
            })

        # 2. QFI conflict: NAS qfi vs NGAP qfi
        if nas_qfi is not None and ngap_qfi is not None and nas_qfi != ngap_qfi:
            field_findings.append({
                "plane": "N1",
                "field_name": "qfi",
                "observed_value": f"NAS: {nas_qfi} vs NGAP: {ngap_qfi}",
                "frame_number": None,
                "capture_file": capture_file,
                "evidence_level": "DERIVED",
                "interpretation": "FIELD_CONFLICT: NAS authorized QFI differs from NGAP configured QFI",
                "limitations": ["Cross-plane QoS flow identifier mismatch observed"],
            })
            deviations.append({
                "type": DEVIATION_CORRELATION_CONFLICT,
                "stage_id": "access_resource_control",
                "description": f"Conflicting QFI: NAS authorized QFI {nas_qfi} while NGAP configured QFI {ngap_qfi}",
                "evidence_level": "DERIVED",
                "limitation": "QFI mismatch across N1 and N2 planes",
            })

        # 3. DNN conflict: NAS dnn vs PFCP network_instance
        if nas_dnn and pfcp_net_inst and nas_dnn != pfcp_net_inst:
            field_findings.append({
                "plane": "N1",
                "field_name": "dnn",
                "observed_value": f"NAS: {nas_dnn} vs PFCP: {pfcp_net_inst}",
                "frame_number": None,
                "capture_file": capture_file,
                "evidence_level": "DERIVED",
                "interpretation": "FIELD_CONFLICT: NAS requested DNN differs from PFCP provisioned network instance",
                "limitations": ["Cross-plane network identifier mismatch observed"],
            })
            deviations.append({
                "type": DEVIATION_CORRELATION_CONFLICT,
                "stage_id": "user_plane_control",
                "description": f"Conflicting DNN/Network Instance: NAS requested {nas_dnn} while PFCP provisioned {pfcp_net_inst}",
                "evidence_level": "DERIVED",
                "limitation": "Data network identifier mismatch across N1 and N4 planes",
            })

        # --- Earliest Observed Deviation Calculation ---
        earliest_dev: dict[str, Any] | None = None
        if deviations:
            def dev_sort_key(d: dict[str, Any]) -> tuple[int, int]:
                st_id = d.get("stage_id")
                idx = STAGES_ORDER.index(st_id) if st_id in STAGES_ORDER else len(STAGES_ORDER)
                return (idx, 0)
            sorted_devs = sorted(deviations, key=dev_sort_key)
            earliest_dev = sorted_devs[0]

        # Overall instance association strength
        if n1_binding and n2_binding:
            inst_assoc_strength = "STRONG"
        elif n1_binding or n2_binding or n4_binding:
            inst_assoc_strength = "SUPPORTED"
        else:
            inst_assoc_strength = "AMBIGUOUS"

        # Collect established context for modification evaluation
        est_qfis: list[int] = []
        if nas_qfi is not None:
            est_qfis.append(nas_qfi)
        if ngap_qfi is not None and ngap_qfi not in est_qfis:
            est_qfis.append(ngap_qfi)

        est_tunnel: dict[str, Any] | None = None
        if gtpu_evs:
            first_g = gtpu_evs[0]
            est_tunnel = {
                "teid": first_g.get("header", {}).get("teid"),
                "ip_address": first_g.get("outer", {}).get("destination_address"),
            }

        pfcp_seid_val = None
        for p_ev in pfcp_evs:
            hdr = p_ev.get("header", {})
            if isinstance(hdr, dict) and hdr.get("seid") is not None:
                pfcp_seid_val = hdr.get("seid")
                break

        mod_attempts, mod_generic_stages = evaluate_modification_attempts(
            inst=inst,
            est_context={
                "pdu_session_id": psi,
                "established_qfi_values": est_qfis,
                "established_tunnel": est_tunnel,
                "sm_context_ref": sm_ref,
                "pfcp_seid": pfcp_seid_val,
            },
            capture_file=capture_file,
        )
        all_generic_stages.extend(mod_generic_stages)

        has_rel = (
            any("release" in str(e.get("message_type", "")).lower() for e in nas_evs)
            or any("deletion" in str(e.get("header", {}).get("message_type", "")).lower() for e in pfcp_evs)
            or any("release" in str(e.get("message_type", "")).lower() for e in ngap_evs)
        )
        if has_rel and "PDU session release signaling observed but release procedure analysis is deferred in this version" not in inst_limitations:
            inst_limitations.append("PDU session release signaling observed but release procedure analysis is deferred in this version")

        instance_analyses.append({
            "instance_id": inst_id,
            "association_basis": "ngap_ue_context_and_pdu_session_id",
            "association_strength": inst_assoc_strength,
            "ue_context": {
                "ran_ue_ngap_id": inst["ran_ue_ngap_id"],
                "amf_ue_ngap_id": inst["amf_ue_ngap_id"],
                "sctp_association": inst["sctp_association"],
            },
            "pdu_session_id": psi,
            "stages": stages_summary,
            "terminal_observation": terminal_obs,
            "deviations": deviations,
            "earliest_observed_deviation": earliest_dev,
            "field_findings": field_findings,
            "plane_bindings": {
                "n1": n1_binding,
                "n2": n2_binding,
                "n3": n3_binding,
                "n4": n4_binding,
                "n11": n11_binding,
            },
            "unbound_evidence": [],
            "limitations": inst_limitations,
            "modification_attempts": mod_attempts,
        })

    # 8. Unbound Evidence Collection across planes
    bound_nas_set = {id(e) for inst in sorted_instances for e in inst["nas_events"]}
    bound_ngap_set = {id(e) for inst in sorted_instances for e in inst["ngap_events"]}
    bound_pfcp_set = {id(e) for inst in sorted_instances for e in inst["pfcp_events"]}
    bound_gtpu_set = {id(e) for inst in sorted_instances for e in inst["gtpu_events"]}
    bound_sbi_set = {id(e) for inst in sorted_instances for e in inst["sbi_events"]}

    unbound_n1 = [e for e in nas_events if id(e) not in bound_nas_set]
    unbound_n2 = [e for e in ngap_events if id(e) not in bound_ngap_set]
    unbound_n3 = [e for e in gtpu_events if id(e) not in bound_gtpu_set]
    unbound_n4 = [e for e in pfcp_events if id(e) not in bound_pfcp_set]
    unbound_n11 = [e for e in sbi_events if id(e) not in bound_sbi_set]

    summary = {
        "procedure_name": PROCEDURE_NAME,
        "procedure_version": ANALYSIS_VERSION,
        "instances": instance_analyses,
        "unbound_evidence": {
            "unbound_n1": unbound_n1,
            "unbound_n2": unbound_n2,
            "unbound_n3": unbound_n3,
            "unbound_n4": unbound_n4,
            "unbound_n11": unbound_n11,
            "ambiguous_events": ambiguous_events,
        },
        "limitations": [
            "Analysis is strictly bounded to procedure evidence observed in the provided capture window",
            "No protocol packet decoding is performed; lower-layer event attributes are accepted as-is",
            "No implementation-specific source code or network function internal state is inferred",
            "Absence of evidence does not prove network function failure",
        ],
    }

    # Sanitize output before returning
    sanitize_output(summary)
    for stage_rec in all_generic_stages:
        sanitize_output(stage_rec)

    return summary, all_generic_stages


def sanitize_output(document: Any) -> Any:
    """Ensure no forbidden causal or verdict wording is present in the document."""
    text = json.dumps(document, sort_keys=True)
    match = FORBIDDEN_OUTPUT_PATTERN.search(text)
    if match:
        raise InputError(f"analysis output contains forbidden verdict wording: {match.group(0)}")
    return document
