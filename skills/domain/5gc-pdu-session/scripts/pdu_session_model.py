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

ANALYSIS_VERSION = "0.1.0"
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
DEVIATION_OUT_OF_ORDER = "OUT_OF_ORDER_EVIDENCE"
DEVIATION_PARTIAL_CAPTURE = "PARTIAL_CAPTURE"
DEVIATION_PROTECTED_UNAVAILABLE = "PROTECTED_OR_UNAVAILABLE_PAYLOAD"
DEVIATION_UNKNOWN_VALUE = "UNKNOWN_OR_RESERVED_PROTOCOL_VALUE"
DEVIATION_DUPLICATE = "DUPLICATE_OR_RETRANSMITTED_EVIDENCE"

TERMINAL_ACCEPT = "ESTABLISHMENT_ACCEPT_OBSERVED"
TERMINAL_REJECT = "ESTABLISHMENT_REJECT_OBSERVED"
TERMINAL_NONE = "NO_N1_TERMINAL_OBSERVATION"
TERMINAL_PARTIAL = "PARTIAL_CAPTURE"

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
