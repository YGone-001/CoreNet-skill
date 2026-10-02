#!/usr/bin/env python3
"""Shared, standalone engine for 5GC registration/mobility procedure analysis.

The engine consumes already-extracted structured evidence — NGAP detailed
events (ngap Skill), NAS-5GS detailed events (nas-5gs Skill), and
optionally cross-protocol-evidence correlation groups — and produces:

A. generic procedure-evidence stage records (JSONL, compatible with the
   procedure-evidence schema), and
B. a bounded registration/mobility analysis summary (JSON).

It never decodes NAS or NGAP, never handles subscriber or session
identity, never maps to an implementation, and never emits success,
failure, or root-cause verdicts. Missing evidence stays missing evidence
under the observation boundary.

Procedure instances (multi-UE safety):
- An instance is one NGAP UE context: (capture_file, SCTP association
  context, RAN-UE-NGAP-ID), with the AMF-UE-NGAP-ID bound when both IDs
  are observed together. Identifier bindings come from the ngap Skill's
  own event fields; this engine does not re-extract them.
- NAS events join an instance through shared packet provenance
  (capture_file + frame_number), preferably via the STRONG groups of the
  correlation layer and otherwise via a minimal direct frame join that
  this engine performs itself (documented as DERIVED).
- Timestamp proximity alone never merges instances, and events that
  cannot be resolved to an instance stay UNBOUND rather than being
  assigned.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

EXIT_MALFORMED_INPUT = 5
EXIT_NO_EVENTS = 6
EXIT_OUTPUT_FAILURE = 7

ANALYSIS_VERSION = "1.0.0"
PROCEDURE_FAMILY = "5gc-registration-mobility"

FORBIDDEN_OUTPUT_PATTERN = re.compile(r"(?i)\b(?:root[ _-]?cause|implementation[ _-]?(?:bug|blame))\b")

DEVIATION_PROTOCOL_REJECT = "PROTOCOL_REJECT_OBSERVED"
DEVIATION_UNSUCCESSFUL = "UNSUCCESSFUL_OUTCOME_OBSERVED"
DEVIATION_MISSING_COUNTERPART = "MISSING_EXPECTED_COUNTERPART"
DEVIATION_UNKNOWN_VALUE = "UNKNOWN_OR_RESERVED_PROTOCOL_VALUE"
DEVIATION_CORRELATION_CONFLICT = "CORRELATION_CONFLICT"
DEVIATION_PROTECTED_UNAVAILABLE = "PROTECTED_INNER_MESSAGE_UNAVAILABLE"
DEVIATION_PARTIAL_CAPTURE = "PARTIAL_CAPTURE"
DEVIATION_OUT_OF_ORDER = "OUT_OF_ORDER_EVIDENCE"
DEVIATION_DUPLICATE = "DUPLICATE_OR_RETRANSMITTED_EVIDENCE"

TERMINAL_COMPLETE = "REGISTRATION_COMPLETE_OBSERVED"
TERMINAL_REJECT = "REGISTRATION_REJECT_OBSERVED"
TERMINAL_NONE = "NO_REGISTRATION_TERMINAL_OBSERVATION_IN_WINDOW"

REJECT_MESSAGES = {"Registration reject", "Authentication reject", "Security mode reject", "Service reject"}
UNSUCCESSFUL_MESSAGES = {"InitialContextSetupFailure", "Authentication failure"}


class InputError(ValueError):
    """Raised when lower-layer evidence cannot be accepted."""


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


def load_ngap_events(path: Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name} at line {line_number}: {exc.msg}") from exc
            record = _require_event_fields(record, len(events), "NGAP")
            if not isinstance(record.get("message_type"), str):
                raise InputError(f"NGAP record {len(events)} lacks a message_type")
            events.append(record)
    return events


def load_nas_events(path: Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name} at line {line_number}: {exc.msg}") from exc
            record = _require_event_fields(record, len(events), "NAS-5GS")
            if record.get("nas_family") not in ("5GMM", None):
                raise InputError(f"NAS-5GS record {len(events)} carries an unsupported family; 5GSM evidence stays with session work")
            events.append(record)
    return events


def load_correlation_groups(path: Path) -> list[dict[str, object]]:
    groups: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name} at line {line_number}: {exc.msg}") from exc
            if not isinstance(record, dict) or not isinstance(record.get("events"), list):
                raise InputError(f"correlation record {len(groups)} lacks an events array")
            groups.append(record)
    return groups


def load_rules(rules_dir: Path) -> dict:
    document = json.loads((rules_dir / "registration-model.json").read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("stages"), list):
        raise InputError("registration-model.json must define a stages list")
    return document


def _association_of(ngap_event: dict[str, object]) -> str:
    sctp = ngap_event.get("sctp")
    if isinstance(sctp, dict) and sctp.get("association_id") is not None:
        return f"sctp-assoc-{sctp['association_id']}"
    parts = []
    for role in ("source", "destination"):
        endpoint = ngap_event.get(role)
        if isinstance(endpoint, dict):
            parts.append(f"{endpoint.get('address')}:{endpoint.get('port')}")
    if parts:
        return "endpoint-pair-" + "<->".join(sorted(parts))
    return "no-association"


def _event_sort_key(event: dict[str, object]) -> tuple:
    return (str(event.get("timestamp")), int(event["frame_number"]), str(event.get("protocol")), int(event.get("input_order", 0)))


def build_instances(
    ngap_events: list[dict[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Group NGAP events into UE-context procedure instances.

    Returns (instances, conflict_findings). Identifier bindings follow the
    first frame where RAN and AMF UE NGAP IDs appear together; later
    contradictions are surfaced as conflicts, never silently resolved.
    """
    instances: dict[tuple, dict[str, object]] = {}
    conflicts: list[dict[str, object]] = []
    bindings: dict[tuple[str, str], dict[int, int]] = {}

    for order, raw_event in enumerate(ngap_events):
        event = dict(raw_event)
        event["input_order"] = order
        capture = str(event["capture_file"])
        association = _association_of(event)
        ran_id = event.get("ran_ue_ngap_id")
        amf_id = event.get("amf_ue_ngap_id")
        key = (capture, association, ran_id if isinstance(ran_id, int) else -1)
        instance = instances.get(key)
        if instance is None:
            instance = {
                "capture_file": capture,
                "association": association,
                "ran_ue_ngap_id": ran_id if isinstance(ran_id, int) else None,
                "amf_ue_ngap_id": None,
                "ngap_events": [],
                "nas_events": [],
            }
            instances[key] = instance
        if isinstance(ran_id, int) and isinstance(amf_id, int):
            known_amf = bindings.get((capture, association), {}).get(ran_id)
            if known_amf is not None and known_amf != amf_id:
                conflicts.append({
                    "capture_file": capture,
                    "association": association,
                    "ran_ue_ngap_id": ran_id,
                    "observed_amf_ue_ngap_id": amf_id,
                    "existing_amf_ue_ngap_id": known_amf,
                    "resolution": "first-binding-retained",
                    "evidence_level": "DERIVED",
                    "frame_number": event["frame_number"],
                })
            else:
                bindings.setdefault((capture, association), {})[ran_id] = amf_id
                if instance["amf_ue_ngap_id"] is None:
                    instance["amf_ue_ngap_id"] = amf_id
        instance["ngap_events"].append(event)
    return list(instances.values()), conflicts


def join_nas_events(
    instances: list[dict[str, object]],
    nas_events: list[dict[str, object]],
    correlation_groups: list[dict[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Attach NAS events to instances through shared frame provenance.

    Preferred: correlation groups (same capture and frame across
    protocols). Fallback when no correlation input is given: a minimal
    direct frame join performed here and labeled DERIVED. Events that
    cannot be resolved stay unbound; timestamps never merge anything.
    """
    frame_to_instance: dict[tuple[str, int], dict[str, object]] = {}
    for instance in instances:
        for event in instance["ngap_events"]:
            frame_to_instance[(str(event["capture_file"]), int(event["frame_number"]))] = instance

    joined_ids: set[int] = set()
    if correlation_groups:
        for group in correlation_groups:
            group_events = group.get("events", [])
            nas_frames = {
                (str(item.get("capture_file")), int(item.get("frame_number", 0)))
                for item in group_events
                if item.get("protocol") == "NAS-5GS"
            }
            for key in nas_frames:
                instance = frame_to_instance.get(key)
                if instance is None:
                    continue
                for event in nas_events:
                    if id(event) in joined_ids:
                        continue
                    if (str(event["capture_file"]), int(event["frame_number"])) == key:
                        instance["nas_events"].append(event)
                        joined_ids.add(id(event))
    else:
        for event in nas_events:
            key = (str(event["capture_file"]), int(event["frame_number"]))
            instance = frame_to_instance.get(key)
            if instance is not None:
                instance["nas_events"].append(event)
                joined_ids.add(id(event))
    unbound = [event for event in nas_events if id(event) not in joined_ids]
    return [event for event in nas_events if id(event) in joined_ids], unbound


def collect_field_findings(
    ngap_events: list[dict[str, object]],
    nas_events: list[dict[str, object]],
    correlation_conflicts: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Extract findings only from fields the lower layers already supplied."""
    findings: list[dict[str, object]] = []

    def finding(event: dict[str, object], protocol: str, field_name: str, observed_value: object, normalized_value: object, interpretation: str) -> None:
        findings.append({
            "protocol": protocol,
            "message_type": event.get("message_type"),
            "field_name": field_name,
            "observed_value": observed_value,
            "normalized_value": normalized_value,
            "frame_number": event["frame_number"],
            "capture_file": event["capture_file"],
            "evidence_level": "OBSERVED",
            "interpretation": interpretation,
            "limitations": [],
        })

    for event in ngap_events:
        cause = event.get("cause")
        if isinstance(cause, dict) and cause.get("category") is not None:
            finding(event, "NGAP", "NGAP cause", cause,
                    f"{cause.get('category')}:{cause.get('value')}" if cause.get("value") is not None else str(cause.get("category")),
                    "NGAP cause carried by the observed message; procedure evidence, never attribution")
        if event.get("pdu_type") == "unsuccessfulOutcome":
            finding(event, "NGAP", "pdu_type", "unsuccessfulOutcome", None,
                    "The NGAP elementary procedure reported its unsuccessful outcome branch")
        status = event.get("support_status")
        if status in ("UNSUPPORTED", "UNKNOWN"):
            finding(event, "NGAP", "support_status", status, None,
                    "Procedure interpretation is limited by this unsupported or unknown lower-layer message")
    for event in nas_events:
        cause = event.get("cause")
        if isinstance(cause, dict) and cause.get("code") is not None:
            finding(event, "NAS-5GS", "5GMM cause", cause,
                    cause.get("name") if cause.get("name") is not None else cause.get("code"),
                    "5GMM cause carried by the observed NAS message; procedure evidence, never attribution")
        security_mode = event.get("security_mode")
        if isinstance(security_mode, dict):
            if security_mode.get("ciphering_algorithm_name") is not None:
                finding(event, "NAS-5GS", "selected NAS ciphering algorithm",
                        security_mode.get("ciphering_algorithm_code"), security_mode.get("ciphering_algorithm_name"),
                        "Selected NAS ciphering algorithm interpreted at protocol level only")
            if security_mode.get("integrity_algorithm_name") is not None:
                finding(event, "NAS-5GS", "selected NAS integrity protection algorithm",
                        security_mode.get("integrity_algorithm_code"), security_mode.get("integrity_algorithm_name"),
                        "Selected NAS integrity protection algorithm interpreted at protocol level only")
        registration = event.get("registration")
        if isinstance(registration, dict) and registration.get("type_name") is not None:
            finding(event, "NAS-5GS", "5GS registration type", registration.get("type_code"), registration.get("type_name"),
                    "Requested registration kind; never an outcome")
        status = event.get("support_status")
        if status in ("UNSUPPORTED", "UNKNOWN"):
            finding(event, "NAS-5GS", "support_status", status, None,
                    "Procedure interpretation is limited by this unsupported or unknown lower-layer message")
        security = event.get("security")
        if isinstance(security, dict) and security.get("inner_message_available") is False:
            finding(event, "NAS-5GS", "inner message availability", False, None,
                    "The protected NAS envelope carried no decodable inner message; contents were never guessed")
    for conflict in correlation_conflicts:
        findings.append({
            "protocol": "NGAP",
            "message_type": None,
            "field_name": "UE-context identifier binding",
            "observed_value": {
                "ran_ue_ngap_id": conflict.get("ran_ue_ngap_id"),
                "observed_amf_ue_ngap_id": conflict.get("observed_amf_ue_ngap_id"),
                "existing_amf_ue_ngap_id": conflict.get("existing_amf_ue_ngap_id"),
            },
            "normalized_value": None,
            "frame_number": conflict.get("frame_number"),
            "capture_file": conflict.get("capture_file"),
            "evidence_level": "DERIVED",
            "interpretation": "Conflicting UE-context identifier binding reported by correlation; procedure confidence is reduced",
            "limitations": ["The conflicting observation is preserved verbatim; this engine does not adjudicate it"],
        })
    return findings


def _stage_branches(stage: dict[str, object]) -> list[dict[str, object]]:
    branches = [stage.get("trigger") or {}]
    outcomes = stage.get("expected_outcomes") or {}
    if outcomes and not outcomes.get("none_required"):
        branches.append(outcomes)
    return branches


def _stage_record(
    instance_id: str,
    capture_file: str,
    stage: dict[str, object],
    observed_statements: list[str],
    missing_statements: list[str],
    basis: str,
    confidence: str,
    limitations: list[str],
) -> dict[str, object]:
    branches = _stage_branches(stage)
    expected_protocols = sorted({str(item.get("protocol")) for branch in branches for item in (branch.get("any_of") or []) if item})
    expected_messages = sorted({str(item.get("message_type")) for branch in branches for item in (branch.get("any_of") or []) if item})
    expected_evidence = [
        f"{item.get('protocol')} {item.get('message_type')}"
        for item in ((stage.get("expected_outcomes") or {}).get("any_of") or [])
        if item
    ]
    return {
        "procedure_name": instance_id,
        "procedure_version": ANALYSIS_VERSION,
        "observation_group": capture_file,
        "stage": {
            "stage_id": stage["stage_id"],
            "stage_name": stage["stage_name"],
            "expected_protocols": expected_protocols,
            "expected_message_types": expected_messages,
        },
        "expected_evidence": expected_evidence,
        "observed_evidence": observed_statements,
        "missing_evidence": missing_statements,
        "evidence_basis": basis,
        "confidence": confidence,
        "limitations": limitations,
    }


def _message_key(event: dict[str, object]) -> tuple[str, str]:
    return (str(event.get("protocol")), str(event.get("message_type")))


def evaluate_instance(
    instance: dict[str, object],
    instance_id: str,
    rules: dict,
    instance_conflicts: list[dict[str, object]],
) -> dict[str, object]:
    """Evaluate one procedure instance against the conditional model."""
    events = [
        [(dict(event, protocol="NGAP")) for event in instance["ngap_events"]],
        [(dict(event, protocol="NAS-5GS")) for event in instance["nas_events"]],
    ]
    merged = [event for group in events for event in group]
    deviations: list[dict[str, object]] = []
    stage_state: dict[str, dict[str, object]] = {}

    source_ordered_events = (instance["ngap_events"], instance["nas_events"])
    input_is_out_of_order = any(
        [str(event.get("timestamp")) for event in source]
        != sorted(str(event.get("timestamp")) for event in source)
        for source in source_ordered_events
    )
    merged.sort(key=_event_sort_key)
    if input_is_out_of_order:
        deviations.append({
            "type": DEVIATION_OUT_OF_ORDER,
            "stage_id": None,
            "description": "Input evidence was not chronological; ordering was normalized by timestamp and frame",
            "evidence_level": "DERIVED",
            "limitation": "Original provenance preserved",
        })

    seen_signatures: set[tuple] = set()
    for event in merged:
        signature = (
            str(event["capture_file"]), int(event["frame_number"]), str(event.get("protocol")),
            str(event.get("message_type")),
        )
        if signature in seen_signatures:
            deviations.append({
                "type": DEVIATION_DUPLICATE,
                "stage_id": None,
                "description": f"Repeated {event.get('protocol')} {event.get('message_type')} observation at frame {event['frame_number']}; preserved as duplicate or retransmission evidence",
                "evidence_level": "DERIVED",
                "limitation": "Retransmission versus a repeated procedure is not distinguished without further context",
            })
        seen_signatures.add(signature)

    initiation_stage = next((stage for stage in rules["stages"] if not stage.get("conditional")), None)
    if merged and initiation_stage is not None:
        first_key = _message_key(merged[0])
        trigger_keys = {
            (item.get("protocol"), item.get("message_type"))
            for item in (initiation_stage.get("trigger", {}).get("any_of") or [])
        }
        if first_key not in trigger_keys:
            deviations.append({
                "type": DEVIATION_PARTIAL_CAPTURE,
                "stage_id": initiation_stage["stage_id"],
                "description": "The observation window begins after the procedure's initiation evidence; the capture starts mid-procedure",
                "evidence_level": "DERIVED",
                "limitation": "Earlier procedure stages may exist outside the capture",
            })

    for conflict in instance_conflicts:
        deviations.append({
            "type": DEVIATION_CORRELATION_CONFLICT,
            "stage_id": None,
            "description": f"Conflicting UE-context identifier binding observed at frame {conflict.get('frame_number')}; the first binding is retained",
            "evidence_level": "DERIVED",
            "limitation": "Conflicting source evidence preserved",
        })

    for event in merged:
        key = _message_key(event)
        for stage in rules["stages"]:
            trigger_keys = {
                (item.get("protocol"), item.get("message_type"))
                for item in (stage.get("trigger", {}).get("any_of") or [])
            }
            if key in trigger_keys:
                state = stage_state.setdefault(stage["stage_id"], {"trigger": event, "outcomes": []})
                if state["trigger"] is None:
                    state["trigger"] = event
            outcomes = stage.get("expected_outcomes") or {}
            outcome_keys = {
                (item.get("protocol"), item.get("message_type"))
                for item in (outcomes.get("any_of") or [])
            }
            if key in outcome_keys:
                state = stage_state.setdefault(stage["stage_id"], {"trigger": None, "outcomes": []})
                state["outcomes"].append(event)

    stage_records: list[dict[str, object]] = []
    for stage in rules["stages"]:
        state = stage_state.get(stage["stage_id"])
        if state is None:
            continue
        outcomes_branch = stage.get("expected_outcomes") or {}
        outcome_keys = [(item.get("protocol"), item.get("message_type")) for item in (outcomes_branch.get("any_of") or [])]
        observed_statements: list[str] = []
        missing_statements: list[str] = []
        limitations: list[str] = []
        if state["trigger"] is not None:
            trigger = state["trigger"]
            observed_statements.append(
                f"{trigger.get('protocol')} {trigger.get('message_type')} observed at frame {trigger['frame_number']} ({trigger.get('timestamp')})"
            )
        for outcome in state["outcomes"]:
            observed_statements.append(
                f"{outcome.get('protocol')} {outcome.get('message_type')} observed at frame {outcome['frame_number']} ({outcome.get('timestamp')})"
            )
        basis = "OBSERVED"
        confidence = "MEDIUM"
        if state["trigger"] is None:
            # An outcome appeared without its trigger inside the window.
            limitations.append("The stage trigger was not observed; the capture may begin mid-procedure")
        if outcome_keys and not state["outcomes"]:
            for protocol_name, message in outcome_keys:
                missing_statements.append(f"{protocol_name} {message} evidence was not observed within the available observation window")
            deviations.append({
                "type": DEVIATION_MISSING_COUNTERPART,
                "stage_id": stage["stage_id"],
                "description": f"The {stage['stage_name']} branch was entered (trigger at frame {state['trigger']['frame_number'] if state['trigger'] else 'n/a'}) but none of its expected outcomes was observed",
                "evidence_level": "DERIVED",
                "limitation": "Capture termination may explain the missing evidence",
            })
            limitations.append("Capture termination may explain the missing evidence if the counterpart falls outside the observation window")
            basis = "DERIVED"
            confidence = "LOW"
        elif outcome_keys:
            confidence = "HIGH"
        stage_records.append(_stage_record(
            instance_id, str(instance["capture_file"]), stage,
            observed_statements, missing_statements, basis, confidence, limitations,
        ))

    ngap_only = [event for event in merged if event.get("protocol") == "NGAP"]
    nas_only = [event for event in merged if event.get("protocol") == "NAS-5GS"]
    field_findings = collect_field_findings(ngap_only, nas_only, instance_conflicts)

    for event in merged:
        message = str(event.get("message_type"))
        protocol = str(event.get("protocol"))
        if message in REJECT_MESSAGES:
            deviations.append({
                "type": DEVIATION_PROTOCOL_REJECT,
                "stage_id": None,
                "description": f"{protocol} {message} observed at frame {event['frame_number']}",
                "evidence_level": "OBSERVED",
                "limitation": "A protocol-defined reject is procedure evidence; it never attributes blame to any network element or implementation",
            })
        elif message in UNSUCCESSFUL_MESSAGES:
            deviations.append({
                "type": DEVIATION_UNSUCCESSFUL,
                "stage_id": None,
                "description": f"{protocol} {message} observed at frame {event['frame_number']}",
                "evidence_level": "OBSERVED",
                "limitation": "An unsuccessful protocol outcome is procedure evidence; it never attributes blame to any network element or implementation",
            })
        if event.get("support_status") in ("UNSUPPORTED", "UNKNOWN"):
            deviations.append({
                "type": DEVIATION_UNKNOWN_VALUE,
                "stage_id": None,
                "description": f"{protocol} {message} at frame {event['frame_number']} was reported {event.get('support_status')} by the lower layer; procedure interpretation is limited",
                "evidence_level": "OBSERVED",
                "limitation": "No semantics are invented for the unsupported or unknown message",
            })
        if protocol == "NAS-5GS":
            security = event.get("security")
            if isinstance(security, dict) and security.get("inner_message_available") is False:
                deviations.append({
                    "type": DEVIATION_PROTECTED_UNAVAILABLE,
                    "stage_id": None,
                    "description": f"A protected NAS envelope at frame {event['frame_number']} carried no decodable inner message",
                    "evidence_level": "OBSERVED",
                    "limitation": "Inner contents were never guessed",
                })

    terminal_events = [
        event for event in merged
        if str(event.get("message_type")) in ("Registration complete", "Registration reject")
    ]
    if terminal_events:
        terminal_events.sort(key=_event_sort_key)
        last = terminal_events[-1]
        terminal = {
            "observation": TERMINAL_COMPLETE if str(last.get("message_type")) == "Registration complete" else TERMINAL_REJECT,
            "message_type": last.get("message_type"),
            "frame_number": last["frame_number"],
            "timestamp": last.get("timestamp"),
            "evidence_level": "OBSERVED",
        }
    else:
        terminal = {
            "observation": TERMINAL_NONE,
            "message_type": None,
            "frame_number": None,
            "timestamp": None,
            "evidence_level": "DERIVED",
        }
        registration_messages = {"Registration request", "Registration accept", "Registration reject", "Registration complete"}
        if any(str(event.get("message_type")) in registration_messages or str(event.get("message_type")) == "InitialUEMessage" for event in merged):
            deviations.append({
                "type": DEVIATION_MISSING_COUNTERPART,
                "stage_id": "registration-decision",
                "description": "No Registration accept or Registration reject was observed within the available observation window",
                "evidence_level": "DERIVED",
                "limitation": "Capture termination may explain the missing evidence",
            })

    deviation_types = {deviation["type"] for deviation in deviations}
    if DEVIATION_CORRELATION_CONFLICT in deviation_types:
        confidence = "LOW"
    elif terminal["observation"] == TERMINAL_COMPLETE and not (deviation_types & {DEVIATION_MISSING_COUNTERPART, DEVIATION_PARTIAL_CAPTURE, DEVIATION_PROTECTED_UNAVAILABLE}):
        confidence = "HIGH"
    elif terminal["observation"] in (TERMINAL_COMPLETE, TERMINAL_REJECT):
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    timestamps = [str(event["timestamp"]) for event in merged if event.get("timestamp") is not None]
    frames_all = [int(event["frame_number"]) for event in merged]
    return {
        "instance": instance,
        "instance_id": instance_id,
        "events": [
            {
                "protocol": event.get("protocol"),
                "timestamp": event.get("timestamp"),
                "frame_number": event["frame_number"],
                "message_type": event.get("message_type"),
                "cause": event.get("cause"),
                "support_status": event.get("support_status"),
            }
            for event in merged
        ],
        "stage_records": stage_records,
        "deviations": deviations,
        "field_findings": field_findings,
        "terminal": terminal,
        "confidence": confidence,
        "observation_window": {
            "first_timestamp": min(timestamps) if timestamps else None,
            "last_timestamp": max(timestamps) if timestamps else None,
            "first_frame": min(frames_all) if frames_all else None,
            "last_frame": max(frames_all) if frames_all else None,
        },
    }


def build_instance_id(instance: dict[str, object]) -> str:
    ran_part = f"r{instance['ran_ue_ngap_id']}" if instance["ran_ue_ngap_id"] is not None else "r?"
    return f"5gc-reg:{instance['capture_file']}:{instance['association']}:{ran_part}"


def analyze(
    ngap_events: list[dict[str, object]],
    nas_events: list[dict[str, object]],
    correlation_groups: list[dict[str, object]],
    rules_dir: Path,
) -> dict[str, object]:
    rules = load_rules(rules_dir)
    instances, conflicts = build_instances(ngap_events)
    _joined, unbound = join_nas_events(instances, nas_events, correlation_groups)
    analyses = []
    stage_records: list[dict[str, object]] = []
    for instance in sorted(instances, key=build_instance_id):
        instance_id = build_instance_id(instance)
        instance_conflicts = [
            conflict for conflict in conflicts
            if conflict["capture_file"] == instance["capture_file"]
            and conflict["association"] == instance["association"]
            and conflict.get("ran_ue_ngap_id") == instance.get("ran_ue_ngap_id")
        ]
        result = evaluate_instance(instance, instance_id, rules, instance_conflicts)
        result["context"] = {
            "capture_file": instance["capture_file"],
            "association": instance["association"],
            "ngap_context": {
                "amf_ue_ngap_id": instance["amf_ue_ngap_id"],
                "ran_ue_ngap_id": instance["ran_ue_ngap_id"],
                "association": instance["association"],
            },
        }
        result["procedure_instance"] = {
            "instance_id": instance_id,
            "identifier_basis": "DERIVED",
            "note": "Local analysis identifier 5gc-reg:<capture>:<association>:<ran-id>; not a standardized 3GPP identifier and not subscriber identity",
        }
        analyses.append(result)
        stage_records.extend(result["stage_records"])
    unbound_records = [
        {
            "procedure_name": "unbound-evidence",
            "procedure_version": ANALYSIS_VERSION,
            "observation_group": str(event["capture_file"]),
            "stage": {
                "stage_id": "unbound",
                "stage_name": "UNBOUND / INCONCLUSIVE",
                "expected_protocols": [str(event.get("protocol"))],
                "expected_message_types": [str(event.get("message_type"))],
            },
            "expected_evidence": [],
            "observed_evidence": [f"{event.get('protocol')} {event.get('message_type')} at frame {event['frame_number']} could not be resolved to a UE procedure instance"],
            "missing_evidence": [],
            "evidence_basis": "OBSERVED",
            "confidence": "LOW",
            "limitations": ["No UE-context or frame provenance connects this record to a procedure instance; no association was invented"],
        }
        for event in unbound
    ]
    return {
        "analyses": analyses,
        "stage_records": stage_records,
        "unbound_records": unbound_records,
        "correlation_conflicts": conflicts,
    }


def sanitize_output(document: object) -> object:
    text = json.dumps(document, sort_keys=True)
    match = FORBIDDEN_OUTPUT_PATTERN.search(text)
    if match:
        raise InputError(f"analysis output contains forbidden verdict wording: {match.group(0)}")
    return document
