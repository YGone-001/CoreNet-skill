#!/usr/bin/env python3
"""Shared helpers for bounded EPS Attach procedure analysis.

The model consumes already-extracted S1AP and NAS-EPS events. It owns EPS Attach
procedure-stage analysis only: it never decodes protocols, never reads subscriber
identity, never claims bearer or PDN success, and never selects a global
first-abnormal boundary.

Stage and deviation vocabulary was reviewed against 3GPP TS 23.401 (EPS attach
procedure context), 3GPP TS 24.301 (EPS NAS message identities and EMM causes) and
3GPP TS 36.413 (S1AP messages), through the accepted `s1ap` and `nas-eps` Protocol
Skill contracts.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

DOMAIN_NAME = "epc-procedures"
DOMAIN_VERSION = "0.1.0"
PROCEDURE = "eps-attach"
PROCEDURE_LABEL = "EPS Attach"

MODEL_VERSION = "1.0.0"

EXIT_MALFORMED_INPUT = 5
EXIT_NO_INSTANCES = 6
EXIT_OUTPUT_FAILURE = 7

STAGE_ORDER = (
    "attach-initiation",
    "identity",
    "authentication",
    "security-mode",
    "attach-decision",
    "attach-completion",
    "s1-context-setup",
    "context-release",
)

STAGE_LABELS = {
    "attach-initiation": "Attach initiation",
    "identity": "Identity procedure",
    "authentication": "Authentication procedure",
    "security-mode": "NAS security mode control",
    "attach-decision": "Attach decision",
    "attach-completion": "Attach completion",
    "s1-context-setup": "S1 context setup",
    "context-release": "UE context release",
}

CONDITIONAL_STAGES = frozenset({"identity", "authentication", "security-mode", "s1-context-setup"})

# Stage -> protocol -> reviewed message identities that belong to the stage.
STAGE_MESSAGES: dict[str, dict[str, tuple[str, ...]]] = {
    "attach-initiation": {"NAS-EPS": ("Attach request",)},
    "identity": {"NAS-EPS": ("Identity request", "Identity response")},
    "authentication": {
        "NAS-EPS": (
            "Authentication request",
            "Authentication response",
            "Authentication failure",
            "Authentication reject",
        )
    },
    "security-mode": {
        "NAS-EPS": ("Security mode command", "Security mode complete", "Security mode reject")
    },
    "attach-decision": {"NAS-EPS": ("Attach accept", "Attach reject")},
    "attach-completion": {"NAS-EPS": ("Attach complete",)},
    "s1-context-setup": {
        "S1AP": (
            "InitialContextSetupRequest",
            "InitialContextSetupResponse",
            "InitialContextSetupFailure",
        )
    },
    "context-release": {
        "S1AP": (
            "UEContextReleaseRequest",
            "UEContextReleaseCommand",
            "UEContextReleaseComplete",
        )
    },
}

TERMINAL_DECISION_MESSAGES = frozenset({"Attach accept", "Attach reject"})

STAGE_STATUSES = (
    "OBSERVED",
    "INCOMPLETE",
    "NOT_OBSERVED",
    "UNAVAILABLE_PROTECTED",
)

OBSERVATION_TYPES = (
    "ATTACH_REQUEST_OBSERVED",
    "ATTACH_ACCEPT_OBSERVED",
    "ATTACH_COMPLETE_OBSERVED",
    "AUTHENTICATION_RESPONSE_OBSERVED",
    "SECURITY_MODE_COMPLETE_OBSERVED",
    "S1_CONTEXT_SETUP_RESPONSE_OBSERVED",
    "CONTEXT_RELEASE_OBSERVED",
    "IDENTITY_EXCHANGE_OBSERVED",
    "REPEATED_ATTACH_REQUEST_OBSERVED",
)

DEVIATION_TYPES = (
    "ATTACH_REJECT_OBSERVED",
    "AUTHENTICATION_FAILURE_OBSERVED",
    "AUTHENTICATION_REJECT_OBSERVED",
    "SECURITY_MODE_REJECT_OBSERVED",
    "S1_CONTEXT_SETUP_FAILURE_OBSERVED",
    "PROTECTED_INNER_MESSAGE_UNAVAILABLE",
    "INSUFFICIENT_TERMINAL_EVIDENCE",
)

ASSOCIATION_STRENGTHS = ("STRONG", "SUPPORTED", "AMBIGUOUS", "UNBOUND")

NOT_CONFIRMED = (
    "default bearer activation is not established by this analysis",
    "PDN connectivity success is not established by this analysis",
    "S1-U user-plane readiness is not established by this analysis",
    "end-to-end service success is not established by this analysis",
    "root cause and network-function blame are not established by this analysis",
    "HSS, MME, SIM or implementation behaviour is not assessed",
)

GLOBAL_BOUNDARY_NOTE = (
    "No EPC Analysis Orchestration exists, so no global first-abnormal boundary is "
    "selected. Deviations below are procedure-local and frame-anchored."
)


class InputError(ValueError):
    """Raised when an accepted event file cannot be used as procedure input."""


def safe_name(path: Path) -> str:
    return path.name


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"input file cannot be read: {path.name}: {exc}") from exc
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputError(f"{path.name} line {number}: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise InputError(f"{path.name} line {number}: event is not an object")
        events.append(record)
    return events


def require(record: dict[str, Any], field: str, source: str) -> Any:
    if field not in record or record[field] in (None, ""):
        raise InputError(f"{source}: event is missing required field '{field}'")
    return record[field]


def validate_events(events: Iterable[dict[str, Any]], protocol: str) -> list[dict[str, Any]]:
    validated: list[dict[str, Any]] = []
    for index, event in enumerate(events, start=1):
        source = f"{protocol} event {index}"
        frame = require(event, "frame_number", source)
        if not isinstance(frame, int) or isinstance(frame, bool) or frame < 1:
            raise InputError(f"{source}: frame_number must be a positive integer")
        require(event, "timestamp", source)
        require(event, "capture_file", source)
        if protocol == "S1AP":
            require(event, "procedure_code", source)
        else:
            if event.get("message_type") is None and not event.get("protected_inner_message_unavailable"):
                raise InputError(
                    f"{source}: NAS-EPS event has neither a message identity nor a protected-envelope marker"
                )
        validated.append(event)
    return validated


def load_inputs(s1ap_path: Path, nas_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    s1ap = validate_events(read_jsonl(s1ap_path), "S1AP")
    nas = validate_events(read_jsonl(nas_path), "NAS-EPS")
    return s1ap, nas


def association_of(event: dict[str, Any]) -> str:
    sctp = event.get("sctp")
    if isinstance(sctp, dict) and sctp.get("association_id") is not None:
        return f"sctp-assoc-{sctp['association_id']}"
    return "sctp-assoc-unknown"


def index_s1ap_by_frame(s1ap_events: list[dict[str, Any]]) -> dict[tuple[str, int], list[dict[str, Any]]]:
    index: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for event in s1ap_events:
        key = (str(event["capture_file"]), int(event["frame_number"]))
        index.setdefault(key, []).append(event)
    return index


def bind_nas_events(
    nas_events: list[dict[str, Any]], s1ap_index: dict[tuple[str, int], list[dict[str, Any]]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Bind each NAS event to its enclosing S1AP UE context when that is provable.

    A NAS event and an S1AP event may describe the same physical frame; that is one
    signaling observation carrying two protocol layers, not two transactions. The
    binding uses capture identity plus frame number plus the S1AP NAS-PDU presence
    only. Timestamp proximity is never used.
    """
    bound: list[dict[str, Any]] = []
    unbound: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    for event in nas_events:
        key = (str(event["capture_file"]), int(event["frame_number"]))
        candidates = [
            item for item in s1ap_index.get(key, []) if item.get("nas_pdu_present") is True
        ]
        if len(candidates) == 1:
            enclosing = candidates[0]
            bound.append({
                "nas": event,
                "s1ap": enclosing,
                "basis": "same_capture_same_frame_s1ap_nas_pdu",
            })
        elif len(candidates) > 1:
            ambiguous.append({
                "nas": event,
                "candidates": [
                    {
                        "frame_number": item.get("frame_number"),
                        "message_type": item.get("message_type"),
                        "enb_ue_s1ap_id": item.get("enb_ue_s1ap_id"),
                        "mme_ue_s1ap_id": item.get("mme_ue_s1ap_id"),
                    }
                    for item in candidates
                ],
                "reason": "more than one S1AP message on this frame carries a NAS-PDU",
            })
        else:
            unbound.append({
                "nas": event,
                "reason": "no enclosing S1AP message carrying a NAS-PDU on this frame",
            })
    return bound, unbound, ambiguous


def _context_tuple(event: dict[str, Any]) -> tuple[str, str, int | None, int | None]:
    return (
        str(event.get("capture_file")),
        association_of(event),
        event.get("enb_ue_s1ap_id"),
        event.get("mme_ue_s1ap_id"),
    )


def resolve_contexts(
    bound: list[dict[str, Any]], s1ap_events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Resolve a stable UE context per bound observation.

    A context observed before the MME allocates its identifier is extended to that
    identifier only when exactly one MME-UE-S1AP-ID is observed for the same
    capture, association and eNB identifier. Conflicting identifiers stay separate
    and are marked ambiguous.
    """
    mme_by_enb: dict[tuple[str, str, int], set[int]] = {}
    for event in s1ap_events:
        capture, association, enb, mme = _context_tuple(event)
        if enb is None or mme is None:
            continue
        mme_by_enb.setdefault((capture, association, enb), set()).add(mme)

    resolved: list[dict[str, Any]] = []
    for item in bound:
        s1ap = item["s1ap"]
        capture, association, enb, mme = _context_tuple(s1ap)
        basis = "observed_identifier_pair" if mme is not None else "enb_identifier_only"
        strength = "STRONG" if mme is not None else "SUPPORTED"
        ambiguity: list[str] = []
        if mme is None and enb is not None:
            candidates = mme_by_enb.get((capture, association, enb), set())
            if len(candidates) == 1:
                mme = next(iter(candidates))
                basis = "pre_assignment_extension_unique_mme_identifier"
            elif len(candidates) > 1:
                ambiguity.append(
                    "one eNB-UE-S1AP-ID is observed with multiple MME-UE-S1AP-ID values; "
                    "the pre-assignment context is not merged"
                )
                strength = "AMBIGUOUS"
        record = dict(item)
        record["context"] = {
            "capture_file": capture,
            "sctp_association": association,
            "enb_ue_s1ap_id": enb,
            "mme_ue_s1ap_id": mme,
        }
        record["association"] = {"basis": basis, "strength": strength}
        record["ambiguity"] = ambiguity
        resolved.append(record)
    return resolved


def context_identity(context: dict[str, Any], attempt: int) -> str:
    material = "|".join(
        str(context.get(key))
        for key in ("capture_file", "sctp_association", "enb_ue_s1ap_id", "mme_ue_s1ap_id")
    ) + f"|attempt={attempt}"
    return f"epc-attach-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:10]}"


def _event_ref(event: dict[str, Any], protocol: str) -> dict[str, Any]:
    return {
        "protocol": protocol,
        "frame_number": event.get("frame_number"),
        "message_type": event.get("message_type"),
        "evidence_level": (event.get("evidence") or {}).get("level", "OBSERVED"),
    }


def _stage_for(protocol: str, message_type: str | None) -> str | None:
    if message_type is None:
        return None
    for stage, mapping in STAGE_MESSAGES.items():
        if message_type in mapping.get(protocol, ()):
            return stage
    return None


def _window(records: list[tuple[int, dict[str, Any]]]) -> dict[str, int] | None:
    frames = [frame for frame, _ in records]
    if not frames:
        return None
    return {"start_frame": min(frames), "end_frame": max(frames)}


def build_attempt(
    context: dict[str, Any],
    attempt_index: int,
    nas_items: list[dict[str, Any]],
    s1ap_items: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build one independently addressable Attach attempt from its bound evidence."""
    combined: list[tuple[int, str, dict[str, Any]]] = []
    for item in nas_items:
        combined.append((int(item["nas"]["frame_number"]), "NAS-EPS", item["nas"]))
    for event in s1ap_items:
        combined.append((int(event["frame_number"]), "S1AP", event))
    combined.sort(key=lambda entry: (entry[0], 0 if entry[1] == "NAS-EPS" else 1))

    stages: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    deviations: list[dict[str, Any]] = []
    limitations: list[str] = []

    for stage in STAGE_ORDER:
        mapping = STAGE_MESSAGES[stage]
        matched = [
            (frame, protocol, event)
            for frame, protocol, event in combined
            if event.get("message_type") in mapping.get(protocol, ())
        ]
        record: dict[str, Any] = {
            "stage_id": stage,
            "stage_name": STAGE_LABELS[stage],
            "conditional": stage in CONDITIONAL_STAGES,
            "status": "NOT_OBSERVED",
            "messages": [event.get("message_type") for _, _, event in matched],
            "first_frame": matched[0][0] if matched else None,
            "last_frame": matched[-1][0] if matched else None,
            "evidence_refs": [
                _event_ref(event, protocol) for _, protocol, event in matched
            ],
        }
        if matched:
            record["status"] = "OBSERVED"
            triggers = {
                "identity": ("Identity request",),
                "authentication": ("Authentication request",),
                "security-mode": ("Security mode command",),
                "s1-context-setup": ("InitialContextSetupRequest",),
                "context-release": ("UEContextReleaseRequest", "UEContextReleaseCommand"),
            }.get(stage, ())
            if triggers and not any(name in record["messages"] for name in triggers):
                record["status"] = "OBSERVED"
        stages.append(record)

    protected = [
        (frame, event)
        for frame, protocol, event in combined
        if protocol == "NAS-EPS" and event.get("protected_inner_message_unavailable") is True
    ]

    def add_observation(observation_type: str, stage: str, event: dict[str, Any], protocol: str) -> None:
        observations.append({
            "observation_type": observation_type,
            "procedure_stage": stage,
            "protocol": protocol,
            "message_type": event.get("message_type"),
            "frame_number": event.get("frame_number"),
            "evidence_level": (event.get("evidence") or {}).get("level", "OBSERVED"),
        })

    def add_deviation(
        deviation_type: str,
        stage: str,
        event: dict[str, Any] | None,
        protocol: str,
        explanation: str,
        extra_limitations: list[str] | None = None,
    ) -> None:
        refs = [_event_ref(event, protocol)] if event is not None else []
        deviations.append({
            "deviation_type": deviation_type,
            "procedure_stage": stage,
            "protocol": protocol,
            "message_type": event.get("message_type") if event is not None else None,
            "frame_number": event.get("frame_number") if event is not None else None,
            "evidence_level": "OBSERVED" if event is not None else "DERIVED",
            "evidence_refs": refs,
            "observation_window": _window([(frame, item) for frame, proto, item in combined if proto == protocol]),
            "explanation": explanation,
            "limitations": list(extra_limitations or []),
        })

    for frame, protocol, event in combined:
        message = event.get("message_type")
        if protocol == "NAS-EPS":
            if message == "Attach request":
                add_observation("ATTACH_REQUEST_OBSERVED", "attach-initiation", event, protocol)
            elif message == "Attach accept":
                add_observation("ATTACH_ACCEPT_OBSERVED", "attach-decision", event, protocol)
            elif message == "Attach complete":
                add_observation("ATTACH_COMPLETE_OBSERVED", "attach-completion", event, protocol)
            elif message == "Attach reject":
                cause = event.get("emm_cause") or {}
                value = cause.get("value")
                name = cause.get("name")
                explanation = "explicit Attach rejection observed"
                if value is not None:
                    explanation += f" with EMM cause {value}" + (f" ({name})" if name else "")
                add_deviation("ATTACH_REJECT_OBSERVED", "attach-decision", event, protocol, explanation)
            elif message == "Authentication response":
                add_observation("AUTHENTICATION_RESPONSE_OBSERVED", "authentication", event, protocol)
            elif message == "Authentication failure":
                add_deviation(
                    "AUTHENTICATION_FAILURE_OBSERVED",
                    "authentication",
                    event,
                    protocol,
                    "explicit Authentication failure observed; it is protocol-defined unsuccessful "
                    "evidence and does not identify a responsible network function",
                )
            elif message == "Authentication reject":
                add_deviation(
                    "AUTHENTICATION_REJECT_OBSERVED",
                    "authentication",
                    event,
                    protocol,
                    "explicit Authentication reject observed; the underlying cause is not assessed",
                )
            elif message == "Security mode complete":
                add_observation("SECURITY_MODE_COMPLETE_OBSERVED", "security-mode", event, protocol)
            elif message == "Security mode reject":
                add_deviation(
                    "SECURITY_MODE_REJECT_OBSERVED",
                    "security-mode",
                    event,
                    protocol,
                    "explicit Security mode reject observed",
                )
            elif message == "Identity request" or message == "Identity response":
                add_observation("IDENTITY_EXCHANGE_OBSERVED", "identity", event, protocol)
        else:
            if message == "InitialContextSetupResponse":
                add_observation("S1_CONTEXT_SETUP_RESPONSE_OBSERVED", "s1-context-setup", event, protocol)
            elif message == "InitialContextSetupFailure":
                add_deviation(
                    "S1_CONTEXT_SETUP_FAILURE_OBSERVED",
                    "s1-context-setup",
                    event,
                    protocol,
                    "explicit S1 Initial Context Setup failure observed; it is not proof that the "
                    "NAS Attach procedure failed",
                )
            elif message in ("UEContextReleaseCommand", "UEContextReleaseComplete", "UEContextReleaseRequest"):
                add_observation("CONTEXT_RELEASE_OBSERVED", "context-release", event, protocol)

    if protected:
        frames = sorted({frame for frame, _ in protected})
        deviations.append({
            "deviation_type": "PROTECTED_INNER_MESSAGE_UNAVAILABLE",
            "procedure_stage": "attach-decision",
            "protocol": "NAS-EPS",
            "message_type": None,
            "frame_number": frames[0],
            "evidence_level": "OBSERVED",
            "evidence_refs": [
                {"protocol": "NAS-EPS", "frame_number": frame, "message_type": None,
                 "evidence_level": "OBSERVED"}
                for frame in frames
            ],
            "observation_window": {"start_frame": frames[0], "end_frame": frames[-1]},
            "explanation": (
                "protected NAS envelopes carry no observable inner message identity; the inner "
                "messages are unavailable, not absent"
            ),
            "limitations": ["ciphered inner NAS content is not decoded"],
        })
        limitations.append(
            "protected NAS envelopes prevent reading inner message identity in this attempt"
        )

    decision_frames = [
        int(event["frame_number"])
        for _, protocol, event in combined
        if protocol == "NAS-EPS" and event.get("message_type") in TERMINAL_DECISION_MESSAGES
    ]
    completion_frames = [
        int(event["frame_number"])
        for _, protocol, event in combined
        if protocol == "NAS-EPS" and event.get("message_type") == "Attach complete"
    ]
    if not decision_frames:
        last_frame = combined[-1][0] if combined else None
        deviations.append({
            "deviation_type": "INSUFFICIENT_TERMINAL_EVIDENCE",
            "procedure_stage": "attach-decision",
            "protocol": "NAS-EPS",
            "message_type": None,
            "frame_number": last_frame,
            "evidence_level": "DERIVED",
            "evidence_refs": [],
            "observation_window": _window([(frame, event) for frame, _, event in combined]),
            "explanation": (
                "no Attach accept or Attach reject was observed for this attempt; the capture "
                "does not contain a terminal decision"
            ),
            "limitations": ["a missing message is not a failed procedure"],
        })
        limitations.append(
            "no terminal Attach decision was observed; the attempt is incomplete within this capture"
        )
    elif decision_frames and not completion_frames:
        accepted = any(
            event.get("message_type") == "Attach accept"
            for _, protocol, event in combined
            if protocol == "NAS-EPS"
        )
        if accepted:
            limitations.append(
                "Attach accept was observed without Attach complete in this capture window"
            )

    bases = {item["association"]["basis"] for item in nas_items}
    if "pre_assignment_extension_unique_mme_identifier" in bases:
        association_basis = "pre_assignment_extension_unique_mme_identifier"
    elif bases:
        association_basis = sorted(bases)[0]
    else:
        association_basis = "s1ap_only"
    association = {
        "basis": association_basis,
        "strength": "STRONG" if context["mme_ue_s1ap_id"] is not None else "SUPPORTED",
    }
    if not nas_items:
        association["strength"] = "SUPPORTED"
        limitations.append(
            "no NAS-EPS message is bound to this UE context; Attach stages are unobservable"
        )

    frames = [frame for frame, _, _ in combined]
    attempt = {
        "procedure_reference": context_identity(context, attempt_index),
        "procedure": PROCEDURE,
        "procedure_label": PROCEDURE_LABEL,
        "attempt_index": attempt_index,
        "association": {
            "basis": association["basis"],
            "strength": association["strength"],
            "capture_file": context["capture_file"],
            "sctp_association": context["sctp_association"],
            "enb_ue_s1ap_id": context["enb_ue_s1ap_id"],
            "mme_ue_s1ap_id": context["mme_ue_s1ap_id"],
        },
        "first_frame": min(frames) if frames else None,
        "last_frame": max(frames) if frames else None,
        "stages": stages,
        "observations": observations,
        "deviations": deviations,
        "evidence_limitations": limitations,
        "additional_evidence_needed": _additional_evidence(stages, deviations),
    }
    return attempt


def _additional_evidence(stages: list[dict[str, Any]], deviations: list[dict[str, Any]]) -> list[str]:
    needed: list[str] = []
    status_by_stage = {stage["stage_id"]: stage["status"] for stage in stages}
    if status_by_stage.get("attach-decision") != "OBSERVED":
        needed.append("capture the NAS Attach accept or Attach reject for this UE context")
    if status_by_stage.get("attach-completion") != "OBSERVED":
        needed.append("capture the NAS Attach complete to observe procedure completion")
    if status_by_stage.get("s1-context-setup") == "NOT_OBSERVED":
        needed.append("capture the S1 Initial Context Setup exchange for this UE context")
    if any(item["deviation_type"] == "PROTECTED_INNER_MESSAGE_UNAVAILABLE" for item in deviations):
        needed.append("obtain decrypted NAS or a capture where the inner message identity is visible")
    return needed


def build_instances(
    bound: list[dict[str, Any]], s1ap_events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Group bound evidence into independently addressable Attach attempts."""
    groups: dict[tuple, dict[str, Any]] = {}
    for item in bound:
        context = item["context"]
        key = (
            context["capture_file"],
            context["sctp_association"],
            context["enb_ue_s1ap_id"],
            context["mme_ue_s1ap_id"],
        )
        groups.setdefault(key, {"context": context, "nas": [], "s1ap": []})["nas"].append(item)

    for key, group in groups.items():
        context = group["context"]
        for event in s1ap_events:
            event_context = {
                "capture_file": str(event.get("capture_file")),
                "sctp_association": association_of(event),
                "enb_ue_s1ap_id": event.get("enb_ue_s1ap_id"),
                "mme_ue_s1ap_id": event.get("mme_ue_s1ap_id"),
            }
            if (
                event_context["capture_file"] == context["capture_file"]
                and event_context["sctp_association"] == context["sctp_association"]
                and event_context["enb_ue_s1ap_id"] == context["enb_ue_s1ap_id"]
                and (
                    event_context["mme_ue_s1ap_id"] == context["mme_ue_s1ap_id"]
                    or event_context["mme_ue_s1ap_id"] is None
                )
            ):
                group["s1ap"].append(event)

    instances: list[dict[str, Any]] = []
    for key in sorted(groups, key=lambda item: tuple(str(part) for part in item)):
        group = groups[key]
        nas_items = sorted(group["nas"], key=lambda item: int(item["nas"]["frame_number"]))
        s1ap_items = sorted(group["s1ap"], key=lambda event: int(event["frame_number"]))

        attempts: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = []
        closed = True
        for item in nas_items:
            message = item["nas"].get("message_type")
            if message == "Attach request":
                if closed and current:
                    attempts.append(current)
                    current = []
                closed = False
            current.append(item)
            if message in TERMINAL_DECISION_MESSAGES:
                closed = True
        if current:
            attempts.append(current)

        if not attempts:
            attempts = [[]]

        s1ap_assigned: set[int] = set()
        for index, attempt_nas in enumerate(attempts, start=1):
            if attempt_nas:
                window_start = int(attempt_nas[0]["nas"]["frame_number"])
                window_end = (
                    int(attempt_nas[-1]["nas"]["frame_number"]) if attempt_nas else window_start
                )
            else:
                window_start = min((int(e["frame_number"]) for e in s1ap_items), default=0)
                window_end = max((int(e["frame_number"]) for e in s1ap_items), default=0)
            assigned = [
                event
                for event in s1ap_items
                if int(event["frame_number"]) >= window_start
                and id(event) not in s1ap_assigned
            ]
            for event in assigned:
                s1ap_assigned.add(id(event))
            attempt = build_attempt(group["context"], index, attempt_nas, assigned)
            if "AMBIGUOUS" in {item["association"]["strength"] for item in attempt_nas}:
                attempt["association"]["strength"] = "AMBIGUOUS"
                for item in attempt_nas:
                    for reason in item.get("ambiguity") or []:
                        if reason not in attempt["evidence_limitations"]:
                            attempt["evidence_limitations"].append(reason)
            if index > 1:
                attempt["evidence_limitations"].append(
                    "this attempt follows a terminal decision on the same UE context and is "
                    "treated as an independent attempt"
                )
            instances.append(attempt)

    return instances


def analyze(
    s1ap_events: list[dict[str, Any]],
    nas_events: list[dict[str, Any]],
    s1ap_name: str,
    nas_name: str,
) -> dict[str, Any]:
    s1ap_index = index_s1ap_by_frame(s1ap_events)
    bound, unbound, ambiguous = bind_nas_events(nas_events, s1ap_index)
    resolved = resolve_contexts(bound, s1ap_events)
    instances = build_instances(resolved, s1ap_events)

    limitations: list[str] = [GLOBAL_BOUNDARY_NOTE]
    if unbound:
        limitations.append(
            f"{len(unbound)} NAS-EPS event(s) have no enclosing S1AP UE context and remain unbound"
        )
    if ambiguous:
        limitations.append(
            f"{len(ambiguous)} NAS-EPS event(s) sit on a frame with several NAS-carrying S1AP "
            "messages and remain ambiguous"
        )
    if any(item["association"]["strength"] == "AMBIGUOUS" for item in resolved):
        limitations.append(
            "conflicting S1AP UE identifiers were observed for one eNB identifier; those contexts "
            "are not merged"
        )
    if not instances:
        limitations.append(
            "no EPS Attach procedure instance could be formed from the supplied evidence"
        )

    additional: list[str] = []
    for instance in instances:
        for item in instance["additional_evidence_needed"]:
            if item not in additional:
                additional.append(item)

    return {
        "domain": DOMAIN_NAME,
        "domain_version": DOMAIN_VERSION,
        "model_version": MODEL_VERSION,
        "analysis_scope": "bounded EPS Attach procedure evidence",
        "input_provenance": {
            "s1ap_events": {"file": s1ap_name, "event_count": len(s1ap_events)},
            "nas_eps_events": {"file": nas_name, "event_count": len(nas_events)},
        },
        "procedure": PROCEDURE,
        "procedure_label": PROCEDURE_LABEL,
        "stage_vocabulary": list(STAGE_ORDER),
        "procedure_instances": instances,
        "instance_count": len(instances),
        "unbound_evidence": [
            {
                "frame_number": item["nas"].get("frame_number"),
                "capture_file": item["nas"].get("capture_file"),
                "message_type": item["nas"].get("message_type"),
                "reason": item["reason"],
            }
            for item in unbound
        ],
        "ambiguous_evidence": [
            {
                "frame_number": item["nas"].get("frame_number"),
                "capture_file": item["nas"].get("capture_file"),
                "message_type": item["nas"].get("message_type"),
                "reason": item["reason"],
                "candidates": item["candidates"],
            }
            for item in ambiguous
        ],
        "global_first_abnormal_boundary": None,
        "global_boundary_evaluation": "NOT_EVALUATED",
        "limitations": limitations,
        "additional_evidence_needed": additional,
        "not_confirmed": list(NOT_CONFIRMED),
    }


def stage_rows(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for instance in analysis["procedure_instances"]:
        for stage in instance["stages"]:
            rows.append({
                "procedure_reference": instance["procedure_reference"],
                "attempt_index": instance["attempt_index"],
                "stage_id": stage["stage_id"],
                "stage_name": stage["stage_name"],
                "conditional": stage["conditional"],
                "status": stage["status"],
                "messages": stage["messages"],
                "first_frame": stage["first_frame"],
                "last_frame": stage["last_frame"],
                "association_strength": instance["association"]["strength"],
            })
    return rows
