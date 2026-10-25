#!/usr/bin/env python3
"""Shared helpers for bounded EPS default-bearer evidence analysis.

The model consumes already-extracted NAS-EPS events (with their decoded ESM
messages), already-extracted S1AP events (with item-scoped E-RAB evidence), and
the accepted EPS Attach and EPC Session-Control Domain analyses. It never decodes
a protocol, never reads subscriber identity and never claims user-plane success.

Stage, outcome and link vocabularies were reviewed against 3GPP TS 23.401 §5.3.2
(initial attach and default bearer establishment), 3GPP TS 24.301 §6.5 (PDN
connectivity) and §6.5.1.5 (ESM container transport), and 3GPP TS 36.413 §9.1.4
(Initial Context Setup E-RAB items).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

DOMAIN_NAME = "epc-procedures"
DOMAIN_VERSION = "0.3.0"
PROCEDURE = "eps-default-bearer"
PROCEDURE_LABEL = "EPS default bearer"

MODEL_VERSION = "1.0.0"

EXIT_MALFORMED_INPUT = 5
EXIT_NO_INSTANCES = 6
EXIT_OUTPUT_FAILURE = 7

STAGE_ORDER = (
    "pdn-connectivity-request",
    "esm-information-exchange",
    "default-bearer-activation-request",
    "default-bearer-activation-response",
    "s1-erab-setup",
    "supporting-gtpv2-session-control",
)

STAGE_LABELS = {
    "pdn-connectivity-request": "PDN connectivity request",
    "esm-information-exchange": "ESM information exchange",
    "default-bearer-activation-request": "Default bearer activation request",
    "default-bearer-activation-response": "Default bearer activation response",
    "s1-erab-setup": "S1 E-RAB setup",
    "supporting-gtpv2-session-control": "Supporting GTPv2-C session control",
}

CONDITIONAL_STAGES = frozenset({"esm-information-exchange", "s1-erab-setup", "supporting-gtpv2-session-control"})

STAGE_STATUSES = (
    "OBSERVED",
    "NOT_OBSERVED",
    "UNAVAILABLE_PROTECTED",
    "AMBIGUOUS",
    "INSUFFICIENT_EVIDENCE",
)

OUTCOMES = (
    "PDN_CONNECTIVITY_REQUEST_OBSERVED",
    "PDN_CONNECTIVITY_REJECT_OBSERVED",
    "DEFAULT_BEARER_ACTIVATION_REQUEST_OBSERVED",
    "DEFAULT_BEARER_ACTIVATION_ACCEPT_OBSERVED",
    "DEFAULT_BEARER_ACTIVATION_REJECT_OBSERVED",
    "S1_ERAB_SETUP_REQUEST_OBSERVED",
    "S1_ERAB_SETUP_RESPONSE_OBSERVED",
    "DEFAULT_BEARER_SIGNALING_INCOMPLETE",
    "PROTECTED_ESM_UNAVAILABLE",
)

LINK_STATUSES = ("ESTABLISHED", "SUPPORTED", "AMBIGUOUS", "NOT_ESTABLISHED")

# ESM message identities that belong to each stage.
STAGE_ESM_MESSAGES: dict[str, tuple[int, ...]] = {
    "pdn-connectivity-request": (208, 209),
    "esm-information-exchange": (217, 218),
    "default-bearer-activation-request": (193,),
    "default-bearer-activation-response": (194, 195),
}

S1AP_ERAB_MESSAGES = {
    "InitialContextSetupRequest": "REQUEST",
    "InitialContextSetupResponse": "RESPONSE",
    "InitialContextSetupFailure": "FAILURE",
}

DEVIATION_PDN_REJECT = "PDN_CONNECTIVITY_REJECT_OBSERVED"
DEVIATION_ACTIVATION_REJECT = "DEFAULT_BEARER_ACTIVATION_REJECT_OBSERVED"
DEVIATION_ESM_REJECT = "ESM_REJECTION_OBSERVED"
DEVIATION_PROTECTED = "PROTECTED_ESM_UNAVAILABLE"
DEVIATION_ERAB_UNBOUND = "ERAB_ITEM_EVIDENCE_UNAVAILABLE"
DEVIATION_TUNNEL_AMBIGUOUS = "TUNNEL_ENDPOINT_LINK_AMBIGUOUS"
DEVIATION_ESM_UNBOUND = "ESM_EVIDENCE_UNBOUND"

DEVIATION_TYPES = (
    DEVIATION_PDN_REJECT,
    DEVIATION_ACTIVATION_REJECT,
    DEVIATION_ESM_REJECT,
    DEVIATION_PROTECTED,
    DEVIATION_ERAB_UNBOUND,
    DEVIATION_TUNNEL_AMBIGUOUS,
    DEVIATION_ESM_UNBOUND,
)

# Deviations that describe a protocol-level negative outcome rather than a
# completeness or association limitation.
NEGATIVE_DEVIATIONS = frozenset(
    {DEVIATION_PDN_REJECT, DEVIATION_ACTIVATION_REJECT, DEVIATION_ESM_REJECT}
)

# Reviewed GTPv2-C F-TEID interface types that carry an S1-U endpoint.
S1U_INTERFACE_TYPES = frozenset({1})

REVIEWED_GTPV2_FAMILIES = frozenset(
    {
        "create-session",
        "modify-bearer",
        "delete-session",
        "release-access-bearers",
        "echo",
    }
)

NOT_CONFIRMED = (
    "an accepted ESM response is protocol-level evidence only; it does not prove that the "
    "default bearer carries user traffic",
    "an E-RAB GTP-TEID is control-plane provisioning evidence only; it does not prove that a "
    "GTP-U tunnel forwards packets",
    "the UE context of this analysis is not equated with any GTPv2-C session subject without a "
    "reviewed identity bridge",
    "no S11 to S5/S8 session association is asserted",
    "no root cause, network-function blame or subscriber service quality verdict is produced",
    "the absence of an observed stage does not prove that the stage did not happen",
)

GLOBAL_BOUNDARY_NOTE = (
    "This analysis keeps boundary selection NOT_EVALUATED. Per-subject EPC abnormal-boundary "
    "selection belongs to the epc-failure-boundary Orchestration Skill."
)

MAX_LIST_ITEMS = 64
MAX_EVIDENCE_REFERENCES = 32


class InputError(ValueError):
    """Raised when a supported structured input cannot be normalized."""


def safe_name(path: Path) -> str:
    return path.name


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise InputError(f"input file does not exist: {path.name}")
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"{path.name}: invalid JSON Lines at line {line_number}: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise InputError(f"{path.name}: JSON Lines record at line {line_number} is not an object")
            records.append(record)
    return records


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise InputError(f"input file does not exist: {path.name}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: invalid JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise InputError(f"{path.name}: JSON document is not an object")
    return payload


def require(record: dict[str, Any], field: str, source: str) -> Any:
    value = record.get(field)
    if value is None:
        raise InputError(f"{source}: required field '{field}' is missing")
    return value


def association_of(event: dict[str, Any]) -> str:
    sctp = event.get("sctp")
    if isinstance(sctp, dict) and sctp.get("association_id") is not None:
        return f"sctp-assoc-{sctp['association_id']}"
    return "sctp-assoc-unknown"


def _context_tuple(event: dict[str, Any]) -> tuple[str, str, int | None, int | None]:
    return (
        str(event.get("capture_file")),
        association_of(event),
        event.get("enb_ue_s1ap_id"),
        event.get("mme_ue_s1ap_id"),
    )


def _context_key(context: dict[str, Any]) -> tuple[str, str, int | None, int | None]:
    """The same tuple shape for an already-resolved UE context."""
    return (
        str(context.get("capture_file")),
        str(context.get("sctp_association")),
        context.get("enb_ue_s1ap_id"),
        context.get("mme_ue_s1ap_id"),
    )


def index_s1ap_by_frame(s1ap_events: list[dict[str, Any]]) -> dict[tuple[str, int], list[dict[str, Any]]]:
    index: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for event in s1ap_events:
        key = (str(event.get("capture_file")), int(event.get("frame_number") or 0))
        index.setdefault(key, []).append(event)
    return index


def bind_nas_to_s1ap(
    nas_events: list[dict[str, Any]], s1ap_index: dict[tuple[str, int], list[dict[str, Any]]]
) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    """Bind each NAS event to its enclosing S1AP UE context when provable.

    The basis is capture identity plus frame number plus the S1AP NAS-PDU
    presence, exactly as in the accepted EPS Attach Domain. Timestamp proximity
    is never used, and a frame with several NAS-PDU carriers stays ambiguous.
    """
    bound: dict[int, dict[str, Any]] = {}
    ambiguous: list[dict[str, Any]] = []
    for event in nas_events:
        key = (str(event.get("capture_file")), int(event.get("frame_number") or 0))
        # Either a message-level NAS-PDU or a NAS layer nested inside an E-RAB
        # item proves that this S1AP message carries the NAS message.
        candidates = [
            item
            for item in s1ap_index.get(key, [])
            if item.get("nas_pdu_present") is True or item.get("nas_pdu_embedded") is True
        ]
        if len(candidates) == 1:
            bound[id(event)] = candidates[0]
        elif len(candidates) > 1:
            ambiguous.append(
                {
                    "frame_number": event.get("frame_number"),
                    "capture_file": event.get("capture_file"),
                    "message_type": event.get("message_type"),
                    "candidate_count": len(candidates),
                    "reason": "more than one S1AP message on this frame carries a NAS-PDU",
                }
            )
    return bound, ambiguous


def resolve_ue_context(
    enclosing: dict[str, Any],
    s1ap_events: list[dict[str, Any]],
    mme_by_enb: dict[tuple[str, str, int], set[int]],
) -> tuple[dict[str, Any], str]:
    """Resolve the UE context of a bound S1AP event and its association strength."""
    capture, association, enb, mme = _context_tuple(enclosing)
    basis = "observed_identifier_pair" if mme is not None else "enb_identifier_only"
    strength = "STRONG" if mme is not None else "SUPPORTED"
    if mme is None and enb is not None:
        candidates = mme_by_enb.get((capture, association, enb), set())
        if len(candidates) == 1:
            mme = next(iter(candidates))
            basis = "pre_assignment_extension_unique_mme_identifier"
        elif len(candidates) > 1:
            basis = "conflicting_mme_identifiers"
            strength = "AMBIGUOUS"
    context = {
        "capture_file": capture,
        "sctp_association": association,
        "enb_ue_s1ap_id": enb,
        "mme_ue_s1ap_id": mme,
    }
    return context, f"{basis}:{strength}"


def context_reference(context: dict[str, Any]) -> str:
    material = "|".join(
        str(context.get(key))
        for key in ("capture_file", "sctp_association", "enb_ue_s1ap_id", "mme_ue_s1ap_id")
    )
    return f"epc-default-bearer-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:10]}"


def unbound_reference(capture_file: str) -> str:
    material = f"{capture_file}|unbound-esm"
    return f"epc-default-bearer-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:10]}"


def mme_index(s1ap_events: list[dict[str, Any]]) -> dict[tuple[str, str, int], set[int]]:
    index: dict[tuple[str, str, int], set[int]] = {}
    for event in s1ap_events:
        capture, association, enb, mme = _context_tuple(event)
        if enb is None or mme is None:
            continue
        index.setdefault((capture, association, enb), set()).add(mme)
    return index


def _evidence_ref(
    protocol: str, frame: int | None, message_type: str | None, evidence_level: str = "OBSERVED"
) -> dict[str, Any]:
    return {
        "protocol": protocol,
        "frame_number": frame,
        "message_type": message_type,
        "evidence_level": evidence_level,
    }


def _window(frames: Iterable[int]) -> dict[str, int] | None:
    values = [frame for frame in frames if isinstance(frame, int)]
    if not values:
        return None
    return {"start_frame": min(values), "end_frame": max(values)}


def _esm_refs(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        _evidence_ref("NAS-EPS", item.get("frame_number"), item.get("message_type")) for item in messages
    ]


def _stage(
    stage_id: str,
    status: str,
    messages: list[dict[str, Any]],
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    frames = [item.get("frame_number") for item in messages]
    return {
        "stage_id": stage_id,
        "stage_label": STAGE_LABELS[stage_id],
        "status": status,
        "conditional": stage_id in CONDITIONAL_STAGES,
        "message_count": len(messages),
        "first_frame": min(frames) if frames else None,
        "last_frame": max(frames) if frames else None,
        "messages": messages[:MAX_LIST_ITEMS],
        "limitations": limitations or [],
    }


def _esm_message_projection(item: dict[str, Any]) -> dict[str, Any]:
    """Allowlisted ESM message projection; values never leave the source event."""
    return {
        "protocol": "NAS-EPS",
        "frame_number": item.get("frame_number"),
        "occurrence_index": item.get("occurrence_index"),
        "message_type_code": item.get("message_type_code"),
        "message_type": item.get("message_type"),
        "support_status": item.get("support_status"),
        "procedure": item.get("procedure"),
        "result": item.get("result"),
        "eps_bearer_identity": item.get("eps_bearer_identity"),
        "procedure_transaction_identity": item.get("procedure_transaction_identity"),
        "esm_cause": item.get("esm_cause"),
        "pdn_type": item.get("pdn_type"),
        "request_type": item.get("request_type"),
        "apn_present": item.get("apn_present"),
        "apn_length": item.get("apn_length"),
        "pdn_address_present": item.get("pdn_address_present"),
        "pdn_address_family": item.get("pdn_address_family"),
        "qos_present": item.get("qos_present"),
        "pco_present": item.get("pco_present"),
        "protection_state": item.get("protection_state"),
        "direction": item.get("direction"),
        "binding_basis": item.get("binding_basis"),
        "container": item.get("container"),
        "evidence": item.get("evidence"),
        "limitations": item.get("limitations") or [],
    }


def collect_esm(nas_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """All ESM messages with the NAS event that carries them."""
    collected: list[dict[str, Any]] = []
    for event in nas_events:
        for item in event.get("esm_messages") or []:
            if not isinstance(item, dict):
                continue
            collected.append({"esm": item, "nas": event})
    collected.sort(key=lambda pair: (int(pair["esm"].get("frame_number") or 0), int(pair["esm"].get("occurrence_index") or 0)))
    return collected


def group_instances(
    nas_events: list[dict[str, Any]],
    s1ap_events: list[dict[str, Any]],
    attach_analysis: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Group ESM evidence into UE-context instances plus unbound evidence."""
    s1ap_index = index_s1ap_by_frame(s1ap_events)
    bound, ambiguous_frames = bind_nas_to_s1ap(nas_events, s1ap_index)
    mme_by_enb = mme_index(s1ap_events)
    groups: dict[str, dict[str, Any]] = {}
    unbound: list[dict[str, Any]] = []
    for pair in collect_esm(nas_events):
        esm, nas = pair["esm"], pair["nas"]
        enclosing = bound.get(id(nas))
        if enclosing is None:
            unbound.append(
                {
                    "reason": "no single enclosing S1AP message carrying a NAS-PDU on this frame",
                    "frame_number": esm.get("frame_number"),
                    "capture_file": nas.get("capture_file"),
                    "message_type": esm.get("message_type"),
                }
            )
            continue
        context, basis = resolve_ue_context(enclosing, s1ap_events, mme_by_enb)
        reference = context_reference(context)
        group = groups.setdefault(
            reference,
            {
                "instance_reference": reference,
                "ue_context": context,
                "association_basis": basis,
                "association_strength": basis.split(":")[1],
                "esm": [],
                "nas": [],
                "nas_frames": set(),
                "s1ap_frames": set(),
            },
        )
        group["esm"].append(esm)
        group["nas"].append(nas)
        group["nas_frames"].add(nas.get("frame_number"))
        group["s1ap_frames"].add(enclosing.get("frame_number"))

    for event in nas_events:
        if event.get("esm_messages"):
            continue
        if event.get("esm_container_present") is not True and event.get("ciphered_payload_present") is not True:
            continue
        enclosing = bound.get(id(event))
        if enclosing is None:
            unbound.append(
                {
                    "reason": "no single enclosing S1AP message carrying a NAS-PDU on this frame",
                    "frame_number": event.get("frame_number"),
                    "capture_file": event.get("capture_file"),
                    "message_type": event.get("message_type"),
                }
            )
            continue
        context, basis = resolve_ue_context(enclosing, s1ap_events, mme_by_enb)
        reference = context_reference(context)
        group = groups.setdefault(
            reference,
            {
                "instance_reference": reference,
                "ue_context": context,
                "association_basis": basis,
                "association_strength": basis.split(":")[1],
                "esm": [],
                "nas": [],
                "nas_frames": set(),
                "s1ap_frames": set(),
            },
        )
        group["nas"].append(event)
        group["nas_frames"].add(event.get("frame_number"))
        group["s1ap_frames"].add(enclosing.get("frame_number"))

    attach_index = attach_context_index(attach_analysis)
    instances: list[dict[str, Any]] = []
    for reference in sorted(groups):
        group = groups[reference]
        instance = build_instance(group, s1ap_events, attach_index)
        instances.append(instance)
    if unbound:
        instances.append(build_unbound_instance(unbound))
    return instances, unbound, ambiguous_frames


def attach_context_index(attach_analysis: dict[str, Any] | None) -> dict[tuple[str, str, int | None, int | None], list[dict[str, Any]]]:
    """Attach instances keyed by their published UE context."""
    index: dict[tuple[str, str, int | None, int | None], list[dict[str, Any]]] = {}
    if not isinstance(attach_analysis, dict):
        return index
    for instance in attach_analysis.get("procedure_instances") or []:
        if not isinstance(instance, dict):
            continue
        # The accepted EPS Attach analysis publishes its UE context in the
        # `association` object, so that object is the link key here.
        context = instance.get("association") or {}
        key = (
            str(context.get("capture_file")),
            str(context.get("sctp_association")),
            context.get("enb_ue_s1ap_id"),
            context.get("mme_ue_s1ap_id"),
        )
        index.setdefault(key, []).append(instance)
    return index


def _attach_link(context: dict[str, Any], attach_index: dict[tuple[str, str, int | None, int | None], list[dict[str, Any]]]) -> dict[str, Any]:
    key = (
        str(context.get("capture_file")),
        str(context.get("sctp_association")),
        context.get("enb_ue_s1ap_id"),
        context.get("mme_ue_s1ap_id"),
    )
    candidates = attach_index.get(key, [])
    if len(candidates) == 1:
        instance = candidates[0]
        return {
            "status": "ESTABLISHED",
            "target_subject_reference": instance.get("procedure_reference"),
            "link_basis": "same_capture_same_sctp_association_same_s1ap_ue_identifiers",
            "supporting_identifiers": [
                {"identifier": "enb_ue_s1ap_id", "value": context.get("enb_ue_s1ap_id")},
                {"identifier": "mme_ue_s1ap_id", "value": context.get("mme_ue_s1ap_id")},
                {"identifier": "sctp_association", "value": context.get("sctp_association")},
            ],
            "limitations": [
                "the Attach instance and this default-bearer instance share one S1AP UE context; "
                "no subscriber identity is compared"
            ],
        }
    if len(candidates) > 1:
        return {
            "status": "AMBIGUOUS",
            "target_subject_reference": None,
            "link_basis": "several_attach_instances_share_this_s1ap_ue_context",
            "supporting_identifiers": [],
            "limitations": [
                "more than one Attach instance publishes this S1AP UE context, so the ESM evidence "
                "is not attributed to one of them"
            ],
        }
    return {
        "status": "NOT_ESTABLISHED",
        "target_subject_reference": None,
        "link_basis": "no_attach_instance_publishes_this_s1ap_ue_context",
        "supporting_identifiers": [],
        "limitations": [
            "no EPS Attach instance publishes this UE context, so the ESM evidence is not joined "
            "to an Attach procedure"
        ],
    }


def _stage_status(
    stage_id: str,
    messages: list[dict[str, Any]],
    *,
    protected: bool,
    terminal: bool,
) -> str:
    if messages:
        return "OBSERVED"
    if protected:
        return "UNAVAILABLE_PROTECTED"
    if terminal:
        return "NOT_OBSERVED"
    return "INSUFFICIENT_EVIDENCE"


def _deviations_for(instance: dict[str, Any], esm_messages: list[dict[str, Any]], window: dict[str, int] | None) -> list[dict[str, Any]]:
    deviations: list[dict[str, Any]] = []
    for item in esm_messages:
        code = item.get("message_type_code")
        cause = item.get("esm_cause") or {}
        cause_code = cause.get("value") if isinstance(cause, dict) else None
        if code == 209:
            deviation_type = DEVIATION_PDN_REJECT
        elif code == 195:
            deviation_type = DEVIATION_ACTIVATION_REJECT
        elif code in (211, 213, 215, 199, 203):
            deviation_type = DEVIATION_ESM_REJECT
        else:
            continue
        deviations.append(
            {
                "deviation_type": deviation_type,
                "instance_reference": instance["instance_reference"],
                "protocol": "NAS-EPS",
                "message_type": item.get("message_type"),
                "frame_number": item.get("frame_number"),
                "esm_cause_code": cause_code,
                "esm_cause_name": cause.get("name") if isinstance(cause, dict) else None,
                "eps_bearer_identity": item.get("eps_bearer_identity"),
                "evidence_level": "OBSERVED",
                "evidence_refs": [_evidence_ref("NAS-EPS", item.get("frame_number"), item.get("message_type"))],
                "observation_window": window,
                "limitations": [
                    "an ESM Cause is a protocol-level rejection; it does not identify a responsible "
                    "network function",
                ],
            }
        )
    return deviations


def build_instance(
    group: dict[str, Any],
    s1ap_events: list[dict[str, Any]],
    attach_index: dict[tuple[str, str, int | None, int | None], list[dict[str, Any]]],
) -> dict[str, Any]:
    context = group["ue_context"]
    esm_messages = sorted(
        group["esm"], key=lambda item: (int(item.get("frame_number") or 0), int(item.get("occurrence_index") or 0))
    )
    codes = {item.get("message_type_code") for item in esm_messages}
    terminal = bool(codes & {194, 195, 209})
    # A stage is unavailable, not absent, when the enclosing NAS message carried a
    # ciphered payload and no ESM message was decoded from it.
    protected = any(
        event.get("ciphered_payload_present") is True for event in group.get("nas") or []
    ) and not esm_messages

    stages: list[dict[str, Any]] = []
    for stage_id in STAGE_ORDER:
        if stage_id == "s1-erab-setup":
            erab_messages = [
                event
                for event in s1ap_events
                if _context_tuple(event) == _context_key(context)
                and event.get("message_type") in S1AP_ERAB_MESSAGES
            ]
            erab_messages.sort(key=lambda event: int(event.get("frame_number") or 0))
            limitations: list[str] = []
            if erab_messages and not any(event.get("erab_items") for event in erab_messages):
                limitations.append(
                    "the S1AP message was observed but no item-scoped E-RAB evidence was available"
                )
            stage = _stage(
                stage_id,
                "OBSERVED" if erab_messages else ("INSUFFICIENT_EVIDENCE" if not terminal else "NOT_OBSERVED"),
                [
                    {
                        "protocol": "S1AP",
                        "frame_number": event.get("frame_number"),
                        "message_type": event.get("message_type"),
                        "result": S1AP_ERAB_MESSAGES.get(event.get("message_type")),
                        "erab_items": event.get("erab_items") or [],
                        "unbound_erab_evidence": event.get("unbound_erab_evidence"),
                        "evidence": event.get("evidence"),
                    }
                    for event in erab_messages
                ],
                limitations,
            )
            stages.append(stage)
            continue
        if stage_id == "supporting-gtpv2-session-control":
            stages.append(
                _stage(
                    stage_id,
                    "INSUFFICIENT_EVIDENCE",
                    [],
                    [
                        "no reviewed identity bridge links this UE context to a GTPv2-C session-control "
                        "subject, so supporting session control is not attributed"
                    ],
                )
            )
            continue
        wanted = STAGE_ESM_MESSAGES[stage_id]
        messages = [item for item in esm_messages if item.get("message_type_code") in wanted]
        status = _stage_status(stage_id, messages, protected=protected, terminal=terminal)
        stage_limitations: list[str] = []
        if status == "UNAVAILABLE_PROTECTED":
            stage_limitations.append(
                "the enclosing NAS message is security protected and no decoded ESM message is "
                "visible, so this stage is unavailable rather than absent"
            )
        stages.append(_stage(stage_id, status, [_esm_message_projection(item) for item in messages], stage_limitations))

    frames = [item.get("frame_number") for item in esm_messages]
    for stage in stages:
        if stage["first_frame"] is not None:
            frames.append(stage["first_frame"])
        if stage["last_frame"] is not None:
            frames.append(stage["last_frame"])
    window = _window(frames)

    outcomes = derive_outcomes(stages, protected=protected, terminal=terminal)
    deviations = _deviations_for({"instance_reference": group["instance_reference"]}, esm_messages, window)

    activation_request = next(item for item in esm_messages if item.get("message_type_code") == 193) if 193 in codes else None
    bearer_context = {
        "eps_bearer_identity": activation_request.get("eps_bearer_identity") if activation_request else None,
        "eps_bearer_identity_basis": "decoded_activate_default_bearer_context_header" if activation_request else None,
        "pdn_type": (activation_request.get("pdn_type") or {}).get("name") if activation_request else None,
        "apn_present": activation_request.get("apn_present") if activation_request else None,
        "apn_length": activation_request.get("apn_length") if activation_request else None,
        "pdn_address_present": activation_request.get("pdn_address_present") if activation_request else None,
        "pdn_address_family": activation_request.get("pdn_address_family") if activation_request else None,
        "qos_present": activation_request.get("qos_present") if activation_request else None,
        "pco_present": activation_request.get("pco_present") if activation_request else None,
    }

    erab_items = [
        item
        for stage in stages
        if stage["stage_id"] == "s1-erab-setup"
        for message in stage["messages"]
        for item in message.get("erab_items") or []
    ]

    limitations: list[str] = []
    if group["association_strength"] != "STRONG":
        limitations.append(
            "the S1AP UE context is resolved without a complete identifier pair; the association "
            "strength reflects that"
        )
    if any(item.get("apn_present") for item in esm_messages):
        limitations.append("only APN presence and length are published; the APN name is never retained")
    if any(item.get("pdn_address_present") for item in esm_messages):
        limitations.append(
            "only PDN address presence and family are published; the assigned address is never retained"
        )
    if "PDN_CONNECTIVITY_REQUEST_OBSERVED" in outcomes and "DEFAULT_BEARER_ACTIVATION_ACCEPT_OBSERVED" in outcomes:
        limitations.append(
            "the observed ESM accept is protocol-level evidence; it does not prove that the default "
            "bearer carries user traffic"
        )

    additional: list[str] = []
    if not erab_items:
        additional.append(
            "an S1AP Initial Context Setup message with item-scoped E-RAB evidence is required to "
            "relate this ESM bearer context to an S1-U tunnel endpoint"
        )
    if "PROTECTED_ESM_UNAVAILABLE" in outcomes:
        additional.append(
            "a capture with readable ESM content is required to observe the default bearer activation"
        )

    instance: dict[str, Any] = {
        "instance_reference": group["instance_reference"],
        "procedure": PROCEDURE,
        "ue_context": context,
        "association_basis": group["association_basis"],
        "association_strength": group["association_strength"],
        "attach_link": _attach_link(context, attach_index),
        "stages": stages,
        "outcomes": outcomes,
        "bearer_context": bearer_context,
        "erab_items": erab_items,
        "esm_message_count": len(esm_messages),
        "deviations": deviations,
        "observation_window": window,
        "evidence_refs": _esm_refs(esm_messages)[:MAX_EVIDENCE_REFERENCES],
        "limitations": limitations,
        "additional_evidence_needed": additional,
    }
    return instance


def derive_outcomes(stages: list[dict[str, Any]], *, protected: bool, terminal: bool) -> list[str]:
    by_stage = {stage["stage_id"]: stage for stage in stages}
    outcomes: list[str] = []
    if by_stage["pdn-connectivity-request"]["status"] == "OBSERVED":
        outcomes.append("PDN_CONNECTIVITY_REQUEST_OBSERVED")
    if by_stage["default-bearer-activation-request"]["status"] == "OBSERVED":
        outcomes.append("DEFAULT_BEARER_ACTIVATION_REQUEST_OBSERVED")
    if by_stage["default-bearer-activation-response"]["status"] == "OBSERVED":
        codes = {
            message.get("message_type_code")
            for message in by_stage["default-bearer-activation-response"]["messages"]
        }
        if 194 in codes:
            outcomes.append("DEFAULT_BEARER_ACTIVATION_ACCEPT_OBSERVED")
        if 195 in codes:
            outcomes.append("DEFAULT_BEARER_ACTIVATION_REJECT_OBSERVED")
    if by_stage["s1-erab-setup"]["status"] == "OBSERVED":
        results = {
            message.get("result") for message in by_stage["s1-erab-setup"]["messages"] if message.get("erab_items")
        }
        if "REQUEST" in results:
            outcomes.append("S1_ERAB_SETUP_REQUEST_OBSERVED")
        if "RESPONSE" in results:
            outcomes.append("S1_ERAB_SETUP_RESPONSE_OBSERVED")
    for stage in stages:
        if stage["stage_id"] != "pdn-connectivity-request":
            continue
        codes = {message.get("message_type_code") for message in stage["messages"]}
        if 209 in codes:
            outcomes.append("PDN_CONNECTIVITY_REJECT_OBSERVED")
    if protected and not outcomes:
        outcomes.append("PROTECTED_ESM_UNAVAILABLE")
    if (
        "PDN_CONNECTIVITY_REQUEST_OBSERVED" in outcomes
        and "DEFAULT_BEARER_ACTIVATION_ACCEPT_OBSERVED" not in outcomes
        and "DEFAULT_BEARER_ACTIVATION_REJECT_OBSERVED" not in outcomes
        and "PDN_CONNECTIVITY_REJECT_OBSERVED" not in outcomes
        and "PROTECTED_ESM_UNAVAILABLE" not in outcomes
    ):
        outcomes.append("DEFAULT_BEARER_SIGNALING_INCOMPLETE")
    return outcomes


def build_unbound_instance(unbound: list[dict[str, Any]]) -> dict[str, Any]:
    capture = unbound[0].get("capture_file") if unbound else None
    reference = unbound_reference(str(capture))
    frames = [item.get("frame_number") for item in unbound]
    window = _window(frames)
    return {
        "instance_reference": reference,
        "procedure": PROCEDURE,
        "ue_context": {
            "capture_file": capture,
            "sctp_association": None,
            "enb_ue_s1ap_id": None,
            "mme_ue_s1ap_id": None,
        },
        "association_basis": "no_enclosing_s1ap_ue_context:UNBOUND",
        "association_strength": "UNBOUND",
        "attach_link": {
            "status": "NOT_ESTABLISHED",
            "target_subject_reference": None,
            "link_basis": "no_s1ap_ue_context",
            "supporting_identifiers": [],
            "limitations": [
                "the ESM evidence carries no enclosing S1AP UE context, so it is published "
                "without a bearer subject"
            ],
        },
        "stages": [
            _stage(
                stage_id,
                "INSUFFICIENT_EVIDENCE",
                [],
                ["the ESM evidence of this capture is not bound to an S1AP UE context"],
            )
            for stage_id in STAGE_ORDER
        ],
        "outcomes": [],
        "bearer_context": {
            "eps_bearer_identity": None,
            "eps_bearer_identity_basis": None,
            "pdn_type": None,
            "apn_present": None,
            "apn_length": None,
            "pdn_address_present": None,
            "pdn_address_family": None,
            "qos_present": None,
            "pco_present": None,
        },
        "erab_items": [],
        "esm_message_count": 0,
        "deviations": [
            {
                "deviation_type": DEVIATION_ESM_UNBOUND,
                "instance_reference": reference,
                "protocol": "NAS-EPS",
                "message_type": item.get("message_type"),
                "frame_number": item.get("frame_number"),
                "esm_cause_code": None,
                "esm_cause_name": None,
                "eps_bearer_identity": None,
                "evidence_level": "OBSERVED",
                "evidence_refs": [_evidence_ref("NAS-EPS", item.get("frame_number"), item.get("message_type"))],
                "observation_window": window,
                "limitations": [str(item.get("reason"))],
            }
            for item in unbound[:MAX_LIST_ITEMS]
        ],
        "observation_window": window,
        "evidence_refs": [_evidence_ref("NAS-EPS", item.get("frame_number"), item.get("message_type")) for item in unbound][
            :MAX_EVIDENCE_REFERENCES
        ],
        "limitations": [
            "no enclosing S1AP UE context was provable for this ESM evidence, so no default-bearer "
            "instance is asserted"
        ],
        "additional_evidence_needed": [
            "an S1AP NAS transport message on the same frame is required to bind this ESM evidence "
            "to a UE context"
        ],
    }


def _gtpv2_endpoint_index(gtpv2_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flattened GTPv2-C F-TEID evidence with its scope and owning frame."""
    entries: list[dict[str, Any]] = []
    for event in gtpv2_events:
        capture = str(event.get("capture_file"))
        family = event.get("procedure_family")
        for item in event.get("f_teids") or []:
            if not isinstance(item, dict):
                continue
            entries.append(
                {
                    "event": event,
                    "capture_file": capture,
                    "procedure_family": family,
                    "scope": "message",
                    "interface_type": item.get("interface_type"),
                    "teid": item.get("teid"),
                    "ipv4": item.get("ipv4"),
                    "ebi": None,
                }
            )
        for context in event.get("bearer_contexts") or []:
            if not isinstance(context, dict):
                continue
            for item in context.get("f_teids") or []:
                if not isinstance(item, dict):
                    continue
                entries.append(
                    {
                        "event": event,
                        "capture_file": capture,
                        "procedure_family": family,
                        "scope": "bearer",
                        "interface_type": item.get("interface_type"),
                        "teid": item.get("teid"),
                        "ipv4": item.get("ipv4"),
                        "ebi": context.get("ebi"),
                    }
                )
    return entries


def tunnel_links(
    instances: list[dict[str, Any]], gtpv2_events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Relate S1AP E-RAB tunnel endpoints to GTPv2-C S1-U F-TEID evidence.

    The only accepted basis is exact equality of the S1-U transport layer address
    and the S1-U GTP-TEID with a reviewed S1-U interface type, inside one capture.
    No E-RAB identity is ever equated with an EPS bearer identity, and no
    transport address alone establishes a relationship.
    """
    entries = _gtpv2_endpoint_index(gtpv2_events)
    links: list[dict[str, Any]] = []
    for instance in instances:
        capture = instance.get("ue_context", {}).get("capture_file")
        for item in instance.get("erab_items") or []:
            address = item.get("transport_layer_address")
            teid = item.get("gtp_teid")
            if not address or teid is None:
                continue
            candidates = [
                entry
                for entry in entries
                if entry["capture_file"] == str(capture)
                and entry["interface_type"] in S1U_INTERFACE_TYPES
                and entry["ipv4"] == address
                and entry["teid"] == teid
                and entry["procedure_family"] in REVIEWED_GTPV2_FAMILIES
            ]
            base = {
                "link_type": "s1ap_erab_to_gtpv2_bearer",
                "source_subject_reference": instance.get("instance_reference"),
                "source_frame": item.get("frame_number"),
                "s1ap_message_type": None,
                "s1u_transport_layer_address": address,
                "s1u_gtp_teid": teid,
                "supporting_identifiers": [
                    {"identifier": "s1u_transport_layer_address", "value": address},
                    {"identifier": "s1u_gtp_teid", "value": teid},
                    {"identifier": "f_teid_interface_type", "value": sorted(S1U_INTERFACE_TYPES)},
                ],
            }
            if not candidates:
                links.append(
                    {
                        **base,
                        "status": "NOT_ESTABLISHED",
                        "target_subject_reference": None,
                        "link_basis": "no_gtpv2_s1u_f_teid_matches_this_endpoint",
                        "evidence_refs": [
                            _evidence_ref("S1AP", item.get("frame_number"), None),
                        ],
                        "association_strength": "NOT_ESTABLISHED",
                        "limitations": [
                            "no observed GTPv2-C S1-U F-TEID carries this transport layer address "
                            "and GTP-TEID in this capture"
                        ],
                    }
                )
                continue
            if len(candidates) > 1:
                links.append(
                    {
                        **base,
                        "status": "AMBIGUOUS",
                        "target_subject_reference": None,
                        "link_basis": "several_gtpv2_s1u_f_teids_match_this_endpoint",
                        "evidence_refs": [
                            _evidence_ref("S1AP", item.get("frame_number"), None)
                        ]
                        + [
                            _evidence_ref("GTPv2-C", entry["event"].get("frame_number"), entry["event"].get("message_type"))
                            for entry in candidates[:MAX_EVIDENCE_REFERENCES]
                        ],
                        "association_strength": "AMBIGUOUS",
                        "limitations": [
                            "more than one observed GTPv2-C message publishes this S1-U endpoint, so "
                            "no single transaction is selected"
                        ],
                    }
                )
                continue
            entry = candidates[0]
            event = entry["event"]
            links.append(
                {
                    **base,
                    "status": "SUPPORTED",
                    "target_subject_reference": f"gtpv2-frame:{event.get('frame_number')}",
                    "target_frame": event.get("frame_number"),
                    "target_message_type": event.get("message_type"),
                    "target_eps_bearer_identity": entry.get("ebi"),
                    "target_scope": entry.get("scope"),
                    "link_basis": "exact_s1u_endpoint_equality_with_reviewed_interface_type",
                    "evidence_refs": [
                        _evidence_ref("S1AP", item.get("frame_number"), None),
                        _evidence_ref("GTPv2-C", event.get("frame_number"), event.get("message_type")),
                    ],
                    "association_strength": "SUPPORTED",
                    "ordering": (
                        "gtpv2_precedes_s1ap"
                        if int(event.get("frame_number") or 0) < int(item.get("frame_number") or 0)
                        else "s1ap_precedes_gtpv2"
                    ),
                    "limitations": [
                        "the E-RAB identity and the EPS bearer identity are different identifiers and "
                        "are never equated",
                        "endpoint equality is control-plane provisioning evidence, not proof that a "
                        "GTP-U tunnel forwards traffic",
                    ],
                }
            )
    return links


def _link_esm_to_context(instance: dict[str, Any]) -> dict[str, Any]:
    return {
        "link_type": "esm_to_s1ap_ue_context",
        "status": "ESTABLISHED" if instance.get("association_strength") in ("STRONG", "SUPPORTED") else "AMBIGUOUS",
        "source_subject_reference": instance.get("instance_reference"),
        "target_subject_reference": "s1ap-ue-context:" + str(instance.get("ue_context", {}).get("enb_ue_s1ap_id")),
        "link_basis": "same_capture_same_frame_s1ap_nas_pdu",
        "supporting_identifiers": [
            {"identifier": "enb_ue_s1ap_id", "value": instance.get("ue_context", {}).get("enb_ue_s1ap_id")},
            {"identifier": "mme_ue_s1ap_id", "value": instance.get("ue_context", {}).get("mme_ue_s1ap_id")},
            {"identifier": "sctp_association", "value": instance.get("ue_context", {}).get("sctp_association")},
        ],
        "evidence_refs": instance.get("evidence_refs") or [],
        "association_strength": instance.get("association_strength"),
        "limitations": [
            "the binding uses capture identity, frame number and S1AP NAS-PDU presence only; "
            "timestamp proximity is never used"
        ],
    }


def analyze(
    nas_events: list[dict[str, Any]],
    s1ap_events: list[dict[str, Any]],
    attach_analysis: dict[str, Any] | None = None,
    session_analysis: dict[str, Any] | None = None,
    gtpv2_events: list[dict[str, Any]] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reconstruct bounded default-bearer evidence from accepted lower-layer output."""
    gtpv2_events = gtpv2_events or []
    instances, unbound, ambiguous_frames = group_instances(nas_events, s1ap_events, attach_analysis)

    links = tunnel_links(instances, gtpv2_events)
    by_instance: dict[str, list[dict[str, Any]]] = {}
    for link in links:
        by_instance.setdefault(str(link.get("source_subject_reference")), []).append(link)

    for instance in instances:
        instance_links = by_instance.get(instance["instance_reference"], [])
        established = [link for link in instance_links if link["status"] == "SUPPORTED"]
        instance["tunnel_links"] = instance_links
        for stage in instance["stages"]:
            if stage["stage_id"] != "supporting-gtpv2-session-control":
                continue
            if established:
                stage["status"] = "OBSERVED"
                stage["message_count"] = len(established)
                stage["messages"] = [
                    {
                        "protocol": "GTPv2-C",
                        "frame_number": link.get("target_frame"),
                        "message_type": link.get("target_message_type"),
                        "eps_bearer_identity": link.get("target_eps_bearer_identity"),
                        "link_status": link["status"],
                    }
                    for link in established
                ]
                frames = [link.get("target_frame") for link in established if link.get("target_frame")]
                stage["first_frame"] = min(frames)
                stage["last_frame"] = max(frames)
                stage["limitations"] = [
                    "the S1-U endpoint equality links the S1AP E-RAB item to a GTPv2-C message; it "
                    "does not link the UE context to a session-control subject"
                ]

    established_links: list[dict[str, Any]] = []
    ambiguous_links: list[dict[str, Any]] = []
    unbound_links: list[dict[str, Any]] = []
    for instance in instances:
        if instance["association_strength"] in ("STRONG", "SUPPORTED", "AMBIGUOUS"):
            context_link = _link_esm_to_context(instance)
            (established_links if context_link["status"] == "ESTABLISHED" else ambiguous_links).append(context_link)
        attach_link = instance.get("attach_link") or {}
        if attach_link.get("status") == "ESTABLISHED":
            established_links.append(
                {
                    "link_type": "esm_to_eps_attach",
                    "status": "ESTABLISHED",
                    "source_subject_reference": instance["instance_reference"],
                    "target_subject_reference": attach_link.get("target_subject_reference"),
                    "link_basis": attach_link.get("link_basis"),
                    "supporting_identifiers": attach_link.get("supporting_identifiers") or [],
                    "evidence_refs": instance.get("evidence_refs") or [],
                    "association_strength": "ESTABLISHED",
                    "limitations": attach_link.get("limitations") or [],
                }
            )
        elif attach_link.get("status") == "AMBIGUOUS":
            ambiguous_links.append(
                {
                    "link_type": "esm_to_eps_attach",
                    "status": "AMBIGUOUS",
                    "source_subject_reference": instance["instance_reference"],
                    "target_subject_reference": None,
                    "link_basis": attach_link.get("link_basis"),
                    "supporting_identifiers": [],
                    "evidence_refs": instance.get("evidence_refs") or [],
                    "association_strength": "AMBIGUOUS",
                    "limitations": attach_link.get("limitations") or [],
                }
            )
    for link in links:
        if link["status"] == "SUPPORTED":
            established_links.append(link)
        elif link["status"] == "AMBIGUOUS":
            ambiguous_links.append(link)
        else:
            unbound_links.append(link)

    deviations: list[dict[str, Any]] = []
    for instance in instances:
        deviations.extend(instance.get("deviations") or [])
    for event in s1ap_events:
        if event.get("unbound_erab_evidence") and event.get("message_type") in S1AP_ERAB_MESSAGES:
            deviations.append(
                {
                    "deviation_type": DEVIATION_ERAB_UNBOUND,
                    "instance_reference": None,
                    "protocol": "S1AP",
                    "message_type": event.get("message_type"),
                    "frame_number": event.get("frame_number"),
                    "esm_cause_code": None,
                    "esm_cause_name": None,
                    "eps_bearer_identity": None,
                    "evidence_level": "OBSERVED",
                    "evidence_refs": [_evidence_ref("S1AP", event.get("frame_number"), event.get("message_type"))],
                    "observation_window": _window([event.get("frame_number")]),
                    "limitations": [event["unbound_erab_evidence"].get("reason")],
                }
            )
    for link in links:
        if link["status"] != "AMBIGUOUS":
            continue
        deviations.append(
            {
                "deviation_type": DEVIATION_TUNNEL_AMBIGUOUS,
                "instance_reference": link.get("source_subject_reference"),
                "protocol": "GTPv2-C",
                "message_type": None,
                "frame_number": link.get("source_frame"),
                "esm_cause_code": None,
                "esm_cause_name": None,
                "eps_bearer_identity": None,
                "evidence_level": "OBSERVED",
                "evidence_refs": link.get("evidence_refs") or [],
                "observation_window": _window([link.get("source_frame")]),
                "limitations": link.get("limitations") or [],
            }
        )
    deviations.sort(
        key=lambda item: (
            int(item.get("frame_number") or 0),
            str(item.get("deviation_type")),
            str(item.get("instance_reference")),
        )
    )

    esm_observations: list[dict[str, Any]] = []
    for instance in instances:
        for stage in instance["stages"]:
            for message in stage["messages"]:
                if message.get("protocol") != "NAS-EPS":
                    continue
                esm_observations.append(
                    {
                        **message,
                        "instance_reference": instance["instance_reference"],
                        "stage_id": stage["stage_id"],
                    }
                )
    esm_observations.sort(key=lambda item: (int(item.get("frame_number") or 0), int(item.get("occurrence_index") or 0)))

    s1_erab_observations: list[dict[str, Any]] = []
    for event in s1ap_events:
        if event.get("message_type") not in S1AP_ERAB_MESSAGES:
            continue
        s1_erab_observations.append(
            {
                "protocol": "S1AP",
                "frame_number": event.get("frame_number"),
                "message_type": event.get("message_type"),
                "result": S1AP_ERAB_MESSAGES.get(event.get("message_type")),
                "enb_ue_s1ap_id": event.get("enb_ue_s1ap_id"),
                "mme_ue_s1ap_id": event.get("mme_ue_s1ap_id"),
                "erab_items": event.get("erab_items") or [],
                "unbound_erab_evidence": event.get("unbound_erab_evidence"),
                "evidence": event.get("evidence"),
            }
        )

    gtpv2_supporting: list[dict[str, Any]] = []
    for entry in _gtpv2_endpoint_index(gtpv2_events):
        if entry["interface_type"] not in S1U_INTERFACE_TYPES:
            continue
        gtpv2_supporting.append(
            {
                "protocol": "GTPv2-C",
                "frame_number": entry["event"].get("frame_number"),
                "message_type": entry["event"].get("message_type"),
                "procedure_family": entry.get("procedure_family"),
                "scope": entry.get("scope"),
                "interface_type": entry.get("interface_type"),
                "teid": entry.get("teid"),
                "transport_layer_address": entry.get("ipv4"),
                "eps_bearer_identity": entry.get("ebi"),
            }
        )

    limitations: list[str] = []
    if unbound:
        limitations.append(
            f"{len(unbound)} ESM observation(s) carry no provable enclosing S1AP UE context and are "
            "published without a default-bearer subject"
        )
    if ambiguous_frames:
        limitations.append(
            f"{len(ambiguous_frames)} frame(s) carry more than one S1AP message with a NAS-PDU, so their "
            "ESM evidence is not attributed to one UE context"
        )
    if not gtpv2_events:
        limitations.append(
            "no GTPv2-C event input was supplied, so no S1-U tunnel endpoint comparison was possible"
        )
    elif not gtpv2_supporting:
        limitations.append(
            "the supplied GTPv2-C events expose no S1-U F-TEID, so no tunnel endpoint comparison was possible"
        )
    if session_analysis is not None:
        limitations.append(
            "the EPC session-control subjects are recorded as provenance only; no reviewed identity "
            "bridge links this UE context to a session-control subject"
        )
    if any(
        message.get("apn_present") for instance in instances for message in instance.get("stages", []) for message in message.get("messages") or []
    ):
        limitations.append("only APN presence and length are published; the APN name is never retained")
    if any(link["status"] == "SUPPORTED" for link in links):
        limitations.append(
            "S1AP E-RAB and GTPv2-C S1-U endpoints are related by exact endpoint equality; no E-RAB "
            "identity is equated with an EPS bearer identity"
        )

    additional: list[str] = []
    for instance in instances:
        for item in instance.get("additional_evidence_needed") or []:
            if item not in additional:
                additional.append(item)
    if not any(instance.get("erab_items") for instance in instances):
        additional.append(
            "a capture with S1AP Initial Context Setup E-RAB items is required to relate the default "
            "bearer to an S1-U tunnel endpoint"
        )

    return {
        "domain": DOMAIN_NAME,
        "domain_version": DOMAIN_VERSION,
        "analysis_name": PROCEDURE,
        "analysis_version": MODEL_VERSION,
        "procedure": PROCEDURE,
        "procedure_label": PROCEDURE_LABEL,
        "analysis_scope": {
            "capability": "bounded EPS default-bearer signalling evidence",
            "stages": [
                {"stage_id": stage_id, "stage_label": STAGE_LABELS[stage_id], "conditional": stage_id in CONDITIONAL_STAGES}
                for stage_id in STAGE_ORDER
            ],
            "stage_status_vocabulary": list(STAGE_STATUSES),
            "outcome_vocabulary": list(OUTCOMES),
            "link_status_vocabulary": list(LINK_STATUSES),
            "supported_esm_messages": [193, 194, 195, 208, 209, 217, 218, 232],
            "input_contract": (
                "already-extracted NAS-EPS events, already-extracted S1AP events, the accepted EPS "
                "Attach analysis, the accepted EPC session-control analysis, and GTPv2-C events for "
                "exact S1-U endpoint identity only"
            ),
            "excluded": [
                "dedicated EPS bearers",
                "PDN disconnect lifecycle",
                "full ESM semantics and the ESM state machine",
                "user-plane delivery verification",
                "root-cause attribution",
                "S11 to S5/S8 session association",
                "Attach UE to GTPv2-C session association without a reviewed identity bridge",
            ],
        },
        "input_provenance": provenance or {},
        "instance_count": len(instances),
        "default_bearer_instances": instances,
        "esm_observations": esm_observations[:MAX_LIST_ITEMS],
        "esm_observation_count": len(esm_observations),
        "s1_erab_observations": s1_erab_observations[:MAX_LIST_ITEMS],
        "s1_erab_observation_count": len(s1_erab_observations),
        "gtpv2_supporting_evidence": gtpv2_supporting[:MAX_LIST_ITEMS],
        "gtpv2_supporting_evidence_count": len(gtpv2_supporting),
        "established_links": established_links[:MAX_LIST_ITEMS],
        "ambiguous_links": ambiguous_links[:MAX_LIST_ITEMS],
        "unbound_evidence": unbound_links[:MAX_LIST_ITEMS] + unbound[:MAX_LIST_ITEMS],
        "procedure_local_deviations": deviations[:MAX_LIST_ITEMS],
        "procedure_local_deviation_count": len(deviations),
        "procedure_local_deviations_omitted": max(0, len(deviations) - MAX_LIST_ITEMS),
        "evidence_limitations": limitations,
        "additional_evidence_needed": additional,
        "not_confirmed": list(NOT_CONFIRMED),
        "boundary_selection_status": "NOT_EVALUATED",
        "first_abnormal_boundary": None,
        "boundary_note": GLOBAL_BOUNDARY_NOTE,
    }
