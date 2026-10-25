#!/usr/bin/env python3
"""Shared, standalone helpers for bounded S1AP semantic extraction.

The protocol identity tables below were reviewed against the S1AP dissector of
Wireshark/TShark 4.7.1 (Git commit 667ab240e6de) through `tshark -G fields` and
`tshark -G values`, which implements 3GPP TS 36.413 procedure codes, PDU
categories and Cause vocabularies. Semantic support is intentionally bounded to
S1 setup, the UE-associated NAS transport messages, Initial Context Setup and
UE context release; every other known procedure code is reported as UNSUPPORTED
without invented semantics, and unknown codes as UNKNOWN.

No NAS-PDU payload is decoded or republished here: only presence and length are
retained. NAS semantics belong to the nas-eps Protocol Skill.

Timestamp normalization matches the core-network-pcap convention; the helper is
duplicated on purpose so this package stays standalone when other Skills are not
installed.
"""

from __future__ import annotations

import csv
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from pathlib import Path
from typing import Any, Iterable, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent))
import s1ap_erab

EXIT_TOOL_UNAVAILABLE = 3
EXIT_TSHARK_FAILURE = 4
EXIT_MALFORMED_INPUT = 5
EXIT_NO_EVENTS = 6
EXIT_OUTPUT_FAILURE = 7

SCHEMA_NAME = "s1ap-event"
PROTOCOL = "S1AP"
INTERFACE = "S1-MME"


@dataclass(frozen=True)
class FieldSpec:
    canonical_name: str
    tshark_candidates: tuple[str, ...]
    required: bool = False


FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "sctp.srcport",
    "sctp.dstport",
    "sctp.assoc_index",
    "_ws.col.Info",
    "s1ap.procedureCode",
    "s1ap.initiatingMessage_element",
    "s1ap.successfulOutcome_element",
    "s1ap.unsuccessfulOutcome_element",
    "s1ap.ENB_UE_S1AP_ID",
    "s1ap.MME_UE_S1AP_ID",
    "s1ap.Cause",
    "s1ap.radioNetwork",
    "s1ap.transport",
    "s1ap.nas",
    "s1ap.protocol",
    "s1ap.misc",
    "s1ap.NAS_PDU",
    "s1ap.TAC",
    "s1ap.PLMNidentity",
    "s1ap.EUTRAN_CGI_element",
    "s1ap.E_RABToBeSetupListCtxtSUReq",
    "s1ap.E_RABSetupListCtxtSURes",
    "s1ap.e_RAB_ID",
)

FIELD_SPECS: tuple[FieldSpec, ...] = tuple(
    FieldSpec(
        canonical_name=name,
        tshark_candidates=("_ws.col.Info", "_ws.col.info") if name == "_ws.col.Info" else (name,),
        required=name in {"frame.number", "frame.time_epoch", "s1ap.procedureCode"},
    )
    for name in FIELDS
)

FILTER_CANDIDATES: tuple[str, ...] = ("s1ap",)

PDU_INITIATING = "initiatingMessage"
PDU_SUCCESSFUL = "successfulOutcome"
PDU_UNSUCCESSFUL = "unsuccessfulOutcome"
PDU_TYPES = (PDU_INITIATING, PDU_SUCCESSFUL, PDU_UNSUCCESSFUL)

PDU_TYPE_FIELDS = {
    PDU_INITIATING: "s1ap.initiatingMessage_element",
    PDU_SUCCESSFUL: "s1ap.successfulOutcome_element",
    PDU_UNSUCCESSFUL: "s1ap.unsuccessfulOutcome_element",
}

# Reviewed TS 36.413 procedure code names, verified against the TShark 4.7.1
# value table for s1ap.procedureCode. Codes outside the bounded scope stay
# nameable but unsupported; an unlisted code is UNKNOWN.
KNOWN_PROCEDURES = {
    0: "id-HandoverPreparation",
    1: "id-HandoverResourceAllocation",
    2: "id-HandoverNotification",
    3: "id-PathSwitchRequest",
    4: "id-HandoverCancel",
    5: "id-E-RABSetup",
    6: "id-E-RABModify",
    7: "id-E-RABRelease",
    8: "id-E-RABReleaseIndication",
    9: "id-InitialContextSetup",
    10: "id-Paging",
    11: "id-downlinkNASTransport",
    12: "id-initialUEMessage",
    13: "id-uplinkNASTransport",
    14: "id-Reset",
    15: "id-ErrorIndication",
    16: "id-NASNonDeliveryIndication",
    17: "id-S1Setup",
    18: "id-UEContextReleaseRequest",
    19: "id-DownlinkS1cdma2000tunnelling",
    20: "id-UplinkS1cdma2000tunnelling",
    21: "id-UEContextModification",
    22: "id-UECapabilityInfoIndication",
    23: "id-UEContextRelease",
    24: "id-eNBStatusTransfer",
    25: "id-MMEStatusTransfer",
    26: "id-DeactivateTrace",
    27: "id-TraceStart",
    28: "id-TraceFailureIndication",
    29: "id-ENBConfigurationUpdate",
    30: "id-MMEConfigurationUpdate",
    31: "id-LocationReportingControl",
    32: "id-LocationReportingFailureIndication",
    33: "id-LocationReport",
    34: "id-OverloadStart",
    35: "id-OverloadStop",
    36: "id-WriteReplaceWarning",
    37: "id-eNBDirectInformationTransfer",
    38: "id-MMEDirectInformationTransfer",
    39: "id-PrivateMessage",
    40: "id-eNBConfigurationTransfer",
    41: "id-MMEConfigurationTransfer",
    42: "id-CellTrafficTrace",
    43: "id-Kill",
    44: "id-downlinkUEAssociatedLPPaTransport",
    45: "id-uplinkUEAssociatedLPPaTransport",
    46: "id-downlinkNonUEAssociatedLPPaTransport",
    47: "id-uplinkNonUEAssociatedLPPaTransport",
    48: "id-UERadioCapabilityMatch",
    49: "id-PWSRestartIndication",
    50: "id-E-RABModificationIndication",
    51: "id-PWSFailureIndication",
    52: "id-RerouteNASRequest",
    53: "id-UEContextModificationIndication",
    54: "id-ConnectionEstablishmentIndication",
    55: "id-UEContextSuspend",
    56: "id-UEContextResume",
    57: "id-NASDeliveryIndication",
    58: "id-RetrieveUEInformation",
    59: "id-UEInformationTransfer",
    60: "id-eNBCPRelocationIndication",
    61: "id-MMECPRelocationIndication",
    62: "id-SecondaryRATDataUsageReport",
    63: "id-UERadioCapabilityIDMapping",
    64: "id-HandoverSuccess",
}

# Bounded supported procedures: procedure code -> (name, {pdu type: message}).
SUPPORTED_PROCEDURES = {
    9: ("InitialContextSetup", {
        PDU_INITIATING: "InitialContextSetupRequest",
        PDU_SUCCESSFUL: "InitialContextSetupResponse",
        PDU_UNSUCCESSFUL: "InitialContextSetupFailure",
    }),
    11: ("downlinkNASTransport", {PDU_INITIATING: "DownlinkNASTransport"}),
    12: ("initialUEMessage", {PDU_INITIATING: "InitialUEMessage"}),
    13: ("uplinkNASTransport", {PDU_INITIATING: "UplinkNASTransport"}),
    17: ("S1Setup", {
        PDU_INITIATING: "S1SetupRequest",
        PDU_SUCCESSFUL: "S1SetupResponse",
        PDU_UNSUCCESSFUL: "S1SetupFailure",
    }),
    18: ("UEContextReleaseRequest", {PDU_INITIATING: "UEContextReleaseRequest"}),
    23: ("UEContextRelease", {
        PDU_INITIATING: "UEContextReleaseCommand",
        PDU_SUCCESSFUL: "UEContextReleaseComplete",
    }),
}

# Local normalized role labels (not 3GPP wire values): the observed message's
# position inside its elementary procedure.
MESSAGE_RESULTS = {
    "S1SetupRequest": "REQUEST",
    "S1SetupResponse": "SUCCESS",
    "S1SetupFailure": "FAILURE",
    "InitialUEMessage": "REQUEST",
    "UplinkNASTransport": "REQUEST",
    "DownlinkNASTransport": "REQUEST",
    "InitialContextSetupRequest": "REQUEST",
    "InitialContextSetupResponse": "SUCCESS",
    "InitialContextSetupFailure": "FAILURE",
    "UEContextReleaseRequest": "REQUEST",
    "UEContextReleaseCommand": "COMMAND",
    "UEContextReleaseComplete": "COMPLETE",
}

# TS 36.413 defines which signaling side sends each message. The role is derived
# from message identity only; endpoint addresses are never mapped to roles.
MESSAGE_SENDER_ROLES = {
    "S1SetupRequest": "enodeb",
    "S1SetupResponse": "mme",
    "S1SetupFailure": "mme",
    "InitialUEMessage": "enodeb",
    "UplinkNASTransport": "enodeb",
    "DownlinkNASTransport": "mme",
    "InitialContextSetupRequest": "mme",
    "InitialContextSetupResponse": "enodeb",
    "InitialContextSetupFailure": "enodeb",
    "UEContextReleaseRequest": "enodeb",
    "UEContextReleaseCommand": "mme",
    "UEContextReleaseComplete": "enodeb",
}

MESSAGE_TO_PDU_TYPE = {
    message: pdu_type
    for _, messages in SUPPORTED_PROCEDURES.values()
    for pdu_type, message in messages.items()
}

# Reviewed TS 36.413 Cause group alternatives, in dissector field order.
CAUSE_GROUPS = (
    ("radioNetwork", "s1ap.radioNetwork"),
    ("transport", "s1ap.transport"),
    ("nas", "s1ap.nas"),
    ("protocol", "s1ap.protocol"),
    ("misc", "s1ap.misc"),
)

E_RAB_LIST_FIELDS = {
    "s1ap.E_RABToBeSetupListCtxtSUReq": ("INITIAL_CONTEXT_SETUP", "REQUEST"),
    "s1ap.E_RABSetupListCtxtSURes": ("INITIAL_CONTEXT_SETUP", "SUCCESS"),
}

SUPPORT_STATUSES = ("SUPPORTED", "UNSUPPORTED", "UNKNOWN")

# Bounded extraction limitations that follow from the installed decoder rather
# than from the protocol. They are reported with the affected message instead of
# being silently dropped.
DECODER_LIMITATIONS = {
    "InitialContextSetupResponse": [
        "the installed decoder exposes no standalone failed-to-setup E-RAB list field, "
        "so item-level failed outcomes are not extracted"
    ],
}

_WORKSTATION_PATH = re.compile(r"[A-Za-z]:[\\/][^\s\"']*")
_POSIX_PATH = re.compile(r"(?:/[^\s\"'/]+){2,}")


class InputError(ValueError):
    """Raised when a supported structured input cannot be normalized."""


class ToolUnavailable(RuntimeError):
    """Raised when tshark is required but unavailable."""


class TsharkError(RuntimeError):
    """Raised when tshark cannot produce the requested fields."""


def safe_capture_name(path: Path) -> str:
    """Return a basename so outputs do not disclose workstation paths."""
    return path.name


def clean(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def first_token(value: object) -> str | None:
    """Return the first comma-joined occurrence of a repeated field."""
    text = clean(value)
    if text is None:
        return None
    return text.split(",")[0].strip() or None


def parse_int(value: object, field: str) -> int:
    text = clean(value)
    if text is None:
        raise InputError(f"{field} is required")
    try:
        return int(text, 10)
    except ValueError as exc:
        raise InputError(f"{field} must be an integer") from exc


def parse_number(value: object, field: str) -> int:
    """Parse an integer that may be exported as decimal or hexadecimal."""
    text = first_token(value)
    if text is None:
        raise InputError(f"{field} is required")
    try:
        return int(text, 0)
    except ValueError as exc:
        raise InputError(f"{field} must be an integer") from exc


def optional_int(value: object) -> int | None:
    text = first_token(value)
    if text is None:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def parse_port(value: object, field: str) -> int | None:
    text = clean(value)
    if text is None:
        return None
    try:
        port = int(text)
    except ValueError as exc:
        raise InputError(f"{field} must be an integer port") from exc
    if not 0 <= port <= 65535:
        raise InputError(f"{field} is outside the valid port range")
    return port


def normalize_timestamp(value: object) -> str:
    """Convert tshark epoch seconds to UTC ISO-8601 with microsecond precision."""
    text = clean(value)
    if text is None:
        raise InputError("frame.time_epoch is required")
    try:
        epoch = Decimal(text)
    except InvalidOperation as exc:
        raise InputError("frame.time_epoch is not a valid epoch timestamp") from exc
    if not epoch.is_finite():
        raise InputError("frame.time_epoch must be finite")
    microseconds = int((epoch * Decimal("1000000")).to_integral_value(rounding=ROUND_HALF_EVEN))
    try:
        instant = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)
    except OverflowError as exc:
        raise InputError("frame.time_epoch is outside the supported UTC range") from exc
    return instant.isoformat(timespec="microseconds").replace("+00:00", "Z")


def byte_length(raw: object) -> int | None:
    """Hex string length in bytes; the payload itself is never retained."""
    text = clean(raw)
    if text is None:
        return None
    compact = text.replace(":", "").replace(" ", "").replace(",", "")
    if not compact:
        return None
    if len(compact) % 2:
        compact = compact[:-1]
    return len(compact) // 2


def repeated_ints(value: object) -> list[int]:
    text = clean(value)
    if text is None:
        return []
    values: list[int] = []
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            values.append(int(token, 0))
        except ValueError:
            continue
    return values


def endpoint(record: dict[str, object], direction: str) -> dict[str, object] | None:
    address = clean(record.get(f"ip.{direction}")) or clean(record.get(f"ipv6.{direction}"))
    port = parse_port(record.get(f"sctp.{direction}port"), f"sctp.{direction}port")
    if address is None and port is None:
        return None
    return {"address": address, "port": port}


def sctp_metadata(record: dict[str, object]) -> dict[str, object] | None:
    association = optional_int(record.get("sctp.assoc_index"))
    stream = optional_int(record.get("sctp.data_sid"))
    if association is None and stream is None:
        return None
    payload: dict[str, object] = {}
    if association is not None:
        payload["association_id"] = association
    if stream is not None:
        payload["stream_id"] = stream
    return payload


def resolve_pdu_type(record: dict[str, object], observed_message: str | None) -> tuple[str | None, str]:
    """Determine the S1AP PDU category from dissector presence fields."""
    for pdu_type in PDU_TYPES:
        if first_token(record.get(PDU_TYPE_FIELDS[pdu_type])) is not None:
            return pdu_type, "presence_field"
    if observed_message is not None:
        for message, pdu_type in MESSAGE_TO_PDU_TYPE.items():
            if observed_message.split(",")[0].strip().startswith(message):
                return pdu_type, "info_column"
    return None, "unavailable"


def resolve_procedure(
    procedure_code: int,
    observed_message: str | None,
    pdu_type: str | None,
    pdu_type_basis: str,
) -> dict[str, object]:
    """Resolve procedure and message identity for one observed PDU."""
    if procedure_code in SUPPORTED_PROCEDURES:
        procedure_name, messages = SUPPORTED_PROCEDURES[procedure_code]
        message_type = messages.get(pdu_type) if pdu_type is not None else None
        if message_type is None and observed_message is not None:
            # The Info column may prefix SCTP chunk text, so the reviewed message
            # name is matched anywhere in the column rather than at its start.
            for candidate in messages.values():
                if candidate in observed_message:
                    message_type = candidate
                    break
        if message_type is None:
            return {
                "procedure_code": procedure_code,
                "procedure_name": procedure_name,
                "message_type": None,
                "support_status": "UNKNOWN",
                "result": None,
                "sender_role": None,
                "pdu_type": pdu_type,
                "pdu_type_basis": pdu_type_basis,
                "derivations": ["message identity unresolved for the observed PDU category"],
            }
        return {
            "procedure_code": procedure_code,
            "procedure_name": procedure_name,
            "message_type": message_type,
            "support_status": "SUPPORTED",
            "result": MESSAGE_RESULTS.get(message_type),
            "sender_role": MESSAGE_SENDER_ROLES.get(message_type),
            "pdu_type": pdu_type,
            "pdu_type_basis": pdu_type_basis,
            "derivations": [],
        }

    known_name = KNOWN_PROCEDURES.get(procedure_code)
    if known_name is None:
        return {
            "procedure_code": procedure_code,
            "procedure_name": None,
            "message_type": None,
            "support_status": "UNKNOWN",
            "result": None,
            "sender_role": None,
            "pdu_type": pdu_type,
            "pdu_type_basis": pdu_type_basis,
            "derivations": [f"procedure code {procedure_code} is not in the reviewed TS 36.413 table"],
        }
    return {
        "procedure_code": procedure_code,
        "procedure_name": known_name,
        "message_type": None,
        "support_status": "UNSUPPORTED",
        "result": None,
        "sender_role": None,
        "pdu_type": pdu_type,
        "pdu_type_basis": pdu_type_basis,
        "derivations": ["procedure outside the bounded S1AP semantic scope"],
    }


def observed_cause(record: dict[str, object]) -> dict[str, object] | None:
    """Return the S1AP Cause group and value, or None when no cause is present."""
    for category, field in CAUSE_GROUPS:
        value = first_token(record.get(field))
        if value is not None:
            try:
                numeric = int(value, 0)
            except ValueError:
                return {"category": category, "value": None}
            return {"category": category, "value": numeric}
    return None


def erab_items(
    record: dict[str, object], capture_file: str, frame_number: int
) -> list[dict[str, object]]:
    """Bounded E-RAB item evidence for the Initial Context Setup subset.

    Flat field input cannot prove an E-RAB item boundary, so the item list stays
    identity-only and every tunnel field stays unset. A capture is dissected to
    PDML separately and supplies the item-scoped evidence.
    """
    return s1ap_erab.flat_erab_items(record, capture_file, frame_number)


def context_key(capture: str, association: str, enb_id: int | None, mme_id: int | None) -> str:
    """Explicitly derived local context key; not a standardized S1AP identifier."""
    enb = f"e{enb_id}" if enb_id is not None else "e?"
    mme = f"m{mme_id}" if mme_id is not None else "m?"
    return f"s1ap-context:{capture}:{association}:{enb}:{mme}"


def association_key(event: dict[str, object]) -> tuple[str, str]:
    """Deterministic association context: capture identity plus SCTP context."""
    capture = str(event.get("capture_file") or "unknown-capture")
    sctp = event.get("sctp")
    if isinstance(sctp, dict) and sctp.get("association_id") is not None:
        return capture, f"sctp-assoc-{sctp['association_id']}"
    endpoints = []
    for role in ("source", "destination"):
        endpoint_data = event.get(role)
        if isinstance(endpoint_data, dict):
            endpoints.append(f"{endpoint_data.get('address')}:{endpoint_data.get('port')}")
    pair = "<->".join(sorted(endpoints)) if endpoints else "no-endpoints"
    return capture, f"endpoint-pair-{pair}"


def normalize_record(
    record: object,
    capture_file: str,
    erab_index: dict[int, list[dict[str, Any]]] | None = None,
    nas_frames: set[int] | None = None,
) -> dict[str, object]:
    """Project one structured S1AP observation into the detailed event."""
    if not isinstance(record, dict):
        raise InputError("structured S1AP record must be a JSON object")
    frame_number = parse_int(record.get("frame.number"), "frame.number")
    if frame_number < 1:
        raise InputError("frame.number must be at least 1")
    procedure_code = parse_number(record.get("s1ap.procedureCode"), "s1ap.procedureCode")
    if not 0 <= procedure_code <= 255:
        raise InputError("s1ap.procedureCode must be within 0..255")

    explicit_pdu_type = clean(record.get("pdu_type"))
    if explicit_pdu_type is not None and explicit_pdu_type not in PDU_TYPES:
        raise InputError("pdu_type must be one of initiatingMessage, successfulOutcome, unsuccessfulOutcome")

    timestamp = normalize_timestamp(record.get("frame.time_epoch"))
    observed_message = clean(record.get("_ws.col.Info")) or clean(record.get("_ws.col.info"))
    if explicit_pdu_type is not None:
        pdu_type, pdu_type_basis = explicit_pdu_type, "explicit"
    else:
        pdu_type, pdu_type_basis = resolve_pdu_type(record, observed_message)
    identity = resolve_procedure(procedure_code, observed_message, pdu_type, pdu_type_basis)

    enb_id = optional_int(record.get("s1ap.ENB_UE_S1AP_ID"))
    if first_token(record.get("s1ap.ENB_UE_S1AP_ID")) is not None and enb_id is None:
        raise InputError("s1ap.ENB_UE_S1AP_ID must be an integer")
    mme_id = optional_int(record.get("s1ap.MME_UE_S1AP_ID"))
    if first_token(record.get("s1ap.MME_UE_S1AP_ID")) is not None and mme_id is None:
        raise InputError("s1ap.MME_UE_S1AP_ID must be an integer")

    nas_length = byte_length(record.get("s1ap.NAS_PDU"))
    tac = optional_int(record.get("s1ap.TAC"))
    source = endpoint(record, "src")
    destination = endpoint(record, "dst")
    sctp = sctp_metadata(record)

    source_ref = f"capture:{capture_file}#frame={frame_number}; procedure-code={procedure_code}"
    if observed_message is not None:
        source_ref += f"; tshark-info={observed_message}"

    capture, association = association_key({
        "capture_file": capture_file,
        "sctp": sctp,
        "source": source,
        "destination": destination,
    })
    event: dict[str, object] = {
        "timestamp": timestamp,
        "frame_number": frame_number,
        "capture_file": capture_file,
        "pdu_type": identity["pdu_type"],
        "pdu_type_basis": identity["pdu_type_basis"],
        "procedure_code": identity["procedure_code"],
        "procedure_name": identity["procedure_name"],
        "message_type": identity["message_type"],
        "support_status": identity["support_status"],
        "result": identity["result"],
        "sender_role": identity["sender_role"],
        "enb_ue_s1ap_id": enb_id,
        "mme_ue_s1ap_id": mme_id,
        "cause": observed_cause(record),
        "nas_pdu_present": nas_length is not None,
        "nas_pdu_length": nas_length,
        # An Initial Context Setup Request carries its NAS-PDU inside the E-RAB
        # item, so a message-level NAS-PDU field is absent even though the
        # message does carry NAS. The two facts are published separately.
        "nas_pdu_embedded": (frame_number in nas_frames) if nas_frames is not None else None,
        "nas_pdu_embedded_basis": (
            "pdml_nested_nas_layer" if nas_frames is not None else "unavailable"
        ),
        "tac": tac,
        "plmn_identity_present": first_token(record.get("s1ap.PLMNidentity")) is not None,
        "eutran_cgi_present": first_token(record.get("s1ap.EUTRAN_CGI_element")) is not None,
        "context_key": context_key(capture, association, enb_id, mme_id),
        "evidence": {"level": "OBSERVED", "source": source_ref},
        "derivations": list(identity["derivations"]),
    }
    if erab_index is not None:
        items = [dict(item) for item in erab_index.get(frame_number, [])]
        if items:
            event["erab_items"] = items
        else:
            unbound = s1ap_erab.unbound_erab_evidence(record)
            if unbound is not None:
                unbound["reason"] = (
                    "the dissector tree exposed no E-RAB item node for this message, so the "
                    "E-RAB list presence is published without item-scoped evidence"
                )
                event["unbound_erab_evidence"] = unbound
    else:
        items = erab_items(record, capture_file, frame_number)
        if items:
            event["erab_items"] = items
        unbound = s1ap_erab.unbound_erab_evidence(record)
        if unbound is not None:
            event["unbound_erab_evidence"] = unbound
    message_name = identity.get("message_type")
    if isinstance(message_name, str) and message_name in DECODER_LIMITATIONS:
        event["extraction_limitations"] = list(DECODER_LIMITATIONS[message_name])
    if source is not None:
        event["source"] = source
    if destination is not None:
        event["destination"] = destination
    if sctp is not None:
        event["sctp"] = sctp
    return event


def project_trace_event(event: dict[str, object]) -> dict[str, object]:
    """Project a detailed S1AP event into the shared trace-event contract.

    S1AP UE identifiers stay in the detailed event; they are never written into
    unrelated generic fields.
    """
    projected: dict[str, object] = {
        "timestamp": event["timestamp"],
        "protocol": PROTOCOL,
        "interface": INTERFACE,
        "procedure": event.get("procedure_name"),
        "message_type": event.get("message_type"),
        "packet": {"frame_number": event["frame_number"], "capture_file": event["capture_file"]},
        "evidence": {
            "level": "DERIVED",
            "source": f"s1ap-event:{event['capture_file']}#frame={event['frame_number']}",
        },
    }
    for role in ("source", "destination"):
        if event.get(role) is not None:
            projected[role] = event[role]
    sctp = event.get("sctp")
    if isinstance(sctp, dict) and sctp.get("stream_id") is not None:
        projected["correlation"] = {"stream_id": str(sctp["stream_id"])}
    cause = event.get("cause")
    if isinstance(cause, dict):
        cause_text = None
        if cause.get("category") is not None:
            cause_text = (
                f"{cause['category']}:{cause['value']}"
                if cause.get("value") is not None
                else str(cause["category"])
            )
        code = cause.get("value") if isinstance(cause.get("value"), int) else None
        projected["result"] = {"status": event.get("result"), "cause": cause_text, "code": code}
    elif event.get("result") is not None:
        projected["result"] = {"status": event.get("result"), "cause": None, "code": None}
    return projected


def build_correlation(events: list[dict[str, object]]) -> dict[str, object]:
    """Summarize UE-context evidence with explicit strength and ambiguity.

    Contexts are formed only from capture provenance, the scoped SCTP
    association and the S1AP UE identifiers themselves. Timestamp proximity is
    never used, and an E-RAB identifier is never treated as a UE identity.
    """
    contexts: dict[str, dict[str, object]] = {}
    for event in events:
        key = str(event.get("context_key"))
        record = contexts.setdefault(key, {
            "context_key": key,
            "capture_file": event.get("capture_file"),
            "association": association_key(event)[1],
            "enb_ue_s1ap_id": event.get("enb_ue_s1ap_id"),
            "mme_ue_s1ap_id": event.get("mme_ue_s1ap_id"),
            "frame_numbers": [],
            "message_count": 0,
            "messages": [],
        })
        frames = record["frame_numbers"]
        if isinstance(frames, list):
            frames.append(event.get("frame_number"))
        record["message_count"] = int(record["message_count"]) + 1
        messages = record["messages"]
        if isinstance(messages, list) and event.get("message_type") is not None:
            label = str(event["message_type"])
            if label not in messages:
                messages.append(label)

    enb_to_mme: dict[tuple[object, object, object], set[int]] = {}
    mme_to_enb: dict[tuple[object, object, object], set[int]] = {}
    for record in contexts.values():
        base = (record.get("capture_file"), record.get("association"))
        enb = record.get("enb_ue_s1ap_id")
        mme = record.get("mme_ue_s1ap_id")
        if isinstance(enb, int) and isinstance(mme, int):
            enb_to_mme.setdefault(base + (enb,), set()).add(mme)
            mme_to_enb.setdefault(base + (mme,), set()).add(enb)

    summaries: list[dict[str, object]] = []
    for key in sorted(contexts):
        record = contexts[key]
        reasons: list[str] = []
        enb = record.get("enb_ue_s1ap_id")
        mme = record.get("mme_ue_s1ap_id")
        base = (record.get("capture_file"), record.get("association"))
        if isinstance(enb, int) and isinstance(mme, int):
            if len(enb_to_mme.get(base + (enb,), set())) > 1:
                reasons.append("one eNB-UE-S1AP-ID observed with multiple MME-UE-S1AP-ID values in this association")
            if len(mme_to_enb.get(base + (mme,), set())) > 1:
                reasons.append("one MME-UE-S1AP-ID observed with multiple eNB-UE-S1AP-ID values in this association")
        if isinstance(enb, int) and isinstance(mme, int):
            strength = "STRONG"
        elif isinstance(enb, int) or isinstance(mme, int):
            strength = "SUPPORTED"
        else:
            strength = "UNBOUND"
        if reasons:
            strength = "AMBIGUOUS"
        frames = [frame for frame in record.get("frame_numbers", []) if isinstance(frame, int)]
        summaries.append({
            "context_key": key,
            "capture_file": record.get("capture_file"),
            "association": record.get("association"),
            "enb_ue_s1ap_id": enb,
            "mme_ue_s1ap_id": mme,
            "message_count": record.get("message_count"),
            "first_frame": min(frames) if frames else None,
            "last_frame": max(frames) if frames else None,
            "messages": record.get("messages"),
            "strength": strength,
            "ambiguity_reasons": reasons,
        })
    return {
        "capture_file": events[0].get("capture_file") if events else None,
        "event_count": len(events),
        "context_count": len(summaries),
        "contexts": summaries,
        "rules": [
            "contexts are scoped by capture file and SCTP association",
            "an E-RAB identifier is never used as a UE identity",
            "timestamp proximity is never used to merge contexts",
            "an event observed before the MME-UE-S1AP-ID is assigned keeps its own context; "
            "identifiers are never inferred",
        ],
    }


def read_jsonl(path: Path) -> Iterator[dict[str, object]]:
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON Lines record at line {line_number}: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise InputError(f"JSON Lines record at line {line_number} is not an object")
            yield record


def resolve_tshark_executable() -> str:
    found = shutil.which("tshark")
    if found:
        return found
    if sys.platform == "win32":
        for candidate in (
            r"D:\Wireshark\tshark.exe",
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ):
            if Path(candidate).is_file():
                return candidate
    return "tshark"


_AVAILABLE_FIELDS_OVERRIDE: set[str] | None = None
_AVAILABLE_PROTOCOLS_OVERRIDE: set[str] | None = None
_AVAILABLE_FIELDS_CACHE: set[str] | None = None
_AVAILABLE_PROTOCOLS_CACHE: set[str] | None = None


def set_discovery_overrides(
    fields: set[str] | None = None, protocols: set[str] | None = None
) -> None:
    global _AVAILABLE_FIELDS_OVERRIDE, _AVAILABLE_PROTOCOLS_OVERRIDE
    _AVAILABLE_FIELDS_OVERRIDE = fields
    _AVAILABLE_PROTOCOLS_OVERRIDE = protocols


def get_available_fields(tshark_bin: str | None = None) -> set[str] | None:
    if _AVAILABLE_FIELDS_OVERRIDE is not None:
        return _AVAILABLE_FIELDS_OVERRIDE
    global _AVAILABLE_FIELDS_CACHE
    if _AVAILABLE_FIELDS_CACHE is not None:
        return _AVAILABLE_FIELDS_CACHE
    exe = tshark_bin or resolve_tshark_executable()
    try:
        proc = subprocess.run(
            [exe, "-G", "fields"], capture_output=True, encoding="utf-8", errors="replace", check=False
        )
        if proc.returncode == 0 and proc.stdout:
            fields = set()
            for line in proc.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3:
                    fields.add(parts[2])
            _AVAILABLE_FIELDS_CACHE = fields
            return fields
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def get_available_protocols(tshark_bin: str | None = None) -> set[str] | None:
    if _AVAILABLE_PROTOCOLS_OVERRIDE is not None:
        return _AVAILABLE_PROTOCOLS_OVERRIDE
    global _AVAILABLE_PROTOCOLS_CACHE
    if _AVAILABLE_PROTOCOLS_CACHE is not None:
        return _AVAILABLE_PROTOCOLS_CACHE
    exe = tshark_bin or resolve_tshark_executable()
    try:
        proc = subprocess.run(
            [exe, "-G", "protocols"], capture_output=True, encoding="utf-8", errors="replace", check=False
        )
        if proc.returncode == 0 and proc.stdout:
            protocols = set()
            for line in proc.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3:
                    protocols.add(parts[2].strip())
            _AVAILABLE_PROTOCOLS_CACHE = protocols
            return protocols
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def resolve_filter(candidates: tuple[str, ...], available_protocols: set[str] | None) -> str:
    if available_protocols is not None:
        for cand in candidates:
            if cand in available_protocols:
                return cand
        raise TsharkError(
            f"tshark compatibility error: none of the protocol filter candidates {candidates} "
            "are supported by installed TShark"
        )
    return candidates[0]


def resolve_field_specs(
    specs: tuple[FieldSpec, ...], available_fields: set[str] | None, tshark_ver: str
) -> tuple[list[tuple[str, str]], list[str]]:
    resolved_mappings: list[tuple[str, str]] = []
    unresolved_optional: list[str] = []
    for spec in specs:
        resolved_field: str | None = None
        if available_fields is not None:
            for cand in spec.tshark_candidates:
                if cand in available_fields:
                    resolved_field = cand
                    break
        else:
            resolved_field = spec.tshark_candidates[0]
        if resolved_field is not None:
            resolved_mappings.append((resolved_field, spec.canonical_name))
        elif spec.required:
            raise TsharkError(
                f"tshark compatibility error: required field '{spec.canonical_name}' "
                f"(candidates: {spec.tshark_candidates}) is not available in installed TShark {tshark_ver}"
            )
        else:
            unresolved_optional.append(spec.canonical_name)
    return resolved_mappings, unresolved_optional


def tshark_version() -> str:
    exe = resolve_tshark_executable()
    try:
        completed = subprocess.run(
            [exe, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False
        )
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown tshark failure"
        raise TsharkError(f"tshark --version failed: {detail}")
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "tshark (version unavailable)"


def build_tshark_fields_command(
    capture: Path,
    mappings: list[tuple[str, str]] | None = None,
    display_filter: str = "s1ap",
) -> list[str]:
    exe = resolve_tshark_executable()
    command = [
        exe,
        "-n",
        "-r",
        str(capture),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=a",
        "-Y",
        display_filter,
    ]
    if mappings is None:
        mappings = [(s.tshark_candidates[0], s.canonical_name) for s in FIELD_SPECS]
    for actual, _ in mappings:
        command.extend(["-e", actual])
    return command


def tshark_records(capture: Path) -> Iterator[dict[str, object]]:
    exe = resolve_tshark_executable()
    ver = tshark_version()
    avail_fields = get_available_fields(exe)
    avail_protos = get_available_protocols(exe)
    resolved_filter = resolve_filter(FILTER_CANDIDATES, avail_protos)
    mappings, unresolved_optional = resolve_field_specs(FIELD_SPECS, avail_fields, ver)
    command = build_tshark_fields_command(capture, mappings, resolved_filter)
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    assert process.stdout is not None
    reader = csv.reader(process.stdout, delimiter="\t")
    header = next(reader, None)
    if header is None:
        stderr = process.stderr.read().strip() if process.stderr else ""
        return_code = process.wait()
        if return_code != 0:
            raise TsharkError(f"tshark returned no field header: {stderr or 'no output'}")
        return
    expected_headers = [actual for actual, _ in mappings]
    if list(header) != expected_headers:
        stderr = process.stderr.read().strip() if process.stderr else ""
        process.wait()
        raise TsharkError(
            f"tshark returned unexpected field header: expected {expected_headers}, got {header}: {stderr}"
        )
    for row in reader:
        if len(row) > len(mappings):
            raise TsharkError("tshark returned more columns than the requested S1AP field set")
        padded = row + [""] * (len(mappings) - len(row))
        record = {canonical: padded[i] for i, (_, canonical) in enumerate(mappings)}
        for optional in unresolved_optional:
            record[optional] = ""
        yield record
    stderr = process.stderr.read().strip() if process.stderr else ""
    return_code = process.wait()
    if return_code != 0:
        raise TsharkError(f"tshark capture parsing failed: {stderr or f'exit {return_code}'}")


def pdml_dissection(capture: Path) -> str:
    """Run a PDML dissection so E-RAB item boundaries stay provable."""
    exe = resolve_tshark_executable()
    command = [
        exe,
        "-n",
        "-r",
        str(capture),
        "-T",
        "pdml",
        "-Y",
        resolve_filter(FILTER_CANDIDATES, get_available_protocols(exe)),
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False
        )
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "unknown tshark failure"
        raise TsharkError(f"tshark PDML dissection failed: {detail}")
    return completed.stdout


def erab_index_for_capture(
    capture: Path,
) -> tuple[dict[int, list[dict[str, Any]]], set[int]]:
    """E-RAB items per frame and nested-NAS frames, from the dissector tree."""
    try:
        return s1ap_erab.pdml_erab_dissection(pdml_dissection(capture), safe_capture_name(capture))
    except ValueError as exc:
        raise TsharkError(f"tshark PDML dissection is unreadable: {exc}") from exc


def input_kind(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    if path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
        return "capture"
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        return "fields-jsonl"
    raise InputError("cannot infer input format; use --input-format capture or fields-jsonl")


def records_for_input(path: Path, requested: str) -> tuple[Iterable[dict[str, object]], str | None]:
    if not path.is_file():
        raise InputError(f"input file does not exist: {path}")
    kind = input_kind(path, requested)
    if kind == "fields-jsonl":
        return read_jsonl(path), None
    if kind == "capture":
        return tshark_records(path), tshark_version()
    raise InputError(f"unsupported extracted format: {kind}")
