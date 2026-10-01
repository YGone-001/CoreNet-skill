#!/usr/bin/env python3
"""Shared, standalone helpers for bounded NGAP semantic extraction.

The protocol identity tables below were reviewed against the NGAP dissector
of Wireshark/TShark 4.7.1 (v4.7.1-0-g667ab240e6de) via `tshark -G fields`
and `tshark -G values`, which implements 3GPP TS 38.413 procedure codes and
cause vocabularies. Semantic support is intentionally bounded to the
UE-context / NAS-transport / Initial Context / Release / Paging subset;
every other known procedure code is reported as UNSUPPORTED without
invented semantics, and unknown codes as UNKNOWN.

Timestamp normalization matches the core-network-pcap convention; the code
is duplicated here on purpose so this package stays standalone when the
core-network-pcap Skill is not installed.
"""

from __future__ import annotations

import csv
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from pathlib import Path
from typing import Iterable, Iterator


EXIT_TOOL_UNAVAILABLE = 3
EXIT_TSHARK_FAILURE = 4
EXIT_MALFORMED_INPUT = 5
EXIT_NO_EVENTS = 6
EXIT_OUTPUT_FAILURE = 7

SCHEMA_NAME = "ngap-event"

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
    "sctp.data_sid",
    "_ws.col.Info",
    "ngap.procedureCode",
    "ngap.AMF_UE_NGAP_ID",
    "ngap.RAN_UE_NGAP_ID",
    "ngap.Cause",
    "ngap.cause",
    "ngap.radioNetwork",
    "ngap.transport",
    "ngap.nas",
    "ngap.protocol",
    "ngap.misc",
    "ngap.NAS_PDU",
    "ngap.RRCEstablishmentCause",
    "ngap.UserLocationInformation",
    "ngap.TAC",
    "ngap.UEPagingIdentity",
    "ngap.fiveG_TMSI",
)

PDU_INITIATING = "initiatingMessage"
PDU_SUCCESSFUL = "successfulOutcome"
PDU_UNSUCCESSFUL = "unsuccessfulOutcome"
PDU_TYPES = (PDU_INITIATING, PDU_SUCCESSFUL, PDU_UNSUCCESSFUL)

# Supported procedures: procedure code -> (name, {pdu type: message name}).
# Message names are the reviewed TS 38.413 message identities for each
# elementary procedure outcome branch.
SUPPORTED_PROCEDURES = {
    4: ("DownlinkNASTransport", {PDU_INITIATING: "DownlinkNASTransport"}),
    9: ("ErrorIndication", {PDU_INITIATING: "ErrorIndication"}),
    14: ("InitialContextSetup", {
        PDU_INITIATING: "InitialContextSetupRequest",
        PDU_SUCCESSFUL: "InitialContextSetupResponse",
        PDU_UNSUCCESSFUL: "InitialContextSetupFailure",
    }),
    15: ("InitialUEMessage", {PDU_INITIATING: "InitialUEMessage"}),
    19: ("NASNonDeliveryIndication", {PDU_INITIATING: "NASNonDeliveryIndication"}),
    24: ("Paging", {PDU_INITIATING: "Paging"}),
    41: ("UEContextRelease", {
        PDU_INITIATING: "UEContextReleaseCommand",
        PDU_SUCCESSFUL: "UEContextReleaseComplete",
    }),
    42: ("UEContextReleaseRequest", {PDU_INITIATING: "UEContextReleaseRequest"}),
    46: ("UplinkNASTransport", {PDU_INITIATING: "UplinkNASTransport"}),
}

# Local normalized protocol-state labels (NOT 3GPP wire values). They
# summarize the observed message's role inside its elementary procedure.
# Indication-only messages without a request/outcome relationship carry null.
MESSAGE_RESULTS = {
    "InitialContextSetupRequest": "REQUEST",
    "InitialContextSetupResponse": "SUCCESS",
    "InitialContextSetupFailure": "FAILURE",
    "InitialUEMessage": "REQUEST",
    "DownlinkNASTransport": "REQUEST",
    "UplinkNASTransport": "REQUEST",
    "Paging": "REQUEST",
    "UEContextReleaseCommand": "COMMAND",
    "UEContextReleaseComplete": "COMPLETE",
    "UEContextReleaseRequest": "REQUEST",
}

# TS 38.413 defines the signaling side that sends each message. The role is
# derived from message identity only; endpoint addresses are never mapped to
# network-function roles.
MESSAGE_SENDER_ROLES = {
    "InitialContextSetupRequest": "amf",
    "InitialContextSetupResponse": "ng-ran",
    "InitialContextSetupFailure": "ng-ran",
    "InitialUEMessage": "ng-ran",
    "DownlinkNASTransport": "amf",
    "UplinkNASTransport": "ng-ran",
    "ErrorIndication": None,
    "NASNonDeliveryIndication": "ng-ran",
    "Paging": "amf",
    "UEContextReleaseCommand": "amf",
    "UEContextReleaseComplete": "ng-ran",
    "UEContextReleaseRequest": "ng-ran",
}

# Cause CHOICE categories as reviewed from the TS 38.413 cause vocabulary.
CAUSE_CATEGORIES = {
    0: "radioNetwork",
    1: "transport",
    2: "nas",
    3: "protocol",
    4: "misc",
    5: "choice-Extensions",
}
CAUSE_CATEGORY_NAMES = {name: code for code, name in CAUSE_CATEGORIES.items()}
CAUSE_VALUE_FIELDS = {
    "radioNetwork": "ngap.radioNetwork",
    "transport": "ngap.transport",
    "nas": "ngap.nas",
    "protocol": "ngap.protocol",
    "misc": "ngap.misc",
}


class InputError(ValueError):
    """Raised when a supported structured input cannot be normalized."""


class ToolUnavailable(RuntimeError):
    """Raised when tshark is required but unavailable."""


class TsharkError(RuntimeError):
    """Raised when tshark cannot produce the requested NGAP fields."""


@dataclass(frozen=True)
class ProcedureIdentity:
    """Normalized NGAP identity for one observed frame."""

    procedure_code: int
    procedure_name: str | None
    message_type: str | None
    pdu_type: str | None
    pdu_type_basis: str | None
    support_status: str
    result: str | None
    sender_role: str | None
    derivations: tuple[str, ...]


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


def parse_int(value: object, field: str) -> int:
    text = clean(value)
    if text is None:
        raise InputError(f"{field} is required")
    try:
        return int(text)
    except ValueError as exc:
        raise InputError(f"{field} must be an integer") from exc


def optional_int(value: object) -> int | None:
    text = clean(value)
    if text is None:
        return None
    try:
        return int(text)
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


def resolve_procedure(
    code: int,
    observed_message: str | None,
    explicit_pdu_type: str | None = None,
) -> ProcedureIdentity:
    """Normalize procedure/message identity from reviewed bounded mappings.

    PDU category resolution, in priority order: an explicit structured-input
    ``pdu_type`` (an observed dissector export) wins; otherwise an exact
    match of the observed Info-column message name against a reviewed
    procedure branch is used. Neither source is invented.
    """
    derivations: list[str] = []
    if code in SUPPORTED_PROCEDURES:
        name, messages = SUPPORTED_PROCEDURES[code]
        derivations.append("procedure_name")
        message_type = None
        pdu_type = None
        basis = None
        if explicit_pdu_type is not None:
            pdu_type = explicit_pdu_type
            basis = "structured-input"
            message_type = messages.get(pdu_type)
            if message_type is not None:
                derivations.append("message_type")
        elif observed_message is not None:
            for candidate_pdu, candidate_message in messages.items():
                if observed_message == candidate_message:
                    message_type = candidate_message
                    pdu_type = candidate_pdu
                    basis = "message-name"
                    derivations.extend(["message_type", "pdu_type"])
                    break
        result = MESSAGE_RESULTS.get(message_type) if message_type else None
        if result is not None:
            derivations.append("result")
        sender_role = MESSAGE_SENDER_ROLES.get(message_type) if message_type else None
        if sender_role is not None:
            derivations.append("sender_role")
        return ProcedureIdentity(
            procedure_code=code,
            procedure_name=name,
            message_type=message_type,
            pdu_type=pdu_type,
            pdu_type_basis=basis,
            support_status="SUPPORTED",
            result=result,
            sender_role=sender_role,
            derivations=tuple(sorted(derivations)),
        )
    known = KNOWN_PROCEDURE_NAMES.get(code)
    if known is not None:
        derivations.append("procedure_name")
    return ProcedureIdentity(
        procedure_code=code,
        procedure_name=known,
        message_type=None,
        pdu_type=None,
        pdu_type_basis=None,
        support_status="UNSUPPORTED" if known is not None else "UNKNOWN",
        result=None,
        sender_role=None,
        derivations=tuple(sorted(derivations)),
    )


# Reviewed procedure-code name table (identity only, no semantics) from the
# TS 38.413 vocabulary implemented by Wireshark/TShark 4.7.1. Codes outside
# the supported subset above are identified by name and marked UNSUPPORTED.
KNOWN_PROCEDURE_NAMES = {
    0: "AMFConfigurationUpdate",
    1: "AMFStatusIndication",
    2: "CellTrafficTrace",
    3: "DeactivateTrace",
    4: "DownlinkNASTransport",
    5: "DownlinkNonUEAssociatedNRPPaTransport",
    6: "DownlinkRANConfigurationTransfer",
    7: "DownlinkRANStatusTransfer",
    8: "DownlinkUEAssociatedNRPPaTransport",
    9: "ErrorIndication",
    10: "HandoverCancel",
    11: "HandoverNotification",
    12: "HandoverPreparation",
    13: "HandoverResourceAllocation",
    14: "InitialContextSetup",
    15: "InitialUEMessage",
    16: "LocationReportingControl",
    17: "LocationReportingFailureIndication",
    18: "LocationReport",
    19: "NASNonDeliveryIndication",
    20: "NGReset",
    21: "NGSetup",
    22: "OverloadStart",
    23: "OverloadStop",
    24: "Paging",
    25: "PathSwitchRequest",
    26: "PDUSessionResourceModify",
    27: "PDUSessionResourceModifyIndication",
    28: "PDUSessionResourceRelease",
    29: "PDUSessionResourceSetup",
    30: "PDUSessionResourceNotify",
    31: "PrivateMessage",
    32: "PWSCancel",
    33: "PWSFailureIndication",
    34: "PWSRestartIndication",
    35: "RANConfigurationUpdate",
    36: "RerouteNASRequest",
    37: "RRCInactiveTransitionReport",
    38: "TraceFailureIndication",
    39: "TraceStart",
    40: "UEContextModification",
    41: "UEContextRelease",
    42: "UEContextReleaseRequest",
    43: "UERadioCapabilityCheck",
    44: "UERadioCapabilityInfoIndication",
    45: "UETNLABindingRelease",
    46: "UplinkNASTransport",
    47: "UplinkNonUEAssociatedNRPPaTransport",
    48: "UplinkRANConfigurationTransfer",
    49: "UplinkRANStatusTransfer",
    50: "UplinkUEAssociatedNRPPaTransport",
    51: "WriteReplaceWarning",
    52: "SecondaryRATDataUsageReport",
    53: "UplinkRIMInformationTransfer",
    54: "DownlinkRIMInformationTransfer",
    55: "RetrieveUEInformation",
    56: "UEInformationTransfer",
    57: "RANCPRelocationIndication",
    58: "UEContextResume",
    59: "UEContextSuspend",
    60: "UERadioCapabilityIDMapping",
    61: "HandoverSuccess",
    62: "UplinkRANEarlyStatusTransfer",
    63: "DownlinkRANEarlyStatusTransfer",
    64: "AMFCPRelocationIndication",
    65: "ConnectionEstablishmentIndication",
    66: "BroadcastSessionModification",
    67: "BroadcastSessionRelease",
    68: "BroadcastSessionSetup",
    69: "DistributionSetup",
    70: "DistributionRelease",
    71: "MulticastSessionActivation",
    72: "MulticastSessionDeactivation",
    73: "MulticastSessionUpdate",
    74: "MulticastGroupPaging",
    75: "BroadcastSessionReleaseRequired",
    76: "TimingSynchronisationStatus",
    77: "TimingSynchronisationStatusReport",
    78: "MTCommunicationHandling",
    79: "RANPagingRequest",
    80: "BroadcastSessionTransport",
    81: "NGRemoval",
    82: "InventoryRequest",
    83: "InventoryReport",
    84: "CommandRequest",
    85: "AIOTSessionRelease",
    86: "AIOTSessionReleaseRequest",
}


def observed_cause(record: dict[str, object]) -> dict[str, object] | None:
    """Preserve the observed cause category and value without interpretation."""
    category_text = clean(record.get("ngap.cause")) or clean(record.get("ngap.Cause"))
    category: str | None = None
    if category_text is not None:
        if category_text.isdigit():
            code = int(category_text)
            category = CAUSE_CATEGORIES.get(code)
            if category is None:
                category = f"unknown-category-{code}"
        elif category_text in CAUSE_CATEGORY_NAMES:
            category = category_text
        else:
            category = category_text
    value: object = None
    if category in CAUSE_VALUE_FIELDS:
        value_text = clean(record.get(CAUSE_VALUE_FIELDS[category]))
        if value_text is not None:
            value = int(value_text) if value_text.lstrip("-").isdigit() else value_text
    elif category is not None:
        for field in CAUSE_VALUE_FIELDS.values():
            value_text = clean(record.get(field))
            if value_text is not None:
                value = int(value_text) if value_text.lstrip("-").isdigit() else value_text
                break
    if category is None and value is None:
        return None
    return {"category": category, "value": value}


def nas_pdu_metadata(record: dict[str, object]) -> tuple[bool, int | None]:
    """NAS-PDU presence and length only; payload bytes are never retained."""
    raw = clean(record.get("ngap.NAS_PDU"))
    if raw is None:
        return False, None
    digits = raw.replace(":", "").replace(" ", "")
    length = len(digits) // 2 if digits else 0
    return True, length


def endpoint(record: dict[str, object], direction: str) -> dict[str, object] | None:
    address = clean(record.get(f"ip.{direction}")) or clean(record.get(f"ipv6.{direction}"))
    port = parse_port(record.get(f"sctp.{direction}port"), f"sctp.{direction}port")
    if address is None and port is None:
        return None
    return {"address": address, "port": port}


def sctp_metadata(record: dict[str, object]) -> dict[str, object] | None:
    association = optional_int(record.get("sctp.assoc_index"))
    stream = optional_int(record.get("sctp.data_sid"))
    srcport = parse_port(record.get("sctp.srcport"), "sctp.srcport")
    dstport = parse_port(record.get("sctp.dstport"), "sctp.dstport")
    if association is None and stream is None and srcport is None and dstport is None:
        return None
    return {
        "association_id": association,
        "stream_id": stream,
        "srcport": srcport,
        "dstport": dstport,
    }


def normalize_record(record: object, capture_file: str) -> dict[str, object]:
    """Project one structured NGAP observation into the detailed event."""
    if not isinstance(record, dict):
        raise InputError("structured NGAP record must be a JSON object")
    frame_number = parse_int(record.get("frame.number"), "frame.number")
    if frame_number < 1:
        raise InputError("frame.number must be at least 1")
    procedure_code = parse_int(record.get("ngap.procedureCode"), "ngap.procedureCode")
    if not 0 <= procedure_code <= 255:
        raise InputError("ngap.procedureCode must be within 0..255")

    explicit_pdu_type = clean(record.get("pdu_type"))
    if explicit_pdu_type is not None and explicit_pdu_type not in PDU_TYPES:
        raise InputError("pdu_type must be one of initiatingMessage, successfulOutcome, unsuccessfulOutcome")

    timestamp = normalize_timestamp(record.get("frame.time_epoch"))
    observed_message = clean(record.get("_ws.col.Info")) or clean(record.get("_ws.col.info"))
    identity = resolve_procedure(procedure_code, observed_message, explicit_pdu_type)
    cause = observed_cause(record)
    nas_present, nas_length = nas_pdu_metadata(record)
    source = endpoint(record, "src")
    destination = endpoint(record, "dst")
    sctp = sctp_metadata(record)
    rrc_cause = clean(record.get("ngap.RRCEstablishmentCause"))
    if rrc_cause is not None and rrc_cause.lstrip("-").isdigit():
        rrc_cause = int(rrc_cause)
    ran_id = optional_int(record.get("ngap.RAN_UE_NGAP_ID"))
    if clean(record.get("ngap.RAN_UE_NGAP_ID")) is not None and ran_id is None:
        raise InputError("ngap.RAN_UE_NGAP_ID must be an integer")
    amf_id = optional_int(record.get("ngap.AMF_UE_NGAP_ID"))
    if clean(record.get("ngap.AMF_UE_NGAP_ID")) is not None and amf_id is None:
        raise InputError("ngap.AMF_UE_NGAP_ID must be an integer")

    # Container IEs often export empty from tshark, so value-carrying child
    # fields are accepted as presence markers; presence only, never contents.
    user_location_present = any(
        clean(record.get(field)) is not None
        for field in ("ngap.UserLocationInformation", "ngap.TAC")
    )
    paging_identity_present = any(
        clean(record.get(field)) is not None
        for field in ("ngap.UEPagingIdentity", "ngap.fiveG_TMSI")
    )

    source_ref = f"capture:{capture_file}#frame={frame_number}; procedure-code={procedure_code}"
    if observed_message is not None:
        source_ref += f"; tshark-info={observed_message}"
    event: dict[str, object] = {
        "timestamp": timestamp,
        "frame_number": frame_number,
        "capture_file": capture_file,
        "pdu_type": identity.pdu_type,
        "pdu_type_basis": identity.pdu_type_basis,
        "procedure_code": identity.procedure_code,
        "procedure_name": identity.procedure_name,
        "message_type": identity.message_type,
        "support_status": identity.support_status,
        "result": identity.result,
        "sender_role": identity.sender_role,
        "amf_ue_ngap_id": amf_id,
        "ran_ue_ngap_id": ran_id,
        "cause": cause,
        "nas_pdu_present": nas_present,
        "nas_pdu_length": nas_length,
        "rrc_establishment_cause": rrc_cause,
        "user_location_information_present": user_location_present,
        "paging_identity_present": paging_identity_present,
        "evidence": {"level": "OBSERVED", "source": source_ref},
        "derivations": list(identity.derivations),
    }
    if source is not None:
        event["source"] = source
    if destination is not None:
        event["destination"] = destination
    if sctp is not None:
        event["sctp"] = sctp
    return event


def project_trace_event(event: dict[str, object]) -> dict[str, object]:
    """Project a detailed NGAP event into the shared trace-event contract.

    NGAP-specific identifiers (AMF/RAN UE NGAP IDs) stay in the detailed
    event; they are never written into unrelated generic fields.
    """
    projected: dict[str, object] = {
        "timestamp": event["timestamp"],
        "protocol": "NGAP",
        "interface": "N2",
        "procedure": event.get("procedure_name"),
        "message_type": event.get("message_type"),
        "packet": {"frame_number": event["frame_number"], "capture_file": event["capture_file"]},
        "evidence": {
            "level": "DERIVED",
            "source": f"ngap-event:{event['capture_file']}#frame={event['frame_number']}",
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
            cause_text = f"{cause['category']}:{cause['value']}" if cause.get("value") is not None else str(cause["category"])
        code = cause.get("value") if isinstance(cause.get("value"), int) else None
        projected["result"] = {"status": event.get("result"), "cause": cause_text, "code": code}
    elif event.get("result") is not None:
        projected["result"] = {"status": event.get("result"), "cause": None, "code": None}
    return projected


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


def tshark_version() -> str:
    try:
        completed = subprocess.run(["tshark", "--version"], capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown tshark failure"
        raise TsharkError(f"tshark --version failed: {detail}")
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "tshark (version unavailable)"


def build_tshark_fields_command(capture: Path) -> list[str]:
    command = ["tshark", "-n", "-r", str(capture), "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f", "-Y", "ngap"]
    for field in FIELDS:
        command.extend(["-e", field])
    return command


def tshark_records(capture: Path) -> Iterator[dict[str, object]]:
    command = build_tshark_fields_command(capture)
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    assert process.stdout is not None
    reader = csv.reader(process.stdout, delimiter="\t")
    header = next(reader, None)
    if header is None:
        stderr = process.stderr.read().strip() if process.stderr else ""
        process.wait()
        raise TsharkError(f"tshark returned no field header: {stderr or 'no output'}")
    if tuple(header) != FIELDS:
        stderr = process.stderr.read().strip() if process.stderr else ""
        process.wait()
        raise TsharkError(f"tshark did not expose the required NGAP fields: {stderr or header}")
    for row in reader:
        if len(row) > len(FIELDS):
            raise TsharkError("tshark returned more columns than the requested NGAP field set")
        padded = row + [""] * (len(FIELDS) - len(row))
        yield dict(zip(FIELDS, padded, strict=True))
    stderr = process.stderr.read().strip() if process.stderr else ""
    return_code = process.wait()
    if return_code != 0:
        raise TsharkError(f"tshark capture parsing failed: {stderr or f'exit {return_code}'}")


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


def association_key(event: dict[str, object]) -> tuple[str, str]:
    """Deterministic association context: capture identity plus SCTP context.

    Different captures and different SCTP associations are never merged,
    even when numeric UE NGAP IDs happen to match.
    """
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


def context_key(capture: str, association: str, ran_id: int | None, amf_id: int | None) -> str:
    """Explicitly derived local context key; not a standardized NGAP identifier."""
    ran = f"r{ran_id}" if ran_id is not None else "r?"
    amf = f"a{amf_id}" if amf_id is not None else "a?"
    return f"ngap-context:{capture}:{association}:{ran}:{amf}"
