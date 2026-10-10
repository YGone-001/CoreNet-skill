#!/usr/bin/env python3
"""Shared, standalone helpers for bounded NGAP semantic extraction.

The protocol identity tables below were reviewed against the NGAP dissector
of Wireshark/TShark 4.7.1 (v4.7.1-0-g667ab240e6de) via `tshark -G fields`
and `tshark -G values`, which implements 3GPP TS 38.413 procedure codes and
cause vocabularies. Semantic support is intentionally bounded to the
UE-context / NAS-transport / Initial Context / Release / Paging subset, the
bounded PDU Session resource subset, and the bounded N2 handover /
path-switch mobility subset; every other known procedure code is reported
as UNSUPPORTED without invented semantics, and unknown codes as UNKNOWN.

The mobility message identities, resource-list fields, transfer-container
fields, HandoverType and TargetID vocabularies were verified in 4.7.1 by
local introspection (`tshark -G fields` / `tshark -G values`) cross-checked
against the TS 38.413 ASN.1 sources packaged with that dissector. No field
name is invented.

Timestamp normalization matches the core-network-pcap convention; the code
is duplicated here on purpose so this package stays standalone when the
core-network-pcap Skill is not installed.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from pathlib import Path
from typing import Iterable, Iterator


@dataclass(frozen=True)
class FieldSpec:
    canonical_name: str
    tshark_candidates: tuple[str, ...]
    required: bool = False


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
    # PDU Session resource evidence (bounded; no transfer decoding).
    "ngap.pDUSessionID",
    "ngap.pDUSessionNAS_PDU",
    "ngap.qosFlowIdentifier",
    "ngap.PDUSessionResourceSetupListSUReq",
    "ngap.PDUSessionResourceSetupListSURes",
    "ngap.PDUSessionResourceFailedToSetupListSURes",
    "ngap.PDUSessionResourceSetupListCxtReq",
    "ngap.PDUSessionResourceSetupListCxtRes",
    "ngap.PDUSessionResourceFailedToSetupListCxtRes",
    "ngap.PDUSessionResourceModifyListModReq",
    "ngap.PDUSessionResourceModifyListModRes",
    "ngap.PDUSessionResourceFailedToModifyListModRes",
    "ngap.PDUSessionResourceToReleaseListRelCmd",
    "ngap.PDUSessionResourceReleasedListRelRes",
    "ngap.pDUSessionResourceSetupRequestTransfer",
    "ngap.pDUSessionResourceSetupResponseTransfer",
    "ngap.pDUSessionResourceSetupUnsuccessfulTransfer",
    "ngap.pDUSessionResourceModifyRequestTransfer",
    "ngap.pDUSessionResourceModifyResponseTransfer",
    "ngap.pDUSessionResourceModifyUnsuccessfulTransfer",
    "ngap.pDUSessionResourceReleaseCommandTransfer",
    "ngap.pDUSessionResourceReleaseResponseTransfer",
    # Bounded N2 mobility evidence (handover / path switch). Names verified
    # via `tshark -G fields` on 4.7.1 and the packaged TS 38.413 ASN.1.
    "ngap.PDUSessionResourceListHORqd",
    "ngap.PDUSessionResourceHandoverList",
    "ngap.PDUSessionResourceToReleaseListHOCmd",
    "ngap.PDUSessionResourceSetupListHOReq",
    "ngap.PDUSessionResourceAdmittedList",
    "ngap.PDUSessionResourceFailedToSetupListHOAck",
    "ngap.PDUSessionResourceToBeSwitchedDLList",
    "ngap.PDUSessionResourceFailedToSetupListPSReq",
    "ngap.PDUSessionResourceSwitchedList",
    "ngap.PDUSessionResourceReleasedListPSAck",
    "ngap.PDUSessionResourceReleasedListPSFail",
    "ngap.handoverRequiredTransfer",
    "ngap.handoverCommandTransfer",
    "ngap.handoverPreparationUnsuccessfulTransfer",
    "ngap.handoverRequestTransfer",
    "ngap.handoverRequestAcknowledgeTransfer",
    "ngap.handoverResourceAllocationUnsuccessfulTransfer",
    "ngap.pathSwitchRequestTransfer",
    "ngap.pathSwitchRequestAcknowledgeTransfer",
    "ngap.pathSwitchRequestUnsuccessfulTransfer",
    "ngap.pathSwitchRequestSetupFailedTransfer",
    "ngap.HandoverType",
    "ngap.TargetID",
    "ngap.SourceToTarget_TransparentContainer",
    "ngap.TargetToSource_TransparentContainer",
    "ngap.TargettoSource_Failure_TransparentContainer",
)

FIELD_SPECS: tuple[FieldSpec, ...] = tuple(
    FieldSpec(
        canonical_name=name,
        tshark_candidates=("_ws.col.Info", "_ws.col.info") if name == "_ws.col.Info" else (name,),
        required=name in {"frame.number", "frame.time_epoch", "ngap.procedureCode"},
    )
    for name in FIELDS
)

FILTER_CANDIDATES: tuple[str, ...] = ("ngap",)

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
    10: ("HandoverCancel", {
        PDU_INITIATING: "HandoverCancel",
        PDU_SUCCESSFUL: "HandoverCancelAcknowledge",
    }),
    11: ("HandoverNotification", {PDU_INITIATING: "HandoverNotify"}),
    12: ("HandoverPreparation", {
        PDU_INITIATING: "HandoverRequired",
        PDU_SUCCESSFUL: "HandoverCommand",
        PDU_UNSUCCESSFUL: "HandoverPreparationFailure",
    }),
    13: ("HandoverResourceAllocation", {
        PDU_INITIATING: "HandoverRequest",
        PDU_SUCCESSFUL: "HandoverRequestAcknowledge",
        PDU_UNSUCCESSFUL: "HandoverFailure",
    }),
    14: ("InitialContextSetup", {
        PDU_INITIATING: "InitialContextSetupRequest",
        PDU_SUCCESSFUL: "InitialContextSetupResponse",
        PDU_UNSUCCESSFUL: "InitialContextSetupFailure",
    }),
    15: ("InitialUEMessage", {PDU_INITIATING: "InitialUEMessage"}),
    19: ("NASNonDeliveryIndication", {PDU_INITIATING: "NASNonDeliveryIndication"}),
    24: ("Paging", {PDU_INITIATING: "Paging"}),
    25: ("PathSwitchRequest", {
        PDU_INITIATING: "PathSwitchRequest",
        PDU_SUCCESSFUL: "PathSwitchRequestAcknowledge",
        PDU_UNSUCCESSFUL: "PathSwitchRequestFailure",
    }),
    26: ("PDUSessionResourceModify", {
        PDU_INITIATING: "PDUSessionResourceModifyRequest",
        PDU_SUCCESSFUL: "PDUSessionResourceModifyResponse",
    }),
    28: ("PDUSessionResourceRelease", {
        PDU_INITIATING: "PDUSessionResourceReleaseCommand",
        PDU_SUCCESSFUL: "PDUSessionResourceReleaseResponse",
    }),
    29: ("PDUSessionResourceSetup", {
        PDU_INITIATING: "PDUSessionResourceSetupRequest",
        PDU_SUCCESSFUL: "PDUSessionResourceSetupResponse",
    }),
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
    "PDUSessionResourceSetupRequest": "REQUEST",
    "PDUSessionResourceSetupResponse": "SUCCESS",
    "PDUSessionResourceModifyRequest": "REQUEST",
    "PDUSessionResourceModifyResponse": "SUCCESS",
    "PDUSessionResourceReleaseCommand": "COMMAND",
    "PDUSessionResourceReleaseResponse": "SUCCESS",
    "UEContextReleaseCommand": "COMMAND",
    "UEContextReleaseComplete": "COMPLETE",
    "UEContextReleaseRequest": "REQUEST",
    # Mobility messages reuse the same bounded local labels. HandoverCommand
    # carries COMMAND because its protocol role is commanding handover
    # execution at the source NG-RAN; its successful-outcome branch identity
    # stays visible in pdu_type. HandoverNotify is an indication-only message
    # (no request/outcome relationship) and carries null like ErrorIndication.
    "HandoverRequired": "REQUEST",
    "HandoverCommand": "COMMAND",
    "HandoverPreparationFailure": "FAILURE",
    "HandoverRequest": "REQUEST",
    "HandoverRequestAcknowledge": "SUCCESS",
    "HandoverFailure": "FAILURE",
    "HandoverCancel": "REQUEST",
    "HandoverCancelAcknowledge": "SUCCESS",
    "PathSwitchRequest": "REQUEST",
    "PathSwitchRequestAcknowledge": "SUCCESS",
    "PathSwitchRequestFailure": "FAILURE",
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
    "PDUSessionResourceSetupRequest": "amf",
    "PDUSessionResourceSetupResponse": "ng-ran",
    "PDUSessionResourceModifyRequest": "amf",
    "PDUSessionResourceModifyResponse": "ng-ran",
    "PDUSessionResourceReleaseCommand": "amf",
    "PDUSessionResourceReleaseResponse": "ng-ran",
    "UEContextReleaseCommand": "amf",
    "UEContextReleaseComplete": "ng-ran",
    "UEContextReleaseRequest": "ng-ran",
    # Reviewed TS 38.413 elementary-procedure directions: Handover
    # Preparation, Handover Cancel, Handover Notification, and Path Switch
    # Request are initiated by the NG-RAN node; Handover Resource Allocation
    # is initiated by the AMF. Outcome branches are sent by the receiving
    # side. Endpoint addresses are never mapped to these roles.
    "HandoverRequired": "ng-ran",
    "HandoverCommand": "amf",
    "HandoverPreparationFailure": "amf",
    "HandoverRequest": "amf",
    "HandoverRequestAcknowledge": "ng-ran",
    "HandoverFailure": "ng-ran",
    "HandoverNotify": "ng-ran",
    "HandoverCancel": "ng-ran",
    "HandoverCancelAcknowledge": "amf",
    "PathSwitchRequest": "ng-ran",
    "PathSwitchRequestAcknowledge": "amf",
    "PathSwitchRequestFailure": "amf",
}

# --- PDU Session resource evidence -------------------------------------
#
# Reviewed against 3GPP TS 38.413 version 19.4.0 Release 19 and the
# published Wireshark NGAP display-filter reference. NGAP reports failed
# PDU Session resources through a FAILED-TO-SETUP / FAILED-TO-MODIFY item
# list inside a successfulOutcome response; TS 38.413 defines no
# "PDUSessionResourceSetupFailure" message.
RESOURCE_OPERATIONS = (
    "SETUP",
    "MODIFY",
    "RELEASE",
    "INITIAL_CONTEXT_SETUP",
    "HANDOVER_PREPARATION",
    "HANDOVER_RESOURCE_ALLOCATION",
    "PATH_SWITCH",
)
RESOURCE_LIST_ROLES = (
    "REQUEST",
    "SUCCESS",
    "FAILED",
    "COMMAND",
    "RESPONSE",
    # Mobility list roles, derived from the reviewed TS 38.413 list meanings.
    # Each role describes the resource's location inside the observed message,
    # never an end-to-end verdict.
    "REQUIRED",
    "HANDOVER",
    "TO_RELEASE",
    "ADMITTED",
    "TO_BE_SWITCHED",
    "SWITCHED",
    "RELEASED",
)

# Resource-list indicator field -> (operation, list role).
RESOURCE_LIST_FIELDS = {
    "ngap.PDUSessionResourceSetupListSUReq": ("SETUP", "REQUEST"),
    "ngap.PDUSessionResourceSetupListSURes": ("SETUP", "SUCCESS"),
    "ngap.PDUSessionResourceFailedToSetupListSURes": ("SETUP", "FAILED"),
    "ngap.PDUSessionResourceSetupListCxtReq": ("INITIAL_CONTEXT_SETUP", "REQUEST"),
    "ngap.PDUSessionResourceSetupListCxtRes": ("INITIAL_CONTEXT_SETUP", "SUCCESS"),
    "ngap.PDUSessionResourceFailedToSetupListCxtRes": ("INITIAL_CONTEXT_SETUP", "FAILED"),
    "ngap.PDUSessionResourceModifyListModReq": ("MODIFY", "REQUEST"),
    "ngap.PDUSessionResourceModifyListModRes": ("MODIFY", "SUCCESS"),
    "ngap.PDUSessionResourceFailedToModifyListModRes": ("MODIFY", "FAILED"),
    "ngap.PDUSessionResourceToReleaseListRelCmd": ("RELEASE", "COMMAND"),
    "ngap.PDUSessionResourceReleasedListRelRes": ("RELEASE", "RESPONSE"),
    # Bounded mobility lists. PDUSessionResourceHandoverList is the verified
    # HandoverCommand PDU Session list (id-PDUSessionResourceHandoverList);
    # the reviewed TS 38.413 ASN.1 defines no PDUSessionResourceListHOCmd.
    "ngap.PDUSessionResourceListHORqd": ("HANDOVER_PREPARATION", "REQUIRED"),
    "ngap.PDUSessionResourceHandoverList": ("HANDOVER_PREPARATION", "HANDOVER"),
    "ngap.PDUSessionResourceToReleaseListHOCmd": ("HANDOVER_PREPARATION", "TO_RELEASE"),
    "ngap.PDUSessionResourceSetupListHOReq": ("HANDOVER_RESOURCE_ALLOCATION", "REQUEST"),
    "ngap.PDUSessionResourceAdmittedList": ("HANDOVER_RESOURCE_ALLOCATION", "ADMITTED"),
    "ngap.PDUSessionResourceFailedToSetupListHOAck": ("HANDOVER_RESOURCE_ALLOCATION", "FAILED"),
    "ngap.PDUSessionResourceToBeSwitchedDLList": ("PATH_SWITCH", "TO_BE_SWITCHED"),
    "ngap.PDUSessionResourceFailedToSetupListPSReq": ("PATH_SWITCH", "FAILED"),
    "ngap.PDUSessionResourceSwitchedList": ("PATH_SWITCH", "SWITCHED"),
    "ngap.PDUSessionResourceReleasedListPSAck": ("PATH_SWITCH", "RELEASED"),
    "ngap.PDUSessionResourceReleasedListPSFail": ("PATH_SWITCH", "RELEASED"),
}

# Reviewed message identity -> resource operation (message-definition basis).
RESOURCE_OPERATION_BY_MESSAGE = {
    "PDUSessionResourceSetupRequest": "SETUP",
    "PDUSessionResourceSetupResponse": "SETUP",
    "PDUSessionResourceModifyRequest": "MODIFY",
    "PDUSessionResourceModifyResponse": "MODIFY",
    "PDUSessionResourceReleaseCommand": "RELEASE",
    "PDUSessionResourceReleaseResponse": "RELEASE",
    "InitialContextSetupRequest": "INITIAL_CONTEXT_SETUP",
    "InitialContextSetupResponse": "INITIAL_CONTEXT_SETUP",
    "HandoverRequired": "HANDOVER_PREPARATION",
    "HandoverCommand": "HANDOVER_PREPARATION",
    "HandoverPreparationFailure": "HANDOVER_PREPARATION",
    "HandoverRequest": "HANDOVER_RESOURCE_ALLOCATION",
    "HandoverRequestAcknowledge": "HANDOVER_RESOURCE_ALLOCATION",
    "HandoverFailure": "HANDOVER_RESOURCE_ALLOCATION",
    "PathSwitchRequest": "PATH_SWITCH",
    "PathSwitchRequestAcknowledge": "PATH_SWITCH",
    "PathSwitchRequestFailure": "PATH_SWITCH",
}

# Transfer-container field -> reviewed transfer kind. Presence and length
# only; the encoded transfer body is never parsed by this Skill.
TRANSFER_FIELDS = {
    "ngap.pDUSessionResourceSetupRequestTransfer": "setup-request-transfer",
    "ngap.pDUSessionResourceSetupResponseTransfer": "setup-response-transfer",
    "ngap.pDUSessionResourceSetupUnsuccessfulTransfer": "setup-unsuccessful-transfer",
    "ngap.pDUSessionResourceModifyRequestTransfer": "modify-request-transfer",
    "ngap.pDUSessionResourceModifyResponseTransfer": "modify-response-transfer",
    "ngap.pDUSessionResourceModifyUnsuccessfulTransfer": "modify-unsuccessful-transfer",
    "ngap.pDUSessionResourceReleaseCommandTransfer": "release-command-transfer",
    "ngap.pDUSessionResourceReleaseResponseTransfer": "release-response-transfer",
    # Bounded mobility transfer containers, verified in 4.7.1. Presence,
    # reviewed kind, and length only; the encoded transfer body is never
    # parsed and the raw bytes are never persisted.
    "ngap.handoverRequiredTransfer": "handover-required-transfer",
    "ngap.handoverCommandTransfer": "handover-command-transfer",
    "ngap.handoverPreparationUnsuccessfulTransfer": "handover-preparation-unsuccessful-transfer",
    "ngap.handoverRequestTransfer": "handover-request-transfer",
    "ngap.handoverRequestAcknowledgeTransfer": "handover-request-acknowledge-transfer",
    "ngap.handoverResourceAllocationUnsuccessfulTransfer": "handover-resource-allocation-unsuccessful-transfer",
    "ngap.pathSwitchRequestTransfer": "path-switch-request-transfer",
    "ngap.pathSwitchRequestAcknowledgeTransfer": "path-switch-request-acknowledge-transfer",
    "ngap.pathSwitchRequestUnsuccessfulTransfer": "path-switch-request-unsuccessful-transfer",
    "ngap.pathSwitchRequestSetupFailedTransfer": "path-switch-request-setup-failed-transfer",
}

# Bounded N2 mobility procedure codes and their protocol-local families.
# The family names the elementary procedure, never a Domain procedure state.
MOBILITY_PROCEDURE_CODES = {10, 11, 12, 13, 25}
MOBILITY_FAMILIES = {
    10: "handover-cancel",
    11: "handover-notification",
    12: "handover-preparation",
    13: "handover-resource-allocation",
    25: "path-switch",
}

# Reviewed HandoverType enumerated values (tshark -G values, table
# ngap.HandoverType). The observed value is preserved; the symbolic name is
# derived only for values in this exact reviewed mapping.
HANDOVER_TYPE_NAMES = {
    0: "intra5gs",
    1: "fivegs-to-eps",
    2: "eps-to-5gs",
    3: "fivegs-to-utran",
}

# Reviewed TargetID CHOICE alternatives (tshark -G values, table
# ngap.TargetID). Only the choice alternative is recorded; no target node,
# site, or vendor identity is derived.
TARGET_ID_TYPES = {
    0: "targetRANNodeID",
    1: "targeteNB-ID",
    2: "choice-Extensions",
}

# Reviewed mobility transparent containers (message-level presence/length
# only; the encoded content is never parsed).
MOBILITY_CONTAINER_FIELDS = (
    ("ngap.SourceToTarget_TransparentContainer", "source_to_target_container"),
    ("ngap.TargetToSource_TransparentContainer", "target_to_source_container"),
    ("ngap.TargettoSource_Failure_TransparentContainer", "target_to_source_failure_container"),
)

# Structured-input binding bases recorded on every resource item.
BINDING_STRUCTURED = "structured-input"
BINDING_SINGLE_ITEM = "single-resource-message"
BINDING_SINGLE_LIST = "single-list-message"
BINDING_UNBOUND = "unbound"

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
    token = text.split(",")[0].strip()
    try:
        return int(token, 0) if token.startswith(("0x", "0X")) else int(token)
    except ValueError as exc:
        raise InputError(f"{field} must be an integer") from exc


def optional_int(value: object) -> int | None:
    text = clean(value)
    if text is None:
        return None
    token = text.split(",")[0].strip()
    try:
        return int(token, 0) if token.startswith(("0x", "0X")) else int(token)
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

    TShark renders the Info column as a composite string when a frame carries
    SCTP acknowledgements, a nested NAS message name, or coalesced NGAP PDUs
    (for example ``SACK (Ack=1, Arwnd=106496) , DownlinkNASTransport,
    Authentication request``). A whole-string comparison therefore misses
    identities that are present verbatim as one delimited segment, so the
    reviewed vocabulary is also matched against the comma/bracket-delimited
    segments. Only exact segment equality resolves; substring matching is
    never used and no message name outside the reviewed table is produced.
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
            candidates = [observed_message]
            candidates.extend(
                segment.strip() for segment in re.split(r"[,\[\]]", observed_message)
            )
            for candidate in candidates:
                for candidate_pdu, candidate_message in messages.items():
                    if candidate == candidate_message:
                        message_type = candidate_message
                        pdu_type = candidate_pdu
                        basis = "message-name"
                        derivations.extend(["message_type", "pdu_type"])
                        break
                if message_type is not None:
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


def repeated_tokens(value: object) -> list[str]:
    """Ordered tokens from a repeated field (comma-joined text or JSON array).

    A repeated dissector field is exported comma-joined; structured input may
    pass a JSON array. Order and duplicates are preserved.
    """
    if value is None:
        return []
    items = [str(item) for item in value] if isinstance(value, (list, tuple)) else str(value).split(",")
    return [token.strip() for token in items if token.strip()]


def repeated_ints(value: object) -> list[int]:
    result: list[int] = []
    for token in repeated_tokens(value):
        try:
            result.append(int(token))
        except ValueError as exc:
            raise InputError("repeated numeric field must contain integers") from exc
    return result


def optional_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes"}:
        return True
    if text in {"0", "false", "no"}:
        return False
    raise InputError("boolean field must be true/false or 0/1")


def byte_length(raw: str | None) -> int | None:
    """Octet length of an exported byte sequence; the bytes are never kept."""
    if raw is None:
        return None
    digits = raw.replace(":", "").replace(" ", "")
    return len(digits) // 2 if digits else 0


def transfer_metadata(record: dict[str, object]) -> dict[str, object]:
    """Presence, reviewed kind, and length of observed transfer containers."""
    kinds: list[str] = []
    total = 0
    for field, kind in TRANSFER_FIELDS.items():
        raw = clean(record.get(field))
        if raw is None:
            continue
        if kind not in kinds:
            kinds.append(kind)
        length = byte_length(raw)
        total += length if length is not None else 0
    if not kinds:
        return {"present": False, "kind": None, "length": None}
    return {"present": True, "kind": kinds[0] if len(kinds) == 1 else "multiple", "length": total}


def mobility_metadata(
    record: dict[str, object], procedure_code: int, derivations: list[str]
) -> dict[str, object]:
    """Bounded protocol-local mobility metadata for one supported mobility message.

    Preserves only: the mobility procedure family, the observed HandoverType
    value with its reviewed symbolic name, TargetID presence with its
    reviewed choice alternative, and transparent-container presence and
    octet length. It never infers why a handover occurred, never decodes
    container content, and never produces a mobility verdict.
    """
    family = MOBILITY_FAMILIES.get(procedure_code)
    derivations.append("mobility_family")

    type_value: int | None = None
    type_name: str | None = None
    raw_type = clean(record.get("ngap.HandoverType"))
    if raw_type is not None:
        as_int = optional_int(raw_type)
        if as_int is not None:
            type_value = as_int
            type_name = HANDOVER_TYPE_NAMES.get(as_int)
            if type_name is not None:
                derivations.append("handover_type_name")
        elif raw_type in HANDOVER_TYPE_NAMES.values():
            type_name = raw_type

    target_present = False
    target_type: str | None = None
    raw_target = clean(record.get("ngap.TargetID"))
    if raw_target is not None:
        target_present = True
        as_int = optional_int(raw_target)
        if as_int is not None:
            target_type = TARGET_ID_TYPES.get(as_int)
            if target_type is not None:
                derivations.append("target_id_type")
        else:
            target_type = raw_target

    containers: dict[str, object] = {}
    for field, key in MOBILITY_CONTAINER_FIELDS:
        raw = clean(record.get(field))
        containers[key] = {"present": raw is not None, "length": byte_length(raw)}
    return {
        "family": family,
        "handover_type_value": type_value,
        "handover_type_name": type_name,
        "target_id_present": target_present,
        "target_id_type": target_type,
        **containers,
    }


def _empty_item(session_id: int, operation: str | None, role: str | None, basis: str) -> dict[str, object]:
    return {
        "pdu_session_id": session_id,
        "resource_operation": operation,
        "resource_list_role": role,
        "snssai": {"sst": None, "sd": None},
        "nas_pdu_present": False,
        "nas_pdu_length": None,
        "transfer": {"present": False, "kind": None, "length": None},
        "qfi_values": [],
        "cause": None,
        "binding_basis": basis,
    }


def _structured_items(record: dict[str, object]) -> list[dict[str, object]] | None:
    """Parse the explicit structured resource array (hierarchy preserved)."""
    raw = record.get("pdu_session_resources")
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise InputError("pdu_session_resources must be an array")
    items: list[dict[str, object]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise InputError("each pdu_session_resources entry must be an object")
        session_id = optional_int(entry.get("pdu_session_id"))
        if session_id is None:
            raise InputError("resource item requires pdu_session_id")
        if not 0 <= session_id <= 255:
            raise InputError("resource pdu_session_id must be within 0..255")
        operation = clean(entry.get("resource_operation"))
        if operation is not None and operation not in RESOURCE_OPERATIONS:
            raise InputError("resource_operation must be a reviewed operation")
        role = clean(entry.get("resource_list_role"))
        if role is not None and role not in RESOURCE_LIST_ROLES:
            raise InputError("resource_list_role must be a reviewed role")
        sst = optional_int(entry.get("snssai_sst"))
        if sst is not None and not 0 <= sst <= 255:
            raise InputError("snssai_sst must be within 0..255")
        cause = None
        cause_category = clean(entry.get("cause_category"))
        cause_value = entry.get("cause_value")
        if cause_category is not None or cause_value is not None:
            cause = {
                "category": cause_category,
                "value": optional_int(cause_value) if cause_value is not None else None,
            }
        nas_present = optional_bool(entry.get("nas_pdu_present"))
        nas_length = optional_int(entry.get("nas_pdu_length"))
        if nas_present is None:
            nas_present = nas_length is not None
        items.append({
            "pdu_session_id": session_id,
            "resource_operation": operation,
            "resource_list_role": role,
            "snssai": {"sst": sst, "sd": clean(entry.get("snssai_sd"))},
            "nas_pdu_present": bool(nas_present),
            "nas_pdu_length": nas_length if nas_present else None,
            "transfer": {
                "present": bool(optional_bool(entry.get("transfer_present"))),
                "kind": clean(entry.get("transfer_kind")),
                "length": optional_int(entry.get("transfer_length")),
            },
            "qfi_values": repeated_ints(entry.get("qfi_values")),
            "cause": cause,
            "binding_basis": BINDING_STRUCTURED,
        })
    return items


def resolve_pdu_session_resources(
    record: dict[str, object], message_type: str | None
) -> tuple[list[dict[str, object]] | None, dict[str, object] | None]:
    """Derive PDU Session resource items and unbound nested metadata.

    Items come from the explicit structured array when present. Otherwise
    flattened dissector fields are used only when the binding is provable:
    a single observed resource list attributes every PDU session identity to
    that list, and nested QFI / NAS-PDU / transfer values are attached only
    when exactly one resource item exists. Everything else is preserved as
    unbound evidence rather than zipped by position.
    """
    structured = _structured_items(record)
    operation_default = RESOURCE_OPERATION_BY_MESSAGE.get(message_type) if message_type else None
    observed_lists = [
        (field, RESOURCE_LIST_FIELDS[field]) for field in RESOURCE_LIST_FIELDS if clean(record.get(field)) is not None
    ]
    flat_ids = repeated_ints(record.get("ngap.pDUSessionID"))
    flat_qfis = repeated_ints(record.get("ngap.qosFlowIdentifier"))
    flat_nas = clean(record.get("ngap.pDUSessionNAS_PDU"))
    flat_transfer = transfer_metadata(record)

    if structured is None and not observed_lists and not flat_ids and not flat_qfis and flat_nas is None:
        return None, None

    limitations: list[str] = []
    unbound_qfis: list[int] = []
    unbound_causes: list[dict[str, object]] = []
    unbound_ids: list[int] = []
    roles_observed: list[str] = []
    for _field, (_operation, role) in observed_lists:
        if role not in roles_observed:
            roles_observed.append(role)

    if structured is not None:
        items = structured
        for item in items:
            if item["resource_operation"] is None:
                item["resource_operation"] = operation_default
        bound_ids = {item["pdu_session_id"] for item in items}
        unbound_ids = [session_id for session_id in flat_ids if session_id not in bound_ids]
        if unbound_ids:
            limitations.append("structured resource items do not cover every observed PDU session identity")
    else:
        items = []
        distinct_roles = sorted({role for _field, (_operation, role) in observed_lists})
        if flat_ids and len(distinct_roles) == 1:
            role = distinct_roles[0]
            operation = observed_lists[0][1][0]
            for session_id in flat_ids:
                items.append(_empty_item(session_id, operation, role, BINDING_SINGLE_LIST))
        elif flat_ids:
            if len(distinct_roles) > 1:
                limitations.append(
                    "multiple resource lists observed; PDU session identities cannot be attributed to one list without structural evidence"
                )
            else:
                limitations.append("PDU session identities observed without a reviewed resource list indicator")
            for session_id in flat_ids:
                items.append(_empty_item(session_id, operation_default, None, BINDING_UNBOUND))
        elif distinct_roles:
            limitations.append("a resource list was observed but no PDU session identity was exported")

    # Nested flattened values (QFI / NAS-PDU / transfer) attach only when
    # exactly one parent resource item exists; they are never zipped by
    # position and never silently dropped. Structured items keep their
    # structured-input identity basis; list-derived items record the
    # single-resource-message basis when flattened values attach.
    if len(items) == 1:
        item = items[0]
        if flat_qfis:
            item["qfi_values"] = flat_qfis
        if flat_nas is not None:
            item["nas_pdu_present"] = True
            item["nas_pdu_length"] = byte_length(flat_nas)
        if flat_transfer["present"]:
            item["transfer"] = dict(flat_transfer)
        if structured is None and (flat_qfis or flat_nas is not None or flat_transfer["present"]):
            item["binding_basis"] = BINDING_SINGLE_ITEM
    else:
        if flat_qfis:
            unbound_qfis = list(flat_qfis)
            limitations.append("QFI values observed but not safely attributable to a specific PDU session resource item")
        if flat_nas is not None:
            limitations.append("a PDU session NAS-PDU was observed but not safely attributable to a specific resource item")
        if flat_transfer["present"]:
            limitations.append("transfer container(s) observed but not safely attributable to a specific resource item")

    explicit_unbound_qfis = repeated_ints(record.get("unbound_qfi_values"))
    for value in explicit_unbound_qfis:
        if value not in unbound_qfis:
            unbound_qfis.append(value)
    explicit_cause = record.get("unbound_cause")
    if isinstance(explicit_cause, dict):
        unbound_causes.append({
            "category": clean(explicit_cause.get("category")),
            "value": optional_int(explicit_cause.get("value")),
        })
    if unbound_qfis or unbound_causes:
        limitations.append("nested resource metadata observed without a provable parent resource item")

    for extra in repeated_tokens(record.get("unbound_limitations")):
        if extra not in limitations:
            limitations.append(extra)

    unbound: dict[str, object] | None = None
    if unbound_qfis or unbound_causes or unbound_ids or len(roles_observed) > 1 or limitations:
        unbound = {
            "qfi_values": unbound_qfis,
            "cause_values": unbound_causes,
            "pdu_session_ids": unbound_ids,
            "resource_list_roles": roles_observed,
            "limitations": limitations,
        }
    return items, unbound


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
    derivations = list(identity.derivations)
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
        "derivations": derivations,
    }
    if identity.support_status == "SUPPORTED" and procedure_code in MOBILITY_PROCEDURE_CODES:
        event["mobility"] = mobility_metadata(record, procedure_code, derivations)
        derivations.sort()
    if source is not None:
        event["source"] = source
    if destination is not None:
        event["destination"] = destination
    if sctp is not None:
        event["sctp"] = sctp
    resources, unbound = resolve_pdu_session_resources(record, identity.message_type)
    if resources is not None:
        event["pdu_session_resources"] = resources
    if unbound is not None:
        event["unbound_resource_metadata"] = unbound
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
    resources = event.get("pdu_session_resources")
    if isinstance(resources, list) and resources:
        session: dict[str, object] = {}
        session_ids = [
            item["pdu_session_id"]
            for item in resources
            if isinstance(item, dict) and item.get("pdu_session_id") is not None
        ]
        if len(session_ids) == 1:
            session["pdu_session_id"] = session_ids[0]
        bound_qfis: list[int] = []
        for item in resources:
            if isinstance(item, dict) and isinstance(item.get("qfi_values"), list):
                bound_qfis.extend(item["qfi_values"])
        if len(bound_qfis) == 1:
            session["qfi"] = bound_qfis[0]
        if session:
            projected["session"] = session
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


def resolve_tshark_executable() -> str:
    found = shutil.which("tshark")
    if found:
        return found
    if sys.platform == "win32":
        for candidate in (r"D:\Wireshark\tshark.exe", r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe"):
            if Path(candidate).is_file():
                return candidate
    return "tshark"


_AVAILABLE_FIELDS_OVERRIDE: set[str] | None = None
_AVAILABLE_PROTOCOLS_OVERRIDE: set[str] | None = None
_AVAILABLE_FIELDS_CACHE: set[str] | None = None
_AVAILABLE_PROTOCOLS_CACHE: set[str] | None = None


def set_discovery_overrides(fields: set[str] | None = None, protocols: set[str] | None = None) -> None:
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
        proc = subprocess.run([exe, "-G", "fields"], capture_output=True, encoding="utf-8", errors="replace", check=False)
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
        proc = subprocess.run([exe, "-G", "protocols"], capture_output=True, encoding="utf-8", errors="replace", check=False)
        if proc.returncode == 0 and proc.stdout:
            protos = set()
            for line in proc.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3:
                    protos.add(parts[2])
            _AVAILABLE_PROTOCOLS_CACHE = protos
            return protos
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def resolve_filter(candidates: tuple[str, ...], available_protocols: set[str] | None) -> str:
    if available_protocols is not None:
        for cand in candidates:
            if cand in available_protocols:
                return cand
        raise TsharkError(f"tshark compatibility error: none of the protocol filter candidates {candidates} are supported by installed TShark")
    return candidates[0]


def resolve_field_specs(
    specs: tuple[FieldSpec, ...],
    available_fields: set[str] | None,
    tshark_ver: str,
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
        completed = subprocess.run([exe, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown tshark failure"
        raise TsharkError(f"tshark --version failed: {detail}")
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "tshark (version unavailable)"


def build_tshark_fields_command(
    capture: Path,
    mappings: list[tuple[str, str]] | None = None,
    display_filter: str = "ngap",
) -> list[str]:
    """Build the bounded field-extraction command.

    ``occurrence=a`` exports every occurrence of a repeated field
    comma-joined, so multiple PDU Session resources and QFI values are never
    truncated to the first occurrence; single-occurrence fields are
    unaffected.
    """
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
        raise TsharkError(f"tshark returned unexpected field header: expected {expected_headers}, got {header}: {stderr}")
    for row in reader:
        if len(row) > len(mappings):
            raise TsharkError("tshark returned more columns than the requested NGAP field set")
        padded = row + [""] * (len(mappings) - len(row))
        record = {canonical: padded[i] for i, (_, canonical) in enumerate(mappings)}
        for opt in unresolved_optional:
            record[opt] = ""
        yield record
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
