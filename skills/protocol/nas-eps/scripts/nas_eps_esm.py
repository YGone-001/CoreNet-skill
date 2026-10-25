#!/usr/bin/env python3
"""Bounded EPS Session Management (ESM) evidence for the NAS-EPS Protocol Skill.

Message identities and cause values below were reviewed against 3GPP TS 24.301
§9.3 (ESM message types) and §9.9.4.4 (ESM cause values), and verified against
the TShark NAS-EPS dissector value tables (`tshark -G values` for
`nas-eps.nas_msg_esm_type` and `nas-eps.esm.cause`).

ESM messages are read from a PDML dissection, because only the dissector tree
proves which ESM message belongs to which ESM container inside which enclosing
NAS message. Flat field input is published as explicitly unbound: it can prove
that an ESM message identity was decoded, but not its container or its order
relative to another ESM message.

Only reviewed, non-identifying fields are published. The ESM container bytes, the
APN name, the assigned PDN address, subscriber identities and authentication
parameters are never retained.
"""

from __future__ import annotations

import xml.etree.ElementTree as ElementTree
from typing import Any, Iterable

# Reviewed TS 24.301 §9.3 ESM message identities, verified against the decoder
# value table for nas-eps.nas_msg_esm_type.
KNOWN_ESM_MESSAGES = {
    193: "Activate default EPS bearer context request",
    194: "Activate default EPS bearer context accept",
    195: "Activate default EPS bearer context reject",
    197: "Activate dedicated EPS bearer context request",
    198: "Activate dedicated EPS bearer context accept",
    199: "Activate dedicated EPS bearer context reject",
    201: "Modify EPS bearer context request",
    202: "Modify EPS bearer context accept",
    203: "Modify EPS bearer context reject",
    205: "Deactivate EPS bearer context request",
    206: "Deactivate EPS bearer context accept",
    208: "PDN connectivity request",
    209: "PDN connectivity reject",
    210: "PDN disconnect request",
    211: "PDN disconnect reject",
    212: "Bearer resource allocation request",
    213: "Bearer resource allocation reject",
    214: "Bearer resource modification request",
    215: "Bearer resource modification reject",
    217: "ESM information request",
    218: "ESM information response",
    219: "Notification",
    220: "ESM dummy message",
    232: "ESM status",
    233: "Remote UE report",
    234: "Remote UE report response",
    235: "ESM data transport",
}

# Bounded support: default-bearer establishment and the ESM information exchange.
SUPPORTED_ESM_MESSAGES = frozenset({193, 194, 195, 208, 209, 217, 218, 232})

ESM_PROCEDURE = {
    208: "pdn-connectivity",
    209: "pdn-connectivity",
    193: "default-bearer-activation",
    194: "default-bearer-activation",
    195: "default-bearer-activation",
    217: "esm-information",
    218: "esm-information",
    232: "esm-status",
}

# Local normalized role labels (not 3GPP wire values).
ESM_RESULTS = {
    193: "REQUEST",
    194: "ACCEPT",
    195: "REJECT",
    197: "REQUEST",
    198: "ACCEPT",
    199: "REJECT",
    201: "REQUEST",
    202: "ACCEPT",
    203: "REJECT",
    205: "REQUEST",
    206: "ACCEPT",
    208: "REQUEST",
    209: "REJECT",
    210: "REQUEST",
    211: "REJECT",
    212: "REQUEST",
    213: "REJECT",
    214: "REQUEST",
    215: "REJECT",
    217: "REQUEST",
    218: "RESPONSE",
    232: "STATUS",
}

# Reviewed TS 24.301 §9.9.4.4 ESM cause values, verified against the decoder
# value table for nas-eps.esm.cause.
ESM_CAUSES = {
    8: "Operator Determined Barring",
    26: "Insufficient resources",
    27: "Missing or unknown APN",
    28: "Unknown PDN type",
    29: "User authentication failed",
    30: "Request rejected by Serving GW or PDN GW",
    31: "Request rejected, unspecified",
    32: "Service option not supported",
    33: "Requested service option not subscribed",
    34: "Service option temporarily out of order",
    35: "PTI already in use",
    36: "Regular deactivation",
    37: "EPS QoS not accepted",
    38: "Network failure",
    39: "Reactivation requested",
    41: "Semantic error in the TFT operation",
    42: "Syntactical error in the TFT operation",
    43: "Invalid EPS bearer identity",
    44: "Semantic errors in packet filter(s)",
    45: "Syntactical errors in packet filter(s)",
    46: "Unused",
    47: "PTI mismatch",
    49: "Last PDN disconnection not allowed",
    50: "PDN type IPv4 only allowed",
    51: "PDN type IPv6 only allowed",
    52: "Single address bearers only allowed",
    53: "ESM information not received",
    54: "PDN connection does not exist",
    55: "Multiple PDN connections for a given APN not allowed",
    56: "Collision with network initiated request",
    57: "PDN type IPv4v6 only allowed",
    58: "PDN type non IP only allowed",
    59: "Unsupported QCI value",
    60: "Bearer handling not supported",
    61: "PDN type Ethernet only allowed",
    65: "Maximum number of EPS bearers reached",
    66: "Requested APN not supported in current RAT and PLMN combination",
    81: "Invalid PTI value",
    95: "Semantically incorrect message",
    96: "Invalid mandatory information",
    97: "Message type non-existent or not implemented",
    98: "Message type not compatible with the protocol state",
    99: "Information element non-existent or not implemented",
    100: "Conditional IE error",
    101: "Message not compatible with the protocol state",
    111: "Protocol error, unspecified",
    112: "APN restriction value incompatible with active EPS bearer context",
    113: "Multiple accesses to a PDN connection not allowed",
}

# Reviewed TS 24.301 §9.9.4.13 PDN type values.
PDN_TYPES = {1: "IPv4", 2: "IPv6", 3: "IPv4v6", 4: "non-IP", 5: "Ethernet"}

# Reviewed TS 24.301 §9.9.4.14 Request type values.
REQUEST_TYPES = {
    1: "initial request",
    2: "handover",
    3: "unassigned/unused",
    4: "emergency",
    5: "existing bearer",
    6: "continuous PDN connectivity",
}

# Structural IE labels used to decide which optional ESM information elements
# are present. Only the presence boolean is published; never the IE value.
_PDN_ADDRESS_LABELS = ("PDN address", "PDN address and prefix")
_QOS_LABELS = ("EPS quality of service",)
_PCO_LABELS = ("Protocol configuration options",)

APN_FIELD = "gsm_a.gm.sm.apn"
PDN_ADDRESS_FIELDS = ("nas-eps.esm.pdn_ipv4", "nas-eps.esm.pdn_ipv6_if_id")
PDN_ADDRESS_FAMILY = {
    "nas-eps.esm.pdn_ipv4": "IPv4",
    "nas-eps.esm.pdn_ipv6_if_id": "IPv6",
}

# EMM message names needed only to describe the enclosing NAS message of an ESM
# container. Kept local so this module stays standalone; the authoritative table
# belongs to the NAS-EPS model.
EMM_CONTAINER_NAMES = {
    65: "Attach request",
    66: "Attach accept",
    67: "Attach complete",
    68: "Attach reject",
    98: "Downlink NAS transport",
    99: "Uplink NAS transport",
}

# Fields that end an ESM segment: any EMM information element that follows the
# ESM container belongs to the enclosing EMM message, not to the ESM message.
_EMM_FIELD_PREFIX = "nas-eps.emm."


def parse_number(value: object) -> int | None:
    """Parse a decoder value that may be decimal or hexadecimal."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    text = text.split(",")[0].strip()
    try:
        return int(text, 0)
    except ValueError:
        return None


def _field_entries(element: ElementTree.Element) -> Iterable[tuple[str, str, str]]:
    """Yield (field name, show value, showname) in dissector document order."""
    for node in element.iter("field"):
        name = node.get("name") or ""
        yield name, node.get("show") or "", node.get("showname") or ""


def _segment_fields(entries: list[tuple[str, str, str]]) -> list[list[tuple[str, str, str]]]:
    """Split a NAS dissection into ESM messages at each EPS bearer identity field.

    An ESM message always starts with the EPS bearer identity octet of its header,
    so the identity field is a structural message boundary inside the dissector
    tree. A segment ends at the next boundary or at the first EMM information
    element, which belongs to the enclosing EMM message.
    """
    segments: list[list[tuple[str, str, str]]] = []
    current: list[tuple[str, str, str]] | None = None
    for entry in entries:
        name = entry[0]
        if name == "nas-eps.bearer_id":
            current = [entry]
            segments.append(current)
            continue
        if current is None:
            continue
        if name.startswith(_EMM_FIELD_PREFIX):
            current = None
            continue
        current.append(entry)
    return segments


def _labels(segment: list[tuple[str, str, str]]) -> list[str]:
    """Structural IE labels inside one ESM message.

    The dissector renders an information element as an unnamed node whose label
    sits in either the `show` or the `showname` attribute depending on the
    Wireshark version, so both are read. Only the label is used; an IE value is
    never republished.
    """
    labels: list[str] = []
    for name, show, showname in segment:
        if name:
            continue
        label = (show or showname).strip()
        if label:
            labels.append(label)
    return labels


def _esm_item(
    segment: list[tuple[str, str, str]],
    *,
    occurrence: int,
    capture_file: str,
    frame_number: int,
    container: dict[str, Any],
    protection_state: str | None,
    protection_state_basis: str,
    direction: str | None,
    direction_basis: str,
    binding_basis: str,
    evidence_source: str,
) -> dict[str, Any] | None:
    fields: dict[str, str] = {}
    for name, show, _showname in segment:
        fields.setdefault(name, show)
    code = parse_number(fields.get("nas-eps.nas_msg_esm_type"))
    if code is None:
        return None
    labels = _labels(segment)
    apn_present = APN_FIELD in fields
    apn_length = len(fields[APN_FIELD]) if apn_present else None
    address_field = next((name for name in PDN_ADDRESS_FIELDS if name in fields), None)
    pdn_address_present = address_field is not None or any(
        label in _PDN_ADDRESS_LABELS for label in labels
    )
    family = PDN_ADDRESS_FAMILY.get(address_field) if address_field else None
    qos_present = "nas-eps.esm.qci" in fields or any(label in _QOS_LABELS for label in labels)
    pco_present = any(
        label.startswith(_PCO_LABELS[0]) for label in labels
    )
    cause_value = parse_number(fields.get("nas-eps.esm.cause"))
    pdn_type_value = parse_number(fields.get("nas-eps.esm_pdn_type"))
    request_type_value = parse_number(fields.get("nas-eps.esm_request_type"))
    name = KNOWN_ESM_MESSAGES.get(code)
    support = "UNSUPPORTED"
    if name is None:
        support = "UNKNOWN"
    elif code in SUPPORTED_ESM_MESSAGES:
        support = "SUPPORTED"
    limitations: list[str] = []
    if binding_basis != "pdml_grouped_ie":
        limitations.append(
            "flat field input cannot prove the ESM container boundary or the message order "
            "inside one NAS message"
        )
    if apn_present:
        limitations.append("only APN presence and length are published; the APN name is never retained")
    if pdn_address_present:
        limitations.append(
            "only PDN address presence and family are published; the assigned address is never retained"
        )
    return {
        "occurrence_index": occurrence,
        "message_type_code": code,
        "message_type": name,
        "support_status": support,
        "procedure": ESM_PROCEDURE.get(code),
        "result": ESM_RESULTS.get(code),
        "eps_bearer_identity": parse_number(fields.get("nas-eps.bearer_id")),
        "procedure_transaction_identity": parse_number(fields.get("nas-eps.proc_trans_id"))
        or parse_number(fields.get("nas-eps.esm.proc_trans_id")),
        "esm_cause": (
            {"value": cause_value, "name": ESM_CAUSES.get(cause_value)}
            if cause_value is not None
            else None
        ),
        "pdn_type": (
            {"value": pdn_type_value, "name": PDN_TYPES.get(pdn_type_value)}
            if pdn_type_value is not None
            else None
        ),
        "request_type": (
            {"value": request_type_value, "name": REQUEST_TYPES.get(request_type_value)}
            if request_type_value is not None
            else None
        ),
        "apn_present": apn_present,
        "apn_length": apn_length,
        "pdn_address_present": pdn_address_present,
        "pdn_address_family": family,
        "qos_present": qos_present,
        "pco_present": pco_present,
        "information_element_count": len(labels),
        "container": container,
        "protection_state": protection_state,
        "protection_state_basis": protection_state_basis,
        "direction": direction,
        "direction_basis": direction_basis,
        "binding_basis": binding_basis,
        "frame_number": frame_number,
        "capture_file": capture_file,
        "evidence": {"level": "OBSERVED", "source": evidence_source},
        "limitations": limitations,
    }


def pdml_esm_index(xml_text: str, capture_file: str) -> dict[int, list[dict[str, Any]]]:
    """Extract ESM messages per frame from a PDML dissection.

    The enclosing NAS message, the ESM container presence and the message order
    all come from the dissector tree, so a published ESM message is always tied
    to a provable container rather than to a list position.
    """
    index: dict[int, list[dict[str, Any]]] = {}
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:  # pragma: no cover - defensive
        raise ValueError(f"PDML dissection is not well-formed XML: {exc}") from exc
    for packet in root.findall("packet"):
        frame_number = None
        for name, show, _showname in _field_entries(packet):
            if name == "frame.number":
                frame_number = parse_number(show)
                break
        if frame_number is None:
            continue
        for proto in packet.iter("proto"):
            if proto.get("name") != "nas-eps":
                continue
            entries = list(_field_entries(proto))
            if not entries:
                continue
            protection = next(
                (show for name, show, _showname in entries if name == "nas-eps.security_header_type"),
                None,
            )
            emm_type = None
            for name, show, _showname in entries:
                if name == "nas-eps.nas_msg_emm_type":
                    emm_type = parse_number(show)
            saw_container = any(name == "nas-eps.emm.esm_msg_cont" for name, _s, _n in entries)
            container_kind = "esm_message_container" if saw_container else "standalone"
            for occurrence, segment in enumerate(_segment_fields(entries)):
                container = {
                    "kind": container_kind,
                    "enclosing_emm_message_type_code": emm_type,
                    "enclosing_emm_message_type": EMM_CONTAINER_NAMES.get(emm_type) if emm_type else None,
                    "frame_number": frame_number,
                    "basis": "pdml_esm_container_ie" if saw_container else "pdml_standalone_esm",
                }
                source = f"capture:{capture_file}#frame={frame_number}; esm-occurrence={occurrence}"
                item = _esm_item(
                    segment,
                    occurrence=occurrence,
                    capture_file=capture_file,
                    frame_number=frame_number,
                    container=container,
                    protection_state=protection,
                    protection_state_basis="outermost_nas_security_header",
                    direction=None,
                    direction_basis="enclosing_s1ap_procedure",
                    binding_basis="pdml_grouped_ie",
                    evidence_source=source,
                )
                if item is not None:
                    index.setdefault(frame_number, []).append(item)
    return index


def flat_esm_messages(
    record: dict[str, object], capture_file: str
) -> list[dict[str, Any]]:
    """ESM messages readable from a flat field record, explicitly unbound."""
    raw = record.get("nas-eps.nas_msg_esm_type")
    if raw is None:
        return []
    text = str(raw).strip()
    if not text:
        return []
    codes = [parse_number(part) for part in text.split(",")]
    frame_number = parse_number(record.get("frame.number")) or 0
    items: list[dict[str, Any]] = []
    for occurrence, code in enumerate(code for code in codes if code is not None):
        segment: list[tuple[str, str, str]] = [
            ("nas-eps.bearer_id", str(record.get("nas-eps.bearer_id") or ""), ""),
            ("nas-eps.esm.proc_trans_id", str(record.get("nas-eps.esm.proc_trans_id") or ""), ""),
            ("nas-eps.nas_msg_esm_type", str(code), ""),
        ]
        for optional in (
            "nas-eps.esm.cause",
            "nas-eps.esm_pdn_type",
            "nas-eps.esm_request_type",
            "nas-eps.esm.qci",
        ):
            value = record.get(optional)
            if value is not None and str(value).strip():
                segment.append((optional, str(value), ""))
        item = _esm_item(
            segment,
            occurrence=occurrence,
            capture_file=capture_file,
            frame_number=frame_number,
            container={
                "kind": "unbound",
                "enclosing_emm_message_type_code": parse_number(record.get("nas-eps.nas_msg_emm_type")),
                "enclosing_emm_message_type": None,
                "frame_number": frame_number,
                "basis": "flat_fields",
            },
            protection_state=None,
            protection_state_basis="unavailable",
            direction=None,
            direction_basis="unavailable",
            binding_basis="flat_fields",
            evidence_source=f"capture:{capture_file}#frame={frame_number}; esm-occurrence={occurrence}",
        )
        if item is not None:
            items.append(item)
    return items
