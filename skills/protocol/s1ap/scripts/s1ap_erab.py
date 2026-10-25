#!/usr/bin/env python3
"""Bounded S1AP E-RAB item evidence for Initial Context Setup.

Field names and the E-RAB item hierarchy below were reviewed against the S1AP
dissector of Wireshark/TShark 4.7.1 (`tshark -G fields`) and 3GPP TS 36.413
§9.1.4 (E-RABToBeSetupItemCtxtSUReq) and §9.1.5 (E-RABSetupItemCtxtSURes).

An E-RAB item is read from a PDML dissection so that the E-RAB identity, the QoS
parameters, the transport layer address and the GTP-TEID of one item stay bound
to that item. Flat repeated fields cannot prove the item boundary, so they are
published as explicitly unbound evidence instead of being paired by list order.

The transport layer address and GTP-TEID published here are the S1-U endpoint
that the eNodeB was told to use (or that it admitted). They are control-plane
provisioning evidence, never proof that a GTP-U tunnel forwards user traffic.
"""

from __future__ import annotations

import xml.etree.ElementTree as ElementTree
from typing import Any, Iterable

# Reviewed item element names for the bounded Initial Context Setup scope. The
# endpoint role is fixed by TS 36.413 message semantics: both lists carry the
# eNodeB's own S1-U transport endpoint.
ERAB_ITEM_FIELDS = {
    "s1ap.E_RABToBeSetupItemCtxtSUReq_element": ("INITIAL_CONTEXT_SETUP", "REQUEST"),
    "s1ap.E_RABSetupItemCtxtSURes_element": ("INITIAL_CONTEXT_SETUP", "SUCCESS"),
}

ERAB_LIST_FIELDS = {
    "s1ap.E_RABToBeSetupListCtxtSUReq": ("INITIAL_CONTEXT_SETUP", "REQUEST"),
    "s1ap.E_RABSetupListCtxtSURes": ("INITIAL_CONTEXT_SETUP", "SUCCESS"),
}

ENDPOINT_ROLE = "enodeb_s1u"
ENDPOINT_ROLE_BASIS = "message_identity"

# The installed decoder exposes no standalone failed-to-setup E-RAB list for the
# Initial Context Setup Response, so a failed item cannot be extracted even when
# the peer signalled one.
FAILED_ITEM_LIMITATION = (
    "the installed decoder exposes no failed-to-setup E-RAB list for this message, "
    "so a failed item is not extracted"
)


def parse_number(value: object) -> int | None:
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


def teid_value(hex_text: str | None) -> int | None:
    """GTP-TEID octets rendered by the dissector, as an integer."""
    if not hex_text:
        return None
    compact = hex_text.replace(":", "").replace(" ", "").strip()
    if not compact or len(compact) > 8:
        return None
    try:
        return int(compact, 16)
    except ValueError:
        return None


def transport_address(hex_text: str | None) -> tuple[str | None, str | None]:
    """Dotted-quad form of a 32-bit transport layer address."""
    if not hex_text:
        return None, None
    compact = hex_text.replace(":", "").replace(" ", "").strip()
    if len(compact) == 8:
        try:
            octets = [int(compact[index : index + 2], 16) for index in range(0, 8, 2)]
        except ValueError:
            return None, None
        return ".".join(str(octet) for octet in octets), "IPv4"
    return None, None


def _direct_fields(element: ElementTree.Element) -> dict[str, str]:
    """Fields of one item, without descending into a nested item."""
    values: dict[str, str] = {}

    def walk(node: ElementTree.Element) -> None:
        for child in node:
            if child.tag != "field":
                continue
            name = child.get("name") or ""
            if name in ERAB_ITEM_FIELDS:
                continue
            if name and name not in values:
                values[name] = child.get("show") or ""
            walk(child)

    walk(element)
    return values


def _items_in_packet(packet: ElementTree.Element, capture_file: str, frame: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for proto in packet.iter("proto"):
        if proto.get("name") != "s1ap":
            continue
        for element in proto.iter("field"):
            name = element.get("name") or ""
            if name not in ERAB_ITEM_FIELDS:
                continue
            operation, role = ERAB_ITEM_FIELDS[name]
            fields = _direct_fields(element)
            address, family = transport_address(fields.get("s1ap.transportLayerAddress"))
            if address is None:
                address = fields.get("s1ap.transportLayerAddressIPv4") or None
                family = "IPv4" if address else None
            limitations: list[str] = []
            if address is None and "s1ap.transportLayerAddressIPv6" in fields:
                limitations.append(
                    "the transport layer address is IPv6; only the IPv4 form is published"
                )
            item: dict[str, Any] = {
                "operation": operation,
                "list_role": role,
                "item_index": len(items),
                "erab_id": parse_number(fields.get("s1ap.e_RAB_ID")),
                "qci": parse_number(fields.get("s1ap.qCI")),
                "arp_present": "s1ap.allocationRetentionPriority_element" in fields,
                "transport_layer_address": address,
                "transport_layer_address_family": family,
                "gtp_teid": teid_value(fields.get("s1ap.gTP_TEID")),
                "gtp_teid_hex": (fields.get("s1ap.gTP_TEID") or "").replace(":", "").lower() or None,
                "endpoint_role": ENDPOINT_ROLE,
                "endpoint_role_basis": ENDPOINT_ROLE_BASIS,
                "binding_basis": "pdml_grouped_ie",
                "frame_number": frame,
                "capture_file": capture_file,
                "limitations": limitations,
            }
            items.append(item)
    return items


def pdml_erab_dissection(
    xml_text: str, capture_file: str
) -> tuple[dict[int, list[dict[str, Any]]], set[int]]:
    """E-RAB items per frame plus the frames that carry a nested NAS layer.

    An Initial Context Setup Request carries its NAS-PDU inside the E-RAB item
    rather than in a message-level NAS-PDU field, so a frame-level flag is needed
    to tell "this message carries NAS" from "this message has a top-level NAS-PDU".
    """
    index: dict[int, list[dict[str, Any]]] = {}
    nas_frames: set[int] = set()
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:  # pragma: no cover - defensive
        raise ValueError(f"PDML dissection is not well-formed XML: {exc}") from exc
    for packet in root.findall("packet"):
        frame = None
        for node in packet.iter("field"):
            if (node.get("name") or "") == "frame.number":
                frame = parse_number(node.get("show"))
                break
        if frame is None:
            continue
        if any(proto.get("name") == "nas-eps" for proto in packet.iter("proto")):
            nas_frames.add(frame)
        items = _items_in_packet(packet, capture_file, frame)
        if items:
            index[frame] = items
    return index, nas_frames


def unbound_erab_evidence(record: dict[str, object]) -> dict[str, Any] | None:
    """E-RAB list presence without a provable item boundary.

    Flat repeated fields cannot prove which E-RAB identity, QoS value or tunnel
    endpoint belongs to which item, so nothing is paired: the list presence and
    the observed identities stay explicitly unbound.
    """
    roles = [
        (field, role)
        for field, (_operation, role) in ERAB_LIST_FIELDS.items()
        if str(record.get(field) or "").strip()
    ]
    if not roles:
        return None
    identities: list[int] = []
    raw = record.get("s1ap.e_RAB_ID")
    if raw is not None:
        for part in str(raw).split(","):
            value = parse_number(part)
            if value is not None:
                identities.append(value)
    return {
        "list_roles": [role for _field, role in roles],
        "erab_ids": identities,
        "reason": (
            "flat field input repeats the E-RAB identity, QoS and tunnel fields per message "
            "without an item boundary, so they are not paired"
        ),
        "binding_basis": "flat_fields",
    }


def flat_erab_items(record: dict[str, object], capture_file: str, frame: int) -> list[dict[str, Any]]:
    """Item list for flat input: identities only, never tunnel endpoints."""
    evidence = unbound_erab_evidence(record)
    if evidence is None:
        return []
    items: list[dict[str, Any]] = []
    for index, identifier in enumerate(evidence["erab_ids"]):
        role = evidence["list_roles"][0] if len(evidence["list_roles"]) == 1 else None
        items.append(
            {
                "operation": "INITIAL_CONTEXT_SETUP",
                "list_role": role,
                "item_index": index,
                "erab_id": identifier,
                "qci": None,
                "arp_present": None,
                "transport_layer_address": None,
                "transport_layer_address_family": None,
                "gtp_teid": None,
                "gtp_teid_hex": None,
                "endpoint_role": None,
                "endpoint_role_basis": "unavailable",
                "binding_basis": "flat_fields",
                "frame_number": frame,
                "capture_file": capture_file,
                "limitations": [
                    "the E-RAB item boundary is not provable from flat field input; "
                    "no QoS value or tunnel endpoint is attributed to this identity"
                ],
            }
        )
    return items
