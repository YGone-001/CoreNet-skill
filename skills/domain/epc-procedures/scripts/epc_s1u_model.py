#!/usr/bin/env python3
"""Shared helpers for bounded EPC S1-U GTP-U observation.

The model consumes already-extracted GTP-U events and directed stream summaries
plus the accepted EPS default-bearer analysis. It never decodes a capture, never
parses a GTP-U header and never publishes inner packet content.

Matching rule (3GPP TS 29.281 §4.4, TS 23.401 §5.3.2): a GTP-U TEID is meaningful
only in the context of the receiving endpoint, so a stream may be related to a
bearer only when its outer destination address and header TEID equal an explicitly
advertised S1-U receiving endpoint. An outer source address, a UDP port or a TEID
value alone never establishes bearer ownership.

An observed G-PDU proves packet visibility at the capture point only. It never
proves delivery to the UE, PDN connectivity success or application reachability.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

DOMAIN_NAME = "epc-procedures"
DOMAIN_VERSION = "0.4.0"
ANALYSIS_NAME = "epc-s1u-observation"
ANALYSIS_VERSION = "1.0.0"

EXIT_MALFORMED_INPUT = 5
EXIT_NO_STREAMS = 6
EXIT_OUTPUT_FAILURE = 7

# Reviewed S1-U receiving-endpoint roles. The role is fixed by the message that
# advertised the endpoint, never inferred from a transport address.
ROLE_ENODEB = "enodeb_s1u"
ROLE_SGW = "sgw_s1u"
S1U_ENDPOINT_ROLES = (ROLE_ENODEB, ROLE_SGW)

# GTPv2-C F-TEID interface type -> receiving-endpoint role (TS 29.274 §8.22).
INTERFACE_TYPE_ROLE = {1: ROLE_SGW, 0: ROLE_ENODEB}

# Reviewed interface type names, published only for a GTPv2-C advertisement.
INTERFACE_TYPE_NAMES = {
    1: "S1-U SGW GTP-U interface",
    0: "S1-U eNodeB GTP-U interface",
}

# An S1AP E-RAB item carries a transport address and a TEID, never a GTPv2-C
# interface type. S1AP-sourced evidence therefore publishes no interface type.
S1AP_INTERFACE_TYPE_BASIS = "s1ap_erab_item_advertises_no_gtpv2_interface_type"
GTPV2_INTERFACE_TYPE_BASIS = "gtpv2_f_teid_interface_type"

# Endpoint match is an observation; bearer ownership is a separate verdict.
MATCH_MATCHED = "MATCHED"
MATCH_NOT_MATCHED = "NOT_MATCHED"

# A GTP-U stream whose receiving endpoint matches an eNB endpoint is the downlink
# direction of the S1-U tunnel; a match on an SGW-U endpoint is the uplink
# direction. Direction is derived from the matched endpoint role only.
DIRECTION_BY_ROLE = {ROLE_ENODEB: "DOWNLINK", ROLE_SGW: "UPLINK"}

# Reviewed S1AP messages that advertise each role.
S1AP_MESSAGE_BY_LIST_ROLE = {
    "REQUEST": "InitialContextSetupRequest",
    "SUCCESS": "InitialContextSetupResponse",
}

INTERFACE_S1U = "S1_U_CANDIDATE"
INTERFACE_UNKNOWN = "UNKNOWN_USER_PLANE_INTERFACE"

ASSOCIATION_SUPPORTED = "SUPPORTED"
ASSOCIATION_AMBIGUOUS = "AMBIGUOUS"
ASSOCIATION_NOT_ESTABLISHED = "NOT_ESTABLISHED"
ASSOCIATION_STATUSES = (
    ASSOCIATION_SUPPORTED,
    ASSOCIATION_AMBIGUOUS,
    ASSOCIATION_NOT_ESTABLISHED,
)

OUTCOME_G_PDU = "G_PDU_OBSERVED"
OUTCOME_DIRECTED = "DIRECTED_TUNNEL_TRAFFIC_OBSERVED"
OUTCOME_PACKET_COUNT = "OBSERVED_PACKET_COUNT"
OUTCOME_BYTE_COUNT = "OBSERVED_BYTE_COUNT"
OUTCOMES = (OUTCOME_G_PDU, OUTCOME_DIRECTED, OUTCOME_PACKET_COUNT, OUTCOME_BYTE_COUNT)

DEVIATION_LIFECYCLE = "LIFECYCLE_ASSOCIATION_AMBIGUOUS"
DEVIATION_COMPETING = "COMPETING_BEARER_CANDIDATES"
DEVIATION_ENDPOINT_UNAVAILABLE = "S1U_ENDPOINT_EVIDENCE_UNAVAILABLE"
DEVIATION_UNBOUND = "STREAM_BEARER_ASSOCIATION_UNBOUND"
DEVIATION_ERROR_INDICATION = "ERROR_INDICATION_OBSERVED"
DEVIATION_TYPES = (
    DEVIATION_LIFECYCLE,
    DEVIATION_COMPETING,
    DEVIATION_ENDPOINT_UNAVAILABLE,
    DEVIATION_UNBOUND,
    DEVIATION_ERROR_INDICATION,
)

# Deviations that describe a protocol observation rather than an association gap.
OBSERVATION_DEVIATIONS = frozenset({DEVIATION_ERROR_INDICATION})

# Reviewed GTPv2-C F-TEID interface type for S1-U.
S1U_INTERFACE_TYPE = 1
REVIEWED_GTPV2_FAMILIES = frozenset(
    {"create-session", "modify-bearer", "delete-session", "release-access-bearers", "echo"}
)

NOT_CONFIRMED = (
    "an observed G-PDU establishes packet visibility at the capture point only; it does not "
    "prove that the UE received the packet",
    "a stream association means the receiving endpoint evidence supports the tunnel "
    "relationship; it does not establish bearer service delivery",
    "an Echo Response is not evidence that a particular bearer is delivering data",
    "an End Marker is not evidence that a PDN session has ended",
    "no packet loss is inferred from frame gaps, sequence values or a missing reverse direction",
    "no application reachability, PDN connectivity success or network-function blame is produced",
)

GLOBAL_BOUNDARY_NOTE = (
    "S1-U packet observations are not abnormal-boundary candidates in this phase; boundary "
    "selection stays with the per-subject EPC failure-boundary Orchestration."
)

MAX_STREAMS = 64
MAX_EVIDENCE_REFERENCES = 32
MAX_LIST_ITEMS = 32


class InputError(ValueError):
    """Raised when a supplied structured input cannot be normalized."""


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


def _window(frames: list[Any]) -> dict[str, int] | None:
    values = [frame for frame in frames if isinstance(frame, int) and not isinstance(frame, bool)]
    if not values:
        return None
    return {"start_frame": min(values), "end_frame": max(values)}


def _evidence_ref(protocol: str, frame: Any, message_type: Any) -> dict[str, Any]:
    return {
        "protocol": protocol,
        "frame_number": frame if isinstance(frame, int) and not isinstance(frame, bool) else None,
        "message_type": message_type if isinstance(message_type, str) else None,
        "evidence_level": "OBSERVED",
    }


def stream_reference(stream: dict[str, Any]) -> str:
    material = "|".join(
        str(stream.get(key))
        for key in ("capture_file", "outer_source", "outer_destination", "teid", "stream_key")
    )
    return f"epc-s1u-stream-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:10]}"


def endpoint_index(default_bearer: dict[str, Any] | None, gtpv2_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Advertised S1-U receiving endpoints with their owning diagnostic subject.

    The eNB-side endpoint comes from the accepted default-bearer analysis, whose
    E-RAB items are item-scoped. The SGW-U-side endpoint comes from GTPv2-C bearer
    F-TEIDs with the reviewed S1-U interface type, when that input is supplied.
    """
    endpoints: list[dict[str, Any]] = []
    if isinstance(default_bearer, dict):
        for instance in default_bearer.get("default_bearer_instances") or []:
            if not isinstance(instance, dict):
                continue
            context = instance.get("ue_context") if isinstance(instance.get("ue_context"), dict) else {}
            capture = context.get("capture_file")
            for item in instance.get("erab_items") or []:
                if not isinstance(item, dict):
                    continue
                if item.get("binding_basis") != "pdml_grouped_ie":
                    continue
                address = item.get("transport_layer_address")
                teid = item.get("gtp_teid")
                if not isinstance(address, str) or not isinstance(teid, int):
                    continue
                endpoints.append(
                    {
                        "capture_file": str(capture),
                        "address": address,
                        "teid": teid,
                        "role": item.get("endpoint_role"),
                        "role_basis": item.get("endpoint_role_basis"),
                        "subject_reference": instance.get("instance_reference"),
                        "subject_type": "EPS_DEFAULT_BEARER",
                        "frame_number": item.get("frame_number"),
                        "erab_id": item.get("erab_id"),
                        "source": "default_bearer_erab_item",
                        # Exact evidence provenance: an S1AP E-RAB item is an S1AP
                        # observation, never a GTPv2-C one.
                        "source_protocol": "S1AP",
                        "source_message_type": S1AP_MESSAGE_BY_LIST_ROLE.get(str(item.get("list_role"))),
                        "source_scope": "erab_item",
                        "interface_type": None,
                        "interface_type_name": None,
                        "interface_type_basis": S1AP_INTERFACE_TYPE_BASIS,
                    }
                )
    for event in gtpv2_events:
        if not isinstance(event, dict):
            continue
        if event.get("procedure_family") not in REVIEWED_GTPV2_FAMILIES:
            continue
        capture = str(event.get("capture_file"))
        for context in event.get("bearer_contexts") or []:
            if not isinstance(context, dict):
                continue
            for item in context.get("f_teids") or []:
                if not isinstance(item, dict):
                    continue
                if item.get("interface_type") not in INTERFACE_TYPE_ROLE:
                    continue
                address = item.get("ipv4")
                teid = item.get("teid")
                if not isinstance(address, str) or not isinstance(teid, int):
                    continue
                endpoints.append(
                    {
                        "capture_file": capture,
                        "address": address,
                        "teid": teid,
                        "role": INTERFACE_TYPE_ROLE.get(item.get("interface_type")),
                        "role_basis": "gtpv2_f_teid_interface_type",
                        "subject_reference": None,
                        "subject_type": None,
                        "frame_number": event.get("frame_number"),
                        "erab_id": None,
                        "source": "gtpv2_bearer_f_teid",
                        "source_protocol": "GTPv2-C",
                        "source_message_type": event.get("message_type"),
                        "source_scope": "bearer_f_teid",
                        "interface_type": item.get("interface_type"),
                        "interface_type_name": INTERFACE_TYPE_NAMES.get(item.get("interface_type")),
                        "interface_type_basis": GTPV2_INTERFACE_TYPE_BASIS,
                    }
                )
    return endpoints


def _single_value(values: Any) -> Any:
    """Return the one distinct non-null value, or None when values disagree."""
    distinct = {value for value in values if value is not None}
    return next(iter(distinct)) if len(distinct) == 1 else None


def _endpoint_key(endpoint: dict[str, Any]) -> tuple[str, str, int]:
    return endpoint["capture_file"], endpoint["address"], endpoint["teid"]


def _subject_owners(endpoints: list[dict[str, Any]]) -> dict[tuple[str, str, int], list[str]]:
    owners: dict[tuple[str, str, int], list[str]] = {}
    for endpoint in endpoints:
        reference = endpoint.get("subject_reference")
        if not isinstance(reference, str):
            continue
        bucket = owners.setdefault(_endpoint_key(endpoint), [])
        if reference not in bucket:
            bucket.append(reference)
    return owners


def _stream_matches(stream: dict[str, Any], endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Endpoints whose advertised receiving side equals this stream's destination."""
    capture = str(stream.get("capture_file"))
    destination = stream.get("outer_destination")
    teid = stream.get("teid")
    if not isinstance(destination, str) or not isinstance(teid, int):
        return []
    return [
        endpoint
        for endpoint in endpoints
        if endpoint["capture_file"] == capture
        and endpoint["address"] == destination
        and endpoint["teid"] == teid
        and endpoint.get("role") in S1U_ENDPOINT_ROLES
    ]


def _stream_tuple(stream: dict[str, Any]) -> tuple[str, str, str, int] | None:
    """Directed context key shared by a stream summary and its events.

    The key is derived from published fields only: capture identity, outer source,
    outer destination and header TEID. It is never a TEID alone.
    """
    capture = stream.get("capture_file")
    source = stream.get("outer_source")
    destination = stream.get("outer_destination")
    teid = stream.get("teid")
    if not isinstance(capture, str) or not isinstance(source, str) or not isinstance(destination, str):
        return None
    if not isinstance(teid, int) or isinstance(teid, bool):
        return None
    return capture, source, destination, teid


def _event_tuple(event: dict[str, Any]) -> tuple[str, str, str, int] | None:
    outer = event.get("outer") if isinstance(event.get("outer"), dict) else {}
    header = event.get("header") if isinstance(event.get("header"), dict) else {}
    return _stream_tuple(
        {
            "capture_file": event.get("capture_file"),
            "outer_source": outer.get("source_address"),
            "outer_destination": outer.get("destination_address"),
            "teid": header.get("teid"),
        }
    )


def build_stream(
    stream: dict[str, Any],
    endpoints: list[dict[str, Any]],
    owners: dict[tuple[str, str, int], list[str]],
    events_by_stream: dict[tuple[str, str, str, int], list[dict[str, Any]]],
) -> dict[str, Any]:
    reference = stream_reference(stream)
    matches = _stream_matches(stream, endpoints)
    competing_subjects: list[str] = []
    matched_subject: str | None = None
    matched_role: str | None = None
    matched_endpoint_frames: list[int] = []
    matched_endpoint_refs: list[dict[str, Any]] = []
    match_status = MATCH_MATCHED if matches else MATCH_NOT_MATCHED
    status = ASSOCIATION_NOT_ESTABLISHED
    basis = "no_advertised_s1u_receiving_endpoint_matches_this_stream"
    limitations: list[str] = []
    deviations: list[dict[str, Any]] = []

    if matches:
        candidate_subjects: list[str] = []
        for match in matches:
            owner_list = owners.get(_endpoint_key(match), [])
            for owner in owner_list:
                if owner not in candidate_subjects:
                    candidate_subjects.append(owner)
            frame = match.get("frame_number")
            if isinstance(frame, int):
                matched_endpoint_frames.append(frame)
            # Exact provenance: the reference names the protocol and message that
            # actually advertised this receiving endpoint.
            matched_endpoint_refs.append(
                _evidence_ref(
                    match.get("source_protocol") or "unknown",
                    frame,
                    match.get("source_message_type"),
                )
            )
        roles = {match.get("role") for match in matches if match.get("role")}
        distinct_endpoints = {(_endpoint_key(match), match.get("role")) for match in matches}
        if len(roles) > 1:
            # Two incompatible receiving roles cannot describe one directed stream.
            status = ASSOCIATION_AMBIGUOUS
            basis = "incompatible_endpoint_roles_match_this_stream"
            matched_role = None
            limitations.append(
                "receiving endpoints of different reviewed roles match this stream, so neither the "
                "direction nor a single bearer allocation is selected"
            )
            deviations.append(DEVIATION_COMPETING)
        elif len(distinct_endpoints) > 1:
            status = ASSOCIATION_AMBIGUOUS
            basis = "several_advertised_s1u_receiving_endpoints_match_this_stream"
            matched_role = next(iter(roles), None)
            limitations.append(
                "more than one advertised S1-U receiving endpoint carries this destination address "
                "and TEID, so no single bearer allocation is selected"
            )
            deviations.append(DEVIATION_COMPETING)
        elif len(candidate_subjects) > 1:
            status = ASSOCIATION_AMBIGUOUS
            basis = "one_s1u_endpoint_claimed_by_several_bearer_subjects"
            matched_role = next(iter(roles), None)
            limitations.append(
                "the receiving endpoint value is published by more than one default-bearer subject, "
                "so this stream is not independent proof for either of them"
            )
            deviations.append(DEVIATION_LIFECYCLE)
        elif len(candidate_subjects) == 1:
            status = ASSOCIATION_SUPPORTED
            basis = "receiving_endpoint_equality_with_advertised_s1u_f_teid"
            matched_role = next(iter(roles), None)
            matched_subject = candidate_subjects[0]
        else:
            # The endpoint match is real and its role is reviewed, but no
            # default-bearer subject owns that advertisement. Endpoint evidence is
            # preserved; bearer ownership stays NOT_ESTABLISHED.
            status = ASSOCIATION_NOT_ESTABLISHED
            basis = "receiving_endpoint_matched_without_bearer_owner"
            matched_role = next(iter(roles), None)
            limitations.append(
                "the receiving endpoint match is supported by reviewed evidence, but no "
                "default-bearer subject owns that advertisement, so no bearer association is asserted"
            )
        competing_subjects = [item for item in candidate_subjects if item != matched_subject]

    stream_events = events_by_stream.get(_stream_tuple(stream) or ("", "", "", -1), [])
    message_types = sorted(
        {
            str(event.get("header", {}).get("message_type"))
            for event in stream_events
            if isinstance(event.get("header"), dict) and event["header"].get("message_type")
        }
    )
    error_frames = [
        frame
        for frame in stream.get("error_indication_refs") or []
        if isinstance(frame, int)
    ]
    if not error_frames:
        error_frames = [
            event.get("frame_number")
            for event in stream_events
            if event.get("error_indication") and isinstance(event.get("frame_number"), int)
        ]
    if error_frames:
        deviations.append(DEVIATION_ERROR_INDICATION)

    interface = INTERFACE_S1U if matches else INTERFACE_UNKNOWN
    interface_basis = (
        "matched_advertised_s1u_receiving_endpoint" if matches else "no_s1u_endpoint_evidence"
    )
    if not matches and (not message_types or not all(item.startswith("Echo") for item in message_types)):
        deviations.append(DEVIATION_UNBOUND)

    g_pdu_count = stream.get("observed_g_pdu_packet_count")
    byte_count = stream.get("observed_payload_byte_count")
    outcomes: list[str] = []
    if isinstance(g_pdu_count, int) and g_pdu_count > 0:
        outcomes.extend([OUTCOME_G_PDU, OUTCOME_DIRECTED, OUTCOME_PACKET_COUNT])
    if isinstance(byte_count, int) and byte_count > 0:
        outcomes.append(OUTCOME_BYTE_COUNT)

    if not matches and g_pdu_count == 0 and message_types and all(
        item.startswith("Echo") for item in message_types
    ):
        # An Echo context carries no bearer traffic, so it stays an observable
        # control stream rather than an unbound bearer association.
        basis = "echo_context_has_no_bearer_receiving_endpoint"

    # Protocol evidence must name the message actually observed in that frame. A
    # stream's first and last frames are not necessarily G-PDUs, so identity comes
    # from the frame-anchored GTP-U events and never from stream membership, the
    # G-PDU count, the UDP port or the header TEID.
    observed_message_types: dict[int, str] = {}
    for event in stream_events:
        frame = event.get("frame_number")
        header = event.get("header")
        if not isinstance(frame, int) or isinstance(frame, bool) or not isinstance(header, dict):
            continue
        message_type = header.get("message_type")
        if isinstance(message_type, str) and message_type:
            observed_message_types.setdefault(frame, message_type)

    packet_references: list[dict[str, Any]] = []
    if observed_message_types:
        ordered_frames = sorted(observed_message_types)
        # Publish one frame per observed message type first, so a bounded list can
        # never hide a message identity the stream actually carried, then fill the
        # remaining slots in frame order.
        representatives: list[int] = []
        covered: set[str] = set()
        for frame in ordered_frames:
            message_type = observed_message_types[frame]
            if message_type in covered:
                continue
            covered.add(message_type)
            representatives.append(frame)
        representative_set = set(representatives)
        ordered = representatives + [frame for frame in ordered_frames if frame not in representative_set]
        for frame in ordered:
            packet_references.append(_evidence_ref("GTP-U", frame, observed_message_types[frame]))
    else:
        # No frame-anchored event is available: keep the frame provenance and
        # leave the message identity unavailable rather than inventing "G-PDU".
        for frame in (stream.get("first_frame"), stream.get("last_frame")):
            packet_references.append(_evidence_ref("GTP-U", frame, None))

    # The advertisement that supports the relationship is the primary evidence, so
    # it is published first and survives any tighter downstream bound. The packet
    # samples keep the remaining slots.
    endpoint_references = matched_endpoint_refs[:MAX_LIST_ITEMS]
    endpoint_dropped = max(0, len(matched_endpoint_refs) - len(endpoint_references))
    packet_budget = max(1, MAX_EVIDENCE_REFERENCES - len(endpoint_references))
    published_packets = packet_references[:packet_budget]
    packet_dropped = max(0, len(packet_references) - len(published_packets))

    references = endpoint_references + published_packets
    references = [item for item in references if item["frame_number"] is not None]
    seen: set[tuple[Any, Any]] = set()
    bounded: list[dict[str, Any]] = []
    for item in references:
        key = (item["protocol"], item["frame_number"])
        if key in seen:
            continue
        seen.add(key)
        bounded.append(item)
    overflow = max(0, len(bounded) - MAX_EVIDENCE_REFERENCES)
    bounded = bounded[:MAX_EVIDENCE_REFERENCES]
    # Every reference the bound withholds is counted, not only the last overflow.
    omitted = packet_dropped + endpoint_dropped + overflow

    if not isinstance(g_pdu_count, int) or g_pdu_count == 0:
        limitations.append(
            "no G-PDU was observed in this directed context; an empty stream does not prove that "
            "the tunnel is broken"
        )
    limitations.extend(
        str(item) for item in stream.get("limitations") or [] if isinstance(item, str)
    )
    if status == ASSOCIATION_SUPPORTED:
        limitations.append(
            "receiving-endpoint equality supports the tunnel relationship; it does not prove that "
            "the UE received the packet"
        )

    entry: dict[str, Any] = {
        "stream_reference": reference,
        "stream_key": stream.get("stream_key"),
        "capture_file": stream.get("capture_file"),
        "outer_source": stream.get("outer_source"),
        "outer_destination": stream.get("outer_destination"),
        "udp_source_port": stream.get("udp_source_port"),
        "udp_destination_port": stream.get("udp_destination_port"),
        "teid": stream.get("teid"),
        "first_frame": stream.get("first_frame"),
        "last_frame": stream.get("last_frame"),
        "observed_g_pdu_packet_count": g_pdu_count,
        "observed_payload_byte_count": byte_count,
        "byte_count_definition": stream.get("byte_count_definition"),
        "message_types": message_types[:MAX_LIST_ITEMS],
        "echo_observed": "Echo Response" in message_types or "Echo Request" in message_types,
        "end_marker_frames": [
            frame for frame in stream.get("end_marker_frames") or [] if isinstance(frame, int)
        ][:MAX_LIST_ITEMS],
        "error_indication_frames": error_frames[:MAX_LIST_ITEMS],
        "user_plane_interface": interface,
        "interface_basis": interface_basis,
        "direction": DIRECTION_BY_ROLE.get(matched_role) if matched_role else "UNKNOWN",
        "receiving_endpoint_match_status": match_status,
        "receiving_endpoint_match_basis": basis,
        "association_status": status,
        "bearer_association_status": status,
        "association_basis": basis,
        "matched_subject_reference": matched_subject,
        "matched_endpoint_role": matched_role,
        "matched_endpoint_role_basis": _single_value(match.get("role_basis") for match in matches),
        "matched_endpoint_source_protocols": sorted(
            {str(match.get("source_protocol")) for match in matches if match.get("source_protocol")}
        ),
        "matched_endpoint_interface_types": sorted(
            {match["interface_type"] for match in matches if isinstance(match.get("interface_type"), int)}
        ),
        "matched_endpoint_interface_type_names": sorted(
            {str(match.get("interface_type_name")) for match in matches if match.get("interface_type_name")}
        ),
        "matched_endpoint_frames": sorted(set(matched_endpoint_frames))[:MAX_LIST_ITEMS],
        "competing_subject_references": competing_subjects[:MAX_LIST_ITEMS],
        "outcomes": outcomes,
        "deviation_types": deviations,
        "evidence_refs": bounded,
        "observation_window": _window([stream.get("first_frame"), stream.get("last_frame")]),
        "limitations": limitations[:MAX_LIST_ITEMS],
    }
    if omitted:
        entry["evidence_refs_omitted"] = omitted
    return entry


def analyze(
    events: list[dict[str, Any]],
    stream_document: dict[str, Any],
    default_bearer: dict[str, Any] | None = None,
    gtpv2_events: list[dict[str, Any]] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reconstruct bounded S1-U packet observation from accepted inputs."""
    gtpv2_events = gtpv2_events or []
    streams = stream_document.get("streams")
    if not isinstance(streams, list):
        raise InputError("stream summary does not contain a streams array")

    events_by_stream: dict[tuple[str, str, str, int], list[dict[str, Any]]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        key = _event_tuple(event)
        if key is not None:
            events_by_stream.setdefault(key, []).append(event)

    endpoints = endpoint_index(default_bearer, gtpv2_events)
    owners = _subject_owners(endpoints)
    observations = [
        build_stream(stream, endpoints, owners, events_by_stream)
        for stream in streams
        if isinstance(stream, dict)
    ]
    observations.sort(
        key=lambda item: (
            item["first_frame"] if isinstance(item["first_frame"], int) else 1 << 30,
            str(item["stream_reference"]),
        )
    )
    omitted_streams = max(0, len(observations) - MAX_STREAMS)
    visible = observations[:MAX_STREAMS]

    supported = [item for item in visible if item["association_status"] == ASSOCIATION_SUPPORTED]
    ambiguous = [item for item in visible if item["association_status"] == ASSOCIATION_AMBIGUOUS]
    unbound = [item for item in visible if item["association_status"] == ASSOCIATION_NOT_ESTABLISHED]

    deviations: list[dict[str, Any]] = []
    for item in visible:
        for deviation_type in item["deviation_types"]:
            deviations.append(
                {
                    "deviation_type": deviation_type,
                    "stream_reference": item["stream_reference"],
                    "protocol": "GTP-U",
                    "message_type": item["message_types"][0] if item["message_types"] else None,
                    "frame_number": item["first_frame"],
                    "evidence_level": "OBSERVED",
                    "evidence_refs": item["evidence_refs"][:MAX_EVIDENCE_REFERENCES],
                    "observation_window": item["observation_window"],
                    "limitations": item["limitations"][:MAX_LIST_ITEMS],
                }
            )
    deviations.sort(
        key=lambda item: (
            item["frame_number"] if isinstance(item["frame_number"], int) else 1 << 30,
            str(item["deviation_type"]),
            str(item["stream_reference"]),
        )
    )

    total_g_pdu = sum(
        item["observed_g_pdu_packet_count"]
        for item in visible
        if isinstance(item["observed_g_pdu_packet_count"], int)
    )
    total_bytes = sum(
        item["observed_payload_byte_count"]
        for item in visible
        if isinstance(item["observed_payload_byte_count"], int)
    )

    limitations: list[str] = []
    if not visible:
        limitations.append("no directed GTP-U stream was observed in the supplied evidence")
    if not endpoints:
        limitations.append(
            "no advertised S1-U receiving endpoint was available, so no stream could be related "
            "to a bearer allocation"
        )
    elif not any(endpoint.get("source") == "gtpv2_bearer_f_teid" for endpoint in endpoints):
        limitations.append(
            "only eNB-side S1-U endpoints were available; an uplink stream cannot be matched "
            "without the SGW-U receiving endpoint"
        )
    if unbound:
        limitations.append(
            f"{len(unbound)} stream(s) carry no matching S1-U receiving endpoint and stay unbound"
        )
    observed_directions = {
        item["direction"] for item in visible if item["direction"] in ("DOWNLINK", "UPLINK")
    }
    if len(observed_directions) == 1:
        limitations.append(
            "only one S1-U direction was observed; this is not evidence about the reverse direction"
        )
    limitations.append(
        "packet counts are observations at the capture point; no loss, delivery or application "
        "reachability is inferred"
    )

    additional: list[str] = []
    if not visible:
        additional.append(
            "a capture containing decoded GTP-U G-PDUs on the S1-U tunnel is required"
        )
    if unbound:
        additional.append(
            "the SGW-U S1-U receiving endpoint is required to relate uplink streams to a bearer"
        )

    return {
        "domain": DOMAIN_NAME,
        "domain_version": DOMAIN_VERSION,
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "procedure": "eps-s1u-observation",
        "procedure_label": "EPC S1-U GTP-U observation",
        "analysis_scope": {
            "capability": "bounded S1-U GTP-U packet observation",
            "inputs": [
                "detailed GTP-U events",
                "directed GTP-U stream summary",
                "accepted EPS default-bearer analysis (optional)",
                "GTPv2-C events for SGW-U S1-U endpoint identity (optional)",
            ],
            "matching_rule": (
                "outer destination address plus header TEID equal to an advertised S1-U receiving "
                "endpoint; a source address, UDP port or TEID value alone never establishes ownership"
            ),
            "association_statuses": list(ASSOCIATION_STATUSES),
            "outcome_vocabulary": list(OUTCOMES),
            "deviation_vocabulary": list(DEVIATION_TYPES),
            "excluded": [
                "GTP-U sequence-gap packet-loss inference",
                "UE packet-delivery confirmation",
                "application reachability verdicts",
                "inner packet content publication",
                "network-function blame",
            ],
        },
        "input_provenance": provenance or {},
        "stream_count": len(observations),
        "stream_observations": visible,
        "streams_omitted": omitted_streams,
        "supported_stream_count": len(supported),
        "ambiguous_stream_count": len(ambiguous),
        "unbound_stream_count": len(unbound),
        "observed_g_pdu_packet_count": total_g_pdu,
        "observed_payload_byte_count": total_bytes,
        "procedure_local_deviations": deviations[:MAX_LIST_ITEMS],
        "procedure_local_deviation_count": len(deviations),
        "procedure_local_deviations_omitted": max(0, len(deviations) - MAX_LIST_ITEMS),
        "evidence_limitations": limitations,
        "additional_evidence_needed": additional,
        "not_confirmed": list(NOT_CONFIRMED),
        "boundary_selection_status": "NOT_APPLICABLE",
        "first_abnormal_boundary": None,
        "boundary_note": GLOBAL_BOUNDARY_NOTE,
    }
