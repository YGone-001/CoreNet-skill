"""Bounded control-to-access attribution feasibility for EPC Dedicated Bearer.

This producer consumes already-accepted Dedicated Bearer Control and EPC Session
Identity artifacts plus observed NAS-EPS and S1AP events. It never re-infers
control outcomes, session identity or access semantics. It publishes the
strongest supportable relationship and the exact missing evidence.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ANALYSIS_NAME = "epc-dedicated-bearer-attribution"
ANALYSIS_VERSION = "1.0.0"
MAX_ENTRIES = 128
MAX_REFERENCES = 16
MAX_LIST_ITEMS = 16
WINDOW_FRAMES = 30

EXIT_MALFORMED_INPUT = 2
EXIT_OUTPUT_FAILURE = 3

ESTABLISHED = "ESTABLISHED_BY_EVIDENCE"
CANDIDATE = "CANDIDATE_UNCONFIRMED"
ENDPOINT_ONLY = "ENDPOINT_CORRESPONDENCE_ONLY"
AMBIGUOUS = "AMBIGUOUS"
NOT_ESTABLISHED = "NOT_ESTABLISHED"
NOT_OBSERVED = "NOT_OBSERVED"
UNSUPPORTED = "UNSUPPORTED_EVIDENCE"

S11 = "S11"
S5S8 = "S5/S8"
CLASS_INTERFACE_TYPES = {S11: frozenset({10, 11}), S5S8: frozenset({6, 7})}

FAMILY_ESM = {
    "create-bearer": frozenset({197, 198, 199}),
    "update-bearer": frozenset({201, 202, 203}),
    "delete-bearer": frozenset({205, 206}),
}
FAMILY_ERAB = {
    "create-bearer": frozenset({"E_RAB_SETUP"}),
    "update-bearer": frozenset({"E_RAB_MODIFY"}),
    "delete-bearer": frozenset({"E_RAB_RELEASE"}),
}

CONTROL_TO_SESSION = "CONTROL_TO_SESSION"
SESSION_TO_ACCESS = "SESSION_TO_ACCESS"
NAS_TO_S1AP = "NAS_TO_S1AP"
CONTROL_TO_ERAB = "CONTROL_TO_ERAB"


class InputError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError("MALFORMED_JSON", f"{path.name} is not readable JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise InputError("MALFORMED_JSON", f"{path.name} is not a JSON object")
    return payload


def read_jsonl(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise InputError("MALFORMED_INPUT", f"{path.name} is not readable: {exc}") from exc
    records: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputError("MALFORMED_INPUT", f"{path.name} contains invalid JSON: {exc}") from exc
        if isinstance(item, dict):
            records.append(item)
        else:
            raise InputError("MALFORMED_INPUT", f"{path.name} contains a non-object record")
    return records


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError as exc:
        raise InputError("MALFORMED_INPUT", f"artifact hash failed: {exc}") from exc
    return digest.hexdigest()


def _text(value: Any, limit: int = 160) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    return text[:limit] if text else None


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _frame(value: Any) -> int | None:
    frame = _int(value)
    return frame if frame is not None and frame >= 1 else None


def _address(value: Any) -> str | None:
    text = _text(value, 64)
    if text is None or text in ("0.0.0.0", "::"):
        return None
    return text


def _scope(value: Any) -> str | None:
    address = _address(value)
    return "PRESENT" if address is not None else "ABSENT"


def _transaction_frames(transaction: dict[str, Any]) -> tuple[int | None, int | None]:
    anchors = _dict(transaction.get("frame_anchors"))
    request = _frame(anchors.get("request_frame"))
    response = _frame(anchors.get("response_frame"))
    if request is None:
        request = _frame(_dict(transaction.get("request")).get("frame_number"))
    if response is None:
        response = _frame(_dict(transaction.get("response")).get("frame_number"))
    return request, response


def _capture(control: dict[str, Any]) -> str:
    captures = sorted(
        {
            _text(_dict(item).get("capture"))
            for item in _list(control.get("control_transactions"))
            if _text(_dict(item).get("capture")) is not None
        }
    )
    if len(captures) > 1:
        raise InputError(
            "MIXED_CAPTURE_ARTIFACT",
            "control artifact contains multiple capture identities: " + ", ".join(captures),
        )
    if captures:
        return captures[0]
    return "unknown-capture"


def _item_map(control: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("item_reference")): _dict(item)
        for item in _list(control.get("bearer_item_observations"))
        if isinstance(item, dict) and isinstance(item.get("item_reference"), str)
    }


def _valid_ebis(transaction: dict[str, Any], items: dict[str, dict[str, Any]]) -> list[int]:
    ebis: set[int] = set()
    for key in ("request_bearer_item_references", "response_bearer_item_references"):
        for reference in _list(transaction.get(key)):
            item = items.get(reference) if isinstance(reference, str) else None
            if isinstance(item, dict) and item.get("ebi_status") == "VALID":
                ebi = _int(item.get("ebi"))
                if ebi is not None and 0 <= ebi <= 15:
                    ebis.add(ebi)
    return sorted(ebis)


def _bearer_endpoints(
    transaction: dict[str, Any], items: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for key in ("request_bearer_item_references", "response_bearer_item_references"):
        for reference in _list(transaction.get(key)):
            item = items.get(reference) if isinstance(reference, str) else None
            if not isinstance(item, dict):
                continue
            for fteid in _list(item.get("f_teids")):
                fteid = _dict(fteid)
                interface_type = _int(fteid.get("interface_type"))
                teid = _int(fteid.get("teid"))
                address = _address(fteid.get("ipv4")) or _address(fteid.get("ipv6"))
                if interface_type not in (0, 1) or teid is None or address is None:
                    continue
                if (teid, address) in seen:
                    continue
                seen.add((teid, address))
                endpoints.append(
                    {
                        "interface_type": interface_type,
                        "teid": teid,
                        "address": address,
                        "role": _text(fteid.get("role")),
                        "source_item_reference": reference,
                        "source_side": "REQUEST" if key == "request_bearer_item_references" else "RESPONSE",
                    }
                )
    return endpoints


def _join_candidates(
    contexts: list[dict[str, Any]], capture: str, request_event: dict[str, Any]
) -> list[dict[str, Any]]:
    header = _dict(request_event.get("header"))
    teid = _int(header.get("teid"))
    destination = _address(_dict(request_event.get("destination")).get("address"))
    source = _address(_dict(request_event.get("source")).get("address"))
    if teid is None or teid == 0 or destination is None or source is None:
        return []
    matched: list[dict[str, Any]] = []
    for context in contexts:
        context = _dict(context)
        if context.get("capture_file") != capture:
            continue
        if context.get("association_status") != "ESTABLISHED":
            continue
        hop_types = CLASS_INTERFACE_TYPES.get(context.get("interface_class"))
        if hop_types is None:
            continue
        hop_local = [
            _dict(record)
            for record in _list(context.get("control_plane_fteids"))
            if _dict(record).get("join_capable")
            and _int(_dict(record).get("interface_type")) in hop_types
        ]
        receiver = any(
            _int(record.get("teid")) == teid
            and _address(record.get("address")) == destination
            for record in hop_local
        )
        peer = any(_address(record.get("address")) == source for record in hop_local)
        if receiver and peer:
            matched.append(context)
    return matched


def _control_session(
    contexts: list[dict[str, Any]], capture: str, request_event: dict[str, Any]
) -> dict[str, Any]:
    candidates = _join_candidates(contexts, capture, request_event)
    header = _dict(request_event.get("header"))
    request_teid = _int(header.get("teid"))
    basis = [
        "accepted receiver-scoped rule: request header TEID and destination equal one hop-local control-plane F-TEID",
        "accepted peer rule: request source equals a hop-local F-TEID address of the same context",
    ]
    if request_teid in (None, 0):
        return {
            "status": NOT_ESTABLISHED,
            "session_context_reference": None,
            "interface_class": None,
            "candidate_contexts": [],
            "request_header_teid_present": False,
            "request_destination_scope": _scope(_dict(request_event.get("destination")).get("address")),
            "request_source_scope": _scope(_dict(request_event.get("source")).get("address")),
            "evidence_basis": basis,
            "missing_evidence": ["the request has no receiver-side header TEID"],
        }
    if not candidates:
        return {
            "status": NOT_ESTABLISHED,
            "session_context_reference": None,
            "interface_class": None,
            "candidate_contexts": [],
            "request_header_teid_present": True,
            "request_destination_scope": _scope(_dict(request_event.get("destination")).get("address")),
            "request_source_scope": _scope(_dict(request_event.get("source")).get("address")),
            "evidence_basis": basis,
            "missing_evidence": [
                "no established hop-local context publishes a control-plane F-TEID matching the request header TEID, destination and source peer"
            ],
        }
    if len(candidates) > 1:
        return {
            "status": AMBIGUOUS,
            "session_context_reference": None,
            "interface_class": None,
            "candidate_contexts": sorted(
                str(context.get("session_context_reference")) for context in candidates
            ),
            "request_header_teid_present": True,
            "request_destination_scope": _scope(_dict(request_event.get("destination")).get("address")),
            "request_source_scope": _scope(_dict(request_event.get("source")).get("address")),
            "evidence_basis": basis,
            "missing_evidence": [
                "receiver-scoped addressing matches several established hop-local contexts; no unique session context is selected"
            ],
        }
    context = candidates[0]
    return {
        "status": ESTABLISHED,
        "session_context_reference": context.get("session_context_reference"),
        "interface_class": context.get("interface_class"),
        "candidate_contexts": [context.get("session_context_reference")],
        "request_header_teid_present": True,
        "request_destination_scope": _scope(_dict(request_event.get("destination")).get("address")),
        "request_source_scope": _scope(_dict(request_event.get("source")).get("address")),
        "evidence_basis": basis
        + [
            "exactly one established hop-local context satisfies receiver and peer scoping",
            "control-plane interface type is compatible with the context class",
        ],
        "missing_evidence": [],
    }


def _related_s11_contexts(
    identity: dict[str, Any], control_session: dict[str, Any]
) -> list[str]:
    references = set(control_session.get("candidate_contexts") or [])
    if control_session.get("session_context_reference"):
        references.add(control_session["session_context_reference"])
    related: set[str] = set()
    for link in _list(identity.get("endpoint_correspondence_links")):
        link = _dict(link)
        if link.get("association_status") not in (None, "SUPPORTED"):
            continue
        source = _text(link.get("source_subject_reference"))
        target = _text(link.get("target_subject_reference"))
        if source in references and target:
            related.add(target)
        if target in references and source:
            related.add(source)
    return sorted(related)


def _nas_observations(
    events: list[dict[str, Any]],
    capture: str,
    family: str,
    ebis: list[int],
    request: int | None,
    response: int | None,
) -> list[dict[str, Any]]:
    codes = FAMILY_ESM[family]
    lower = request or (response or 0)
    upper = response if response is not None else lower + WINDOW_FRAMES
    result: list[dict[str, Any]] = []
    for event in events:
        event = _dict(event)
        if _text(event.get("capture_file")) not in (None, capture):
            continue
        frame = _frame(event.get("frame_number"))
        if frame is None or not (lower <= frame <= upper):
            continue
        for message in _list(event.get("esm_messages")):
            message = _dict(message)
            code = _int(message.get("message_type_code"))
            if code not in codes:
                continue
            if _int(message.get("eps_bearer_identity")) not in ebis:
                continue
            result.append(
                {
                    "reference": f"nas-esm:{capture}:{frame}:{_int(message.get('occurrence_index')) or 0}",
                    "frame_number": frame,
                    "message_type_code": code,
                    "result": _text(message.get("result")),
                    "eps_bearer_identity": _int(message.get("eps_bearer_identity")),
                    "support_status": _text(message.get("support_status")),
                    "protection_state": _text(message.get("protection_state")),
                }
            )
    return result


def _s1ap_by_frame(events: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    index: dict[int, list[dict[str, Any]]] = {}
    for event in events:
        event = _dict(event)
        frame = _frame(event.get("frame_number"))
        if frame is not None:
            index.setdefault(frame, []).append(event)
    return index


def _nas_access(
    nas_observations: list[dict[str, Any]],
    s1ap_by_frame: dict[int, list[dict[str, Any]]],
    capture: str,
) -> dict[str, Any]:
    if not nas_observations:
        return {
            "status": NOT_OBSERVED,
            "owner_s1ap_context": None,
            "candidate_contexts": [],
            "observed_references": [],
            "evidence_basis": ["no dedicated NAS-ESM observation matched the control family, EBI and window"],
            "missing_evidence": [],
        }
    owners: set[str] = set()
    ambiguous = False
    unsupported = False
    for observation in nas_observations:
        if observation.get("support_status") != "SUPPORTED":
            unsupported = True
        frame_owners = [
            owner
            for owner in s1ap_by_frame.get(observation["frame_number"], [])
            if _dict(owner).get("nas_pdu_embedded") is True
            and _text(owner.get("context_key")) is not None
        ]
        contexts = sorted(
            {
                str(_text(owner.get("context_key")))
                for owner in frame_owners
            }
        )
        if len(contexts) > 1:
            ambiguous = True
        elif len(contexts) == 1:
            owners.add(contexts[0])
    basis = [
        "same-frame S1AP message independently observed",
        "the observed S1AP message declares an embedded NAS-PDU",
        "capture and frame identity match",
    ]
    if unsupported:
        return {
            "status": UNSUPPORTED,
            "owner_s1ap_context": None,
            "candidate_contexts": sorted(owners),
            "observed_references": nas_observations[:MAX_REFERENCES],
            "evidence_basis": basis,
            "missing_evidence": ["at least one matched NAS-ESM identity is not semantically supported"],
        }
    if ambiguous or len(owners) > 1:
        return {
            "status": AMBIGUOUS,
            "owner_s1ap_context": None,
            "candidate_contexts": sorted(owners),
            "observed_references": nas_observations[:MAX_REFERENCES],
            "evidence_basis": basis,
            "missing_evidence": [
                "the same NAS observation is carried by more than one S1AP UE context, or multiple contexts own different matched occurrences"
            ],
        }
    if not owners:
        return {
            "status": NOT_ESTABLISHED,
            "owner_s1ap_context": None,
            "candidate_contexts": [],
            "observed_references": nas_observations[:MAX_REFERENCES],
            "evidence_basis": basis,
            "missing_evidence": [
                "no same-frame S1AP message with an embedded NAS-PDU identifies one owning UE context"
            ],
        }
    return {
        "status": ESTABLISHED,
        "owner_s1ap_context": sorted(owners)[0],
        "candidate_contexts": sorted(owners),
        "observed_references": nas_observations[:MAX_REFERENCES],
        "evidence_basis": basis
        + ["exactly one S1AP UE context owns the enclosing NAS transport for every matched observation"],
        "missing_evidence": [],
    }


def _erab_observations(
    events: list[dict[str, Any]],
    capture: str,
    family: str,
    request: int | None,
    response: int | None,
) -> list[dict[str, Any]]:
    operations = FAMILY_ERAB[family]
    lower = request or (response or 0)
    upper = response if response is not None else lower + WINDOW_FRAMES
    observations: list[dict[str, Any]] = []
    for event in events:
        event = _dict(event)
        if _text(event.get("capture_file")) not in (None, capture):
            continue
        frame = _frame(event.get("frame_number"))
        if frame is None or not (lower <= frame <= upper):
            continue
        context = _text(event.get("context_key"))
        for index, raw in enumerate(_list(event.get("erab_items"))):
            item = _dict(raw)
            if _text(item.get("operation")) not in operations:
                continue
            observations.append(
                {
                    "reference": f"s1ap-erab:{capture}:{frame}:{index}",
                    "frame_number": frame,
                    "operation": _text(item.get("operation")),
                    "result": _text(item.get("list_role")),
                    "erab_id": _int(item.get("erab_id")),
                    "gtp_teid": _int(item.get("gtp_teid")),
                    "address": _address(item.get("transport_layer_address")),
                    "ue_context_reference": context,
                    "binding_basis": _text(item.get("binding_basis")),
                }
            )
        if not _list(event.get("erab_items")):
            unbound = _dict(event.get("unbound_erab_evidence"))
            operations_seen = [
                op
                for op in _list(unbound.get("list_operations"))
                if op in operations
            ]
            if operations_seen:
                observations.append(
                    {
                        "reference": f"s1ap-erab-unbound:{capture}:{frame}",
                        "frame_number": frame,
                        "operation": operations_seen[0],
                        "result": (_list(unbound.get("list_roles")) or [None])[0],
                        "erab_id": None,
                        "gtp_teid": None,
                        "address": None,
                        "ue_context_reference": context,
                        "binding_basis": "flat_fields",
                        "limitations": ["no proven item boundary; no item identity was fabricated"],
                    }
                )
    return observations


def _public_erab(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "reference": observation.get("reference"),
        "frame_number": observation.get("frame_number"),
        "operation": observation.get("operation"),
        "result": observation.get("result"),
        "erab_id": observation.get("erab_id"),
        "ue_context_reference": observation.get("ue_context_reference"),
        "binding_basis": observation.get("binding_basis"),
        "bearer_endpoint_present": observation.get("gtp_teid") is not None
        and observation.get("address") is not None,
        "limitations": _list(observation.get("limitations")),
    }


def _s1ap_access(
    observations: list[dict[str, Any]], endpoints: list[dict[str, Any]]
) -> dict[str, Any]:
    if not observations:
        return {
            "status": NOT_OBSERVED,
            "observed_items": [],
            "endpoint_matches": [],
            "candidate_contexts": [],
            "evidence_basis": ["no matching standalone S1AP E-RAB item was observed in the control window"],
            "missing_evidence": [],
        }
    if any(observation.get("binding_basis") == "flat_fields" for observation in observations):
        return {
            "status": UNSUPPORTED,
            "observed_items": [_public_erab(item) for item in observations[:MAX_REFERENCES]],
            "endpoint_matches": [],
            "candidate_contexts": sorted(
                {
                    str(observation.get("ue_context_reference"))
                    for observation in observations
                    if observation.get("ue_context_reference")
                }
            ),
            "evidence_basis": ["the S1AP evidence has no proven E-RAB item boundary"],
            "missing_evidence": ["a PDML-grouped E-RAB item boundary is required"],
        }
    matches: list[dict[str, Any]] = []
    for observation in observations:
        if observation.get("gtp_teid") is None or observation.get("address") is None:
            continue
        for endpoint in endpoints:
            if (
                observation["gtp_teid"] == endpoint["teid"]
                and observation["address"] == endpoint["address"]
            ):
                matches.append(
                    {
                        "erab_reference": observation["reference"],
                        "control_endpoint_reference": endpoint["source_item_reference"],
                        "erab_id": observation.get("erab_id"),
                        "ue_context_reference": observation.get("ue_context_reference"),
                        "match_basis": "equal_bearer_scope_user_plane_fteid_and_address",
                    }
                )
    contexts = sorted(
        {
            str(observation.get("ue_context_reference"))
            for observation in observations
            if observation.get("ue_context_reference")
        }
    )
    basis = [
        "standalone S1AP E-RAB item identity and complete request/response evidence observed",
        "bearer-scope user-plane endpoint equality is endpoint correspondence only",
    ]
    if matches:
        return {
            "status": ENDPOINT_ONLY,
            "observed_items": [_public_erab(item) for item in observations[:MAX_REFERENCES]],
            "endpoint_matches": matches[:MAX_REFERENCES],
            "candidate_contexts": contexts,
            "evidence_basis": basis,
            "missing_evidence": [
                "no independent standards-reviewed UE/session identity bridge connects the S1AP UE context to the control session context"
            ],
        }
    return {
        "status": CANDIDATE,
        "observed_items": [_public_erab(item) for item in observations[:MAX_REFERENCES]],
        "endpoint_matches": [],
        "candidate_contexts": contexts,
        "evidence_basis": basis,
        "missing_evidence": [
            "no exact bearer-scope user-plane endpoint correspondence was observed between the control bearer and the S1AP E-RAB item"
        ],
    }


def _session_access(
    identity: dict[str, Any],
    control_session: dict[str, Any],
    s1ap_access: dict[str, Any],
    nas_access: dict[str, Any],
) -> dict[str, Any]:
    related = _related_s11_contexts(identity, control_session)
    correspondences = [
        {
            "reference": _text(_dict(link).get("reference")),
            "association_status": _text(_dict(link).get("association_status")),
        }
        for link in _list(identity.get("endpoint_correspondence_links"))
        if _dict(link).get("source_subject_reference") in related
        or _dict(link).get("target_subject_reference") in related
    ][:MAX_REFERENCES]
    if control_session.get("status") not in (ESTABLISHED, AMBIGUOUS) or not related:
        return {
            "status": NOT_ESTABLISHED,
            "related_session_contexts": related,
            "endpoint_correspondence_references": correspondences,
            "s1ap_candidate_contexts": s1ap_access.get("candidate_contexts", []),
            "evidence_basis": ["no control-to-session context is available for a session-to-access evaluation"],
            "missing_evidence": ["a unique established control-to-session context is required"],
        }
    if s1ap_access.get("status") == ENDPOINT_ONLY:
        return {
            "status": ENDPOINT_ONLY,
            "related_session_contexts": related,
            "endpoint_correspondence_references": correspondences,
            "s1ap_candidate_contexts": s1ap_access.get("candidate_contexts", []),
            "evidence_basis": [
                "cross-interface endpoint correspondence exists between established session contexts",
                "an S1AP E-RAB bearer endpoint equals the control bearer endpoint",
                "endpoint equality is never a UE identity proof",
            ],
            "missing_evidence": [
                "an independent UE/session identity bridge, not TEID, address, E-RAB ID, QCI or timing equality"
            ],
        }
    if nas_access.get("status") == ESTABLISHED:
        return {
            "status": CANDIDATE,
            "related_session_contexts": related,
            "endpoint_correspondence_references": correspondences,
            "s1ap_candidate_contexts": s1ap_access.get("candidate_contexts", []),
            "evidence_basis": [
                "NAS ownership identifies one S1AP UE context",
                "no independent session-to-S1AP identity bridge is observed",
            ],
            "missing_evidence": [
                "a reviewed binding between the S11 session context and the S1AP UE context"
            ],
        }
    return {
        "status": NOT_ESTABLISHED,
        "related_session_contexts": related,
        "endpoint_correspondence_references": correspondences,
        "s1ap_candidate_contexts": s1ap_access.get("candidate_contexts", []),
        "evidence_basis": ["session contexts are recorded, but no access-context ownership evidence is established"],
        "missing_evidence": ["observable S1AP NAS transport or E-RAB evidence tied to the session context"],
    }


def _overall(
    control_session: dict[str, Any], session_access: dict[str, Any], nas_access: dict[str, Any], s1ap_access: dict[str, Any]
) -> tuple[str, list[str], list[str]]:
    established = []
    if control_session.get("status") == ESTABLISHED:
        established.append(CONTROL_TO_SESSION)
    if nas_access.get("status") == ESTABLISHED:
        established.append(NAS_TO_S1AP)
    if control_session.get("status") == AMBIGUOUS or session_access.get("status") == AMBIGUOUS:
        status = AMBIGUOUS
    elif control_session.get("status") == ESTABLISHED and nas_access.get("status") == ESTABLISHED:
        status = CANDIDATE
    elif control_session.get("status") == ESTABLISHED or nas_access.get("status") == ESTABLISHED:
        status = CANDIDATE
    elif control_session.get("status") == NOT_ESTABLISHED and nas_access.get("status") == NOT_OBSERVED:
        status = NOT_ESTABLISHED
    else:
        status = NOT_ESTABLISHED
    limiting = []
    for part in (control_session, session_access, nas_access, s1ap_access):
        for item in _list(part.get("missing_evidence")):
            if isinstance(item, str):
                limiting.append(item)
    additional = [
        "a standards-reviewed identity or binding relationship between the S11 session context and the S1AP UE context",
        "explicit UE-context ownership inside the accepted control artifact (not inferred from TEID, EBI, E-RAB ID or timing)",
        "exhaustive coverage declaration for NAS/S1AP event streams",
    ]
    return status, established, (limiting + additional)[:MAX_LIST_ITEMS]


def _status_counts(entries: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        value = entry.get(key)
        if isinstance(value, dict):
            value = value.get("status")
        if isinstance(value, str):
            counts[value] = counts.get(value, 0) + 1
    return {name: counts[name] for name in sorted(counts)}


def build_attribution(
    control: dict[str, Any],
    identity: dict[str, Any],
    gtpv2_events: list[dict[str, Any]],
    nas_events: list[dict[str, Any]],
    s1ap_events: list[dict[str, Any]],
    *,
    control_path: Path,
    identity_path: Path,
    gtpv2_path: Path | None,
    nas_path: Path | None,
    s1ap_path: Path | None,
) -> dict[str, Any]:
    capture = _capture(control)
    contexts = [
        _dict(item)
        for item in _list(identity.get("hop_local_contexts"))
        if _dict(item).get("capture_file") in (None, capture)
    ]
    events_by_frame = {
        _frame(event.get("frame_number")): _dict(event)
        for event in gtpv2_events
        if isinstance(event, dict) and _frame(event.get("frame_number")) is not None
    }
    items = _item_map(control)
    s1ap_index = _s1ap_by_frame(s1ap_events)
    entries: list[dict[str, Any]] = []
    for raw in _list(control.get("control_transactions")):
        transaction = _dict(raw)
        family = _text(transaction.get("procedure_family"))
        if family not in FAMILY_ESM:
            continue
        reference = _text(transaction.get("transaction_reference")) or "unidentified-control-transaction"
        request, response = _transaction_frames(transaction)
        request_event = events_by_frame.get(request, {})
        ebis = _valid_ebis(transaction, items)
        control_session = _control_session(contexts, capture, request_event)
        nas_observations = _nas_observations(
            nas_events, capture, family, ebis, request, response
        )
        nas_access = _nas_access(nas_observations, s1ap_index, capture)
        endpoints = _bearer_endpoints(transaction, items)
        erab_observations = _erab_observations(
            s1ap_events, capture, family, request, response
        )
        s1ap_access = _s1ap_access(erab_observations, endpoints)
        session_access = _session_access(identity, control_session, s1ap_access, nas_access)
        overall, established_links, limiting = _overall(
            control_session, session_access, nas_access, s1ap_access
        )
        entries.append(
            {
                "entry_reference": f"epc-db-attribution:{capture}:{reference}",
                "control_transaction_reference": reference,
                "procedure_family": family,
                "request_frame": request,
                "response_frame": response,
                "control_outcome": _text(_dict(transaction.get("message_outcome")).get("status")),
                "control_session": control_session,
                "session_access": session_access,
                "nas_access": nas_access,
                "s1ap_access": s1ap_access,
                "overall_status": overall,
                "established_links": established_links,
                "limiting_evidence": limiting,
                "additional_evidence_needed": limiting,
            }
        )
    entries.sort(
        key=lambda item: (
            item["request_frame"] if item["request_frame"] is not None else 1 << 30,
            item["procedure_family"],
            item["entry_reference"],
        )
    )
    published = entries[:MAX_ENTRIES]
    omitted = max(0, len(entries) - len(published))
    return {
        "domain": "epc-procedures",
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "input_provenance": {
            "control_artifact": control_path.name,
            "control_artifact_sha256": sha256_file(control_path),
            "session_identity_artifact": identity_path.name,
            "session_identity_artifact_sha256": sha256_file(identity_path),
            "gtpv2_events": gtpv2_path.name if gtpv2_path is not None else None,
            "nas_events": nas_path.name if nas_path is not None else None,
            "s1ap_events": s1ap_path.name if s1ap_path is not None else None,
            "control_transaction_count": len(entries),
            "context_count": len(contexts),
            "gtpv2_event_count": len(gtpv2_events),
            "nas_event_count": len(nas_events),
            "s1ap_event_count": len(s1ap_events),
        },
        "analysis_scope": {
            "capture": capture,
            "reviewed_rules": [
                "receiver-scoped control-plane F-TEID and verified path peer for control-to-session attribution",
                "NAS ownership requires the observed enclosing S1AP message with an embedded NAS-PDU",
                "endpoint equality is correspondence only and never UE identity",
                "EBI, E-RAB ID, QCI, timing and single-context membership are never identity proofs",
            ],
            "not_inferred": [
                "no subscriber identity",
                "no full control-to-access identity chain",
                "no bearer activation or user-plane delivery verdict",
            ],
        },
        "source_completeness": {
            "status": "PARTIAL",
            "control_artifact_supplied": True,
            "session_identity_artifact_supplied": True,
            "gtpv2_events_supplied": gtpv2_path is not None,
            "nas_events_supplied": nas_path is not None,
            "s1ap_events_supplied": s1ap_path is not None,
            "control_source_completeness": _text(
                _dict(control.get("source_completeness")).get("status")
            )
            or "UNKNOWN",
            "exhaustive_coverage_proven": False,
            "limitations": [
                "the accepted artifacts and event streams do not declare exhaustive control-to-access coverage",
                "no independent UE identity bridge is present in the accepted evidence",
            ],
        },
        "execution_status": "EXECUTED" if entries else "NOT_OBSERVED_IN_CAPTURE",
        "attribution_entries": published,
        "attribution_entry_count": len(entries),
        "attribution_entries_omitted": omitted,
        "control_session_status_counts": _status_counts(entries, "control_session"),
        "session_access_status_counts": _status_counts(entries, "session_access"),
        "nas_access_status_counts": _status_counts(entries, "nas_access"),
        "s1ap_access_status_counts": _status_counts(entries, "s1ap_access"),
        "overall_status_counts": _status_counts(entries, "overall_status"),
        "established_link_counts": {
            key: sum(
                1
                for entry in entries
                if key in (entry.get("established_links") or [])
            )
            for key in (CONTROL_TO_SESSION, SESSION_TO_ACCESS, NAS_TO_S1AP, CONTROL_TO_ERAB)
        },
        "unresolved_evidence": [
            {
                "entry_reference": entry["entry_reference"],
                "status": entry["overall_status"],
                "reason": (entry["limiting_evidence"] or ["no evidence"])[0],
            }
            for entry in entries
            if entry["overall_status"] != ESTABLISHED
        ][:MAX_ENTRIES],
        "not_confirmed": [
            "a control-plane accepted Cause does not prove UE acceptance",
            "an endpoint correspondence does not prove a UE identity",
            "no complete control-to-session-to-S1AP identity chain is asserted",
            "no end-to-end user-plane delivery is asserted",
        ],
        "bounded": True,
        "limits": {
            "attribution_entries": MAX_ENTRIES,
            "references": MAX_REFERENCES,
            "unresolved_evidence": MAX_ENTRIES,
        },
    }