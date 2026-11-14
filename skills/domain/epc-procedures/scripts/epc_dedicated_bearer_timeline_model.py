"""Bounded cross-layer evidence timeline for EPC Dedicated Bearer control.

The timeline consumes the accepted Dedicated Bearer control artifact and optional
NAS-EPS and S1AP event streams. It never re-infers GTPv2-C outcomes, never
fabricates NAS or E-RAB stages, and never equates a control-plane Cause with UE
acceptance or radio setup.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

ANALYSIS_NAME = "epc-dedicated-bearer-timeline"
ANALYSIS_VERSION = "1.0.0"
MAX_TIMELINE_ENTRIES = 128
MAX_SOURCE_REFERENCES = 16
MAX_UNRESOLVED_EVIDENCE = 64
MAX_LIST_ITEMS = 16
ASSOCIATION_WINDOW_FRAMES = 30

EXIT_MALFORMED_INPUT = 2
EXIT_OUTPUT_FAILURE = 3

ESTABLISHED = "ESTABLISHED_BY_EVIDENCE"
CANDIDATE = "CANDIDATE_UNCONFIRMED"
AMBIGUOUS = "AMBIGUOUS"
NOT_ESTABLISHED = "NOT_ESTABLISHED"
NOT_OBSERVED = "NOT_OBSERVED"
UNSUPPORTED = "UNSUPPORTED_EVIDENCE"

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
REQUEST_RESULTS = frozenset({"REQUEST", "COMMAND"})
COMPLETION_RESULTS = frozenset({"ACCEPT", "REJECT", "SUCCESS", "COMPLETE"})


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
        if not isinstance(item, dict):
            raise InputError("MALFORMED_INPUT", f"{path.name} contains a non-object record")
        records.append(item)
    return records


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError as exc:
        raise InputError("MALFORMED_INPUT", f"control artifact hash failed: {exc}") from exc
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


def _ordered_counts(values: Iterable[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        if isinstance(value, str) and value:
            counts[value] = counts.get(value, 0) + 1
    return {key: counts[key] for key in sorted(counts)}


def _frame(value: Any) -> int | None:
    frame = _int(value)
    return frame if frame is not None and frame >= 1 else None


def _transaction_frames(transaction: dict[str, Any]) -> tuple[int | None, int | None]:
    anchors = _dict(transaction.get("frame_anchors"))
    request = _frame(anchors.get("request_frame"))
    response = _frame(anchors.get("response_frame"))
    if request is None:
        request = _frame(_dict(transaction.get("request")).get("frame_number"))
    if response is None:
        response = _frame(_dict(transaction.get("response")).get("frame_number"))
    return request, response


def _transaction_ebis(
    transaction: dict[str, Any], items_by_reference: dict[str, dict[str, Any]]
) -> list[int]:
    ebis: set[int] = set()
    for key in ("request_bearer_item_references", "response_bearer_item_references"):
        for reference in _list(transaction.get(key)):
            item = items_by_reference.get(reference) if isinstance(reference, str) else None
            if not isinstance(item, dict):
                continue
            if item.get("ebi_status") != "VALID":
                continue
            ebi = _int(item.get("ebi"))
            if ebi is not None and 0 <= ebi <= 15:
                ebis.add(ebi)
    return sorted(ebis)


def _item_outcome_summary(
    transaction: dict[str, Any], items_by_reference: dict[str, dict[str, Any]]
) -> dict[str, int]:
    outcomes: list[str] = []
    for key in ("request_bearer_item_references", "response_bearer_item_references"):
        for reference in _list(transaction.get(key)):
            item = items_by_reference.get(reference) if isinstance(reference, str) else None
            if isinstance(item, dict) and isinstance(item.get("item_outcome"), str):
                outcomes.append(item["item_outcome"])
    return _ordered_counts(outcomes)


def _s1ap_context_by_frame(events: list[dict[str, Any]]) -> dict[int, list[str]]:
    index: dict[int, list[str]] = {}
    for event in events:
        frame = _frame(event.get("frame_number"))
        context = _text(event.get("context_key"))
        if frame is not None and context is not None:
            index.setdefault(frame, []).append(context)
    return {frame: sorted(set(values)) for frame, values in index.items()}


def _dedicated_nas_observations(
    events: list[dict[str, Any]], capture: str, s1ap_by_frame: dict[int, list[str]]
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for event in events:
        event_capture = _text(event.get("capture_file"))
        if event_capture is not None and event_capture != capture:
            continue
        frame = _frame(event.get("frame_number"))
        if frame is None:
            continue
        contexts = s1ap_by_frame.get(frame) or []
        context = contexts[0] if len(contexts) == 1 else None
        for message in _list(event.get("esm_messages")):
            message = _dict(message)
            code = _int(message.get("message_type_code"))
            if code not in (197, 198, 199, 201, 202, 203, 205, 206):
                continue
            occurrence = _int(message.get("occurrence_index")) or 0
            limitations = [
                text for text in (_text(value) for value in _list(message.get("limitations")) if isinstance(value, str)) if text
            ]
            if len(contexts) > 1:
                limitations.append(
                    "the same frame carries more than one S1AP UE context, so the ESM UE context is ambiguous"
                )
            elif not contexts:
                limitations.append(
                    "the frame carries no S1AP UE context, so the ESM UE context cannot be scoped from this evidence"
                )
            observations.append(
                {
                    "reference": f"nas-esm:{capture}:{frame}:{occurrence}",
                    "frame_number": frame,
                    "kind": "NAS_ESM",
                    "source_analysis": "nas-eps",
                    "support_status": _text(message.get("support_status")),
                    "procedure": _text(message.get("procedure")),
                    "result": _text(message.get("result")),
                    "eps_bearer_identity": _int(message.get("eps_bearer_identity")),
                    "erab_id": None,
                    "operation": None,
                    "direction": _text(message.get("direction")) or _text(event.get("direction")),
                    "protection_state": _text(message.get("protection_state")),
                    "ue_context_reference": context,
                    "binding_basis": _text(message.get("binding_basis")),
                    "message_type_code": code,
                    "message_type": _text(message.get("message_type")),
                    "limitations": limitations[:MAX_LIST_ITEMS],
                }
            )
    return observations


def _dedicated_s1ap_observations(
    events: list[dict[str, Any]], capture: str
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for event in events:
        event_capture = _text(event.get("capture_file"))
        if event_capture is not None and event_capture != capture:
            continue
        frame = _frame(event.get("frame_number"))
        if frame is None:
            continue
        context = _text(event.get("context_key"))
        items = _list(event.get("erab_items"))
        if items:
            for index, raw in enumerate(items):
                item = _dict(raw)
                operation = _text(item.get("operation"))
                if operation not in ("E_RAB_SETUP", "E_RAB_MODIFY", "E_RAB_RELEASE"):
                    continue
                observations.append(
                    {
                        "reference": f"s1ap-erab:{capture}:{frame}:{index}",
                        "frame_number": frame,
                        "kind": "S1AP_ERAB",
                        "source_analysis": "s1ap",
                        "support_status": _text(event.get("support_status")) or "SUPPORTED",
                        "procedure": _text(event.get("procedure_name")),
                        "result": _text(item.get("list_role")),
                        "eps_bearer_identity": None,
                        "erab_id": _int(item.get("erab_id")),
                        "operation": operation,
                        "direction": _text(event.get("sender_role")),
                        "protection_state": None,
                        "ue_context_reference": context,
                        "binding_basis": _text(item.get("binding_basis")),
                        "limitations": [
                            text
                            for text in (_text(value) for value in _list(item.get("limitations")) if isinstance(value, str))
                            if text
                        ][:MAX_LIST_ITEMS],
                    }
                )
            continue
        unbound = _dict(event.get("unbound_erab_evidence"))
        if not unbound:
            continue
        operations = [
            value
            for value in _list(unbound.get("list_operations"))
            if value in ("E_RAB_SETUP", "E_RAB_MODIFY", "E_RAB_RELEASE")
        ]
        if not operations:
            continue
        observations.append(
            {
                "reference": f"s1ap-erab-unbound:{capture}:{frame}",
                "frame_number": frame,
                "kind": "S1AP_ERAB_UNBOUND",
                "source_analysis": "s1ap",
                "support_status": "UNSUPPORTED",
                "procedure": _text(event.get("procedure_name")),
                "result": (_list(unbound.get("list_roles")) or [None])[0],
                "eps_bearer_identity": None,
                "erab_id": None,
                "operation": operations[0],
                "direction": _text(event.get("sender_role")),
                "protection_state": None,
                "ue_context_reference": context,
                "binding_basis": "flat_fields",
                "limitations": [
                    "the dissector tree exposed no provable E-RAB item boundary; no item identity is fabricated"
                ],
            }
        )
    return observations


def _association(
    status: str, basis: list[str], candidates: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "status": status,
        "evidence_basis": basis[:MAX_LIST_ITEMS],
        "candidate_count": len(candidates),
        "candidate_contexts": sorted(
            {
                candidate["ue_context_reference"]
                for candidate in candidates
                if isinstance(candidate.get("ue_context_reference"), str)
            }
        )[:MAX_LIST_ITEMS],
    }


def _nas_association(
    transaction: dict[str, Any],
    family: str,
    ebis: list[int],
    request: int | None,
    response: int | None,
    observations: list[dict[str, Any]],
    sibling_count: int,
    control_context: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    codes = FAMILY_ESM[family]
    lower = request if request is not None else (response if response is not None else 0)
    upper = response if response is not None else (lower + ASSOCIATION_WINDOW_FRAMES if lower else 1 << 30)
    candidates = [
        item
        for item in observations
        if item["message_type_code"] in codes
        and item["eps_bearer_identity"] in ebis
        and lower <= item["frame_number"] <= upper
    ]
    basis: list[str] = [
        "capture-scoped NAS-EPS event and accepted Dedicated Bearer control artifact",
        "procedure family, EPS bearer identity and control observation window matched",
    ]
    if not candidates:
        return _association(NOT_OBSERVED, basis, []), []
    if any(candidate.get("support_status") != "SUPPORTED" for candidate in candidates):
        basis.append("at least one matching ESM identity is only recognized, not semantically supported")
        return _association(UNSUPPORTED, basis, candidates), candidates
    request_items = [item for item in candidates if item.get("result") in REQUEST_RESULTS]
    completion_items = [item for item in candidates if item.get("result") in COMPLETION_RESULTS]
    if sibling_count > 1:
        basis.append("multiple control transactions share the same procedure family and bearer identity")
        basis.append("a bearer-identity match alone is not a cross-layer identity proof")
        return _association(AMBIGUOUS, basis, candidates), candidates
    if len(request_items) > 1 or len(completion_items) > 1:
        basis.append("more than one ESM request or completion message matches the same control observation")
        basis.append("a bearer-identity match alone is not a cross-layer identity proof")
        return _association(AMBIGUOUS, basis, candidates), candidates
    if len(request_items) != 1 or len(completion_items) != 1:
        basis.append("the observed ESM messages do not form exactly one request and one completion")
        basis.append("a bearer-identity match alone is not a cross-layer identity proof")
        return _association(CANDIDATE, basis, candidates), candidates
    if request_items[0]["frame_number"] > completion_items[0]["frame_number"]:
        basis.append("the ESM completion frame precedes its request frame")
        return _association(CANDIDATE, basis, candidates), candidates
    candidate_contexts = {
        item.get("ue_context_reference") for item in (request_items + completion_items)
    }
    if (
        control_context is not None
        and len(candidate_contexts) == 1
        and control_context in candidate_contexts
    ):
        basis.append(f"shared capture-scoped UE context {control_context}")
        basis.append("exactly one ESM request and completion pair matches the control observation window")
        return _association(ESTABLISHED, basis, candidates), candidates
    basis.append("no shared UE context exists between the control artifact and the ESM observations")
    basis.append("a bearer-identity match plus frame order is not sufficient for an established link")
    return _association(CANDIDATE, basis, candidates), candidates


def _s1ap_association(
    family: str,
    request: int | None,
    response: int | None,
    observations: list[dict[str, Any]],
    control_context: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    operations = FAMILY_ERAB[family]
    lower = request if request is not None else (response if response is not None else 0)
    upper = response if response is not None else (lower + ASSOCIATION_WINDOW_FRAMES if lower else 1 << 30)
    candidates = [
        item
        for item in observations
        if item["operation"] in operations
        and lower <= item["frame_number"] <= upper
    ]
    basis: list[str] = [
        "capture-scoped S1AP event and accepted Dedicated Bearer control artifact",
        "protocol procedure ownership and control observation window matched",
    ]
    if not candidates:
        return _association(NOT_OBSERVED, basis, []), []
    if any(candidate.get("kind") == "S1AP_ERAB_UNBOUND" for candidate in candidates):
        basis.append("the S1AP evidence has no provable E-RAB item boundary")
        basis.append("flattened E-RAB fields were not converted into a fabricated item")
        return _association(UNSUPPORTED, basis, candidates), candidates
    contexts = {
        candidate.get("ue_context_reference")
        for candidate in candidates
        if candidate.get("ue_context_reference")
    }
    if len(contexts) > 1:
        basis.append("more than one S1AP UE context carries candidate E-RAB items")
        basis.append("an E-RAB identifier alone is not an EPS bearer identity")
        return _association(AMBIGUOUS, basis, candidates), candidates
    if control_context is not None and contexts == {control_context}:
        basis.append(f"shared capture-scoped UE context {control_context}")
        return _association(ESTABLISHED, basis, candidates), candidates
    results = {candidate.get("result") for candidate in candidates}
    if not (results & REQUEST_RESULTS) or not (results & COMPLETION_RESULTS):
        basis.append("the observed E-RAB procedure is missing its request or completion message")
    basis.append("no shared UE context exists between the control artifact and the S1AP observations")
    basis.append("an E-RAB identifier alone is not an EPS bearer identity")
    basis.append("temporal proximity alone is not a cross-layer identity proof")
    return _association(CANDIDATE, basis, candidates), candidates


def _combined_status(nas: str, s1ap: str) -> str:
    if ESTABLISHED in (nas, s1ap):
        return ESTABLISHED
    if AMBIGUOUS in (nas, s1ap):
        return AMBIGUOUS
    if CANDIDATE in (nas, s1ap):
        return CANDIDATE
    if UNSUPPORTED in (nas, s1ap):
        return UNSUPPORTED
    if nas == NOT_OBSERVED and s1ap == NOT_OBSERVED:
        return NOT_OBSERVED
    return NOT_ESTABLISHED


def _public_reference(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        key: observation.get(key)
        for key in (
            "reference",
            "frame_number",
            "kind",
            "source_analysis",
            "support_status",
            "procedure",
            "result",
            "eps_bearer_identity",
            "erab_id",
            "operation",
            "direction",
            "protection_state",
            "ue_context_reference",
            "binding_basis",
            "limitations",
        )
    }


def build_timeline(
    control: dict[str, Any],
    nas_events: list[dict[str, Any]],
    s1ap_events: list[dict[str, Any]],
    *,
    control_path: Path,
    nas_path: Path | None,
    s1ap_path: Path | None,
) -> dict[str, Any]:
    capture = _text(control.get("input_provenance", {}).get("gtpv2_events"))
    capture_names = sorted(
        {
            _text(_dict(item).get("capture"))
            for item in _list(control.get("control_transactions"))
            if isinstance(item.get("capture"), str)
        }
    )
    if len(capture_names) == 1:
        capture = capture_names[0]
    elif capture_names:
        capture = capture_names[0]
    if capture is None:
        capture = "unknown-capture"

    transactions = []
    for raw in _list(control.get("control_transactions")):
        transaction = _dict(raw)
        if _text(transaction.get("capture")) not in (None, capture):
            continue
        transactions.append(transaction)
    transactions.sort(
        key=lambda item: (
            _transaction_frames(item)[0] or 1 << 30,
            str(item.get("procedure_family")),
            str(item.get("transaction_reference")),
        )
    )
    items_by_reference = {
        str(item.get("item_reference")): _dict(item)
        for item in _list(control.get("bearer_item_observations"))
        if isinstance(item, dict) and isinstance(item.get("item_reference"), str)
    }

    s1ap_by_frame = _s1ap_context_by_frame(s1ap_events)
    nas_observations = _dedicated_nas_observations(nas_events, capture, s1ap_by_frame)
    s1ap_observations = _dedicated_s1ap_observations(s1ap_events, capture)

    entries: list[dict[str, Any]] = []
    for transaction in transactions:
        family = _text(transaction.get("procedure_family"))
        if family not in FAMILY_ESM:
            continue
        reference = _text(transaction.get("transaction_reference")) or "unidentified-control-transaction"
        request, response = _transaction_frames(transaction)
        ebis = _transaction_ebis(transaction, items_by_reference)
        control_context = _text(transaction.get("ue_context_reference"))
        sibling_count = sum(
            1
            for other in transactions
            if other.get("procedure_family") == family
            and set(_transaction_ebis(other, items_by_reference)) & set(ebis)
        )
        nas_association, nas_candidates = _nas_association(
            transaction, family, ebis, request, response, nas_observations, sibling_count, control_context
        )
        s1ap_association, s1ap_candidates = _s1ap_association(
            family, request, response, s1ap_observations, control_context
        )
        status = _combined_status(nas_association["status"], s1ap_association["status"])
        basis = sorted(
            set(nas_association["evidence_basis"] + s1ap_association["evidence_basis"])
        )
        limitations: list[str] = []
        if request is None:
            limitations.append("the accepted control transaction has no request frame anchor")
        if response is None:
            limitations.append("the accepted control transaction has no response frame; the procedure may be incomplete")
        if not ebis:
            limitations.append("no valid EPS bearer identity was published for the control transaction")
            limitations.append("NAS-ESM association cannot be attempted from an invalid or absent EBI")
        if not control_context:
            limitations.append("the accepted control artifact carries no shared UE context reference")
        if s1ap_path is None:
            limitations.append("no S1AP event stream was supplied to the timeline")
        if nas_path is None:
            limitations.append("no NAS-EPS event stream was supplied to the timeline")

        entry_not_confirmed = [
            "a GTPv2-C accepted Cause is a control-plane outcome and does not prove UE acceptance",
            "observed control and access signaling do not prove end-to-end user-plane delivery",
        ]
        if status != ESTABLISHED:
            entry_not_confirmed.append(
                "no cross-layer association between the control transaction and NAS/S1AP evidence is established"
            )
        entries.append(
            {
                "entry_reference": f"epc-db-timeline:{capture}:{reference}",
                "capture": capture,
                "control_transaction_reference": reference,
                "procedure_family": family,
                "request_frame": request,
                "response_frame": response,
                "correlation_status": _text(transaction.get("correlation_status")),
                "message_outcome": _text(_dict(transaction.get("message_outcome")).get("status")),
                "bearer_item_outcome_summary": _item_outcome_summary(transaction, items_by_reference),
                "observed_nas_esm_references": [
                    _public_reference(item) for item in nas_candidates[:MAX_SOURCE_REFERENCES]
                ],
                "observed_s1ap_erab_references": [
                    _public_reference(item) for item in s1ap_candidates[:MAX_SOURCE_REFERENCES]
                ],
                "nas_esm_association": nas_association,
                "s1ap_erab_association": s1ap_association,
                "cross_layer_association_status": status,
                "association_evidence_basis": basis[:MAX_LIST_ITEMS],
                "source_completeness_status": _text(transaction.get("source_completeness_status")),
                "limitations": limitations[:MAX_LIST_ITEMS],
                "not_confirmed": entry_not_confirmed,
            }
        )

    entries.sort(
        key=lambda item: (
            item["request_frame"] if item["request_frame"] is not None else 1 << 30,
            item["procedure_family"],
            item["entry_reference"],
        )
    )
    total_entries = len(entries)
    published = entries[:MAX_TIMELINE_ENTRIES]
    omitted = max(0, total_entries - len(published))
    status_counts = _ordered_counts(item["cross_layer_association_status"] for item in entries)
    unresolved = [
        {
            "entry_reference": item["entry_reference"],
            "status": item["cross_layer_association_status"],
            "reason": (item["association_evidence_basis"] or ["no association evidence"])[-1],
        }
        for item in entries
        if item["cross_layer_association_status"] != ESTABLISHED
    ][:MAX_UNRESOLVED_EVIDENCE]
    source_limitations = []
    if nas_path is None:
        source_limitations.append("NAS-EPS events were not supplied; NAS-ESM coverage is NOT_OBSERVED")
    if s1ap_path is None:
        source_limitations.append("S1AP events were not supplied; S1AP E-RAB coverage is NOT_OBSERVED")
    return {
        "domain": "epc-procedures",
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "input_provenance": {
            "control_artifact": control_path.name,
            "control_artifact_sha256": sha256_file(control_path),
            "nas_events": nas_path.name if nas_path is not None else None,
            "s1ap_events": s1ap_path.name if s1ap_path is not None else None,
            "control_transaction_count": total_entries,
            "nas_event_count": len(nas_events),
            "s1ap_event_count": len(s1ap_events),
        },
        "analysis_scope": {
            "capture": capture,
            "procedures": ["create-bearer", "update-bearer", "delete-bearer"],
            "nas_esm_scope": [
                "197 activate dedicated EPS bearer context request",
                "198 activate dedicated EPS bearer context accept",
                "199 activate dedicated EPS bearer context reject",
                "201 modify EPS bearer context request",
                "202 modify EPS bearer context accept",
                "203 modify EPS bearer context reject",
                "205 deactivate EPS bearer context request",
                "206 deactivate EPS bearer context accept",
            ],
            "s1ap_erab_scope": [
                "E-RAB Setup",
                "E-RAB Modify",
                "E-RAB Release",
                "E-RAB Release Indication",
            ],
            "not_inferred": [
                "no Dedicated Bearer activation success verdict",
                "no UE acceptance inference from a control-plane Cause",
                "no E-RAB item identity from flattened fields",
                "no end-to-end user-plane delivery conclusion",
            ],
        },
        "source_completeness": {
            "status": "COMPLETE" if nas_path is not None and s1ap_path is not None else "PARTIAL",
            "control_source_present": bool(transactions),
            "nas_source_present": nas_path is not None,
            "s1ap_source_present": s1ap_path is not None,
            "limitations": source_limitations,
        },
        "execution_status": "EXECUTED" if transactions else "NOT_OBSERVED_IN_CAPTURE",
        "timeline_entries": published,
        "timeline_entry_count": total_entries,
        "timeline_entries_omitted": omitted,
        "association_status_counts": status_counts,
        "unresolved_evidence": unresolved,
        "not_confirmed": [
            "GTPv2-C control outcomes do not prove UE acceptance",
            "correlated control and access signaling does not prove successful bearer activation",
            "correlated signaling does not prove end-to-end user-plane delivery",
            "absence of NAS-ESM or S1AP E-RAB evidence is not evidence of failure",
        ],
        "bounded": True,
        "limits": {
            "timeline_entries": MAX_TIMELINE_ENTRIES,
            "source_references": MAX_SOURCE_REFERENCES,
            "unresolved_evidence": MAX_UNRESOLVED_EVIDENCE,
        },
    }