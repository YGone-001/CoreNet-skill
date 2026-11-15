#!/usr/bin/env python3
"""Non-vacuous validation of Dedicated Bearer attribution inference boundaries."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODEL = load_module(
    ROOT
    / "skills"
    / "domain"
    / "epc-procedures"
    / "scripts"
    / "epc_dedicated_bearer_attribution_model.py",
    "attribution_model_validator",
)

CAPTURE = "fixture.pcap"


def fteid(interface_type: int, teid: int, address: str) -> dict:
    return {"interface_type": interface_type, "teid": teid, "address": address, "join_capable": True}


def context(reference: str, interface_class: str, fteids: list[dict], capture: str = CAPTURE) -> dict:
    return {
        "capture_file": capture,
        "session_context_reference": reference,
        "interface_class": interface_class,
        "association_status": "ESTABLISHED",
        "control_plane_fteids": fteids,
        "bearer_user_plane_fteids": [],
        "member_transactions": [],
    }


def transaction() -> tuple[dict, list[dict]]:
    tx_ref = "epc-db-tx:fixture.pcap:create-1"
    req = f"epc-db-item:{tx_ref}:request:100:0:0"
    res = f"epc-db-item:{tx_ref}:response:110:0:0"
    tx = {
        "transaction_reference": tx_ref,
        "capture": CAPTURE,
        "procedure_family": "create-bearer",
        "correlation_status": "MATCHED",
        "frame_anchors": {"request_frame": 100, "response_frame": 110},
        "message_outcome": {"status": "MESSAGE_ACCEPTED_OBSERVED"},
        "request_bearer_item_references": [req],
        "response_bearer_item_references": [res],
        "source_completeness_status": "COMPLETE",
    }
    items = [
        {
            "item_reference": req,
            "ebi": 0,
            "ebi_status": "INVALID",
            "f_teids": [{"interface_type": 1, "teid": 40987, "ipv4": "10.10.0.139"}],
        },
        {
            "item_reference": res,
            "ebi": 7,
            "ebi_status": "VALID",
            "f_teids": [{"interface_type": 1, "teid": 4261120, "ipv4": "10.10.0.138"}],
        },
    ]
    return tx, items


def control() -> dict:
    tx, items = transaction()
    return {
        "analysis_name": "epc-dedicated-bearer-control",
        "analysis_version": "1.0.0",
        "input_provenance": {"gtpv2_events": CAPTURE},
        "control_transactions": [tx],
        "control_transaction_count": 1,
        "control_transactions_omitted": 0,
        "bearer_item_observations": items,
        "bearer_item_observation_count": len(items),
        "source_completeness": {"status": "COMPLETE"},
    }


def identity(contexts: list[dict], links: list[dict] | None = None) -> dict:
    return {
        "analysis_name": "epc-session-identity",
        "analysis_version": "1.0.0",
        "hop_local_contexts": contexts,
        "endpoint_correspondence_links": links or [],
    }


def gtpv2(frame: int, teid: int, source: str, destination: str) -> dict:
    return {
        "capture_file": CAPTURE,
        "frame_number": frame,
        "header": {"teid": teid},
        "source": {"address": source},
        "destination": {"address": destination},
    }


def nas(frame: int = 105) -> dict:
    return {
        "capture_file": CAPTURE,
        "frame_number": frame,
        "esm_messages": [
            {
                "occurrence_index": 0,
                "message_type_code": 197,
                "support_status": "SUPPORTED",
                "result": "REQUEST",
                "eps_bearer_identity": 7,
                "protection_state": "PLAIN",
                "binding_basis": "pdml_grouped_ie",
                "limitations": [],
            }
        ],
    }


def s1ap(frame: int = 105, *, context_name: str = "s1ap-ctx-1", embedded: bool = True) -> dict:
    return {
        "capture_file": CAPTURE,
        "frame_number": frame,
        "context_key": context_name,
        "procedure_name": "id-E-RABSetup",
        "message_type": "E-RABSetupRequest",
        "support_status": "SUPPORTED",
        "sender_role": "mme",
        "nas_pdu_embedded": embedded,
        "erab_items": [
            {
                "operation": "E_RAB_SETUP",
                "list_role": "REQUEST",
                "erab_id": 7,
                "gtp_teid": 40987,
                "transport_layer_address": "10.10.0.139",
                "binding_basis": "pdml_grouped_ie",
                "limitations": [],
            }
        ],
    }


def build(
    control_doc: dict,
    identity_doc: dict,
    gtpv2_events: list[dict],
    nas_events: list[dict] | None = None,
    s1ap_events: list[dict] | None = None,
) -> dict:
    with tempfile.TemporaryDirectory() as temporary:
        cp = Path(temporary) / "control.json"
        ip = Path(temporary) / "identity.json"
        cp.write_text(json.dumps(control_doc), encoding="utf-8")
        ip.write_text(json.dumps(identity_doc), encoding="utf-8")
        return MODEL.build_attribution(
            control_doc,
            identity_doc,
            gtpv2_events,
            nas_events or [],
            s1ap_events or [],
            control_path=cp,
            identity_path=ip,
            gtpv2_path=Path("gtpv2.jsonl"),
            nas_path=Path("nas.jsonl"),
            s1ap_path=Path("s1ap.jsonl"),
        )


def gate_teid_only() -> str | None:
    ctx = context("ctx-1", "S11", [fteid(10, 1000, "10.0.0.2"), fteid(10, 2000, "10.0.0.1")])
    attribution = build(control(), identity([ctx]), [gtpv2(100, 1000, "10.0.0.1", "10.9.9.9")])
    status = attribution["attribution_entries"][0]["control_session"]["status"]
    if status == "ESTABLISHED_BY_EVIDENCE":
        return "a header TEID match with the wrong receiver endpoint was joined"
    return None


def gate_endpoint_only() -> str | None:
    ctx = context("ctx-1", "S11", [fteid(10, 1000, "10.0.0.2"), fteid(10, 2000, "10.0.0.1")])
    attribution = build(
        control(),
        identity([ctx]),
        [gtpv2(100, 1000, "10.0.0.1", "10.0.0.2")],
        [nas()],
        [s1ap()],
    )
    entry = attribution["attribution_entries"][0]
    if entry["s1ap_access"]["status"] == "ENDPOINT_CORRESPONDENCE_ONLY" and entry["overall_status"] == "ESTABLISHED_BY_EVIDENCE":
        return "endpoint correspondence was promoted to established UE identity"
    if entry["overall_status"] == "ESTABLISHED_BY_EVIDENCE":
        return "a complete control-to-access identity chain was fabricated"
    return None


def gate_multi_ue_isolation() -> str | None:
    tx, items = transaction()
    ctx1 = context("ctx-1", "S11", [fteid(10, 1000, "10.0.0.2"), fteid(10, 2000, "10.0.0.1")])
    ctx2 = context("ctx-2", "S11", [fteid(10, 1000, "10.0.0.2"), fteid(10, 2000, "10.0.0.1")])
    attribution = build(
        control(),
        identity([ctx1, ctx2]),
        [gtpv2(100, 1000, "10.0.0.1", "10.0.0.2")],
        [nas()],
        [s1ap(context_name="ctx-a"), s1ap(context_name="ctx-b")],
    )
    entry = attribution["attribution_entries"][0]
    if entry["control_session"]["status"] != "AMBIGUOUS":
        return "equal EBI/TEID across UE contexts produced a unique session"
    if entry["session_access"]["status"] == "ESTABLISHED_BY_EVIDENCE":
        return "equal EBI/TEID across UE contexts produced an established session-to-access link"
    if entry["overall_status"] == "ESTABLISHED_BY_EVIDENCE":
        return "equal EBI/TEID across UE contexts produced an established chain"
    return None


def gate_nas_encapsulation() -> str | None:
    ctx = context("ctx-1", "S11", [fteid(10, 1000, "10.0.0.2"), fteid(10, 2000, "10.0.0.1")])
    attribution = build(
        control(),
        identity([ctx]),
        [gtpv2(100, 1000, "10.0.0.1", "10.0.0.2")],
        [nas()],
        [s1ap(embedded=False)],
    )
    status = attribution["attribution_entries"][0]["nas_access"]["status"]
    if status == "ESTABLISHED_BY_EVIDENCE":
        return "NAS ownership was resolved from frame proximity without an embedded NAS-PDU"
    return None


GATES = (
    ("TEID only", gate_teid_only),
    ("endpoint only", gate_endpoint_only),
    ("multi-UE isolation", gate_multi_ue_isolation),
    ("NAS encapsulation", gate_nas_encapsulation),
)


def main() -> int:
    errors: list[str] = []
    for label, gate in GATES:
        check = gate()
        if check:
            errors.append(f"baseline gate failed: {label}: {check}")
    if errors:
        for error in errors:
            print(f"validate-epc-dedicated-bearer-attribution: {error}", file=sys.stderr)
        return 1

    mutations: list[tuple[str, list[str]]] = []
    original_join = MODEL._join_candidates
    original_overall = MODEL._overall
    original_erab = MODEL._s1ap_access
    original_nas = MODEL._nas_access
    original_session = MODEL._session_access

    MODEL._join_candidates = lambda contexts, capture, event: [
        context
        for context in contexts
        if any(
            item.get("teid") == (event.get("header") or {}).get("teid")
            for item in context.get("control_plane_fteids") or []
        )
    ]
    try:
        check = gate_teid_only()
    finally:
        MODEL._join_candidates = original_join
    mutations.append(("A: join by header TEID alone", [check] if check else []))

    MODEL._overall = lambda *args, **kwargs: ("ESTABLISHED_BY_EVIDENCE", list(MODEL.__dict__.keys())[:0], ["mutated"])
    try:
        check = gate_endpoint_only()
    finally:
        MODEL._overall = original_overall
    mutations.append(("B: endpoint correspondence as UE identity", [check] if check else []))

    MODEL._s1ap_access = lambda observations, endpoints: {
        "status": "ENDPOINT_CORRESPONDENCE_ONLY",
        "observed_items": observations[:16],
        "endpoint_matches": [],
        "candidate_contexts": [],
        "evidence_basis": ["mutated"],
        "missing_evidence": [],
    }
    MODEL._session_access = lambda identity_doc, control_session, s1ap_access, nas_access: {
        "status": "ESTABLISHED_BY_EVIDENCE",
        "related_session_contexts": [],
        "endpoint_correspondence_references": [],
        "s1ap_candidate_contexts": [],
        "evidence_basis": ["mutated"],
        "missing_evidence": [],
    }
    try:
        check = gate_multi_ue_isolation()
    finally:
        MODEL._s1ap_access = original_erab
        MODEL._session_access = original_session
    mutations.append(("C: merge equal EBI/E-RAB across UE contexts", [check] if check else []))

    def proximity_nas(observations: list[dict], s1ap_by_frame: dict[int, list[dict]], capture: str) -> dict:
        result = original_nas(observations, s1ap_by_frame, capture)
        if result["status"] != "ESTABLISHED_BY_EVIDENCE":
            result = dict(result)
            result["status"] = "ESTABLISHED_BY_EVIDENCE"
            result["owner_s1ap_context"] = "frame-proximity"
        return result

    MODEL._nas_access = proximity_nas
    try:
        check = gate_nas_encapsulation()
    finally:
        MODEL._nas_access = original_nas
    mutations.append(("D: NAS ownership by frame proximity", [check] if check else []))

    for label, mutation_errors in mutations:
        if not mutation_errors:
            errors.append(f"mutation was not detected: {label}")
    if errors:
        for error in errors:
            print(f"validate-epc-dedicated-bearer-attribution: {error}", file=sys.stderr)
        return 1
    print(
        "validate-epc-dedicated-bearer-attribution: OK "
        f"({len(mutations)} attribution mutations detected)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())