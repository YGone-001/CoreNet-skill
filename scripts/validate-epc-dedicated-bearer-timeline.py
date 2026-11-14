#!/usr/bin/env python3
"""Non-vacuous validation of Dedicated Bearer timeline association semantics."""

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
    / "epc_dedicated_bearer_timeline_model.py",
    "timeline_model_validator",
)

CAPTURE = "fixture.pcap"


def reference(frame: int) -> dict:
    return {
        "frame_number": frame,
        "message_type": "Bearer request",
        "message_type_code": 95,
        "sequence_number": 1,
        "header_teid": 0,
        "header_teid_state": "PRESENT",
        "message_occurrence": 1,
    }


def transaction(name: str, family: str, request: int, response: int, ebi: int, context: str | None = None) -> tuple[dict, list[dict]]:
    tx_ref = f"epc-db-tx:{CAPTURE}:{name}"
    request_item = f"epc-db-item:{tx_ref}:request:{request}:0:0"
    response_item = f"epc-db-item:{tx_ref}:response:{response}:0:0"
    tx = {
        "transaction_reference": tx_ref,
        "capture": CAPTURE,
        "procedure_family": family,
        "correlation_status": "MATCHED",
        "request": reference(request),
        "response": reference(response),
        "frame_anchors": {"request_frame": request, "response_frame": response},
        "message_outcome": {"status": "MESSAGE_ACCEPTED_OBSERVED"},
        "request_bearer_item_references": [request_item],
        "response_bearer_item_references": [response_item],
        "source_completeness_status": "COMPLETE",
        "evidence_limitations": [],
    }
    if context:
        tx["ue_context_reference"] = context
    items = [
        {"item_reference": request_item, "ebi": 0, "ebi_status": "INVALID", "item_outcome": "ITEM_REQUEST_EVIDENCE_ONLY"},
        {"item_reference": response_item, "ebi": ebi, "ebi_status": "VALID", "item_outcome": "ITEM_CONTROL_ACCEPTED_OBSERVED"},
    ]
    return tx, items


def control(transactions: list[dict], items: list[dict]) -> dict:
    return {
        "analysis_name": "epc-dedicated-bearer-control",
        "analysis_version": "1.0.0",
        "input_provenance": {"gtpv2_events": CAPTURE},
        "control_transactions": transactions,
        "control_transaction_count": len(transactions),
        "control_transactions_omitted": 0,
        "bearer_item_observations": items,
        "bearer_item_observation_count": len(items),
    }


def nas(frame: int, code: int, result: str, ebi: int) -> dict:
    return {
        "capture_file": CAPTURE,
        "frame_number": frame,
        "direction": "uplink",
        "esm_messages": [
            {
                "occurrence_index": 0,
                "message_type_code": code,
                "support_status": "SUPPORTED",
                "procedure": "dedicated-bearer-control",
                "result": result,
                "eps_bearer_identity": ebi,
                "protection_state": "PLAIN",
                "binding_basis": "pdml_grouped_ie",
                "limitations": [],
            }
        ],
    }


def s1ap(frame: int, operation: str, role: str, erab_id: int | None, context: str, *, unbound: bool = False) -> dict:
    event = {
        "capture_file": CAPTURE,
        "frame_number": frame,
        "procedure_name": "id-E-RABSetup",
        "support_status": "SUPPORTED",
        "sender_role": "mme",
        "context_key": context,
    }
    if unbound:
        event["unbound_erab_evidence"] = {
            "list_operations": [operation],
            "list_roles": [role],
            "erab_ids": [erab_id] if erab_id is not None else [],
            "binding_basis": "flat_fields",
        }
    else:
        event["erab_items"] = [
            {
                "operation": operation,
                "list_role": role,
                "erab_id": erab_id,
                "binding_basis": "pdml_grouped_ie",
                "limitations": [],
            }
        ]
    return event


def build(control_doc: dict, nas_events: list[dict], s1ap_events: list[dict]) -> dict:
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "control.json"
        path.write_text(json.dumps(control_doc), encoding="utf-8")
        return MODEL.build_timeline(
            control_doc,
            nas_events,
            s1ap_events,
            control_path=path,
            nas_path=Path("nas-eps-events.jsonl"),
            s1ap_path=Path("s1ap-events.jsonl"),
        )


def gate_ambiguous_ebi() -> str | None:
    tx1, items1 = transaction("create-1", "create-bearer", 100, 110, 5)
    tx2, items2 = transaction("create-2", "create-bearer", 100, 130, 5)
    timeline = build(
        control([tx1, tx2], items1 + items2),
        [nas(102, 197, "REQUEST", 5), nas(108, 198, "ACCEPT", 5)],
        [],
    )
    statuses = [entry["nas_esm_association"]["status"] for entry in timeline["timeline_entries"]]
    if statuses != ["AMBIGUOUS", "AMBIGUOUS"]:
        return "an EBI match with multiple control candidates was treated as established"
    if any(entry["cross_layer_association_status"] == "ESTABLISHED_BY_EVIDENCE" for entry in timeline["timeline_entries"]):
        return "an ambiguous EBI match produced an established cross-layer association"
    return None


def gate_control_cause() -> str | None:
    tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
    timeline = build(control([tx], items), [], [])
    entry = timeline["timeline_entries"][0]
    if entry["cross_layer_association_status"] == "ESTABLISHED_BY_EVIDENCE":
        return "a GTPv2-C accepted Cause was treated as UE acceptance"
    if entry["cross_layer_association_status"] != "NOT_OBSERVED":
        return "missing access evidence was not reported as NOT_OBSERVED"
    if "bearer_activated" in entry:
        return "a bearer activation verdict was fabricated"
    return None


def gate_unbound_erab() -> str | None:
    tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
    timeline = build(control([tx], items), [], [s1ap(101, "E_RAB_SETUP", "REQUEST", 7, "ctx-1", unbound=True)])
    entry = timeline["timeline_entries"][0]
    if entry["s1ap_erab_association"]["status"] != "UNSUPPORTED_EVIDENCE":
        return "unbound E-RAB fields were treated as supported item evidence"
    references = entry["observed_s1ap_erab_references"]
    if references and references[0]["erab_id"] is not None:
        return "an unbound E-RAB field was converted into a fabricated item identity"
    return None


def gate_unobserved_stage() -> str | None:
    tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
    timeline = build(control([tx], items), [], [])
    entry = timeline["timeline_entries"][0]
    if entry["cross_layer_association_status"] != "NOT_OBSERVED":
        return "an unobserved access stage was marked complete"
    if timeline["source_completeness"]["nas_source_present"] is not True:
        return "the supplied empty NAS source was not distinguished from absence"
    return None


GATES = (
    ("ambiguous EBI", gate_ambiguous_ebi),
    ("control Cause", gate_control_cause),
    ("unbound E-RAB", gate_unbound_erab),
    ("unobserved stage", gate_unobserved_stage),
)


def main() -> int:
    errors: list[str] = []
    for label, gate in GATES:
        check = gate()
        if check:
            errors.append(f"baseline gate failed: {label}: {check}")
    if errors:
        for error in errors:
            print(f"validate-epc-dedicated-bearer-timeline: {error}", file=sys.stderr)
        return 1

    mutations: list[tuple[str, list[str]]] = []
    original_combined = MODEL._combined_status
    original_s1ap = MODEL._dedicated_s1ap_observations
    original_build = MODEL.build_timeline

    MODEL._combined_status = lambda nas, s1ap: (
        "ESTABLISHED_BY_EVIDENCE"
        if nas != "NOT_OBSERVED" or s1ap != "NOT_OBSERVED"
        else original_combined(nas, s1ap)
    )
    try:
        check = gate_ambiguous_ebi()
    finally:
        MODEL._combined_status = original_combined
    mutations.append(("A: correlate by EBI alone", [check] if check else []))

    def patched_build(
        control_doc: dict, nas_events: list[dict], s1ap_events: list[dict], **kwargs: Any
    ) -> dict:
        timeline = original_build(control_doc, nas_events, s1ap_events, **kwargs)
        for entry in timeline["timeline_entries"]:
            entry["cross_layer_association_status"] = "ESTABLISHED_BY_EVIDENCE"
        return timeline

    MODEL.build_timeline = patched_build
    try:
        check = gate_control_cause()
    finally:
        MODEL.build_timeline = original_build
    mutations.append(("B: control Cause as UE acceptance", [check] if check else []))

    def fabricate_unbound(events: list[dict], capture: str) -> list[dict]:
        observations = original_s1ap(events, capture)
        for observation in observations:
            if observation["kind"] == "S1AP_ERAB_UNBOUND":
                observation["kind"] = "S1AP_ERAB"
                observation["erab_id"] = 7
        return observations

    MODEL._dedicated_s1ap_observations = fabricate_unbound
    try:
        check = gate_unbound_erab()
    finally:
        MODEL._dedicated_s1ap_observations = original_s1ap
    mutations.append(("C: fabricate item from unbound fields", [check] if check else []))

    MODEL._combined_status = lambda nas, s1ap: "ESTABLISHED_BY_EVIDENCE"
    try:
        check = gate_unobserved_stage()
    finally:
        MODEL._combined_status = original_combined
    mutations.append(("D: mark unobserved stage complete", [check] if check else []))

    for label, mutation_errors in mutations:
        if not mutation_errors:
            errors.append(f"mutation was not detected: {label}")
    if errors:
        for error in errors:
            print(f"validate-epc-dedicated-bearer-timeline: {error}", file=sys.stderr)
        return 1
    print(
        "validate-epc-dedicated-bearer-timeline: OK "
        f"({len(mutations)} association mutations detected)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())