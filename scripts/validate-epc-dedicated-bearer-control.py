#!/usr/bin/env python3
"""Behavior validation for the EPC dedicated-bearer control producer."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def validate(root: Path = ROOT) -> list[str]:
    errors: list[str] = []

    def fail(message: str) -> None:
        errors.append(message)

    skill = root / "skills" / "domain" / "epc-procedures"
    protocol = root / "skills" / "protocol" / "gtpv2" / "examples"
    model = load_module(
        skill / "scripts" / "epc_dedicated_bearer_control_model.py",
        "epc_dedicated_bearer_control_validator_model",
    )
    events = model.read_jsonl(protocol / "expected" / "bearer-control-events.jsonl")
    transactions = model.read_json(protocol / "expected" / "bearer-control-transactions.json")
    schema_path = skill / "schemas" / "epc-dedicated-bearer-control-analysis.schema.json"

    def analyze(evts=None, txs=None, identity=None):
        return model.analyze(
            copy.deepcopy(events if evts is None else evts),
            copy.deepcopy(transactions if txs is None else txs),
            session_identity=identity,
            provenance={
                "gtpv2_events": "gtpv2-events.jsonl",
                "transaction_artifact": "gtpv2-transactions.json",
                "session_identity": "epc-session-identity-analysis.json" if identity else None,
            },
        )

    baseline = analyze()
    families = [item["procedure_family"] for item in baseline["control_transactions"]]
    if families != ["create-bearer", "update-bearer", "delete-bearer"]:
        fail("all three dedicated-bearer control procedures must be analyzed")
    if baseline["control_transaction_count"] != 3:
        fail("the accepted fixture must produce three control transactions")
    create = next(item for item in baseline["control_transactions"] if item["procedure_family"] == "create-bearer")
    update = next(item for item in baseline["control_transactions"] if item["procedure_family"] == "update-bearer")
    delete = next(item for item in baseline["control_transactions"] if item["procedure_family"] == "delete-bearer")
    if create["message_outcome"]["status"] != "MESSAGE_ACCEPTED_OBSERVED":
        fail("Create Bearer message outcome must be accepted")
    if create["transaction_outcome"] != "CONTROL_PARTIAL_OR_MIXED":
        fail("mixed Create Bearer item outcomes must not become transaction acceptance")
    if update["transaction_outcome"] != "CONTROL_ACCEPTED_OBSERVED":
        fail("Update Bearer accepted transaction outcome is required")
    if delete["transaction_outcome"] != "CONTROL_ACCEPTED_OBSERVED":
        fail("Delete Bearer accepted transaction outcome is required")

    response_items = [
        item
        for item in baseline["bearer_item_observations"]
        if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
        and item["side"] == "RESPONSE"
    ]
    if [item["ebi"] for item in response_items] != [5, 6]:
        fail("two grouped Bearer Context items must remain separate")
    if [item["item_outcome"] for item in response_items] != [
        "ITEM_CONTROL_ACCEPTED_OBSERVED",
        "ITEM_CONTROL_REJECTED_OBSERVED",
    ]:
        fail("message-level Cause must not be copied to every bearer item")
    if [item["cause"]["cause_code"] for item in response_items] != [16, 73]:
        fail("item-specific Cause values must be preserved")

    associations = [
        item
        for item in baseline["item_associations"]
        if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
    ]
    if sorted(item["ebi"] for item in associations if item["status"] == "ITEM_ASSOCIATION_ESTABLISHED") != [5, 6]:
        fail("unique valid EBIs must establish the two item associations")

    missing_cause = copy.deepcopy(events)
    for event in missing_cause:
        if event.get("frame_number") == 2:
            event["bearer_contexts"][0]["cause"] = None
    missing_analysis = analyze(evts=missing_cause)
    missing_item = next(
        item
        for item in missing_analysis["bearer_item_observations"]
        if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
        and item["side"] == "RESPONSE"
        and item["item_index"] == 0
    )
    if missing_item["item_outcome"] != "ITEM_OUTCOME_NOT_OBSERVED":
        fail("a missing bearer-item Cause must not become accepted")

    duplicate = copy.deepcopy(events)
    for event in duplicate:
        if event.get("frame_number") == 2:
            event["bearer_contexts"][1]["ebi"] = event["bearer_contexts"][0]["ebi"]
    duplicate_analysis = analyze(evts=duplicate)
    if any(
        item["status"] == "ITEM_ASSOCIATION_ESTABLISHED"
        for item in duplicate_analysis["item_associations"]
        if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
    ):
        fail("duplicate EBI evidence must not create a unique item association")

    cross_capture = copy.deepcopy(events)
    for event in cross_capture:
        if event.get("frame_number") == 2:
            event["capture_file"] = "other-capture.pcap"
    cross_analysis = analyze(evts=cross_capture)
    cross_create = next(
        item for item in cross_analysis["control_transactions"] if item["procedure_family"] == "create-bearer"
    )
    if cross_analysis["source_completeness"]["status"] != "INVALID":
        fail("cross-capture item evidence must fail closed")
    if cross_create["transaction_outcome"] != "CONTROL_OUTCOME_UNRESOLVED":
        fail("cross-capture item evidence must not publish a control outcome")
    if any(
        item["status"] == "ITEM_ASSOCIATION_ESTABLISHED"
        for item in cross_analysis["item_associations"]
        if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
    ):
        fail("cross-capture items must not be associated")

    session_analysis = analyze(
        identity={
            "analysis_name": "epc-session-identity",
            "analysis_version": "1.0.0",
            "hop_local_contexts": [
                {"capture_file": "bearer-control.pdml", "session_context_reference": "ctx-test"}
            ],
        }
    )
    if session_analysis["session_identity_context"]["status"] != "NOT_ESTABLISHED":
        fail("optional session identity must not publish an unsupported established relationship")
    if session_analysis["session_identity_context"]["associated_transaction_references"]:
        fail("optional session identity must not invent transaction associations")

    rendered = json.dumps(baseline).lower()
    for forbidden in (
        "bearer_activated",
        "bearer_established",
        "resource_admitted",
        "tft_installed",
        "forwarding_stopped",
    ):
        if forbidden in rendered:
            fail(f"control evidence promoted to unsupported lifecycle claim: {forbidden}")

    if baseline["source_completeness"]["exhaustive_coverage_proven"] is not False:
        fail("bounded input must not claim exhaustive coverage")
    for key in (
        "control_transactions_omitted",
        "bearer_item_observations_omitted",
        "item_associations_omitted",
    ):
        if key not in baseline:
            fail(f"bounded output lacks {key}")

    bounded_transactions = copy.deepcopy(transactions)
    template = bounded_transactions["transactions"][0]
    bounded_transactions["transactions"] = [copy.deepcopy(template) for _ in range(130)]
    bounded = analyze(txs=bounded_transactions)
    if bounded["control_transaction_count"] < 130 or bounded["control_transactions_omitted"] <= 0:
        fail("bounded transaction publication must report omissions")

    if json.dumps(analyze(), sort_keys=True) != json.dumps(analyze(), sort_keys=True):
        fail("identical input must produce deterministic output")

    private = copy.deepcopy(transactions)
    private["transactions"][0]["limitations"] = ["imsi 460020000000001", "ordinary limitation"]
    if "460020000000001" in json.dumps(analyze(txs=private)):
        fail("subscriber identity must not be published")

    try:
        import jsonschema

        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(baseline, schema)
        reordered = copy.deepcopy(events)
        response = next(item for item in reordered if item.get("frame_number") == 2)
        response["bearer_contexts"].reverse()
        jsonschema.validate(analyze(evts=reordered), schema)
    except ImportError:
        pass
    except Exception as exc:
        fail(f"schema validation failed: {exc}")

    original_item = model._item_observations

    def promote_message_cause(*args, **kwargs):
        items = original_item(*args, **kwargs)
        if kwargs.get("side") == model.SIDE_RESPONSE:
            event = kwargs.get("event") or {}
            message_cause = model._cause(event, "message_cause")
            if message_cause is not None:
                for item in items:
                    item["cause"] = dict(message_cause, scope="bearer")
                    item["item_outcome"] = model.ITEM_ACCEPTED
        return items

    try:
        model._item_observations = promote_message_cause
        mutated_cause = analyze()
    finally:
        model._item_observations = original_item
    mutated_create = next(
        item for item in mutated_cause["control_transactions"] if item["procedure_family"] == "create-bearer"
    )
    if mutated_create["transaction_outcome"] != "CONTROL_ACCEPTED_OBSERVED":
        fail("mutation check failed: promoting the message Cause to items was not detected")
    restored_create = next(
        item for item in analyze()["control_transactions"] if item["procedure_family"] == "create-bearer"
    )
    if restored_create["transaction_outcome"] != "CONTROL_PARTIAL_OR_MIXED":
        fail("mutation restore failed: message Cause stayed promoted")

    original_associate = model._associate_items

    def pair_by_index(request_items, response_items, correlation_status):
        if (
            correlation_status == model.CORRELATION_MATCHED
            and len(request_items) == len(response_items)
            and request_items
        ):
            return [
                model._association(
                    request,
                    response,
                    model.ASSOC_ESTABLISHED,
                    ["pairwise list index"],
                    [],
                )
                for request, response in zip(request_items, response_items)
            ]
        return original_associate(request_items, response_items, correlation_status)

    try:
        model._associate_items = pair_by_index
        index_mutated = analyze(evts=copy.deepcopy(events))
    finally:
        model._associate_items = original_associate
    if any(
        item["status"] == "ITEM_ASSOCIATION_ESTABLISHED"
        and item["request_item_reference"]
        and item["response_item_reference"]
        and item["ebi"] != 5
        and item["ebi"] != 6
        for item in index_mutated["item_associations"]
    ):
        fail("mutation check failed: list-index pairing produced an invalid EBI association")
    # Reordered arrays make index pairing visibly wrong even when EBI values remain 5/6.
    reordered_events = copy.deepcopy(events)
    response_event = next(item for item in reordered_events if item.get("frame_number") == 2)
    response_event["bearer_contexts"].reverse()
    try:
        model._associate_items = pair_by_index
        index_reordered = analyze(evts=reordered_events)
    finally:
        model._associate_items = original_associate
    mismatched = [
        item
        for item in index_reordered["item_associations"]
        if item["status"] == "ITEM_ASSOCIATION_ESTABLISHED"
        and item["request_item_reference"]
        and item["response_item_reference"]
    ]
    baseline_reordered = analyze(evts=reordered_events)
    baseline_established = {
        (item["request_item_reference"], item["response_item_reference"])
        for item in baseline_reordered["item_associations"]
        if item["status"] == "ITEM_ASSOCIATION_ESTABLISHED"
        and item["request_item_reference"]
        and item["response_item_reference"]
    }
    if not mismatched or {
        (item["request_item_reference"], item["response_item_reference"]) for item in mismatched
    } == baseline_established:
        fail("mutation check failed: list-index item pairing was not detected")
    if not baseline_established:
        fail("mutation restore failed: correct EBI association disappeared")

    original_outcome = model._transaction_outcome

    def activation_outcome(*args, **kwargs):
        return "BEARER_ACTIVATED", ["mutated lifecycle promotion"]

    try:
        model._transaction_outcome = activation_outcome
        activation_analysis = analyze()
    finally:
        model._transaction_outcome = original_outcome
    if not any(
        item["transaction_outcome"] == "BEARER_ACTIVATED"
        for item in activation_analysis["control_transactions"]
    ):
        fail("mutation check failed: accepted signaling to activation was not detected")
    if any(
        item["transaction_outcome"] == "BEARER_ACTIVATED"
        for item in analyze()["control_transactions"]
    ):
        fail("mutation restore failed: activation outcome stayed active")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("epc-dedicated-bearer-control validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("epc-dedicated-bearer-control validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())