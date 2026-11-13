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
            message_cause, _detail = model._cause(event, "message_cause", "message")
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


    wrong_message = copy.deepcopy(events)
    for event in wrong_message:
        if event.get("frame_number") == 2:
            event["message_cause"]["scope"] = "bearer"
    wrong_message_analysis = analyze(evts=wrong_message)
    wrong_message_tx = next(
        item for item in wrong_message_analysis["control_transactions"] if item["procedure_family"] == "create-bearer"
    )
    if wrong_message_tx["message_outcome"]["status"] != "MESSAGE_OUTCOME_UNRESOLVED":
        fail("a bearer-scoped message Cause must not establish message acceptance")
    if wrong_message_tx["message_outcome"]["cause"]["scope"] != "bearer":
        fail("an invalid-scope Cause code must be preserved as bounded diagnostic evidence")

    wrong_item = copy.deepcopy(events)
    for event in wrong_item:
        if event.get("frame_number") == 2:
            event["bearer_contexts"][0]["cause"]["scope"] = "message"
    wrong_item_analysis = analyze(evts=wrong_item)
    wrong_items = [
        item
        for item in wrong_item_analysis["bearer_item_observations"]
        if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
        and item["side"] == "RESPONSE"
    ]
    if wrong_items[0]["item_outcome"] != "ITEM_OUTCOME_UNRESOLVED":
        fail("a message-scoped bearer Cause must not establish item acceptance")
    if wrong_items[1]["item_outcome"] != "ITEM_CONTROL_REJECTED_OBSERVED":
        fail("an independently valid item Cause must remain valid beside an invalid item")

    missing_scope = copy.deepcopy(events)
    for event in missing_scope:
        if event.get("frame_number") == 2:
            event["message_cause"].pop("scope", None)
    if next(
        item for item in analyze(evts=missing_scope)["control_transactions"] if item["procedure_family"] == "create-bearer"
    )["message_outcome"]["status"] != "MESSAGE_OUTCOME_UNRESOLVED":
        fail("a message Cause without scope must not establish message acceptance")

    partial = copy.deepcopy(events)
    for event in partial:
        if event.get("frame_number") == 2:
            event["message_cause"]["cause_code"] = 17
            event["message_cause"]["cause_name"] = "Request accepted partially"
    partial_analysis = analyze(evts=partial)
    partial_tx = next(
        item for item in partial_analysis["control_transactions"] if item["procedure_family"] == "create-bearer"
    )
    if partial_tx["message_outcome"]["status"] != "MESSAGE_PARTIALLY_ACCEPTED_OBSERVED":
        fail("Cause 17 must be classified as partial acceptance, not rejection")
    if partial_tx["transaction_outcome"] != "CONTROL_PARTIAL_OR_MIXED":
        fail("partial acceptance must map to a conservative partial/mixed transaction")

    partial_item = copy.deepcopy(events)
    for event in partial_item:
        if event.get("frame_number") == 2:
            event["bearer_contexts"][0]["cause"]["cause_code"] = 17
            event["bearer_contexts"][0]["cause"]["cause_name"] = "Request accepted partially"
    partial_item_analysis = analyze(evts=partial_item)
    partial_item_row = next(
        item
        for item in partial_item_analysis["bearer_item_observations"]
        if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
        and item["side"] == "RESPONSE"
        and item["item_index"] == 0
    )
    if partial_item_row["item_outcome"] != "ITEM_CONTROL_PARTIALLY_ACCEPTED_OBSERVED":
        fail("bearer-item Cause 17 must not become ordinary acceptance or rejection")

    unknown = copy.deepcopy(events)
    for event in unknown:
        if event.get("frame_number") == 2:
            event["message_cause"]["cause_code"] = 999
            event["message_cause"]["cause_name"] = "Unreviewed cause"
    unknown_tx = next(
        item for item in analyze(evts=unknown)["control_transactions"] if item["procedure_family"] == "create-bearer"
    )
    if unknown_tx["message_outcome"]["status"] != "MESSAGE_OUTCOME_UNRESOLVED":
        fail("an unreviewed Cause code must not be assigned a rejection classification")

    missing_response = copy.deepcopy(transactions)
    next(
        item for item in missing_response["transactions"] if item["procedure_family"] == "create-bearer"
    )["response"] = None
    missing_response_analysis = analyze(txs=missing_response)
    missing_tx = next(
        item for item in missing_response_analysis["control_transactions"] if item["procedure_family"] == "create-bearer"
    )
    if missing_tx["source_completeness_status"] == "COMPLETE":
        fail("a matched transaction without a selected Response must not be complete")
    if missing_response_analysis["source_completeness"]["reference_complete"]:
        fail("global reference completeness must be false when a mandatory Response is missing")
    if missing_tx["transaction_outcome"] != "CONTROL_OUTCOME_UNRESOLVED":
        fail("a missing selected Response must keep the transaction unresolved")
    if any(
        item["status"] == "ITEM_ASSOCIATION_ESTABLISHED"
        for item in missing_response_analysis["item_associations"]
        if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
    ):
        fail("no item association may be established through a missing Response")

    open_missing_response = copy.deepcopy(transactions)
    open_tx = next(
        item for item in open_missing_response["transactions"] if item["procedure_family"] == "create-bearer"
    )
    open_tx["correlation_status"] = "OPEN_REQUEST"
    open_tx["response"] = None
    if next(
        item for item in analyze(txs=open_missing_response)["control_transactions"] if item["procedure_family"] == "create-bearer"
    )["source_completeness_status"] != "COMPLETE":
        fail("an absent Response in OPEN_REQUEST must not be treated as malformed")

    invalid_then_truncated = copy.deepcopy(transactions)
    invalid = copy.deepcopy(invalid_then_truncated["transactions"][0])
    invalid["transaction_reference"] = ""
    truncated = copy.deepcopy(invalid_then_truncated["transactions"][1])
    truncated["response"] = {"frame_number": 99, "message_type_code": 98, "sequence_number": 257}
    invalid_then_truncated["transactions"] = [invalid, truncated]
    first_status = analyze(txs=invalid_then_truncated)["source_completeness"]["status"]
    invalid_then_truncated["transactions"] = [truncated, invalid]
    second_status = analyze(txs=invalid_then_truncated)["source_completeness"]["status"]
    if first_status != "INVALID" or second_status != "INVALID":
        fail("global completeness must be monotonic and order-independent")

    if jsonschema is not None:
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            jsonschema.validate(partial_analysis, schema)
            jsonschema.validate(partial_item_analysis, schema)
        except Exception as exc:
            fail(f"partial-acceptance schema validation failed: {exc}")

    original_cause = model._cause

    def ignore_scope(event, key, expected_scope):
        cause, _detail = original_cause(event, key, expected_scope)
        return cause, None

    try:
        model._cause = ignore_scope
        mutated_scope = analyze(evts=wrong_message)
    finally:
        model._cause = original_cause
    mutated_scope_tx = next(
        item for item in mutated_scope["control_transactions"] if item["procedure_family"] == "create-bearer"
    )
    if mutated_scope_tx["message_outcome"]["status"] != "MESSAGE_ACCEPTED_OBSERVED":
        fail("mutation check failed: disabling Cause Scope enforcement was not detected")
    restored_scope = next(
        item for item in analyze(evts=wrong_message)["control_transactions"] if item["procedure_family"] == "create-bearer"
    )
    if restored_scope["message_outcome"]["status"] != "MESSAGE_OUTCOME_UNRESOLVED":
        fail("mutation restore failed: Cause Scope enforcement stayed disabled")

    original_message_classifier = model.classify_message_cause

    def old_rejection_rule(cause, detail):
        if cause is None:
            return "MESSAGE_OUTCOME_NOT_OBSERVED", []
        if cause.get("cause_code") == 16:
            return "MESSAGE_ACCEPTED_OBSERVED", []
        return "MESSAGE_REJECTED_OBSERVED", []

    try:
        model.classify_message_cause = old_rejection_rule
        mutated_17 = analyze(evts=partial)
    finally:
        model.classify_message_cause = original_message_classifier
    mutated_17_tx = next(
        item for item in mutated_17["control_transactions"] if item["procedure_family"] == "create-bearer"
    )
    if mutated_17_tx["message_outcome"]["status"] != "MESSAGE_REJECTED_OBSERVED":
        fail("mutation check failed: Cause 17 rejection regression was not detected")
    if next(
        item for item in analyze(evts=partial)["control_transactions"] if item["procedure_family"] == "create-bearer"
    )["message_outcome"]["status"] != "MESSAGE_PARTIALLY_ACCEPTED_OBSERVED":
        fail("mutation restore failed: Cause 17 stayed rejected")

    original_expected_reference = model._resolve_expected_reference

    def old_missing_reference(reference, evts, expected, expected_code, kind):
        if not reference:
            return None, "COMPLETE", None
        return original_expected_reference(reference, evts, expected, expected_code, kind)

    try:
        model._resolve_expected_reference = old_missing_reference
        mutated_missing = analyze(txs=missing_response)
    finally:
        model._resolve_expected_reference = original_expected_reference
    if next(
        item for item in mutated_missing["control_transactions"] if item["procedure_family"] == "create-bearer"
    )["source_completeness_status"] != "COMPLETE":
        fail("mutation check failed: missing mandatory Response completeness regression was not detected")
    if next(
        item for item in analyze(txs=missing_response)["control_transactions"] if item["procedure_family"] == "create-bearer"
    )["source_completeness_status"] == "COMPLETE":
        fail("mutation restore failed: missing Response stayed complete")

    invalid_then_truncated["transactions"] = [invalid, truncated]
    original_merge = model._merge_status

    def last_wins(current, incoming):
        return incoming

    try:
        model._merge_status = last_wins
        mutated_severity = analyze(txs=invalid_then_truncated)
    finally:
        model._merge_status = original_merge
    if mutated_severity["source_completeness"]["status"] != "TRUNCATED":
        fail("mutation check failed: direct global-status overwrite was not detected")
    if analyze(txs=invalid_then_truncated)["source_completeness"]["status"] != "INVALID":
        fail("mutation restore failed: invalid status stayed downgraded")

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