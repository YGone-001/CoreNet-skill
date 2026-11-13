#!/usr/bin/env python3
"""Behavior tests for the standalone EPC dedicated-bearer control producer."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
CLI = SCRIPTS / "analyze_epc_dedicated_bearer_control.py"
SCHEMA = PACKAGE / "schemas" / "epc-dedicated-bearer-control-analysis.schema.json"
REPO = PACKAGE.parents[2]
GTPV2 = REPO / "skills" / "protocol" / "gtpv2" / "examples" / "expected"
GTPV2_EXTRACTED = REPO / "skills" / "protocol" / "gtpv2" / "examples" / "extracted"

sys.path.insert(0, str(SCRIPTS))
import epc_dedicated_bearer_control_model as model  # noqa: E402

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(CLI), *args], capture_output=True, text=True, check=False)


class DedicatedBearerControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.events = load_jsonl(GTPV2 / "bearer-control-events.jsonl")
        cls.transactions = load_json(GTPV2 / "bearer-control-transactions.json")

    def analyze(self, events=None, transactions=None, identity=None):
        return model.analyze(
            copy.deepcopy(self.events if events is None else events),
            copy.deepcopy(self.transactions if transactions is None else transactions),
            session_identity=identity,
            provenance={
                "gtpv2_events": "gtpv2-events.jsonl",
                "transaction_artifact": "gtpv2-transactions.json",
                "session_identity": "epc-session-identity-analysis.json" if identity else None,
            },
        )

    def event(self, events: list[dict], frame: int, occurrence: int = 0) -> dict:
        for item in events:
            if item.get("frame_number") == frame and (item.get("message_occurrence") or 0) == occurrence:
                return item
        raise AssertionError(f"event frame {frame} occurrence {occurrence} not found")

    def transaction(self, transactions: dict, family: str) -> dict:
        for item in transactions["transactions"]:
            if item.get("procedure_family") == family:
                return item
        raise AssertionError(f"transaction family {family} not found")

    def tx_output(self, analysis: dict, family: str) -> dict:
        for item in analysis["control_transactions"]:
            if item.get("procedure_family") == family:
                return item
        raise AssertionError(f"output transaction family {family} not found")

    def test_create_bearer_accepted_message_outcome(self) -> None:
        analysis = self.analyze()
        tx = self.tx_output(analysis, "create-bearer")
        self.assertEqual(tx["correlation_status"], "MATCHED")
        self.assertEqual(tx["message_outcome"]["status"], "MESSAGE_ACCEPTED_OBSERVED")
        self.assertEqual(tx["message_outcome"]["cause"]["cause_code"], 16)
        self.assertEqual(tx["transaction_outcome"], "CONTROL_PARTIAL_OR_MIXED")

    def test_update_bearer_accepted_message_outcome(self) -> None:
        tx = self.tx_output(self.analyze(), "update-bearer")
        self.assertEqual(tx["message_outcome"]["status"], "MESSAGE_ACCEPTED_OBSERVED")
        self.assertEqual(tx["transaction_outcome"], "CONTROL_ACCEPTED_OBSERVED")

    def test_delete_bearer_accepted_message_outcome(self) -> None:
        tx = self.tx_output(self.analyze(), "delete-bearer")
        self.assertEqual(tx["message_outcome"]["status"], "MESSAGE_ACCEPTED_OBSERVED")
        self.assertEqual(tx["transaction_outcome"], "CONTROL_ACCEPTED_OBSERVED")

    def test_explicit_message_level_rejection(self) -> None:
        events = copy.deepcopy(self.events)
        self.event(events, 2)["message_cause"] = {
            "cause_code": 72,
            "cause_name": "No such bearer",
            "scope": "message",
        }
        tx = self.tx_output(self.analyze(events=events), "create-bearer")
        self.assertEqual(tx["message_outcome"]["status"], "MESSAGE_REJECTED_OBSERVED")
        self.assertEqual(tx["transaction_outcome"], "CONTROL_REJECTED_OBSERVED")

    def test_response_with_two_grouped_bearer_contexts(self) -> None:
        analysis = self.analyze()
        response_items = [
            item
            for item in analysis["bearer_item_observations"]
            if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
            and item["side"] == "RESPONSE"
        ]
        self.assertEqual([item["ebi"] for item in response_items], [5, 6])
        self.assertEqual([item["item_index"] for item in response_items], [0, 1])

    def test_one_item_accepted_and_another_rejected(self) -> None:
        analysis = self.analyze()
        items = [
            item
            for item in analysis["bearer_item_observations"]
            if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
            and item["side"] == "RESPONSE"
        ]
        self.assertEqual(
            [item["item_outcome"] for item in items],
            ["ITEM_CONTROL_ACCEPTED_OBSERVED", "ITEM_CONTROL_REJECTED_OBSERVED"],
        )
        self.assertEqual(self.tx_output(analysis, "create-bearer")["transaction_outcome"], "CONTROL_PARTIAL_OR_MIXED")

    def test_unique_ebi_establishes_item_association(self) -> None:
        analysis = self.analyze()
        associations = [
            item
            for item in analysis["item_associations"]
            if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
        ]
        established = [item for item in associations if item["status"] == "ITEM_ASSOCIATION_ESTABLISHED"]
        self.assertEqual([item["ebi"] for item in established], [5, 6])

    def test_item_specific_fteids(self) -> None:
        analysis = self.analyze()
        items = [
            item
            for item in analysis["bearer_item_observations"]
            if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
            and item["side"] == "RESPONSE"
        ]
        self.assertEqual(items[0]["f_teids"][0]["teid"], 13107)
        self.assertEqual(items[1]["f_teids"][0]["teid"], 17476)

    def test_item_specific_qos(self) -> None:
        analysis = self.analyze()
        request_items = [
            item
            for item in analysis["bearer_item_observations"]
            if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
            and item["side"] == "REQUEST"
        ]
        self.assertEqual(request_items[0]["qos"]["qci"], 9)
        self.assertEqual(request_items[1]["qos"]["qci"], 1)

    def test_item_specific_cause(self) -> None:
        analysis = self.analyze()
        response_items = [
            item
            for item in analysis["bearer_item_observations"]
            if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
            and item["side"] == "RESPONSE"
        ]
        self.assertEqual([item["cause"]["cause_code"] for item in response_items], [16, 73])
        self.assertTrue(all(item["cause"]["scope"] == "bearer" for item in response_items))

    def test_explicit_linked_ebi_evidence(self) -> None:
        analysis = self.analyze()
        tx = self.tx_output(analysis, "delete-bearer")
        self.assertEqual(tx["request_top_level_ebi_references"], ["epc-db-top-ebi:bearer-control.pdml:5:6"])
        top = [
            item
            for item in analysis["item_associations"]
            if item.get("request_top_level_ebi_reference")
        ]
        self.assertEqual(len(top), 1)
        self.assertEqual(top[0]["status"], "ITEM_ASSOCIATION_NOT_ESTABLISHED")
        self.assertEqual(top[0]["ebi"], 6)

    def test_accepted_transaction_correlation_is_reused(self) -> None:
        analysis = self.analyze()
        self.assertEqual([item["correlation_status"] for item in analysis["control_transactions"]], ["MATCHED"] * 3)

    def test_strong_correlation_strength_is_preserved(self) -> None:
        transactions = copy.deepcopy(self.transactions)
        self.transaction(transactions, "update-bearer")["correlation_strength"] = "STRONG"
        tx = self.tx_output(self.analyze(transactions=transactions), "update-bearer")
        self.assertEqual(tx["correlation_strength"], "STRONG")

    def test_supported_correlation_strength_is_preserved(self) -> None:
        tx = self.tx_output(self.analyze(), "create-bearer")
        self.assertEqual(tx["correlation_strength"], "SUPPORTED")

    def test_item_references_are_deterministic(self) -> None:
        first = self.analyze()
        second = self.analyze()
        self.assertEqual(
            [item["item_reference"] for item in first["bearer_item_observations"]],
            [item["item_reference"] for item in second["bearer_item_observations"]],
        )

    def test_transaction_ordering_is_deterministic(self) -> None:
        first = self.analyze()
        events = list(reversed(copy.deepcopy(self.events)))
        transactions = copy.deepcopy(self.transactions)
        transactions["transactions"] = list(reversed(transactions["transactions"]))
        second = self.analyze(events=events, transactions=transactions)
        self.assertEqual(
            [item["transaction_reference"] for item in first["control_transactions"]],
            [item["transaction_reference"] for item in second["control_transactions"]],
        )

    def test_output_is_schema_valid(self) -> None:
        if jsonschema is None:
            self.skipTest("jsonschema unavailable")
        jsonschema.validate(self.analyze(), load_json(SCHEMA))

    def test_standalone_cli_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            events = directory / "gtpv2-events.jsonl"
            events.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in self.events),
                encoding="utf-8",
            )
            transactions = directory / "transactions.json"
            transactions.write_text(json.dumps(self.transactions, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            output = directory / "analysis.json"
            timeline = directory / "timeline.jsonl"
            result = run_cli(
                "--gtpv2",
                str(events),
                "--transactions",
                str(transactions),
                "--output",
                str(output),
                "--timeline-output",
                str(timeline),
                "--force",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            analysis = load_json(output)
            self.assertEqual(analysis["control_transaction_count"], 3)
            self.assertEqual(len(load_jsonl(timeline)), 3)
            if jsonschema is not None:
                jsonschema.validate(analysis, load_json(SCHEMA))

    def test_m1_ownership_fixture_is_compatible(self) -> None:
        events = load_jsonl(GTPV2_EXTRACTED / "bearer-ownership-positive-events.jsonl")
        transactions = load_json(GTPV2 / "bearer-ownership-positive-transactions.json")
        analysis = self.analyze(events=events, transactions=transactions)
        self.assertEqual(analysis["control_transaction_count"], 2)
        self.assertEqual(
            [item["transaction_outcome"] for item in analysis["control_transactions"]],
            ["CONTROL_OUTCOME_UNRESOLVED", "CONTROL_OUTCOME_UNRESOLVED"],
        )

    def test_valid_absence_of_optional_session_identity(self) -> None:
        analysis = self.analyze()
        self.assertEqual(analysis["session_identity_context"]["status"], "NOT_PROVIDED")
        self.assertEqual(analysis["session_identity_context"]["associated_transaction_references"], [])

    def test_open_request_remains_unresolved(self) -> None:
        transactions = copy.deepcopy(self.transactions)
        tx = self.transaction(transactions, "create-bearer")
        tx["correlation_status"] = "OPEN_REQUEST"
        tx["response"] = None
        output = self.tx_output(self.analyze(transactions=transactions), "create-bearer")
        self.assertEqual(output["transaction_outcome"], "CONTROL_OUTCOME_UNRESOLVED")
        self.assertEqual(output["message_outcome"]["status"], "MESSAGE_OUTCOME_NOT_OBSERVED")
        self.assertTrue(any("not a proven network timeout" in item for item in output["evidence_limitations"]))

    def test_response_only_remains_response_only(self) -> None:
        transactions = copy.deepcopy(self.transactions)
        tx = self.transaction(transactions, "create-bearer")
        tx["correlation_status"] = "RESPONSE_ONLY"
        tx["request"] = None
        output = self.tx_output(self.analyze(transactions=transactions), "create-bearer")
        self.assertEqual(output["transaction_outcome"], "CONTROL_OUTCOME_UNRESOLVED")
        self.assertEqual(output["request_bearer_item_references"], [])
        self.assertEqual(len(output["response_bearer_item_references"]), 2)
        associations = [
            item
            for item in self.analyze(transactions=transactions)["item_associations"]
            if item["transaction_reference"] == output["transaction_reference"]
        ]
        self.assertTrue(all(item["status"] != "ITEM_ASSOCIATION_ESTABLISHED" for item in associations))

    def test_ambiguous_response_ownership_is_unresolved(self) -> None:
        events = load_jsonl(GTPV2_EXTRACTED / "bearer-ownership-competing-events.jsonl")
        transactions = load_json(GTPV2 / "bearer-ownership-competing-transactions.json")
        analysis = self.analyze(events=events, transactions=transactions)
        self.assertEqual(analysis["control_transaction_count"], 2)
        self.assertTrue(
            all(item["transaction_outcome"] == "CONTROL_OUTCOME_UNRESOLVED" for item in analysis["control_transactions"])
        )
        self.assertTrue(
            all(item["message_outcome"]["status"] == "MESSAGE_OUTCOME_AMBIGUOUS" for item in analysis["control_transactions"])
        )

    def test_conflicting_decoder_link_fixture_stays_unresolved(self) -> None:
        events = load_jsonl(GTPV2_EXTRACTED / "bearer-ownership-competing-events.jsonl")
        transactions = load_json(GTPV2 / "bearer-ownership-competing-transactions.json")
        for tx in transactions["transactions"]:
            tx["correlation_status"] = "AMBIGUOUS"
        analysis = self.analyze(events=events, transactions=transactions)
        associations = [item for item in analysis["item_associations"] if item["status"] == "ITEM_ASSOCIATION_ESTABLISHED"]
        self.assertEqual(associations, [])

    def test_missing_message_cause_is_not_observed(self) -> None:
        events = copy.deepcopy(self.events)
        self.event(events, 2)["message_cause"] = None
        tx = self.tx_output(self.analyze(events=events), "create-bearer")
        self.assertEqual(tx["message_outcome"]["status"], "MESSAGE_OUTCOME_NOT_OBSERVED")
        self.assertEqual(tx["transaction_outcome"], "CONTROL_OUTCOME_UNRESOLVED")

    def test_message_accepted_but_item_rejected(self) -> None:
        analysis = self.analyze()
        tx = self.tx_output(analysis, "create-bearer")
        self.assertEqual(tx["message_outcome"]["status"], "MESSAGE_ACCEPTED_OBSERVED")
        self.assertEqual(tx["transaction_outcome"], "CONTROL_PARTIAL_OR_MIXED")
        self.assertEqual(analysis["outcome_summary"]["item_outcome_counts"]["ITEM_CONTROL_REJECTED_OBSERVED"], 1)

    def test_missing_bearer_item_cause_is_not_accepted(self) -> None:
        events = copy.deepcopy(self.events)
        self.event(events, 2)["bearer_contexts"][0]["cause"] = None
        analysis = self.analyze(events=events)
        items = [
            item
            for item in analysis["bearer_item_observations"]
            if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
            and item["side"] == "RESPONSE"
        ]
        self.assertEqual(items[0]["item_outcome"], "ITEM_OUTCOME_NOT_OBSERVED")
        self.assertEqual(self.tx_output(analysis, "create-bearer")["transaction_outcome"], "CONTROL_PARTIAL_OR_MIXED")

    def test_duplicate_ebi_inside_one_context_is_ambiguous(self) -> None:
        events = copy.deepcopy(self.events)
        item = self.event(events, 2)["bearer_contexts"][0]
        item["ebi_values"] = [5, 6]
        analysis = self.analyze(events=events)
        target = [
            obs
            for obs in analysis["bearer_item_observations"]
            if obs["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
            and obs["side"] == "RESPONSE"
            and obs["item_index"] == 0
        ][0]
        self.assertEqual(target["ebi_status"], "DUPLICATE_IN_CONTEXT")
        self.assertFalse(target["ebi_valid"])
        self.assertTrue(any(item["status"] == "ITEM_ASSOCIATION_AMBIGUOUS" for item in analysis["item_associations"]))

    def test_duplicate_ebi_across_contexts_is_ambiguous(self) -> None:
        events = copy.deepcopy(self.events)
        contexts = self.event(events, 2)["bearer_contexts"]
        contexts[1]["ebi"] = contexts[0]["ebi"]
        analysis = self.analyze(events=events)
        items = [
            obs
            for obs in analysis["bearer_item_observations"]
            if obs["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
            and obs["side"] == "RESPONSE"
        ]
        self.assertTrue(all(item["ebi_status"] == "DUPLICATE_ACROSS_CONTEXTS" for item in items))
        self.assertTrue(any(item["status"] == "ITEM_ASSOCIATION_AMBIGUOUS" for item in analysis["item_associations"]))

    def test_invalid_ebi_zero_fails_closed(self) -> None:
        events = copy.deepcopy(self.events)
        self.event(events, 2)["bearer_contexts"][0]["ebi"] = 0
        analysis = self.analyze(events=events)
        item = next(
            obs
            for obs in analysis["bearer_item_observations"]
            if obs["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
            and obs["side"] == "RESPONSE"
            and obs["item_index"] == 0
        )
        self.assertEqual(item["ebi_status"], "INVALID")
        self.assertFalse(item["ebi_valid"])

    def test_missing_ebi_fails_closed(self) -> None:
        events = copy.deepcopy(self.events)
        self.event(events, 2)["bearer_contexts"][0]["ebi"] = None
        analysis = self.analyze(events=events)
        item = next(
            obs
            for obs in analysis["bearer_item_observations"]
            if obs["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
            and obs["side"] == "RESPONSE"
            and obs["item_index"] == 0
        )
        self.assertEqual(item["ebi_status"], "MISSING")
        self.assertFalse(item["ebi_valid"])

    def test_multiple_response_candidates_do_not_establish_association(self) -> None:
        events = load_jsonl(GTPV2_EXTRACTED / "bearer-ownership-competing-events.jsonl")
        transactions = load_json(GTPV2 / "bearer-ownership-competing-transactions.json")
        analysis = self.analyze(events=events, transactions=transactions)
        self.assertEqual(
            [item for item in analysis["item_associations"] if item["status"] == "ITEM_ASSOCIATION_ESTABLISHED"],
            [],
        )

    def test_reordered_item_arrays_do_not_change_ebi_association(self) -> None:
        events = copy.deepcopy(self.events)
        contexts = self.event(events, 2)["bearer_contexts"]
        contexts.reverse()
        analysis = self.analyze(events=events)
        established = [
            item
            for item in analysis["item_associations"]
            if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
            and item["status"] == "ITEM_ASSOCIATION_ESTABLISHED"
        ]
        self.assertEqual(sorted(item["ebi"] for item in established), [5, 6])

    def test_equal_ebi_in_another_capture_is_not_associated(self) -> None:
        events = copy.deepcopy(self.events)
        self.event(events, 2)["capture_file"] = "other-capture.pcap"
        analysis = self.analyze(events=events)
        self.assertEqual(analysis["source_completeness"]["status"], "INVALID")
        create_associations = [
            item
            for item in analysis["item_associations"]
            if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
        ]
        self.assertFalse(
            any(item["status"] == "ITEM_ASSOCIATION_ESTABLISHED" for item in create_associations)
        )

    def test_equal_teid_is_not_used_as_item_identity(self) -> None:
        events = copy.deepcopy(self.events)
        contexts = self.event(events, 2)["bearer_contexts"]
        contexts[0]["ebi"] = 7
        contexts[0]["f_teids"] = copy.deepcopy(contexts[1]["f_teids"])
        analysis = self.analyze(events=events)
        assoc = [
            item
            for item in analysis["item_associations"]
            if item["ebi"] == 7 and item["response_item_reference"] is not None
        ]
        self.assertTrue(assoc)
        self.assertEqual(assoc[0]["status"], "ITEM_ASSOCIATION_NOT_ESTABLISHED")

    def test_equal_frame_numbers_across_captures_fail_closed(self) -> None:
        events = copy.deepcopy(self.events)
        self.event(events, 2)["capture_file"] = "other-capture.pcap"
        analysis = self.analyze(events=events)
        tx = self.tx_output(analysis, "create-bearer")
        self.assertEqual(tx["source_completeness_status"], "INVALID")
        self.assertEqual(tx["transaction_outcome"], "CONTROL_OUTCOME_UNRESOLVED")

    def test_two_message_occurrences_in_one_frame_are_distinct(self) -> None:
        events = copy.deepcopy(self.events)
        duplicate = copy.deepcopy(self.event(events, 1))
        duplicate["message_occurrence"] = 1
        events.append(duplicate)
        transactions = copy.deepcopy(self.transactions)
        tx = self.transaction(transactions, "create-bearer")
        tx["request"]["message_occurrence"] = 1
        analysis = self.analyze(events=events, transactions=transactions)
        output = self.tx_output(analysis, "create-bearer")
        self.assertEqual(output["request"]["message_occurrence"], 1)
        self.assertTrue(
            any(item["message_occurrence"] == 1 for item in analysis["bearer_item_observations"])
        )

    def test_same_frame_ambiguous_request_occurrences_stay_unresolved(self) -> None:
        events = load_jsonl(GTPV2_EXTRACTED / "bearer-ownership-competing-events.jsonl")
        transactions = load_json(GTPV2 / "bearer-ownership-competing-transactions.json")
        analysis = self.analyze(events=events, transactions=transactions)
        self.assertTrue(
            all(item["transaction_outcome"] == "CONTROL_OUTCOME_UNRESOLVED" for item in analysis["control_transactions"])
        )

    def test_incomplete_source_is_truncated(self) -> None:
        events = [item for item in copy.deepcopy(self.events) if item["frame_number"] != 2]
        analysis = self.analyze(events=events)
        tx = self.tx_output(analysis, "create-bearer")
        self.assertEqual(analysis["source_completeness"]["status"], "TRUNCATED")
        self.assertEqual(tx["source_completeness_status"], "TRUNCATED")
        self.assertEqual(tx["transaction_outcome"], "CONTROL_OUTCOME_UNRESOLVED")

    def test_malformed_transaction_reference_is_reported(self) -> None:
        transactions = copy.deepcopy(self.transactions)
        self.transaction(transactions, "create-bearer")["transaction_reference"] = ""
        analysis = self.analyze(transactions=transactions)
        self.assertEqual(analysis["source_completeness"]["status"], "INVALID")
        self.assertTrue(
            any(item["kind"] == "MALFORMED_TRANSACTION_REFERENCE" for item in analysis["unresolved_findings"])
        )

    def test_unsupported_procedure_family_is_ignored(self) -> None:
        events = copy.deepcopy(self.events)
        transactions = copy.deepcopy(self.transactions)
        ignored = copy.deepcopy(self.transaction(transactions, "update-bearer"))
        ignored["procedure_family"] = "modify-bearer"
        ignored["transaction_reference"] = "gtpv2-modify-bearer-40-999"
        transactions["transactions"].append(ignored)
        analysis = self.analyze(events=events, transactions=transactions)
        self.assertEqual(analysis["control_transaction_count"], 3)
        self.assertTrue(any("modify-bearer" in item for item in analysis["evidence_limitations"]))

    def test_optional_session_identity_does_not_create_relationship(self) -> None:
        identity = {
            "analysis_name": "epc-session-identity",
            "analysis_version": "1.0.0",
            "hop_local_contexts": [
                {
                    "capture_file": "bearer-control.pdml",
                    "session_context_reference": "epc-session-context-test",
                }
            ],
        }
        analysis = self.analyze(identity=identity)
        self.assertEqual(analysis["session_identity_context"]["status"], "NOT_ESTABLISHED")
        self.assertEqual(analysis["session_identity_context"]["associated_transaction_references"], [])

    def test_qos_advertised_without_response_evidence(self) -> None:
        events = copy.deepcopy(self.events)
        self.event(events, 2)["bearer_contexts"][0]["qos"] = None
        analysis = self.analyze(events=events)
        response_item = next(
            item
            for item in analysis["bearer_item_observations"]
            if item["transaction_reference"].endswith("create-bearer-1-256-ebi-5-6")
            and item["side"] == "RESPONSE"
            and item["item_index"] == 0
        )
        self.assertIsNone(response_item["qos"])
        self.assertNotIn("qos_admitted", json.dumps(analysis).lower())

    def test_tft_presence_does_not_imply_installation(self) -> None:
        payload = json.dumps(self.analyze()).lower()
        self.assertNotIn("tft_installed", payload)
        self.assertNotIn("tft_installation_proven", payload)

    def test_no_bearer_activation_is_inferred(self) -> None:
        payload = json.dumps(self.analyze()).lower()
        for forbidden in ("bearer_activated", "bearer_established", "resource_admitted", "forwarding_stopped"):
            self.assertNotIn(forbidden, payload)

    def test_subscriber_identity_is_not_published(self) -> None:
        transactions = copy.deepcopy(self.transactions)
        self.transaction(transactions, "create-bearer")["limitations"] = [
            "imsi 460020000000001",
            "ordinary limitation",
        ]
        payload = json.dumps(self.analyze(transactions=transactions))
        self.assertNotIn("460020000000001", payload)
        self.assertIn("ordinary limitation", payload)


if __name__ == "__main__":
    unittest.main()