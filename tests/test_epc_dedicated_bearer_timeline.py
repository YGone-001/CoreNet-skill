#!/usr/bin/env python3
"""Tests for the bounded Dedicated Bearer cross-layer evidence timeline."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_SCRIPTS = ROOT / "skills" / "domain" / "epc-procedures" / "scripts"
sys.path.insert(0, str(MODEL_SCRIPTS))

import epc_dedicated_bearer_timeline_model as model  # noqa: E402


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


def transaction(
    name: str,
    family: str,
    request: int,
    response: int,
    ebi: int,
    *,
    context: str | None = None,
    completeness: str = "COMPLETE",
) -> tuple[dict, list[dict]]:
    transaction_reference = f"epc-db-tx:fixture.pcap:{name}"
    request_item = f"epc-db-item:{transaction_reference}:request:{request}:0:0"
    response_item = f"epc-db-item:{transaction_reference}:response:{response}:0:0"
    tx = {
        "transaction_reference": transaction_reference,
        "protocol_transaction_reference": f"gtpv2-{name}",
        "capture": "fixture.pcap",
        "procedure_family": family,
        "correlation_status": "MATCHED",
        "correlation_strength": "STRONG",
        "correlation_basis": ["sequence_number"],
        "request": reference(request),
        "response": reference(response),
        "retransmissions": [],
        "frame_anchors": {"request_frame": request, "response_frame": response},
        "message_outcome": {
            "status": "MESSAGE_ACCEPTED_OBSERVED",
            "cause": {"cause_code": 16, "cause_name": "Request accepted", "scope": "message"},
            "source_reference": reference(response),
            "limitations": [],
        },
        "transaction_outcome": "CONTROL_ACCEPTED_OBSERVED",
        "transaction_outcome_basis": ["message and item evidence summarized"],
        "request_bearer_item_references": [request_item],
        "response_bearer_item_references": [response_item],
        "request_top_level_ebi_references": [],
        "source_completeness_status": completeness,
        "evidence_limitations": [],
    }
    if context is not None:
        tx["ue_context_reference"] = context
    items = [
        {
            "item_reference": request_item,
            "transaction_reference": transaction_reference,
            "side": "REQUEST",
            "ebi": 0,
            "ebi_valid": False,
            "ebi_status": "INVALID",
            "item_outcome": "ITEM_REQUEST_EVIDENCE_ONLY",
        },
        {
            "item_reference": response_item,
            "transaction_reference": transaction_reference,
            "side": "RESPONSE",
            "ebi": ebi,
            "ebi_valid": True,
            "ebi_status": "VALID",
            "item_outcome": "ITEM_CONTROL_ACCEPTED_OBSERVED",
        },
    ]
    return tx, items


def control_document(
    transactions: list[dict],
    items: list[dict],
    *,
    omitted: int = 0,
) -> dict:
    return {
        "analysis_name": "epc-dedicated-bearer-control",
        "analysis_version": "1.0.0",
        "input_provenance": {"gtpv2_events": "fixture.pcap"},
        "control_transactions": transactions,
        "control_transaction_count": len(transactions) + omitted,
        "control_transactions_omitted": omitted,
        "bearer_item_observations": items,
        "bearer_item_observation_count": len(items),
        "bearer_item_observations_omitted": 0,
    }


def nas_event(
    frame: int,
    code: int,
    result: str,
    ebi: int,
    *,
    capture: str = "fixture.pcap",
    support: str = "SUPPORTED",
    protection: str = "PLAIN",
    occurrence: int = 0,
) -> dict:
    return {
        "capture_file": capture,
        "frame_number": frame,
        "direction": "uplink" if result in ("REQUEST", "ACCEPT", "REJECT") else "downlink",
        "esm_messages": [
            {
                "occurrence_index": occurrence,
                "message_type_code": code,
                "message_type": "Dedicated bearer message",
                "support_status": support,
                "procedure": "dedicated-bearer-control",
                "result": result,
                "eps_bearer_identity": ebi,
                "protection_state": protection,
                "binding_basis": "pdml_grouped_ie",
                "limitations": [],
            }
        ],
    }


def s1ap_event(
    frame: int,
    operation: str,
    role: str,
    erab_id: int | None,
    context: str,
    *,
    capture: str = "fixture.pcap",
    unbound: bool = False,
) -> dict:
    event = {
        "capture_file": capture,
        "frame_number": frame,
        "procedure_name": "id-E-RABSetup",
        "support_status": "SUPPORTED",
        "sender_role": "mme" if role == "REQUEST" else "enodeb",
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


class TimelineTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)
        self.control_path = self.base / "epc-dedicated-bearer-control-analysis.json"

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def build(
        self,
        control: dict,
        nas: list[dict] | None = None,
        s1ap: list[dict] | None = None,
        *,
        nas_present: bool = True,
        s1ap_present: bool = True,
    ) -> dict:
        self.control_path.write_text(json.dumps(control), encoding="utf-8")
        return model.build_timeline(
            control,
            nas or [],
            s1ap or [],
            control_path=self.control_path,
            nas_path=self.base / "nas-eps-events.jsonl" if nas_present else None,
            s1ap_path=self.base / "s1ap-events.jsonl" if s1ap_present else None,
        )


class TimelinePositiveTests(TimelineTestCase):
    def test_control_only_timeline_is_useful_and_explicit(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5, context="ctx-1")
        timeline = self.build(control_document([tx], items), nas_present=False, s1ap_present=False)
        self.assertEqual(timeline["execution_status"], "EXECUTED")
        entry = timeline["timeline_entries"][0]
        self.assertEqual(entry["request_frame"], 100)
        self.assertEqual(entry["response_frame"], 110)
        self.assertEqual(entry["nas_esm_association"]["status"], "NOT_OBSERVED")
        self.assertEqual(entry["s1ap_erab_association"]["status"], "NOT_OBSERVED")
        self.assertEqual(entry["cross_layer_association_status"], "NOT_OBSERVED")
        self.assertEqual(entry["observed_nas_esm_references"], [])

    def test_complete_create_signaling_is_established(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5, context="ctx-1")
        nas = [
            nas_event(102, 197, "REQUEST", 5),
            nas_event(108, 198, "ACCEPT", 5),
        ]
        s1ap = [
            s1ap_event(102, "E_RAB_SETUP", "REQUEST", 7, "ctx-1"),
            s1ap_event(108, "E_RAB_SETUP", "SUCCESS", 7, "ctx-1"),
        ]
        timeline = self.build(control_document([tx], items), nas, s1ap)
        entry = timeline["timeline_entries"][0]
        self.assertEqual(entry["nas_esm_association"]["status"], "ESTABLISHED_BY_EVIDENCE")
        self.assertEqual(entry["s1ap_erab_association"]["status"], "ESTABLISHED_BY_EVIDENCE")
        self.assertEqual(entry["cross_layer_association_status"], "ESTABLISHED_BY_EVIDENCE")
        self.assertEqual(
            [ref["frame_number"] for ref in entry["observed_nas_esm_references"]], [102, 108]
        )
        self.assertEqual(
            [ref["frame_number"] for ref in entry["observed_s1ap_erab_references"]], [102, 108]
        )

    def test_complete_update_and_delete_signaling(self) -> None:
        for family, code, operation in (
            ("update-bearer", (201, 202), "E_RAB_MODIFY"),
            ("delete-bearer", (205, 206), "E_RAB_RELEASE"),
        ):
            with self.subTest(family=family):
                tx, items = transaction(f"{family}-1", family, 200, 210, 7, context="ctx-1")
                nas = [
                    nas_event(202, code[0], "REQUEST", 7),
                    nas_event(208, code[1], "ACCEPT", 7),
                ]
                s1ap = [
                    s1ap_event(202, operation, "REQUEST", 7, "ctx-1"),
                    s1ap_event(208, operation, "COMPLETE" if family == "delete-bearer" else "SUCCESS", 7, "ctx-1"),
                ]
                timeline = self.build(control_document([tx], items), nas, s1ap)
                self.assertEqual(
                    timeline["timeline_entries"][0]["cross_layer_association_status"],
                    "ESTABLISHED_BY_EVIDENCE",
                )

    def test_reject_is_observed_without_acceptance_verdict(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5, context="ctx-1")
        nas = [
            nas_event(102, 197, "REQUEST", 5),
            nas_event(108, 199, "REJECT", 5),
        ]
        s1ap = [
            s1ap_event(102, "E_RAB_SETUP", "REQUEST", 5, "ctx-1"),
            s1ap_event(108, "E_RAB_SETUP", "SUCCESS", 5, "ctx-1"),
        ]
        timeline = self.build(control_document([tx], items), nas, s1ap)
        entry = timeline["timeline_entries"][0]
        self.assertEqual(entry["nas_esm_association"]["status"], "ESTABLISHED_BY_EVIDENCE")
        self.assertIn("does not prove UE acceptance", " ".join(entry["not_confirmed"]))
        self.assertNotIn("bearer_activated", entry)
        self.assertNotIn("activation_success", entry)

    def test_multiple_bearers_in_one_ue_context(self) -> None:
        tx1, items1 = transaction("create-1", "create-bearer", 100, 110, 5, context="ctx-1")
        tx2, items2 = transaction("create-2", "create-bearer", 200, 210, 6, context="ctx-1")
        nas = [
            nas_event(102, 197, "REQUEST", 5),
            nas_event(108, 198, "ACCEPT", 5),
            nas_event(202, 197, "REQUEST", 6),
            nas_event(208, 198, "ACCEPT", 6),
        ]
        s1ap = [
            s1ap_event(102, "E_RAB_SETUP", "REQUEST", 5, "ctx-1"),
            s1ap_event(108, "E_RAB_SETUP", "SUCCESS", 5, "ctx-1"),
            s1ap_event(202, "E_RAB_SETUP", "REQUEST", 6, "ctx-1"),
            s1ap_event(208, "E_RAB_SETUP", "SUCCESS", 6, "ctx-1"),
        ]
        timeline = self.build(control_document([tx1, tx2], items1 + items2), nas, s1ap)
        statuses = [entry["nas_esm_association"]["status"] for entry in timeline["timeline_entries"]]
        self.assertEqual(statuses, ["ESTABLISHED_BY_EVIDENCE", "ESTABLISHED_BY_EVIDENCE"])

    def test_multiple_ue_contexts_stay_isolated(self) -> None:
        tx1, items1 = transaction("create-1", "create-bearer", 100, 110, 5, context="ctx-1")
        tx2, items2 = transaction("create-2", "create-bearer", 200, 210, 6, context="ctx-2")
        nas = [
            nas_event(102, 197, "REQUEST", 5),
            nas_event(108, 198, "ACCEPT", 5),
            nas_event(202, 197, "REQUEST", 6),
            nas_event(208, 198, "ACCEPT", 6),
        ]
        s1ap = [
            s1ap_event(102, "E_RAB_SETUP", "REQUEST", 5, "ctx-1"),
            s1ap_event(108, "E_RAB_SETUP", "SUCCESS", 5, "ctx-1"),
            s1ap_event(202, "E_RAB_SETUP", "REQUEST", 6, "ctx-2"),
            s1ap_event(208, "E_RAB_SETUP", "SUCCESS", 6, "ctx-2"),
        ]
        timeline = self.build(control_document([tx1, tx2], items1 + items2), nas, s1ap)
        self.assertEqual(
            [entry["cross_layer_association_status"] for entry in timeline["timeline_entries"]],
            ["ESTABLISHED_BY_EVIDENCE", "ESTABLISHED_BY_EVIDENCE"],
        )
        self.assertEqual(
            [
                entry["s1ap_erab_association"]["candidate_contexts"]
                for entry in timeline["timeline_entries"]
            ],
            [["ctx-1"], ["ctx-2"]],
        )

    def test_deterministic_ordering_and_navigation_references(self) -> None:
        tx1, items1 = transaction("create-2", "create-bearer", 200, 210, 6)
        tx2, items2 = transaction("create-1", "create-bearer", 100, 110, 5)
        first = self.build(control_document([tx1, tx2], items1 + items2))
        second = self.build(control_document([tx2, tx1], items2 + items1))
        self.assertEqual(
            [entry["request_frame"] for entry in first["timeline_entries"]], [100, 200]
        )
        self.assertEqual(first["timeline_entries"], second["timeline_entries"])

    def test_bounded_publication_and_truncation(self) -> None:
        transactions = []
        items = []
        for index in range(model.MAX_TIMELINE_ENTRIES + 1):
            tx, item = transaction(
                f"create-{index}", "create-bearer", 100 + index, 200 + index, 5
            )
            transactions.append(tx)
            items.extend(item)
        timeline = self.build(
            control_document(transactions, items, omitted=0)
        )
        self.assertEqual(timeline["timeline_entry_count"], model.MAX_TIMELINE_ENTRIES + 1)
        self.assertEqual(len(timeline["timeline_entries"]), model.MAX_TIMELINE_ENTRIES)
        self.assertEqual(timeline["timeline_entries_omitted"], 1)

    def test_no_subject_document_is_explicit(self) -> None:
        timeline = self.build(control_document([], []))
        self.assertEqual(timeline["execution_status"], "NOT_OBSERVED_IN_CAPTURE")
        self.assertEqual(timeline["timeline_entry_count"], 0)


class TimelineNegativeTests(TimelineTestCase):
    def test_missing_sources_are_not_observed(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
        timeline = self.build(control_document([tx], items), nas_present=False, s1ap_present=False)
        self.assertEqual(
            timeline["timeline_entries"][0]["cross_layer_association_status"], "NOT_OBSERVED"
        )
        self.assertEqual(timeline["source_completeness"]["status"], "PARTIAL")

    def test_protected_payload_does_not_create_esm_evidence(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
        nas = [
            {
                "capture_file": "fixture.pcap",
                "frame_number": 102,
                "protected_inner_message_unavailable": True,
                "esm_messages": [],
            }
        ]
        timeline = self.build(control_document([tx], items), nas, [])
        self.assertEqual(
            timeline["timeline_entries"][0]["nas_esm_association"]["status"], "NOT_OBSERVED"
        )

    def test_incomplete_erab_response_is_candidate(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
        s1ap = [s1ap_event(101, "E_RAB_SETUP", "REQUEST", 7, "ctx-1")]
        timeline = self.build(control_document([tx], items), [], s1ap)
        self.assertEqual(
            timeline["timeline_entries"][0]["s1ap_erab_association"]["status"],
            "CANDIDATE_UNCONFIRMED",
        )

    def test_reused_ebi_across_contexts_is_ambiguous(self) -> None:
        tx1, items1 = transaction("create-1", "create-bearer", 100, 110, 5)
        tx2, items2 = transaction("create-2", "create-bearer", 100, 130, 5)
        nas = [
            nas_event(102, 197, "REQUEST", 5),
            nas_event(108, 198, "ACCEPT", 5),
        ]
        timeline = self.build(control_document([tx1, tx2], items1 + items2), nas, [])
        self.assertTrue(
            all(
                entry["nas_esm_association"]["status"] == "AMBIGUOUS"
                for entry in timeline["timeline_entries"]
            )
        )

    def test_ambiguous_s1ap_contexts_do_not_establish(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
        s1ap = [
            s1ap_event(101, "E_RAB_SETUP", "REQUEST", 7, "ctx-1"),
            s1ap_event(102, "E_RAB_SETUP", "REQUEST", 7, "ctx-2"),
        ]
        timeline = self.build(control_document([tx], items), [], s1ap)
        self.assertEqual(
            timeline["timeline_entries"][0]["s1ap_erab_association"]["status"], "AMBIGUOUS"
        )

    def test_out_of_order_completion_is_not_established(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5, context="ctx-1")
        nas = [
            nas_event(108, 198, "ACCEPT", 5),
            nas_event(102, 197, "REQUEST", 5),
        ]
        timeline = self.build(control_document([tx], items), nas, [])
        self.assertEqual(
            timeline["timeline_entries"][0]["nas_esm_association"]["status"],
            "CANDIDATE_UNCONFIRMED",
        )

    def test_repeated_requests_are_ambiguous(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5, context="ctx-1")
        nas = [
            nas_event(102, 197, "REQUEST", 5),
            nas_event(104, 197, "REQUEST", 5),
            nas_event(108, 198, "ACCEPT", 5),
        ]
        timeline = self.build(control_document([tx], items), nas, [])
        self.assertEqual(
            timeline["timeline_entries"][0]["nas_esm_association"]["status"], "AMBIGUOUS"
        )

    def test_unsupported_esm_identity_is_explicit(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
        nas = [
            nas_event(102, 197, "REQUEST", 5, support="UNSUPPORTED"),
        ]
        timeline = self.build(control_document([tx], items), nas, [])
        self.assertEqual(
            timeline["timeline_entries"][0]["nas_esm_association"]["status"],
            "UNSUPPORTED_EVIDENCE",
        )

    def test_flattened_erab_fields_are_not_fabricated_items(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
        s1ap = [s1ap_event(101, "E_RAB_SETUP", "REQUEST", 7, "ctx-1", unbound=True)]
        timeline = self.build(control_document([tx], items), [], s1ap)
        entry = timeline["timeline_entries"][0]
        self.assertEqual(entry["s1ap_erab_association"]["status"], "UNSUPPORTED_EVIDENCE")
        self.assertIsNone(entry["observed_s1ap_erab_references"][0]["erab_id"])

    def test_wrong_capture_and_owner_are_ignored(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
        nas = [nas_event(102, 197, "REQUEST", 5, capture="other.pcap")]
        s1ap = [s1ap_event(101, "E_RAB_MODIFY", "REQUEST", 7, "ctx-1")]
        timeline = self.build(control_document([tx], items), nas, s1ap)
        entry = timeline["timeline_entries"][0]
        self.assertEqual(entry["nas_esm_association"]["status"], "NOT_OBSERVED")
        self.assertEqual(entry["s1ap_erab_association"]["status"], "NOT_OBSERVED")

    def test_invalid_ebi_prevents_nas_association(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
        for item in items:
            item["ebi_status"] = "INVALID"
            item["ebi"] = 0
        nas = [
            nas_event(102, 197, "REQUEST", 5),
            nas_event(108, 198, "ACCEPT", 5),
        ]
        timeline = self.build(control_document([tx], items), nas, [])
        entry = timeline["timeline_entries"][0]
        self.assertEqual(entry["nas_esm_association"]["status"], "NOT_OBSERVED")
        self.assertTrue(any("EB" in value for value in entry["limitations"]))

    def test_response_only_control_procedure_is_preserved(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
        tx["request"] = {}
        tx["frame_anchors"] = {"request_frame": None, "response_frame": 110}
        timeline = self.build(control_document([tx], items))
        entry = timeline["timeline_entries"][0]
        self.assertIsNone(entry["request_frame"])
        self.assertTrue(any("request frame" in value for value in entry["limitations"]))

    def test_source_truncation_is_preserved(self) -> None:
        tx, items = transaction(
            "create-1", "create-bearer", 100, 110, 5, completeness="TRUNCATED"
        )
        timeline = self.build(control_document([tx], items, omitted=1))
        self.assertEqual(
            timeline["timeline_entries"][0]["source_completeness_status"], "TRUNCATED"
        )


class TimelineContractTests(unittest.TestCase):
    def setUp(self) -> None:
        path = ROOT / "scripts" / "epc_dedicated_bearer_timeline_contract.py"
        spec = importlib.util.spec_from_file_location("timeline_contract_under_test", path)
        contract = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(contract)
        self.contract = contract

    def test_valid_artifact_and_count_integrity(self) -> None:
        tx, items = transaction("create-1", "create-bearer", 100, 110, 5)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "control.json"
            path.write_text(json.dumps(control_document([tx], items)), encoding="utf-8")
            timeline = model.build_timeline(
                control_document([tx], items),
                [],
                [],
                control_path=path,
                nas_path=None,
                s1ap_path=None,
            )
        self.contract.validate_artifact(timeline)
        broken = copy.deepcopy(timeline)
        broken["timeline_entry_count"] += 1
        with self.assertRaises(self.contract.ContractValidationError):
            self.contract.validate_artifact(broken)
        boolean_counts = copy.deepcopy(timeline)
        boolean_counts["association_status_counts"] = {
            "NOT_OBSERVED": True,
            "CANDIDATE_UNCONFIRMED": 0,
            "AMBIGUOUS": 0,
            "ESTABLISHED_BY_EVIDENCE": 0,
            "NOT_ESTABLISHED": 0,
            "UNSUPPORTED_EVIDENCE": 0,
        }
        with self.assertRaises(self.contract.ContractValidationError):
            self.contract.validate_artifact(boolean_counts)
        bad_ref = copy.deepcopy(timeline)
        bad_ref["timeline_entries"][0]["observed_nas_esm_references"] = [
            {"reference": "x", "frame_number": 0, "kind": "NAS_ESM", "source_analysis": "nas-eps"}
        ]
        with self.assertRaises(self.contract.ContractValidationError):
            self.contract.validate_artifact(bad_ref)
        bad_version = copy.deepcopy(timeline)
        bad_version["analysis_version"] = "2.0.0"
        with self.assertRaises(self.contract.ContractValidationError):
            self.contract.validate_artifact(bad_version)


class TimelineReviewCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)
        test_path = ROOT / "tests" / "test_epc_evidence_review.py"
        spec = importlib.util.spec_from_file_location("review_fixtures_under_test", test_path)
        review_tests = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(review_tests)
        self.review_tests = review_tests
        self.review = review_tests.REVIEW
        self.epc = review_tests.EPC

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def timeline_document(self) -> dict:
        control = self.review_tests.dedicated_document()
        control_path = self.base / "control.json"
        control_path.write_text(json.dumps(control), encoding="utf-8")
        return model.build_timeline(
            control,
            [],
            [],
            control_path=control_path,
            nas_path=None,
            s1ap_path=None,
        )

    def source(self, timeline: dict | None = None) -> Path:
        documents = self.epc.scenario()
        documents["dedicated"] = self.review_tests.dedicated_document()
        source = self.base / "artifacts"
        self.review_tests.write_documents(source, documents, detailed=True)
        if timeline is not None:
            (source / "epc-dedicated-bearer-timeline-analysis.json").write_text(
                json.dumps(timeline), encoding="utf-8"
            )
        return source

    def test_valid_optional_timeline_is_hashed_and_provenanced(self) -> None:
        timeline = self.timeline_document()
        source = self.source(timeline)
        artifacts = self.review.load_artifacts(source)
        entry = [
            item
            for item in artifacts["sources"]
            if item["artifact_type"] == self.review.ARTIFACT_DEDICATED_BEARER_TIMELINE
        ][0]
        self.assertTrue(entry["supplied"])
        self.assertEqual(entry["validation_status"], self.review.SUPPLIED_ARTIFACT_VALID)
        self.assertEqual(len(entry["sha256"]), 64)
        manifest = self.review.build_manifest(
            artifacts,
            mode="EXISTING_ARTIFACTS",
            local_pcap_replayed=False,
            replay_status="NOT_REPLAYED",
        )
        self.assertEqual(
            manifest["provenance"]["dedicated_bearer_timeline"],
            "epc-dedicated-bearer-timeline-analysis.json",
        )

    def test_invalid_optional_timeline_is_rejected(self) -> None:
        timeline = self.timeline_document()
        del timeline["timeline_entries"]
        source = self.source(timeline)
        with self.assertRaises(self.review.ReviewInputError) as raised:
            self.review.load_artifacts(source)
        self.assertEqual(raised.exception.code, self.review.SUPPLIED_ARTIFACT_INVALID)

    def test_missing_timeline_remains_compatible(self) -> None:
        source = self.source(None)
        artifacts = self.review.load_artifacts(source)
        entry = [
            item
            for item in artifacts["sources"]
            if item["artifact_type"] == self.review.ARTIFACT_DEDICATED_BEARER_TIMELINE
        ][0]
        self.assertFalse(entry["supplied"])
        self.assertEqual(
            entry["validation_status"], self.review.OPTIONAL_ARTIFACT_NOT_SUPPLIED
        )


if __name__ == "__main__":
    unittest.main()