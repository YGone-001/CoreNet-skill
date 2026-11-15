#!/usr/bin/env python3
"""Tests for the Dedicated Bearer control-to-access attribution artifact."""

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

import epc_dedicated_bearer_attribution_model as model  # noqa: E402


def ref(frame: int) -> dict:
    return {
        "frame_number": frame,
        "message_type": "Bearer request",
        "message_type_code": 95,
        "sequence_number": 1,
        "header_teid": 0,
        "header_teid_state": "PRESENT",
        "message_occurrence": 1,
    }


def fteid(interface_type: int, teid: int, address: str, join: bool = True) -> dict:
    return {
        "interface_type": interface_type,
        "teid": teid,
        "address": address,
        "join_capable": join,
        "scope": "control_plane",
    }


def context(reference: str, interface_class: str, fteids: list[dict], capture: str = "fixture.pcap") -> dict:
    return {
        "capture_file": capture,
        "session_context_reference": reference,
        "interface_class": interface_class,
        "association_status": "ESTABLISHED",
        "control_plane_fteids": fteids,
        "bearer_user_plane_fteids": [],
        "member_transactions": [],
    }


def transaction(name: str = "create-1", ebi: int = 7, request: int = 100, response: int = 110) -> tuple[dict, list[dict]]:
    tx_ref = f"epc-db-tx:fixture.pcap:{name}"
    req_item = f"epc-db-item:{tx_ref}:request:{request}:0:0"
    res_item = f"epc-db-item:{tx_ref}:response:{response}:0:0"
    tx = {
        "transaction_reference": tx_ref,
        "protocol_transaction_reference": f"gtpv2-{name}",
        "capture": "fixture.pcap",
        "procedure_family": "create-bearer",
        "correlation_status": "MATCHED",
        "request": ref(request),
        "response": ref(response),
        "frame_anchors": {"request_frame": request, "response_frame": response},
        "message_outcome": {"status": "MESSAGE_ACCEPTED_OBSERVED"},
        "request_bearer_item_references": [req_item],
        "response_bearer_item_references": [res_item],
        "source_completeness_status": "COMPLETE",
        "evidence_limitations": [],
    }
    items = [
        {
            "item_reference": req_item,
            "ebi": 0,
            "ebi_status": "INVALID",
            "item_outcome": "ITEM_REQUEST_EVIDENCE_ONLY",
            "f_teids": [{"interface_type": 1, "teid": 40987, "ipv4": "10.10.0.139", "scope": "bearer"}],
        },
        {
            "item_reference": res_item,
            "ebi": ebi,
            "ebi_status": "VALID",
            "item_outcome": "ITEM_CONTROL_ACCEPTED_OBSERVED",
            "f_teids": [{"interface_type": 1, "teid": 4261120, "ipv4": "10.10.0.138", "scope": "bearer"}],
        },
    ]
    return tx, items


def control_document(transactions: list[dict], items: list[dict], *, capture: str = "fixture.pcap") -> dict:
    return {
        "analysis_name": "epc-dedicated-bearer-control",
        "analysis_version": "1.0.0",
        "input_provenance": {"gtpv2_events": capture},
        "control_transactions": transactions,
        "control_transaction_count": len(transactions),
        "control_transactions_omitted": 0,
        "bearer_item_observations": items,
        "bearer_item_observation_count": len(items),
        "source_completeness": {"status": "COMPLETE"},
    }


def identity_document(contexts: list[dict], links: list[dict] | None = None) -> dict:
    return {
        "analysis_name": "epc-session-identity",
        "analysis_version": "1.0.0",
        "hop_local_contexts": contexts,
        "endpoint_correspondence_links": links or [],
    }


def gtpv2_event(frame: int, teid: int, source: str, destination: str) -> dict:
    return {
        "capture_file": "fixture.pcap",
        "frame_number": frame,
        "header": {"teid": teid},
        "source": {"address": source},
        "destination": {"address": destination},
        "message_type": "Create Bearer Request",
        "message_type_code": 95,
    }


def nas_event(frame: int, code: int = 197, result: str = "REQUEST", ebi: int = 7) -> dict:
    return {
        "capture_file": "fixture.pcap",
        "frame_number": frame,
        "esm_messages": [
            {
                "occurrence_index": 0,
                "message_type_code": code,
                "message_type": "Dedicated bearer",
                "support_status": "SUPPORTED",
                "procedure": "dedicated-bearer-activation",
                "result": result,
                "eps_bearer_identity": ebi,
                "protection_state": "INTEGRITY_AND_CIPHERED",
                "binding_basis": "pdml_grouped_ie",
                "limitations": [],
            }
        ],
    }


def s1ap_event(
    frame: int,
    context: str = "s1ap-ctx-1",
    operation: str = "E_RAB_SETUP",
    role: str = "REQUEST",
    teid: int | None = 40987,
    address: str = "10.10.0.139",
    *,
    embedded: bool = True,
) -> dict:
    return {
        "capture_file": "fixture.pcap",
        "frame_number": frame,
        "context_key": context,
        "procedure_name": "id-E-RABSetup",
        "message_type": "E-RABSetupRequest",
        "support_status": "SUPPORTED",
        "sender_role": "mme",
        "nas_pdu_embedded": embedded,
        "erab_items": [
            {
                "operation": operation,
                "list_role": role,
                "erab_id": 7,
                "gtp_teid": teid,
                "transport_layer_address": address,
                "binding_basis": "pdml_grouped_ie",
                "limitations": [],
            }
        ],
    }


class AttributionTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)
        self.control_path = self.base / "control.json"
        self.identity_path = self.base / "identity.json"

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def build(
        self,
        control: dict,
        identity: dict,
        gtpv2: list[dict],
        nas: list[dict] | None = None,
        s1ap: list[dict] | None = None,
        *,
        gtpv2_present: bool = True,
        nas_present: bool = True,
        s1ap_present: bool = True,
    ) -> dict:
        self.control_path.write_text(json.dumps(control), encoding="utf-8")
        self.identity_path.write_text(json.dumps(identity), encoding="utf-8")
        return model.build_attribution(
            control,
            identity,
            gtpv2,
            nas or [],
            s1ap or [],
            control_path=self.control_path,
            identity_path=self.identity_path,
            gtpv2_path=self.base / "gtpv2.jsonl" if gtpv2_present else None,
            nas_path=self.base / "nas.jsonl" if nas_present else None,
            s1ap_path=self.base / "s1ap.jsonl" if s1ap_present else None,
        )

    def base_fixture(self):
        tx, items = transaction()
        context_value = context(
            "epc-session-context-s11-1",
            "S11",
            [
                fteid(10, 1000, "10.0.0.2"),
                fteid(10, 2000, "10.0.0.1"),
            ],
        )
        return tx, items, context_value


class AttributionPositiveTests(AttributionTestCase):
    def test_unique_receiver_scoped_context_is_established(self) -> None:
        tx, items, ctx = self.base_fixture()
        attribution = self.build(
            control_document([tx], items),
            identity_document([ctx]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
            [nas_event(105, 197, "REQUEST")],
            [s1ap_event(105)],
        )
        entry = attribution["attribution_entries"][0]
        self.assertEqual(entry["control_session"]["status"], "ESTABLISHED_BY_EVIDENCE")
        self.assertEqual(entry["control_session"]["session_context_reference"], "epc-session-context-s11-1")
        self.assertEqual(entry["overall_status"], "CANDIDATE_UNCONFIRMED")
        self.assertIn("CONTROL_TO_SESSION", entry["established_links"])

    def test_multiple_bearers_and_contexts_remain_isolated(self) -> None:
        tx1, items1 = transaction("create-1", ebi=7, request=100, response=110)
        tx2, items2 = transaction("create-2", ebi=8, request=200, response=210)
        ctx1 = context("ctx-1", "S11", [fteid(10, 1000, "10.0.0.2"), fteid(10, 2000, "10.0.0.1")])
        ctx2 = context("ctx-2", "S11", [fteid(10, 3000, "10.0.0.4"), fteid(10, 4000, "10.0.0.3")])
        attribution = self.build(
            control_document([tx1, tx2], items1 + items2),
            identity_document([ctx1, ctx2]),
            [
                gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2"),
                gtpv2_event(200, 3000, "10.0.0.3", "10.0.0.4"),
            ],
        )
        self.assertEqual(
            [entry["control_session"]["session_context_reference"] for entry in attribution["attribution_entries"]],
            ["ctx-1", "ctx-2"],
        )

    def test_valid_nas_ownership_with_embedded_pdu(self) -> None:
        tx, items, ctx = self.base_fixture()
        attribution = self.build(
            control_document([tx], items),
            identity_document([ctx]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
            [nas_event(105)],
            [s1ap_event(105)],
        )
        nas = attribution["attribution_entries"][0]["nas_access"]
        self.assertEqual(nas["status"], "ESTABLISHED_BY_EVIDENCE")
        self.assertEqual(nas["owner_s1ap_context"], "s1ap-ctx-1")

    def test_endpoint_correspondence_is_not_established(self) -> None:
        tx, items, ctx = self.base_fixture()
        ctx5 = context("ctx-s5", "S5/S8", [fteid(6, 5000, "10.0.0.9")])
        link = {
            "reference": "epc-identity-link-test",
            "source_subject_reference": "epc-session-context-s11-1",
            "target_subject_reference": "ctx-s5",
            "association_status": "SUPPORTED",
        }
        attribution = self.build(
            control_document([tx], items),
            identity_document([ctx, ctx5], [link]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
            [nas_event(105)],
            [s1ap_event(105)],
        )
        entry = attribution["attribution_entries"][0]
        self.assertEqual(entry["s1ap_access"]["status"], "ENDPOINT_CORRESPONDENCE_ONLY")
        self.assertNotEqual(entry["overall_status"], "ESTABLISHED_BY_EVIDENCE")
        self.assertIn("CONTROL_TO_SESSION", entry["established_links"])
        self.assertNotIn("SESSION_TO_ACCESS", entry["established_links"])

    def test_deterministic_ordering_and_frame_references(self) -> None:
        tx1, items1 = transaction("create-2", ebi=8, request=200, response=210)
        tx2, items2 = transaction("create-1", ebi=7, request=100, response=110)
        ctx1 = context("ctx-1", "S11", [fteid(10, 1000, "10.0.0.2"), fteid(10, 2000, "10.0.0.1")])
        ctx2 = context("ctx-2", "S11", [fteid(10, 3000, "10.0.0.4"), fteid(10, 4000, "10.0.0.3")])
        identity = identity_document([ctx1, ctx2])
        first = self.build(
            control_document([tx1, tx2], items1 + items2),
            identity,
            [
                gtpv2_event(200, 3000, "10.0.0.3", "10.0.0.4"),
                gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2"),
            ],
        )
        second = self.build(
            control_document([tx2, tx1], items2 + items1),
            identity,
            [
                gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2"),
                gtpv2_event(200, 3000, "10.0.0.3", "10.0.0.4"),
            ],
        )
        self.assertEqual(
            [entry["request_frame"] for entry in first["attribution_entries"]], [100, 200]
        )
        self.assertEqual(first["attribution_entries"], second["attribution_entries"])


class AttributionNegativeTests(AttributionTestCase):
    def test_receiver_endpoint_mismatch_does_not_join(self) -> None:
        tx, items, ctx = self.base_fixture()
        attribution = self.build(
            control_document([tx], items),
            identity_document([ctx]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.9.9.9")],
            [nas_event(105)],
            [s1ap_event(105)],
        )
        self.assertEqual(
            attribution["attribution_entries"][0]["control_session"]["status"],
            "NOT_ESTABLISHED",
        )

    def test_peer_mismatch_does_not_join(self) -> None:
        tx, items, ctx = self.base_fixture()
        attribution = self.build(
            control_document([tx], items),
            identity_document([ctx]),
            [gtpv2_event(100, 1000, "10.9.9.9", "10.0.0.2")],
            [nas_event(105)],
            [s1ap_event(105)],
        )
        self.assertEqual(
            attribution["attribution_entries"][0]["control_session"]["status"],
            "NOT_ESTABLISHED",
        )

    def test_wrong_interface_type_does_not_join(self) -> None:
        tx, items, _ctx = self.base_fixture()
        wrong = context(
            "ctx-wrong",
            "S11",
            [fteid(6, 1000, "10.0.0.2"), fteid(6, 2000, "10.0.0.1")],
        )
        attribution = self.build(
            control_document([tx], items),
            identity_document([wrong]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
        )
        self.assertEqual(
            attribution["attribution_entries"][0]["control_session"]["status"],
            "NOT_ESTABLISHED",
        )

    def test_two_context_candidates_are_ambiguous(self) -> None:
        tx, items, ctx = self.base_fixture()
        duplicate = copy.deepcopy(ctx)
        duplicate["session_context_reference"] = "epc-session-context-s11-2"
        attribution = self.build(
            control_document([tx], items),
            identity_document([ctx, duplicate]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
        )
        self.assertEqual(
            attribution["attribution_entries"][0]["control_session"]["status"], "AMBIGUOUS"
        )

    def test_nas_without_embedded_pdu_is_not_owned(self) -> None:
        tx, items, ctx = self.base_fixture()
        attribution = self.build(
            control_document([tx], items),
            identity_document([ctx]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
            [nas_event(105)],
            [s1ap_event(105, embedded=False)],
        )
        self.assertEqual(
            attribution["attribution_entries"][0]["nas_access"]["status"],
            "NOT_ESTABLISHED",
        )

    def test_multiple_same_frame_nas_owners_are_ambiguous(self) -> None:
        tx, items, ctx = self.base_fixture()
        attribution = self.build(
            control_document([tx], items),
            identity_document([ctx]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
            [nas_event(105)],
            [s1ap_event(105, context="ctx-a"), s1ap_event(105, context="ctx-b")],
        )
        self.assertEqual(
            attribution["attribution_entries"][0]["nas_access"]["status"], "AMBIGUOUS"
        )

    def test_equal_teid_across_captures_does_not_join(self) -> None:
        tx, items, ctx = self.base_fixture()
        other = copy.deepcopy(ctx)
        other["capture_file"] = "other.pcap"
        attribution = self.build(
            control_document([tx], items),
            identity_document([other]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
        )
        self.assertEqual(
            attribution["attribution_entries"][0]["control_session"]["status"],
            "NOT_ESTABLISHED",
        )

    def test_missing_control_teid_is_not_established(self) -> None:
        tx, items, ctx = self.base_fixture()
        attribution = self.build(
            control_document([tx], items),
            identity_document([ctx]),
            [gtpv2_event(100, 0, "10.0.0.1", "10.0.0.2")],
        )
        self.assertEqual(
            attribution["attribution_entries"][0]["control_session"]["status"],
            "NOT_ESTABLISHED",
        )

    def test_truncated_control_source_is_not_upgraded(self) -> None:
        tx, items, ctx = self.base_fixture()
        control = control_document([tx], items)
        control["source_completeness"]["status"] = "TRUNCATED"
        attribution = self.build(
            control,
            identity_document([ctx]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
        )
        self.assertEqual(
            attribution["source_completeness"]["control_source_completeness"], "TRUNCATED"
        )
        self.assertNotEqual(attribution["source_completeness"]["status"], "COMPLETE")

    def test_mixed_capture_control_is_rejected(self) -> None:
        tx, items, ctx = self.base_fixture()
        foreign = copy.deepcopy(tx)
        foreign["capture"] = "other.pcap"
        foreign["transaction_reference"] = "epc-db-tx:other.pcap:create-2"
        with self.assertRaises(model.InputError) as raised:
            self.build(
                control_document([tx, foreign], items),
                identity_document([ctx]),
                [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
            )
        self.assertEqual(raised.exception.code, "MIXED_CAPTURE_ARTIFACT")

    def test_control_only_partial_and_unsupported_evidence(self) -> None:
        tx, items, ctx = self.base_fixture()
        control_only = self.build(
            control_document([tx], items),
            identity_document([ctx]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
            nas_present=False,
            s1ap_present=False,
        )
        entry = control_only["attribution_entries"][0]
        self.assertEqual(entry["control_session"]["status"], "ESTABLISHED_BY_EVIDENCE")
        self.assertEqual(entry["nas_access"]["status"], "NOT_OBSERVED")
        self.assertEqual(entry["s1ap_access"]["status"], "NOT_OBSERVED")
        self.assertEqual(entry["overall_status"], "CANDIDATE_UNCONFIRMED")
        self.assertIn("CONTROL_TO_SESSION", entry["established_links"])

        unsupported_nas = nas_event(105)
        unsupported_nas["esm_messages"][0]["support_status"] = "UNSUPPORTED"
        unsupported = self.build(
            control_document([tx], items),
            identity_document([ctx]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
            [unsupported_nas],
            [s1ap_event(105)],
        )
        self.assertEqual(
            unsupported["attribution_entries"][0]["nas_access"]["status"],
            "UNSUPPORTED_EVIDENCE",
        )

        temporal_only = self.build(
            control_document([tx], items),
            identity_document([ctx]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
            [nas_event(105)],
            [s1ap_event(105, teid=999999)],
        )
        entry = temporal_only["attribution_entries"][0]
        self.assertEqual(entry["s1ap_access"]["status"], "CANDIDATE_UNCONFIRMED")
        self.assertNotEqual(entry["overall_status"], "ESTABLISHED_BY_EVIDENCE")

    def test_no_fabricated_activation_or_chain(self) -> None:
        tx, items, ctx = self.base_fixture()
        attribution = self.build(
            control_document([tx], items),
            identity_document([ctx]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
            [nas_event(105)],
            [s1ap_event(105)],
        )
        entry = attribution["attribution_entries"][0]
        self.assertNotEqual(entry["overall_status"], "ESTABLISHED_BY_EVIDENCE")
        self.assertNotIn("bearer_activated", entry)
        self.assertNotIn("SESSION_TO_ACCESS", entry["established_links"])
        self.assertTrue(entry["additional_evidence_needed"])

    def test_wrong_capture_events_are_not_used(self) -> None:
        tx, items, ctx = self.base_fixture()
        attribution = self.build(
            control_document([tx], items),
            identity_document([ctx]),
            [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
            [nas_event(105) | {"capture_file": "other.pcap"}],
            [s1ap_event(105) | {"capture_file": "other.pcap"}],
        )
        entry = attribution["attribution_entries"][0]
        self.assertEqual(entry["nas_access"]["status"], "NOT_OBSERVED")
        self.assertEqual(entry["s1ap_access"]["status"], "NOT_OBSERVED")

    def test_no_control_transactions_is_not_observed(self) -> None:
        attribution = self.build(
            control_document([], []),
            identity_document([]),
            [],
        )
        self.assertEqual(attribution["execution_status"], "NOT_OBSERVED_IN_CAPTURE")
        self.assertEqual(attribution["attribution_entry_count"], 0)


class AttributionContractTests(unittest.TestCase):
    def setUp(self) -> None:
        path = ROOT / "scripts" / "epc_dedicated_bearer_attribution_contract.py"
        spec = importlib.util.spec_from_file_location("attribution_contract_under_test", path)
        contract = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(contract)
        self.contract = contract

    def valid(self) -> dict:
        tx, items = transaction()
        ctx = context(
            "epc-session-context-s11-1",
            "S11",
            [fteid(10, 1000, "10.0.0.2"), fteid(10, 2000, "10.0.0.1")],
        )
        with tempfile.TemporaryDirectory() as temporary:
            cp = Path(temporary) / "control.json"
            ip = Path(temporary) / "identity.json"
            cp.write_text(json.dumps(control_document([tx], items)), encoding="utf-8")
            ip.write_text(json.dumps(identity_document([ctx])), encoding="utf-8")
            return model.build_attribution(
                control_document([tx], items),
                identity_document([ctx]),
                [gtpv2_event(100, 1000, "10.0.0.1", "10.0.0.2")],
                [nas_event(105)],
                [s1ap_event(105)],
                control_path=cp,
                identity_path=ip,
                gtpv2_path=Path("gtpv2.jsonl"),
                nas_path=Path("nas.jsonl"),
                s1ap_path=Path("s1ap.jsonl"),
            )

    def test_valid_artifact(self) -> None:
        self.contract.validate_artifact(self.valid())

    def test_overall_promotion_is_rejected(self) -> None:
        document = self.valid()
        document["attribution_entries"][0]["overall_status"] = "ESTABLISHED_BY_EVIDENCE"
        with self.assertRaises(self.contract.ContractValidationError):
            self.contract.validate_artifact(document)

    def test_endpoint_only_promotion_is_rejected(self) -> None:
        document = self.valid()
        entry = document["attribution_entries"][0]
        entry["s1ap_access"]["status"] = "ENDPOINT_CORRESPONDENCE_ONLY"
        entry["overall_status"] = "ESTABLISHED_BY_EVIDENCE"
        with self.assertRaises(self.contract.ContractValidationError):
            self.contract.validate_artifact(document)

    def test_count_mismatch_is_rejected(self) -> None:
        document = self.valid()
        document["attribution_entry_count"] += 1
        with self.assertRaises(self.contract.ContractValidationError):
            self.contract.validate_artifact(document)


class AttributionReviewCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)
        test_path = ROOT / "tests" / "test_epc_evidence_review.py"
        spec = importlib.util.spec_from_file_location("review_fixtures_for_attribution", test_path)
        review_tests = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(review_tests)
        self.review_tests = review_tests
        self.review = review_tests.REVIEW
        self.epc = review_tests.EPC

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def attribution(self) -> dict:
        control = self.review_tests.dedicated_document()
        identity = {
            "analysis_name": "epc-session-identity",
            "analysis_version": "1.0.0",
            "hop_local_contexts": [],
            "endpoint_correspondence_links": [],
        }
        control_path = self.base / "control.json"
        identity_path = self.base / "identity.json"
        control_path.write_text(json.dumps(control), encoding="utf-8")
        identity_path.write_text(json.dumps(identity), encoding="utf-8")
        return model.build_attribution(
            control,
            identity,
            [],
            [],
            [],
            control_path=control_path,
            identity_path=identity_path,
            gtpv2_path=None,
            nas_path=None,
            s1ap_path=None,
        )

    def source(self, attribution: dict | None) -> Path:
        documents = self.epc.scenario()
        documents["dedicated"] = self.review_tests.dedicated_document()
        source = self.base / "artifacts"
        self.review_tests.write_documents(source, documents, detailed=True)
        if attribution is not None:
            (source / "epc-dedicated-bearer-attribution-analysis.json").write_text(
                json.dumps(attribution), encoding="utf-8"
            )
        return source

    def test_valid_optional_attribution_is_accepted(self) -> None:
        source = self.source(self.attribution())
        artifacts = self.review.load_artifacts(source)
        entry = [
            item
            for item in artifacts["sources"]
            if item["artifact_type"] == self.review.ARTIFACT_DEDICATED_BEARER_ATTRIBUTION
        ][0]
        self.assertTrue(entry["supplied"])
        self.assertEqual(entry["validation_status"], self.review.SUPPLIED_ARTIFACT_VALID)
        manifest = self.review.build_manifest(
            artifacts,
            mode="EXISTING_ARTIFACTS",
            local_pcap_replayed=False,
            replay_status="NOT_REPLAYED",
        )
        self.assertEqual(
            manifest["provenance"]["dedicated_bearer_attribution"],
            "epc-dedicated-bearer-attribution-analysis.json",
        )

    def test_invalid_optional_attribution_is_rejected(self) -> None:
        attribution = self.attribution()
        del attribution["attribution_entries"]
        source = self.source(attribution)
        with self.assertRaises(self.review.ReviewInputError) as raised:
            self.review.load_artifacts(source)
        self.assertEqual(raised.exception.code, self.review.SUPPLIED_ARTIFACT_INVALID)

    def test_missing_attribution_remains_compatible(self) -> None:
        source = self.source(None)
        artifacts = self.review.load_artifacts(source)
        entry = [
            item
            for item in artifacts["sources"]
            if item["artifact_type"] == self.review.ARTIFACT_DEDICATED_BEARER_ATTRIBUTION
        ][0]
        self.assertFalse(entry["supplied"])
        self.assertEqual(entry["validation_status"], self.review.OPTIONAL_ARTIFACT_NOT_SUPPLIED)


if __name__ == "__main__":
    unittest.main()