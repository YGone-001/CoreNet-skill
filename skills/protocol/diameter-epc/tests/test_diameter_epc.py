#!/usr/bin/env python3
"""Standalone tests for the bounded Diameter EPC S6a/S6d application Skill."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:
    jsonschema = None

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
CLI = SCRIPTS / "analyze-diameter-epc.py"
SCHEMA = PACKAGE / "schemas" / "diameter-epc-analysis.schema.json"
sys.path.insert(0, str(SCRIPTS))
import diameter_epc_model as model  # noqa: E402

CAPTURE = "epc-synthetic.pcapng"


def avp(code, name, *, vendor=None, sensitive=False, grouping="NOT_GROUPED", kind="OPAQUE", value=None):
    return {
        "avp_reference": f"diameter-avp:{CAPTURE}:{code}",
        "code": code,
        "name": name,
        "name_reviewed": True,
        "occurrence_index": 1,
        "depth": 1,
        "vendor_specific": vendor is not None,
        "mandatory": True,
        "protected": False,
        "vendor_id": vendor,
        "length": 12,
        "data_present": True,
        "sensitive": sensitive,
        "value": value,
        "value_kind": kind,
        "grouping_status": grouping,
        "children_omitted": 0,
        "children": [],
    }


def empty_result():
    return {
        "result_code": None,
        "result_code_name": None,
        "result_namespace": None,
        "experimental_result_present": False,
        "experimental_result_code": None,
        "experimental_vendor_id": None,
    }


def base_result(code, name=None):
    result = empty_result()
    result.update(
        {
            "result_code": code,
            "result_code_name": name,
            "result_namespace": "BASE",
        }
    )
    return result


def experimental_result(code, vendor):
    result = empty_result()
    result.update(
        {
            "result_namespace": "VENDOR_SPECIFIC",
            "experimental_result_present": True,
            "experimental_result_code": code,
            "experimental_vendor_id": vendor,
        }
    )
    return result


def event(
    frame,
    *,
    occurrence=1,
    request=True,
    command=318,
    application=16777251,
    hop,
    end_to_end,
    avps=None,
    result=None,
    omitted=0,
    association=0,
):
    return {
        "capture_file": CAPTURE,
        "frame_number": frame,
        "frame_time_epoch": f"{1700000000 + frame}.0",
        "message_occurrence": occurrence,
        "protocol_version": 1,
        "message_length": 100,
        "message_length_status": "VALID",
        "command_code": command,
        "command_name": None,
        "command_scope": "APPLICATION_OR_UNKNOWN",
        "application_id": application,
        "application_semantics": "UNSUPPORTED",
        "flags": {"request": request, "proxyable": False, "error": False, "retransmitted": False},
        "direction": "REQUEST" if request else "ANSWER",
        "hop_by_hop_id": hop,
        "end_to_end_id": end_to_end,
        "transport": {
            "protocol": "SCTP",
            "source_address": "10.1.0.1" if request else "10.1.0.2",
            "source_port": 40000 if request else 3868,
            "destination_address": "10.1.0.2" if request else "10.1.0.1",
            "destination_port": 3868 if request else 40000,
            "verification_tag": "0x00000001",
            "stream_id": None,
            "association_index": association,
            "association_identity_status": "DECODER_INDEX",
            "association_reference": f"diameter-assoc:{CAPTURE}:sctp-assoc-{association}",
        },
        "avps": avps or [],
        "avp_count": len(avps or []),
        "avps_omitted": omitted,
        "result": result or empty_result(),
        "evidence_class": "OBSERVED",
        "limitations": [],
    }


def reference(ev, name=None):
    return {
        "frame_number": ev["frame_number"],
        "message_occurrence": ev["message_occurrence"],
        "frame_time_epoch": ev["frame_time_epoch"],
        "command_code": ev["command_code"],
        "command_name": name,
        "application_id": ev["application_id"],
        "direction": ev["direction"],
        "hop_by_hop_id": ev["hop_by_hop_id"],
        "end_to_end_id": ev["end_to_end_id"],
        "source_endpoint": "10.1.0.1:40000",
        "destination_endpoint": "10.1.0.2:3868",
    }


def transaction(ref, status, request_ev=None, answer_ev=None, candidates=None, latency=None):
    return {
        "transaction_reference": ref,
        "command_code": (request_ev or answer_ev)["command_code"],
        "command_name": None,
        "command_scope": "APPLICATION_OR_UNKNOWN",
        "application_id": (request_ev or answer_ev)["application_id"],
        "application_semantics": "UNSUPPORTED",
        "transport_association_reference": (request_ev or answer_ev)["transport"]["association_reference"],
        "request": reference(request_ev) if request_ev else None,
        "answer": reference(answer_ev) if answer_ev else None,
        "response_candidates": [reference(item) for item in (candidates or [])],
        "correlation_status": status,
        "correlation_strength": "STRONG" if status == "MATCHED" else "NONE",
        "correlation_basis": [],
        "latency_seconds": latency if status == "MATCHED" else None,
        "result_code": None,
        "result_code_name": None,
        "result_namespace": None,
        "experimental_result_code": None,
        "experimental_vendor_id": None,
        "limitations": [],
    }


def documents():
    events = []
    transactions = []

    air = event(
        1,
        hop=100,
        end_to_end=500,
        avps=[
            avp(263, "Session-Id"),
            avp(1, "User-Name", sensitive=True, kind="SENSITIVE_REDACTED"),
            avp(1408, "Requested-EUTRAN-Authentication-Info", vendor=10415, sensitive=True, grouping="NOT_DECODED", kind="SENSITIVE_REDACTED"),
            avp(1407, "Visited-PLMN-Id", vendor=10415),
            avp(264, "Origin-Host", kind="STRING", value="mme.example"),
        ],
        omitted=2,
    )
    aia = event(
        2,
        request=False,
        hop=100,
        end_to_end=500,
        avps=[
            avp(268, "Result-Code", kind="INTEGER", value=2001),
            avp(1413, "E-UTRAN-Authentication-Info", vendor=10415, sensitive=True, grouping="NOT_DECODED", kind="SENSITIVE_REDACTED"),
        ],
        result=base_result(2001, "DIAMETER_SUCCESS"),
    )
    ulr = event(
        3,
        request=True,
        command=316,
        hop=101,
        end_to_end=501,
        avps=[
            avp(263, "Session-Id"),
            avp(1032, "RAT-Type", vendor=10415),
            avp(1405, "ULR-Flags", vendor=10415),
            avp(1407, "Visited-PLMN-Id", vendor=10415),
            avp(628, "Supported-Features", vendor=10415),
        ],
        omitted=3,
    )
    ula = event(
        4,
        request=False,
        command=316,
        hop=101,
        end_to_end=501,
        avps=[
            avp(268, "Result-Code", kind="INTEGER", value=2001),
            avp(1400, "Subscription-Data", vendor=10415, grouping="NOT_DECODED"),
        ],
        result=base_result(2001, "DIAMETER_SUCCESS"),
        omitted=33,
    )
    nor = event(5, request=True, command=321, hop=102, end_to_end=502, avps=[avp(263, "Session-Id")])
    noa = event(
        6,
        request=False,
        command=321,
        hop=102,
        end_to_end=502,
        avps=[avp(268, "Result-Code", kind="INTEGER", value=2001)],
        result=base_result(2001, "DIAMETER_SUCCESS"),
    )
    non_s6a_request = event(7, hop=103, end_to_end=503, application=16777238)
    non_s6a_answer = event(
        8,
        request=False,
        hop=103,
        end_to_end=503,
        application=16777238,
        result=base_result(2001, "DIAMETER_SUCCESS"),
    )
    answer_only = event(
        9,
        request=False,
        hop=104,
        end_to_end=504,
        avps=[avp(268, "Result-Code", kind="INTEGER", value=2001)],
        result=base_result(2001, "DIAMETER_SUCCESS"),
    )
    open_air = event(10, hop=105, end_to_end=505, avps=[avp(263, "Session-Id")])
    amb_a = event(11, hop=106, end_to_end=506)
    amb_b = event(12, hop=106, end_to_end=506)
    amb_answer = event(
        13,
        request=False,
        hop=106,
        end_to_end=506,
        avps=[avp(268, "Result-Code", kind="INTEGER", value=2001)],
        result=base_result(2001, "DIAMETER_SUCCESS"),
    )
    reuse_a = event(14, hop=107, end_to_end=507, association=0)
    reuse_b = event(15, hop=107, end_to_end=507, association=1)
    reuse_a_answer = event(
        16,
        request=False,
        hop=107,
        end_to_end=507,
        association=0,
        result=base_result(2001, "DIAMETER_SUCCESS"),
        avps=[avp(268, "Result-Code", kind="INTEGER", value=2001)],
    )
    reuse_b_answer = event(
        17,
        request=False,
        hop=107,
        end_to_end=507,
        association=1,
        result=base_result(2001, "DIAMETER_SUCCESS"),
        avps=[avp(268, "Result-Code", kind="INTEGER", value=2001)],
    )
    multi_air = event(18, occurrence=1, hop=108, end_to_end=508)
    multi_ulr = event(18, occurrence=2, command=316, hop=109, end_to_end=509)

    events.extend(
        [
            air, aia, ulr, ula, nor, noa, non_s6a_request, non_s6a_answer,
            answer_only, open_air, amb_a, amb_b, amb_answer, reuse_a, reuse_b,
            reuse_a_answer, reuse_b_answer, multi_air, multi_ulr,
        ]
    )
    transactions.extend(
        [
            transaction("tx-air", "MATCHED", air, aia, latency="0.100000"),
            transaction("tx-ulr", "MATCHED", ulr, ula, latency="0.200000"),
            transaction("tx-nor", "MATCHED", nor, noa, latency="0.300000"),
            transaction("tx-non-s6a", "MATCHED", non_s6a_request, non_s6a_answer, latency="0.400000"),
            transaction("tx-answer-only", "RESPONSE_ONLY", answer_ev=answer_only),
            transaction("tx-open-air", "OPEN_REQUEST", request_ev=open_air),
            transaction("tx-ambiguous", "AMBIGUOUS", answer_ev=amb_answer, candidates=[amb_a, amb_b]),
            transaction("tx-reuse-0", "MATCHED", reuse_a, reuse_a_answer, latency="0.500000"),
            transaction("tx-reuse-1", "MATCHED", reuse_b, reuse_b_answer, latency="0.600000"),
            transaction("tx-multi-air", "OPEN_REQUEST", request_ev=multi_air),
            transaction("tx-multi-ulr", "OPEN_REQUEST", request_ev=multi_ulr),
        ]
    )
    document = {
        "protocol": "Diameter",
        "capture_files": [CAPTURE],
        "transaction_count": len(transactions),
        "transactions": transactions,
    }
    return events, document


class DiameterEpcBehaviorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.events, self.transactions = documents()
        self.document = model.analyze(
            self.events,
            self.transactions,
            input_provenance={
                "capture_files": [CAPTURE],
                "event_count": len(self.events),
                "transaction_count": len(self.transactions["transactions"]),
                "events_sha256": "a" * 64,
                "transactions_sha256": "b" * 64,
            },
        )

    def observation(self, reference: str) -> dict:
        return next(item for item in self.document["observations"] if item["observation_reference"].endswith(reference))

    def test_air_aia_classification_and_provenance(self) -> None:
        air = self.observation("1.1")
        self.assertEqual(air["procedure"], "AIR")
        self.assertEqual(air["procedure_family"], "AUTHENTICATION_INFORMATION")
        self.assertEqual(air["transaction_status"], "MATCHED")
        self.assertEqual(air["request"]["frame_number"], 1)
        self.assertEqual(air["answer"]["frame_number"], 2)
        self.assertEqual(air["latency_seconds"], "0.100000")
        self.assertEqual(air["application_result"], "SUCCESS_REPORTED")
        self.assertEqual(air["authentication_information"], "PRESENT_REDACTED")

    def test_ulr_ula_bounded_presence(self) -> None:
        ulr = self.observation("3.1")
        self.assertEqual(ulr["procedure"], "ULR")
        self.assertEqual(ulr["transaction_status"], "MATCHED")
        subscription = [item for item in ulr["answer_avp_presence"] if item["code"] == 1400][0]
        self.assertEqual(subscription["status"], "PRESENT_STRUCTURE_ONLY")
        self.assertFalse(subscription["value_published"])

    def test_known_unsupported_command_is_not_malformed(self) -> None:
        nor = self.observation("5.1")
        self.assertEqual(nor["procedure"], "NOR")
        self.assertEqual(nor["message_status"], "UNSUPPORTED")
        self.assertEqual(nor["application_result"], "NOT_APPLICABLE")
        self.assertEqual(nor["result"]["application_result"], "NOT_APPLICABLE")
        self.assertTrue(any("outside this capability" in item for item in nor["limitations"]))

    def test_non_s6a_application_is_not_classified(self) -> None:
        self.assertFalse(any(item["command_code"] == 318 and item["request"] and item["request"]["frame_number"] == 7 for item in self.document["observations"]))
        inventory = [item for item in self.document["command_inventory"] if item["application_id"] == 16777238]
        self.assertTrue(inventory)
        self.assertTrue(all(item["scope"] == "NON_S6A_APPLICATION" for item in inventory))

    def test_answer_only_is_response_only_without_request_or_latency(self) -> None:
        answer = self.observation("9.1")
        self.assertEqual(answer["transaction_status"], "RESPONSE_ONLY")
        self.assertIsNone(answer["request"])
        self.assertIsNone(answer["latency_seconds"])
        self.assertEqual(answer["application_result"], "SUCCESS_REPORTED")

    def test_open_request_is_not_a_timeout(self) -> None:
        open_air = self.observation("10.1")
        self.assertEqual(open_air["transaction_status"], "OPEN_REQUEST")
        self.assertIsNone(open_air["answer"])
        self.assertIsNone(open_air["latency_seconds"])
        self.assertEqual(open_air["application_result"], "NOT_APPLICABLE")

    def test_ambiguous_transaction_retains_candidates(self) -> None:
        ambiguous = self.observation("13.1")
        self.assertEqual(ambiguous["transaction_status"], "AMBIGUOUS")
        self.assertIsNone(ambiguous["request"])
        self.assertIsNone(ambiguous["latency_seconds"])
        self.assertEqual(len(ambiguous["response_candidates"]), 2)
        self.assertEqual(self.document["completeness"]["unresolved_core_transactions"], 0)

    def test_reused_identifiers_on_distinct_associations_stay_separate(self) -> None:
        matched = [
            item for item in self.document["observations"]
            if item["transaction_status"] == "MATCHED" and item["command_code"] == 318
        ]
        pairs = {(item["request"]["frame_number"], item["answer"]["frame_number"]) for item in matched}
        self.assertIn((14, 16), pairs)
        self.assertIn((15, 17), pairs)

    def test_multiple_messages_in_one_frame_keep_occurrence_identity(self) -> None:
        first = self.observation("18.1")
        second = self.observation("18.2")
        self.assertEqual(first["request"]["message_occurrence"], 1)
        self.assertEqual(second["request"]["message_occurrence"], 2)
        self.assertNotEqual(first["observation_reference"], second["observation_reference"])

    def test_interface_identity_is_unproved(self) -> None:
        self.assertEqual(self.document["capability"]["interface_identity"], "UNPROVED")
        self.assertEqual(self.document["capability"]["interface_identity_basis"], [])

    def test_no_attach_or_authentication_verdict(self) -> None:
        serialized = json.dumps(self.document, sort_keys=True).lower()
        for forbidden in ("attach_success", "attach_failure", "ue_authenticated", "registration_success"):
            self.assertNotIn(forbidden, serialized)
        self.assertTrue(
            any("eps attach success or failure is not proven" in item.lower() for item in self.document["not_confirmed"])
        )


class DiameterEpcResultNamespaceTest(unittest.TestCase):
    def build(self, answer_result):
        events = [
            event(1, hop=1, end_to_end=1),
            event(2, request=False, hop=1, end_to_end=1, result=answer_result, avps=[]),
        ]
        document = {"protocol": "Diameter", "capture_files": [CAPTURE], "transactions": [transaction("tx", "MATCHED", events[0], events[1], latency="0.1")]}
        analysis = model.analyze(
            events,
            document,
            input_provenance={
                "capture_files": [CAPTURE],
                "event_count": 2,
                "transaction_count": 1,
                "events_sha256": "a" * 64,
                "transactions_sha256": "b" * 64,
            },
        )
        return analysis["observations"][0]["result"]

    def test_base_5001_is_avp_unsupported_not_user_unknown(self) -> None:
        result = self.build(base_result(5001, "DIAMETER_AVP_UNSUPPORTED"))
        self.assertEqual(result["namespace_status"], "BASE_RFC6733")
        self.assertEqual(result["base_result_code_name"], "DIAMETER_AVP_UNSUPPORTED")
        self.assertNotEqual(result["base_result_code_name"], "DIAMETER_ERROR_USER_UNKNOWN")
        self.assertEqual(result["application_result"], "FAILURE_REPORTED")

    def test_3gpp_experimental_5001_is_user_unknown(self) -> None:
        result = self.build(experimental_result(5001, 10415))
        self.assertEqual(result["namespace_status"], "3GPP_TS_29_272_EXPERIMENTAL")
        self.assertEqual(result["experimental_result_code_name"], "DIAMETER_ERROR_USER_UNKNOWN")
        self.assertEqual(result["application_result"], "FAILURE_REPORTED")

    def test_unknown_vendor_5001_has_no_3gpp_semantics(self) -> None:
        result = self.build(experimental_result(5001, 9999))
        self.assertEqual(result["namespace_status"], "UNKNOWN_VENDOR_EXPERIMENTAL")
        self.assertIsNone(result["experimental_result_code_name"])
        self.assertEqual(result["application_result"], "UNRESOLVED")

    def test_missing_vendor_5001_has_no_3gpp_semantics(self) -> None:
        result = self.build(experimental_result(5001, None))
        self.assertEqual(result["namespace_status"], "UNKNOWN_VENDOR_EXPERIMENTAL")
        self.assertIsNone(result["experimental_result_code_name"])
        self.assertEqual(result["application_result"], "UNRESOLVED")

    def test_both_namespaces_are_conflicting(self) -> None:
        combined = base_result(2001, "DIAMETER_SUCCESS")
        combined.update({"experimental_result_present": True, "experimental_result_code": 5001, "experimental_vendor_id": 10415})
        result = self.build(combined)
        self.assertEqual(result["namespace_status"], "CONFLICTING")
        self.assertEqual(result["application_result"], "UNRESOLVED")
        self.assertEqual(result["base_result_code"], 2001)
        self.assertEqual(result["experimental_result_code"], 5001)

    def test_missing_result_is_unresolved(self) -> None:
        result = self.build(empty_result())
        self.assertEqual(result["namespace_status"], "MISSING")
        self.assertEqual(result["application_result"], "UNRESOLVED")

    def test_unknown_3gpp_experimental_code_keeps_numeric_only(self) -> None:
        result = self.build(experimental_result(5099, 10415))
        self.assertEqual(result["status"] if "status" in result else result["namespace_status"], "3GPP_TS_29_272_EXPERIMENTAL")
        self.assertIsNone(result["experimental_result_code_name"])
        self.assertEqual(result["experimental_result_code"], 5099)
        self.assertEqual(result["application_result"], "UNRESOLVED")


class DiameterEpcPrivacyTest(unittest.TestCase):
    def test_authentication_values_are_never_published(self) -> None:
        events, transactions = documents()
        analysis = model.analyze(
            events,
            transactions,
            input_provenance={
                "capture_files": [CAPTURE],
                "event_count": len(events),
                "transaction_count": len(transactions["transactions"]),
                "events_sha256": "a" * 64,
                "transactions_sha256": "b" * 64,
            },
        )
        serialized = json.dumps(analysis)
        for secret in ("mme.example", "001010000000001", "RAND", "AUTN", "XRES", "KASME"):
            self.assertNotIn(secret, serialized)
        for observation in analysis["observations"]:
            for presence in observation["request_avp_presence"] + observation["answer_avp_presence"]:
                self.assertFalse(presence["value_published"])

    def test_truncated_auth_group_is_not_proven_absent(self) -> None:
        air = event(1, hop=1, end_to_end=1, omitted=10)
        aia = event(
            2,
            request=False,
            hop=1,
            end_to_end=1,
            omitted=10,
            result=base_result(2001, "DIAMETER_SUCCESS"),
        )
        document = {"protocol": "Diameter", "capture_files": [CAPTURE], "transactions": [transaction("tx", "MATCHED", air, aia, latency="0.1")]}
        analysis = model.analyze(
            events=[air, aia],
            transaction_document=document,
            input_provenance={
                "capture_files": [CAPTURE],
                "event_count": 2,
                "transaction_count": 1,
                "events_sha256": "a" * 64,
                "transactions_sha256": "b" * 64,
            },
        )
        observation = analysis["observations"][0]
        self.assertEqual(observation["authentication_information"], "NOT_OBSERVED_IN_PUBLISHED_SUBSET")
        self.assertGreater(analysis["completeness"]["truncated_observations"], 0)


class DiameterEpcInputValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def write(self, events, transactions):
        events_path = self.base / "events.jsonl"
        transactions_path = self.base / "transactions.json"
        events_path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
        transactions_path.write_text(json.dumps(transactions), encoding="utf-8")
        return events_path, transactions_path

    def test_capture_identity_mismatch_is_rejected(self) -> None:
        events, transactions = documents()
        events[1]["capture_file"] = "other.pcapng"
        path, tx_path = self.write(events, transactions)
        completed = subprocess.run(
            [sys.executable, str(CLI), "--events", str(path), "--transactions", str(tx_path), "--output", str(self.base / "out.json")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("capture", completed.stderr)

    def test_missing_event_reference_is_rejected(self) -> None:
        events, transactions = documents()
        transactions["transactions"][0]["answer"]["frame_number"] = 999
        path, tx_path = self.write(events, transactions)
        completed = subprocess.run(
            [sys.executable, str(CLI), "--events", str(path), "--transactions", str(tx_path), "--output", str(self.base / "out.json")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("does not resolve", completed.stderr)

    def test_inconsistent_matched_transaction_is_rejected(self) -> None:
        events, transactions = documents()
        transactions["transactions"][0]["answer"]["end_to_end_id"] = 999
        path, tx_path = self.write(events, transactions)
        completed = subprocess.run(
            [sys.executable, str(CLI), "--events", str(path), "--transactions", str(tx_path), "--output", str(self.base / "out.json")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("disagrees", completed.stderr)

    def test_invalid_json_input_is_rejected(self) -> None:
        events_path = self.base / "events.jsonl"
        transactions_path = self.base / "transactions.json"
        events_path.write_text("{not-json}\n", encoding="utf-8")
        transactions_path.write_text("{}", encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, str(CLI), "--events", str(events_path), "--transactions", str(transactions_path), "--output", str(self.base / "out.json")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("not valid JSON", completed.stderr)

    def test_existing_output_requires_force(self) -> None:
        events, transactions = documents()
        path, tx_path = self.write(events, transactions)
        output = self.base / "out.json"
        output.write_text("existing", encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, str(CLI), "--events", str(path), "--transactions", str(tx_path), "--output", str(output)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 6)
        self.assertIn("use --force", completed.stderr)

    def test_cli_output_and_schema_validation(self) -> None:
        if jsonschema is None:
            if os.environ.get("CI"):
                self.fail("jsonschema is required for the Diameter EPC schema gate in CI")
            self.skipTest("jsonschema unavailable")
        events, transactions = documents()
        path, tx_path = self.write(events, transactions)
        output = self.base / "analysis.json"
        timeline = self.base / "timeline.txt"
        completed = subprocess.run(
            [
                sys.executable,
                str(CLI),
                "--events",
                str(path),
                "--transactions",
                str(tx_path),
                "--output",
                str(output),
                "--timeline-output",
                str(timeline),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        analysis = json.loads(output.read_text(encoding="utf-8"))
        jsonschema.validate(analysis, json.loads(SCHEMA.read_text(encoding="utf-8")))
        self.assertTrue(timeline.read_text(encoding="utf-8").strip())
        self.assertIn("MATCHED", timeline.read_text(encoding="utf-8"))

    def test_invalid_analysis_object_fails_schema(self) -> None:
        if jsonschema is None:
            self.skipTest("jsonschema unavailable")
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({"analysis_name": "diameter-epc"}, schema)

    def test_deterministic_output(self) -> None:
        events, transactions = documents()
        path, tx_path = self.write(events, transactions)
        first = self.base / "first.json"
        second = self.base / "second.json"
        for output in (first, second):
            completed = subprocess.run(
                [sys.executable, str(CLI), "--events", str(path), "--transactions", str(tx_path), "--output", str(output), "--force"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())


if __name__ == "__main__":
    unittest.main()