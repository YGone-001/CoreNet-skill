#!/usr/bin/env python3
"""Standalone tests for the bounded Diameter IMS Cx/Dx application Skill."""

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
CLI = SCRIPTS / "analyze-diameter-ims.py"
SCHEMA = PACKAGE / "schemas" / "diameter-ims-analysis.schema.json"
CORE_EVENTS = PACKAGE / "examples" / "core" / "events.jsonl"
CORE_TRANSACTIONS = PACKAGE / "examples" / "core" / "transactions.json"
sys.path.insert(0, str(SCRIPTS))
import diameter_ims_model as model  # noqa: E402

CAPTURE = "ims-cx-synthetic.pcapng"
VENDOR = 10415


def load_documents():
    events = model.load_jsonl(CORE_EVENTS)
    transactions = model.load_json(CORE_TRANSACTIONS)
    return events, transactions


def analyze_documents(events=None, transactions=None):
    if events is None or transactions is None:
        events, transactions = load_documents()
    return model.analyze(
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


def observation_at(document, frame):
    for item in document["observations"]:
        anchor = item["request"] or item["answer"]
        if anchor["frame_number"] == frame:
            return item
    raise AssertionError(f"no observation anchored at frame {frame}")


def presence(observation, side, code):
    for item in observation[f"{side}_avp_presence"]:
        if item["code"] == code:
            return item
    raise AssertionError(f"no {side} presence for {code}")


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
    result.update({"result_code": code, "result_code_name": name, "result_namespace": "BASE"})
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


def avp(code, name, *, vendor=None, namespace=None, sensitive=False, grouping="NOT_GROUPED", kind="OPAQUE", value=None):
    return {
        "avp_reference": f"diameter-avp:unit:{code}",
        "code": code,
        "namespace": namespace or ("3GPP" if vendor == VENDOR else "BASE"),
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


def event(avps, direction="REQUEST"):
    return {
        "capture_file": CAPTURE,
        "frame_number": 1,
        "frame_time_epoch": "1700000301.0",
        "message_occurrence": 1,
        "command_code": 301,
        "application_id": model.CX_APPLICATION_ID,
        "direction": direction,
        "hop_by_hop_id": 1,
        "end_to_end_id": 2,
        "transport": {},
        "avps": avps,
        "avps_omitted": 0,
        "result": empty_result(),
    }


class DiameterImsFixtureBehaviorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = analyze_documents()

    def test_all_six_command_families_are_observed(self) -> None:
        families = {
            observation["procedure_family"]
            for observation in self.document["observations"]
            if observation["message_status"] == "OBSERVED"
        }
        self.assertEqual(
            families,
            {
                "USER_AUTHORIZATION",
                "SERVER_ASSIGNMENT",
                "LOCATION_INFO",
                "MULTIMEDIA_AUTH",
                "REGISTRATION_TERMINATION",
                "PUSH_PROFILE",
            },
        )
        self.assertEqual(
            self.document["capability"]["supported_commands"],
            [
                "300 UAR/UAA",
                "301 SAR/SAA",
                "302 LIR/LIA",
                "303 MAR/MAA",
                "304 RTR/RTA",
                "305 PPR/PPA",
            ],
        )

    def test_uar_uaa_identity_and_provenance(self) -> None:
        observation = observation_at(self.document, 1)
        self.assertEqual(observation["procedure"], "UAR")
        self.assertEqual(observation["procedure_family"], "USER_AUTHORIZATION")
        self.assertEqual(observation["command_code"], 300)
        self.assertEqual(observation["command_name"], "User-Authorization")
        self.assertEqual(observation["request"]["message_name"], "UAR")
        self.assertEqual(observation["answer"]["message_name"], "UAA")
        self.assertEqual(observation["request"]["frame_number"], 1)
        self.assertEqual(observation["answer"]["frame_number"], 2)
        self.assertEqual(observation["transaction_status"], "MATCHED")
        self.assertEqual(observation["latency_seconds"], "0.100000")
        self.assertEqual(observation["application_result"], "SUCCESS_REPORTED")
        self.assertIn("diameter-tx:ims-cx-synthetic.pcapng:300:1.1", observation["transaction_reference"])

    def test_sar_saa_grouped_structure_and_enumerated_value(self) -> None:
        observation = observation_at(self.document, 5)
        self.assertEqual(observation["procedure_family"], "SERVER_ASSIGNMENT")
        server_assignment = presence(observation, "request", 614)
        self.assertEqual(server_assignment["status"], "PRESENT")
        self.assertEqual(server_assignment["reviewed_values"], ["REGISTRATION"])
        self.assertTrue(server_assignment["value_published"])
        features = presence(observation, "request", 628)
        self.assertTrue(features["structure_proven"])
        self.assertEqual(
            {child["code"] for child in features["children"]},
            {266, 629, 630},
        )
        self.assertEqual(presence(observation, "answer", 606)["status"], "PRESENT_REDACTED")

    def test_mar_maa_authentication_presence_and_repetition(self) -> None:
        observation = observation_at(self.document, 3)
        self.assertEqual(observation["procedure_family"], "MULTIMEDIA_AUTH")
        self.assertEqual(presence(observation, "request", 607)["status"], "PRESENT")
        auth_item = presence(observation, "request", 612)
        self.assertTrue(auth_item["structure_proven"])
        request_children = {child["code"]: child for child in auth_item["children"]}
        self.assertTrue(request_children[609]["sensitive"])
        self.assertFalse(request_children[609]["value_published"])
        answer_item = presence(observation, "answer", 612)
        answer_children = {child["code"]: child for child in answer_item["children"]}
        self.assertEqual(answer_children[609]["occurrence_count"], 2)
        self.assertFalse(answer_children[610]["value_published"])

    def test_rtr_rta_reason_names(self) -> None:
        observation = observation_at(self.document, 9)
        self.assertEqual(observation["procedure_family"], "REGISTRATION_TERMINATION")
        reason = presence(observation, "request", 615)
        self.assertTrue(reason["structure_proven"])
        children = {child["code"]: child for child in reason["children"]}
        self.assertEqual(children[616]["reviewed_values"], ["PERMANENT_TERMINATION"])
        self.assertTrue(children[617]["sensitive"])
        self.assertFalse(children[617]["value_published"])

    def test_ppr_ppa_missing_grouped_structure_is_not_inferred(self) -> None:
        observation = observation_at(self.document, 11)
        features = presence(observation, "request", 628)
        self.assertEqual(features["status"], "PRESENT_STRUCTURE_ONLY")
        self.assertFalse(features["structure_proven"])
        self.assertEqual(features["children"], [])
        self.assertTrue(
            any("grouped AVP" in limitation for limitation in observation["limitations"])
        )

    def test_open_request_has_no_answer_or_application_result(self) -> None:
        observation = observation_at(self.document, 13)
        self.assertEqual(observation["transaction_status"], "OPEN_REQUEST")
        self.assertIsNone(observation["answer"])
        self.assertIsNone(observation["latency_seconds"])
        self.assertEqual(observation["application_result"], "NOT_APPLICABLE")

    def test_response_only_has_no_request(self) -> None:
        observation = observation_at(self.document, 14)
        self.assertEqual(observation["transaction_status"], "RESPONSE_ONLY")
        self.assertIsNone(observation["request"])
        self.assertIsNone(observation["latency_seconds"])
        self.assertEqual(observation["application_result"], "FAILURE_REPORTED")
        self.assertEqual(
            observation["result"]["experimental_result_code_name"],
            "DIAMETER_ERROR_USER_UNKNOWN",
        )

    def test_ambiguous_transaction_retains_candidates(self) -> None:
        observation = observation_at(self.document, 17)
        self.assertEqual(observation["transaction_status"], "AMBIGUOUS")
        self.assertIsNone(observation["request"])
        self.assertEqual(len(observation["response_candidates"]), 2)
        self.assertIsNone(observation["latency_seconds"])

    def test_unsupported_command_keeps_numeric_identity(self) -> None:
        observation = observation_at(self.document, 18)
        self.assertEqual(observation["message_status"], "KNOWN_UNSUPPORTED")
        self.assertEqual(observation["command_code"], 306)
        self.assertIsNone(observation["command_name"])
        self.assertIsNone(observation["procedure"])
        self.assertEqual(observation["request_avp_presence"], [])
        self.assertEqual(observation["answer_avp_presence"], [])

    def test_wrong_application_is_conflicting_and_uninterpreted(self) -> None:
        observation = observation_at(self.document, 20)
        self.assertEqual(observation["message_status"], "CONFLICTING")
        self.assertEqual(observation["command_code"], 301)
        self.assertEqual(observation["request"]["application_id"], 16777251)
        self.assertIsNone(observation["command_name"])
        self.assertEqual(observation["request_avp_presence"], [])
        self.assertEqual(observation["application_result"], "NOT_APPLICABLE")

    def test_non_cx_transaction_is_inventoried_not_interpreted(self) -> None:
        scopes = {
            (item["application_id"], item["command_code"], item["scope"])
            for item in self.document["command_inventory"]
        }
        self.assertIn((16777251, 318, "NON_CX_APPLICATION"), scopes)
        self.assertIn((16777251, 301, "CONFLICTING_APPLICATION"), scopes)
        self.assertNotIn(318, {item["command_code"] for item in self.document["observations"]})

    def test_interface_identity_is_unproved(self) -> None:
        self.assertEqual(self.document["capability"]["interface_identity"], "UNPROVED")
        self.assertEqual(self.document["capability"]["interface_identity_basis"], [])
        self.assertEqual(self.document["capability"]["application_id"], 16777216)
        self.assertEqual(self.document["capability"]["application_name"], "Cx/Dx")

    def test_completeness_counts(self) -> None:
        completeness = self.document["completeness"]
        self.assertEqual(completeness["observation_count"], 13)
        self.assertEqual(completeness["observations_omitted"], 0)
        self.assertEqual(completeness["cx_event_count"], 22)
        self.assertEqual(completeness["cx_transaction_count"], 12)
        self.assertEqual(completeness["events_with_avp_omissions"], 1)
        self.assertEqual(completeness["truncated_observations"], 1)
        self.assertEqual(completeness["unsupported_observations"], 1)
        self.assertEqual(completeness["conflicting_observations"], 1)
        self.assertEqual(completeness["observations_with_unproven_grouping"], 1)

    def test_analysis_version_is_corrected(self) -> None:
        self.assertEqual(self.document["analysis_version"], "1.1.0")

    def test_no_ims_registration_or_call_verdict(self) -> None:
        text = json.dumps(self.document) + model.render_timeline(self.document)
        for token in (
            "ims_registered",
            "registration_success",
            "registration_failure",
            "hss_authorized",
            "authentication_success",
            "call_success",
            "media_delivered",
            "root_cause",
        ):
            self.assertNotIn(token, text)


class DiameterImsCommandIdentityTest(unittest.TestCase):
    def test_unknown_command_code_keeps_numeric_identity(self) -> None:
        record = event([avp(263, "Session-Id")])
        record["command_code"] = 999
        reference = {
            "frame_number": 1,
            "message_occurrence": 1,
            "frame_time_epoch": record["frame_time_epoch"],
            "command_code": 999,
            "command_name": None,
            "application_id": model.CX_APPLICATION_ID,
            "direction": "REQUEST",
            "hop_by_hop_id": 1,
            "end_to_end_id": 2,
            "source_endpoint": "10.0.0.1:40000",
            "destination_endpoint": "10.0.0.2:3868",
        }
        transaction = {
            "transaction_reference": "diameter-tx:unit:999:1.1",
            "command_code": 999,
            "command_name": None,
            "command_scope": "APPLICATION_OR_UNKNOWN",
            "application_id": model.CX_APPLICATION_ID,
            "application_semantics": "UNSUPPORTED",
            "transport_association_reference": "diameter-assoc:unit:sctp-assoc-0",
            "request": reference,
            "answer": None,
            "response_candidates": [],
            "correlation_status": "OPEN_REQUEST",
            "correlation_strength": "NONE",
            "correlation_basis": [],
            "latency_seconds": None,
            "result_code": None,
            "result_code_name": None,
            "result_namespace": None,
            "experimental_result_code": None,
            "experimental_vendor_id": None,
            "limitations": [],
        }
        document = analyze_documents(
            [record],
            {"protocol": "Diameter", "capture_files": [CAPTURE], "transactions": [transaction]},
        )
        observation = document["observations"][0]
        self.assertEqual(observation["message_status"], "KNOWN_UNSUPPORTED")
        self.assertEqual(observation["command_code"], 999)
        self.assertIsNone(observation["command_name"])
        self.assertIsNone(observation["procedure"])
        self.assertEqual(observation["request_avp_presence"], [])
        self.assertEqual(
            {item["scope"] for item in document["command_inventory"]},
            {"KNOWN_UNSUPPORTED"},
        )


class DiameterImsResultNamespaceTest(unittest.TestCase):
    def answer(self, result):
        return {"result": result}

    def test_base_5001_is_avp_unsupported_not_user_unknown(self) -> None:
        classified = model.classify_result(
            self.answer(base_result(5001, "DIAMETER_AVP_UNSUPPORTED"))
        )
        self.assertEqual(classified["namespace_status"], "BASE_RFC6733")
        self.assertEqual(classified["base_result_code_name"], "DIAMETER_AVP_UNSUPPORTED")
        self.assertEqual(classified["application_result"], "FAILURE_REPORTED")
        self.assertIsNone(classified["experimental_result_code_name"])

    def test_3gpp_experimental_5001_is_user_unknown(self) -> None:
        classified = model.classify_result(self.answer(experimental_result(5001, VENDOR)))
        self.assertEqual(classified["namespace_status"], "3GPP_TS_29_229_EXPERIMENTAL")
        self.assertEqual(classified["experimental_result_code_name"], "DIAMETER_ERROR_USER_UNKNOWN")

    def test_unknown_vendor_5001_has_no_3gpp_semantics(self) -> None:
        classified = model.classify_result(self.answer(experimental_result(5001, 9999)))
        self.assertEqual(classified["namespace_status"], "UNKNOWN_VENDOR_EXPERIMENTAL")
        self.assertIsNone(classified["experimental_result_code_name"])
        self.assertEqual(classified["application_result"], "UNRESOLVED")

    def test_missing_vendor_5001_has_no_3gpp_semantics(self) -> None:
        classified = model.classify_result(self.answer(experimental_result(5001, None)))
        self.assertEqual(classified["namespace_status"], "UNKNOWN_VENDOR_EXPERIMENTAL")
        self.assertIsNone(classified["experimental_result_code_name"])

    def test_unknown_3gpp_code_keeps_numeric_only(self) -> None:
        classified = model.classify_result(self.answer(experimental_result(5999, VENDOR)))
        self.assertEqual(classified["namespace_status"], "3GPP_TS_29_229_EXPERIMENTAL")
        self.assertEqual(classified["experimental_result_code"], 5999)
        self.assertIsNone(classified["experimental_result_code_name"])
        self.assertEqual(classified["application_result"], "UNRESOLVED")

    def test_both_namespaces_are_conflicting(self) -> None:
        result = base_result(2001, "DIAMETER_SUCCESS")
        result.update(
            {
                "experimental_result_present": True,
                "experimental_result_code": 5001,
                "experimental_vendor_id": VENDOR,
            }
        )
        classified = model.classify_result(self.answer(result))
        self.assertEqual(classified["core_result_status"], "CONFLICTING")
        self.assertEqual(classified["namespace_status"], "CONFLICTING")
        self.assertEqual(classified["application_result"], "UNRESOLVED")
        self.assertIsNone(classified["base_result_code"])
        self.assertIsNone(classified["experimental_result_code"])

    def test_duplicate_base_results_are_unresolved(self) -> None:
        result = empty_result()
        result.update(
            {
                "result_status": "DUPLICATE",
                "base_result_codes": [
                    {"code": 2001, "name": "DIAMETER_SUCCESS", "avp_reference": None},
                    {"code": 5001, "name": "DIAMETER_AVP_UNSUPPORTED", "avp_reference": None},
                ],
                "experimental_results": [],
            }
        )
        classified = model.classify_result(self.answer(result))
        self.assertEqual(classified["core_result_status"], "DUPLICATE")
        self.assertEqual(classified["application_result"], "UNRESOLVED")

    def test_missing_result_is_unresolved_not_success(self) -> None:
        classified = model.classify_result(self.answer(empty_result()))
        self.assertEqual(classified["core_result_status"], "MISSING")
        self.assertEqual(classified["application_result"], "UNRESOLVED")

    def test_no_answer_is_not_applicable(self) -> None:
        classified = model.classify_result(None)
        self.assertEqual(classified["application_result"], "NOT_APPLICABLE")
        self.assertEqual(classified["core_result_status"], "MISSING")

    def test_fixture_conflicting_result_is_unresolved(self) -> None:
        document = analyze_documents()
        observation = observation_at(document, 22)
        self.assertEqual(observation["result"]["namespace_status"], "CONFLICTING")
        self.assertEqual(observation["application_result"], "UNRESOLVED")
        self.assertEqual(len(observation["result"]["base_results"]), 1)
        self.assertEqual(len(observation["result"]["experimental_results"]), 1)

    def test_cx_success_results_2001_to_2004(self) -> None:
        expected = {
            2001: "DIAMETER_FIRST_REGISTRATION",
            2002: "DIAMETER_SUBSEQUENT_REGISTRATION",
            2003: "DIAMETER_UNREGISTERED_SERVICE",
            2004: "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED",
        }
        for code, name in expected.items():
            classified = model.classify_result(self.answer(experimental_result(code, VENDOR)))
            self.assertEqual(classified["namespace_status"], "3GPP_TS_29_229_EXPERIMENTAL")
            self.assertEqual(classified["application_result"], "SUCCESS_REPORTED")
            self.assertEqual(classified["experimental_result_code"], code)
            self.assertEqual(classified["experimental_result_code_name"], name)
            self.assertEqual(classified["experimental_vendor_id"], VENDOR)
            self.assertIsNone(classified["base_result_code"])
            self.assertIsNone(classified["base_result_code_name"])

    def test_base_2001_and_2002_remain_base_success(self) -> None:
        for code in (2001, 2002):
            classified = model.classify_result(self.answer(base_result(code, "DIAMETER_SUCCESS")))
            self.assertEqual(classified["namespace_status"], "BASE_RFC6733")
            self.assertEqual(classified["application_result"], "SUCCESS_REPORTED")
            self.assertEqual(classified["base_result_code"], code)
            self.assertIsNone(classified["experimental_result_code_name"])

    def test_experimental_2001_missing_vendor_is_numeric_only(self) -> None:
        classified = model.classify_result(self.answer(experimental_result(2001, None)))
        self.assertEqual(classified["namespace_status"], "UNKNOWN_VENDOR_EXPERIMENTAL")
        self.assertEqual(classified["application_result"], "UNRESOLVED")
        self.assertEqual(classified["experimental_result_code"], 2001)
        self.assertIsNone(classified["experimental_result_code_name"])

    def test_experimental_2001_wrong_vendor_is_numeric_only(self) -> None:
        classified = model.classify_result(self.answer(experimental_result(2001, 9999)))
        self.assertEqual(classified["namespace_status"], "UNKNOWN_VENDOR_EXPERIMENTAL")
        self.assertEqual(classified["application_result"], "UNRESOLVED")
        self.assertIsNone(classified["experimental_result_code_name"])

    def test_experimental_2002_wrong_vendor_is_numeric_only(self) -> None:
        classified = model.classify_result(self.answer(experimental_result(2002, 9999)))
        self.assertEqual(classified["namespace_status"], "UNKNOWN_VENDOR_EXPERIMENTAL")
        self.assertEqual(classified["application_result"], "UNRESOLVED")
        self.assertIsNone(classified["experimental_result_code_name"])

    def test_reviewed_permanent_failure_results(self) -> None:
        expected = {
            5001: "DIAMETER_ERROR_USER_UNKNOWN",
            5002: "DIAMETER_ERROR_IDENTITIES_DONT_MATCH",
            5003: "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED",
            5004: "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
            5005: "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED",
            5006: "DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED",
            5007: "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE",
            5008: "DIAMETER_ERROR_TOO_MUCH_DATA",
            5009: "DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA",
            5011: "DIAMETER_ERROR_FEATURE_UNSUPPORTED",
            5012: "DIAMETER_ERROR_SERVING_NODE_FEATURE_UNSUPPORTED",
        }
        for code, name in expected.items():
            classified = model.classify_result(self.answer(experimental_result(code, VENDOR)))
            self.assertEqual(classified["namespace_status"], "3GPP_TS_29_229_EXPERIMENTAL")
            self.assertEqual(classified["application_result"], "FAILURE_REPORTED")
            self.assertEqual(classified["experimental_result_code"], code)
            self.assertEqual(classified["experimental_result_code_name"], name)

    def test_5010_is_unassigned_void(self) -> None:
        classified = model.classify_result(self.answer(experimental_result(5010, VENDOR)))
        self.assertEqual(classified["namespace_status"], "3GPP_TS_29_229_EXPERIMENTAL")
        self.assertEqual(classified["application_result"], "UNRESOLVED")
        self.assertEqual(classified["experimental_result_code"], 5010)
        self.assertIsNone(classified["experimental_result_code_name"])
        self.assertTrue(
            any("Void" in limitation and "6.2.2.10" in limitation for limitation in classified["limitations"])
        )
        self.assertNotIn(5010, model.THREEGPP_CX_FAILURE_RESULT_NAMES)
        self.assertNotIn(5010, model.THREEGPP_CX_RESULT_NAMES)

    def test_2005_is_void(self) -> None:
        classified = model.classify_result(self.answer(experimental_result(2005, VENDOR)))
        self.assertEqual(classified["application_result"], "UNRESOLVED")
        self.assertEqual(classified["experimental_result_code"], 2005)
        self.assertIsNone(classified["experimental_result_code_name"])
        self.assertTrue(any("6.2.1.5" in limitation for limitation in classified["limitations"]))

    def test_reserved_and_unknown_codes_keep_numeric_identity(self) -> None:
        for code in (5013, 5020):
            classified = model.classify_result(self.answer(experimental_result(code, VENDOR)))
            self.assertEqual(classified["application_result"], "UNRESOLVED")
            self.assertEqual(classified["experimental_result_code"], code)
            self.assertIsNone(classified["experimental_result_code_name"])
            self.assertTrue(any("reserved" in limitation for limitation in classified["limitations"]))
        classified = model.classify_result(self.answer(experimental_result(5999, VENDOR)))
        self.assertEqual(classified["application_result"], "UNRESOLVED")
        self.assertEqual(classified["experimental_result_code"], 5999)
        self.assertIsNone(classified["experimental_result_code_name"])

    def test_registry_reserved_ranges_are_separate(self) -> None:
        success = set(model.THREEGPP_CX_RESERVED_SUCCESS_RESULT_CODES)
        permanent = set(model.THREEGPP_CX_RESERVED_PERMANENT_FAILURE_RESULT_CODES)
        other = set(model.THREEGPP_OTHER_SPEC_RESERVED_RESULT_CODES)
        self.assertEqual(success, set(range(2006, 2021)))
        self.assertEqual(permanent, set(range(5013, 5021)))
        self.assertEqual(other, set(range(5021, 5041)))
        self.assertFalse(success & permanent)
        self.assertFalse(success & other)
        self.assertFalse(permanent & other)
        self.assertEqual(
            model.THREEGPP_CX_RESERVED_RESULT_CODES,
            model.THREEGPP_CX_RESERVED_PERMANENT_FAILURE_RESULT_CODES,
        )

    def test_reserved_success_range_2006_to_2020(self) -> None:
        for code in (2006, 2020):
            classified = model.classify_result(self.answer(experimental_result(code, VENDOR)))
            self.assertEqual(classified["application_result"], "UNRESOLVED")
            self.assertEqual(classified["experimental_result_code"], code)
            self.assertIsNone(classified["experimental_result_code_name"])
            self.assertTrue(
                any(
                    "8.1.2" in limitation and "2006-2020" in limitation
                    for limitation in classified["limitations"]
                )
            )
        boundary = model.classify_result(self.answer(experimental_result(2021, VENDOR)))
        self.assertEqual(boundary["application_result"], "UNRESOLVED")
        self.assertEqual(boundary["experimental_result_code"], 2021)
        self.assertIsNone(boundary["experimental_result_code_name"])
        self.assertFalse(any("2006-2020" in item for item in boundary["limitations"]))

    def test_reserved_permanent_failure_range_5013_to_5020(self) -> None:
        for code in (5013, 5020):
            classified = model.classify_result(self.answer(experimental_result(code, VENDOR)))
            self.assertEqual(classified["application_result"], "UNRESOLVED")
            self.assertEqual(classified["experimental_result_code"], code)
            self.assertIsNone(classified["experimental_result_code_name"])
            self.assertTrue(
                any(
                    "8.1.4" in limitation and "5013-5020" in limitation
                    for limitation in classified["limitations"]
                )
            )

    def test_other_specification_reserved_range_is_not_cx_semantics(self) -> None:
        for code in (5021, 5040):
            classified = model.classify_result(self.answer(experimental_result(code, VENDOR)))
            self.assertEqual(classified["application_result"], "UNRESOLVED")
            self.assertEqual(classified["experimental_result_code"], code)
            self.assertIsNone(classified["experimental_result_code_name"])
            self.assertTrue(
                any("TS 32.299" in limitation for limitation in classified["limitations"])
            )
            self.assertNotIn(code, model.THREEGPP_CX_RESERVED_PERMANENT_FAILURE_RESULT_CODES)

    def test_2005_reconciles_void_and_deprecated(self) -> None:
        classified = model.classify_result(self.answer(experimental_result(2005, VENDOR)))
        text = " ".join(classified["limitations"])
        self.assertIn("6.2.1.5", text)
        self.assertIn("Void", text)
        self.assertIn("8.1.2", text)
        self.assertIn("Deprecated", text)
        self.assertEqual(classified["application_result"], "UNRESOLVED")
        self.assertIsNone(classified["experimental_result_code_name"])
        self.assertNotIn(2005, model.THREEGPP_CX_SUCCESS_RESULT_NAMES)

    def test_5010_reconciles_void_and_unassigned(self) -> None:
        classified = model.classify_result(self.answer(experimental_result(5010, VENDOR)))
        text = " ".join(classified["limitations"])
        self.assertIn("6.2.2.10", text)
        self.assertIn("Void", text)
        self.assertIn("8.1.4", text)
        self.assertIn("unassigned", text)
        self.assertEqual(classified["application_result"], "UNRESOLVED")
        self.assertIsNone(classified["experimental_result_code_name"])

    def test_success_and_failure_result_maps_do_not_overlap(self) -> None:
        self.assertFalse(
            set(model.THREEGPP_CX_SUCCESS_RESULT_NAMES)
            & set(model.THREEGPP_CX_FAILURE_RESULT_NAMES)
        )
        self.assertEqual(set(model.THREEGPP_CX_SUCCESS_RESULT_NAMES), {2001, 2002, 2003, 2004})
        self.assertEqual(
            set(model.THREEGPP_CX_FAILURE_RESULT_NAMES),
            {5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5011, 5012},
        )


class DiameterImsAvpEvidenceTest(unittest.TestCase):
    def test_present_grouped_avp_requires_proven_children(self) -> None:
        item = model._presence(event([avp(603, "Server-Capabilities", vendor=VENDOR, grouping="NOT_DECODED")]), 603, 0)
        self.assertEqual(item["status"], "PRESENT_STRUCTURE_ONLY")
        self.assertFalse(item["structure_proven"])
        self.assertEqual(item["children"], [])

    def test_proven_grouped_avp_preserves_direct_children(self) -> None:
        parent = avp(612, "3GPP-SIP-Auth-Data-Item", vendor=VENDOR, grouping="DECODED", kind="GROUPED")
        parent["children"] = [
            avp(613, "3GPP-SIP-Item-Number", vendor=VENDOR, kind="INTEGER", value=1),
            avp(609, "3GPP-SIP-Authenticate", vendor=VENDOR, sensitive=True, kind="SENSITIVE_REDACTED"),
        ]
        item = model._presence(event([parent]), 612, 0)
        self.assertTrue(item["structure_proven"])
        self.assertEqual({child["code"] for child in item["children"]}, {613, 609})

    def test_repeated_occurrences_are_counted(self) -> None:
        record = event(
            [
                avp(604, "Mandatory-Capability", vendor=VENDOR, kind="INTEGER", value=1),
                avp(604, "Mandatory-Capability", vendor=VENDOR, kind="INTEGER", value=2),
            ]
        )
        item = model._presence(record, 604, 0)
        self.assertEqual(item["occurrence_count"], 2)
        self.assertFalse(item["value_published"])

    def test_namespace_mismatch_is_not_matched(self) -> None:
        record = event([avp(601, "Public-Identity", namespace="BASE")])
        item = model._presence(record, 601, 0)
        self.assertEqual(item["status"], "NOT_OBSERVED")
        record = event([avp(263, "Session-Id", vendor=VENDOR)])
        item = model._presence(record, 263, 0)
        self.assertEqual(item["status"], "NOT_OBSERVED")

    def test_truncated_subset_is_not_proven_absent(self) -> None:
        record = event([])
        record["avps_omitted"] = 5
        item = model._presence(record, 601, 5)
        self.assertEqual(item["status"], "NOT_OBSERVED_IN_PUBLISHED_SUBSET")

    def test_protected_avp_never_publishes_value(self) -> None:
        record = event([avp(601, "Public-Identity", vendor=VENDOR, kind="STRING", value="PRIVATE-IMPU")])
        item = model._presence(record, 601, 0)
        self.assertTrue(item["sensitive"])
        self.assertEqual(item["reviewed_values"], [])
        self.assertFalse(item["value_published"])

    def test_reviewed_enumeration_requires_known_value(self) -> None:
        record = event([avp(614, "Server-Assignment-Type", vendor=VENDOR, kind="INTEGER", value=99)])
        item = model._presence(record, 614, 0)
        self.assertEqual(item["reviewed_values"], [])
        self.assertFalse(item["value_published"])

    def test_unknown_reviewed_code_has_no_name(self) -> None:
        record = event([avp(999, "Unreviewed", vendor=VENDOR)])
        self.assertNotIn(999, model.AVP_NAMES)
        self.assertIsNone(model.AVP_NAMES.get(999))

    def test_canonical_names_reconcile_decoder_aliases(self) -> None:
        expected = {
            606: ("Cx-User-Data", "User-Data"),
            607: ("3GPP-SIP-Number-Auth-Items", "SIP-Number-Auth-Items"),
            608: ("3GPP-SIP-Authentication-Scheme", "SIP-Authentication-Scheme"),
            609: ("3GPP-SIP-Authenticate", "SIP-Authenticate"),
            610: ("3GPP-SIP-Authorization", "SIP-Authorization"),
            612: ("3GPP-SIP-Auth-Data-Item", "SIP-Auth-Data-Item"),
            613: ("3GPP-SIP-Item-Number", "SIP-Item-Number"),
        }
        for code, (decoder_name, canonical_name) in expected.items():
            record = event([avp(code, decoder_name, vendor=VENDOR)])
            item = model._presence(record, code, 0)
            self.assertEqual(item["name"], decoder_name)
            self.assertEqual(item["canonical_name"], canonical_name)

    def test_grouped_child_carries_canonical_name(self) -> None:
        parent = avp(612, "3GPP-SIP-Auth-Data-Item", vendor=VENDOR, grouping="DECODED", kind="GROUPED")
        parent["children"] = [avp(613, "3GPP-SIP-Item-Number", vendor=VENDOR, kind="INTEGER", value=1)]
        item = model._presence(event([parent]), 612, 0)
        self.assertEqual(item["children"][0]["name"], "3GPP-SIP-Item-Number")
        self.assertEqual(item["children"][0]["canonical_name"], "SIP-Item-Number")

    def test_implemented_avps_expose_both_names(self) -> None:
        document = analyze_documents()
        for observation in document["observations"]:
            for item in observation["request_avp_presence"] + observation["answer_avp_presence"]:
                self.assertIn("canonical_name", item)
                self.assertTrue(item["canonical_name"])


class DiameterImsPrivacyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = analyze_documents()
        cls.text = json.dumps(cls.document) + model.render_timeline(cls.document)

    def test_no_raw_uri_or_host_value_is_published(self) -> None:
        for secret in (
            "client.example",
            "scscf.example",
            "scscf-scscf.example",
            "visited.example",
            "Digest",
            "PRIVATE",
            "sip:",
        ):
            self.assertNotIn(secret, self.text)

    def test_protected_avps_never_publish_a_value(self) -> None:
        for observation in self.document["observations"]:
            for item in observation["request_avp_presence"] + observation["answer_avp_presence"]:
                if item["code"] in model.PROTECTED_CODES:
                    self.assertFalse(item["value_published"])
                    self.assertEqual(item["reviewed_values"], [])
                for child in item["children"]:
                    if child["code"] in model.PROTECTED_CODES:
                        self.assertFalse(child["value_published"])
                        self.assertEqual(child["reviewed_values"], [])

    def test_no_raw_avp_value_field_is_published(self) -> None:
        for observation in self.document["observations"]:
            for item in observation["request_avp_presence"] + observation["answer_avp_presence"]:
                self.assertNotIn("value", item)
                for child in item["children"]:
                    self.assertNotIn("value", child)

    def test_cli_output_has_no_sensitive_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "analysis.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "--events",
                    str(CORE_EVENTS),
                    "--transactions",
                    str(CORE_TRANSACTIONS),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            text = output.read_text(encoding="utf-8") + completed.stdout + completed.stderr
            for secret in ("client.example", "scscf.example", "visited.example", "PRIVATE", "Digest"):
                self.assertNotIn(secret, text)


class DiameterImsInputValidationTest(unittest.TestCase):
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

    def run_cli(self, events_path, transactions_path, output_name="out.json"):
        return subprocess.run(
            [
                sys.executable,
                str(CLI),
                "--events",
                str(events_path),
                "--transactions",
                str(transactions_path),
                "--output",
                str(self.base / output_name),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_capture_identity_mismatch_is_rejected(self) -> None:
        events, transactions = load_documents()
        events[1]["capture_file"] = "other.pcapng"
        path, tx_path = self.write(events, transactions)
        completed = self.run_cli(path, tx_path)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("capture", completed.stderr)

    def test_missing_event_reference_is_rejected(self) -> None:
        events, transactions = load_documents()
        transactions["transactions"][0]["answer"]["frame_number"] = 999
        path, tx_path = self.write(events, transactions)
        completed = self.run_cli(path, tx_path)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("does not resolve", completed.stderr)

    def test_missing_event_field_is_rejected(self) -> None:
        events, transactions = load_documents()
        del events[0]["application_id"]
        path, tx_path = self.write(events, transactions)
        completed = self.run_cli(path, tx_path)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("missing required event field", completed.stderr)

    def test_malformed_result_structure_is_rejected(self) -> None:
        events, transactions = load_documents()
        events[0]["result"] = []
        path, tx_path = self.write(events, transactions)
        completed = self.run_cli(path, tx_path)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("result must be an object", completed.stderr)

    def test_inconsistent_matched_transaction_is_rejected(self) -> None:
        events, transactions = load_documents()
        transactions["transactions"][0]["answer"]["end_to_end_id"] = 999
        path, tx_path = self.write(events, transactions)
        completed = self.run_cli(path, tx_path)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("disagrees", completed.stderr)

    def test_duplicate_event_identity_is_rejected(self) -> None:
        events, transactions = load_documents()
        events.append(dict(events[0]))
        path, tx_path = self.write(events, transactions)
        completed = self.run_cli(path, tx_path)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("duplicate event", completed.stderr)

    def test_duplicate_transaction_reference_is_rejected(self) -> None:
        events, transactions = load_documents()
        transactions["transactions"].append(dict(transactions["transactions"][0]))
        path, tx_path = self.write(events, transactions)
        completed = self.run_cli(path, tx_path)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("duplicate transaction", completed.stderr)

    def test_invalid_transaction_reference_is_rejected(self) -> None:
        events, transactions = load_documents()
        transactions["transactions"][0]["transaction_reference"] = "invalid"
        path, tx_path = self.write(events, transactions)
        completed = self.run_cli(path, tx_path)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("transaction_reference", completed.stderr)

    def test_missing_core_transaction_coverage_is_rejected(self) -> None:
        events, transactions = load_documents()
        transactions["transactions"] = [
            item
            for item in transactions["transactions"]
            if item["transaction_reference"] != "diameter-tx:ims-cx-synthetic.pcapng:300:1.1"
        ]
        path, tx_path = self.write(events, transactions)
        completed = self.run_cli(path, tx_path)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("do not cover", completed.stderr)

    def test_invalid_json_input_is_rejected(self) -> None:
        events_path = self.base / "events.jsonl"
        transactions_path = self.base / "transactions.json"
        events_path.write_text("{not-json}\n", encoding="utf-8")
        transactions_path.write_text("{}", encoding="utf-8")
        completed = self.run_cli(events_path, transactions_path)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("not valid JSON", completed.stderr)

    def test_existing_output_requires_force(self) -> None:
        events, transactions = load_documents()
        path, tx_path = self.write(events, transactions)
        output = self.base / "out.json"
        output.write_text("existing", encoding="utf-8")
        completed = self.run_cli(path, tx_path)
        self.assertEqual(completed.returncode, 6)
        self.assertIn("use --force", completed.stderr)

    def test_no_cx_input_returns_no_observations(self) -> None:
        events, transactions = load_documents()
        non_cx_events = [item for item in events if item["application_id"] != model.CX_APPLICATION_ID]
        non_cx_transactions = {
            "protocol": "Diameter",
            "capture_files": [CAPTURE],
            "transactions": [
                item
                for item in transactions["transactions"]
                if item["application_id"] != model.CX_APPLICATION_ID
                and item["command_code"] not in model.SUPPORTED_COMMAND_CODES
            ],
        }
        path, tx_path = self.write(non_cx_events, non_cx_transactions)
        completed = self.run_cli(path, tx_path)
        self.assertEqual(completed.returncode, 3)
        self.assertFalse((self.base / "out.json").exists())

    def test_cli_output_and_schema_validation(self) -> None:
        if jsonschema is None:
            if os.environ.get("CI"):
                self.fail("jsonschema is required for the Diameter IMS schema gate in CI")
            self.skipTest("jsonschema unavailable")
        events, transactions = load_documents()
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
        self.assertIn("UNPROVED", timeline.read_text(encoding="utf-8"))

    def test_invalid_analysis_object_fails_schema(self) -> None:
        if jsonschema is None:
            self.skipTest("jsonschema unavailable")
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({"analysis_name": "diameter-ims"}, schema)

    def test_deterministic_output(self) -> None:
        events, transactions = load_documents()
        path, tx_path = self.write(events, transactions)
        first = self.base / "first.json"
        second = self.base / "second.json"
        for output in (first, second):
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
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())


if __name__ == "__main__":
    unittest.main()