#!/usr/bin/env python3
"""Behavior tests for GTPv2-C dedicated-bearer control message support."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
EXAMPLES = SKILL / "examples"

IMSI_VALUE = "46002" + "0000000001"
MEI_VALUE = "1122334455" + "667788"
MSISDN_VALUE = "919" + "000001"

sys.path.insert(0, str(SCRIPTS))
import gtpv2_model as model  # noqa: E402


def run(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class DedicatedBearerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.directory = Path(cls._directory.name)
        cls.events_path = cls.directory / "bearer-events.jsonl"
        cls.trace_path = cls.directory / "bearer-trace.jsonl"
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "pdml" / "bearer-control.pdml"),
            "--output",
            str(cls.events_path),
            "--trace-output",
            str(cls.trace_path),
            "--force",
        )
        if result.returncode != 0:
            raise AssertionError(f"bearer extraction failed: {result.stderr}")
        cls.events = load_jsonl(cls.events_path)
        cls.by_frame = {event["frame_number"]: event for event in cls.events}
        cls.transactions_path = cls.directory / "bearer-transactions.json"
        correlated = run(
            "correlate-gtpv2.py",
            str(cls.events_path),
            "--output",
            str(cls.transactions_path),
            "--force",
        )
        if correlated.returncode != 0:
            raise AssertionError(f"bearer correlation failed: {correlated.stderr}")
        cls.transactions = load_json(cls.transactions_path)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def correlate_custom(self, events: list[dict], name: str) -> dict:
        path = self.directory / f"{name}.jsonl"
        path.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )
        output = self.directory / f"{name}-transactions.json"
        result = run("correlate-gtpv2.py", str(path), "--output", str(output), "--force")
        self.assertEqual(result.returncode, 0, result.stderr)
        return load_json(output)

    def test_create_bearer_request_is_supported(self) -> None:
        event = self.by_frame[1]
        self.assertEqual(event["message_type"], "Create Bearer Request")
        self.assertEqual(event["message_type_code"], 95)
        self.assertEqual(event["procedure_family"], "create-bearer")
        self.assertEqual(event["message_family"], "create-bearer")
        self.assertEqual(event["support_status"], "SUPPORTED")

    def test_create_bearer_response_is_supported(self) -> None:
        event = self.by_frame[2]
        self.assertEqual(event["message_type"], "Create Bearer Response")
        self.assertEqual(event["message_type_code"], 96)
        self.assertEqual(event["procedure_family"], "create-bearer")
        self.assertEqual(event["support_status"], "SUPPORTED")

    def test_update_bearer_request_is_supported(self) -> None:
        event = self.by_frame[3]
        self.assertEqual(event["message_type"], "Update Bearer Request")
        self.assertEqual(event["message_type_code"], 97)
        self.assertEqual(event["procedure_family"], "update-bearer")
        self.assertEqual(event["support_status"], "SUPPORTED")

    def test_update_bearer_response_is_supported(self) -> None:
        event = self.by_frame[4]
        self.assertEqual(event["message_type"], "Update Bearer Response")
        self.assertEqual(event["message_type_code"], 98)
        self.assertEqual(event["procedure_family"], "update-bearer")
        self.assertEqual(event["support_status"], "SUPPORTED")

    def test_delete_bearer_request_is_supported(self) -> None:
        event = self.by_frame[5]
        self.assertEqual(event["message_type"], "Delete Bearer Request")
        self.assertEqual(event["message_type_code"], 99)
        self.assertEqual(event["procedure_family"], "delete-bearer")
        self.assertEqual(event["support_status"], "SUPPORTED")

    def test_delete_bearer_response_is_supported(self) -> None:
        event = self.by_frame[6]
        self.assertEqual(event["message_type"], "Delete Bearer Response")
        self.assertEqual(event["message_type_code"], 100)
        self.assertEqual(event["procedure_family"], "delete-bearer")
        self.assertEqual(event["support_status"], "SUPPORTED")

    def test_all_three_request_response_pairs_match(self) -> None:
        self.assertEqual(self.transactions["matched_count"], 3)
        pairs = [
            (item["request"]["message_type_code"], item["response"]["message_type_code"])
            for item in self.transactions["transactions"]
        ]
        self.assertEqual(pairs, [(95, 96), (97, 98), (99, 100)])

    def test_supported_status_and_procedure_family_are_explicit(self) -> None:
        for code, family in (
            (95, "create-bearer"),
            (96, "create-bearer"),
            (97, "update-bearer"),
            (98, "update-bearer"),
            (99, "delete-bearer"),
            (100, "delete-bearer"),
        ):
            name, status, procedure, message_family = model.resolve_message(code)
            self.assertEqual(status, "SUPPORTED")
            self.assertEqual(procedure, family)
            self.assertEqual(message_family, family)
            self.assertIsNotNone(name)

    def test_header_teid_states_remain_distinct(self) -> None:
        self.assertEqual(self.by_frame[1]["header"]["teid_state"], "ZERO")
        self.assertEqual(self.by_frame[2]["header"]["teid_state"], "PRESENT")
        self.assertEqual(self.by_frame[5]["header"]["teid_state"], "ABSENT")
        self.assertIsNone(self.by_frame[5]["header"]["teid"])

    def test_message_and_bearer_cause_remain_separate(self) -> None:
        request = self.by_frame[1]
        response = self.by_frame[2]
        self.assertIsNone(request["message_cause"])
        self.assertEqual(response["message_cause"]["cause_code"], 16)
        self.assertEqual(response["message_cause"]["scope"], "message")
        self.assertEqual(
            [context["cause"]["cause_code"] for context in response["bearer_contexts"]],
            [16, 73],
        )
        self.assertTrue(
            all(context["cause"]["scope"] == "bearer" for context in response["bearer_contexts"])
        )

    def test_bearer_level_cause_is_preserved_per_item(self) -> None:
        contexts = self.by_frame[2]["bearer_contexts"]
        self.assertEqual(contexts[1]["cause"]["cause_code"], 73)
        self.assertEqual(contexts[1]["cause"]["cause_name"], "No resources available")
        self.assertEqual(contexts[1]["cause"]["scope"], "bearer")

    def test_multiple_grouped_bearer_contexts_are_not_flattened(self) -> None:
        contexts = self.by_frame[1]["bearer_contexts"]
        self.assertEqual(len(contexts), 2)
        self.assertEqual([context["item_index"] for context in contexts], [0, 1])
        self.assertEqual([context["ebi"] for context in contexts], [5, 6])

    def test_item_specific_ebi(self) -> None:
        contexts = self.by_frame[2]["bearer_contexts"]
        self.assertEqual([context["ebi"] for context in contexts], [5, 6])

    def test_item_specific_f_teid(self) -> None:
        request_contexts = self.by_frame[1]["bearer_contexts"]
        response_contexts = self.by_frame[2]["bearer_contexts"]
        self.assertEqual([context["f_teids"][0]["teid"] for context in request_contexts], [4369, 8738])
        self.assertEqual([context["f_teids"][0]["teid"] for context in response_contexts], [13107, 17476])
        self.assertTrue(
            all(
                context["f_teids"][0]["scope"] == "bearer"
                for context in request_contexts + response_contexts
            )
        )

    def test_bearer_qos_metadata_is_published(self) -> None:
        qos = self.by_frame[1]["bearer_contexts"][0]["qos"]
        self.assertEqual(qos["source_ie"], "Bearer QoS")
        self.assertEqual(qos["qci"], 9)
        self.assertEqual(qos["priority_level"], 8)
        self.assertEqual(qos["mbr_uplink_kbps"], 100000)
        self.assertEqual(qos["mbr_downlink_kbps"], 200000)
        self.assertEqual(qos["gbr_uplink_kbps"], 0)
        self.assertEqual(qos["gbr_downlink_kbps"], 0)
        self.assertTrue(qos["preemption_capability"])
        self.assertTrue(qos["preemption_vulnerability"])

    def test_missing_optional_qos_metadata_is_not_invented(self) -> None:
        response_context = self.by_frame[2]["bearer_contexts"][0]
        self.assertIsNone(response_context.get("qos"))
        request_context = self.by_frame[1]["bearer_contexts"][0]
        self.assertNotIn("arp_source_ie", request_context["qos"])

    def test_ipv4_and_ipv6_endpoint_evidence(self) -> None:
        ipv4_context = self.by_frame[1]["bearer_contexts"][0]
        ipv6_context = self.by_frame[3]["bearer_contexts"][0]
        self.assertEqual(ipv4_context["f_teids"][0]["ipv4"], "10.0.0.9")
        self.assertFalse(ipv4_context["f_teids"][0]["ipv6_present"])
        self.assertEqual(ipv6_context["f_teids"][0]["ipv6"], "2001:db8::1")
        self.assertFalse(ipv6_context["f_teids"][0]["ipv4_present"])

    def test_nested_ie_grouping_keeps_qos_and_tft_inside_the_context(self) -> None:
        context = self.by_frame[1]["bearer_contexts"][0]
        self.assertNotIn("Bearer QoS", context.get("other_ie_names") or [])
        self.assertNotIn("Bearer TFT", context.get("other_ie_names") or [])
        self.assertTrue(context["tft"]["present"])
        self.assertEqual(context["tft"]["source_ie"], "Bearer TFT")

    def test_retransmission_is_grouped_not_duplicated(self) -> None:
        self.assertEqual(self.transactions["retransmission_count"], 1)
        first = self.transactions["transactions"][0]
        self.assertEqual([item["frame_number"] for item in first["retransmissions"]], [7])
        self.assertEqual(self.transactions["transaction_count"], 3)

    def test_transaction_references_are_deterministic(self) -> None:
        second = self.directory / "bearer-transactions-second.json"
        result = run(
            "correlate-gtpv2.py",
            str(self.events_path),
            "--output",
            str(second),
            "--force",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.transactions_path.read_text(), second.read_text())

    def test_extraction_output_is_deterministic(self) -> None:
        second = self.directory / "bearer-events-second.jsonl"
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "pdml" / "bearer-control.pdml"),
            "--output",
            str(second),
            "--force",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events_path.read_text(), second.read_text())

    def test_trace_event_projection_is_compatible(self) -> None:
        trace = model.project_trace_event(self.by_frame[1])
        self.assertEqual(trace["message_type"], "Create Bearer Request")
        self.assertEqual(trace["procedure"], "create-bearer")
        self.assertEqual(trace["evidence"]["level"], "DERIVED")

    def test_existing_session_control_families_remain_unchanged(self) -> None:
        for code, family in (
            (32, "create-session"),
            (34, "modify-bearer"),
            (36, "delete-session"),
            (170, "release-access-bearers"),
        ):
            _name, status, procedure, message_family = model.resolve_message(code)
            self.assertEqual(status, "SUPPORTED")
            self.assertEqual(procedure, family)
            self.assertEqual(message_family, family)

    def test_open_request_is_not_a_timeout(self) -> None:
        events = [event for event in self.events if event["frame_number"] not in (2, 7)]
        result = self.correlate_custom(events, "bearer-open")
        create = next(item for item in result["transactions"] if item["procedure_family"] == "create-bearer")
        self.assertEqual(create["correlation_status"], "OPEN_REQUEST")
        self.assertIsNone(create["response"])
        self.assertTrue(any("not a proven timeout" in item for item in create["limitations"]))

    def test_response_only_evidence_remains_response_only(self) -> None:
        events = [event for event in self.events if event["frame_number"] in (2, 4, 6)]
        result = self.correlate_custom(events, "bearer-response-only")
        self.assertEqual(result["response_only_count"], 3)
        self.assertTrue(all(item["correlation_status"] == "RESPONSE_ONLY" for item in result["transactions"]))

    def test_ambiguous_response_candidates_are_not_selected(self) -> None:
        events = [event for event in self.events if event["frame_number"] in (1, 2, 7)]
        duplicate = dict(events[1], frame_number=102)
        events.append(duplicate)
        result = self.correlate_custom(events, "bearer-ambiguous")
        create = next(item for item in result["transactions"] if item["procedure_family"] == "create-bearer")
        self.assertEqual(create["correlation_status"], "AMBIGUOUS")
        self.assertIsNone(create["response"])
        self.assertEqual(len(create["response_candidates"]), 2)

    def test_equal_sequence_in_another_capture_does_not_match(self) -> None:
        events = [dict(event) for event in self.events if event["frame_number"] in (1, 2, 7)]
        events[1]["capture_file"] = "other.pcap"
        result = self.correlate_custom(events, "bearer-cross-capture")
        create = next(item for item in result["transactions"] if item["procedure_family"] == "create-bearer")
        self.assertEqual(create["correlation_status"], "OPEN_REQUEST")

    def test_equal_sequence_on_different_endpoints_does_not_match(self) -> None:
        events = [dict(event) for event in self.events if event["frame_number"] in (1, 2, 7)]
        events[1]["source"] = {"address": "10.9.9.9", "port": 2123}
        result = self.correlate_custom(events, "bearer-different-endpoints")
        create = next(item for item in result["transactions"] if item["procedure_family"] == "create-bearer")
        self.assertEqual(create["correlation_status"], "OPEN_REQUEST")

    def test_wrong_response_message_type_does_not_match(self) -> None:
        events = [dict(event) for event in self.events if event["frame_number"] in (1, 2, 7)]
        events[1]["message_type_code"] = 98
        events[1]["message_type"] = "Update Bearer Response"
        result = self.correlate_custom(events, "bearer-wrong-response")
        create = next(item for item in result["transactions"] if item["procedure_family"] == "create-bearer")
        self.assertEqual(create["correlation_status"], "OPEN_REQUEST")

    def test_malformed_grouping_does_not_fabricate_a_bearer_context(self) -> None:
        event = model.normalize_flat_record(
            {
                "frame.number": "1",
                "frame.time_epoch": "1792851200.1",
                "gtpv2.message_type": "95",
                "gtpv2.ebi": "5,6",
            },
            "flat.jsonl",
        )
        self.assertEqual(event["bearer_contexts"], [])
        self.assertEqual(event["unbound_ie_metadata"]["ebi_values"], [5, 6])
        self.assertTrue(any("does not preserve grouped-IE" in item for item in event["extraction_limitations"]))

    def test_missing_ebi_is_published_without_invention(self) -> None:
        target = self.directory / "incomplete-bearer-events.jsonl"
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "pdml" / "multi-bearer-context.pdml"),
            "--output",
            str(target),
            "--force",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        context = load_jsonl(target)[1]["bearer_contexts"][0]
        self.assertIsNone(context["ebi"])
        self.assertEqual(context["f_teids"][0]["teid"], 13107)

    def test_duplicate_ebi_in_flat_input_is_disclosed(self) -> None:
        event = model.normalize_flat_record(
            {
                "frame.number": "1",
                "frame.time_epoch": "1792851200.1",
                "gtpv2.message_type": "95",
                "gtpv2.ebi": "5,5",
            },
            "flat.jsonl",
        )
        self.assertEqual(event["unbound_ie_metadata"]["ebi_values"], [5, 5])
        self.assertTrue(any("duplicate EBI" in item for item in event["extraction_limitations"]))

    def test_multiple_fteds_without_grouping_stay_unbound(self) -> None:
        event = model.normalize_flat_record(
            {
                "frame.number": "1",
                "frame.time_epoch": "1792851200.1",
                "gtpv2.message_type": "95",
                "gtpv2.f_teid_interface_type": "0,1",
                "gtpv2.f_teid_gre_key": "0x1111,0x2222",
            },
            "flat.jsonl",
        )
        self.assertEqual(event["bearer_contexts"], [])
        self.assertEqual(len(event["unbound_ie_metadata"]["f_teid_values"]), 2)
        self.assertTrue(all(item["scope"] == "unbound" for item in event["f_teids"]))

    def test_flat_input_without_grouped_ie_evidence(self) -> None:
        event = model.normalize_flat_record(
            {
                "frame.number": "1",
                "frame.time_epoch": "1792851200.1",
                "gtpv2.message_type": "97",
                "gtpv2.ebi": "5",
            },
            "flat.jsonl",
        )
        self.assertEqual(event["hierarchy_basis"], "flat_fields")
        self.assertEqual(event["bearer_contexts"], [])
        self.assertIn("does not preserve grouped-IE", event["extraction_limitations"][0])

    def test_unsupported_qos_fields_are_not_invented(self) -> None:
        event = model.normalize_flat_record(
            {
                "frame.number": "1",
                "frame.time_epoch": "1792851200.1",
                "gtpv2.message_type": "95",
                "gtpv2.bearer_qos_mbr_up": "1000",
            },
            "flat.jsonl",
        )
        qos = event["unbound_ie_metadata"]["qos"]
        self.assertEqual(qos["mbr_uplink_kbps"], 1000)
        self.assertNotIn("qci", qos)
        self.assertNotIn("gbr_uplink_kbps", qos)

    def test_malformed_qos_value_is_dropped(self) -> None:
        event = model.normalize_flat_record(
            {
                "frame.number": "1",
                "frame.time_epoch": "1792851200.1",
                "gtpv2.message_type": "95",
                "gtpv2.bearer_qos_label_qci": "not-a-number",
                "gtpv2.bearer_qos_mbr_up": "1000",
            },
            "flat.jsonl",
        )
        qos = event["unbound_ie_metadata"]["qos"]
        self.assertNotIn("qci", qos)
        self.assertEqual(qos["mbr_uplink_kbps"], 1000)

    def test_message_level_cause_is_not_promoted_from_bearer_context(self) -> None:
        request = self.by_frame[1]
        self.assertIsNone(request["message_cause"])
        self.assertTrue(all(context["cause"] is None for context in request["bearer_contexts"]))

    def test_bearer_cause_is_not_promoted_to_message_level(self) -> None:
        response = self.by_frame[2]
        self.assertEqual(response["message_cause"]["cause_code"], 16)
        self.assertEqual(response["bearer_contexts"][1]["cause"]["cause_code"], 73)
        self.assertNotEqual(
            response["message_cause"]["cause_code"],
            response["bearer_contexts"][1]["cause"]["cause_code"],
        )

    def test_truncated_source_input_is_rejected(self) -> None:
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "extracted" / "missing-required.jsonl"),
            "--output",
            str(self.directory / "truncated-events.jsonl"),
        )
        self.assertEqual(result.returncode, 5)
        self.assertIn("frame.number is required", result.stderr)

    def test_unknown_message_type_stays_unknown(self) -> None:
        event = model.normalize_flat_record(
            {
                "frame.number": "1",
                "frame.time_epoch": "1792851200.1",
                "gtpv2.message_type": "250",
            },
            "flat.jsonl",
        )
        self.assertIsNone(event["message_type"])
        self.assertEqual(event["support_status"], "UNKNOWN")

    def test_subscriber_identifiers_are_not_published(self) -> None:
        payload = self.events_path.read_text(encoding="utf-8")
        self.assertNotIn(IMSI_VALUE, payload)
        self.assertNotIn(MSISDN_VALUE, payload)
        self.assertNotIn(MEI_VALUE, payload)

    def test_raw_tft_packet_filters_are_not_published(self) -> None:
        tft = self.by_frame[1]["bearer_contexts"][0]["tft"]
        self.assertEqual(set(tft), {"source_ie", "present", "limitation"})
        self.assertFalse(any("filter" in key.lower() for key in tft))
        self.assertNotIn("packet_filter", json.dumps(tft).lower().replace(tft["limitation"].lower(), ""))

    def test_no_dedicated_bearer_lifecycle_inference(self) -> None:
        payload = json.dumps(self.events + self.transactions["transactions"]).lower()
        for forbidden in (
            "bearer_activated",
            "bearer_established",
            "lifecycle_state",
            "resource_admitted",
            "tft_installed",
            "forwarding_stopped",
        ):
            self.assertNotIn(forbidden, payload)
        self.assertTrue(any("never asserts" in item for item in self.transactions["limitations"]))


if __name__ == "__main__":
    unittest.main()