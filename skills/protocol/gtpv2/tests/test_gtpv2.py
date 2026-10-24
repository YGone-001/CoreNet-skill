#!/usr/bin/env python3
"""Functional tests for the bounded GTPv2-C Protocol Skill."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
EXAMPLES = SKILL / "examples"

# Assembled from fragments so the package-wide privacy scan can assert that no
# file inside the Skill contains a subscriber identity verbatim.
IMSI_VALUE = "46002" + "0000000001"
MEI_VALUE = "1122334455" + "667788"
MSISDN_VALUE = "919" + "000001"

sys.path.insert(0, str(SCRIPTS))
import gtpv2_model as model  # noqa: E402


def run(script: str, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    command = [sys.executable, str(SCRIPTS / script), *args]
    return subprocess.run(command, capture_output=True, text=True, env=env, check=False)


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class ExtractionTestCase(unittest.TestCase):
    """Shared extraction of the bundled PDML excerpt."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.directory = Path(cls._directory.name)
        cls.events_path = cls.directory / "events.jsonl"
        cls.trace_path = cls.directory / "trace.jsonl"
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "pdml" / "session-control.pdml"),
            "--output",
            str(cls.events_path),
            "--trace-output",
            str(cls.trace_path),
        )
        if result.returncode != 0:
            raise AssertionError(f"extraction failed: {result.stderr}")
        cls.events = load_jsonl(cls.events_path)
        cls.by_frame = {event["frame_number"]: event for event in cls.events}

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()


class ProtocolIdentityTests(ExtractionTestCase):
    def test_create_session_request_identified(self) -> None:
        event = self.by_frame[5]
        self.assertEqual(event["message_type"], "Create Session Request")
        self.assertEqual(event["message_type_code"], 32)
        self.assertEqual(event["procedure_family"], "create-session")
        self.assertEqual(event["support_status"], "SUPPORTED")

    def test_create_session_response_identified(self) -> None:
        event = self.by_frame[8]
        self.assertEqual(event["message_type"], "Create Session Response")
        self.assertEqual(event["message_type_code"], 33)

    def test_modify_bearer_pair_identified(self) -> None:
        self.assertEqual(self.by_frame[9]["message_type"], "Modify Bearer Request")
        self.assertEqual(self.by_frame[10]["message_type"], "Modify Bearer Response")

    def test_delete_session_pair_identified(self) -> None:
        self.assertEqual(self.by_frame[1]["message_type"], "Delete Session Request")
        self.assertEqual(self.by_frame[4]["message_type"], "Delete Session Response")

    def test_release_access_bearers_uses_170_and_171(self) -> None:
        self.assertEqual(self.by_frame[11]["message_type_code"], 170)
        self.assertEqual(self.by_frame[12]["message_type_code"], 171)
        self.assertEqual(self.by_frame[11]["message_type"], "Release Access Bearers Request")

    def test_unknown_message_code_keeps_number_and_null_name(self) -> None:
        events = load_jsonl(
            self._extract_fixture("unsupported-messages.jsonl", "unsupported-events.jsonl")
        )
        unknown = events[0]
        self.assertEqual(unknown["message_type_code"], 250)
        self.assertIsNone(unknown["message_type"])
        self.assertEqual(unknown["support_status"], "UNKNOWN")
        self.assertIsNone(unknown["procedure_family"])

    def test_unsupported_message_is_named_but_not_analysed(self) -> None:
        events = load_jsonl(
            self._extract_fixture("unsupported-messages.jsonl", "unsupported-events.jsonl")
        )
        request, response = events[1], events[2]
        self.assertEqual(request["message_type"], "Create Bearer Request")
        self.assertEqual(request["support_status"], "UNSUPPORTED")
        self.assertIsNone(request["procedure_family"])
        self.assertEqual(response["message_type"], "Create Bearer Response")
        self.assertEqual(response["message_cause"]["cause_code"], 16)

    def test_header_teid_states_stay_distinct(self) -> None:
        events = load_jsonl(self._extract_fixture("teid-states.jsonl", "teid-states-events.jsonl"))
        states = [event["header"]["teid_state"] for event in events]
        self.assertEqual(states, ["ABSENT", "ABSENT", "ZERO", "PRESENT"])
        self.assertIsNone(events[0]["header"]["teid"])
        self.assertEqual(events[2]["header"]["teid"], 0)
        self.assertEqual(events[3]["header"]["teid"], 0x000003C9)

    def test_sequence_number_is_parsed_from_hex(self) -> None:
        self.assertEqual(self.by_frame[5]["header"]["sequence_number"], 23)
        self.assertEqual(self.by_frame[1]["header"]["sequence_number"], 22)

    def test_flags_are_read_from_the_flags_subtree(self) -> None:
        event = self.by_frame[5]
        self.assertEqual(event["header"]["version"], 2)
        self.assertTrue(event["header"]["teid_flag"])
        self.assertFalse(event["header"]["piggybacking_flag"])
        self.assertEqual(event["header"]["flags"], 0x48)

    def test_message_length_preserved(self) -> None:
        self.assertEqual(self.by_frame[8]["header"]["message_length"], 103)

    def test_echo_family_is_supported(self) -> None:
        events = load_jsonl(self._extract_fixture("teid-states.jsonl", "teid-states-events.jsonl"))
        self.assertEqual(events[0]["procedure_family"], "echo")
        self.assertEqual(events[0]["message_type"], "Echo Request")

    def _extract_fixture(self, source: str, destination: str) -> Path:
        target = self.directory / destination
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "extracted" / source),
            "--output",
            str(target),
            "--force",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return target


class InformationElementTests(ExtractionTestCase):
    def test_message_scope_cause_published(self) -> None:
        cause = self.by_frame[8]["message_cause"]
        self.assertEqual(cause["cause_code"], 16)
        self.assertEqual(cause["cause_name"], "Request accepted")
        self.assertEqual(cause["scope"], "message")

    def test_bearer_scope_cause_kept_separate(self) -> None:
        event = self.by_frame[8]
        self.assertEqual(len(event["bearer_contexts"]), 1)
        bearer_cause = event["bearer_contexts"][0]["cause"]
        self.assertEqual(bearer_cause["scope"], "bearer")
        self.assertEqual(bearer_cause["cause_code"], 16)
        self.assertIsNot(bearer_cause, event["message_cause"])

    def test_request_has_no_fabricated_cause(self) -> None:
        self.assertIsNone(self.by_frame[5]["message_cause"])
        self.assertIsNone(self.by_frame[5]["bearer_contexts"][0]["cause"])

    def test_f_teid_interface_types_are_named(self) -> None:
        message_teids = self.by_frame[8]["f_teids"]
        self.assertEqual([item["interface_type"] for item in message_teids], [11, 7])
        self.assertEqual(message_teids[0]["interface_type_name"], "S11/S4 SGW GTP-C interface")
        self.assertEqual(message_teids[1]["interface_type_name"], "S5/S8 PGW GTP-C interface")

    def test_message_and_bearer_f_teids_are_separated(self) -> None:
        event = self.by_frame[8]
        self.assertEqual([item["scope"] for item in event["f_teids"]], ["message", "message"])
        bearer_teids = event["bearer_contexts"][0]["f_teids"]
        self.assertEqual([item["scope"] for item in bearer_teids], ["bearer", "bearer"])
        self.assertEqual([item["interface_type"] for item in bearer_teids], [1, 5])
        self.assertNotIn(969, [item["teid"] for item in bearer_teids])

    def test_bearer_only_f_teid_stays_in_the_bearer(self) -> None:
        event = self.by_frame[9]
        self.assertEqual(event["f_teids"], [])
        bearer = event["bearer_contexts"][0]
        self.assertEqual(bearer["ebi"], 5)
        self.assertEqual(bearer["f_teids"][0]["interface_type"], 0)
        self.assertEqual(bearer["f_teids"][0]["interface_type_name"], "S1-U eNodeB GTP-U interface")
        self.assertEqual(bearer["f_teids"][0]["teid"], 0x285704B5)

    def test_ebi_is_bound_to_the_bearer_item(self) -> None:
        for frame in (5, 6, 7, 8, 9, 10):
            contexts = self.by_frame[frame]["bearer_contexts"]
            self.assertEqual(len(contexts), 1, frame)
            self.assertEqual(contexts[0]["ebi"], 5)
            self.assertEqual(contexts[0]["item_index"], 0)

    def test_apn_is_published_as_presence_and_length_only(self) -> None:
        elements = self.by_frame[5]["information_elements"]
        self.assertTrue(elements["apn_present"])
        self.assertEqual(elements["apn_length"], 8)
        serialized = json.dumps(self.by_frame[5])
        self.assertNotIn("internet", serialized)

    def test_pdn_type_and_paa_family_without_address(self) -> None:
        request = self.by_frame[5]["information_elements"]
        self.assertEqual(request["pdn_type"], {"value": 1, "name": "IPv4"})
        self.assertEqual(request["paa_address_family"], "IPv4")
        response = self.by_frame[8]["information_elements"]
        self.assertEqual(response["pdn_type"], {"value": 1, "name": "IPv4"})
        self.assertNotIn("10.45.0.7", json.dumps(self.by_frame[8]))

    def test_rat_type_and_ambr_preserved(self) -> None:
        elements = self.by_frame[5]["information_elements"]
        self.assertEqual(elements["rat_type"], {"value": 6, "name": "EUTRAN"})
        self.assertTrue(elements["ambr_present"])
        self.assertEqual(elements["ambr_uplink"], 1000000)
        self.assertEqual(elements["ambr_downlink"], 1000000)

    def test_charging_id_presence_only(self) -> None:
        self.assertTrue(self.by_frame[7]["bearer_contexts"][0]["charging_id_present"])
        self.assertFalse(self.by_frame[9]["bearer_contexts"][0]["charging_id_present"])

    def test_identity_ies_published_as_presence_only(self) -> None:
        identities = self.by_frame[5]["identity_ies"]
        self.assertTrue(identities["imsi_present"])
        self.assertTrue(identities["mei_present"])
        self.assertTrue(identities["msisdn_present"])
        serialized = json.dumps(self.by_frame[5])
        self.assertNotIn(IMSI_VALUE, serialized)
        self.assertNotIn(MEI_VALUE, serialized)
        self.assertNotIn(MSISDN_VALUE, serialized)

    def test_top_level_ebi_is_reported_as_unbound(self) -> None:
        event = self.by_frame[1]
        self.assertEqual(event["bearer_contexts"], [])
        self.assertEqual(event["unbound_ie_metadata"]["ebi_values"], [5])
        self.assertEqual(event["unbound_ie_metadata"]["binding_basis"], "pdml_grouped_ie")

    def test_hierarchy_basis_recorded(self) -> None:
        self.assertEqual(self.by_frame[8]["hierarchy_basis"], "pdml_grouped_ie")

    def test_multiple_bearer_contexts_stay_item_scoped(self) -> None:
        target = self.directory / "multi-bearer-events.jsonl"
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "pdml" / "multi-bearer-context.pdml"),
            "--output",
            str(target),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        response = load_jsonl(target)[0]
        contexts = response["bearer_contexts"]
        self.assertEqual(len(contexts), 2)
        self.assertEqual([item["item_index"] for item in contexts], [0, 1])
        self.assertEqual([item["ebi"] for item in contexts], [5, 6])
        self.assertEqual([item["f_teids"][0]["teid"] for item in contexts], [4369, 8738])
        self.assertEqual([item["cause"]["cause_code"] for item in contexts], [16, 16])
        self.assertEqual([item["cause"]["scope"] for item in contexts], ["bearer", "bearer"])
        self.assertEqual([item["teid"] for item in response["f_teids"]], [969])
        self.assertEqual([item["scope"] for item in response["f_teids"]], ["message"])

    def test_incomplete_bearer_context_is_published_without_invention(self) -> None:
        target = self.directory / "incomplete-bearer-events.jsonl"
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "pdml" / "multi-bearer-context.pdml"),
            "--output",
            str(target),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        event = load_jsonl(target)[1]
        self.assertEqual(len(event["bearer_contexts"]), 1)
        context = event["bearer_contexts"][0]
        self.assertIsNone(context["ebi"])
        self.assertIsNone(context["cause"])
        self.assertEqual(context["f_teids"][0]["teid"], 13107)
        self.assertEqual(context["f_teids"][0]["scope"], "bearer")
        self.assertEqual(event["f_teids"], [])
        self.assertEqual(event["message_cause"]["cause_code"], 16)
        self.assertEqual(event["message_cause"]["scope"], "message")

    def test_ie_summary_names_the_bearer_context(self) -> None:
        summary = self.by_frame[8]["ie_summary"]
        bearer = [item for item in summary if item["ie_type"] == 93]
        self.assertEqual(len(bearer), 1)
        self.assertEqual(bearer[0]["ie_name"], "Bearer Context")


class FlatInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.directory = Path(cls._directory.name)
        cls.events_path = cls.directory / "flat.jsonl"
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "extracted" / "session-control-fields.jsonl"),
            "--input-format",
            "fields-jsonl",
            "--output",
            str(cls.events_path),
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        cls.events = load_jsonl(cls.events_path)
        cls.by_frame = {event["frame_number"]: event for event in cls.events}

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_flat_input_produces_same_message_identity(self) -> None:
        self.assertEqual(len(self.events), 12)
        self.assertEqual(self.by_frame[8]["message_type"], "Create Session Response")
        self.assertEqual(self.by_frame[8]["message_type_code"], 33)

    def test_flat_input_never_claims_bearer_binding(self) -> None:
        for event in self.events:
            self.assertEqual(event["bearer_contexts"], [])
            self.assertEqual(event["hierarchy_basis"], "flat_fields")
            self.assertIn(
                "flat field input does not preserve grouped-IE item boundaries, so no bearer context is published",
                event["extraction_limitations"],
            )

    def test_flat_f_teid_scope_is_unbound(self) -> None:
        scopes = {item["scope"] for event in self.events for item in event["f_teids"]}
        self.assertEqual(scopes, {"unbound"})

    def test_flat_additional_causes_are_unbound(self) -> None:
        event = self.by_frame[8]
        self.assertEqual(event["message_cause"]["cause_code"], 16)
        additional = event["unbound_ie_metadata"]["additional_causes"]
        self.assertEqual(additional[0]["cause_code"], 16)

    def test_flat_header_teid_states_preserved(self) -> None:
        self.assertEqual(self.by_frame[5]["header"]["teid_state"], "ZERO")
        self.assertEqual(self.by_frame[9]["header"]["teid_state"], "PRESENT")

    def test_flat_pdn_type_from_repeated_field(self) -> None:
        self.assertEqual(self.by_frame[5]["information_elements"]["pdn_type"]["value"], 1)


class CorrelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.directory = Path(cls._directory.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def _correlate(self, events: Path, name: str) -> dict:
        output = self.directory / name
        result = run("correlate-gtpv2.py", str(events), "--output", str(output), "--force")
        self.assertEqual(result.returncode, 0, result.stderr)
        return load_json(output)

    def _events_for(self, fixture: str) -> Path:
        output = self.directory / f"{Path(fixture).stem}-events.jsonl"
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "extracted" / fixture),
            "--output",
            str(output),
            "--force",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return output

    def test_real_fixture_transactions_all_match(self) -> None:
        result = self._correlate(
            self._events_for("session-control-fields.jsonl"), "session-control-transactions.json"
        )
        self.assertEqual(result["transaction_count"], 6)
        self.assertEqual(result["matched_count"], 6)
        self.assertEqual(result["open_request_count"], 0)
        self.assertEqual(result["ambiguous_count"], 0)
        pairs = [
            (item["request"]["frame_number"], item["response"]["frame_number"])
            for item in result["transactions"]
        ]
        self.assertEqual(pairs, [(1, 4), (2, 3), (5, 8), (6, 7), (9, 10), (11, 12)])

    def test_open_request_is_not_a_timeout(self) -> None:
        result = self._correlate(self._events_for("teid-states.jsonl"), "teid-transactions.json")
        open_items = [item for item in result["transactions"] if item["correlation_status"] == "OPEN_REQUEST"]
        self.assertEqual(len(open_items), 2)
        for item in open_items:
            self.assertTrue(any("not a proven timeout" in text for text in item["limitations"]))

    def test_response_only_evidence(self) -> None:
        result = self._correlate(
            EXAMPLES / "extracted" / "correlation-response-only-events.jsonl", "response-only.json"
        )
        self.assertEqual(result["response_only_count"], 2)
        for item in result["transactions"]:
            self.assertEqual(item["correlation_status"], "RESPONSE_ONLY")
            self.assertIsNone(item["request"])

    def test_ambiguous_candidates_are_not_resolved(self) -> None:
        result = self._correlate(
            EXAMPLES / "extracted" / "correlation-ambiguous-events.jsonl", "ambiguous.json"
        )
        self.assertEqual(result["ambiguous_count"], 1)
        self.assertEqual(result["response_only_count"], 0)
        transaction = result["transactions"][0]
        self.assertIsNone(transaction["response"])
        self.assertEqual(len(transaction["response_candidates"]), 2)

    def test_retransmission_is_grouped_not_duplicated(self) -> None:
        result = self._correlate(
            EXAMPLES / "extracted" / "correlation-retransmission-events.jsonl", "retransmission.json"
        )
        self.assertEqual(result["transaction_count"], 1)
        self.assertEqual(result["retransmission_count"], 1)
        transaction = result["transactions"][0]
        self.assertEqual(transaction["correlation_status"], "MATCHED")
        self.assertEqual(transaction["correlation_strength"], "SUPPORTED")
        self.assertEqual(transaction["retransmissions"][0]["frame_number"], 6)
        self.assertEqual(transaction["request"]["frame_number"], 5)

    def test_equal_sequence_numbers_on_different_endpoints_stay_isolated(self) -> None:
        result = self._correlate(
            EXAMPLES / "extracted" / "correlation-endpoints-events.jsonl", "endpoints.json"
        )
        self.assertEqual(result["transaction_count"], 2)
        self.assertEqual(result["matched_count"], 2)
        pairs = [
            (item["request"]["frame_number"], item["response"]["frame_number"])
            for item in result["transactions"]
        ]
        self.assertEqual(pairs, [(10, 11), (12, 13)])

    def test_teid_echo_corroborates_initial_requests(self) -> None:
        events = self.directory / "pdml-events.jsonl"
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "pdml" / "session-control.pdml"),
            "--output",
            str(events),
            "--force",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        correlation = self._correlate(events, "pdml-transactions.json")
        create = [item for item in correlation["transactions"] if item["request"]["frame_number"] == 5][0]
        self.assertTrue(create["corroboration"]["teid_echo"])
        self.assertEqual(create["corroboration"]["teid_relation"], "initial_zero_teid_request")

    def test_flat_input_cannot_corroborate_with_teid(self) -> None:
        result = self._correlate(
            self._events_for("session-control-fields.jsonl"), "session-control-transactions.json"
        )
        for item in result["transactions"]:
            self.assertIsNone(item["corroboration"]["teid_echo"])

    def test_strength_reflects_corroboration(self) -> None:
        result = self._correlate(
            self._events_for("session-control-fields.jsonl"), "session-control-transactions.json"
        )
        strengths = {
            item["procedure_family"]: item["correlation_strength"] for item in result["transactions"]
        }
        # Flat input carries neither a decoder link nor provable F-TEID scope, so
        # every pairing rests on the correlation keys alone.
        self.assertEqual(set(strengths.values()), {"SUPPORTED"})

    def test_decoder_link_upgrades_strength(self) -> None:
        events = self.directory / "pdml-link-events.jsonl"
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "pdml" / "session-control.pdml"),
            "--output",
            str(events),
            "--force",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        correlation = self._correlate(events, "pdml-link-transactions.json")
        release = [
            item for item in correlation["transactions"] if item["procedure_family"] == "release-access-bearers"
        ][0]
        self.assertEqual(release["corroboration"]["decoder_link_frame"], 11)
        self.assertEqual(release["correlation_strength"], "STRONG")

    def test_correlation_never_asserts_lifecycle(self) -> None:
        result = self._correlate(
            self._events_for("session-control-fields.jsonl"), "session-control-transactions.json"
        )
        self.assertTrue(
            any("never asserts session" in text for text in result["limitations"])
        )
        for item in result["transactions"]:
            self.assertNotIn("bearer_state", item)
            self.assertNotIn("session_state", item)


class EngineeringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.directory = Path(cls._directory.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_deterministic_event_output(self) -> None:
        first = self.directory / "one.jsonl"
        second = self.directory / "two.jsonl"
        for target in (first, second):
            result = run(
                "extract-gtpv2.py",
                str(EXAMPLES / "pdml" / "session-control.pdml"),
                "--output",
                str(target),
                "--force",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_deterministic_transaction_output(self) -> None:
        events = self.directory / "events.jsonl"
        run("extract-gtpv2.py", str(EXAMPLES / "pdml" / "session-control.pdml"), "--output", str(events), "--force")
        first = self.directory / "tx-one.json"
        second = self.directory / "tx-two.json"
        for target in (first, second):
            result = run("correlate-gtpv2.py", str(events), "--output", str(target), "--force")
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_timeline_text_lists_every_event(self) -> None:
        events = self.directory / "timeline-events.jsonl"
        run("extract-gtpv2.py", str(EXAMPLES / "pdml" / "session-control.pdml"), "--output", str(events), "--force")
        result = run("gtpv2_timeline.py", str(events), "--format", "text")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GTPv2-C timeline: 12 event(s)", result.stdout)
        self.assertIn("Create Session Request", result.stdout)
        self.assertIn("teid=ZERO", result.stdout)
        self.assertIn("cause=16(Request accepted)", result.stdout)

    def test_timeline_json_structure(self) -> None:
        events = self.directory / "timeline-events.jsonl"
        run("extract-gtpv2.py", str(EXAMPLES / "pdml" / "session-control.pdml"), "--output", str(events), "--force")
        result = run("gtpv2_timeline.py", str(events), "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["protocol"], "GTPv2-C")
        self.assertEqual(payload["event_count"], 12)
        self.assertEqual(payload["events"][0]["frame_number"], 1)

    def test_malformed_json_lines_rejected(self) -> None:
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "extracted" / "malformed.jsonl"),
            "--output",
            str(self.directory / "malformed-events.jsonl"),
        )
        self.assertEqual(result.returncode, 5)
        self.assertIn("invalid JSON Lines record", result.stderr)
        self.assertFalse((self.directory / "malformed-events.jsonl").exists())

    def test_missing_required_field_rejected(self) -> None:
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "extracted" / "missing-required.jsonl"),
            "--output",
            str(self.directory / "missing-events.jsonl"),
        )
        self.assertEqual(result.returncode, 5)
        self.assertIn("frame.number is required", result.stderr)

    def test_empty_input_reports_no_events(self) -> None:
        empty = self.directory / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        result = run("extract-gtpv2.py", str(empty), "--output", str(self.directory / "empty-events.jsonl"))
        self.assertEqual(result.returncode, 6)

    def test_output_overwrite_is_protected(self) -> None:
        target = self.directory / "protected.jsonl"
        target.write_text("keep\n", encoding="utf-8")
        result = run(
            "extract-gtpv2.py",
            str(EXAMPLES / "pdml" / "session-control.pdml"),
            "--output",
            str(target),
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")

    def test_output_must_not_replace_input(self) -> None:
        source = self.directory / "self.jsonl"
        shutil.copy(EXAMPLES / "extracted" / "teid-states.jsonl", source)
        result = run("extract-gtpv2.py", str(source), "--output", str(source), "--force")
        self.assertEqual(result.returncode, 7)
        self.assertIn("must not replace the input", result.stderr)

    def test_missing_decoder_reports_tool_unavailable(self) -> None:
        capture = self.directory / "empty.pcap"
        capture.write_bytes(b"")
        environment = dict(os.environ)
        environment["PATH"] = str(self.directory)
        result = run(
            "extract-gtpv2.py",
            str(capture),
            "--input-format",
            "capture",
            "--output",
            str(self.directory / "capture-events.jsonl"),
            env=environment,
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("tshark is unavailable", result.stderr)

    def test_package_runs_from_a_standalone_copy(self) -> None:
        copy = self.directory / "gtpv2-copy"
        shutil.copytree(SKILL, copy)
        output = self.directory / "standalone-events.jsonl"
        result = subprocess.run(
            [
                sys.executable,
                str(copy / "scripts" / "extract-gtpv2.py"),
                str(copy / "examples" / "pdml" / "session-control.pdml"),
                "--output",
                str(output),
            ],
            capture_output=True,
            text=True,
            check=False,
            cwd=str(self.directory),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(load_jsonl(output)), 12)

    def test_sensitive_values_are_absent_from_output(self) -> None:
        events = self.directory / "sensitive.jsonl"
        run("extract-gtpv2.py", str(EXAMPLES / "pdml" / "session-control.pdml"), "--output", str(events), "--force")
        text = events.read_text(encoding="utf-8")
        for forbidden in (IMSI_VALUE, MEI_VALUE, MSISDN_VALUE, "internet", "10.45.0.7"):
            self.assertNotIn(forbidden, text)

    def test_trace_projection_matches_shared_contract(self) -> None:
        events = self.directory / "trace-events.jsonl"
        trace = self.directory / "trace.jsonl"
        run(
            "extract-gtpv2.py",
            str(EXAMPLES / "pdml" / "session-control.pdml"),
            "--output",
            str(events),
            "--trace-output",
            str(trace),
            "--force",
        )
        rows = load_jsonl(trace)
        self.assertEqual(len(rows), 12)
        required = {"timestamp", "protocol", "interface", "procedure", "message_type", "packet", "evidence"}
        for row in rows:
            self.assertTrue(required.issubset(row.keys()))
            self.assertEqual(row["protocol"], "GTPv2-C")
            self.assertEqual(row["evidence"]["level"], "DERIVED")
            self.assertIn("frame_number", row["packet"])

    def test_events_match_committed_expectations(self) -> None:
        actual = self.directory / "actual.jsonl"
        run("extract-gtpv2.py", str(EXAMPLES / "pdml" / "session-control.pdml"), "--output", str(actual), "--force")
        expected = EXAMPLES / "expected" / "session-control-events.jsonl"
        self.assertEqual(actual.read_text(encoding="utf-8"), expected.read_text(encoding="utf-8"))

    def test_transactions_match_committed_expectations(self) -> None:
        events = self.directory / "expect-events.jsonl"
        run("extract-gtpv2.py", str(EXAMPLES / "pdml" / "session-control.pdml"), "--output", str(events), "--force")
        actual = self.directory / "actual-transactions.json"
        run("correlate-gtpv2.py", str(events), "--output", str(actual), "--force")
        expected = EXAMPLES / "expected" / "session-control-transactions.json"
        self.assertEqual(actual.read_text(encoding="utf-8"), expected.read_text(encoding="utf-8"))


class ModelUnitTests(unittest.TestCase):
    def test_message_table_covers_required_families(self) -> None:
        for code in (1, 2, 32, 33, 34, 35, 36, 37, 170, 171):
            self.assertIn(code, model.MESSAGE_TYPES)
            self.assertIn(code, model.SUPPORTED_CODES)

    def test_release_access_bearers_is_not_149(self) -> None:
        self.assertEqual(model.MESSAGE_TYPES[149], "Detach Notification")
        self.assertEqual(model.MESSAGE_TYPES[170], "Release Access Bearers Request")

    def test_cause_names_are_not_shifted(self) -> None:
        self.assertEqual(model.CAUSES[16], "Request accepted")
        self.assertEqual(model.CAUSES[68], "Service not supported")
        self.assertEqual(model.CAUSES[70], "Mandatory IE missing")
        self.assertEqual(model.CAUSES[128], "S1-U Path Failure")

    def test_interface_type_names_match_the_specification(self) -> None:
        self.assertEqual(model.INTERFACE_TYPES[10], "S11 MME GTP-C interface")
        self.assertEqual(model.INTERFACE_TYPES[11], "S11/S4 SGW GTP-C interface")
        self.assertEqual(model.INTERFACE_TYPES[7], "S5/S8 PGW GTP-C interface")

    def test_resolve_message_marks_unknown(self) -> None:
        name, status, procedure, family = model.resolve_message(250)
        self.assertIsNone(name)
        self.assertEqual(status, "UNKNOWN")
        self.assertIsNone(procedure)
        self.assertIsNone(family)

    def test_timestamp_normalization_is_utc_microseconds(self) -> None:
        self.assertEqual(model.normalize_timestamp("1792850867.419250457"), "2026-10-24T14:07:47.419250Z")

    def test_to_int_handles_hex_and_repeated_values(self) -> None:
        self.assertEqual(model.to_int("0x000003c9"), 969)
        self.assertEqual(model.to_int("16,16"), 16)
        self.assertIsNone(model.to_int(""))

    def test_flat_record_without_message_type_is_rejected(self) -> None:
        with self.assertRaises(model.InputError):
            model.normalize_flat_record({"frame.number": "1", "frame.time_epoch": "1.0"}, "x.jsonl")


if __name__ == "__main__":
    unittest.main()
