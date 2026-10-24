#!/usr/bin/env python3
"""Functional tests for the bounded EPC session-control Domain analysis."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
EXAMPLES = SKILL / "examples" / "gtpv2"

sys.path.insert(0, str(SCRIPTS))
import epc_session_model as model  # noqa: E402


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "analyze_epc_session.py"), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def event(
    frame: int,
    code: int,
    family: str,
    *,
    teid_state: str = "PRESENT",
    teid: int | None = 6,
    sequence: int = 1,
    cause: int | None = None,
    f_teids: list[dict] | None = None,
    bearers: list[dict] | None = None,
    hierarchy: str = "pdml_grouped_ie",
    capture: str = "fixture.pcap",
) -> dict:
    message_cause = None
    if cause is not None:
        message_cause = {"cause_code": cause, "cause_name": model_cause_name(cause), "scope": "message"}
    return {
        "protocol": "GTPv2-C",
        "capture_file": capture,
        "frame_number": frame,
        "message_type_code": code,
        "message_type": f"type-{code}",
        "procedure_family": family,
        "message_family": family,
        "hierarchy_basis": hierarchy,
        "header": {"teid": teid, "teid_state": teid_state, "sequence_number": sequence},
        "message_cause": message_cause,
        "f_teids": f_teids or [],
        "bearer_contexts": bearers or [],
        "identity_ies": {},
        "evidence": {"level": "OBSERVED", "source": f"fixture#{frame}"},
    }


def model_cause_name(code: int) -> str | None:
    return {16: "Request accepted", 17: "Request accepted partially", 72: "System failure"}.get(code)


def transaction(
    reference: str,
    family: str,
    request: int | None,
    response: int | None,
    status: str = "MATCHED",
) -> dict:
    return {
        "transaction_reference": reference,
        "procedure_family": family,
        "message_family": family,
        "correlation_status": status,
        "correlation_strength": "STRONG" if status == "MATCHED" else "NONE",
        "request": {"frame_number": request} if request is not None else None,
        "response": {"frame_number": response} if response is not None else None,
        "response_candidates": [],
        "retransmissions": [],
    }


def document(transactions: list[dict]) -> dict:
    return {"protocol": "GTPv2-C", "transactions": transactions}


def analyze(events: list[dict], transactions: list[dict]) -> dict:
    return model.analyze(events, document(transactions), "events.jsonl", "transactions.json")


def control_fteid(interface_type: int, teid: int) -> dict:
    return {"scope": "message", "interface_type": interface_type, "teid": teid}


def bearer(ebi: int | None, cause: int | None = None, teid: int | None = None, interface_type: int = 1) -> dict:
    return {
        "item_index": 0,
        "ebi": ebi,
        "cause": (
            {"cause_code": cause, "cause_name": model_cause_name(cause), "scope": "bearer"}
            if cause is not None
            else None
        ),
        "f_teids": (
            [{"scope": "bearer", "interface_type": interface_type, "teid": teid}] if teid is not None else []
        ),
        "charging_id_present": False,
        "binding_basis": "pdml_grouped_ie",
    }


class SessionControlTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.events = load_jsonl(EXAMPLES / "events.jsonl")
        cls.transactions = load_json(EXAMPLES / "transactions.json")["transactions"]
        cls.analysis = model.analyze(
            cls.events, document(cls.transactions), "events.jsonl", "transactions.json"
        )

    def subject_for(self, interface: str, family: str) -> dict:
        for subject in self.analysis["control_plane_subjects"]:
            if subject["interface"] == interface and family in subject["procedure_families"]:
                return subject
        raise AssertionError(f"no {interface} subject with {family}")


class ProcedureObservationTests(SessionControlTestCase):
    def test_matched_create_session_is_one_observation(self) -> None:
        observations = [
            item
            for item in self.analysis["transaction_observations"]
            if item["procedure_family"] == "create-session" and item["request"]["frame_number"] == 5
        ]
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["correlation_status"], "MATCHED")
        self.assertEqual(observations[0]["request"]["frame_number"], 5)
        self.assertEqual(observations[0]["response"]["frame_number"], 8)

    def test_cause_16_is_protocol_acceptance_only(self) -> None:
        observation = [
            item
            for item in self.analysis["transaction_observations"]
            if item["procedure_family"] == "create-session" and item["request"]["frame_number"] == 5
        ][0]
        self.assertEqual(observation["outcome"], model.OUTCOME_ACCEPTED)
        self.assertEqual(observation["message_cause"]["cause_code"], 16)
        self.assertEqual(observation["message_cause"]["scope"], "message")
        self.assertIn("default EPS bearer service availability", self.analysis["not_confirmed"])

    def test_rejected_cause_is_preserved(self) -> None:
        events = [
            event(1, 32, "create-session", teid_state="ZERO", teid=0, f_teids=[control_fteid(10, 6)]),
            event(2, 33, "create-session", cause=72),
        ]
        analysis = analyze(events, [transaction("tx-1", "create-session", 1, 2)])
        observation = analysis["transaction_observations"][0]
        self.assertEqual(observation["outcome"], model.OUTCOME_REJECTED)
        self.assertEqual(observation["message_cause"]["cause_code"], 72)
        types = [item["deviation_type"] for item in analysis["procedure_local_deviations"]]
        self.assertIn(model.DEVIATION_CREATE_REJECTED, types)

    def test_bearer_cause_stays_item_scoped(self) -> None:
        events = [
            event(1, 32, "create-session", teid_state="ZERO", teid=0, f_teids=[control_fteid(10, 6)]),
            event(2, 33, "create-session", cause=16, bearers=[bearer(5, cause=72)]),
        ]
        analysis = analyze(events, [transaction("tx-1", "create-session", 1, 2)])
        observation = analysis["transaction_observations"][0]
        self.assertEqual(observation["message_cause"]["cause_code"], 16)
        self.assertEqual(observation["bearer_contexts"][0]["cause"]["cause_code"], 72)
        self.assertEqual(observation["bearer_contexts"][0]["cause"]["scope"], "bearer")
        self.assertEqual(observation["outcome"], model.OUTCOME_ACCEPTED)
        types = [item["deviation_type"] for item in analysis["procedure_local_deviations"]]
        self.assertIn(model.DEVIATION_BEARER_REJECTED, types)

    def test_two_bearer_contexts_stay_distinct(self) -> None:
        first = bearer(5, cause=16, teid=4369)
        second = bearer(6, cause=72, teid=8738)
        second["item_index"] = 1
        events = [
            event(1, 32, "create-session", teid_state="ZERO", teid=0, f_teids=[control_fteid(10, 6)]),
            event(2, 33, "create-session", cause=16, bearers=[first, second]),
        ]
        analysis = analyze(events, [transaction("tx-1", "create-session", 1, 2)])
        contexts = analysis["transaction_observations"][0]["bearer_contexts"]
        self.assertEqual([item["ebi"] for item in contexts], [5, 6])
        self.assertEqual([item["f_teids"][0]["teid"] for item in contexts], [4369, 8738])
        self.assertEqual([item["cause"]["cause_code"] for item in contexts], [16, 72])

    def test_incomplete_bearer_context_keeps_nulls(self) -> None:
        events = [
            event(1, 34, "modify-bearer", teid=6),
            event(2, 35, "modify-bearer", cause=16, bearers=[bearer(None, cause=None, teid=13107, interface_type=0)]),
        ]
        analysis = analyze(events, [transaction("tx-1", "modify-bearer", 1, 2)])
        context = analysis["transaction_observations"][0]["bearer_contexts"][0]
        self.assertIsNone(context["ebi"])
        self.assertIsNone(context["cause"])
        self.assertEqual(context["f_teids"][0]["teid"], 13107)

    def test_header_teid_and_f_teid_stay_distinct(self) -> None:
        subject = self.subject_for("S11", "create-session")
        self.assertIn("0x00000006", subject["control_plane_teids"])
        self.assertIn("0x000003c9", subject["control_plane_teids"])
        fteid_teids = {item["teid"] for item in subject["f_teid_evidence"]}
        self.assertIn(969, fteid_teids)
        for observation in self.analysis["transaction_observations"]:
            for item in observation["f_teids"]:
                self.assertEqual(item["scope"], "message")

    def test_modify_bearer_is_represented(self) -> None:
        subject = self.subject_for("S11", "modify-bearer")
        payload = subject["procedure_observations"]["modify-bearer"]
        self.assertEqual(payload["transaction_count"], 1)
        self.assertEqual(payload["outcomes"], [model.OUTCOME_ACCEPTED])

    def test_delete_session_is_represented(self) -> None:
        families = [
            family
            for subject in self.analysis["control_plane_subjects"]
            for family in subject["procedure_families"]
        ]
        self.assertIn("delete-session", families)

    def test_release_access_bearers_is_not_delete_session(self) -> None:
        subject = self.subject_for("S11", "release-access-bearers")
        self.assertIn("release-access-bearers", subject["procedure_families"])
        self.assertNotIn("delete-session", subject["procedure_families"])

    def test_open_request_stays_inconclusive(self) -> None:
        events = [event(1, 32, "create-session", teid_state="ZERO", teid=0, f_teids=[control_fteid(10, 6)])]
        analysis = analyze(events, [transaction("tx-1", "create-session", 1, None, status="OPEN_REQUEST")])
        observation = analysis["transaction_observations"][0]
        self.assertEqual(observation["outcome"], model.OUTCOME_OPEN)
        types = [item["deviation_type"] for item in analysis["procedure_local_deviations"]]
        self.assertIn(model.DEVIATION_OPEN_REQUEST, types)
        self.assertTrue(
            any("not a proven timeout" in item or "no observed response" in item for item in observation["limitations"])
        )

    def test_response_only_stays_partial(self) -> None:
        events = [event(2, 33, "create-session", cause=16)]
        analysis = analyze(events, [transaction("tx-1", "create-session", None, 2, status="RESPONSE_ONLY")])
        observation = analysis["transaction_observations"][0]
        self.assertEqual(observation["outcome"], model.OUTCOME_RESPONSE_ONLY)
        types = [item["deviation_type"] for item in analysis["procedure_local_deviations"]]
        self.assertIn(model.DEVIATION_RESPONSE_ONLY, types)

    def test_ambiguous_transaction_is_not_resolved(self) -> None:
        events = [
            event(1, 32, "create-session", teid_state="ZERO", teid=0, f_teids=[control_fteid(10, 6)]),
            event(2, 33, "create-session", cause=16),
        ]
        analysis = analyze(events, [transaction("tx-1", "create-session", 1, None, status="AMBIGUOUS")])
        observation = analysis["transaction_observations"][0]
        self.assertEqual(observation["outcome"], model.OUTCOME_AMBIGUOUS)
        self.assertIsNone(observation["response"])
        self.assertTrue(analysis["ambiguous_evidence"])


class SubjectGroupingTests(SessionControlTestCase):
    def test_s11_and_s5s8_stay_separate(self) -> None:
        interfaces = {subject["interface"] for subject in self.analysis["control_plane_subjects"]}
        self.assertIn("S11", interfaces)
        self.assertIn("S5/S8", interfaces)
        for subject in self.analysis["control_plane_subjects"]:
            self.assertEqual(subject["cross_interface_association"], "NOT_ESTABLISHED")
        self.assertTrue(
            any("no reviewed identity bridge" in item for item in self.analysis["evidence_limitations"])
        )

    def test_equal_ebi_does_not_merge_subjects(self) -> None:
        s11 = self.subject_for("S11", "create-session")
        s5s8 = self.subject_for("S5/S8", "create-session")
        self.assertNotEqual(s11["subject_reference"], s5s8["subject_reference"])
        self.assertEqual(s11["bearer_contexts"][0]["ebi"], 5)
        self.assertEqual(s5s8["bearer_contexts"][0]["ebi"], 5)

    def test_repeated_transactions_do_not_create_new_sessions(self) -> None:
        events = [
            event(1, 32, "create-session", teid_state="ZERO", teid=0, f_teids=[control_fteid(10, 6)]),
            event(2, 33, "create-session", cause=16, f_teids=[control_fteid(11, 969)]),
            event(3, 34, "modify-bearer", teid=969),
            event(4, 35, "modify-bearer", cause=16),
        ]
        analysis = analyze(
            events,
            [
                transaction("tx-1", "create-session", 1, 2),
                transaction("tx-2", "modify-bearer", 3, 4),
            ],
        )
        self.assertEqual(analysis["control_plane_subject_count"], 1)
        subject = analysis["control_plane_subjects"][0]
        self.assertEqual(subject["association_strength"], "STRONG")
        self.assertEqual(len(subject["transaction_references"]), 2)

    def test_reused_teid_after_deletion_starts_a_new_generation(self) -> None:
        events = [
            event(1, 32, "create-session", teid_state="ZERO", teid=0, f_teids=[control_fteid(10, 6)]),
            event(2, 33, "create-session", cause=16, f_teids=[control_fteid(11, 969)]),
            event(3, 36, "delete-session", teid=969),
            event(4, 37, "delete-session", cause=16),
            event(5, 32, "create-session", teid=969),
            event(6, 33, "create-session", cause=16),
        ]
        analysis = analyze(
            events,
            [
                transaction("tx-1", "create-session", 1, 2),
                transaction("tx-2", "delete-session", 3, 4),
                transaction("tx-3", "create-session", 5, 6),
            ],
        )
        self.assertEqual(analysis["control_plane_subject_count"], 2)
        types = [item["deviation_type"] for item in analysis["procedure_local_deviations"]]
        self.assertIn(model.DEVIATION_CONTEXT_REUSE, types)
        references = {subject["subject_reference"] for subject in analysis["control_plane_subjects"]}
        self.assertEqual(len(references), 2)

    def test_unresolved_interface_never_groups(self) -> None:
        events = [
            event(1, 36, "delete-session", teid=64),
            event(2, 37, "delete-session", cause=16),
            event(3, 36, "delete-session", teid=64),
            event(4, 37, "delete-session", cause=16),
        ]
        analysis = analyze(
            events,
            [
                transaction("tx-1", "delete-session", 1, 2),
                transaction("tx-2", "delete-session", 3, 4),
            ],
        )
        self.assertEqual(analysis["control_plane_subject_count"], 2)
        for subject in analysis["control_plane_subjects"]:
            self.assertEqual(subject["interface"], "UNKNOWN_INTERFACE")
            self.assertEqual(subject["association_strength"], "UNBOUND")
        types = [item["deviation_type"] for item in analysis["procedure_local_deviations"]]
        self.assertIn(model.DEVIATION_INTERFACE_UNRESOLVED, types)

    def test_no_user_plane_or_bearer_success_verdict(self) -> None:
        published = json.dumps(self.analysis).lower()
        for forbidden in ("user_plane_ready", "bearer_active", "pdn_connected", "service_success"):
            self.assertNotIn(forbidden, published)
        self.assertIn("user-plane packet forwarding", self.analysis["not_confirmed"])

    def test_global_boundary_is_not_evaluated(self) -> None:
        self.assertEqual(self.analysis["boundary_selection_status"], "NOT_EVALUATED")
        self.assertIsNone(self.analysis["first_abnormal_boundary"])


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls._temporary.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def test_committed_example_reproduces_expected_analysis(self) -> None:
        output = self.directory / "analysis.json"
        result = run_cli(
            "--gtpv2", str(EXAMPLES / "events.jsonl"),
            "--transactions", str(EXAMPLES / "transactions.json"),
            "--output", str(output),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            output.read_text(encoding="utf-8"),
            (EXAMPLES / "expected-session-analysis.json").read_text(encoding="utf-8"),
        )

    def test_analysis_is_deterministic(self) -> None:
        first = self.directory / "first.json"
        second = self.directory / "second.json"
        for target in (first, second):
            result = run_cli(
                "--gtpv2", str(EXAMPLES / "events.jsonl"),
                "--transactions", str(EXAMPLES / "transactions.json"),
                "--output", str(target),
                "--force",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_timeline_renders_text_and_json(self) -> None:
        analysis = EXAMPLES / "expected-session-analysis.json"
        text = subprocess.run(
            [sys.executable, str(SCRIPTS / "epc_session_timeline.py"), str(analysis), "--format", "text"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertIn("EPC session-control timeline", text.stdout)
        self.assertIn("create-session", text.stdout)
        payload = subprocess.run(
            [sys.executable, str(SCRIPTS / "epc_session_timeline.py"), str(analysis), "--format", "json"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(payload.returncode, 0, payload.stderr)
        rows = json.loads(payload.stdout)["procedure_rows"]
        self.assertEqual(len(rows), 6)
        self.assertTrue(all("subject_reference" in row for row in rows))

    def test_malformed_events_are_rejected(self) -> None:
        bad = self.directory / "bad.jsonl"
        bad.write_text('{"protocol": "S1AP"}\n', encoding="utf-8")
        result = run_cli(
            "--gtpv2", str(bad),
            "--transactions", str(EXAMPLES / "transactions.json"),
            "--output", str(self.directory / "bad.json"),
        )
        self.assertEqual(result.returncode, 5)
        self.assertIn("another protocol", result.stderr)

    def test_missing_transactions_are_rejected(self) -> None:
        bad = self.directory / "tx.json"
        bad.write_text('{"protocol": "GTPv2-C"}', encoding="utf-8")
        result = run_cli(
            "--gtpv2", str(EXAMPLES / "events.jsonl"),
            "--transactions", str(bad),
            "--output", str(self.directory / "tx.json.out"),
        )
        self.assertEqual(result.returncode, 5)

    def test_no_transactions_reports_no_subjects(self) -> None:
        empty = self.directory / "empty.json"
        empty.write_text('{"protocol": "GTPv2-C", "transactions": []}', encoding="utf-8")
        result = run_cli(
            "--gtpv2", str(EXAMPLES / "events.jsonl"),
            "--transactions", str(empty),
            "--output", str(self.directory / "empty-analysis.json"),
        )
        self.assertEqual(result.returncode, 6)
        self.assertTrue((self.directory / "empty-analysis.json").is_file())

    def test_output_overwrite_is_protected(self) -> None:
        target = self.directory / "protected.json"
        target.write_text("keep\n", encoding="utf-8")
        result = run_cli(
            "--gtpv2", str(EXAMPLES / "events.jsonl"),
            "--transactions", str(EXAMPLES / "transactions.json"),
            "--output", str(target),
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")

    def test_schema_and_rules_match_the_model(self) -> None:
        schema = load_json(SKILL / "schemas" / "epc-session-analysis.schema.json")
        required = set(schema["required"])
        for field in (
            "control_plane_subjects",
            "transaction_observations",
            "bearer_context_observations",
            "procedure_local_deviations",
            "not_confirmed",
        ):
            self.assertIn(field, required)
        rules = load_json(SKILL / "rules" / "epc-session-model.json")
        self.assertEqual(set(rules["procedure_families"]), set(model.FAMILY_ORDER))
        self.assertEqual(set(rules["accepting_causes"]), set(model.ACCEPTING_CAUSES))
        self.assertEqual(set(rules["interface_detection"]["s11_control_interface_types"]), set(model.S11_CONTROL_TYPES))
        self.assertEqual(
            set(rules["interface_detection"]["s5s8_control_interface_types"]), set(model.S5S8_CONTROL_TYPES)
        )
        self.assertEqual(set(rules["outcome_vocabulary"]), set(model.OUTCOMES))
        self.assertEqual(rules["not_confirmed"], list(model.NOT_CONFIRMED))

    def test_analysis_publishes_no_subscriber_identity(self) -> None:
        analysis = EXAMPLES / "expected-session-analysis.json"
        text = analysis.read_text(encoding="utf-8")
        for forbidden in ("460020000000001", "1122334455667788", "919000001", "internet", "10.45.0.7"):
            self.assertNotIn(forbidden, text)


class ModelUnitTests(unittest.TestCase):
    def test_interface_resolution_prefers_control_plane_f_teid(self) -> None:
        request = event(1, 32, "create-session", teid_state="ZERO", teid=0, f_teids=[control_fteid(10, 6)])
        evidence = model.interface_evidence(request, None, {})
        self.assertEqual(evidence["interface"], "S11")
        self.assertEqual(evidence["basis"], "control_plane_f_teid_in_message")

    def test_interface_resolution_uses_teid_continuity(self) -> None:
        request = event(9, 34, "modify-bearer", teid=969)
        evidence = model.interface_evidence(request, None, {969: {"S11"}})
        self.assertEqual(evidence["interface"], "S11")
        self.assertEqual(evidence["basis"], "control_plane_teid_continuity")

    def test_conflicting_control_teids_are_not_guessed(self) -> None:
        request = event(
            1,
            32,
            "create-session",
            teid_state="ZERO",
            teid=0,
            f_teids=[control_fteid(10, 6), control_fteid(6, 3051)],
        )
        evidence = model.interface_evidence(request, None, {})
        self.assertEqual(evidence["interface"], "UNKNOWN_INTERFACE")
        self.assertEqual(evidence["basis"], "conflicting_control_plane_f_teids")

    def test_transport_address_alone_never_identifies_an_interface(self) -> None:
        request = event(1, 36, "delete-session", teid=64)
        request["source"] = {"address": "127.0.0.2", "port": 2123}
        request["destination"] = {"address": "127.0.0.3", "port": 2123}
        evidence = model.interface_evidence(request, None, {})
        self.assertEqual(evidence["interface"], "UNKNOWN_INTERFACE")
        self.assertEqual(evidence["basis"], "unavailable")

    def test_outcome_vocabulary_is_exhaustive(self) -> None:
        self.assertEqual(
            set(model.OUTCOMES),
            {
                "RESPONSE_ACCEPTED_OBSERVED",
                "RESPONSE_REJECTED_OBSERVED",
                "RESPONSE_OUTCOME_UNKNOWN",
                "OPEN_REQUEST",
                "RESPONSE_ONLY",
                "AMBIGUOUS_TRANSACTION",
            },
        )

    def test_release_access_bearers_codes_are_170_and_171(self) -> None:
        self.assertEqual(model.FAMILY_ORDER.count("release-access-bearers"), 1)
        self.assertEqual(model.FAMILY_LABELS["release-access-bearers"], "Release Access Bearers")


if __name__ == "__main__":
    unittest.main()
