#!/usr/bin/env python3
"""Deterministic tests for the bounded IMS media signaling Domain Skill."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:
    jsonschema = None

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
CLI = SCRIPTS / "analyze-ims-media-signaling.py"
SCHEMA = SKILL / "schemas" / "ims-media-signaling-analysis.schema.json"
TEST_DIR = Path(__file__).resolve().parent
for path in (SCRIPTS, TEST_DIR, SKILL.parents[1] / "protocol" / "sdp-rtp" / "scripts"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import ims_media_signaling_model  # noqa: E402
import media_fixture_builder as builder  # noqa: E402
import sdp_model  # noqa: E402

PRIVATE_TOKENS = (
    "sip:caller@example.com",
    "sip:callee@example.com",
    "192.0.2.10",
    "192.0.2.20",
    "PRIVATE-CALLID",
    "PRIVATE-FTAG",
    "PRIVATE-TTAG",
)


def analyze(
    records=None,
    *,
    sdp_records=None,
    session_mutation=None,
    sdp_mutation=None,
    raw_events=None,
) -> tuple[int, dict | None, str, dict]:
    directory = Path(tempfile.mkdtemp())
    paths = builder.write_inputs(
        directory,
        records if records is not None else builder.build_records(),
        sdp_records=sdp_records,
        session_mutation=session_mutation,
        sdp_mutation=sdp_mutation,
    )
    if raw_events is not None:
        paths["events"].write_text(raw_events, encoding="utf-8")
    output = directory / "analysis.json"
    report = directory / "report.txt"
    completed = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "--sip-events",
            str(paths["events"]),
            "--ims-session",
            str(paths["session"]),
            "--sdp-analysis",
            str(paths["sdp"]),
            "--output",
            str(output),
            "--report",
            str(report),
            "--force",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    document = json.loads(output.read_text(encoding="utf-8")) if output.is_file() else None
    report_text = report.read_text(encoding="utf-8") if report.is_file() else ""
    return completed.returncode, document, report_text, paths


def exchanges(document: dict, exchange_type: str | None = None) -> list[dict]:
    items = document["exchanges"]
    if exchange_type is not None:
        items = [item for item in items if item["exchange_type"] == exchange_type]
    return items


def observations(document: dict, reason: str | None = None) -> list[dict]:
    items = document["unbound_observations"]
    if reason is not None:
        items = [item for item in items if item["reason_code"] == reason]
    return items


def sdp_message(document: dict, reference: str) -> dict:
    for message in document["messages"]:
        if message["source_reference"] == reference:
            return message
    raise AssertionError(f"SDP message not found: {reference}")


class ProvenanceTests(unittest.TestCase):
    def test_01_exact_sip_event_sdp_reference_match(self) -> None:
        code, document, _report, _paths = analyze()
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "ESTABLISHED")
        self.assertEqual(pair["offer_sdp_reference"], pair["offer_event_reference"])

    def test_02_same_capture_different_message_occurrence(self) -> None:
        records = builder.build_records()
        paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
        offer_reference = paths["event_references"][0]
        sdp_records = [
            builder.sdp_record(
                offer_reference,
                1,
                2,
                builder.AUDIO_OFFER,
            )
        ]
        code, document, _report, _paths = analyze(records, sdp_records=sdp_records)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_03_same_frame_with_different_message_occurrence(self) -> None:
        records = builder.build_records()
        paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
        offer_reference = paths["event_references"][0]
        foreign_reference = offer_reference.rsplit(".", 1)[0] + ".2"
        sdp_records = [
            builder.sdp_record(foreign_reference, 1, 2, builder.AUDIO_OFFER)
        ]
        code, document, _report, _paths = analyze(records, sdp_records=sdp_records)
        self.assertEqual(code, 0)
        self.assertIn("SIP_EVENT_NOT_FOUND", [item["reason_code"] for item in observations(document)])
        for exchange in document["exchanges"]:
            self.assertNotEqual(exchange["association_status"], "ESTABLISHED")

    def test_04_cross_capture_rejection(self) -> None:
        records = builder.build_records()
        paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
        offer_reference = paths["event_references"][0]
        sdp_records = [
            builder.sdp_record(
                offer_reference, 1, 1, builder.AUDIO_OFFER, capture="other-capture.pcapng"
            )
        ]
        code, document, _report, _paths = analyze(records, sdp_records=sdp_records)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_05_duplicate_sip_event_references(self) -> None:
        records = builder.build_records()
        directory = Path(tempfile.mkdtemp())
        paths = builder.write_inputs(directory, records)
        events = [json.loads(line) for line in paths["events"].read_text(encoding="utf-8").splitlines()]
        raw = "\n".join(json.dumps(item, separators=(",", ":"), sort_keys=True) for item in events + [events[0]]) + "\n"
        code, document, _report, _paths = analyze(records, raw_events=raw)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_06_duplicate_sdp_references(self) -> None:
        def mutate(document: dict) -> None:
            document["messages"].append(copy.deepcopy(document["messages"][0]))
            document["message_count"] = len(document["messages"])

        code, document, _report, _paths = analyze(sdp_mutation=mutate)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_07_ims_session_event_sha_mismatch(self) -> None:
        def mutate(document: dict) -> None:
            document["input_provenance"]["event_sha256"] = "0" * 64

        code, document, _report, _paths = analyze(session_mutation=mutate)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_08_ims_session_capture_mismatch(self) -> None:
        def mutate(document: dict) -> None:
            document["input_provenance"]["capture_files"] = ["other.pcapng"]

        code, document, _report, _paths = analyze(session_mutation=mutate)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_09_sdp_capture_mismatch(self) -> None:
        def mutate(document: dict) -> None:
            document["input_provenance"]["capture_files"] = ["other.pcapng"]

        code, document, _report, _paths = analyze(sdp_mutation=mutate)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_10_missing_source_event(self) -> None:
        def mutate(document: dict) -> None:
            attempt = document["session_attempts"][0]
            attempt["initial_invite_event_reference"] = "sip-event:missing.pcapng:999.1"

        code, document, _report, _paths = analyze(session_mutation=mutate)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_11_frame_only_attempted_association(self) -> None:
        records = builder.build_records()
        paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
        offer_reference = paths["event_references"][0]
        foreign_reference = "sdp-message:" + offer_reference.split(":", 1)[1]
        sdp_records = [builder.sdp_record(foreign_reference, 1, 1, builder.AUDIO_OFFER)]
        code, document, _report, _paths = analyze(records, sdp_records=sdp_records)
        self.assertEqual(code, 0)
        self.assertIn("SIP_EVENT_NOT_FOUND", [item["reason_code"] for item in observations(document)])
        for exchange in document["exchanges"]:
            self.assertNotEqual(exchange["association_status"], "ESTABLISHED")

    def test_12_timestamp_only_attempted_association(self) -> None:
        records = builder.build_records()
        paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
        offer_reference = paths["event_references"][0]
        foreign_reference = offer_reference.rsplit(":", 1)[0] + ":900.1"
        sdp_records = [builder.sdp_record(foreign_reference, 900, 1, builder.AUDIO_OFFER)]
        code, document, _report, _paths = analyze(records, sdp_records=sdp_records)
        self.assertEqual(code, 0)
        self.assertIn("SIP_EVENT_NOT_FOUND", [item["reason_code"] for item in observations(document)])
        self.assertFalse(exchanges(document, "INITIAL_INVITE_OFFER_ANSWER"))

    def test_13_wrong_content_type(self) -> None:
        records = [
            builder.rec(
                1,
                method="INVITE",
                sdp_body=builder.AUDIO_OFFER,
                content_type="application/3gpp-ims+xml",
            ),
            builder.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1"),
        ]
        paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
        offer_reference = paths["event_references"][0]
        sdp_records = [builder.sdp_record(offer_reference, 1, 1, builder.AUDIO_OFFER)]
        code, document, _report, _paths = analyze(records, sdp_records=sdp_records)
        self.assertEqual(code, 0)
        self.assertIn("SIP_CONTENT_TYPE_NOT_SDP", [item["reason_code"] for item in observations(document)])

    def test_14_missing_sip_body(self) -> None:
        records = [
            builder.rec(1, method="INVITE"),
            builder.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1"),
        ]
        paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
        offer_reference = paths["event_references"][0]
        sdp_records = [builder.sdp_record(offer_reference, 1, 1, builder.AUDIO_OFFER)]
        code, document, _report, _paths = analyze(records, sdp_records=sdp_records)
        self.assertEqual(code, 0)
        self.assertIn("SDP_SOURCE_REFERENCE_MISMATCH", [item["reason_code"] for item in observations(document)])
        unusable = exchanges(document, "INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE")
        self.assertEqual(unusable[0]["initial_sdp_state"], "UNRESOLVED")
        self.assertEqual(unusable[0]["association_status"], "INSUFFICIENT_EVIDENCE")

    def test_15_incomplete_sip_message(self) -> None:
        records = [
            builder.rec(1, method="INVITE", sdp_body=builder.AUDIO_OFFER, truncated=True),
            builder.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1"),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        statuses = [item["association_status"] for item in document["exchanges"]]
        self.assertIn("INSUFFICIENT_EVIDENCE", statuses)
        self.assertNotIn("ESTABLISHED", statuses)

    def test_16_incomplete_sdp_analysis(self) -> None:
        def mutate(document: dict) -> None:
            target = document["messages"][0]
            target["evidence_status"] = "INCOMPLETE"

        code, document, _report, _paths = analyze(sdp_mutation=mutate)
        self.assertEqual(code, 0)
        self.assertIn("SDP_MESSAGE_INCOMPLETE", [item["reason_code"] for item in document["unbound_observations"]])
        for exchange in document["exchanges"]:
            self.assertNotEqual(exchange["association_status"], "ESTABLISHED")


class InitialOfferAnswerTests(unittest.TestCase):
    def test_17_invite_offer_and_200_answer(self) -> None:
        code, document, _report, _paths = analyze()
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "ESTABLISHED")
        self.assertEqual(pair["negotiation_compatibility"], "NOT_EVALUATED")

    def test_18_provisional_responses_without_sdp(self) -> None:
        code, document, _report, _paths = analyze()
        self.assertEqual(code, 0)
        self.assertFalse(
            any(item["observation_type"] == "PROVISIONAL_SDP_UNINTERPRETED" for item in document["unbound_observations"])
        )
        self.assertEqual(exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]["association_status"], "ESTABLISHED")

    def test_19_invite_without_sdp(self) -> None:
        records = [
            builder.rec(1, method="INVITE"),
            builder.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1"),
            builder.rec(3, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        self.assertTrue(exchanges(document, "INITIAL_INVITE_WITHOUT_SDP"))
        for exchange in document["exchanges"]:
            self.assertNotEqual(exchange["association_status"], "ESTABLISHED")

    def test_20_offer_without_final_sdp_answer(self) -> None:
        records = [
            builder.rec(1, method="INVITE", sdp_body=builder.AUDIO_OFFER),
            builder.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1"),
            builder.rec(3, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("SDP_ANSWER_NOT_OBSERVED", pair["missing_evidence"])

    def test_21_invalid_sdp_offer(self) -> None:
        def mutate(document: dict) -> None:
            document["messages"][0]["evidence_status"] = "INVALID"

        code, document, _report, _paths = analyze(sdp_mutation=mutate)
        self.assertEqual(code, 0)
        for exchange in document["exchanges"]:
            self.assertNotEqual(exchange["association_status"], "ESTABLISHED")

    def test_22_invalid_sdp_answer(self) -> None:
        def mutate(document: dict) -> None:
            document["messages"][1]["evidence_status"] = "INVALID"

        code, document, _report, _paths = analyze(sdp_mutation=mutate)
        self.assertEqual(code, 0)
        self.assertEqual(
            exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]["association_status"],
            "INSUFFICIENT_EVIDENCE",
        )

    def test_23_unsupported_sdp_message(self) -> None:
        def mutate(document: dict) -> None:
            document["messages"][0]["evidence_status"] = "UNSUPPORTED"

        code, document, _report, _paths = analyze(sdp_mutation=mutate)
        self.assertEqual(code, 0)
        self.assertIn("SDP_MESSAGE_UNSUPPORTED", [item["reason_code"] for item in document["unbound_observations"]])

    def test_24_non_2xx_final_response_with_sdp(self) -> None:
        records = [
            builder.rec(1, method="INVITE", sdp_body=builder.AUDIO_OFFER),
            builder.rec(2, status=486, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(3, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        self.assertIn(
            "NON_2XX_FINAL_SDP_OUT_OF_SCOPE",
            [item["reason_code"] for item in document["unbound_observations"]],
        )
        self.assertFalse(exchanges(document, "INITIAL_INVITE_OFFER_ANSWER"))


class ForkingTests(unittest.TestCase):
    def test_25_one_invite_two_accepted_branches(self) -> None:
        code, document, _report, _paths = analyze(builder.fork_records())
        self.assertEqual(code, 0)
        pairs = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")
        self.assertEqual(len(pairs), 2)
        self.assertTrue(all(item["association_status"] == "ESTABLISHED" for item in pairs))

    def test_26_each_branch_has_its_own_answer(self) -> None:
        _code, document, _report, _paths = analyze(builder.fork_records())
        answers = [item["answer_sdp_reference"] for item in exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")]
        self.assertEqual(len(set(answers)), 2)

    def test_27_mixed_accepted_and_rejected_forks(self) -> None:
        records = [
            builder.rec(1, method="INVITE", sdp_body=builder.AUDIO_OFFER),
            builder.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(3, status=486, cseq_method="INVITE", to_tag="TT-2", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(4, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        self.assertEqual(
            exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]["association_status"], "ESTABLISHED"
        )
        self.assertIn(
            "NON_2XX_FINAL_SDP_OUT_OF_SCOPE",
            [item["reason_code"] for item in document["unbound_observations"]],
        )

    def test_28_missing_confirmed_dialog(self) -> None:
        def mutate(document: dict) -> None:
            for attempt in document["session_attempts"]:
                for branch in attempt["branches"]:
                    branch["dialog_reference"] = None
                    branch["identity_status"] = "INSUFFICIENT_EVIDENCE"

        code, document, _report, _paths = analyze(session_mutation=mutate)
        self.assertEqual(code, 0)
        self.assertTrue(all(item["dialog_reference"] is None for item in document["exchanges"]))
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("DIALOG_IDENTITY_NOT_ESTABLISHED", pair["missing_evidence"])
        self.assertEqual(pair["answer_event_reference"], None)
        self.assertEqual(pair["answer_role"], None)

    def test_29_missing_branch_identity(self) -> None:
        def mutate(document: dict) -> None:
            for attempt in document["session_attempts"]:
                for branch in attempt["branches"]:
                    branch.pop("branch_reference", None)

        code, document, _report, _paths = analyze(session_mutation=mutate)
        self.assertEqual(code, 0)
        self.assertTrue(all(item["branch_reference"] is None for item in document["exchanges"]))
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("BRANCH_REFERENCE_MISSING", pair["missing_evidence"])

    def test_30_competing_sdp_response_candidates(self) -> None:
        records = [
            builder.rec(1, method="INVITE", sdp_body=builder.AUDIO_OFFER),
            builder.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(3, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(4, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        self.assertTrue(
            any(item["association_status"] == "AMBIGUOUS" for item in exchanges(document))
        )
        self.assertIn(
            "COMPETING_SDP_CANDIDATES",
            [finding for item in exchanges(document) for finding in item["conflict_findings"]],
        )

    def test_31_two_initial_invites_sharing_call_id(self) -> None:
        records = [
            builder.rec(1, method="INVITE", call_id="SHARED", branch="z9hG4bK-A", sdp_body=builder.AUDIO_OFFER),
            builder.rec(2, status=200, cseq_method="INVITE", call_id="SHARED", branch="z9hG4bK-A", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(3, method="ACK", call_id="SHARED", branch="z9hG4bK-A", cseq=1, to_tag="TT-1"),
            builder.rec(4, method="INVITE", call_id="SHARED", branch="z9hG4bK-B", sdp_body=builder.AUDIO_OFFER),
            builder.rec(5, status=200, cseq_method="INVITE", call_id="SHARED", branch="z9hG4bK-B", to_tag="TT-2", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(6, method="ACK", call_id="SHARED", branch="z9hG4bK-B", cseq=1, to_tag="TT-2"),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        self.assertEqual(len(document["input_provenance"]["capture_files"]), 1)
        pairs = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")
        self.assertEqual(len(pairs), 2)
        self.assertEqual(len({item["attempt_reference"] for item in pairs}), 2)

    def test_32_no_cross_branch_answer_assignment(self) -> None:
        _code, document, _report, _paths = analyze(builder.fork_records())
        session = json.loads(_paths["session"].read_text(encoding="utf-8"))
        branch_answers: dict[str, set[str]] = {}
        for attempt in session["session_attempts"]:
            for branch in attempt["branches"]:
                branch_answers[branch["branch_reference"]] = set(
                    branch.get("response_event_references") or []
                )
        for exchange in exchanges(document, "INITIAL_INVITE_OFFER_ANSWER"):
            self.assertIn(
                exchange["answer_event_reference"],
                branch_answers[exchange["branch_reference"]],
            )


class LateOfferTests(unittest.TestCase):
    def test_33_invite_without_sdp_and_200_offer(self) -> None:
        code, document, _report, _paths = analyze(builder.late_offer_records())
        self.assertEqual(code, 0)
        late = exchanges(document, "LATE_OFFER_ANSWER")[0]
        self.assertEqual(late["association_status"], "ESTABLISHED")

    def test_34_matching_2xx_ack_carries_answer(self) -> None:
        _code, document, _report, _paths = analyze(builder.late_offer_records())
        late = exchanges(document, "LATE_OFFER_ANSWER")[0]
        self.assertEqual(late["answer_event_reference"], late["answer_sdp_reference"])
        self.assertEqual(late["answer_role"], "ANSWERER")

    def test_35_late_offer_without_observed_ack(self) -> None:
        records = [
            builder.rec(1, method="INVITE"),
            builder.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_OFFER),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        late = exchanges(document, "LATE_OFFER_ANSWER")[0]
        self.assertEqual(late["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("LATE_OFFER_ACK_NOT_OBSERVED", late["missing_evidence"])

    def test_36_ack_without_sdp(self) -> None:
        records = builder.late_offer_records()
        records[3] = builder.rec(4, method="ACK", cseq=1, to_tag="TT-1")
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        late = exchanges(document, "LATE_OFFER_ANSWER")[0]
        self.assertEqual(late["association_status"], "INSUFFICIENT_EVIDENCE")

    def test_37_ack_with_invalid_sdp(self) -> None:
        def mutate(document: dict) -> None:
            document["messages"][1]["evidence_status"] = "INVALID"

        code, document, _report, _paths = analyze(builder.late_offer_records(), sdp_mutation=mutate)
        self.assertEqual(code, 0)
        self.assertEqual(
            exchanges(document, "LATE_OFFER_ANSWER")[0]["association_status"],
            "INSUFFICIENT_EVIDENCE",
        )

    def test_38_multiple_competing_ack_candidates(self) -> None:
        records = builder.late_offer_records() + [
            builder.rec(5, method="ACK", cseq=1, to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
        ]

        def mutate(document: dict) -> None:
            branch = document["session_attempts"][0]["branches"][0]
            branch["ack_event_references"] = [
                f"sip-event:{builder.CAPTURE}:4.1",
                f"sip-event:{builder.CAPTURE}:5.1",
            ]

        code, document, _report, _paths = analyze(records, session_mutation=mutate)
        self.assertEqual(code, 0)
        self.assertEqual(exchanges(document, "LATE_OFFER_ANSWER")[0]["association_status"], "AMBIGUOUS")

    def test_39_ack_belonging_to_another_branch(self) -> None:
        records = [
            builder.rec(1, method="INVITE"),
            builder.rec(2, status=180, cseq_method="INVITE", to_tag="TT-1"),
            builder.rec(3, status=180, cseq_method="INVITE", to_tag="TT-2"),
            builder.rec(4, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_OFFER),
            builder.rec(5, status=200, cseq_method="INVITE", to_tag="TT-2", sdp_body=builder.AUDIO_OFFER),
            builder.rec(6, method="ACK", cseq=1, to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        late = exchanges(document, "LATE_OFFER_ANSWER")
        self.assertEqual(len(late), 2)
        statuses = sorted(item["association_status"] for item in late)
        self.assertEqual(statuses, ["ESTABLISHED", "INSUFFICIENT_EVIDENCE"])


class ProvisionalAndOutOfScopeTests(unittest.TestCase):
    def test_40_183_with_sdp(self) -> None:
        records = [
            builder.rec(1, method="INVITE", sdp_body=builder.AUDIO_OFFER),
            builder.rec(2, status=183, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(3, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(4, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        provisional = [item for item in document["unbound_observations"] if item["observation_type"] == "PROVISIONAL_SDP_UNINTERPRETED"]
        self.assertTrue(provisional)
        self.assertEqual(provisional[0]["association_status"], "OUT_OF_SCOPE")
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "AMBIGUOUS")
        self.assertIn("PROVISIONAL_FINAL_SDP_ROLE_UNRESOLVED", pair["conflict_findings"])
        self.assertFalse(pair["answer_role"] == "ANSWERER")

    def test_41_180_with_sdp(self) -> None:
        records = [
            builder.rec(1, method="INVITE", sdp_body=builder.AUDIO_OFFER),
            builder.rec(2, status=180, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(3, status=200, cseq_method="INVITE", to_tag="TT-1"),
            builder.rec(4, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        self.assertIn(
            "PROVISIONAL_SDP_RELIABILITY_NOT_PROVEN",
            [item["reason_code"] for item in document["unbound_observations"]],
        )
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIsNone(pair["answer_sdp_reference"])

    def test_42_prack_with_sdp(self) -> None:
        records = builder.build_records() + [
            builder.rec(6, method="PRACK", cseq=2, cseq_method="PRACK", to_tag="TT-1", sdp_body=builder.AUDIO_OFFER),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        self.assertIn(
            "IN_DIALOG_SDP_OUT_OF_SCOPE",
            [item["reason_code"] for item in document["unbound_observations"]],
        )

    def test_43_re_invite_with_sdp(self) -> None:
        records = builder.build_records() + [
            builder.rec(6, method="INVITE", cseq=2, to_tag="TT-1", sdp_body=builder.AUDIO_OFFER),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        self.assertIn(
            "IN_DIALOG_SDP_OUT_OF_SCOPE",
            [item["reason_code"] for item in document["unbound_observations"]],
        )
        self.assertFalse(
            any(item["exchange_type"] == "INITIAL_INVITE_OFFER_ANSWER" and item["offer_event_reference"].endswith("6.1") for item in document["exchanges"])
        )

    def test_44_update_with_sdp(self) -> None:
        records = builder.build_records() + [
            builder.rec(6, method="UPDATE", cseq=2, to_tag="TT-1", sdp_body=builder.AUDIO_OFFER),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        self.assertIn(
            "IN_DIALOG_SDP_OUT_OF_SCOPE",
            [item["reason_code"] for item in document["unbound_observations"]],
        )

    def test_45_info_with_sdp_content(self) -> None:
        records = builder.build_records() + [
            builder.rec(6, method="INFO", cseq=2, to_tag="TT-1", sdp_body=builder.AUDIO_OFFER),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        self.assertIn(
            "IN_DIALOG_SDP_OUT_OF_SCOPE",
            [item["reason_code"] for item in document["unbound_observations"]],
        )

    def test_46_sdp_with_unrecognized_sip_role(self) -> None:
        records = [
            builder.rec(1, method="INVITE"),
            builder.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_OFFER),
        ]
        paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
        stray_reference = f"sdp-analysis:{builder.CAPTURE}:99.1"
        sdp_records = [
            builder.sdp_record(paths["event_references"][1], 2, 1, builder.AUDIO_OFFER),
            builder.sdp_record(stray_reference, 99, 1, builder.AUDIO_OFFER),
        ]
        code, document, _report, _paths = analyze(records, sdp_records=sdp_records)
        self.assertEqual(code, 0)
        self.assertIn("SIP_EVENT_NOT_FOUND", [item["reason_code"] for item in observations(document)])


class OutputIntegrityTests(unittest.TestCase):
    def test_47_evidence_classification(self) -> None:
        _code, document, _report, _paths = analyze()
        for exchange in document["exchanges"]:
            self.assertEqual(exchange["evidence_class"], "DERIVED")
            self.assertEqual(exchange["negotiation_compatibility"], "NOT_EVALUATED")
        self.assertNotIn("CALL_SUCCESS", document["not_confirmed"])

    def test_48_count_conservation(self) -> None:
        _code, document, _report, _paths = analyze()
        completeness = document["completeness"]
        self.assertEqual(
            completeness["supplied_sdp_message_count"],
            completeness["matched_sip_event_count"] + completeness["unmatched_sdp_message_count"],
        )
        self.assertEqual(
            completeness["established_exchange_count"]
            + completeness["incomplete_exchange_count"]
            + completeness["ambiguous_exchange_count"]
            + completeness["not_established_exchange_count"],
            len(document["exchanges"]),
        )

    def test_49_output_schema_validation(self) -> None:
        if jsonschema is None:
            self.skipTest("jsonschema is unavailable")
        _code, document, _report, _paths = analyze()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        jsonschema.validate(document, schema)

    def test_50_raw_sdp_privacy(self) -> None:
        _code, document, report, _paths = analyze()
        text = json.dumps(document) + report
        self.assertNotIn("v=0", text)
        self.assertNotIn("m=audio", text)
        self.assertNotIn("a=rtpmap", text)
        self.assertNotIn("sdp_body", text)

    def test_51_raw_sip_body_privacy(self) -> None:
        _code, document, report, _paths = analyze()
        text = json.dumps(document) + report
        for token in PRIVATE_TOKENS:
            self.assertNotIn(token, text)
        for field in ('"call_id"', '"from_tag"', '"to_tag"', '"request_uri"', '"sip_uri"'):
            self.assertNotIn(field, text)

    def test_52_deterministic_replay(self) -> None:
        directory = Path(tempfile.mkdtemp())
        paths = builder.write_inputs(directory, builder.build_records())
        outputs = []
        for name in ("first.json", "second.json"):
            output = directory / name
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "--sip-events",
                    str(paths["events"]),
                    "--ims-session",
                    str(paths["session"]),
                    "--sdp-analysis",
                    str(paths["sdp"]),
                    "--output",
                    str(output),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0)
            outputs.append(output.read_bytes())
        self.assertEqual(outputs[0], outputs[1])

    def test_53_bounded_output_behavior(self) -> None:
        records = builder.build_records()
        paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
        extra = [
            builder.sdp_record(f"sdp-extra:{builder.CAPTURE}:{100 + index}.1", 100 + index, 1, builder.AUDIO_OFFER)
            for index in range(80)
        ]
        sdp_records = [
            builder.sdp_record(reference, 1, 1, builder.AUDIO_OFFER)
            for reference in paths["event_references"][:1]
        ] + extra
        code, document, _report, _paths = analyze(records, sdp_records=sdp_records)
        self.assertEqual(code, 0)
        self.assertEqual(document["unbound_observation_count"], 64)
        self.assertGreater(document["completeness"]["omitted_observation_count"], 0)

    def test_54_expected_output_stability(self) -> None:
        input_directory = SKILL / "examples" / "inputs"
        expected = SKILL / "examples" / "expected"
        directory = Path(tempfile.mkdtemp())
        output = directory / "analysis.json"
        report = directory / "report.txt"
        completed = subprocess.run(
            [
                sys.executable,
                str(CLI),
                "--sip-events",
                str(input_directory / "media-cases-events.jsonl"),
                "--ims-session",
                str(input_directory / "media-cases-ims-session.json"),
                "--sdp-analysis",
                str(input_directory / "media-cases-sdp-analysis.json"),
                "--output",
                str(output),
                "--report",
                str(report),
                "--force",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(output.read_bytes(), (expected / "media-analysis.json").read_bytes())
        self.assertEqual(report.read_bytes(), (expected / "media-report.txt").read_bytes())


def run_existing(paths: dict) -> tuple[subprocess.CompletedProcess, dict | None]:
    directory = paths["events"].parent
    output = directory / "rerun-analysis.json"
    report = directory / "rerun-report.txt"
    completed = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "--sip-events",
            str(paths["events"]),
            "--ims-session",
            str(paths["session"]),
            "--sdp-analysis",
            str(paths["sdp"]),
            "--output",
            str(output),
            "--report",
            str(report),
            "--force",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    document = json.loads(output.read_text(encoding="utf-8")) if output.is_file() else None
    return completed, document


def rewrite_events(paths: dict, mutate) -> None:
    events = [json.loads(line) for line in paths["events"].read_text(encoding="utf-8").splitlines()]
    mutate(events)
    text = "\n".join(json.dumps(item, separators=(",", ":"), sort_keys=True) for item in events) + "\n"
    paths["events"].write_text(text, encoding="utf-8")
    session = json.loads(paths["session"].read_text(encoding="utf-8"))
    session["input_provenance"]["event_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    paths["session"].write_text(
        json.dumps(session, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


class CorrectedEvidenceIntegrityTests(unittest.TestCase):
    def test_55_ambiguous_branch_identity(self) -> None:
        def mutate(document: dict) -> None:
            for attempt in document["session_attempts"]:
                for branch in attempt["branches"]:
                    branch["identity_status"] = "AMBIGUOUS"

        code, document, _report, _paths = analyze(session_mutation=mutate)
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "AMBIGUOUS")
        self.assertIn("COMPETING_BRANCH_OWNERSHIP", pair["conflict_findings"])

    def test_56_insufficient_branch_identity(self) -> None:
        def mutate(document: dict) -> None:
            for attempt in document["session_attempts"]:
                for branch in attempt["branches"]:
                    branch["identity_status"] = "INSUFFICIENT_EVIDENCE"

        code, document, _report, _paths = analyze(session_mutation=mutate)
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("BRANCH_IDENTITY_NOT_ESTABLISHED", pair["missing_evidence"])

    def test_57_unproven_branch_response_ownership(self) -> None:
        def mutate(document: dict) -> None:
            for attempt in document["session_attempts"]:
                for branch in attempt["branches"]:
                    branch["response_event_references"] = []

        code, document, _report, _paths = analyze(session_mutation=mutate)
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("BRANCH_RESPONSE_OWNERSHIP_UNPROVEN", pair["missing_evidence"])

    def test_58_conflicting_branch_ownership_same_response(self) -> None:
        def mutate(document: dict) -> None:
            attempt = document["session_attempts"][0]
            first, second = attempt["branches"][0], attempt["branches"][1]
            second["response_event_references"] = list(first["response_event_references"])
            second["response_status_codes"] = list(first["response_status_codes"])

        code, document, _report, _paths = analyze(builder.fork_records(), session_mutation=mutate)
        self.assertEqual(code, 0)
        pairs = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")
        self.assertTrue(
            any("COMPETING_BRANCH_OWNERSHIP" in item["conflict_findings"] for item in pairs)
        )
        self.assertFalse(any(item["association_status"] == "ESTABLISHED" for item in pairs))

    def test_59_invalid_initial_sdp_never_establishes_late_offer(self) -> None:
        def mutate(document: dict) -> None:
            document["messages"][0]["evidence_status"] = "INVALID"

        code, document, _report, _paths = analyze(sdp_mutation=mutate)
        self.assertEqual(code, 0)
        unusable = exchanges(document, "INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE")
        self.assertEqual(unusable[0]["initial_sdp_state"], "OBSERVED_INVALID")
        self.assertFalse(exchanges(document, "LATE_OFFER_ANSWER"))
        self.assertFalse(any(item["association_status"] == "ESTABLISHED" for item in document["exchanges"]))

    def test_60_truncated_initial_sdp_never_establishes_late_offer(self) -> None:
        def mutate(document: dict) -> None:
            document["messages"][0]["evidence_status"] = "INCOMPLETE"

        code, document, _report, _paths = analyze(sdp_mutation=mutate)
        self.assertEqual(code, 0)
        unusable = exchanges(document, "INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE")
        self.assertEqual(unusable[0]["initial_sdp_state"], "OBSERVED_INCOMPLETE")
        self.assertFalse(any(item["association_status"] == "ESTABLISHED" for item in document["exchanges"]))

    def test_61_missing_initial_sdp_message_is_unresolved(self) -> None:
        records = [
            builder.rec(1, method="INVITE", sdp_body=builder.AUDIO_OFFER),
            builder.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(3, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
        answer_reference = paths["event_references"][1]
        sdp_records = [builder.sdp_record(answer_reference, 2, 1, builder.AUDIO_ANSWER)]
        code, document, _report, _paths = analyze(records, sdp_records=sdp_records)
        self.assertEqual(code, 0)
        unusable = exchanges(document, "INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE")
        self.assertEqual(unusable[0]["initial_sdp_state"], "UNRESOLVED")
        self.assertFalse(exchanges(document, "INITIAL_INVITE_WITHOUT_SDP"))

    def test_62_unsupported_initial_content_type_never_establishes_late_offer(self) -> None:
        records = [
            builder.rec(
                1,
                method="INVITE",
                sdp_body=builder.AUDIO_OFFER,
                content_type="application/3gpp-ims+xml",
            ),
            builder.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(3, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
        sdp_records = [
            builder.sdp_record(paths["event_references"][0], 1, 1, builder.AUDIO_OFFER),
            builder.sdp_record(paths["event_references"][1], 2, 1, builder.AUDIO_ANSWER),
        ]
        code, document, _report, _paths = analyze(records, sdp_records=sdp_records)
        self.assertEqual(code, 0)
        unusable = exchanges(document, "INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE")
        self.assertEqual(unusable[0]["initial_sdp_state"], "OUT_OF_SCOPE")
        self.assertEqual(unusable[0]["association_status"], "OUT_OF_SCOPE")
        self.assertFalse(exchanges(document, "LATE_OFFER_ANSWER"))

    def test_63_sdp_message_capture_sha_mismatch_rejected(self) -> None:
        def mutate(document: dict) -> None:
            document["messages"][0]["capture_sha256"] = "0" * 64

        code, document, _report, _paths = analyze(sdp_mutation=mutate)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_64_sdp_source_reference_frame_mismatch_rejected(self) -> None:
        def mutate(document: dict) -> None:
            document["messages"][0]["frame_number"] = document["messages"][0]["frame_number"] + 1

        code, document, _report, _paths = analyze(sdp_mutation=mutate)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_65_sdp_frame_reference_inconsistency_rejected(self) -> None:
        def mutate(document: dict) -> None:
            frame = document["messages"][0]["frame_number"]
            document["messages"][0]["frame_reference"] = f"frame-{frame + 50}"

        code, document, _report, _paths = analyze(sdp_mutation=mutate)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_66_response_with_wrong_cseq_method_is_not_an_invite_answer(self) -> None:
        records = builder.build_records() + [
            builder.rec(6, status=200, cseq_method="BYE", to_tag="TT-9", sdp_body=builder.AUDIO_ANSWER),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        self.assertFalse(
            any(
                item["association_status"] == "ESTABLISHED"
                and item["exchange_type"] == "INITIAL_INVITE_OFFER_ANSWER"
                and item["answer_event_reference"]
                and item["answer_event_reference"].endswith("6.1")
                for item in document["exchanges"]
            )
        )

    def test_67_invalid_response_message_type(self) -> None:
        directory = Path(tempfile.mkdtemp())
        paths = builder.write_inputs(directory, builder.build_records())

        def mutate(events: list) -> None:
            response = [item for item in events if item.get("status_code") == 200][0]
            response["message_type"] = "UNKNOWN"

        rewrite_events(paths, mutate)
        completed, document = run_existing(paths)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("RESPONSE_MESSAGE_TYPE_INVALID", pair["missing_evidence"])

    def test_68_invalid_response_status_validity(self) -> None:
        directory = Path(tempfile.mkdtemp())
        paths = builder.write_inputs(directory, builder.build_records())

        def mutate(events: list) -> None:
            response = [item for item in events if item.get("status_code") == 200][0]
            response["status_code_valid"] = False

        rewrite_events(paths, mutate)
        completed, document = run_existing(paths)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("RESPONSE_STATUS_INVALID", pair["missing_evidence"])

    def test_69_schema_rejects_established_without_branch_identity(self) -> None:
        if jsonschema is None:
            self.skipTest("jsonschema is unavailable")
        _code, document, _report, _paths = analyze()
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        broken = copy.deepcopy(document)
        for item in broken["exchanges"]:
            if item["exchange_reference"] == pair["exchange_reference"]:
                item["dialog_reference"] = None
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(broken, schema)

    def test_70_privacy_of_error_messages(self) -> None:
        directory = Path(tempfile.mkdtemp())
        paths = builder.write_inputs(directory, builder.build_records())
        session = json.loads(paths["session"].read_text(encoding="utf-8"))
        session["input_provenance"]["event_sha256"] = "0" * 64
        paths["session"].write_text(json.dumps(session, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        completed, document = run_existing(paths)
        self.assertEqual(completed.returncode, 2)
        self.assertIsNone(document)
        self.assertNotIn("sip:", completed.stderr)
        self.assertNotIn(str(directory), completed.stderr)

    def test_71_provisional_sdp_in_other_branch_does_not_block_answer(self) -> None:
        records = [
            builder.rec(1, method="INVITE", sdp_body=builder.AUDIO_OFFER),
            builder.rec(2, status=183, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(3, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(4, status=200, cseq_method="INVITE", to_tag="TT-2", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(5, method="ACK", cseq=1, to_tag="TT-1"),
            builder.rec(6, method="ACK", cseq=1, to_tag="TT-2"),
        ]
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        pairs = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")
        statuses = [item["association_status"] for item in pairs]
        self.assertIn("AMBIGUOUS", statuses)
        self.assertIn("ESTABLISHED", statuses)

def built_artifacts(records: list) -> tuple[dict, dict, dict]:
    paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
    dialogs = json.loads(paths["dialogs"].read_text(encoding="utf-8"))
    return paths, dialogs, paths["session_document"]


class HistoricalDialogConfirmationTests(unittest.TestCase):
    def test_72_terminated_builder_chain_is_genuinely_terminated(self) -> None:
        _paths, dialogs, session = built_artifacts(builder.terminated_records())
        self.assertEqual([item["dialog_state"] for item in dialogs["dialogs"]], ["TERMINATED"])
        attempt = session["session_attempts"][0]
        self.assertEqual(attempt["invite_outcome"], "ACCEPTED_2XX_OBSERVED")
        self.assertEqual(attempt["release_evidence"]["outcome"], "SIP_TERMINATION_SIGNALING_SUPPORTED")
        branch = attempt["branches"][0]
        self.assertEqual(branch["dialog_state"], "TERMINATED")
        self.assertEqual(branch["outcome"], "ACCEPTED_2XX")
        self.assertEqual(branch["release"]["outcome"], "SIP_TERMINATION_SIGNALING_SUPPORTED")
        self.assertIn(
            branch["dialog_reference"],
            branch["release"]["termination_supported_dialog_references"],
        )

    def test_73_confirmed_dialog_without_bye_keeps_association(self) -> None:
        _paths, dialogs, session = built_artifacts(builder.build_records())
        self.assertEqual(dialogs["dialogs"][0]["dialog_state"], "CONFIRMED")
        self.assertEqual(session["session_attempts"][0]["branches"][0]["dialog_state"], "CONFIRMED")
        code, document, _report, _paths = analyze(builder.build_records())
        self.assertEqual(code, 0)
        self.assertEqual(
            exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]["association_status"],
            "ESTABLISHED",
        )

    def test_74_historical_initial_association_survives_bye(self) -> None:
        code, document, _report, _paths = analyze(builder.terminated_records())
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "ESTABLISHED")
        self.assertEqual(pair["answer_event_reference"], "sip-event:synthetic-ims-media.pcapng:4.1")
        self.assertEqual(pair["answer_role"], "ANSWERER")
        self.assertEqual(pair["negotiation_compatibility"], "NOT_EVALUATED")
        for token in ("MEDIA_DELIVERY", "IMS_CALL_SUCCESS", "RTP_DELIVERY", "TWO_WAY_AUDIO"):
            self.assertIn(token, document["not_confirmed"])

    def test_75_historical_late_offer_association_survives_bye(self) -> None:
        _paths, dialogs, session = built_artifacts(builder.terminated_late_offer_records())
        self.assertEqual(dialogs["dialogs"][0]["dialog_state"], "TERMINATED")
        self.assertEqual(session["session_attempts"][0]["branches"][0]["dialog_state"], "TERMINATED")
        code, document, _report, _paths = analyze(builder.terminated_late_offer_records())
        self.assertEqual(code, 0)
        late = exchanges(document, "LATE_OFFER_ANSWER")[0]
        self.assertEqual(late["association_status"], "ESTABLISHED")
        self.assertEqual(late["answer_event_reference"], "sip-event:synthetic-ims-media.pcapng:4.1")

    def test_76_confirmed_dialog_with_bye_without_response_stays_confirmed(self) -> None:
        _paths, dialogs, session = built_artifacts(builder.unacknowledged_bye_records())
        self.assertEqual(dialogs["dialogs"][0]["dialog_state"], "CONFIRMED")
        self.assertIn("BYE_RESPONSE_NOT_OBSERVED", dialogs["dialogs"][0]["missing_evidence"])
        code, document, _report, _paths = analyze(builder.unacknowledged_bye_records())
        self.assertEqual(code, 0)
        self.assertEqual(
            exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]["association_status"],
            "ESTABLISHED",
        )

    def test_77_negative_bye_does_not_terminate_the_dialog(self) -> None:
        _paths, dialogs, session = built_artifacts(builder.negative_bye_records())
        self.assertEqual(dialogs["dialogs"][0]["dialog_state"], "CONFIRMED")
        branch = session["session_attempts"][0]["branches"][0]
        self.assertEqual(branch["release"]["outcome"], "BYE_NEGATIVE_RESPONSE_OBSERVED")
        self.assertEqual(branch["release"]["termination_supported_dialog_references"], [])
        code, document, _report, _paths = analyze(builder.negative_bye_records())
        self.assertEqual(code, 0)
        self.assertEqual(
            exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]["association_status"],
            "ESTABLISHED",
        )

    def test_78_terminated_without_confirming_2xx_is_insufficient(self) -> None:
        def mutate(document: dict) -> None:
            attempt = document["session_attempts"][0]
            branch = attempt["branches"][0]
            branch["dialog_state"] = "TERMINATED"
            branch["release"]["outcome"] = "SIP_TERMINATION_SIGNALING_SUPPORTED"
            branch["release"]["termination_supported_dialog_references"] = [branch["dialog_reference"]]
            attempt["release_evidence"]["outcome"] = "SIP_TERMINATION_SIGNALING_SUPPORTED"
            attempt["release_evidence"]["termination_supported_dialog_references"] = [
                branch["dialog_reference"]
            ]
            branch["response_event_references"] = [
                reference
                for reference in branch["response_event_references"]
                if reference.endswith(":3.1")
            ]
            branch["response_status_codes"] = [180]

        code, document, _report, _paths = analyze(
            builder.terminated_records(), session_mutation=mutate
        )
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("HISTORICAL_DIALOG_CONFIRMATION_UNPROVEN", pair["missing_evidence"])
        self.assertIsNone(pair["answer_event_reference"])

    def test_79_terminated_without_release_evidence_fails_closed(self) -> None:
        def mutate(document: dict) -> None:
            document["session_attempts"][0]["branches"][0]["dialog_state"] = "TERMINATED"

        code, document, _report, _paths = analyze(
            builder.build_records(), session_mutation=mutate
        )
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("SIP_TERMINATION_EVIDENCE_NOT_PROVEN", pair["missing_evidence"])
        self.assertIsNone(pair["answer_event_reference"])

    def test_80_foreign_dialog_termination_evidence_is_ambiguous(self) -> None:
        foreign = f"sip-dialog:{builder.CAPTURE}:1.1"

        def mutate(document: dict) -> None:
            attempt = document["session_attempts"][0]
            branch = attempt["branches"][0]
            branch["dialog_state"] = "TERMINATED"
            branch["release"]["outcome"] = "SIP_TERMINATION_SIGNALING_SUPPORTED"
            branch["release"]["termination_supported_dialog_references"] = [foreign]
            attempt["release_evidence"]["outcome"] = "SIP_TERMINATION_SIGNALING_SUPPORTED"
            attempt["release_evidence"]["termination_supported_dialog_references"] = [foreign]

        code, document, _report, _paths = analyze(
            builder.terminated_records(), session_mutation=mutate
        )
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "AMBIGUOUS")
        self.assertIn("TERMINATION_EVIDENCE_DIALOG_MISMATCH", pair["conflict_findings"])
        self.assertIsNone(pair["answer_event_reference"])

    def test_81_forked_terminated_and_confirmed_branches_stay_independent(self) -> None:
        _paths, dialogs, session = built_artifacts(builder.forked_terminated_records())
        states = {item["dialog_reference"]: item["dialog_state"] for item in dialogs["dialogs"]}
        self.assertEqual(sorted(states.values()), ["CONFIRMED", "TERMINATED"])
        code, document, _report, _paths = analyze(builder.forked_terminated_records())
        self.assertEqual(code, 0)
        pairs = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")
        self.assertEqual(len(pairs), 2)
        self.assertTrue(all(item["association_status"] == "ESTABLISHED" for item in pairs))
        self.assertEqual(len({item["dialog_reference"] for item in pairs}), 2)
        self.assertEqual(len({item["answer_event_reference"] for item in pairs}), 2)

    def test_82_forked_accepted_and_negative_never_cross_assign_answers(self) -> None:
        records = [
            builder.rec(1, method="INVITE", sdp_body=builder.AUDIO_OFFER),
            builder.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(3, status=486, cseq_method="INVITE", to_tag="TT-2", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(4, method="ACK", cseq=1, to_tag="TT-1"),
            builder.rec(5, method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
            builder.rec(6, status=200, cseq_method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
        ]
        paths, _dialogs, session = built_artifacts(records)
        branch_responses = {
            branch["branch_reference"]: set(branch.get("response_event_references") or [])
            for attempt in session["session_attempts"]
            for branch in attempt["branches"]
        }
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        pairs = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0]["association_status"], "ESTABLISHED")
        self.assertIn(pairs[0]["answer_event_reference"], branch_responses[pairs[0]["branch_reference"]])
        self.assertIn(
            "NON_2XX_FINAL_SDP_OUT_OF_SCOPE",
            [item["reason_code"] for item in observations(document)],
        )

    def test_83_missing_dialog_reference_terminated_is_insufficient(self) -> None:
        def mutate(document: dict) -> None:
            branch = document["session_attempts"][0]["branches"][0]
            branch["dialog_reference"] = None
            branch["dialog_state"] = "TERMINATED"

        code, document, _report, _paths = analyze(
            builder.terminated_records(), session_mutation=mutate
        )
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("DIALOG_IDENTITY_NOT_ESTABLISHED", pair["missing_evidence"])
        self.assertIsNone(pair["dialog_reference"])

    def test_84_missing_branch_reference_terminated_is_insufficient(self) -> None:
        def mutate(document: dict) -> None:
            document["session_attempts"][0]["branches"][0].pop("branch_reference", None)

        code, document, _report, _paths = analyze(
            builder.terminated_records(), session_mutation=mutate
        )
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("BRANCH_REFERENCE_MISSING", pair["missing_evidence"])
        self.assertIsNone(pair["branch_reference"])

    def test_85_ambiguous_branch_ownership_terminated_stays_ambiguous(self) -> None:
        def mutate(document: dict) -> None:
            document["session_attempts"][0]["branches"][0]["identity_status"] = "AMBIGUOUS"

        code, document, _report, _paths = analyze(
            builder.terminated_records(), session_mutation=mutate
        )
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "AMBIGUOUS")
        self.assertIn("COMPETING_BRANCH_OWNERSHIP", pair["conflict_findings"])

    def test_86_competing_2xx_sdp_answers_terminated_stays_ambiguous(self) -> None:
        records = [
            builder.rec(1, method="INVITE", sdp_body=builder.AUDIO_OFFER),
            builder.rec(2, status=180, cseq_method="INVITE", to_tag="TT-1"),
            builder.rec(3, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(4, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.AUDIO_ANSWER),
            builder.rec(5, method="ACK", cseq=1, to_tag="TT-1"),
            builder.rec(6, method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
            builder.rec(7, status=200, cseq_method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
        ]
        paths, dialogs, _session = built_artifacts(records)
        self.assertEqual(dialogs["dialogs"][0]["dialog_state"], "TERMINATED")
        code, document, _report, _paths = analyze(records)
        self.assertEqual(code, 0)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "AMBIGUOUS")
        self.assertIn("COMPETING_SDP_CANDIDATES", pair["conflict_findings"])
        self.assertIsNone(pair["answer_event_reference"])

    def test_87_invalid_response_role_terminated_never_establishes(self) -> None:
        directory = Path(tempfile.mkdtemp())
        paths = builder.write_inputs(directory, builder.terminated_records())

        def mutate(events: list) -> None:
            response = [item for item in events if item.get("status_code") == 200 and item.get("message_type") == "RESPONSE"][0]
            response["message_type"] = "UNKNOWN"

        rewrite_events(paths, mutate)
        completed, document = run_existing(paths)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        pair = exchanges(document, "INITIAL_INVITE_OFFER_ANSWER")[0]
        self.assertEqual(pair["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("RESPONSE_MESSAGE_TYPE_INVALID", pair["missing_evidence"])
        self.assertIsNone(pair["answer_event_reference"])

    def test_88_invalid_initial_sdp_terminated_never_establishes_late_offer(self) -> None:
        def mutate(document: dict) -> None:
            document["messages"][0]["evidence_status"] = "INVALID"

        code, document, _report, _paths = analyze(
            builder.terminated_records(), sdp_mutation=mutate
        )
        self.assertEqual(code, 0)
        self.assertFalse(exchanges(document, "LATE_OFFER_ANSWER"))
        self.assertFalse(any(item["association_status"] == "ESTABLISHED" for item in document["exchanges"]))

    def test_89_terminated_cross_capture_reference_is_rejected(self) -> None:
        records = builder.terminated_records()
        paths = builder.write_inputs(Path(tempfile.mkdtemp()), records)
        offer_reference = paths["event_references"][0]
        sdp_records = [
            builder.sdp_record(
                offer_reference, 1, 1, builder.AUDIO_OFFER, capture="other-capture.pcapng"
            )
        ]
        code, document, _report, _paths = analyze(records, sdp_records=sdp_records)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_90_terminated_duplicate_references_are_rejected(self) -> None:
        records = builder.terminated_records()
        directory = Path(tempfile.mkdtemp())
        paths = builder.write_inputs(directory, records)
        events = [json.loads(line) for line in paths["events"].read_text(encoding="utf-8").splitlines()]
        raw = "\n".join(
            json.dumps(item, separators=(",", ":"), sort_keys=True) for item in events + [events[0]]
        ) + "\n"
        code, document, _report, _paths = analyze(records, raw_events=raw)
        self.assertEqual(code, 2)
        self.assertIsNone(document)

    def test_91_terminated_privacy_and_deterministic_replay(self) -> None:
        directory = Path(tempfile.mkdtemp())
        paths = builder.write_inputs(directory, builder.terminated_records())
        outputs = []
        for name in ("terminated-first.json", "terminated-second.json"):
            output = directory / name
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "--sip-events",
                    str(paths["events"]),
                    "--ims-session",
                    str(paths["session"]),
                    "--sdp-analysis",
                    str(paths["sdp"]),
                    "--output",
                    str(output),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0)
            outputs.append(output.read_bytes())
        self.assertEqual(outputs[0], outputs[1])
        text = outputs[0].decode("utf-8")
        for token in PRIVATE_TOKENS:
            self.assertNotIn(token, text)
        for token in ("v=0", "m=audio", "a=rtpmap", "sdp_body", '"call_id"', '"to_tag"'):
            self.assertNotIn(token, text)

    def test_92_terminated_schema_and_completeness(self) -> None:
        if jsonschema is None:
            self.skipTest("jsonschema is unavailable")
        code, document, _report, _paths = analyze(builder.terminated_records())
        self.assertEqual(code, 0)
        jsonschema.validate(document, json.loads(SCHEMA.read_text(encoding="utf-8")))
        completeness = document["completeness"]
        self.assertEqual(
            completeness["established_exchange_count"]
            + completeness["incomplete_exchange_count"]
            + completeness["ambiguous_exchange_count"]
            + completeness["not_established_exchange_count"],
            len(document["exchanges"]),
        )
