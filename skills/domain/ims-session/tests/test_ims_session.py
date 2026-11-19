#!/usr/bin/env python3
"""Deterministic tests for the bounded IMS session Domain Skill."""

from __future__ import annotations

import copy
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
CLI = SCRIPTS / "analyze-ims-session.py"
SCHEMA = SKILL / "schemas" / "ims-session-analysis.schema.json"
TEST_DIR = Path(__file__).resolve().parent
for path in (SCRIPTS, TEST_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import ims_session_model  # noqa: E402
import session_fixture_builder as builder  # noqa: E402

PRIVATE_TOKENS = (
    "sip:caller@example.com",
    "sip:callee@example.com",
    "PRIVATE-CALLID-001",
    "z9hG4bK-PRIVATE-001",
    "PRIVATE-FTAG-001",
    "PRIVATE-TTAG-001",
)


def _write_artifacts(directory: Path, events, transactions, dialogs) -> tuple[Path, Path, Path]:
    event_path = directory / "events.jsonl"
    transaction_path = directory / "transactions.json"
    dialog_path = directory / "dialogs.json"
    event_path.write_text(
        "\n".join(json.dumps(event, separators=(",", ":"), sort_keys=True) for event in events)
        + "\n",
        encoding="utf-8",
    )
    transaction_path.write_text(
        json.dumps(transactions, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    dialog_path.write_text(
        json.dumps(dialogs, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return event_path, transaction_path, dialog_path


def analyze(
    records,
    *,
    mutate_transactions=None,
    mutate_dialogs=None,
    mutate_events=None,
) -> tuple[dict, str, str, int, str]:
    events, transactions, dialogs, _messages = builder.build_artifacts(records)
    if mutate_transactions is not None:
        mutate_transactions(transactions)
    if mutate_dialogs is not None:
        mutate_dialogs(dialogs)
    if mutate_events is not None:
        mutate_events(events)
    directory = Path(tempfile.mkdtemp())
    event_path, transaction_path, dialog_path = _write_artifacts(
        directory, events, transactions, dialogs
    )
    output = directory / "analysis.json"
    report = directory / "report.txt"
    completed = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "--sip-events",
            str(event_path),
            "--sip-transactions",
            str(transaction_path),
            "--sip-dialogs",
            str(dialog_path),
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
    document = json.loads(output.read_text(encoding="utf-8")) if output.is_file() else {}
    report_text = report.read_text(encoding="utf-8") if report.is_file() else ""
    return document, report_text, completed.stderr, completed.returncode, str(directory)


def attempt(document: dict, index: int = 0) -> dict:
    return document["session_attempts"][index]


def make_invite(
    frame: int,
    *,
    call_id: str = "CALL",
    branch: str = "z9hG4bK-A",
    cseq: int = 1,
    from_tag: str = "FT",
) -> dict:
    return builder.rec(
        frame, method="INVITE", call_id=call_id, branch=branch, cseq=cseq, from_tag=from_tag
    )


def make_response(
    frame: int,
    status: int,
    *,
    call_id: str = "CALL",
    branch: str = "z9hG4bK-A",
    cseq: int = 1,
    from_tag: str = "FT",
    to_tag: str = "T1",
    cseq_method: str = "INVITE",
) -> dict:
    return builder.rec(
        frame,
        status=status,
        call_id=call_id,
        branch=branch,
        cseq=cseq,
        cseq_method=cseq_method,
        from_tag=from_tag,
        to_tag=to_tag,
    )


def make_ack(
    frame: int,
    *,
    call_id: str = "CALL",
    branch: str = "z9hG4bK-A",
    cseq: int = 1,
    from_tag: str = "FT",
    to_tag: str = "T1",
) -> dict:
    return builder.rec(
        frame,
        method="ACK",
        call_id=call_id,
        branch=branch,
        cseq=cseq,
        cseq_method="ACK",
        from_tag=from_tag,
        to_tag=to_tag,
    )


def confirmed_call(
    start: int,
    *,
    call_id: str = "CALL",
    branch: str = "z9hG4bK-A",
) -> list[dict]:
    return [
        make_invite(start, call_id=call_id, branch=branch),
        make_response(start + 1, 200, call_id=call_id, branch=branch),
        make_ack(start + 2, call_id=call_id, branch=branch),
    ]


class ImsSessionEvidenceTests(unittest.TestCase):
    def run_valid(self, records, **kwargs) -> dict:
        document, _report, stderr, code, _directory = analyze(records, **kwargs)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(document["analysis_name"], "ims-session")
        return document

    def test_01_initial_invite_without_response(self) -> None:
        document = self.run_valid([make_invite(1)])
        item = attempt(document)
        self.assertEqual(item["invite_outcome"], "NO_RESPONSE_OBSERVED")
        self.assertEqual(item["branches"][0]["outcome"], "NO_FINAL_RESPONSE")
        self.assertIn("INVITE_FINAL_RESPONSE_NOT_OBSERVED", item["missing_evidence"])

    def test_02_invite_followed_by_100_trying(self) -> None:
        document = self.run_valid(
            [make_invite(1), make_response(2, 100, to_tag=None)]
        )
        item = attempt(document)
        self.assertEqual(item["stage_evidence"]["trying_100_event_references"], [
            "sip-event:synthetic-ims-session.pcapng:2.1"
        ])
        self.assertEqual(item["invite_outcome"], "PROVISIONAL_ONLY")

    def test_03_invite_followed_by_tagged_180(self) -> None:
        document = self.run_valid([make_invite(1), make_response(2, 180)])
        stage = attempt(document)["stage_evidence"]
        self.assertEqual(len(stage["ringing_180_event_references"]), 1)
        self.assertEqual(len(stage["early_dialog_references"]), 1)
        self.assertEqual(attempt(document)["branches"][0]["outcome"], "EARLY_ONLY")

    def test_04_invite_followed_by_tagged_183(self) -> None:
        document = self.run_valid([make_invite(1), make_response(2, 183)])
        stage = attempt(document)["stage_evidence"]
        self.assertEqual(len(stage["session_progress_183_event_references"]), 1)
        self.assertEqual(attempt(document)["branches"][0]["outcome"], "EARLY_ONLY")

    def test_05_invite_followed_by_200_without_provisional(self) -> None:
        document = self.run_valid(
            [make_invite(1), make_response(2, 200)]
        )
        item = attempt(document)
        self.assertEqual(item["invite_outcome"], "ACCEPTED_2XX_OBSERVED")
        self.assertEqual(item["branches"][0]["outcome"], "ACCEPTED_2XX")
        self.assertEqual(item["ack_evidence"]["status"], "MISSING_FOR_ACCEPTED_BRANCH")

    def test_06_invite_200_plus_associated_2xx_ack(self) -> None:
        document = self.run_valid(
            [make_invite(1), make_response(2, 200), make_ack(3)]
        )
        item = attempt(document)
        self.assertEqual(item["ack_evidence"]["status"], "OBSERVED_FOR_ALL_ACCEPTED_BRANCHES")
        self.assertEqual(len(item["ack_evidence"]["twoxx_ack_event_references"]), 1)

    def test_07_invite_200_without_ack_keeps_confirmed_dialog(self) -> None:
        document = self.run_valid([make_invite(1), make_response(2, 200)])
        branch = attempt(document)["branches"][0]
        self.assertEqual(branch["dialog_state"], "CONFIRMED")
        self.assertEqual(branch["ack_status"], "MISSING_FOR_ACCEPTED_BRANCH")
        self.assertIn("TWO_XX_ACK_NOT_OBSERVED", branch["missing_evidence"])

    def test_08_invite_non_2xx_final_response(self) -> None:
        document = self.run_valid([make_invite(1), make_response(2, 486)])
        item = attempt(document)
        self.assertEqual(item["invite_outcome"], "NEGATIVE_FINAL_OBSERVED")
        self.assertEqual(item["branches"][0]["outcome"], "NEGATIVE_FINAL")

    def test_09_non_2xx_ack_association(self) -> None:
        document = self.run_valid(
            [make_invite(1), make_response(2, 486), make_ack(3)]
        )
        item = attempt(document)
        self.assertTrue(item["ack_evidence"]["non_twoxx_ack_event_references"])
        self.assertEqual(item["ack_evidence"]["status"], "NOT_APPLICABLE")

    def test_10_one_invite_two_forked_branches(self) -> None:
        document = self.run_valid(
            [
                make_invite(1),
                make_response(2, 180, to_tag="TA"),
                make_response(3, 200, to_tag="TA"),
                make_response(4, 200, to_tag="TB"),
            ]
        )
        item = attempt(document)
        self.assertEqual(item["branch_count"], 2)
        self.assertEqual({branch["outcome"] for branch in item["branches"]}, {"ACCEPTED_2XX"})

    def test_11_multiple_2xx_responses_with_distinct_branches(self) -> None:
        document = self.run_valid(
            [
                make_invite(1),
                make_response(2, 200, to_tag="TA"),
                make_response(3, 200, to_tag="TB"),
            ]
        )
        item = attempt(document)
        self.assertEqual(len(item["stage_evidence"]["confirmed_dialog_references"]), 2)
        self.assertEqual(len({branch["dialog_reference"] for branch in item["branches"]}), 2)

    def test_12_one_accepted_and_one_rejected_branch(self) -> None:
        document = self.run_valid(
            [
                make_invite(1),
                make_response(2, 200, to_tag="TA"),
                make_response(3, 486, to_tag="TB"),
            ]
        )
        outcomes = {branch["outcome"] for branch in attempt(document)["branches"]}
        self.assertIn("ACCEPTED_2XX", outcomes)
        self.assertIn("NEGATIVE_FINAL", outcomes)

    def test_13_repeated_provisional_same_branch(self) -> None:
        document = self.run_valid(
            [
                make_invite(1),
                make_response(2, 180, to_tag="TA"),
                make_response(3, 180, to_tag="TA"),
                make_response(4, 200, to_tag="TA"),
            ]
        )
        item = attempt(document)
        self.assertEqual(len(item["stage_evidence"]["ringing_180_event_references"]), 2)
        self.assertEqual(item["branch_count"], 1)

    def test_14_cancel_without_final_response(self) -> None:
        document = self.run_valid(
            [
                make_invite(1),
                builder.rec(2, method="CANCEL", call_id="CALL", branch="z9hG4bK-A"),
            ]
        )
        cancel = attempt(document)["cancel_evidence"]
        self.assertEqual(cancel["outcome"], "CANCEL_REQUEST_OBSERVED")
        self.assertFalse(cancel["invite_transaction_termination_established"])

    def test_15_cancel_200_without_invite_final_response(self) -> None:
        document = self.run_valid(
            [
                make_invite(1),
                builder.rec(2, method="CANCEL", call_id="CALL", branch="z9hG4bK-A"),
                make_response(3, 200, to_tag="TC", cseq_method="CANCEL"),
            ]
        )
        cancel = attempt(document)["cancel_evidence"]
        self.assertEqual(cancel["outcome"], "CANCEL_RESPONSE_OBSERVED")
        self.assertIsNone(cancel["invite_final_response_status"])

    def test_16_cancel_200_plus_associated_invite_487(self) -> None:
        document = self.run_valid(
            [
                make_invite(1),
                builder.rec(2, method="CANCEL", call_id="CALL", branch="z9hG4bK-A"),
                make_response(3, 200, to_tag="TC", cseq_method="CANCEL"),
                make_response(4, 487, to_tag="T487"),
            ]
        )
        cancel = attempt(document)["cancel_evidence"]
        self.assertEqual(cancel["outcome"], "CANCEL_INVITE_SEQUENCE_OBSERVED")
        self.assertTrue(cancel["response_sequence_observed"])
        self.assertEqual(cancel["invite_final_response_status"], 487)

    def test_17_unrelated_200_does_not_establish_cancel_success(self) -> None:
        document = self.run_valid(
            [
                make_invite(1),
                builder.rec(
                    2,
                    method="CANCEL",
                    call_id="OTHER",
                    branch="z9hG4bK-OTHER",
                ),
                make_response(
                    3,
                    200,
                    call_id="OTHER",
                    branch="z9hG4bK-OTHER",
                    to_tag="TO",
                    cseq_method="CANCEL",
                ),
            ]
        )
        self.assertEqual(attempt(document)["cancel_evidence"]["outcome"], "NO_CANCEL_OBSERVED")
        self.assertTrue(
            any(
                item["reason"] == "CANCEL_ASSOCIATION_NOT_ESTABLISHED"
                for item in document["unbound_observations"]
            )
        )

    def test_18_conflicting_cancel_to_invite_relationship(self) -> None:
        def mutate(transactions: dict) -> None:
            invite = transactions["transactions"][0]["transaction_reference"]
            cancel = next(
                item
                for item in transactions["transactions"]
                if item["transaction_method"] == "CANCEL"
            )
            cancel["cancel_invite_association_status"] = "AMBIGUOUS"
            cancel["associated_transaction_reference"] = None
            cancel["associated_transaction_references"] = [invite]

        document = self.run_valid(
            [
                make_invite(1),
                builder.rec(2, method="CANCEL", call_id="CALL", branch="z9hG4bK-A"),
                make_response(3, 200, to_tag="TC", cseq_method="CANCEL"),
            ],
            mutate_transactions=mutate,
        )
        cancel = attempt(document)["cancel_evidence"]
        self.assertEqual(cancel["outcome"], "CANCEL_ASSOCIATION_NOT_ESTABLISHED")
        self.assertIn("CANCEL_INVITE_ASSOCIATION_AMBIGUOUS", cancel["conflict_findings"])

    def test_19_bye_with_200_response(self) -> None:
        document = self.run_valid(
            confirmed_call(1)
            + [
                builder.rec(4, method="BYE", call_id="CALL", branch="z9hG4bK-A", cseq=2, to_tag="T1"),
                make_response(5, 200, cseq=2, to_tag="T1", cseq_method="BYE"),
            ]
        )
        item = attempt(document)
        self.assertEqual(item["release_evidence"]["outcome"], "SIP_TERMINATION_SIGNALING_SUPPORTED")
        observation = item["branches"][0]["release"]["observations"][0]
        self.assertTrue(observation["termination_supported"])

    def test_20_bye_without_final_response(self) -> None:
        document = self.run_valid(
            confirmed_call(1)
            + [
                builder.rec(4, method="BYE", call_id="CALL", branch="z9hG4bK-A", cseq=2, to_tag="T1")
            ]
        )
        self.assertEqual(attempt(document)["release_evidence"]["outcome"], "BYE_RESPONSE_NOT_OBSERVED")

    def test_21_bye_with_negative_response(self) -> None:
        document = self.run_valid(
            confirmed_call(1)
            + [
                builder.rec(4, method="BYE", call_id="CALL", branch="z9hG4bK-A", cseq=2, to_tag="T1"),
                make_response(5, 481, cseq=2, to_tag="T1", cseq_method="BYE"),
            ]
        )
        self.assertEqual(attempt(document)["release_evidence"]["outcome"], "BYE_NEGATIVE_RESPONSE_OBSERVED")

    def test_22_bye_without_observed_dialog_creator(self) -> None:
        document = self.run_valid(
            [
                builder.rec(1, method="BYE", call_id="NOINVITE", branch="z9hG4bK-BYE", cseq=1, to_tag="T")
            ]
        )
        self.assertEqual(document["session_attempt_count"], 0)
        self.assertTrue(
            any(
                item["reason"] == "DIALOG_CREATOR_NOT_OBSERVED"
                for item in document["unbound_observations"]
            )
        )

    def test_23_re_invite_observed_without_modification_interpretation(self) -> None:
        document = self.run_valid(
            confirmed_call(1)
            + [
                builder.rec(4, method="INVITE", call_id="CALL", branch="z9hG4bK-B", cseq=2, to_tag="T1"),
                make_response(5, 200, branch="z9hG4bK-B", cseq=2, to_tag="T1"),
            ]
        )
        self.assertEqual(document["session_attempt_count"], 1)
        observation = document["in_dialog_observations"][0]
        self.assertEqual(observation["method"], "INVITE")
        self.assertEqual(observation["conclusion"], "NOT_INTERPRETED")
        self.assertNotIn("session_modification", observation)

    def test_24_update_observed_without_modification_interpretation(self) -> None:
        document = self.run_valid(
            confirmed_call(1)
            + [
                builder.rec(4, method="UPDATE", call_id="CALL", branch="z9hG4bK-B", cseq=2, to_tag="T1"),
                make_response(5, 200, branch="z9hG4bK-B", cseq=2, to_tag="T1", cseq_method="UPDATE"),
            ]
        )
        observation = document["in_dialog_observations"][0]
        self.assertEqual(observation["method"], "UPDATE")
        self.assertEqual(observation["conclusion"], "NOT_INTERPRETED")

    def test_25_mid_capture_invite_or_bye(self) -> None:
        document = self.run_valid([make_invite(5)])
        self.assertEqual(attempt(document)["branches"][0]["outcome"], "NO_FINAL_RESPONSE")
        bye_document = self.run_valid(
            [builder.rec(1, method="BYE", call_id="MID", branch="z9hG4bK-MID", cseq=1, to_tag="T")]
        )
        self.assertEqual(bye_document["session_attempt_count"], 0)
        self.assertTrue(bye_document["unbound_observations"])

    def test_26_multiple_initial_invites_sharing_one_call_id(self) -> None:
        document = self.run_valid(
            [
                make_invite(1, call_id="SAME", branch="z9hG4bK-1", from_tag="F1"),
                make_invite(2, call_id="SAME", branch="z9hG4bK-2", from_tag="F2"),
            ]
        )
        self.assertEqual(document["session_attempt_count"], 2)
        self.assertEqual(len({item["attempt_reference"] for item in document["session_attempts"]}), 2)

    def test_27_same_frame_with_multiple_messages(self) -> None:
        first = make_invite(1, call_id="F1", branch="z9hG4bK-1", from_tag="F1")
        second = make_invite(1, call_id="F2", branch="z9hG4bK-2", from_tag="F2")
        second["message_occurrence"] = 2
        document = self.run_valid([first, second])
        self.assertEqual(document["session_attempt_count"], 2)
        refs = {item["initial_invite_event_reference"] for item in document["session_attempts"]}
        self.assertEqual(len(refs), 2)
        self.assertTrue(all(ref.endswith((".1", ".2")) for ref in refs))

    def test_28_same_dialog_identity_across_captures_is_rejected(self) -> None:
        def mutate(events: list[dict]) -> None:
            events[0]["capture_file"] = "other-capture.pcapng"

        document, _report, stderr, code, _directory = analyze(
            [make_invite(1), make_response(2, 200)], mutate_events=mutate
        )
        self.assertNotEqual(code, 0)
        self.assertIn("capture", stderr.lower())
        self.assertEqual(document, {})

    def test_29_mismatched_capture_provenance_is_rejected(self) -> None:
        def mutate(dialogs: dict) -> None:
            dialogs["capture_provenance"]["capture_files"] = ["other.pcapng"]

        _document, _report, stderr, code, _directory = analyze(
            [make_invite(1), make_response(2, 200)], mutate_dialogs=mutate
        )
        self.assertNotEqual(code, 0)
        self.assertIn("capture provenance", stderr)

    def test_30_missing_source_event_reference_is_rejected(self) -> None:
        def mutate(transactions: dict) -> None:
            transactions["transactions"][0]["request_event_references"] = [
                "sip-event:synthetic-ims-session.pcapng:99.1"
            ]

        _document, _report, stderr, code, _directory = analyze(
            [make_invite(1)], mutate_transactions=mutate
        )
        self.assertNotEqual(code, 0)
        self.assertIn("missing source event", stderr)

    def test_31_duplicate_transaction_reference_is_rejected(self) -> None:
        def mutate(transactions: dict) -> None:
            transactions["transactions"].append(copy.deepcopy(transactions["transactions"][0]))
            transactions["transaction_count"] = len(transactions["transactions"])

        _document, _report, stderr, code, _directory = analyze(
            [make_invite(1)], mutate_transactions=mutate
        )
        self.assertNotEqual(code, 0)
        self.assertIn("duplicate", stderr.lower())

    def test_32_truncated_and_malformed_sip_event(self) -> None:
        truncated = make_invite(1)
        truncated["capture_truncated"] = True
        document = self.run_valid([truncated])
        self.assertEqual(
            document["input_provenance"]["capture_completeness"], "PARTIAL"
        )

        def mutate(events: list[dict]) -> None:
            del events[0]["headers"]["cseq"]

        _document, _report, stderr, code, _directory = analyze(
            [make_invite(1)], mutate_events=mutate
        )
        self.assertNotEqual(code, 0)
        self.assertIn("CSeq", stderr)

    def test_33_no_invite_in_otherwise_valid_capture(self) -> None:
        document = self.run_valid(
            [
                builder.rec(1, method="OPTIONS", call_id="OPT", branch="z9hG4bK-OPT"),
                make_response(2, 200, call_id="OPT", branch="z9hG4bK-OPT", to_tag="TO", cseq_method="OPTIONS"),
            ]
        )
        self.assertEqual(document["session_attempt_count"], 0)
        self.assertEqual(document["session_attempts"], [])
        self.assertEqual(document["completeness"]["capture_completeness"], "COMPLETE")

    def test_34_empty_session_evidence_with_valid_contracts(self) -> None:
        document = self.run_valid(
            [
                builder.rec(
                    1,
                    method="REGISTER",
                    call_id="REG",
                    branch="z9hG4bK-REG",
                    request_uri="sip:registrar.example.com",
                )
            ]
        )
        self.assertEqual(document["session_attempt_count"], 0)
        self.assertEqual(document["unbound_observations"], [])

    def test_35_privacy_and_raw_identity_leakage(self) -> None:
        records = [
            builder.rec(
                1,
                method="INVITE",
                call_id="PRIVATE-CALLID-001",
                branch="z9hG4bK-PRIVATE-001",
                from_tag="PRIVATE-FTAG-001",
            ),
            builder.rec(
                2,
                status=200,
                call_id="PRIVATE-CALLID-001",
                branch="z9hG4bK-PRIVATE-001",
                from_tag="PRIVATE-FTAG-001",
                to_tag="PRIVATE-TTAG-001",
            ),
            builder.rec(
                3,
                method="ACK",
                call_id="PRIVATE-CALLID-001",
                branch="z9hG4bK-PRIVATE-001",
                from_tag="PRIVATE-FTAG-001",
                to_tag="PRIVATE-TTAG-001",
                cseq_method="ACK",
            ),
        ]
        document, report, stderr, code, _directory = analyze(records)
        self.assertEqual(code, 0, stderr)
        text = json.dumps(document) + report + stderr
        for token in PRIVATE_TOKENS:
            self.assertNotIn(token, text)
        for field in ('"call_id"', '"from_tag"', '"to_tag"', '"request_uri"', '"sip_uri"'):
            self.assertNotIn(field, text)

    def test_36_bounded_output_and_reference_accounting(self) -> None:
        records = [
            make_invite(index + 1, call_id=f"B{index}", branch=f"z9hG4bK-B{index}", from_tag=f"F{index}")
            for index in range(70)
        ]
        document = self.run_valid(records)
        self.assertEqual(len(document["session_attempts"]), 64)
        completeness = document["completeness"]
        self.assertEqual(completeness["initial_invite_transaction_count"], 70)
        self.assertEqual(
            completeness["session_attempt_count"],
            len(document["session_attempts"]) + completeness["attempts_omitted"],
        )
        self.assertEqual(
            completeness["branch_count"],
            sum(item["branch_count"] for item in document["session_attempts"])
            + completeness["branches_omitted"],
        )
        self.assertEqual(completeness["attempts_omitted"], 6)

    def test_37_untagged_provisional_is_not_an_early_dialog(self) -> None:
        document = self.run_valid(
            [make_invite(1), make_response(2, 180, to_tag=None)]
        )
        item = attempt(document)
        self.assertEqual(item["stage_evidence"]["untagged_provisional_event_references"], [
            "sip-event:synthetic-ims-session.pcapng:2.1"
        ])
        self.assertEqual(item["stage_evidence"]["early_dialog_references"], [])
        self.assertEqual(item["branches"][0]["outcome"], "PROVISIONAL_ONLY")

    def test_38_reused_dialog_identity_remains_unbound(self) -> None:
        document = self.run_valid(
            [
                make_invite(1, call_id="REUSE", branch="z9hG4bK-R1", from_tag="F1"),
                make_response(2, 200, call_id="REUSE", branch="z9hG4bK-R1", from_tag="F1", to_tag="T"),
                make_invite(3, call_id="REUSE", branch="z9hG4bK-R2", from_tag="F1"),
                make_response(4, 200, call_id="REUSE", branch="z9hG4bK-R2", from_tag="F1", to_tag="T"),
            ]
        )
        self.assertEqual(document["session_attempt_count"], 2)
        self.assertTrue(
            any(
                item["reason"] == "REUSED_DIALOG_IDENTITY"
                for item in document["unbound_observations"]
            )
        )

    def test_39_cancel_negative_response_does_not_establish_sequence(self) -> None:
        document = self.run_valid(
            [
                make_invite(1),
                builder.rec(2, method="CANCEL", call_id="CALL", branch="z9hG4bK-A"),
                make_response(3, 481, to_tag="TC", cseq_method="CANCEL"),
            ]
        )
        cancel = attempt(document)["cancel_evidence"]
        self.assertEqual(cancel["outcome"], "CANCEL_RESPONSE_OBSERVED")
        self.assertFalse(cancel["response_sequence_observed"])

    def test_40_cancel_after_invite_final_response_is_a_conflict(self) -> None:
        document = self.run_valid(
            [
                make_invite(1),
                make_response(2, 200, to_tag="T1"),
                make_ack(3, to_tag="T1"),
                builder.rec(4, method="CANCEL", call_id="CALL", branch="z9hG4bK-A"),
                make_response(5, 200, to_tag="TC", cseq_method="CANCEL"),
            ]
        )
        cancel = attempt(document)["cancel_evidence"]
        self.assertEqual(cancel["outcome"], "CANCEL_AFTER_INVITE_FINAL_RESPONSE")
        self.assertIn("CANCEL_AFTER_INVITE_FINAL_RESPONSE", cancel["conflict_findings"])

    def test_41_retransmitted_cancel_keeps_one_transaction(self) -> None:
        document = self.run_valid(
            [
                make_invite(1),
                builder.rec(2, method="CANCEL", call_id="CALL", branch="z9hG4bK-A"),
                builder.rec(3, method="CANCEL", call_id="CALL", branch="z9hG4bK-A"),
                make_response(4, 200, to_tag="TC", cseq_method="CANCEL"),
            ]
        )
        cancel = attempt(document)["cancel_evidence"]
        self.assertEqual(len(cancel["cancel_transaction_references"]), 1)

    def test_42_multiple_bye_transactions_in_one_dialog(self) -> None:
        document = self.run_valid(
            confirmed_call(1)
            + [
                builder.rec(4, method="BYE", call_id="CALL", branch="z9hG4bK-A", cseq=2, to_tag="T1"),
                make_response(5, 200, cseq=2, to_tag="T1", cseq_method="BYE"),
                builder.rec(6, method="BYE", call_id="CALL", branch="z9hG4bK-B", cseq=3, to_tag="T1"),
                make_response(7, 200, branch="z9hG4bK-B", cseq=3, to_tag="T1", cseq_method="BYE"),
            ]
        )
        release = attempt(document)["branches"][0]["release"]
        self.assertEqual(release["bye_transaction_count"], 2)
        self.assertEqual(len(release["termination_supported_dialog_references"]), 1)

    def test_deterministic_replay_and_schema(self) -> None:
        first, first_report, stderr, code, first_dir = analyze(
            builder.main_example_records()
        )
        self.assertEqual(code, 0, stderr)
        second, second_report, stderr, code, second_dir = analyze(
            builder.main_example_records()
        )
        self.assertEqual(code, 0, stderr)
        self.assertEqual(first, second)
        self.assertEqual(first_report, second_report)
        self.assertEqual(
            Path(first_dir, "analysis.json").read_bytes(),
            Path(second_dir, "analysis.json").read_bytes(),
        )
        if jsonschema is not None:
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            jsonschema.validate(first, schema)
        ims_session_model.validate_analysis(first)

    def test_expected_output_and_report_match_committed_fixture(self) -> None:
        directory = Path(tempfile.mkdtemp())
        inputs = SKILL / "examples" / "inputs"
        output = directory / "analysis.json"
        report = directory / "report.txt"
        completed = subprocess.run(
            [
                sys.executable,
                str(CLI),
                "--sip-events",
                str(inputs / "session-cases-events.jsonl"),
                "--sip-transactions",
                str(inputs / "session-cases-transactions.json"),
                "--sip-dialogs",
                str(inputs / "session-cases-dialogs.json"),
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
        expected = SKILL / "examples" / "expected"
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8")),
            json.loads((expected / "session-analysis.json").read_text(encoding="utf-8")),
        )
        self.assertEqual(
            report.read_text(encoding="utf-8"),
            (expected / "session-report.txt").read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()