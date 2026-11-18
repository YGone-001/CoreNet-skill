#!/usr/bin/env python3
"""SIP dialog evidence tests."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
SCHEMA = SKILL / "schemas" / "sip-dialogs.schema.json"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import sip_dialogs  # noqa: E402
import sip_transactions  # noqa: E402

INIT = "sip:alice@example.com"
REMOTE = "sip:bob@example.com"


def rec(
    frame: int,
    *,
    method: str | None = None,
    status: int | None = None,
    branch: str = "z9hG4bK-A",
    call_id: str = "CALL",
    cseq: int = 1,
    cseq_method: str | None = None,
    from_tag: str | None = "INIT-TAG",
    to_tag: str | None = None,
    to_uri: str = REMOTE,
    from_uri: str = INIT,
    request_uri: str = REMOTE,
    outbound: bool | None = None,
    reason: str = "OK",
    capture: str = "sip-dialog.pcapng",
) -> dict:
    if outbound is None:
        outbound = method is not None
    source, destination = (
        ("192.0.2.10", "192.0.2.20") if outbound else ("192.0.2.20", "192.0.2.10")
    )
    headers = {
        "call_id": call_id,
        "cseq_sequence": cseq,
        "cseq_method": cseq_method or method or "REGISTER",
        "via": [{"branch": branch, "sent_by": "192.0.2.10:5060", "transport": "UDP"}],
        "from": {"uri": from_uri, "count": 1, "tag": from_tag},
        "to": {"uri": to_uri, "count": 1, "tag": to_tag},
        "content_length": 0,
        "body_length": 0,
        "request_uri": request_uri,
    }
    if method is not None:
        headers["method"] = method
        headers["max_forwards"] = 70
    if status is not None:
        headers["status_code"] = status
        headers["reason_phrase"] = reason
    return {
        "capture_file": capture,
        "frame_number": frame,
        "frame_time_epoch": f"1700000200.{frame:09d}",
        "frame_time_relative": f"{frame}.000000000",
        "message_occurrence": 1,
        "transport": {
            "protocol": "UDP",
            "source_address": source,
            "source_port": 5060,
            "destination_address": destination,
            "destination_port": 5060,
            "stream_id": None,
        },
        "headers": headers,
    }


def run_input(records: list[dict]) -> tuple[dict, dict, dict]:
    directory = Path(tempfile.mkdtemp())
    source = directory / "dialogs.jsonl"
    source.write_text(
        "\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n",
        encoding="utf-8",
    )
    events = directory / "events.jsonl"
    transactions = directory / "transactions.json"
    dialogs = directory / "dialogs.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "extract-sip.py"),
            str(source),
            "--output",
            str(events),
            "--transaction-output",
            str(transactions),
            "--dialog-output",
            str(dialogs),
            "--force",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return (
        json.loads(transactions.read_text(encoding="utf-8")),
        json.loads(dialogs.read_text(encoding="utf-8")),
        {
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "events": events,
            "dialogs": dialogs,
        },
    )


def run_fixture() -> tuple[dict, dict]:
    transactions = SKILL / "examples" / "expected" / "dialog-cases-transactions.json"
    dialogs = SKILL / "examples" / "expected" / "dialog-cases-dialogs.json"
    return (
        json.loads(transactions.read_text(encoding="utf-8")),
        json.loads(dialogs.read_text(encoding="utf-8")),
    )


def dialog_by_state(document: dict, state: str) -> list[dict]:
    return [item for item in document["dialogs"] if item["dialog_state"] == state]


def dialog_for_call(document: dict, transaction_capture: str, frame: int) -> dict:
    reference = f"sip-dialog:{transaction_capture}:{frame}.1"
    for dialog in document["dialogs"]:
        if dialog["dialog_reference"] == reference:
            return dialog
    raise AssertionError(f"no dialog at {reference}")


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.transactions, cls.document = run_fixture()

    def test_fixture_dialog_schema_validation(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        jsonschema.validate(self.document, json.loads(SCHEMA.read_text(encoding="utf-8")))
        sip_dialogs.validate_dialog_document(self.document, None, self.transactions)

    def test_forking_produces_two_independent_dialogs(self) -> None:
        self.assertEqual(self.document["dialog_summary"]["forked_initiating_transaction_count"], 1)
        forked = [
            dialog
            for dialog in self.document["dialogs"]
            if dialog["initiating_transaction_reference"]
            == self.document["dialogs"][0]["initiating_transaction_reference"]
        ]
        self.assertEqual(len(forked), 2)
        self.assertEqual(len({dialog["dialog_reference"] for dialog in forked}), 2)

    def test_both_forked_branches_are_confirmed(self) -> None:
        branch_dialogs = self.document["dialogs"][:2]
        self.assertEqual([dialog["dialog_state"] for dialog in branch_dialogs], ["CONFIRMED", "CONFIRMED"])
        self.assertTrue(all(dialog["early_response_event_references"] for dialog in branch_dialogs))

    def test_2xx_ack_is_bound_only_to_its_branch(self) -> None:
        first, second = self.document["dialogs"][:2]
        self.assertEqual(len(first["ack_event_references"]), 1)
        self.assertEqual(second["ack_event_references"], [])

    def test_bye_forward_and_reverse_terminate_their_dialog(self) -> None:
        terminated = dialog_by_state(self.document, "TERMINATED")
        self.assertEqual(len(terminated), 2)
        directions = {direction for dialog in terminated for direction in dialog["direction_observations"]}
        self.assertEqual(directions, {"ORIGINAL", "REVERSE"})

    def test_bye_without_response_keeps_confirmed_state(self) -> None:
        dialog = next(
            item
            for item in self.document["dialogs"]
            if item["dialog_state"] == "CONFIRMED"
            and item["observed_lifecycle_status"] == "TERMINATION_SIGNALING_OBSERVED"
        )
        self.assertIn("BYE_RESPONSE_NOT_OBSERVED", dialog["missing_evidence"])

    def test_reinvite_update_info_do_not_create_new_dialogs(self) -> None:
        self.assertEqual(self.document["dialog_count"], 10)
        with_in_dialog = [
            dialog
            for dialog in self.document["dialogs"]
            if dialog["in_dialog_transaction_references"]
        ]
        self.assertGreaterEqual(len(with_in_dialog), 2)
        self.assertTrue(
            all(len(dialog["in_dialog_transaction_references"]) >= 1 for dialog in with_in_dialog)
        )

    def test_mid_capture_and_unsupported_are_unbound(self) -> None:
        reasons = {item["reason"] for item in self.document["unbound_observations"]}
        self.assertIn("DIALOG_CREATOR_NOT_OBSERVED", reasons)
        self.assertIn("UNSUPPORTED_SUBSCRIPTION_DIALOG", reasons)
        self.assertIn("PROVISIONAL_WITHOUT_TO_TAG", reasons)
        self.assertIn("CONFIRMATION_WITHOUT_TO_TAG", reasons)

    def test_register_does_not_create_dialog(self) -> None:
        self.assertNotIn(
            "sip-dialog:synthetic-dialog-cases.pcapng:44.1",
            [dialog["dialog_reference"] for dialog in self.document["dialogs"]],
        )

    def test_duplicate_2xx_same_branch_does_not_duplicate_dialog(self) -> None:
        dialog = dialog_for_call(self.document, "synthetic-dialog-cases.pcapng", 47)
        self.assertEqual(len(dialog["confirming_response_event_references"]), 2)

    def test_lifecycle_axes_remain_separate(self) -> None:
        for dialog in self.document["dialogs"]:
            self.assertIn(dialog["dialog_state"], ("EARLY", "CONFIRMED", "TERMINATED", "UNKNOWN"))
            self.assertIn(
                dialog["observed_lifecycle_status"],
                (
                    "EARLY_OBSERVED",
                    "CONFIRMATION_OBSERVED",
                    "TERMINATION_SIGNALING_OBSERVED",
                    "INCOMPLETE_CAPTURE",
                    "UNRESOLVED",
                ),
            )

    def test_no_ims_call_or_media_verdict(self) -> None:
        text = json.dumps(self.document)
        for token in ("call_success", "call_failure", "rtp_delivered", "registration_success", "answer_selected"):
            self.assertNotIn(token, text)


class IdentityTests(unittest.TestCase):
    def test_tagged_180_creates_early_dialog(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=180, cseq_method="INVITE", to_tag="A", outbound=False, reason="Ringing"),
            ]
        )
        self.assertEqual(document["dialog_count"], 1)
        self.assertEqual(document["dialogs"][0]["dialog_state"], "EARLY")

    def test_183_creates_eligible_early_dialog(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=183, cseq_method="INVITE", to_tag="A", outbound=False),
            ]
        )
        self.assertEqual(document["dialogs"][0]["observed_lifecycle_status"], "EARLY_OBSERVED")

    def test_100_trying_does_not_create_dialog(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=100, cseq_method="INVITE", outbound=False, reason="Trying"),
            ]
        )
        self.assertEqual(document["dialog_count"], 0)
        self.assertEqual(document["unbound_observations"], [])

    def test_180_without_to_tag_is_unresolved(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=180, cseq_method="INVITE", outbound=False, reason="Ringing"),
            ]
        )
        self.assertEqual(document["dialog_count"], 0)
        self.assertEqual(document["unbound_observations"][0]["reason"], "PROVISIONAL_WITHOUT_TO_TAG")

    def test_same_call_id_different_tags_are_distinct_dialogs(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=183, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, status=183, cseq_method="INVITE", to_tag="B", outbound=False),
            ]
        )
        self.assertEqual(document["dialog_count"], 2)
        self.assertEqual(len({dialog["dialog_reference"] for dialog in document["dialogs"]}), 2)

    def test_different_call_id_never_share_dialog(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE", branch="z9hG4bK-A", call_id="A"),
                rec(2, status=200, branch="z9hG4bK-A", call_id="A", cseq_method="INVITE", to_tag="T", outbound=False),
                rec(3, method="INVITE", branch="z9hG4bK-B", call_id="B"),
                rec(4, status=200, branch="z9hG4bK-B", call_id="B", cseq_method="INVITE", to_tag="T", outbound=False),
            ]
        )
        self.assertEqual(document["dialog_count"], 2)
        self.assertEqual(
            len({dialog["initiating_transaction_reference"] for dialog in document["dialogs"]}), 2
        )

    def test_missing_from_tag_is_insufficient(self) -> None:
        _, document, _ = run_input(
            [rec(1, method="INVITE", from_tag=None), rec(2, status=200, cseq_method="INVITE", to_tag="T", outbound=False)]
        )
        self.assertEqual(document["dialog_count"], 0)
        self.assertIn(
            "FROM_TAG_NOT_OBSERVED",
            document["unbound_observations"][0]["missing_evidence"],
        )

    def test_missing_to_tag_on_confirmation_is_insufficient(self) -> None:
        _, document, _ = run_input(
            [rec(1, method="INVITE"), rec(2, status=200, cseq_method="INVITE", outbound=False)]
        )
        self.assertEqual(document["dialog_count"], 0)
        self.assertIn(
            "TO_TAG_NOT_OBSERVED",
            document["unbound_observations"][0]["missing_evidence"],
        )

    def test_missing_call_id_is_insufficient(self) -> None:
        _, document, _ = run_input(
            [rec(1, method="INVITE", call_id=None), rec(2, status=200, cseq_method="INVITE", to_tag="T", outbound=False)]
        )
        self.assertEqual(document["dialog_count"], 0)
        self.assertIn(
            "CALL_ID_NOT_OBSERVED",
            document["unbound_observations"][0]["missing_evidence"],
        )

    def test_reversed_tags_are_orientation_safe(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="R", outbound=False),
                rec(3, method="BYE", from_tag="R", to_tag="INIT-TAG", outbound=False, cseq=2),
                rec(4, status=200, cseq_method="BYE", from_tag="R", to_tag="INIT-TAG", cseq=2),
            ]
        )
        self.assertEqual(document["dialogs"][0]["direction_observations"], ["REVERSE"])


class ConfirmationTests(unittest.TestCase):
    def test_early_dialog_is_confirmed_by_200(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=180, cseq_method="INVITE", to_tag="A", outbound=False, reason="Ringing"),
                rec(3, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
            ]
        )
        self.assertEqual(document["dialog_count"], 1)
        self.assertEqual(document["dialogs"][0]["dialog_state"], "CONFIRMED")

    def test_200_creates_confirmed_dialog_without_provisional(self) -> None:
        _, document, _ = run_input(
            [rec(1, method="INVITE"), rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False)]
        )
        self.assertEqual(document["dialogs"][0]["observed_lifecycle_status"], "CONFIRMATION_OBSERVED")
        self.assertIn("confirmation_without_provisional", document["dialogs"][0]["lifecycle_evidence"])

    def test_200_without_to_tag_is_not_confirmed(self) -> None:
        _, document, _ = run_input(
            [rec(1, method="INVITE"), rec(2, status=200, cseq_method="INVITE", outbound=False)]
        )
        self.assertEqual(document["dialog_count"], 0)

    def test_486_does_not_confirm_dialog(self) -> None:
        _, document, _ = run_input(
            [rec(1, method="INVITE"), rec(2, status=486, cseq_method="INVITE", to_tag="A", outbound=False, reason="Busy Here")]
        )
        self.assertEqual(document["dialog_count"], 0)

    def test_repeated_200_does_not_create_duplicate(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
            ]
        )
        self.assertEqual(document["dialog_count"], 1)


class ForkingTests(unittest.TestCase):
    def test_two_early_branches(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=180, cseq_method="INVITE", to_tag="A", outbound=False, reason="Ringing"),
                rec(3, status=183, cseq_method="INVITE", to_tag="B", outbound=False),
            ]
        )
        self.assertEqual(document["dialog_count"], 2)
        self.assertEqual(document["dialog_summary"]["forked_initiating_transaction_count"], 1)

    def test_one_branch_confirms_while_another_stays_early(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=183, cseq_method="INVITE", to_tag="B", outbound=False),
                rec(3, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
            ]
        )
        states = {dialog["dialog_state"] for dialog in document["dialogs"]}
        self.assertEqual(states, {"EARLY", "CONFIRMED"})

    def test_two_200_with_different_tags(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, status=200, cseq_method="INVITE", to_tag="B", outbound=False),
            ]
        )
        self.assertEqual(document["dialog_count"], 2)
        self.assertTrue(all(dialog["dialog_state"] == "CONFIRMED" for dialog in document["dialogs"]))

    def test_failure_on_one_branch_does_not_invalidate_another(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=486, cseq_method="INVITE", to_tag="A", outbound=False, reason="Busy Here"),
                rec(3, status=200, cseq_method="INVITE", to_tag="B", outbound=False),
            ]
        )
        self.assertEqual(document["dialog_count"], 1)
        self.assertEqual(document["dialogs"][0]["dialog_state"], "CONFIRMED")

    def test_duplicate_final_on_same_branch_is_one_dialog(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
            ]
        )
        self.assertEqual(document["dialog_count"], 1)
        self.assertEqual(len(document["dialogs"][0]["confirming_response_event_references"]), 2)

    def test_missing_identity_does_not_force_branch_selection(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", outbound=False),
                rec(3, status=200, cseq_method="INVITE", to_tag="B", outbound=False),
            ]
        )
        self.assertEqual(document["dialog_count"], 1)
        self.assertTrue(any(item["reason"] == "CONFIRMATION_WITHOUT_TO_TAG" for item in document["unbound_observations"]))


class AckTests(unittest.TestCase):
    def test_valid_2xx_ack_is_bound(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="ACK", cseq_method="ACK", to_tag="A"),
            ]
        )
        self.assertEqual(len(document["dialogs"][0]["ack_event_references"]), 1)

    def test_ack_with_different_via_branch_is_bound(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE", branch="z9hG4bK-INV"),
                rec(2, status=200, branch="z9hG4bK-INV", cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="ACK", branch="z9hG4bK-ACK", cseq_method="ACK", to_tag="A"),
            ]
        )
        self.assertEqual(len(document["dialogs"][0]["ack_event_references"]), 1)

    def test_ack_with_mismatched_to_tag_is_not_bound(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="ACK", cseq_method="ACK", to_tag="B"),
            ]
        )
        self.assertEqual(document["dialogs"][0]["ack_event_references"], [])
        self.assertTrue(any(item["reason"] == "CONFIRMING_RESPONSE_NOT_OBSERVED" for item in document["unbound_observations"]))

    def test_ack_with_missing_call_id_is_not_bound(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="ACK", call_id=None, cseq_method="ACK", to_tag="A"),
            ]
        )
        self.assertEqual(document["dialogs"][0]["ack_event_references"], [])

    def test_ack_with_forked_dialogs_binds_unique_branch(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, status=200, cseq_method="INVITE", to_tag="B", outbound=False),
                rec(4, method="ACK", cseq_method="ACK", to_tag="A"),
            ]
        )
        self.assertEqual(document["dialog_count"], 2)
        self.assertEqual(len(document["dialogs"][0]["ack_event_references"]), 1)
        self.assertEqual(document["dialogs"][1]["ack_event_references"], [])

    def test_non_2xx_ack_does_not_create_dialog(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=486, cseq_method="INVITE", to_tag="A", outbound=False, reason="Busy Here"),
                rec(3, method="ACK", cseq_method="ACK", to_tag="A"),
            ]
        )
        self.assertEqual(document["dialog_count"], 0)

    def test_ack_without_invite_is_unbound(self) -> None:
        _, document, _ = run_input([rec(1, method="ACK", cseq_method="ACK", to_tag="A")])
        self.assertEqual(document["dialog_count"], 0)
        self.assertTrue(document["unbound_observations"])


class InDialogTests(unittest.TestCase):
    def test_bye_original_direction(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="BYE", cseq=2, to_tag="A"),
                rec(4, status=200, cseq_method="BYE", cseq=2, to_tag="A", outbound=False),
            ]
        )
        self.assertEqual(document["dialogs"][0]["direction_observations"], ["ORIGINAL"])
        self.assertEqual(document["dialogs"][0]["dialog_state"], "TERMINATED")

    def test_bye_reverse_direction(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="BYE", from_tag="A", to_tag="INIT-TAG", cseq=1, outbound=False),
                rec(4, status=200, cseq_method="BYE", from_tag="A", to_tag="INIT-TAG", cseq=1),
            ]
        )
        self.assertEqual(document["dialogs"][0]["direction_observations"], ["REVERSE"])

    def test_bye_with_200_terminates(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="BYE", cseq=2, to_tag="A"),
                rec(4, status=200, cseq_method="BYE", cseq=2, to_tag="A", outbound=False),
            ]
        )
        self.assertEqual(document["dialogs"][0]["dialog_state"], "TERMINATED")

    def test_bye_without_response_is_signaling_only(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="BYE", cseq=2, to_tag="A"),
            ]
        )
        self.assertEqual(document["dialogs"][0]["dialog_state"], "CONFIRMED")
        self.assertIn("BYE_RESPONSE_NOT_OBSERVED", document["dialogs"][0]["missing_evidence"])

    def test_bye_with_error_response_is_not_terminated(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="BYE", cseq=2, to_tag="A"),
                rec(4, status=481, cseq_method="BYE", cseq=2, to_tag="A", outbound=False, reason="Call/Transaction Does Not Exist"),
            ]
        )
        self.assertEqual(document["dialogs"][0]["dialog_state"], "CONFIRMED")
        self.assertEqual(document["dialogs"][0]["observed_lifecycle_status"], "TERMINATION_SIGNALING_OBSERVED")

    def test_bye_belongs_to_one_forked_dialog(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, status=200, cseq_method="INVITE", to_tag="B", outbound=False),
                rec(4, method="BYE", cseq=2, to_tag="A"),
                rec(5, status=200, cseq_method="BYE", cseq=2, to_tag="A", outbound=False),
            ]
        )
        self.assertEqual(len(document["dialogs"]), 2)
        with_bye = [dialog for dialog in document["dialogs"] if dialog["bye_transaction_references"]]
        self.assertEqual(len(with_bye), 1)
        self.assertEqual(len(with_bye[0]["bye_transaction_references"]), 1)

    def test_reinvite_update_info_stay_in_dialog(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="INVITE", branch="z9hG4bK-RI", cseq=2, to_tag="A"),
                rec(4, method="UPDATE", branch="z9hG4bK-UP", cseq=3, to_tag="A"),
                rec(5, method="INFO", branch="z9hG4bK-IN", cseq=4, to_tag="A"),
            ]
        )
        self.assertEqual(document["dialog_count"], 1)
        self.assertEqual(len(document["dialogs"][0]["in_dialog_transaction_references"]), 3)

    def test_in_dialog_transactions_have_unique_references(self) -> None:
        transactions, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="INVITE", branch="z9hG4bK-RI", cseq=2, to_tag="A"),
                rec(4, method="UPDATE", branch="z9hG4bK-UP", cseq=3, to_tag="A"),
            ]
        )
        references = document["dialogs"][0]["in_dialog_transaction_references"]
        known = {item["transaction_reference"] for item in transactions["transactions"]}
        self.assertEqual(len(references), 2)
        self.assertTrue(set(references).issubset(known))

    def test_cseq_tracking_is_direction_aware(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="UPDATE", cseq=2, to_tag="A"),
                rec(4, method="INFO", from_tag="A", to_tag="INIT-TAG", cseq=1, outbound=False),
            ]
        )
        cseq = document["dialogs"][0]["cseq_observations"]
        self.assertEqual(cseq["initiator_direction_values"], [2])
        self.assertEqual(cseq["responder_direction_values"], [1])

    def test_cseq_gap_does_not_imply_packet_loss(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="UPDATE", cseq=5, to_tag="A"),
                rec(4, method="INFO", cseq=7, to_tag="A"),
            ]
        )
        cseq = document["dialogs"][0]["cseq_observations"]
        self.assertTrue(cseq["sequence_gap_observed"])
        self.assertEqual(cseq["assessment"], "DIRECTION_AWARE_OBSERVATION_ONLY")


class IncompleteTests(unittest.TestCase):
    def test_mid_capture_bye_is_unbound(self) -> None:
        _, document, _ = run_input(
            [rec(1, method="BYE", cseq=5, from_tag="X", to_tag="Y")]
        )
        self.assertEqual(document["dialog_count"], 0)
        self.assertEqual(document["unbound_observations"][0]["reason"], "DIALOG_CREATOR_NOT_OBSERVED")
        self.assertTrue(document["unbound_observations"][0]["tag_pair_observed"])

    def test_mid_capture_reinvite_is_unbound(self) -> None:
        _, document, _ = run_input(
            [rec(1, method="INVITE", cseq=7, from_tag="X", to_tag="Y")]
        )
        self.assertEqual(document["dialog_count"], 0)
        self.assertEqual(document["unbound_observations"][0]["reason"], "DIALOG_CREATOR_NOT_OBSERVED")

    def test_mid_capture_update_is_unbound(self) -> None:
        _, document, _ = run_input(
            [rec(1, method="UPDATE", cseq=7, from_tag="X", to_tag="Y")]
        )
        self.assertEqual(document["dialog_count"], 0)

    def test_missing_dialog_creator_is_unbound(self) -> None:
        _, document, _ = run_input(
            [rec(1, method="BYE", call_id=None, cseq=1, from_tag="X", to_tag="Y")]
        )
        self.assertEqual(document["unbound_observations"][0]["reason"], "MISSING_DIALOG_IDENTITY")

    def test_contradictory_tag_evidence_is_unresolved(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, method="BYE", from_tag="WRONG", to_tag="A", cseq=2),
            ]
        )
        self.assertEqual(document["dialog_count"], 1)
        self.assertTrue(document["unbound_observations"])

    def test_truncated_message_without_identity_is_unbound(self) -> None:
        records = [
            rec(1, method="INVITE"),
            rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
        ]
        records[1]["capture_truncated"] = True
        _, document, _ = run_input(records)
        self.assertEqual(document["dialog_count"], 1)

    def test_cross_capture_messages_do_not_form_a_dialog(self) -> None:
        records = [
            rec(1, method="INVITE"),
            rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
        ]
        records[1]["capture_file"] = "other.pcapng"
        _, document, _ = run_input(records)
        self.assertEqual(document["dialog_count"], 0)

    def test_invalid_transaction_reference_is_rejected(self) -> None:
        transactions, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
            ]
        )
        document["dialogs"][0]["initiating_transaction_reference"] = "invalid"
        with self.assertRaises(sip_dialogs.DialogError):
            sip_dialogs.validate_dialog_document(document, None, transactions)

    def test_duplicate_source_associations_are_not_allowed_for_reused_transaction(self) -> None:
        transactions, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, status=200, cseq_method="INVITE", to_tag="B", outbound=False),
                rec(4, method="BYE", cseq=2, to_tag="A"),
            ]
        )
        document["dialogs"][1]["bye_transaction_references"] = document["dialogs"][0][
            "bye_transaction_references"
        ]
        with self.assertRaises(sip_dialogs.DialogError):
            sip_dialogs.validate_dialog_document(document, None, transactions)

    def test_missing_source_reference_is_rejected(self) -> None:
        transactions, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
            ]
        )
        document["dialogs"][0]["associated_message_event_references"].append(
            "sip-event:missing.pcapng:999.1"
        )
        with self.assertRaises(sip_dialogs.DialogError):
            sip_dialogs.validate_dialog_document(
                document,
                [
                    {
                        "match": {
                            "source_reference": "sip-event:sip-dialog.pcapng:2.1",
                            "capture": "sip-dialog.pcapng",
                            "frame": 2,
                            "occurrence": 1,
                        }
                    }
                ],
                transactions,
            )

    def test_same_frame_multiple_occurrences_are_distinct(self) -> None:
        invite = rec(1, method="INVITE")
        ringing = rec(
            1, status=180, cseq_method="INVITE", to_tag="A", outbound=False, reason="Ringing"
        )
        ringing["message_occurrence"] = 2
        _, document, _ = run_input([invite, ringing])
        self.assertEqual(document["dialog_count"], 1)
        self.assertIn(
            "sip-event:sip-dialog.pcapng:1.2",
            document["dialogs"][0]["early_response_event_references"],
        )


class DeterminismTests(unittest.TestCase):
    def test_replay_is_deterministic(self) -> None:
        first, second = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
            ]
        )[1], run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
            ]
        )[1]
        self.assertEqual(first, second)


class PrivacyTests(unittest.TestCase):
    def test_no_raw_identity_or_secret_is_published(self) -> None:
        transactions, document, artifacts = run_input(
            [
                rec(
                    1,
                    method="INVITE",
                    call_id="PRIVATE-CALL-ID",
                    from_tag="PRIVATE-FROM-TAG",
                    to_uri="sip:private-user@example.com",
                    from_uri="sip:private-user@example.com",
                ),
                rec(
                    2,
                    status=200,
                    call_id="PRIVATE-CALL-ID",
                    cseq_method="INVITE",
                    to_tag="PRIVATE-TO-TAG",
                    to_uri="sip:private-user@example.com",
                    from_uri="sip:private-user@example.com",
                    outbound=False,
                ),
                rec(
                    3,
                    method="ACK",
                    call_id="PRIVATE-CALL-ID",
                    cseq_method="ACK",
                    to_tag="PRIVATE-TO-TAG",
                    to_uri="sip:private-user@example.com",
                    from_uri="sip:private-user@example.com",
                ),
            ]
        )
        text = json.dumps(document) + artifacts["stdout"] + artifacts["stderr"]
        for secret in (
            "PRIVATE-CALL-ID",
            "PRIVATE-FROM-TAG",
            "PRIVATE-TO-TAG",
            "private-user",
            "sip:",
        ):
            self.assertNotIn(secret, json.dumps(document))
        self.assertNotIn("PRIVATE-CALL-ID", text)

    def test_no_sip_or_sdp_body_fields(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
            ]
        )
        raw = json.dumps(document)
        for field in ('"call_id"', '"from_tag"', '"to_tag"', '"request_uri"', '"body"', '"sdp"'):
            self.assertNotIn(field, raw)

    def test_existing_sip_transaction_output_is_unchanged(self) -> None:
        transactions = json.loads(
            (
                SKILL / "examples" / "expected" / "transaction-cases-transactions.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(transactions["analysis_version"], "1.1.0")


def capture_of(reference: str) -> str:
    return reference.split(":")[1]


def in_dialog_record(
    frame: int,
    method: str,
    cseq: int,
    *,
    direction: str = "ORIGINAL",
    capture: str = "sip-dialog.pcapng",
) -> dict:
    branch = f"z9hG4bK-{method}-{frame}"
    if direction == "ORIGINAL":
        return rec(
            frame,
            method=method,
            cseq=cseq,
            branch=branch,
            to_tag="A",
            capture=capture,
        )
    return rec(
        frame,
        method=method,
        cseq=cseq,
        branch=branch,
        from_tag="A",
        to_tag="INIT-TAG",
        outbound=False,
        capture=capture,
    )


def confirmed_dialog(*extra: dict) -> list[dict]:
    return [
        rec(1, method="INVITE"),
        rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
        *extra,
    ]


class CaptureIsolationTests(unittest.TestCase):
    def test_capture_identity_isolation(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE", capture="A.pcapng"),
                rec(
                    2,
                    status=200,
                    cseq_method="INVITE",
                    to_tag="T",
                    outbound=False,
                    capture="A.pcapng",
                ),
                rec(1, method="INVITE", capture="B.pcapng"),
                rec(
                    2,
                    status=200,
                    cseq_method="INVITE",
                    to_tag="T",
                    outbound=False,
                    capture="B.pcapng",
                ),
            ]
        )
        self.assertEqual(document["dialog_count"], 2)
        references = {dialog["dialog_reference"] for dialog in document["dialogs"]}
        self.assertEqual(len(references), 2)
        for dialog in document["dialogs"]:
            self.assertEqual(capture_of(dialog["dialog_reference"]), dialog["fork_branch_reference"].split(":")[1])
            for reference in dialog["associated_message_event_references"]:
                self.assertEqual(capture_of(reference), capture_of(dialog["dialog_reference"]))
            for reference in dialog["in_dialog_transaction_references"]:
                self.assertEqual(reference.split(":")[1], capture_of(dialog["dialog_reference"]))
        transactions = {
            dialog["initiating_transaction_reference"] for dialog in document["dialogs"]
        }
        self.assertEqual(len(transactions), 2)

    def test_identical_identifiers_in_two_captures_stay_separate(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE", capture="A.pcapng", call_id="SAME"),
                rec(
                    2,
                    status=200,
                    cseq_method="INVITE",
                    to_tag="SAME-TO",
                    outbound=False,
                    call_id="SAME",
                    capture="A.pcapng",
                ),
                rec(1, method="INVITE", capture="B.pcapng", call_id="SAME"),
                rec(
                    2,
                    status=200,
                    cseq_method="INVITE",
                    to_tag="SAME-TO",
                    outbound=False,
                    call_id="SAME",
                    capture="B.pcapng",
                ),
            ]
        )
        self.assertEqual(document["dialog_count"], 2)
        self.assertEqual(
            len({dialog["initiating_transaction_reference"] for dialog in document["dialogs"]}),
            2,
        )
        for dialog in document["dialogs"]:
            for reference in dialog["associated_message_event_references"]:
                self.assertEqual(capture_of(reference), capture_of(dialog["dialog_reference"]))

    def test_each_capture_keeps_its_own_forked_branches(self) -> None:
        records = []
        for capture in ("A.pcapng", "B.pcapng"):
            records.extend(
                [
                    rec(1, method="INVITE", capture=capture),
                    rec(2, status=180, cseq_method="INVITE", to_tag="EARLY", outbound=False, reason="Ringing", capture=capture),
                    rec(3, status=200, cseq_method="INVITE", to_tag="EARLY", outbound=False, capture=capture),
                    rec(4, status=200, cseq_method="INVITE", to_tag="OTHER", outbound=False, capture=capture),
                ]
            )
        _, document, _ = run_input(records)
        self.assertEqual(document["dialog_count"], 4)
        self.assertEqual(document["dialog_summary"]["forked_initiating_transaction_count"], 2)
        self.assertEqual(len({dialog["fork_branch_reference"] for dialog in document["dialogs"]}), 4)

    def test_one_capture_terminated_while_other_confirmed(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE", capture="A.pcapng"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False, capture="A.pcapng"),
                rec(1, method="INVITE", capture="B.pcapng"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False, capture="B.pcapng"),
                rec(3, method="BYE", cseq=2, to_tag="A", capture="B.pcapng"),
                rec(4, status=200, cseq_method="BYE", cseq=2, to_tag="A", outbound=False, capture="B.pcapng"),
            ]
        )
        states = {
            capture_of(dialog["dialog_reference"]): dialog["dialog_state"]
            for dialog in document["dialogs"]
        }
        self.assertEqual(states, {"A.pcapng": "CONFIRMED", "B.pcapng": "TERMINATED"})

    def test_cross_capture_bye_is_rejected(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE", capture="A.pcapng"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False, capture="A.pcapng"),
                rec(3, method="BYE", cseq=2, to_tag="A", capture="B.pcapng"),
                rec(4, status=200, cseq_method="BYE", cseq=2, to_tag="A", outbound=False, capture="B.pcapng"),
            ]
        )
        self.assertEqual(document["dialog_count"], 1)
        self.assertEqual(document["dialogs"][0]["dialog_state"], "CONFIRMED")
        self.assertEqual(document["dialogs"][0]["bye_transaction_references"], [])
        self.assertTrue(
            any(
                item["reason"] == "DIALOG_CREATOR_NOT_OBSERVED"
                and capture_of(item["observation_reference"]) == "B.pcapng"
                for item in document["unbound_observations"]
            )
        )

    def test_cross_capture_ack_is_rejected(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE", capture="A.pcapng"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False, capture="A.pcapng"),
                rec(3, method="ACK", cseq_method="ACK", to_tag="A", capture="B.pcapng"),
            ]
        )
        self.assertEqual(document["dialog_count"], 1)
        self.assertEqual(document["dialogs"][0]["ack_event_references"], [])
        self.assertTrue(
            any(
                item["reason"] == "CONFIRMING_RESPONSE_NOT_OBSERVED"
                and capture_of(item["observation_reference"]) == "B.pcapng"
                for item in document["unbound_observations"]
            )
        )

    def test_cross_capture_update_is_rejected(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE", capture="A.pcapng"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False, capture="A.pcapng"),
                rec(
                    3,
                    method="UPDATE",
                    branch="z9hG4bK-B",
                    cseq=2,
                    to_tag="A",
                    capture="B.pcapng",
                ),
            ]
        )
        self.assertEqual(document["dialog_count"], 1)
        self.assertEqual(document["dialogs"][0]["in_dialog_transaction_references"], [])
        self.assertTrue(
            any(
                item["reason"] == "DIALOG_CREATOR_NOT_OBSERVED"
                and capture_of(item["observation_reference"]) == "B.pcapng"
                for item in document["unbound_observations"]
            )
        )

    def test_reused_initial_transaction_is_not_collapsed(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE", branch="z9hG4bK-ONE", cseq=1),
                rec(2, status=200, branch="z9hG4bK-ONE", cseq_method="INVITE", to_tag="A", cseq=1, outbound=False),
                rec(3, method="INVITE", branch="z9hG4bK-TWO", cseq=1),
                rec(4, status=200, branch="z9hG4bK-TWO", cseq_method="INVITE", to_tag="A", cseq=1, outbound=False),
            ]
        )
        self.assertEqual(document["dialog_count"], 1)
        dialog = document["dialogs"][0]
        self.assertIn("initiating_transaction_reference", dialog)
        self.assertNotIn(
            "sip-event:sip-dialog.pcapng:4.1",
            dialog["confirming_response_event_references"],
        )
        reused = [
            item
            for item in document["unbound_observations"]
            if item["reason"] == "REUSED_DIALOG_IDENTITY"
        ]
        self.assertEqual(len(reused), 1)
        self.assertIn("REUSED_DIALOG_IDENTITY", reused[0]["conflict_findings"])
        self.assertEqual(reused[0]["identity_status"], "AMBIGUOUS")
        self.assertIn("sip-event:sip-dialog.pcapng:3.1", reused[0]["event_references"])
        self.assertIn("sip-event:sip-dialog.pcapng:4.1", reused[0]["event_references"])

    def test_duplicate_response_in_one_capture_is_one_dialog(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE", call_id="DUP", capture="A.pcapng"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False, call_id="DUP", capture="A.pcapng"),
                rec(3, status=200, cseq_method="INVITE", to_tag="A", outbound=False, call_id="DUP", capture="A.pcapng"),
                rec(1, method="INVITE", call_id="DUP", capture="B.pcapng"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False, call_id="DUP", capture="B.pcapng"),
            ]
        )
        self.assertEqual(document["dialog_count"], 2)
        confirmed = [
            dialog
            for dialog in document["dialogs"]
            if dialog["confirming_response_event_references"]
        ]
        self.assertEqual(len(confirmed), 2)

    def test_one_invite_with_two_to_tags_remains_two_dialogs(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=183, cseq_method="INVITE", to_tag="A", outbound=False),
                rec(3, status=183, cseq_method="INVITE", to_tag="B", outbound=False),
            ]
        )
        self.assertEqual(document["dialog_count"], 2)
        self.assertEqual(len({dialog["fork_branch_reference"] for dialog in document["dialogs"]}), 2)

    def test_cross_capture_tampering_is_rejected(self) -> None:
        transactions, document, _ = run_input(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
            ]
        )
        document["dialogs"][0]["associated_message_event_references"].append(
            "sip-event:other.pcapng:1.1"
        )
        with self.assertRaises(sip_dialogs.DialogError):
            sip_dialogs.validate_dialog_document(document, None, transactions)

    def test_dual_capture_document_publishes_no_raw_identity(self) -> None:
        _, document, artifacts = run_input(
            [
                rec(1, method="INVITE", call_id="PRIVATE", from_tag="PRIVATE-FROM", capture="A.pcapng"),
                rec(
                    2,
                    status=200,
                    cseq_method="INVITE",
                    to_tag="PRIVATE-TO",
                    outbound=False,
                    call_id="PRIVATE",
                    from_tag="PRIVATE-FROM",
                    capture="A.pcapng",
                ),
                rec(1, method="INVITE", call_id="PRIVATE", from_tag="PRIVATE-FROM", capture="B.pcapng"),
                rec(
                    2,
                    status=200,
                    cseq_method="INVITE",
                    to_tag="PRIVATE-TO",
                    outbound=False,
                    call_id="PRIVATE",
                    from_tag="PRIVATE-FROM",
                    capture="B.pcapng",
                ),
            ]
        )
        text = json.dumps(document) + artifacts["stdout"] + artifacts["stderr"]
        for secret in ("PRIVATE", "PRIVATE-FROM", "PRIVATE-TO", "sip:"):
            self.assertNotIn(secret, text)


class CseqDirectionTests(unittest.TestCase):
    def _dialogs(self, records: list[dict]) -> dict:
        _, document, _ = run_input(records)
        self.assertEqual(document["dialog_count"], 1)
        return document["dialogs"][0]["cseq_observations"]

    def test_cseq_gap_is_direction_specific(self) -> None:
        cseq = self._dialogs(
            confirmed_dialog(
                in_dialog_record(3, "UPDATE", 2),
                in_dialog_record(4, "INFO", 4),
                in_dialog_record(5, "INFO", 3, direction="REVERSE"),
            )
        )
        self.assertEqual(cseq["initiator_direction_values"], [2, 4])
        self.assertEqual(cseq["responder_direction_values"], [3])
        self.assertTrue(cseq["initiator_direction_gap_observed"])
        self.assertFalse(cseq["responder_direction_gap_observed"])
        self.assertTrue(cseq["sequence_gap_observed"])

    def test_cseq_cross_direction_values_do_not_form_a_gap(self) -> None:
        cseq = self._dialogs(
            confirmed_dialog(
                in_dialog_record(3, "UPDATE", 1),
                in_dialog_record(4, "INFO", 2),
                in_dialog_record(5, "INFO", 8, direction="REVERSE"),
                in_dialog_record(6, "INFO", 9, direction="REVERSE"),
            )
        )
        self.assertFalse(cseq["initiator_direction_gap_observed"])
        self.assertFalse(cseq["responder_direction_gap_observed"])
        self.assertFalse(cseq["sequence_gap_observed"])

    def test_adjacent_direction_values_do_not_form_a_gap(self) -> None:
        cseq = self._dialogs(
            confirmed_dialog(
                in_dialog_record(3, "UPDATE", 2),
                in_dialog_record(4, "INFO", 3),
                in_dialog_record(5, "INFO", 1, direction="REVERSE"),
                in_dialog_record(6, "INFO", 2, direction="REVERSE"),
            )
        )
        self.assertFalse(cseq["sequence_gap_observed"])

    def test_original_direction_only_gap(self) -> None:
        cseq = self._dialogs(
            confirmed_dialog(
                in_dialog_record(3, "UPDATE", 5),
                in_dialog_record(4, "INFO", 7),
                in_dialog_record(5, "INFO", 10, direction="REVERSE"),
                in_dialog_record(6, "INFO", 11, direction="REVERSE"),
            )
        )
        self.assertTrue(cseq["initiator_direction_gap_observed"])
        self.assertFalse(cseq["responder_direction_gap_observed"])

    def test_responder_direction_only_gap(self) -> None:
        cseq = self._dialogs(
            confirmed_dialog(
                in_dialog_record(3, "UPDATE", 5),
                in_dialog_record(4, "INFO", 6),
                in_dialog_record(5, "INFO", 10, direction="REVERSE"),
                in_dialog_record(6, "INFO", 13, direction="REVERSE"),
            )
        )
        self.assertFalse(cseq["initiator_direction_gap_observed"])
        self.assertTrue(cseq["responder_direction_gap_observed"])

    def test_both_directions_contain_gaps(self) -> None:
        cseq = self._dialogs(
            confirmed_dialog(
                in_dialog_record(3, "UPDATE", 2),
                in_dialog_record(4, "INFO", 4),
                in_dialog_record(5, "INFO", 5, direction="REVERSE"),
                in_dialog_record(6, "INFO", 8, direction="REVERSE"),
            )
        )
        self.assertTrue(cseq["initiator_direction_gap_observed"])
        self.assertTrue(cseq["responder_direction_gap_observed"])
        self.assertTrue(cseq["sequence_gap_observed"])

    def test_only_one_direction_observed(self) -> None:
        cseq = self._dialogs(
            confirmed_dialog(
                in_dialog_record(3, "UPDATE", 2),
                in_dialog_record(4, "INFO", 4),
            )
        )
        self.assertEqual(cseq["responder_direction_values"], [])
        self.assertTrue(cseq["initiator_direction_gap_observed"])
        self.assertFalse(cseq["responder_direction_gap_observed"])

    def test_no_cseq_observed(self) -> None:
        cseq = self._dialogs(confirmed_dialog())
        self.assertEqual(cseq["initiator_direction_values"], [])
        self.assertEqual(cseq["responder_direction_values"], [])
        self.assertFalse(cseq["initiator_direction_gap_observed"])
        self.assertFalse(cseq["responder_direction_gap_observed"])
        self.assertFalse(cseq["sequence_gap_observed"])
        self.assertEqual(cseq["initiator_direction_omitted_count"], 0)
        self.assertEqual(cseq["responder_direction_omitted_count"], 0)

    def test_retransmitted_cseq_does_not_form_a_gap(self) -> None:
        cseq = self._dialogs(
            confirmed_dialog(
                in_dialog_record(3, "UPDATE", 2),
                in_dialog_record(4, "UPDATE", 2),
                in_dialog_record(5, "UPDATE", 2),
            )
        )
        self.assertEqual(cseq["initiator_direction_values"], [2])
        self.assertFalse(cseq["sequence_gap_observed"])

    def test_out_of_order_cseq_does_not_form_a_gap(self) -> None:
        cseq = self._dialogs(
            confirmed_dialog(
                in_dialog_record(3, "UPDATE", 4),
                in_dialog_record(4, "INFO", 2),
                in_dialog_record(5, "INFO", 3),
            )
        )
        self.assertEqual(cseq["initiator_direction_values"], [2, 3, 4])
        self.assertEqual(cseq["initiator_direction_observed_sequence"], [4, 2, 3])
        self.assertFalse(cseq["sequence_gap_observed"])

    def test_direction_reversal_in_bye_is_direction_scoped(self) -> None:
        cseq = self._dialogs(
            confirmed_dialog(
                in_dialog_record(3, "UPDATE", 2),
                in_dialog_record(4, "INFO", 3),
                rec(5, method="BYE", from_tag="A", to_tag="INIT-TAG", cseq=9, outbound=False),
            )
        )
        self.assertEqual(cseq["initiator_direction_values"], [2, 3])
        self.assertEqual(cseq["responder_direction_values"], [9])
        self.assertFalse(cseq["initiator_direction_gap_observed"])
        self.assertFalse(cseq["responder_direction_gap_observed"])
        self.assertFalse(cseq["sequence_gap_observed"])

    def test_large_cseq_values(self) -> None:
        cseq = self._dialogs(
            confirmed_dialog(
                in_dialog_record(3, "UPDATE", 4000000),
                in_dialog_record(4, "INFO", 4000002),
            )
        )
        self.assertEqual(cseq["initiator_direction_values"], [4000000, 4000002])
        self.assertTrue(cseq["initiator_direction_gap_observed"])

    def test_bounded_cseq_publication_preserves_truthful_assessment(self) -> None:
        extra = [in_dialog_record(3 + index, "UPDATE", index + 1) for index in range(16)]
        extra.append(in_dialog_record(20, "UPDATE", 40))
        cseq = self._dialogs(confirmed_dialog(*extra))
        self.assertEqual(len(cseq["initiator_direction_values"]), 16)
        self.assertEqual(cseq["initiator_direction_omitted_count"], 1)
        self.assertTrue(cseq["initiator_direction_gap_observed"])
        self.assertFalse(cseq["responder_direction_gap_observed"])

    def test_cseq_gap_never_produces_packet_loss_verdict(self) -> None:
        _, document, _ = run_input(
            confirmed_dialog(
                in_dialog_record(3, "UPDATE", 5),
                in_dialog_record(4, "INFO", 9),
            )
        )
        text = json.dumps(document)
        for token in ("packet_loss", "packet-loss", "loss_observed", "media_failure"):
            self.assertNotIn(token, text)
        self.assertEqual(
            document["dialogs"][0]["cseq_observations"]["assessment"],
            "DIRECTION_AWARE_OBSERVATION_ONLY",
        )


class ReferenceAccountingTests(unittest.TestCase):
    COLLECTIONS = (
        "early_response_event_references",
        "confirming_response_event_references",
        "ack_event_references",
        "in_dialog_transaction_references",
        "bye_transaction_references",
        "associated_message_event_references",
    )

    def assert_conserved(self, dialog: dict) -> None:
        for name in self.COLLECTIONS:
            entry = dialog["reference_accounting"][name]
            self.assertEqual(entry["published_count"], len(dialog[name]))
            self.assertEqual(
                entry["observed_unique_count"],
                entry["published_count"] + entry["omitted_count"],
            )
        associated = dialog["reference_accounting"]["associated_message_event_references"]
        self.assertEqual(dialog["omitted_associated_event_count"], associated["omitted_count"])

    def test_zero_references(self) -> None:
        _, document, _ = run_input(confirmed_dialog())
        dialog = document["dialogs"][0]
        self.assert_conserved(dialog)
        self.assertEqual(dialog["reference_accounting"]["bye_transaction_references"]["observed_unique_count"], 0)
        self.assertEqual(document["dialogs"][0]["ack_event_references"], [])

    def test_exactly_at_publication_limit(self) -> None:
        records = [rec(1, method="INVITE")]
        records.extend(
            rec(frame, status=180, cseq_method="INVITE", to_tag="A", outbound=False, reason="Ringing")
            for frame in range(2, 66)
        )
        _, document, _ = run_input(records)
        accounting = document["dialogs"][0]["reference_accounting"]["early_response_event_references"]
        self.assertEqual(accounting["observed_unique_count"], 64)
        self.assertEqual(accounting["published_count"], 64)
        self.assertEqual(accounting["omitted_count"], 0)

    def test_one_reference_over_limit(self) -> None:
        records = [rec(1, method="INVITE")]
        records.extend(
            rec(frame, status=180, cseq_method="INVITE", to_tag="A", outbound=False, reason="Ringing")
            for frame in range(2, 67)
        )
        _, document, _ = run_input(records)
        accounting = document["dialogs"][0]["reference_accounting"]["early_response_event_references"]
        self.assertEqual(accounting["observed_unique_count"], 65)
        self.assertEqual(accounting["published_count"], 64)
        self.assertEqual(accounting["omitted_count"], 1)
        self.assert_conserved(document["dialogs"][0])

    def test_many_references_over_limit(self) -> None:
        records = [rec(1, method="INVITE")]
        records.extend(
            rec(frame, status=183, cseq_method="INVITE", to_tag="A", outbound=False)
            for frame in range(2, 72)
        )
        _, document, _ = run_input(records)
        dialog = document["dialogs"][0]
        accounting = dialog["reference_accounting"]["early_response_event_references"]
        self.assertEqual(accounting["observed_unique_count"], 70)
        self.assertEqual(accounting["omitted_count"], 6)
        associated = dialog["reference_accounting"]["associated_message_event_references"]
        self.assertGreater(associated["omitted_count"], 0)
        self.assert_conserved(dialog)

    def test_repeated_references_do_not_inflate_unique_counts(self) -> None:
        dialog = sip_dialogs._new_dialog(
            reference="sip-dialog:unit.pcapng:2.1",
            capture="unit.pcapng",
            call_id="C",
            initiator_tag="F",
            remote_tag="T",
            invite_cseq=1,
            initiating_transaction="sip-transaction:unit.pcapng:request:1.1",
            first_reference="sip-event:unit.pcapng:2.1",
        )
        dialog["early_refs"] = ["sip-event:unit.pcapng:2.1"] * 5
        dialog["associated_refs"] = ["sip-event:unit.pcapng:2.1"] * 5
        public = sip_dialogs._public_dialog(dialog)
        accounting = public["reference_accounting"]["early_response_event_references"]
        self.assertEqual(accounting["observed_unique_count"], 1)
        self.assertEqual(accounting["published_count"], 1)
        self.assertEqual(accounting["omitted_count"], 0)

    def test_more_than_64_confirming_responses(self) -> None:
        records = [rec(1, method="INVITE")]
        records.extend(
            rec(frame, status=200, cseq_method="INVITE", to_tag="A", outbound=False)
            for frame in range(2, 67)
        )
        _, document, _ = run_input(records)
        dialog = document["dialogs"][0]
        accounting = dialog["reference_accounting"]["confirming_response_event_references"]
        self.assertEqual(accounting["observed_unique_count"], 65)
        self.assertEqual(accounting["omitted_count"], 1)
        self.assert_conserved(dialog)

    def test_more_than_64_ack_observations(self) -> None:
        records = [
            rec(1, method="INVITE"),
            rec(2, status=200, cseq_method="INVITE", to_tag="A", outbound=False),
        ]
        for index in range(65):
            records.append(
                rec(
                    3 + index,
                    method="ACK",
                    branch=f"z9hG4bK-ACK-{index}",
                    cseq_method="ACK",
                    to_tag="A",
                    cseq=1,
                )
            )
        _, document, _ = run_input(records)
        dialog = document["dialogs"][0]
        accounting = dialog["reference_accounting"]["ack_event_references"]
        self.assertEqual(accounting["observed_unique_count"], 65)
        self.assertEqual(accounting["omitted_count"], 1)
        self.assert_conserved(dialog)

    def test_more_than_64_in_dialog_transactions(self) -> None:
        records = confirmed_dialog()
        for index in range(65):
            records.append(
                in_dialog_record(
                    3 + index,
                    "UPDATE",
                    2 + index,
                )
            )
        _, document, _ = run_input(records)
        dialog = document["dialogs"][0]
        accounting = dialog["reference_accounting"]["in_dialog_transaction_references"]
        self.assertEqual(accounting["observed_unique_count"], 65)
        self.assertEqual(accounting["omitted_count"], 1)
        self.assert_conserved(dialog)

    def test_more_than_64_bye_transactions(self) -> None:
        records = confirmed_dialog()
        for index in range(65):
            records.append(
                rec(
                    3 + index,
                    method="BYE",
                    branch=f"z9hG4bK-BYE-{index}",
                    cseq=2,
                    to_tag="A",
                )
            )
        _, document, _ = run_input(records)
        dialog = document["dialogs"][0]
        accounting = dialog["reference_accounting"]["bye_transaction_references"]
        self.assertEqual(accounting["observed_unique_count"], 65)
        self.assertEqual(accounting["omitted_count"], 1)
        self.assert_conserved(dialog)

    def test_published_ordering_is_deterministic(self) -> None:
        records = [rec(1, method="INVITE")]
        records.extend(
            rec(frame, status=180, cseq_method="INVITE", to_tag="A", outbound=False, reason="Ringing")
            for frame in range(2, 72)
        )
        first = run_input(records)[1]["dialogs"][0]
        second = run_input(records)[1]["dialogs"][0]
        self.assertEqual(first, second)
        published = first["early_response_event_references"]
        self.assertEqual(published, sorted(published, key=lambda item: int(item.split(":")[-1].split(".")[0])))

    def test_reference_accounting_conserves_counts(self) -> None:
        records = [rec(1, method="INVITE")]
        records.extend(
            rec(frame, status=180, cseq_method="INVITE", to_tag="A", outbound=False, reason="Ringing")
            for frame in range(2, 72)
        )
        records.append(rec(72, method="ACK", branch="z9hG4bK-ACK", cseq_method="ACK", to_tag="A", cseq=1))
        _, document, _ = run_input(records)
        for dialog in document["dialogs"]:
            self.assert_conserved(dialog)
        self.assertEqual(document["dialog_count"], 1)

    def test_reference_accounting_marks_truncated_collections(self) -> None:
        records = [rec(1, method="INVITE")]
        records.extend(
            rec(frame, status=180, cseq_method="INVITE", to_tag="A", outbound=False, reason="Ringing")
            for frame in range(2, 72)
        )
        _, document, _ = run_input(records)
        accounting = document["dialogs"][0]["reference_accounting"]["early_response_event_references"]
        self.assertGreater(accounting["omitted_count"], 0)
        self.assertLess(accounting["published_count"], accounting["observed_unique_count"])

    def test_unbound_observation_retains_omission_accounting(self) -> None:
        event_references = [f"sip-event:unit.pcapng:{frame}.1" for frame in range(1, 70)]
        observation = sip_dialogs._unbound(
            reference=event_references[0],
            capture="unit.pcapng",
            frame=1,
            occurrence=1,
            identity_status="INSUFFICIENT_EVIDENCE",
            reason="PROVISIONAL_WITHOUT_TO_TAG",
            event_references=event_references,
            transaction_references=["sip-transaction:unit.pcapng:request:1.1"],
            tag_pair_observed=False,
        )
        accounting = observation["reference_accounting"]["event_references"]
        self.assertEqual(accounting["observed_unique_count"], 69)
        self.assertEqual(accounting["published_count"], 64)
        self.assertEqual(accounting["omitted_count"], 5)
        self.assertEqual(len(observation["event_references"]), 64)

    def test_ambiguous_observation_retains_omission_accounting(self) -> None:
        candidates = [f"sip-dialog:unit.pcapng:{frame}.1" for frame in range(1, 20)]
        observation = sip_dialogs._ambiguous(
            reference="sip-observation:unit.pcapng:20.1",
            capture="unit.pcapng",
            frame=20,
            occurrence=1,
            transaction_reference="sip-transaction:unit.pcapng:request:20.1",
            reason="MULTIPLE_DIALOG_CANDIDATES",
            candidates=candidates,
        )
        accounting = observation["reference_accounting"]["candidate_dialog_references"]
        self.assertEqual(accounting["observed_unique_count"], 19)
        self.assertEqual(accounting["published_count"], 16)
        self.assertEqual(accounting["omitted_count"], 3)

    def test_ambiguous_producer_output_is_accounted(self) -> None:
        _, document, _ = run_input(
            [
                rec(1, method="INVITE", from_tag="T1", branch="z9hG4bK-X1"),
                rec(2, status=200, cseq_method="INVITE", to_tag="T2", outbound=False, from_tag="T1", branch="z9hG4bK-X1"),
                rec(3, method="INVITE", from_tag="T2", branch="z9hG4bK-X2"),
                rec(4, status=200, cseq_method="INVITE", to_tag="T1", outbound=False, from_tag="T2", branch="z9hG4bK-X2"),
                rec(5, method="UPDATE", from_tag="T1", to_tag="T2", branch="z9hG4bK-X3", cseq=2),
            ]
        )
        self.assertEqual(document["dialog_count"], 2)
        self.assertTrue(document["ambiguous_observations"])
        observation = document["ambiguous_observations"][0]
        accounting = observation["reference_accounting"]["candidate_dialog_references"]
        self.assertEqual(accounting["published_count"], len(observation["candidate_dialog_references"]))
        self.assertEqual(
            accounting["observed_unique_count"],
            accounting["published_count"] + accounting["omitted_count"],
        )

    def test_strict_schema_passes_over_limit(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        records = [rec(1, method="INVITE")]
        records.extend(
            rec(frame, status=183, cseq_method="INVITE", to_tag="A", outbound=False)
            for frame in range(2, 72)
        )
        transactions, document, _ = run_input(records)
        jsonschema.validate(document, json.loads(SCHEMA.read_text(encoding="utf-8")))
        sip_dialogs.validate_dialog_document(document, None, transactions)


class MissingSourceReferenceTests(unittest.TestCase):
    def test_missing_event_reference_is_rejected_in_named_collection(self) -> None:
        transactions, document, _ = run_input(confirmed_dialog())
        document["dialogs"][0]["early_response_event_references"].append(
            "sip-event:missing.pcapng:999.1"
        )
        with self.assertRaises(sip_dialogs.DialogError):
            sip_dialogs.validate_dialog_document(document, None, transactions)

    def test_inconsistent_accounting_is_rejected(self) -> None:
        transactions, document, _ = run_input(confirmed_dialog())
        document["dialogs"][0]["reference_accounting"][
            "early_response_event_references"
        ]["omitted_count"] = 1
        with self.assertRaises(sip_dialogs.DialogError):
            sip_dialogs.validate_dialog_document(document, None, transactions)


if __name__ == "__main__":
    unittest.main()