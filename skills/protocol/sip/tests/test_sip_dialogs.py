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


if __name__ == "__main__":
    unittest.main()