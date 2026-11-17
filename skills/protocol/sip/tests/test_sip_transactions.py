#!/usr/bin/env python3
"""Deterministic tests for SIP transaction correlation and transaction evidence."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
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
CLI = SCRIPTS / "extract-sip.py"
TRANSACTION_SCHEMA = PACKAGE / "schemas" / "sip-transactions.schema.json"
EVENT_SCHEMA = PACKAGE / "schemas" / "sip-events.schema.json"

sys.path.insert(0, str(SCRIPTS))
import sip_model  # noqa: E402
import sip_transactions  # noqa: E402

TSHARK = shutil.which("tshark")
TEXT2PCAP = shutil.which("text2pcap")

REASONS = {
    100: "Trying",
    180: "Ringing",
    183: "Session Progress",
    200: "OK",
    401: "Unauthorized",
    404: "Not Found",
    407: "Proxy Authentication Required",
    486: "Busy Here",
    487: "Request Terminated",
}
PRIVATE_TOKENS = (
    "PRIVATE-CALL-ID",
    "PRIVATE-BRANCH",
    "PRIVATE-FROM-TAG",
    "PRIVATE-TO-TAG",
    "PRIVATE-USER",
    "PRIVATE-AUTH",
    "PRIVATE-BODY",
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def record(
    frame: int,
    *,
    method: str | None = None,
    status: int | None = None,
    branch: str = "z9hG4bK-PRIVATE-BRANCH",
    sent_by: str = "192.0.2.10:5060",
    cseq: int = 1,
    cseq_method: str | None = None,
    call_id: str = "PRIVATE-CALL-ID",
    from_tag: str = "PRIVATE-FROM-TAG",
    to_tag: str | None = None,
    protocol: str = "UDP",
    stream_id: int | None = None,
    reassembly: str | None = None,
    occurrence: int = 1,
    addressed_from_client: bool | None = None,
    capture_truncated: bool = False,
    content_length: int = 0,
    body_length: int = 0,
    capture: str = "synthetic-transactions.pcapng",
) -> dict:
    is_request = method is not None
    if addressed_from_client is None:
        addressed_from_client = is_request
    if addressed_from_client:
        source_address, destination_address = "192.0.2.10", "192.0.2.20"
    else:
        source_address, destination_address = "192.0.2.20", "192.0.2.10"
    headers: dict = {
        "call_id": call_id,
        "cseq_sequence": cseq,
        "cseq_method": cseq_method or method or "REGISTER",
        "via": [
            {
                "branch": branch,
                "sent_by": sent_by,
                "transport": protocol,
            }
        ],
        "from": {"count": 1, "tag": from_tag, "uri": "sip:PRIVATE-USER@ims.private.example"},
        "to": {"count": 1, "tag": to_tag, "uri": "sip:PRIVATE-USER@ims.private.example"},
        "content_length": content_length,
        "body_length": body_length,
        "request_uri": f"sip:{'PRIVATE-USER'}@ims.private.example",
    }
    if method is not None:
        headers["method"] = method
        headers["max_forwards"] = 70
        headers["contact_count"] = 1
    if status is not None:
        headers["status_code"] = status
        headers["reason_phrase"] = REASONS.get(status, "Unknown")
    transport = {
        "protocol": protocol,
        "source_address": source_address,
        "source_port": 5060,
        "destination_address": destination_address,
        "destination_port": 5060,
        "stream_id": stream_id,
    }
    if reassembly is not None:
        transport["reassembly"] = reassembly
    if protocol == "TCP" and reassembly is None:
        transport["reassembly"] = "SINGLE_SEGMENT"
    return {
        "capture_file": capture,
        "frame_number": frame,
        "frame_time_epoch": f"1700000000.{frame:06d}000",
        "frame_time_relative": f"{frame}.000000000",
        "message_occurrence": occurrence,
        "transport": transport,
        "headers": headers,
        "capture_truncated": capture_truncated,
    }


def run_transactions(directory: Path, records: list[dict]) -> tuple[subprocess.CompletedProcess, dict, list[dict]]:
    source = directory / "input.jsonl"
    source.write_text("\n".join(json.dumps(item, separators=(",", ":")) for item in records) + "\n", encoding="utf-8")
    events_path = directory / "events.jsonl"
    transactions_path = directory / "transactions.json"
    completed = run(
        [
            sys.executable,
            str(CLI),
            str(source),
            "--output",
            str(events_path),
            "--transaction-output",
            str(transactions_path),
            "--force",
        ]
    )
    document = load_json(transactions_path) if transactions_path.is_file() else {}
    events = load_jsonl(events_path) if events_path.is_file() else []
    return completed, document, events


def tx_of_type(document: dict, transaction_type: str) -> dict:
    matches = [tx for tx in document["transactions"] if tx["transaction_type"] == transaction_type]
    if not matches:
        raise AssertionError(f"no transaction of type {transaction_type}: {[tx['transaction_type'] for tx in document['transactions']]}")
    return matches[0]


def tx_for_event(document: dict, event_reference: str) -> dict:
    for transaction in document["transactions"]:
        if event_reference in (
            transaction["request_event_references"]
            + transaction["response_event_references"]
            + transaction["associated_control_event_references"]
        ):
            return transaction
    raise AssertionError(f"event reference not assigned: {event_reference}")


def event_ref(frame: int, occurrence: int = 1, capture: str = "synthetic-transactions.pcapng") -> str:
    return f"sip-event:{capture}:{frame}.{occurrence}"


def require_schema(test: unittest.TestCase) -> None:
    if jsonschema is None:
        if os.environ.get("CI"):
            test.fail("jsonschema is required for the transaction schema gate in CI")
        test.skipTest("jsonschema unavailable")


class TransactionTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def correlate(self, records: list[dict]) -> tuple[dict, list[dict], subprocess.CompletedProcess]:
        completed, document, events = run_transactions(self.base, records)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return document, events, completed


class BasicTransactionTests(TransactionTestBase):
    def assert_pair(
        self,
        method: str,
        status: int,
        expected_state: str = "FINAL_RESPONSE_OBSERVED",
        expected_matching: str = "MATCHED",
    ) -> dict:
        document, events, _ = self.correlate(
            [
                record(1, method=method, cseq=1, cseq_method=method),
                record(2, status=status, cseq=1, cseq_method=method, to_tag="PRIVATE-TO-TAG", addressed_from_client=False),
            ]
        )
        self.assertEqual(document["transaction_count"], 1, document)
        transaction = document["transactions"][0]
        self.assertEqual(transaction["matching_status"], expected_matching)
        self.assertEqual(transaction["transaction_state"], expected_state)
        self.assertEqual(transaction["request_event_references"], [event_ref(1)])
        self.assertEqual(transaction["response_event_references"], [event_ref(2)])
        self.assertEqual(transaction["first_observed_frame"], 1)
        self.assertEqual(transaction["last_observed_frame"], 2)
        self.assertEqual(transaction["request_frame"], 1)
        self.assertEqual(transaction["response_frame"], 2)
        return transaction

    def test_register_401(self) -> None:
        transaction = self.assert_pair("REGISTER", 401, "FINAL_RESPONSE_OBSERVED")
        self.assertEqual(transaction["transaction_type"], "NON_INVITE")
        self.assertIn(401, transaction["final_response_status_codes"])

    def test_register_200(self) -> None:
        self.assert_pair("REGISTER", 200)

    def test_invite_100(self) -> None:
        transaction = self.assert_pair("INVITE", 100, "PROVISIONAL_RESPONSE_OBSERVED", "PARTIALLY_MATCHED")
        self.assertIn("FINAL_RESPONSE_NOT_OBSERVED", transaction["missing_evidence"])

    def test_invite_180(self) -> None:
        self.assert_pair("INVITE", 180, "PROVISIONAL_RESPONSE_OBSERVED", "PARTIALLY_MATCHED")

    def test_invite_183(self) -> None:
        self.assert_pair("INVITE", 183, "PROVISIONAL_RESPONSE_OBSERVED", "PARTIALLY_MATCHED")

    def test_invite_200(self) -> None:
        transaction = self.assert_pair("INVITE", 200, "FINAL_RESPONSE_OBSERVED")
        self.assertIn("DIALOG_ASSOCIATION_UNAVAILABLE", transaction["missing_evidence"])

    def test_invite_486(self) -> None:
        transaction = self.assert_pair("INVITE", 486, "FINAL_RESPONSE_OBSERVED")
        self.assertIn("ACK_NOT_OBSERVED", transaction["missing_evidence"])

    def test_invite_487(self) -> None:
        self.assert_pair("INVITE", 487, "FINAL_RESPONSE_OBSERVED")

    def test_options_200(self) -> None:
        self.assert_pair("OPTIONS", 200)

    def test_bye_200(self) -> None:
        self.assert_pair("BYE", 200)

    def test_update_200(self) -> None:
        self.assert_pair("UPDATE", 200)

    def test_message_200(self) -> None:
        self.assert_pair("MESSAGE", 200)

    def test_prack_200(self) -> None:
        self.assert_pair("PRACK", 200)

    def test_extension_method(self) -> None:
        transaction = self.assert_pair("X-CUSTOM", 200)
        self.assertEqual(transaction["transaction_type"], "NON_INVITE")
        self.assertEqual(transaction["transaction_method"], "X-CUSTOM")


class MatchingIntegrityTests(TransactionTestBase):
    def test_different_call_id(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", call_id="A"),
                record(2, status=200, cseq_method="REGISTER", call_id="B", addressed_from_client=False),
            ]
        )
        self.assertEqual(document["transaction_count"], 2)
        request_tx = tx_of_type(document, "NON_INVITE")
        self.assertEqual(request_tx["matching_status"], "REQUEST_ONLY")
        response_tx = tx_of_type(document, "RESPONSE_ONLY")
        self.assertEqual(response_tx["matching_status"], "NOT_ESTABLISHED")
        self.assertIn("CALL_ID_MISMATCH", response_tx["conflict_findings"])

    def test_same_call_id_different_branch(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", branch="z9hG4bK-A", call_id="C"),
                record(2, status=200, branch="z9hG4bK-B", call_id="C", cseq_method="REGISTER", addressed_from_client=False),
            ]
        )
        self.assertEqual(document["transaction_count"], 2)
        self.assertIn("REQUEST_NOT_OBSERVED", tx_of_type(document, "RESPONSE_ONLY")["missing_evidence"])

    def test_same_call_id_and_cseq_different_method(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", call_id="C", cseq=1),
                record(2, status=200, call_id="C", cseq=1, cseq_method="INVITE", addressed_from_client=False),
            ]
        )
        self.assertEqual(document["transaction_count"], 2)
        self.assertEqual(tx_of_type(document, "NON_INVITE")["matching_status"], "REQUEST_ONLY")
        self.assertEqual(tx_of_type(document, "RESPONSE_ONLY")["matching_status"], "RESPONSE_ONLY")

    def test_same_branch_different_sent_by(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", branch="z9hG4bK-A", sent_by="192.0.2.10:5060"),
                record(2, status=200, branch="z9hG4bK-A", sent_by="192.0.2.99:5060", cseq_method="REGISTER", addressed_from_client=False),
            ]
        )
        self.assertEqual(document["transaction_count"], 2)

    def test_same_branch_and_sent_by_incompatible_cseq(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", branch="z9hG4bK-A", cseq=1),
                record(2, status=200, branch="z9hG4bK-A", cseq=2, cseq_method="REGISTER", addressed_from_client=False),
            ]
        )
        self.assertEqual(document["transaction_count"], 2)
        request_tx = tx_of_type(document, "NON_INVITE")
        self.assertEqual(request_tx["matching_status"], "REQUEST_ONLY")
        response_tx = tx_of_type(document, "RESPONSE_ONLY")
        self.assertEqual(response_tx["matching_status"], "NOT_ESTABLISHED")
        self.assertIn("CSEQ_MISMATCH", response_tx["conflict_findings"])
        self.assertEqual(response_tx["transaction_state"], "INCOMPLETE_EVIDENCE")

    def test_response_without_matching_request(self) -> None:
        document, _, _ = self.correlate([record(1, status=200, cseq_method="REGISTER", addressed_from_client=False)])
        transaction = tx_of_type(document, "RESPONSE_ONLY")
        self.assertEqual(transaction["transaction_state"], "RESPONSE_ONLY")
        self.assertEqual(transaction["request_event_references"], [])
        self.assertIn("REQUEST_NOT_OBSERVED", transaction["missing_evidence"])

    def test_request_without_matching_response(self) -> None:
        document, _, _ = self.correlate([record(1, method="REGISTER")])
        transaction = tx_of_type(document, "NON_INVITE")
        self.assertEqual(transaction["transaction_state"], "REQUEST_OBSERVED")
        self.assertEqual(transaction["matching_status"], "REQUEST_ONLY")

    def test_response_with_inconsistent_cseq(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", cseq=1),
                record(2, status=200, cseq=9, cseq_method="REGISTER", addressed_from_client=False),
            ]
        )
        self.assertEqual(document["transaction_count"], 2)
        self.assertIn("CSEQ_MISMATCH", tx_of_type(document, "RESPONSE_ONLY")["conflict_findings"])

    def test_response_with_inconsistent_call_id(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", call_id="A"),
                record(2, status=200, call_id="B", cseq_method="REGISTER", addressed_from_client=False),
            ]
        )
        self.assertIn("CALL_ID_MISMATCH", tx_of_type(document, "RESPONSE_ONLY")["conflict_findings"])

    def test_missing_via_branch(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", branch=None, call_id="C"),
                record(2, status=200, branch=None, call_id="C", cseq_method="REGISTER", addressed_from_client=False),
            ]
        )
        self.assertEqual(document["transaction_count"], 2)
        for transaction in document["transactions"]:
            self.assertEqual(transaction["matching_status"], "NOT_ESTABLISHED")
            self.assertIn("VIA_BRANCH_NOT_OBSERVED", transaction["missing_evidence"])
            self.assertFalse(transaction["transaction_identity_available"])

    def test_missing_cseq(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", cseq=None),
                record(2, status=200, cseq=None, cseq_method="REGISTER", addressed_from_client=False),
            ]
        )
        request_tx = tx_of_type(document, "NON_INVITE")
        self.assertEqual(request_tx["matching_status"], "REQUEST_ONLY")
        self.assertIn("CSEQ_NOT_OBSERVED", request_tx["missing_evidence"])
        response_tx = tx_of_type(document, "RESPONSE_ONLY")
        self.assertEqual(response_tx["matching_status"], "NOT_ESTABLISHED")
        self.assertIn("CSEQ_NOT_OBSERVED", response_tx["missing_evidence"])

    def test_multiple_candidate_transactions(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="INVITE", branch="z9hG4bK-A", call_id="A", cseq=1),
                record(2, method="INVITE", branch="z9hG4bK-A", call_id="B", cseq=2),
                record(3, status=200, branch="z9hG4bK-A", call_id="A", cseq=1, cseq_method="INVITE", addressed_from_client=False),
            ]
        )
        request_tx = tx_of_type(document, "INVITE")
        self.assertEqual(request_tx["matching_status"], "NOT_ESTABLISHED")
        response_tx = tx_of_type(document, "AMBIGUOUS")
        self.assertEqual(response_tx["matching_status"], "AMBIGUOUS")
        self.assertEqual(response_tx["response_event_references"], [event_ref(3)])
        self.assertTrue(response_tx["candidate_transaction_references"])

    def test_conflicting_matching_fields(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", branch="z9hG4bK-A", call_id="A"),
                record(2, method="REGISTER", branch="z9hG4bK-A", call_id="B"),
            ]
        )
        transaction = tx_of_type(document, "NON_INVITE")
        self.assertEqual(transaction["matching_status"], "NOT_ESTABLISHED")
        self.assertIn("CALL_ID_MISMATCH", transaction["conflict_findings"])
        self.assertEqual(len(transaction["conflicting_request_event_references"]), 1)

    def test_call_id_alone_never_matches(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", branch="z9hG4bK-A", call_id="SAME"),
                record(2, status=200, branch="z9hG4bK-B", call_id="SAME", cseq_method="REGISTER", addressed_from_client=False),
            ]
        )
        self.assertEqual(document["transaction_count"], 2)
        self.assertEqual(tx_of_type(document, "NON_INVITE")["matching_status"], "REQUEST_ONLY")


class CancelAckTests(TransactionTestBase):
    def invite_with_cancel(self, cancel_branch: str | None = None, cancel_cseq: int = 1, cancel_call_id: str = "PRIVATE-CALL-ID") -> dict:
        records = [
            record(1, method="INVITE", branch="z9hG4bK-A", cseq=1, call_id="PRIVATE-CALL-ID"),
            record(
                2,
                method="CANCEL",
                branch=cancel_branch or "z9hG4bK-A",
                cseq=cancel_cseq,
                cseq_method="CANCEL",
                call_id=cancel_call_id,
            ),
            record(3, status=200, branch=cancel_branch or "z9hG4bK-A", cseq=cancel_cseq, cseq_method="CANCEL", call_id=cancel_call_id, to_tag="CANCEL-TAG", addressed_from_client=False),
            record(4, status=487, branch="z9hG4bK-A", cseq=1, cseq_method="INVITE", call_id="PRIVATE-CALL-ID", to_tag="INVITE-TAG", addressed_from_client=False),
        ]
        document, _, _ = self.correlate(records)
        return document

    def test_cancel_matching_invite(self) -> None:
        document = self.invite_with_cancel()
        invite = tx_of_type(document, "INVITE")
        cancel = tx_of_type(document, "CANCEL")
        self.assertEqual(cancel["associated_transaction_reference"], invite["transaction_reference"])
        self.assertEqual(invite["transaction_state"], "CANCEL_RESPONSE_SEQUENCE_OBSERVED")
        self.assertIsNone(invite["termination_basis"])
        self.assertFalse(invite["invite_transaction_termination_established"])
        self.assertEqual(invite["cancel_invite_association_status"], "ASSOCIATED")
        self.assertEqual(cancel["matching_status"], "MATCHED")
        self.assertEqual(cancel["final_response_status_codes"], [200])

    def test_cancel_mismatched_branch(self) -> None:
        document = self.invite_with_cancel(cancel_branch="z9hG4bK-B")
        cancel = tx_of_type(document, "CANCEL")
        self.assertIsNone(cancel["associated_transaction_reference"])
        self.assertIn("VIA_BRANCH_MISMATCH", cancel["conflict_findings"])

    def test_cancel_mismatched_cseq(self) -> None:
        document = self.invite_with_cancel(cancel_cseq=9)
        self.assertIsNone(tx_of_type(document, "CANCEL")["associated_transaction_reference"])

    def test_cancel_mismatched_call_id(self) -> None:
        document = self.invite_with_cancel(cancel_call_id="OTHER")
        self.assertIsNone(tx_of_type(document, "CANCEL")["associated_transaction_reference"])

    def test_200_ok_to_cancel(self) -> None:
        document = self.invite_with_cancel()
        cancel = tx_of_type(document, "CANCEL")
        self.assertEqual(cancel["response_event_references"], [event_ref(3)])
        self.assertEqual(cancel["matching_status"], "MATCHED")

    def test_487_response_to_invite(self) -> None:
        document = self.invite_with_cancel()
        invite = tx_of_type(document, "INVITE")
        self.assertIn(event_ref(4), invite["final_response_event_references"])
        self.assertEqual(invite["final_response_status_codes"], [487])

    def test_ack_for_non_2xx_invite(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="INVITE", branch="z9hG4bK-A", cseq=1),
                record(2, status=486, branch="z9hG4bK-A", cseq=1, cseq_method="INVITE", to_tag="T", addressed_from_client=False),
                record(3, method="ACK", branch="z9hG4bK-A", cseq=1, cseq_method="ACK", to_tag="T"),
            ]
        )
        invite = tx_of_type(document, "INVITE")
        self.assertEqual(invite["transaction_state"], "NON_2XX_ACK_OBSERVED")
        self.assertEqual(invite["observed_evidence_status"], "NON_2XX_ACK_OBSERVED")
        self.assertIsNone(invite["rfc_transaction_state"])
        self.assertEqual(invite["associated_control_event_references"], [event_ref(3)])
        self.assertNotIn("ACK_NOT_OBSERVED", invite["missing_evidence"])
        self.assertFalse(any(tx["transaction_type"].startswith("ACK") for tx in document["transactions"]))

    def test_ack_for_2xx_invite_is_independent(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="INVITE", branch="z9hG4bK-A", cseq=1),
                record(2, status=200, branch="z9hG4bK-A", cseq=1, cseq_method="INVITE", to_tag="T", addressed_from_client=False),
                record(3, method="ACK", branch="z9hG4bK-B", cseq=1, cseq_method="ACK", to_tag="T"),
            ]
        )
        invite = tx_of_type(document, "INVITE")
        ack = tx_of_type(document, "ACK_2XX")
        self.assertEqual(invite["associated_control_event_references"], [])
        self.assertNotEqual(invite["transaction_reference"], ack["transaction_reference"])
        self.assertEqual(ack["matching_status"], "REQUEST_ONLY")
        self.assertIn("DIALOG_ASSOCIATION_UNAVAILABLE", ack["missing_evidence"])

    def test_2xx_ack_with_same_branch_is_not_merged(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="INVITE", branch="z9hG4bK-A", cseq=1),
                record(2, status=200, branch="z9hG4bK-A", cseq=1, cseq_method="INVITE", to_tag="T", addressed_from_client=False),
                record(3, method="ACK", branch="z9hG4bK-A", cseq=1, cseq_method="ACK", to_tag="T"),
            ]
        )
        invite = tx_of_type(document, "INVITE")
        ack = tx_of_type(document, "ACK_2XX")
        self.assertEqual(invite["associated_control_event_references"], [])
        self.assertNotEqual(invite["transaction_reference"], ack["transaction_reference"])

    def test_ack_without_invite_outcome(self) -> None:
        document, _, _ = self.correlate([record(1, method="ACK", branch="z9hG4bK-A", cseq=1, cseq_method="ACK")])
        ack = tx_of_type(document, "ACK_ORPHAN")
        self.assertEqual(ack["transaction_state"], "REQUEST_ONLY")
        self.assertEqual(ack["matching_status"], "NOT_ESTABLISHED")


class RetransmissionTests(TransactionTestBase):
    def test_udp_invite_retransmission(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="INVITE"),
                record(2, method="INVITE"),
            ]
        )
        transaction = tx_of_type(document, "INVITE")
        self.assertEqual(transaction["retransmission_count"], 0)
        self.assertEqual(transaction["retransmission_candidate_count"], 1)
        self.assertEqual(transaction["retransmission_candidate_event_references"], [event_ref(2)])
        self.assertIn("RETRANSMISSION_FINGERPRINT_INCOMPLETE", transaction["missing_evidence"])
        classifications = {item["event_reference"]: item["classification"] for item in transaction["message_classifications"]}
        self.assertEqual(classifications[event_ref(1)], "ORIGINAL")
        self.assertEqual(classifications[event_ref(2)], "RETRANSMISSION_CANDIDATE")

    def test_udp_response_retransmission(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER"),
                record(2, status=200, cseq_method="REGISTER", addressed_from_client=False),
                record(3, status=200, cseq_method="REGISTER", addressed_from_client=False),
            ]
        )
        transaction = tx_of_type(document, "NON_INVITE")
        self.assertEqual(transaction["retransmission_count"], 0)
        self.assertEqual(transaction["retransmission_candidate_count"], 1)
        self.assertEqual(transaction["final_response_count"], 2)
        self.assertEqual(transaction["distinct_final_response_count"], 1)
        self.assertEqual(transaction["selected_final_response_reference"], event_ref(2))

    def test_repeated_identical_message_in_separate_frame(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="OPTIONS"),
                record(8, method="OPTIONS"),
            ]
        )
        self.assertEqual(tx_of_type(document, "NON_INVITE")["retransmission_candidate_count"], 1)

    def test_same_call_id_and_cseq_different_branch(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", branch="z9hG4bK-A", call_id="C", cseq=1),
                record(2, method="REGISTER", branch="z9hG4bK-B", call_id="C", cseq=1),
            ]
        )
        invites = [tx for tx in document["transactions"] if tx["transaction_type"] == "NON_INVITE"]
        self.assertEqual(len(invites), 2)
        for transaction in invites:
            self.assertEqual(transaction["matching_status"], "REQUEST_ONLY")

    def test_repeated_tcp_message_is_not_sip_retransmission(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", protocol="TCP", stream_id=0),
                record(2, method="REGISTER", protocol="TCP", stream_id=0),
            ]
        )
        transaction = tx_of_type(document, "NON_INVITE")
        self.assertEqual(transaction["retransmission_count"], 0)
        self.assertEqual(transaction["repeated_observation_event_references"], [event_ref(2)])
        classifications = {item["event_reference"]: item["classification"] for item in transaction["message_classifications"]}
        self.assertEqual(classifications[event_ref(2)], "REPEATED_TCP_OBSERVATION")


class AdvancedTransactionTests(TransactionTestBase):
    def test_multiple_provisional_responses(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="INVITE"),
                record(2, status=100, cseq_method="INVITE", addressed_from_client=False),
                record(3, status=180, cseq_method="INVITE", to_tag="T", addressed_from_client=False),
                record(4, status=183, cseq_method="INVITE", to_tag="T", addressed_from_client=False),
            ]
        )
        transaction = tx_of_type(document, "INVITE")
        self.assertEqual(transaction["transaction_state"], "PROVISIONAL_RESPONSE_OBSERVED")
        self.assertEqual(transaction["provisional_response_count"], 3)
        self.assertEqual(transaction["final_response_count"], 0)
        self.assertEqual(len(transaction["provisional_response_event_references"]), 3)

    def test_multiple_distinct_final_responses(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="INVITE"),
                record(2, status=200, cseq_method="INVITE", to_tag="A", addressed_from_client=False),
                record(3, status=200, cseq_method="INVITE", to_tag="B", addressed_from_client=False),
            ]
        )
        transaction = tx_of_type(document, "INVITE")
        self.assertEqual(transaction["final_response_count"], 2)
        self.assertEqual(transaction["distinct_final_response_count"], 2)
        self.assertEqual(transaction["response_branch_count"], 2)
        self.assertIsNone(transaction["selected_final_response_reference"])
        self.assertIn("SINGLE_FINAL_RESPONSE_NOT_ESTABLISHED", transaction["missing_evidence"])

    def test_multiple_to_tags_in_forked_responses(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="INVITE"),
                record(2, status=180, cseq_method="INVITE", to_tag="FORK-A", addressed_from_client=False),
                record(3, status=180, cseq_method="INVITE", to_tag="FORK-B", addressed_from_client=False),
            ]
        )
        transaction = tx_of_type(document, "INVITE")
        self.assertEqual(transaction["response_branch_count"], 2)
        self.assertIsNone(transaction["selected_final_response_reference"])

    def test_out_of_order_request_and_response(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, status=200, cseq_method="REGISTER", addressed_from_client=False),
                record(2, method="REGISTER"),
            ]
        )
        transaction = tx_of_type(document, "NON_INVITE")
        self.assertEqual(transaction["matching_status"], "MATCHED")
        self.assertEqual(transaction["request_frame"], 2)
        self.assertEqual(transaction["response_frame"], 1)
        self.assertEqual(transaction["first_observed_frame"], 1)
        self.assertEqual(transaction["last_observed_frame"], 2)

    def test_partial_capture_request_only(self) -> None:
        document, _, _ = self.correlate([record(1, method="INVITE")])
        transaction = tx_of_type(document, "INVITE")
        self.assertEqual(transaction["transaction_state"], "OPEN_IN_CAPTURE")
        self.assertEqual(transaction["capture_completeness"], "PARTIAL")
        self.assertIn("FINAL_RESPONSE_NOT_OBSERVED", transaction["missing_evidence"])

    def test_truncated_capture(self) -> None:
        document, _, _ = self.correlate([record(1, method="REGISTER", capture_truncated=True)])
        transaction = tx_of_type(document, "NON_INVITE")
        self.assertEqual(transaction["capture_completeness"], "TRUNCATED")

    def test_multiple_independent_transactions(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER", branch="z9hG4bK-A", call_id="A"),
                record(2, method="REGISTER", branch="z9hG4bK-B", call_id="B"),
                record(3, method="OPTIONS", branch="z9hG4bK-C", call_id="C"),
            ]
        )
        self.assertEqual(document["transaction_count"], 3)
        self.assertEqual(sum(1 for tx in document["transactions"] if tx["matching_status"] == "REQUEST_ONLY"), 3)

    def test_multiple_sip_messages_in_one_frame(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="OPTIONS", occurrence=1),
                record(1, status=200, occurrence=2, cseq_method="OPTIONS", addressed_from_client=False),
            ]
        )
        transaction = document["transactions"][0]
        self.assertEqual(transaction["request_event_references"], [event_ref(1, 1)])
        self.assertEqual(transaction["response_event_references"], [event_ref(1, 2)])
        self.assertEqual(transaction["first_observed_frame"], 1)
        self.assertEqual(transaction["last_observed_frame"], 1)

    def test_mixed_2xx_and_non_2xx_final_responses(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="INVITE"),
                record(2, status=200, cseq_method="INVITE", to_tag="A", addressed_from_client=False),
                record(3, status=486, cseq_method="INVITE", to_tag="B", addressed_from_client=False),
            ]
        )
        transaction = tx_of_type(document, "INVITE")
        self.assertIsNone(transaction["selected_final_response_reference"])
        self.assertIn("SINGLE_FINAL_RESPONSE_NOT_ESTABLISHED", transaction["missing_evidence"])


class PrivacyAndDefensiveTests(TransactionTestBase):
    def test_transaction_output_has_no_sensitive_values(self) -> None:
        document, events, completed = self.correlate(
            [
                record(1, method="INVITE"),
                record(2, status=200, cseq_method="INVITE", to_tag="PRIVATE-TO-TAG", addressed_from_client=False),
            ]
        )
        combined = json.dumps(document) + json.dumps(events) + completed.stdout + completed.stderr
        for token in PRIVATE_TOKENS:
            self.assertNotIn(token, combined)
        self.assertNotIn("<sip:", combined)
        self.assertNotIn("sip:PRIVATE", combined)

    def test_transaction_output_has_no_raw_matching_field_names(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="REGISTER"),
                record(2, status=401, cseq_method="REGISTER", addressed_from_client=False),
            ]
        )
        text = json.dumps(document)
        for raw_key in ('"call_id"', '"via_branch"', '"from_tag"', '"to_tag"', '"request_uri"', '"from_uri"', '"to_uri"', '"top_via"', '"observation_role"', '"authorization"', '"cseq_sequence"'):
            self.assertNotIn(raw_key, text)
        for transaction in document["transactions"]:
            for token in PRIVATE_TOKENS:
                self.assertNotIn(token, transaction["transaction_reference"])

    def test_every_event_has_transaction_reference(self) -> None:
        document, events, _ = self.correlate(
            [
                record(1, method="REGISTER"),
                record(2, status=200, cseq_method="REGISTER", addressed_from_client=False),
            ]
        )
        self.assertTrue(all(event.get("transaction_reference") for event in events))
        for event in events:
            self.assertTrue(tx_for_event(document, event["source_reference"]))

    def test_transaction_schema_validation(self) -> None:
        require_schema(self)
        document, _, _ = self.correlate(
            [
                record(1, method="INVITE"),
                record(2, status=200, cseq_method="INVITE", to_tag="T", addressed_from_client=False),
            ]
        )
        jsonschema.validate(document, load_json(TRANSACTION_SCHEMA))

    def test_event_schema_accepts_transaction_reference(self) -> None:
        require_schema(self)
        _, events, _ = self.correlate(
            [
                record(1, method="REGISTER"),
                record(2, status=401, cseq_method="REGISTER", addressed_from_client=False),
            ]
        )
        schema = load_json(EVENT_SCHEMA)
        for event in events:
            jsonschema.validate(event, schema)

    def test_invalid_transaction_reference_is_rejected(self) -> None:
        document, _, _ = self.correlate([record(1, method="REGISTER")])
        document["transactions"][0]["transaction_reference"] = "invalid"
        with self.assertRaises(sip_transactions.TransactionError):
            sip_transactions.validate_transaction_document(document)

    def test_duplicate_source_reference_is_rejected(self) -> None:
        document, _, _ = self.correlate([record(1, method="REGISTER")])
        document["transactions"][0]["request_event_references"].append(event_ref(1))
        with self.assertRaises(sip_transactions.TransactionError):
            sip_transactions.validate_transaction_document(document)

    def test_duplicate_input_source_reference_is_rejected(self) -> None:
        duplicate = record(1, method="REGISTER")
        source = self.base / "duplicate.jsonl"
        source.write_text(
            json.dumps(duplicate, separators=(",", ":")) + "\n" +
            json.dumps(duplicate, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        completed = run(
            [
                sys.executable,
                str(CLI),
                str(source),
                "--output",
                str(self.base / "out.jsonl"),
                "--transaction-output",
                str(self.base / "transactions.json"),
            ]
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("PRIVATE", completed.stderr)

    def test_ambiguous_matching_remains_unresolved(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="INVITE", branch="z9hG4bK-A", call_id="A"),
                record(2, method="INVITE", branch="z9hG4bK-A", call_id="B"),
                record(3, status=200, branch="z9hG4bK-A", call_id="A", cseq_method="INVITE", addressed_from_client=False),
            ]
        )
        ambiguous = tx_of_type(document, "AMBIGUOUS")
        self.assertIsNone(ambiguous["selected_final_response_reference"])
        self.assertTrue(ambiguous["missing_evidence"])
        self.assertTrue(ambiguous["candidate_transaction_references"])

    def test_deterministic_output(self) -> None:
        records = [
            record(1, method="INVITE"),
            record(2, status=180, cseq_method="INVITE", to_tag="A", addressed_from_client=False),
            record(3, status=200, cseq_method="INVITE", to_tag="A", addressed_from_client=False),
            record(4, method="ACK", branch="z9hG4bK-B", cseq=1, cseq_method="ACK", to_tag="A"),
        ]
        first_completed, first_document, first_events = run_transactions(self.base, records)
        second_completed, second_document, second_events = run_transactions(self.base, records)
        self.assertEqual(first_completed.returncode, 0)
        self.assertEqual(second_completed.returncode, 0)
        self.assertEqual(first_document, second_document)
        self.assertEqual(first_events, second_events)

    def test_no_ims_semantics_in_transaction_output(self) -> None:
        document, _, _ = self.correlate([record(1, method="REGISTER")])
        text = json.dumps(document)
        for token in ("registration_success", "registration_failure", "call_success", "call_failure", "ims_registered", "root_cause"):
            self.assertNotIn(token, text)

    def test_200_ok_to_cancel_does_not_claim_invite_cancelled(self) -> None:
        document, _, _ = self.correlate(
            [
                record(1, method="INVITE", branch="z9hG4bK-A", cseq=1),
                record(2, method="CANCEL", branch="z9hG4bK-A", cseq=1, cseq_method="CANCEL"),
                record(3, status=200, branch="z9hG4bK-A", cseq=1, cseq_method="CANCEL", addressed_from_client=False),
            ]
        )
        invite = tx_of_type(document, "INVITE")
        self.assertNotEqual(invite["transaction_state"], "TERMINATED")
        self.assertIn("FINAL_RESPONSE_NOT_OBSERVED", invite["missing_evidence"])
        self.assertTrue(any("200 OK to CANCEL" in item for item in tx_of_type(document, "CANCEL")["limitations"]))

    def test_malformed_input_error_does_not_echo_secret(self) -> None:
        source = self.base / "bad.jsonl"
        source.write_text('{"frame_number": 1, "headers": {"call_id": "PRIVATE-CALL-ID"', encoding="utf-8")
        completed = run(
            [
                sys.executable,
                str(CLI),
                str(source),
                "--output",
                str(self.base / "out.jsonl"),
                "--transaction-output",
                str(self.base / "transactions.json"),
            ]
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("PRIVATE-CALL-ID", completed.stderr + completed.stdout)


def hexdump(data: bytes) -> str:
    return "\n".join(
        f"{index:06x} " + " ".join(f"{byte:02x}" for byte in data[index:index + 16])
        for index in range(0, len(data), 16)
    )


def build_capture(directory: Path, packets: list[bytes], *, mode: str = "udp", ports: tuple[int, int] = (5060, 5060)) -> Path:
    source = directory / "packets.txt"
    destination = directory / "synthetic.pcapng"
    source.write_text("\n\n".join(hexdump(packet) for packet in packets) + "\n", encoding="utf-8")
    completed = run([TEXT2PCAP, "-q", "-u" if mode == "udp" else "-T", f"{ports[0]},{ports[1]}", str(source), str(destination)])
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr)
    return destination


def sip_invite() -> bytes:
    return (
        "INVITE sip:PRIVATE-USER@ims.example SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-PRIVATE-BRANCH\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:PRIVATE-USER@ims.example>;tag=PRIVATE-FROM-TAG\r\n"
        "To: <sip:PRIVATE-USER@ims.example>\r\n"
        "Call-ID: PRIVATE-CALL-ID\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:PRIVATE-USER@192.0.2.10:5060>\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode()


@unittest.skipUnless(TSHARK and TEXT2PCAP, "TShark and text2pcap are required for live decoder tests")
class LiveSipTransactionTests(TransactionTestBase):
    def test_tcp_segmented_invite_creates_one_transaction(self) -> None:
        payload = sip_invite()
        cut = len(payload) // 2
        capture = build_capture(self.base, [payload[:cut], payload[cut:]], mode="tcp")
        events_path = self.base / "events.jsonl"
        transactions_path = self.base / "transactions.json"
        completed = run([sys.executable, str(CLI), str(capture), "--output", str(events_path), "--transaction-output", str(transactions_path)])
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document = load_json(transactions_path)
        events = load_jsonl(events_path)
        self.assertEqual(len(events), 1)
        self.assertEqual(document["transaction_count"], 1)
        transaction = document["transactions"][0]
        self.assertEqual(transaction["request_event_references"], [events[0]["source_reference"]])
        self.assertEqual(events[0]["transport"]["reassembly"], "REASSEMBLED")
        self.assertEqual(events[0]["transaction_reference"], transaction["transaction_reference"])

    def test_udp_retransmitted_invite_is_classified(self) -> None:
        payload = sip_invite()
        capture = build_capture(self.base, [payload, payload], mode="udp")
        transactions_path = self.base / "transactions.json"
        completed = run(
            [
                sys.executable,
                str(CLI),
                str(capture),
                "--output",
                str(self.base / "events.jsonl"),
                "--transaction-output",
                str(transactions_path),
            ]
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document = load_json(transactions_path)
        transaction = tx_of_type(document, "INVITE")
        self.assertEqual(transaction["retransmission_count"], 1)


if __name__ == "__main__":
    unittest.main()