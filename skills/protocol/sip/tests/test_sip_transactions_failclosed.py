#!/usr/bin/env python3
"""Fail-closed association and RFC transaction-state regression tests."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

REASONS = {100: "Trying", 180: "Ringing", 200: "OK", 486: "Busy Here", 487: "Request Terminated"}


def rec(
    frame: int,
    *,
    method: str | None = None,
    status: int | None = None,
    branch: str = "z9hG4bK-A",
    sent_by: str = "192.0.2.10:5060",
    cseq: int = 1,
    cseq_method: str | None = None,
    call_id: str = "CALL-ID",
    from_uri: str | None = "sip:alice@example.com",
    from_tag: str | None = "FTAG",
    to_uri: str | None = "sip:bob@example.com",
    to_tag: str | None = None,
    request_uri: str | None = "sip:bob@example.com",
    protocol: str = "UDP",
    role: str = "UNKNOWN",
    include_via: bool = True,
) -> dict:
    from_client = method is not None
    source, destination = (
        ("192.0.2.10", "192.0.2.20") if from_client else ("192.0.2.20", "192.0.2.10")
    )
    headers = {
        "call_id": call_id,
        "cseq_sequence": cseq,
        "cseq_method": cseq_method or method or "REGISTER",
        "request_uri": request_uri,
        "via": (
            [{"branch": branch, "sent_by": sent_by, "transport": protocol}]
            if include_via
            else []
        ),
        "from": {"count": 1, "tag": from_tag, "uri": from_uri},
        "to": {"count": 1, "tag": to_tag, "uri": to_uri},
        "content_length": 0,
    }
    if method is not None:
        headers["method"] = method
        headers["max_forwards"] = 70
    if status is not None:
        headers["status_code"] = status
        headers["reason_phrase"] = REASONS.get(status, "Unknown")
    return {
        "capture_file": "sip-failclosed.pcapng",
        "frame_number": frame,
        "message_occurrence": 1,
        "transport": {
            "protocol": protocol,
            "source_address": source,
            "source_port": 5060,
            "destination_address": destination,
            "destination_port": 5060,
            "reassembly": "NOT_APPLICABLE" if protocol == "UDP" else "SINGLE_SEGMENT",
        },
        "headers": headers,
        "observation_role": role,
    }


def run(records: list[dict]) -> dict:
    directory = Path(tempfile.mkdtemp())
    source = directory / "input.jsonl"
    source.write_text(
        "\n".join(json.dumps(item, separators=(",", ":")) for item in records) + "\n",
        encoding="utf-8",
    )
    destination = directory / "transactions.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "extract-sip.py"),
            str(source),
            "--transaction-output",
            str(destination),
            "--force",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return json.loads(destination.read_text(encoding="utf-8"))


def tx(document: dict, transaction_type: str) -> dict:
    for item in document["transactions"]:
        if item["transaction_type"] == transaction_type:
            return item
    raise AssertionError(
        f"no transaction of type {transaction_type}: "
        f"{[item['transaction_type'] for item in document['transactions']]}"
    )


class InviteStateTests(unittest.TestCase):
    def client(self, status: int, *, ack: bool = True) -> dict:
        records = [
            rec(1, method="INVITE", role="CLIENT"),
            rec(2, status=status, cseq_method="INVITE", to_tag="T", role="CLIENT"),
        ]
        if ack:
            records.append(rec(3, method="ACK", cseq_method="ACK", to_tag="T", role="CLIENT"))
        return tx(run(records), "INVITE")

    def server(self, status: int, *, ack: bool = True) -> dict:
        records = [
            rec(1, method="INVITE", role="SERVER"),
            rec(2, status=status, cseq_method="INVITE", to_tag="T", role="SERVER"),
        ]
        if ack:
            records.append(rec(3, method="ACK", cseq_method="ACK", to_tag="T", role="SERVER"))
        return tx(run(records), "INVITE")

    def test_client_486_with_ack_is_completed_not_terminated(self) -> None:
        invite = self.client(486)
        self.assertEqual(invite["rfc_transaction_state"], "COMPLETED")
        self.assertNotEqual(invite["rfc_transaction_state"], "TERMINATED")
        self.assertEqual(invite["observed_evidence_status"], "NON_2XX_ACK_OBSERVED")

    def test_client_487_with_ack_is_completed_not_terminated(self) -> None:
        invite = self.client(487)
        self.assertEqual(invite["rfc_transaction_state"], "COMPLETED")
        self.assertNotEqual(invite["rfc_transaction_state"], "TERMINATED")

    def test_client_non_2xx_without_ack_is_completed(self) -> None:
        self.assertEqual(self.client(486, ack=False)["rfc_transaction_state"], "COMPLETED")

    def test_server_non_2xx_with_ack_is_confirmed(self) -> None:
        invite = self.server(486)
        self.assertEqual(invite["rfc_transaction_state"], "CONFIRMED")

    def test_server_non_2xx_without_ack_is_completed(self) -> None:
        self.assertEqual(self.server(486, ack=False)["rfc_transaction_state"], "COMPLETED")

    def test_client_and_server_2xx_are_accepted(self) -> None:
        for role in ("CLIENT", "SERVER"):
            with self.subTest(role=role):
                document = run(
                    [
                        rec(1, method="INVITE", role=role),
                        rec(2, status=200, cseq_method="INVITE", to_tag="T", role=role),
                    ]
                )
                self.assertEqual(tx(document, "INVITE")["rfc_transaction_state"], "ACCEPTED")

    def test_multiple_2xx_remain_independent(self) -> None:
        document = run(
            [
                rec(1, method="INVITE", role="CLIENT"),
                rec(2, status=200, cseq_method="INVITE", to_tag="T1", role="CLIENT"),
                rec(3, status=200, cseq_method="INVITE", to_tag="T2", role="CLIENT"),
            ]
        )
        invite = tx(document, "INVITE")
        self.assertEqual(invite["rfc_transaction_state"], "ACCEPTED")
        self.assertEqual(len(invite["final_response_event_references"]), 2)
        self.assertEqual(invite["distinct_final_response_count"], 2)

    def test_unknown_role_remains_evidence_only(self) -> None:
        invite = tx(
            run(
                [
                    rec(1, method="INVITE"),
                    rec(2, status=486, cseq_method="INVITE", to_tag="T"),
                    rec(3, method="ACK", cseq_method="ACK", to_tag="T"),
                ]
            ),
            "INVITE",
        )
        self.assertEqual(invite["transaction_role"], "UNKNOWN")
        self.assertEqual(invite["state_semantics"], "EVIDENCE_ONLY")
        self.assertIsNone(invite["rfc_transaction_state"])

    def test_cancel_sequence_does_not_establish_termination(self) -> None:
        invite = tx(
            run(
                [
                    rec(1, method="INVITE", role="CLIENT"),
                    rec(2, method="CANCEL", cseq_method="CANCEL", role="CLIENT"),
                    rec(3, status=200, cseq_method="CANCEL", to_tag="CT", role="CLIENT"),
                    rec(4, status=487, cseq_method="INVITE", to_tag="IT", role="CLIENT"),
                ]
            ),
            "INVITE",
        )
        self.assertEqual(invite["observed_evidence_status"], "CANCEL_RESPONSE_SEQUENCE_OBSERVED")
        self.assertFalse(invite["invite_transaction_termination_established"])
        self.assertNotEqual(invite["rfc_transaction_state"], "TERMINATED")

    def test_capture_silence_is_not_timer_expiry(self) -> None:
        invite = self.client(486, ack=False)
        self.assertEqual(invite["rfc_transaction_state"], "COMPLETED")
        self.assertNotEqual(invite["rfc_transaction_state"], "TERMINATED")

    def test_invalid_ack_does_not_change_rfc_state(self) -> None:
        document = run(
            [
                rec(1, method="INVITE", role="SERVER"),
                rec(2, status=486, cseq_method="INVITE", to_tag="T", role="SERVER"),
                rec(3, method="ACK", cseq_method="ACK", to_tag="OTHER", role="SERVER"),
            ]
        )
        invite = tx(document, "INVITE")
        self.assertEqual(invite["associated_control_event_references"], [])
        self.assertEqual(invite["rfc_transaction_state"], "COMPLETED")


class CancelFailClosedTests(unittest.TestCase):
    def build(self, **overrides: object) -> dict:
        records = [
            rec(1, method="INVITE"),
            rec(2, method="CANCEL", cseq_method="CANCEL", **overrides),
            rec(3, status=200, cseq_method="CANCEL", to_tag="CT"),
            rec(4, status=487, cseq_method="INVITE", to_tag="IT"),
        ]
        return run(records)

    def test_valid_association_remains_accepted(self) -> None:
        cancel = tx(self.build(), "CANCEL")
        self.assertEqual(cancel["cancel_invite_association_status"], "ASSOCIATED")
        self.assertIsNotNone(cancel["associated_transaction_reference"])

    def test_missing_required_identity_values_block_association(self) -> None:
        for field, value, label in (
            ("request_uri", None, "REQUEST_URI_NOT_OBSERVED"),
            ("from_uri", None, "FROM_VALUE_NOT_OBSERVED"),
            ("to_uri", None, "TO_VALUE_NOT_OBSERVED"),
            ("call_id", None, "CALL_ID_NOT_OBSERVED"),
            ("cseq", None, "CSEQ_NOT_OBSERVED"),
        ):
            with self.subTest(field=field):
                cancel = tx(self.build(**{field: value}), "CANCEL")
                self.assertIsNone(cancel["associated_transaction_reference"])
                self.assertEqual(cancel["cancel_invite_association_status"], "NOT_ESTABLISHED")
                self.assertIn(label, cancel["missing_evidence"])
                self.assertEqual(cancel["conflict_findings"], [])

    def test_missing_via_identity_blocks_association(self) -> None:
        cancel = tx(self.build(include_via=False), "CANCEL")
        self.assertIsNone(cancel["associated_transaction_reference"])
        self.assertIn("VIA_BRANCH_NOT_OBSERVED", cancel["missing_evidence"])

    def test_absent_initial_to_tags_are_consistent(self) -> None:
        cancel = tx(self.build(), "CANCEL")
        self.assertEqual(cancel["cancel_invite_association_status"], "ASSOCIATED")

    def test_to_tag_present_only_on_cancel_is_a_conflict(self) -> None:
        cancel = tx(self.build(to_tag="CANCEL-TAG"), "CANCEL")
        self.assertIsNone(cancel["associated_transaction_reference"])
        self.assertIn("TO_TAG_MISMATCH", cancel["conflict_findings"])
        self.assertNotIn("TO_VALUE_NOT_OBSERVED", cancel["missing_evidence"])

    def test_observed_contradictions_are_conflicts_not_missing(self) -> None:
        for field, value, label in (
            ("to_uri", "sip:other@example.com", "TO_VALUE_MISMATCH"),
            ("request_uri", "sip:other@example.com", "REQUEST_URI_MISMATCH"),
            ("call_id", "OTHER", "CALL_ID_MISMATCH"),
            ("from_uri", "sip:other@example.com", "FROM_VALUE_MISMATCH"),
        ):
            with self.subTest(field=field):
                cancel = tx(self.build(**{field: value}), "CANCEL")
                self.assertIsNone(cancel["associated_transaction_reference"])
                self.assertIn(label, cancel["conflict_findings"])
                self.assertNotIn("REQUEST_URI_NOT_OBSERVED", cancel["missing_evidence"])

    def test_incomplete_cancel_does_not_change_invite_outcome(self) -> None:
        document = run(
            [
                rec(1, method="INVITE"),
                rec(2, status=486, cseq_method="INVITE", to_tag="T"),
                rec(3, method="CANCEL", cseq_method="CANCEL", call_id=None),
            ]
        )
        invite = tx(document, "INVITE")
        cancel = tx(document, "CANCEL")
        self.assertIsNone(cancel["associated_transaction_reference"])
        self.assertEqual(invite["observed_evidence_status"], "FINAL_RESPONSE_OBSERVED")
        self.assertEqual(invite["cancel_invite_association_status"], None)

    def test_legacy_cancel_fail_closed(self) -> None:
        document = run(
            [
                rec(1, method="INVITE", branch="legacy"),
                rec(2, method="CANCEL", branch="legacy", cseq_method="CANCEL", from_uri=None),
                rec(3, status=200, branch="legacy", cseq_method="CANCEL", to_tag="CT"),
            ]
        )
        cancel = tx(document, "CANCEL")
        self.assertEqual(cancel["matching_mode"], "LEGACY")
        self.assertIsNone(cancel["associated_transaction_reference"])
        self.assertIn("FROM_VALUE_NOT_OBSERVED", cancel["missing_evidence"])
        self.assertEqual(cancel["conflict_findings"], [])


class AckFailClosedTests(unittest.TestCase):
    def build(self, ack_overrides: dict | None = None, *, role: str = "CLIENT") -> dict:
        headers = {"cseq_method": "ACK", "to_tag": "T", **(ack_overrides or {})}
        return run(
            [
                rec(1, method="INVITE", role=role),
                rec(2, status=486, cseq_method="INVITE", to_tag="T", role=role),
                rec(3, method="ACK", role=role, **headers),
            ]
        )

    def test_valid_association_remains_accepted(self) -> None:
        invite = tx(self.build(), "INVITE")
        self.assertEqual(invite["associated_control_event_references"], ["sip-event:sip-failclosed.pcapng:3.1"])

    def test_missing_required_values_block_association(self) -> None:
        for field, value, label in (
            ("request_uri", None, "REQUEST_URI_NOT_OBSERVED"),
            ("from_uri", None, "FROM_VALUE_NOT_OBSERVED"),
            ("to_uri", None, "TO_VALUE_NOT_OBSERVED"),
            ("call_id", None, "CALL_ID_NOT_OBSERVED"),
            ("cseq", None, "CSEQ_NOT_OBSERVED"),
            ("to_tag", None, "TO_TAG_NOT_OBSERVED"),
            ("include_via", False, "VIA_BRANCH_NOT_OBSERVED"),
        ):
            with self.subTest(field=field):
                document = self.build({field: value})
                invite = tx(document, "INVITE")
                self.assertEqual(invite["associated_control_event_references"], [])
                orphan = tx(document, "ACK_ORPHAN")
                self.assertIsNone(orphan["associated_transaction_reference"])
                self.assertIn(label, orphan["missing_evidence"])
                self.assertEqual(invite["rfc_transaction_state"], "COMPLETED")

    def test_contradictions_block_association(self) -> None:
        for field, value, label in (
            ("request_uri", "sip:other@example.com", "REQUEST_URI_MISMATCH"),
            ("to_uri", "sip:other@example.com", "TO_VALUE_MISMATCH"),
            ("to_tag", "OTHER", "TO_TAG_MISMATCH"),
            ("from_uri", "sip:other@example.com", "FROM_VALUE_MISMATCH"),
            ("from_tag", "OTHER", "FROM_TAG_MISMATCH"),
            ("call_id", "OTHER", "CALL_ID_MISMATCH"),
            ("cseq", 9, "CSEQ_MISMATCH"),
        ):
            with self.subTest(field=field):
                document = self.build({field: value})
                invite = tx(document, "INVITE")
                self.assertEqual(invite["associated_control_event_references"], [])
                orphan = tx(document, "ACK_ORPHAN")
                self.assertIn(label, orphan["conflict_findings"])
                self.assertEqual(invite["rfc_transaction_state"], "COMPLETED")

    def test_wrong_cseq_method_blocks_association(self) -> None:
        document = self.build({"cseq_method": "INVITE"})
        invite = tx(document, "INVITE")
        self.assertEqual(invite["associated_control_event_references"], [])
        orphan = tx(document, "ACK_ORPHAN")
        self.assertIn("CSEQ_METHOD_MISMATCH", orphan["conflict_findings"])

    def test_missing_evidence_cannot_produce_server_confirmed(self) -> None:
        document = self.build({"call_id": None}, role="SERVER")
        invite = tx(document, "INVITE")
        self.assertNotEqual(invite["rfc_transaction_state"], "CONFIRMED")
        self.assertEqual(invite["rfc_transaction_state"], "COMPLETED")

    def test_missing_evidence_cannot_produce_client_terminated(self) -> None:
        document = self.build({"to_tag": None}, role="CLIENT")
        invite = tx(document, "INVITE")
        self.assertEqual(invite["rfc_transaction_state"], "COMPLETED")
        self.assertNotEqual(invite["rfc_transaction_state"], "TERMINATED")

    def test_multiple_candidates_remain_ambiguous(self) -> None:
        document = run(
            [
                rec(1, method="INVITE", branch="z9hG4bK-A", call_id="C"),
                rec(2, status=486, cseq_method="INVITE", to_tag="T", branch="z9hG4bK-A", call_id="C"),
                rec(3, method="INVITE", branch="z9hG4bK-B", call_id="C"),
                rec(4, status=486, cseq_method="INVITE", to_tag="T", branch="z9hG4bK-B", call_id="C"),
                rec(5, method="ACK", cseq_method="ACK", to_tag="T", branch="z9hG4bK-C", call_id="C"),
            ]
        )
        ack = tx(document, "ACK_AMBIGUOUS")
        self.assertIsNone(ack["associated_transaction_reference"])
        self.assertEqual(len(ack["candidate_transaction_references"]), 2)
        for item in document["transactions"]:
            if item["transaction_type"] == "INVITE":
                self.assertEqual(item["associated_control_event_references"], [])

    def test_ack_for_2xx_remains_independent(self) -> None:
        document = run(
            [
                rec(1, method="INVITE"),
                rec(2, status=200, cseq_method="INVITE", to_tag="T"),
                rec(3, method="ACK", cseq_method="ACK", to_tag="T"),
            ]
        )
        self.assertEqual(tx(document, "ACK_2XX")["associated_transaction_reference"], None)
        self.assertIn("DIALOG_ASSOCIATION_UNAVAILABLE", tx(document, "ACK_2XX")["missing_evidence"])


class SchemaSemanticValidationTests(unittest.TestCase):
    def test_produced_document_passes_strict_schema(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(
            (PACKAGE / "schemas" / "sip-transactions.schema.json").read_text(encoding="utf-8")
        )
        document = run(
            [
                rec(1, method="INVITE", role="CLIENT"),
                rec(2, status=486, cseq_method="INVITE", to_tag="T", role="CLIENT"),
                rec(3, method="ACK", cseq_method="ACK", to_tag="T", role="CLIENT"),
                rec(4, method="REGISTER"),
                rec(5, status=401, cseq_method="REGISTER", to_tag="T2"),
            ]
        )
        jsonschema.validate(document, schema)

    def test_producer_rejects_unsupported_client_terminated(self) -> None:
        import sip_transactions

        document = run([rec(1, method="INVITE", role="CLIENT")])
        document["transactions"][0]["rfc_transaction_state"] = "TERMINATED"
        document["transactions"][0]["state_semantics"] = "RFC_STATE"
        document["transactions"][0]["transaction_state"] = "TERMINATED"
        with self.assertRaises(sip_transactions.TransactionError):
            sip_transactions.validate_transaction_document(document)

    def test_producer_rejects_associated_cancel_without_reference(self) -> None:
        import sip_transactions

        document = run(
            [
                rec(1, method="INVITE"),
                rec(2, method="CANCEL", cseq_method="CANCEL"),
                rec(3, status=200, cseq_method="CANCEL", to_tag="CT"),
            ]
        )
        cancel = tx(document, "CANCEL")
        cancel["associated_transaction_reference"] = None
        with self.assertRaises(sip_transactions.TransactionError):
            sip_transactions.validate_transaction_document(document)

    def test_producer_rejects_confirmed_without_ack(self) -> None:
        import sip_transactions

        document = run(
            [
                rec(1, method="INVITE", role="SERVER"),
                rec(2, status=486, cseq_method="INVITE", to_tag="T", role="SERVER"),
            ]
        )
        invite = tx(document, "INVITE")
        invite["rfc_transaction_state"] = "CONFIRMED"
        invite["state_semantics"] = "RFC_STATE"
        invite["transaction_state"] = "CONFIRMED"
        with self.assertRaises(sip_transactions.TransactionError):
            sip_transactions.validate_transaction_document(document)


if __name__ == "__main__":
    unittest.main()