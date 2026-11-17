#!/usr/bin/env python3
"""RFC 3261 and RFC 6026 conformance tests for SIP transaction correlation."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
sys.path.insert(0, str(SCRIPTS))
import sip_model  # noqa: E402
import sip_transactions  # noqa: E402

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
    from_tag: str = "FTAG",
    to_uri: str | None = "sip:bob@example.com",
    to_tag: str | None = None,
    request_uri: str | None = "sip:bob@example.com",
    protocol: str = "UDP",
    role: str = "UNKNOWN",
    from_client: bool | None = None,
    content_length: int = 0,
) -> dict:
    if from_client is None:
        from_client = method is not None
    source, destination = (
        ("192.0.2.10", "192.0.2.20") if from_client else ("192.0.2.20", "192.0.2.10")
    )
    headers = {
        "call_id": call_id,
        "cseq_sequence": cseq,
        "cseq_method": cseq_method or method or "REGISTER",
        "request_uri": request_uri,
        "via": [{"branch": branch, "sent_by": sent_by, "transport": protocol}],
        "from": {"count": 1, "tag": from_tag, "uri": from_uri},
        "to": {"count": 1, "tag": to_tag, "uri": to_uri},
        "content_length": content_length,
    }
    if method is not None:
        headers["method"] = method
        headers["max_forwards"] = 70
    if status is not None:
        headers["status_code"] = status
        headers["reason_phrase"] = REASONS.get(status, "Unknown")
    transport = {
        "protocol": protocol,
        "source_address": source,
        "source_port": 5060,
        "destination_address": destination,
        "destination_port": 5060,
        "reassembly": "NOT_APPLICABLE" if protocol == "UDP" else "SINGLE_SEGMENT",
    }
    return {
        "capture_file": "sip-rfc.pcapng",
        "frame_number": frame,
        "message_occurrence": 1,
        "transport": transport,
        "headers": headers,
        "observation_role": role,
    }


def correlate(records: list[dict]) -> dict:
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
    matches = [item for item in document["transactions"] if item["transaction_type"] == transaction_type]
    if not matches:
        raise AssertionError(f"no transaction of type {transaction_type}")
    return matches[0]


def tx_with_method(document: dict, method: str) -> dict:
    for item in document["transactions"]:
        if item["transaction_method"] == method:
            return item
    raise AssertionError(f"no transaction for method {method}")


class MagicCookieTests(unittest.TestCase):
    def test_modern_magic_cookie_matching(self) -> None:
        document = correlate([rec(1, method="INVITE"), rec(2, status=180, cseq_method="INVITE", to_tag="T")])
        transaction = tx(document, "INVITE")
        self.assertEqual(transaction["matching_mode"], "MODERN")
        self.assertEqual(transaction["matching_status"], "PARTIALLY_MATCHED")
        self.assertEqual(transaction["response_event_references"], ["sip-event:sip-rfc.pcapng:2.1"])

    def test_legacy_branch_never_uses_modern_key(self) -> None:
        document = correlate(
            [
                rec(1, method="INVITE", branch="legacybranch", call_id="C"),
                rec(2, method="INVITE", branch="legacybranch", call_id="C", to_uri="sip:carol@example.com"),
            ]
        )
        self.assertEqual(len(document["transactions"]), 2)
        for transaction in document["transactions"]:
            self.assertEqual(transaction["matching_mode"], "LEGACY")

    def test_missing_branch_is_not_established(self) -> None:
        records = [rec(1, method="REGISTER")]
        records[0]["headers"]["via"] = []
        document = correlate(records)
        transaction = tx(document, "NON_INVITE")
        self.assertEqual(transaction["matching_mode"], "UNAVAILABLE")
        self.assertEqual(transaction["matching_status"], "NOT_ESTABLISHED")
        self.assertIn("VIA_BRANCH_NOT_OBSERVED", transaction["missing_evidence"])

    def test_legacy_invite_retransmission_candidate(self) -> None:
        document = correlate(
            [rec(1, method="INVITE", branch="legacy"), rec(2, method="INVITE", branch="legacy")]
        )
        transaction = tx(document, "INVITE")
        self.assertEqual(transaction["matching_mode"], "LEGACY")
        self.assertEqual(transaction["retransmission_candidate_count"], 1)
        self.assertEqual(transaction["retransmission_count"], 0)
        self.assertIn("RETRANSMISSION_FINGERPRINT_INCOMPLETE", transaction["missing_evidence"])

    def test_legacy_non_invite_and_cancel_matching(self) -> None:
        document = correlate(
            [
                rec(1, method="REGISTER", branch="legacy"),
                rec(2, status=200, branch="legacy", cseq_method="REGISTER", to_tag="T"),
                rec(3, method="INVITE", branch="legacy-invite"),
                rec(4, method="CANCEL", branch="legacy-invite", cseq_method="CANCEL"),
                rec(5, status=200, branch="legacy-invite", cseq_method="CANCEL", to_tag="T2"),
            ]
        )
        register = tx_with_method(document, "REGISTER")
        self.assertEqual(register["matching_status"], "MATCHED")
        cancel = tx(document, "CANCEL")
        self.assertEqual(cancel["cancel_invite_association_status"], "ASSOCIATED")

    def test_legacy_ack_matching(self) -> None:
        document = correlate(
            [
                rec(1, method="INVITE", branch="legacy"),
                rec(2, status=486, branch="legacy", cseq_method="INVITE", to_tag="T"),
                rec(3, method="ACK", branch="legacy", cseq_method="ACK", to_tag="T"),
            ]
        )
        invite = tx(document, "INVITE")
        self.assertEqual(invite["associated_control_event_references"], ["sip-event:sip-rfc.pcapng:3.1"])
        self.assertEqual(invite["observed_evidence_status"], "NON_2XX_ACK_OBSERVED")

    def test_legacy_missing_request_uri_is_not_established(self) -> None:
        document = correlate(
            [rec(1, method="REGISTER", branch="legacy", request_uri=None)]
        )
        transaction = tx(document, "NON_INVITE")
        self.assertEqual(transaction["matching_status"], "NOT_ESTABLISHED")
        self.assertIn("REQUEST_URI_NOT_OBSERVED", transaction["missing_evidence"])

    def test_legacy_conflicting_to_from_call_id_cseq(self) -> None:
        for field, value, finding in (
            ("to_uri", "sip:other@example.com", "TO_VALUE_MISMATCH"),
            ("from_uri", "sip:other@example.com", "FROM_VALUE_MISMATCH"),
            ("call_id", "OTHER", "CALL_ID_MISMATCH"),
            ("cseq", 9, "CSEQ_MISMATCH"),
        ):
            with self.subTest(field=field):
                document = correlate(
                    [
                        rec(1, method="INVITE", branch="legacy"),
                        rec(2, status=200, branch="legacy", cseq_method="INVITE", to_tag="T", **{field: value}),
                    ]
                )
                invite = tx(document, "INVITE")
                self.assertNotEqual(invite["matching_status"], "MATCHED")
                self.assertEqual(invite["response_event_references"], [])

    def test_legacy_missing_evidence_never_matches_by_call_id(self) -> None:
        document = correlate(
            [
                rec(1, method="INVITE", branch="legacy", from_uri=None),
                rec(2, status=200, branch="legacy", cseq_method="INVITE", from_uri=None, to_tag="T"),
            ]
        )
        self.assertEqual(len(document["transactions"]), 2)
        for transaction in document["transactions"]:
            self.assertEqual(transaction["matching_status"], "NOT_ESTABLISHED")


class CancelConsistencyTests(unittest.TestCase):
    def build(self, **overrides: object) -> dict:
        cancel_headers = {"cseq_method": "CANCEL", **overrides}
        response_headers = {"cseq_method": "CANCEL", "to_tag": "CT", **overrides}
        records = [
            rec(1, method="INVITE"),
            rec(2, method="CANCEL", **cancel_headers),
            rec(3, status=200, **response_headers),
            rec(4, status=487, cseq_method="INVITE", to_tag="IT"),
        ]
        return correlate(records)

    def test_matching_cancel_is_associated_without_termination(self) -> None:
        document = self.build()
        invite = tx(document, "INVITE")
        cancel = tx(document, "CANCEL")
        self.assertEqual(cancel["cancel_invite_association_status"], "ASSOCIATED")
        self.assertEqual(invite["transaction_state"], "CANCEL_RESPONSE_SEQUENCE_OBSERVED")
        self.assertIsNone(invite["termination_basis"])
        self.assertFalse(invite["invite_transaction_termination_established"])
        self.assertIn("TRANSACTION_TERMINATION_NOT_ESTABLISHED", invite["missing_evidence"])

    def test_inconsistent_cancel_headers(self) -> None:
        for field, value in (
            ("request_uri", "sip:other@example.com"),
            ("to_uri", "sip:other@example.com"),
            ("to_tag", "OTHER-TAG"),
            ("from_tag", "OTHER-FROM"),
            ("call_id", "OTHER"),
            ("cseq", 7),
            ("sent_by", "192.0.2.99:5060"),
            ("branch", "z9hG4bK-OTHER"),
        ):
            with self.subTest(field=field):
                document = self.build(**{field: value})
                cancel = tx(document, "CANCEL")
                self.assertIsNone(cancel["associated_transaction_reference"])
                self.assertEqual(cancel["cancel_invite_association_status"], "NOT_ESTABLISHED")
                self.assertNotEqual(tx(document, "INVITE")["transaction_state"], "CANCEL_RESPONSE_SEQUENCE_OBSERVED")

    def test_cancel_wrong_cseq_method(self) -> None:
        document = correlate(
            [
                rec(1, method="INVITE"),
                rec(2, method="CANCEL", cseq_method="INVITE"),
                rec(3, status=200, cseq_method="CANCEL", to_tag="CT"),
            ]
        )
        cancel = tx(document, "CANCEL")
        self.assertIn("METHOD_MISMATCH", cancel["conflict_findings"])
        self.assertIsNone(cancel["associated_transaction_reference"])

    def test_200_cancel_without_487_and_487_without_200(self) -> None:
        without_487 = correlate(
            [
                rec(1, method="INVITE"),
                rec(2, method="CANCEL", cseq_method="CANCEL"),
                rec(3, status=200, cseq_method="CANCEL", to_tag="CT"),
            ]
        )
        self.assertFalse(tx(without_487, "INVITE")["cancel_response_sequence_observed"])
        without_200 = correlate(
            [rec(1, method="INVITE"), rec(2, method="CANCEL", cseq_method="CANCEL"), rec(3, status=487, cseq_method="INVITE", to_tag="IT")]
        )
        self.assertFalse(tx(without_200, "INVITE")["cancel_response_sequence_observed"])


class AckConsistencyTests(unittest.TestCase):
    def build(self, ack_overrides: dict | None = None, *, status: int = 486, ack_to_tag: str | None = "T") -> dict:
        ack_headers = {"cseq_method": "ACK", "cseq": 1, "to_tag": ack_to_tag, **(ack_overrides or {})}
        return correlate(
            [
                rec(1, method="INVITE", cseq=1),
                rec(2, status=status, cseq_method="INVITE", cseq=1, to_tag="T"),
                rec(3, method="ACK", **ack_headers),
            ]
        )

    def test_valid_non_2xx_ack(self) -> None:
        invite = tx(self.build(), "INVITE")
        self.assertEqual(invite["associated_control_event_references"], ["sip-event:sip-rfc.pcapng:3.1"])
        self.assertEqual(invite["observed_evidence_status"], "NON_2XX_ACK_OBSERVED")
        self.assertIsNone(invite["rfc_transaction_state"])

    def test_inconsistent_non_2xx_ack(self) -> None:
        for overrides in (
            {"request_uri": "sip:other@example.com"},
            {"to_uri": "sip:other@example.com"},
            {"to_tag": "OTHER"},
            {"from_tag": "OTHER"},
            {"call_id": "OTHER"},
            {"cseq": 9},
            {"cseq_method": "INVITE"},
            {"branch": "z9hG4bK-OTHER"},
            {"sent_by": "192.0.2.99:5060"},
        ):
            with self.subTest(overrides=overrides):
                document = self.build(overrides)
                invite = tx(document, "INVITE")
                self.assertEqual(invite["associated_control_event_references"], [])
                self.assertEqual(invite["observed_evidence_status"], "FINAL_RESPONSE_OBSERVED")
                orphan = tx(document, "ACK_ORPHAN")
                self.assertTrue(orphan["conflict_findings"] or orphan["matching_status"] == "NOT_ESTABLISHED")

    def test_ack_for_2xx_stays_independent(self) -> None:
        document = self.build(status=200)
        invite = tx(document, "INVITE")
        self.assertEqual(invite["associated_control_event_references"], [])
        ack = tx(document, "ACK_2XX")
        self.assertIn("DIALOG_ASSOCIATION_UNAVAILABLE", ack["missing_evidence"])

    def test_ambiguous_ack_and_invalid_ack_do_not_change_state(self) -> None:
        document = correlate(
            [
                rec(1, method="INVITE", call_id="C", branch="z9hG4bK-A"),
                rec(2, status=486, cseq_method="INVITE", to_tag="T", branch="z9hG4bK-A", call_id="C"),
                rec(3, method="INVITE", call_id="C", branch="z9hG4bK-B"),
                rec(4, status=486, cseq_method="INVITE", to_tag="T", branch="z9hG4bK-B", call_id="C"),
                rec(5, method="ACK", cseq_method="ACK", to_tag="T", branch="z9hG4bK-C", call_id="C"),
            ]
        )
        ack = tx(document, "ACK_AMBIGUOUS")
        self.assertEqual(ack["matching_status"], "AMBIGUOUS")
        self.assertEqual(len(ack["candidate_transaction_references"]), 2)
        for invite in [item for item in document["transactions"] if item["transaction_type"] == "INVITE"]:
            self.assertEqual(invite["associated_control_event_references"], [])
            self.assertNotEqual(invite["transaction_state"], "NON_2XX_ACK_OBSERVED")


class CSeqMethodTests(unittest.TestCase):
    def test_method_cseq_contradictions_cannot_form_transactions(self) -> None:
        for method, cseq_method in (
            ("INVITE", "REGISTER"),
            ("REGISTER", "INVITE"),
            ("CANCEL", "INVITE"),
            ("ACK", "INVITE"),
        ):
            with self.subTest(method=method):
                document = correlate([rec(1, method=method, cseq_method=cseq_method)])
                transaction = document["transactions"][0]
                self.assertEqual(transaction["matching_status"], "NOT_ESTABLISHED")
                self.assertIn("METHOD_MISMATCH", transaction["conflict_findings"])
                self.assertIn("CONSISTENT_REQUEST_IDENTITY", transaction["missing_evidence"])

    def test_valid_pairs_and_extension_method(self) -> None:
        for method in ("INVITE", "REGISTER", "CANCEL", "ACK", "OPTIONS", "BYE", "UPDATE", "X-CUSTOM"):
            with self.subTest(method=method):
                document = correlate([rec(1, method=method, cseq_method=method)])
                self.assertNotIn("METHOD_MISMATCH", document["transactions"][0]["conflict_findings"])

    def test_missing_and_malformed_cseq(self) -> None:
        missing = correlate([rec(1, method="REGISTER")])
        record = missing["transactions"][0]
        self.assertNotIn("CSEQ_NOT_OBSERVED", record["missing_evidence"])
        self.assertEqual(record["matching_status"], "REQUEST_ONLY")
        records = [rec(1, method="REGISTER")]
        records[0]["headers"]["cseq_sequence"] = None
        records[0]["headers"]["cseq_method"] = None
        malformed = correlate(records)
        self.assertIn("CSEQ_NOT_OBSERVED", malformed["transactions"][0]["missing_evidence"])

    def test_inconsistent_request_never_matches_response(self) -> None:
        document = correlate(
            [
                rec(1, method="INVITE", cseq_method="INVITE"),
                rec(2, method="INVITE", cseq_method="CANCEL"),
                rec(3, status=200, cseq_method="INVITE", to_tag="T"),
            ]
        )
        for transaction in document["transactions"]:
            if transaction["transaction_type"] == "INVITE":
                self.assertNotEqual(transaction["matching_status"], "MATCHED")


class StateSemanticsTests(unittest.TestCase):
    def test_unknown_role_publishes_evidence_only(self) -> None:
        document = correlate([rec(1, method="INVITE"), rec(2, status=200, cseq_method="INVITE", to_tag="T")])
        transaction = tx(document, "INVITE")
        self.assertEqual(transaction["transaction_role"], "UNKNOWN")
        self.assertEqual(transaction["state_semantics"], "EVIDENCE_ONLY")
        self.assertIsNone(transaction["rfc_transaction_state"])
        self.assertEqual(transaction["observed_evidence_status"], "FINAL_RESPONSE_OBSERVED")

    def test_client_and_server_rfc_states(self) -> None:
        for role, expected in (
            ("CLIENT", "ACCEPTED"),
            ("SERVER", "ACCEPTED"),
        ):
            with self.subTest(role=role):
                document = correlate(
                    [
                        rec(1, method="INVITE", role=role),
                        rec(2, status=200, cseq_method="INVITE", to_tag="T", role=role),
                    ]
                )
                transaction = tx(document, "INVITE")
                self.assertEqual(transaction["transaction_role"], role)
                self.assertEqual(transaction["state_semantics"], "RFC_STATE")
                self.assertEqual(transaction["rfc_transaction_state"], expected)

    def test_confirmed_requires_server_role_and_non_2xx_ack(self) -> None:
        client = correlate(
            [
                rec(1, method="INVITE", role="CLIENT"),
                rec(2, status=486, cseq_method="INVITE", to_tag="T", role="CLIENT"),
                rec(3, method="ACK", cseq_method="ACK", to_tag="T", role="CLIENT"),
            ]
        )
        self.assertEqual(tx(client, "INVITE")["rfc_transaction_state"], "TERMINATED")
        server = correlate(
            [
                rec(1, method="INVITE", role="SERVER"),
                rec(2, status=486, cseq_method="INVITE", to_tag="T", role="SERVER"),
                rec(3, method="ACK", cseq_method="ACK", to_tag="T", role="SERVER"),
            ]
        )
        self.assertEqual(tx(server, "INVITE")["rfc_transaction_state"], "CONFIRMED")

    def test_non_invite_rfc_states(self) -> None:
        for role in ("CLIENT", "SERVER"):
            with self.subTest(role=role):
                document = correlate(
                    [
                        rec(1, method="REGISTER", role=role),
                        rec(2, status=200, cseq_method="REGISTER", to_tag="T", role=role),
                    ]
                )
                self.assertEqual(tx(document, "NON_INVITE")["rfc_transaction_state"], "COMPLETED")


class FingerprintTests(unittest.TestCase):
    def message(self, frame: int, *, request_uri: str = "sip:bob@example.com", body: str = "", header_suffix: str = "") -> dict:
        headers = {
            "method": "INVITE",
            "request_uri": request_uri,
            "call_id": "CALL-ID",
            "cseq_sequence": 1,
            "cseq_method": "INVITE",
            "cseq_present": True,
            "cseq_count": 1,
            "via": {"count": 1, "branch_present": True, "branch_length": 10, "transports": ["UDP"]},
            "via_raw": [{"branch": "z9hG4bK-A", "sent_by": "192.0.2.10:5060", "transport": "UDP", "value": "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-A"}],
            "from": {"count": 1, "tag_present": True, "tag_length": 4},
            "to": {"count": 1, "tag_present": False, "tag_length": None},
            "from_tag_raw": "FTAG",
            "to_tag_raw": None,
            "content_type": None,
            "content_length": len(body),
            "body_length": len(body),
            "msg_hdr_raw": f"INVITE {request_uri} SIP/2.0{header_suffix}",
            "msg_body_raw": body,
        }
        transport = {
            "protocol": "UDP",
            "source_address": "192.0.2.10",
            "source_port": 5060,
            "destination_address": "192.0.2.20",
            "destination_port": 5060,
            "stream_id": None,
            "reassembly": "NOT_APPLICABLE",
            "reassembled_length": None,
            "segment_count": None,
        }
        event = sip_model._build_event(
            capture="sip-fingerprint.pcapng",
            frame=frame,
            frame_time_epoch=f"1700000000.{frame:06d}",
            frame_time_relative=f"{frame}.000000000",
            occurrence=1,
            transport=transport,
            headers=headers,
            integrity_findings=[],
            capture_truncated=False,
        )
        return sip_model._build_message_record(event, headers, transport)

    def test_full_message_repeat_is_exact(self) -> None:
        document = sip_transactions.correlate([self.message(1), self.message(2)])
        transaction = document["transactions"][0]
        self.assertEqual(transaction["retransmission_count"], 1)
        classification = transaction["message_classifications"][1]["classification"]
        self.assertEqual(classification, "EXACT_RETRANSMISSION")

    def test_different_request_uri_and_body_are_not_exact(self) -> None:
        for second in (self.message(2, request_uri="sip:carol@example.com"), self.message(2, body="abcd")):
            with self.subTest(second=second["event"]["frame_number"]):
                document = sip_transactions.correlate([self.message(1), second])
                transaction = document["transactions"][0]
                self.assertEqual(transaction["retransmission_count"], 0)
                self.assertEqual(transaction["retransmission_candidate_count"], 0)

    def test_header_only_and_fields_only_never_claim_exact(self) -> None:
        header_only = self.message(1, body="body")
        header_only["match"] = dict(header_only["match"])
        header_only["match"]["fingerprint_completeness"] = "HEADER_ONLY"
        second = self.message(2, body="body")
        second["match"] = dict(second["match"])
        second["match"]["fingerprint_completeness"] = "HEADER_ONLY"
        document = sip_transactions.correlate([header_only, second])
        transaction = document["transactions"][0]
        self.assertEqual(transaction["retransmission_count"], 0)
        self.assertEqual(transaction["retransmission_candidate_count"], 1)

    def test_tcp_repeat_is_not_sip_retransmission(self) -> None:
        document = correlate(
            [
                rec(1, method="REGISTER", protocol="TCP"),
                rec(2, method="REGISTER", protocol="TCP"),
            ]
        )
        transaction = tx(document, "NON_INVITE")
        self.assertEqual(transaction["retransmission_count"], 0)
        self.assertEqual(
            transaction["repeated_observation_event_references"], ["sip-event:sip-rfc.pcapng:2.1"]
        )


if __name__ == "__main__":
    unittest.main()