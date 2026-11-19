#!/usr/bin/env python3
"""IMS registration Domain evidence tests."""

from __future__ import annotations

import json
import os
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
DOMAIN = SKILL.parents[1]
SCRIPTS = SKILL / "scripts"
SIP_SCRIPTS = SKILL.parents[1] / "protocol" / "sip" / "scripts"
SIP_SCHEMA = SKILL.parents[1] / "protocol" / "sip" / "schemas" / "sip-events.schema.json"
SCHEMA = SKILL / "schemas" / "ims-registration-analysis.schema.json"
DIAMETER_FIXTURE = SKILL / "examples" / "input" / "diameter-ims-cases.json"
for path in (SCRIPTS, SIP_SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import ims_registration_model  # noqa: E402
import sip_model  # noqa: E402

INIT = "sip:alice@example.com"
REGISTRAR = "sip:registrar.example.com"


def rec(
    frame: int,
    *,
    method: str | None = None,
    status: int | None = None,
    branch: str = "z9hG4bK-A",
    call_id: str | None = "CALL",
    cseq: int | None = 1,
    cseq_method: str | None = None,
    from_tag: str | None = "FTAG",
    to_tag: str | None = None,
    request_uri: str | None = REGISTRAR,
    from_uri: str | None = INIT,
    outbound: bool | None = None,
    reason: str = "OK",
    auth: int = 0,
    proxy_auth: int = 0,
    www_auth: int = 0,
    proxy_auth_challenge: int = 0,
    expires: int | None = None,
    contact_expires: int | None = None,
    contact_expiration_values: list[int | None] | None = None,
    contact_count: int | None = None,
    contact_wildcard: bool = False,
    contact_non_wildcard: bool = False,
    expires_present: bool | None = None,
    expires_valid: bool = True,
    contact_expires_present: bool | None = None,
    contact_expires_valid: bool = True,
    min_expires: int | None = None,
    capture: str = "sip-ims.pcapng",
    truncated: bool = False,
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
        "to": {"uri": REGISTRAR, "count": 1, "tag": to_tag},
        "content_length": 0,
        "body_length": 0,
        "request_uri": request_uri,
        "authorization_count": auth,
        "proxy_authorization_count": proxy_auth,
        "www_authenticate_count": www_auth,
        "proxy_authenticate_count": proxy_auth_challenge,
        "contact_count": contact_count if contact_count is not None else (
            (1 if contact_wildcard else 0)
            + (
                len(contact_expiration_values)
                if contact_expiration_values is not None
                else (
                    1
                    if contact_non_wildcard
                    or contact_expires is not None
                    or contact_expires_present is not None
                    else 0
                )
            )
        ),
        "contact_wildcard": contact_wildcard,
        "contact_non_wildcard": contact_non_wildcard,
    }
    if contact_expiration_values is not None:
        headers["contact_expiration_values"] = list(contact_expiration_values)
    for key, value in (
        ("expires_seconds", expires),
        ("contact_expires_seconds", contact_expires),
        ("min_expires_seconds", min_expires),
    ):
        if value is not None:
            headers[key] = value
    if expires_present is not None:
        headers["expires_present"] = expires_present
    if not expires_valid:
        headers["expires_valid"] = False
    if contact_expires_present is not None:
        headers["contact_expires_present"] = contact_expires_present
    if not contact_expires_valid:
        headers["contact_expires_valid"] = False
    if method is not None:
        headers["method"] = method
        headers["max_forwards"] = 70
    if status is not None:
        headers["status_code"] = status
        headers["reason_phrase"] = reason
    record = {
        "capture_file": capture,
        "frame_number": frame,
        "frame_time_epoch": f"1700000300.{frame:09d}",
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
    if truncated:
        record["capture_truncated"] = True
    return record


def run(
    records: list[dict], *, diameter: Path | None = None
) -> tuple[dict, dict]:
    directory = Path(tempfile.mkdtemp())
    source = directory / "registration.jsonl"
    source.write_text(
        "\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n",
        encoding="utf-8",
    )
    output = directory / "analysis.json"
    report = directory / "report.txt"
    command = [
        sys.executable,
        str(SCRIPTS / "analyze-ims-registration.py"),
        "--sip-input",
        str(source),
        "--output",
        str(output),
        "--report",
        str(report),
        "--force",
    ]
    if diameter is not None:
        command.extend(["--diameter-ims", str(diameter)])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return (
        json.loads(output.read_text(encoding="utf-8")),
        {
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "report": report.read_text(encoding="utf-8") if report.is_file() else "",
        },
    )


def _diameter_document(count: int, capture: str | None = "sip-ims.pcapng") -> dict:
    source = capture or "unknown"
    observations = []
    for index in range(count):
        frame = index + 1
        observations.append(
            {
                "observation_reference": f"diameter-observation:{source}:300:{index}",
                "procedure": "UAR",
                "procedure_family": "UAR",
                "command_code": 300,
                "command_name": "UAR",
                "message_status": "OBSERVED",
                "transaction_status": "MATCHED",
                "application_result": "SUCCESS_REPORTED",
                "request": {
                    "event_reference": f"diameter-event:{source}:{frame}.1",
                    "frame_number": frame,
                    "message_occurrence": 1,
                    "direction": "REQUEST",
                    "application_id": 16777216,
                    "command_code": 300,
                    "command_name": "UAR",
                    "message_name": "UAR",
                    "hop_by_hop_id": frame,
                    "end_to_end_id": frame,
                    "source_endpoint": "192.0.2.30:3868",
                    "destination_endpoint": "192.0.2.40:3868",
                },
                "answer": None,
                "response_candidates": [],
                "latency_seconds": None,
                "transaction_reference": f"diameter-transaction:{source}:300:{index}",
                "result": {
                    "core_result_status": "MISSING",
                    "namespace_status": "MISSING",
                    "application_result": "NOT_APPLICABLE",
                    "base_result_code": None,
                    "base_result_code_name": None,
                    "experimental_result_code": None,
                    "experimental_result_code_name": None,
                    "experimental_vendor_id": None,
                    "base_results": [],
                    "experimental_results": [],
                    "limitations": [],
                },
                "request_avp_presence": [],
                "answer_avp_presence": [],
                "limitations": [],
                "not_confirmed": [],
            }
        )
    return {
        "analysis_name": "diameter-ims",
        "analysis_version": "1.1.0",
        "domain": "protocol",
        "capability": {
            "supported_commands": ["UAR"],
            "recognized_unsupported_commands": [],
            "application_id": 16777216,
            "application_name": "Cx/Dx",
            "interface_identity": "UNPROVED",
            "interface_identity_basis": [],
            "unreviewed_command_policy": "KNOWN_UNSUPPORTED_WITH_NUMERIC_IDENTITY",
        },
        "input_provenance": {
            "capture_files": [capture] if capture else [],
            "event_count": count,
            "transaction_count": count,
            "events_sha256": "a" * 64,
            "transactions_sha256": "b" * 64,
        },
        "command_inventory": [],
        "observations": observations,
        "completeness": {
            "observation_count": count,
            "observations_omitted": 0,
            "cx_event_count": count,
            "cx_transaction_count": count,
            "events_with_avp_omissions": 0,
            "truncated_observations": 0,
            "unsupported_observations": 0,
            "conflicting_observations": 0,
            "observations_with_unproven_grouping": 0,
        },
        "not_confirmed": [],
        "limitations": [],
    }


def _write_diameter(document: dict) -> Path:
    directory = Path(tempfile.mkdtemp())
    path = directory / "diameter.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def run_fixture(*, diameter: bool = False) -> dict:
    command = [
        sys.executable,
        str(SCRIPTS / "analyze-ims-registration.py"),
        "--sip-input",
        str(SKILL / "examples" / "input" / "registration-cases.jsonl"),
        "--output",
        str(Path(tempfile.mkdtemp()) / "analysis.json"),
        "--force",
    ]
    if diameter:
        command.extend(["--diameter-ims", str(DIAMETER_FIXTURE)])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return json.loads(Path(command[command.index("--output") + 1]).read_text(encoding="utf-8"))


def attempt(document: dict, index: int = 0) -> dict:
    return document["registration_attempts"][index]


def attempts_with(document: dict, registration_type: str) -> list[dict]:
    return [item for item in document["registration_attempts"] if item["registration_type"] == registration_type]


class RegistrationFundamentals(unittest.TestCase):
    def test_single_register_with_200(self) -> None:
        document, _ = run([rec(1, method="REGISTER"), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)])
        self.assertEqual(len(document["sip_registration_inventory"]), 1)
        self.assertEqual(len(document["registration_attempts"]), 1)
        self.assertEqual(attempt(document)["sip_outcome"], "SUCCESS_RESPONSE_OBSERVED")
        self.assertEqual(attempt(document)["authentication_evidence_status"], "NOT_OBSERVED")

    def test_401_is_a_challenge_not_a_failure(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER"),
                rec(2, status=401, cseq_method="REGISTER", to_tag="T", outbound=False, reason="Unauthorized", www_auth=1),
            ]
        )
        item = attempt(document)
        self.assertEqual(item["authentication_evidence_status"], "CHALLENGE_WITHOUT_OBSERVED_RETRY")
        self.assertEqual(item["sip_outcome"], "INCOMPLETE_EVIDENCE")
        self.assertNotEqual(item["sip_outcome"], "NEGATIVE_RESPONSE_OBSERVED")

    def test_407_is_a_challenge_not_a_failure(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER"),
                rec(2, status=407, cseq_method="REGISTER", to_tag="T", outbound=False, reason="Proxy Authentication Required", proxy_auth_challenge=1),
            ]
        )
        self.assertEqual(attempt(document)["authentication_evidence_status"], "CHALLENGE_WITHOUT_OBSERVED_RETRY")

    def test_401_retry_200(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", cseq=1),
                rec(2, status=401, cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, reason="Unauthorized", www_auth=1),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2, auth=1),
                rec(4, status=200, branch="z9hG4bK-B", cseq=2, cseq_method="REGISTER", to_tag="T2", outbound=False),
            ]
        )
        self.assertEqual(len(document["registration_attempts"]), 1)
        self.assertEqual(attempt(document)["authentication_evidence_status"], "CHALLENGE_RETRY_ASSOCIATED")
        self.assertEqual(attempt(document)["sip_outcome"], "SUCCESS_RESPONSE_OBSERVED")
        self.assertFalse(attempt(document)["authentication_cryptographically_verified"])

    def test_407_retry_200(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", cseq=1),
                rec(2, status=407, cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, proxy_auth_challenge=1),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2, proxy_auth=1),
                rec(4, status=200, branch="z9hG4bK-B", cseq=2, cseq_method="REGISTER", to_tag="T2", outbound=False),
            ]
        )
        self.assertEqual(attempt(document)["authentication_evidence_status"], "CHALLENGE_RETRY_ASSOCIATED")

    def test_401_without_retry(self) -> None:
        document, _ = run([rec(1, method="REGISTER"), rec(2, status=401, cseq_method="REGISTER", to_tag="T", outbound=False, www_auth=1)])
        self.assertIn("CHALLENGE_WITHOUT_OBSERVED_RETRY", attempt(document)["authentication_evidence_status"])

    def test_authorized_register_without_challenge(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", auth=1), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        self.assertEqual(attempt(document)["authentication_evidence_status"], "RETRY_WITHOUT_OBSERVED_CHALLENGE")

    def test_register_without_final_response(self) -> None:
        document, _ = run([rec(1, method="REGISTER")])
        self.assertEqual(attempt(document)["sip_outcome"], "OPEN_IN_CAPTURE")
        self.assertIn("FINAL_RESPONSE_NOT_OBSERVED", attempt(document)["missing_evidence"])

    def test_response_only_is_not_a_successful_attempt(self) -> None:
        document, _ = run([rec(1, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)])
        item = attempt(document)
        self.assertEqual(item["registration_type"], "UNDETERMINED")
        self.assertEqual(item["sip_outcome"], "INCOMPLETE_EVIDENCE")
        self.assertIn("REQUEST_NOT_OBSERVED", item["missing_evidence"])

    def test_multiple_independent_registrations(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", call_id="A", branch="z9hG4bK-A"),
                rec(2, status=200, call_id="A", branch="z9hG4bK-A", cseq_method="REGISTER", to_tag="T", outbound=False),
                rec(3, method="REGISTER", call_id="B", branch="z9hG4bK-B"),
                rec(4, status=200, call_id="B", branch="z9hG4bK-B", cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        self.assertEqual(len(document["registration_attempts"]), 2)
        self.assertEqual(len({item["attempt_reference"] for item in document["registration_attempts"]}), 2)


class AttemptAssociation(unittest.TestCase):
    def test_two_transactions_with_shared_identity(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", cseq=1),
                rec(2, status=401, cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, www_auth=1),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2, auth=1),
                rec(4, status=200, branch="z9hG4bK-B", cseq=2, cseq_method="REGISTER", to_tag="T2", outbound=False),
            ]
        )
        self.assertEqual(len(attempt(document)["transaction_references"]), 2)

    def test_same_call_id_conflicting_from_identity(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", from_tag="ONE"),
                rec(2, status=200, from_tag="ONE", cseq_method="REGISTER", to_tag="T", outbound=False),
                rec(3, method="REGISTER", branch="z9hG4bK-B", from_tag="TWO"),
            ]
        )
        self.assertEqual(len(document["registration_attempts"]), 2)

    def test_same_call_id_conflicting_request_uri(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", request_uri="sip:one.example.com"),
                rec(2, method="REGISTER", branch="z9hG4bK-B", request_uri="sip:two.example.com"),
            ]
        )
        self.assertEqual(len(document["registration_attempts"]), 2)

    def test_incompatible_cseq_is_split(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", branch="z9hG4bK-A", cseq=2),
                rec(2, method="REGISTER", branch="z9hG4bK-B", cseq=1),
            ]
        )
        self.assertEqual(len(document["registration_attempts"]), 2)
        self.assertTrue(
            any("CSEQ_INCOMPATIBLE" in item["conflict_findings"] for item in document["registration_attempts"])
        )

    def test_several_retries_are_not_dropped(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", branch="z9hG4bK-A", cseq=1),
                rec(2, status=401, branch="z9hG4bK-A", cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, www_auth=1),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2, auth=1),
                rec(4, status=401, branch="z9hG4bK-B", cseq=2, cseq_method="REGISTER", to_tag="T2", outbound=False, www_auth=1),
                rec(5, method="REGISTER", branch="z9hG4bK-C", cseq=3, auth=1),
                rec(6, status=200, branch="z9hG4bK-C", cseq=3, cseq_method="REGISTER", to_tag="T3", outbound=False),
            ]
        )
        self.assertEqual(len(document["registration_attempts"]), 1)
        self.assertEqual(len(attempt(document)["transaction_references"]), 3)

    def test_missing_call_id_is_insufficient(self) -> None:
        document, _ = run([rec(1, method="REGISTER", call_id=None)])
        self.assertIn("CALL_ID_NOT_OBSERVED", attempt(document)["missing_evidence"])
        self.assertEqual(attempt(document)["registration_type"], "UNDETERMINED")

    def test_missing_cseq_is_observable(self) -> None:
        document, _ = run([rec(1, method="REGISTER", cseq=None)])
        self.assertEqual(attempt(document)["cseq_observations"]["progression"], "UNKNOWN")

    def test_different_captures_never_share_an_attempt(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", capture="one.pcapng"),
                rec(2, method="REGISTER", branch="z9hG4bK-B", capture="two.pcapng"),
            ]
        )
        self.assertEqual(len(document["registration_attempts"]), 2)
        self.assertFalse(document["timeline"]["global_order_proven"])
        self.assertEqual(document["timeline"]["ordering_basis"], "SOURCE_LOCAL_ONLY")

    def test_duplicate_retransmission_does_not_duplicate_attempt(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER"),
                rec(2, method="REGISTER"),
                rec(3, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        self.assertEqual(len(document["registration_attempts"]), 1)

    def test_attempt_references_are_deterministic(self) -> None:
        records = [
            rec(1, method="REGISTER"),
            rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
        ]
        first, _ = run(records)
        second, _ = run(records)
        self.assertEqual(
            [item["attempt_reference"] for item in first["registration_attempts"]],
            [item["attempt_reference"] for item in second["registration_attempts"]],
        )


class AuthenticationEdges(unittest.TestCase):
    def test_401_followed_by_403_is_negative(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", cseq=1),
                rec(2, status=401, cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, www_auth=1),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2, auth=1),
                rec(4, status=403, branch="z9hG4bK-B", cseq=2, cseq_method="REGISTER", to_tag="T2", outbound=False, reason="Forbidden"),
            ]
        )
        self.assertEqual(attempt(document)["sip_outcome"], "NEGATIVE_RESPONSE_OBSERVED")

    def test_repeated_challenges_remain_observable(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", cseq=1),
                rec(2, status=401, cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, www_auth=1),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2, auth=1),
                rec(4, status=401, branch="z9hG4bK-B", cseq=2, cseq_method="REGISTER", to_tag="T2", outbound=False, www_auth=1),
            ]
        )
        self.assertGreaterEqual(len(attempt(document)["challenge_event_references"]), 1)

    def test_retry_without_success_is_unproved(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", cseq=1),
                rec(2, status=401, cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, www_auth=1),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2, auth=1),
            ]
        )
        self.assertEqual(attempt(document)["sip_outcome"], "OPEN_IN_CAPTURE")

    def test_no_cryptographic_claim(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", auth=1), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        self.assertFalse(attempt(document)["authentication_cryptographically_verified"])
        self.assertTrue(any("cryptographic" in item for item in attempt(document)["limitations"]))

    def test_no_raw_challenge_or_response_value(self) -> None:
        document, artifacts = run(
            [
                rec(1, method="REGISTER", cseq=1),
                rec(2, status=401, cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, www_auth=1),
            ]
        )
        text = json.dumps(document) + artifacts["stdout"] + artifacts["stderr"]
        for token in ("nonce", "response=", "Digest ", "Authorization:"):
            self.assertNotIn(token, text)


    def test_authorized_register_then_401_without_later_register(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", auth=1),
                rec(2, status=401, cseq_method="REGISTER", to_tag="T", outbound=False, www_auth=1),
            ]
        )
        item = attempt(document)
        self.assertNotEqual(item["authentication_evidence_status"], "CHALLENGE_RETRY_ASSOCIATED")
        self.assertEqual(item["authentication_evidence_status"], "RETRY_NOT_ESTABLISHED")
        self.assertIn("AUTHORIZATION_PRECEDED_CHALLENGE", item["conflict_findings"])
        self.assertIsNone(
            item["challenge_retry_association"]["retry_transaction_reference"]
        )

    def test_authorized_register_then_407_without_later_register(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", proxy_auth=1),
                rec(2, status=407, cseq_method="REGISTER", to_tag="T", outbound=False, proxy_auth_challenge=1),
            ]
        )
        self.assertNotEqual(
            attempt(document)["authentication_evidence_status"],
            "CHALLENGE_RETRY_ASSOCIATED",
        )

    def test_challenge_then_unauthenticated_register(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", cseq=1),
                rec(2, status=401, cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, www_auth=1),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2),
            ]
        )
        self.assertNotEqual(
            attempt(document)["authentication_evidence_status"], "CHALLENGE_RETRY_ASSOCIATED"
        )

    def test_challenge_then_conflicting_identity_is_not_associated(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", call_id="A", cseq=1),
                rec(2, status=401, call_id="A", cseq=1, cseq_method="REGISTER", to_tag="T", outbound=False, www_auth=1),
                rec(3, method="REGISTER", call_id="B", branch="z9hG4bK-B", cseq=2, auth=1),
            ]
        )
        self.assertFalse(
            any(
                item["authentication_evidence_status"] == "CHALLENGE_RETRY_ASSOCIATED"
                for item in document["registration_attempts"]
            )
        )

    def test_challenge_retry_with_incompatible_cseq(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", cseq=2),
                rec(2, status=401, cseq=2, cseq_method="REGISTER", to_tag="T", outbound=False, www_auth=1),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=1, auth=1),
            ]
        )
        self.assertFalse(
            any(
                item["authentication_evidence_status"] == "CHALLENGE_RETRY_ASSOCIATED"
                for item in document["registration_attempts"]
            )
        )
        self.assertTrue(
            any(
                "CSEQ_INCOMPATIBLE" in item["conflict_findings"]
                for item in document["registration_attempts"]
            )
        )

    def test_multiple_competing_retries_are_not_associated(self) -> None:
        synthetic = {
            "transactions": [
                {
                    "transaction_reference": "sip-transaction:test:request:1.1",
                    "final_response_status_codes": [401],
                    "request_event_references": ["sip-event:test:1.1"],
                    "final_response_event_references": ["sip-event:test:2.1"],
                },
                {
                    "transaction_reference": "sip-transaction:test:request:3.1",
                    "final_response_status_codes": [200],
                    "request_event_references": ["sip-event:test:3.1"],
                    "final_response_event_references": ["sip-event:test:4.1"],
                },
                {
                    "transaction_reference": "sip-transaction:test:request:5.1",
                    "final_response_status_codes": [200],
                    "request_event_references": ["sip-event:test:5.1"],
                    "final_response_event_references": ["sip-event:test:6.1"],
                },
            ],
            "request_matches": [
                {"cseq_number": 1, "authorization_count": 0},
                {"cseq_number": 2, "authorization_count": 1},
                {"cseq_number": 3, "authorization_count": 1},
            ],
        }
        association = ims_registration_model._challenge_retry_association(
            synthetic,
            {
                "sip-event:test:2.1": {"status_code": 401},
                "sip-event:test:4.1": {"status_code": 200},
                "sip-event:test:6.1": {"status_code": 200},
            },
        )
        self.assertEqual(association["status"], "AMBIGUOUS")
        self.assertIn("MULTIPLE_RETRY_CANDIDATES", association["conflict_findings"])

    def test_repeated_challenges_keep_the_first_eligible_retry(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", cseq=1),
                rec(2, status=401, cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, www_auth=1),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2, auth=1),
                rec(4, status=401, branch="z9hG4bK-B", cseq=2, cseq_method="REGISTER", to_tag="T2", outbound=False, www_auth=1),
                rec(5, method="REGISTER", branch="z9hG4bK-C", cseq=3, auth=1),
                rec(6, status=200, branch="z9hG4bK-C", cseq=3, cseq_method="REGISTER", to_tag="T3", outbound=False),
            ]
        )
        item = attempt(document)
        self.assertEqual(item["authentication_evidence_status"], "CHALLENGE_RETRY_ASSOCIATED")
        self.assertEqual(
            item["challenge_retry_association"]["retry_request_event_reference"],
            "sip-event:sip-ims.pcapng:3.1",
        )

    def test_challenge_then_unrelated_register(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", call_id="A", cseq=1),
                rec(2, status=401, call_id="A", cseq=1, cseq_method="REGISTER", to_tag="T", outbound=False, www_auth=1),
                rec(3, method="REGISTER", call_id="B", branch="z9hG4bK-B", cseq=2, auth=1),
            ]
        )
        first = document["registration_attempts"][0]
        self.assertEqual(first["authentication_evidence_status"], "CHALLENGE_WITHOUT_OBSERVED_RETRY")

    def test_multi_hop_retry_copies_are_one_logical_retry(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", cseq=1),
                rec(2, status=401, cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, www_auth=1),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2, auth=1),
                rec(4, method="REGISTER", branch="z9hG4bK-C", cseq=2, auth=1),
            ]
        )
        item = attempt(document)
        self.assertTrue(item["multi_hop_candidate"])
        self.assertEqual(item["authentication_evidence_status"], "CHALLENGE_RETRY_ASSOCIATED")
        self.assertIn(
            "multi_hop_copies_of_one_logical_retry",
            item["challenge_retry_association"]["basis"],
        )

    def test_association_references_are_deterministic(self) -> None:
        records = [
            rec(1, method="REGISTER", cseq=1),
            rec(2, status=401, cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, www_auth=1),
            rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2, auth=1),
            rec(4, status=200, branch="z9hG4bK-B", cseq=2, cseq_method="REGISTER", to_tag="T2", outbound=False),
        ]
        first, _ = run(records)
        second, _ = run(records)
        self.assertEqual(
            first["registration_attempts"][0]["challenge_retry_association"],
            second["registration_attempts"][0]["challenge_retry_association"],
        )


class LifecycleEvidence(unittest.TestCase):
    def test_initial_candidate(self) -> None:
        document, _ = run([rec(1, method="REGISTER")])
        self.assertEqual(attempt(document)["registration_type"], "INITIAL_REGISTRATION_CANDIDATE")

    def test_pre_authenticated_register(self) -> None:
        document, _ = run([rec(1, method="REGISTER", auth=1)])
        self.assertEqual(attempt(document)["authentication_evidence_status"], "RETRY_WITHOUT_OBSERVED_CHALLENGE")

    def test_re_registration_candidate(self) -> None:
        document = run_fixture()
        self.assertTrue(attempts_with(document, "RE_REGISTRATION_CANDIDATE"))

    def test_refresh_observed(self) -> None:
        document = run_fixture()
        self.assertTrue(attempts_with(document, "REFRESH_OBSERVED"))

    def test_missing_preceding_registration_stays_initial(self) -> None:
        document, _ = run([rec(1, method="REGISTER", auth=1)])
        self.assertEqual(attempt(document)["registration_type"], "INITIAL_REGISTRATION_CANDIDATE")

    def test_positive_expires(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", expires=3600), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        self.assertIn("positive_expires", attempt(document)["registration_type_evidence"])

    def test_expires_zero_with_contact_is_contact_scoped_deregistration(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", expires=0, contact_expiration_values=[None]),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        item = attempt(document)
        self.assertEqual(item["registration_type"], "DEREGISTRATION_REQUESTED")
        self.assertTrue(item["deregistration"]["accepted_by_sip"])
        self.assertEqual(item["deregistration"]["scope"], "CONTACT_SCOPED")
        self.assertFalse(item["deregistration"]["valid_all_bindings_request"])

    def test_contact_specific_expiration(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", contact_expires=0), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        self.assertTrue(attempt(document)["deregistration"]["request_observed"])

    def test_wildcard_contact_deregistration(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", contact_wildcard=True, expires=0),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertTrue(deregistration["contact_wildcard"])
        self.assertTrue(deregistration["valid_all_bindings_request"])
        self.assertEqual(deregistration["scope"], "ALL_BINDINGS")

    def test_wildcard_without_expires_is_invalid(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", contact_wildcard=True), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        item = attempt(document)
        self.assertFalse(item["deregistration"]["valid_all_bindings_request"])
        self.assertEqual(item["deregistration"]["scope"], "NONE")
        self.assertIn("WILDCARD_WITHOUT_EXPIRES", item["deregistration"]["invalidity"])
        self.assertIn("INVALID_DEREGISTRATION_REQUEST", item["conflict_findings"])

    def test_wildcard_with_nonzero_expires_is_invalid(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", contact_wildcard=True, expires=3600), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        self.assertIn("WILDCARD_WITH_NONZERO_EXPIRES", attempt(document)["deregistration"]["invalidity"])

    def test_wildcard_with_additional_contact_is_invalid(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", contact_wildcard=True, contact_non_wildcard=True, expires=0),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertFalse(deregistration["valid_all_bindings_request"])
        self.assertEqual(deregistration["scope"], "NONE")
        self.assertIn("WILDCARD_WITH_ADDITIONAL_CONTACT", deregistration["invalidity"])

    def test_contact_specific_expiration_is_scoped(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", contact_expires=0), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["scope"], "CONTACT_SCOPED")
        self.assertFalse(deregistration["valid_all_bindings_request"])

    def test_expires_zero_without_contact_is_not_deregistration(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", expires=0), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["scope"], "NONE")
        self.assertFalse(deregistration["valid_all_bindings_request"])
        self.assertIn("EXPIRES_WITHOUT_CONTACT", deregistration["invalidity"])
        self.assertNotEqual(
            attempt(document)["registration_type"], "DEREGISTRATION_REQUESTED"
        )

    def test_absent_expiration_is_not_zero(self) -> None:
        document, _ = run([rec(1, method="REGISTER")])
        self.assertIsNone(attempt(document)["deregistration"])

    def test_malformed_expires_is_invalid_evidence(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", expires_present=True, expires_valid=False, contact_wildcard=True)]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertFalse(deregistration["valid_all_bindings_request"])
        self.assertIn("EXPIRES_MALFORMED", deregistration["invalidity"])
        self.assertFalse(deregistration["accepted_by_sip"])

    def test_invalid_wildcard_with_200_is_not_proven_removal(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", contact_wildcard=True), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertTrue(deregistration["accepted_by_sip"])
        self.assertEqual(deregistration["outcome"], "DEREGISTRATION_OUTCOME_UNPROVED")
        self.assertFalse(deregistration["valid_all_bindings_request"])

    def test_no_raw_contact_uri_is_published(self) -> None:
        document, artifacts = run(
            [rec(1, method="REGISTER", contact_wildcard=True, expires=0), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        text = json.dumps(document) + artifacts["stdout"] + artifacts["stderr"] + artifacts["report"]
        self.assertNotIn("contact_uri", text)
        self.assertNotIn("sip:", text)

    def test_missing_expiration_evidence(self) -> None:
        document, _ = run([rec(1, method="REGISTER")])
        self.assertIn("EXPIRATION_NOT_OBSERVED", attempt(document)["missing_evidence"])

    def test_deregistration_with_200(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", contact_expiration_values=[0]),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        self.assertEqual(attempt(document)["deregistration"]["outcome"], "DEREGISTRATION_ACCEPTED_BY_SIP")

    def test_deregistration_without_final_response(self) -> None:
        document, _ = run([rec(1, method="REGISTER", contact_expiration_values=[0])])
        self.assertEqual(attempt(document)["deregistration"]["outcome"], "DEREGISTRATION_OUTCOME_UNPROVED")


class ContactBindingScope(unittest.TestCase):
    def test_wildcard_with_expires_zero_is_all_bindings(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", contact_wildcard=True, expires=0)]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["scope"], "ALL_BINDINGS")
        self.assertTrue(deregistration["valid_all_bindings_request"])
        self.assertTrue(deregistration["request_observed"])

    def test_wildcard_without_expires_is_not_all_bindings(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", contact_wildcard=True),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["scope"], "NONE")
        self.assertFalse(deregistration["valid_all_bindings_request"])
        self.assertIn("WILDCARD_WITHOUT_EXPIRES", deregistration["invalidity"])

    def test_wildcard_with_nonzero_expires_is_not_all_bindings(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", contact_wildcard=True, expires=3600),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["scope"], "NONE")
        self.assertIn("WILDCARD_WITH_NONZERO_EXPIRES", deregistration["invalidity"])

    def test_wildcard_with_another_contact_is_not_all_bindings(self) -> None:
        document, _ = run(
            [
                rec(
                    1,
                    method="REGISTER",
                    contact_wildcard=True,
                    contact_expiration_values=[None],
                    expires=0,
                ),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["scope"], "NONE")
        self.assertFalse(deregistration["valid_all_bindings_request"])
        self.assertIn("WILDCARD_WITH_ADDITIONAL_CONTACT", deregistration["invalidity"])

    def test_one_contact_with_default_expires_zero_is_contact_scoped(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", expires=0, contact_expiration_values=[None]),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        observation = attempt(document)["deregistration"]["transaction_observations"][0]
        self.assertEqual(observation["scope"], "CONTACT_SCOPED")
        self.assertFalse(observation["valid_all_bindings_request"])

    def test_one_contact_with_explicit_expires_zero_is_contact_scoped(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", contact_expiration_values=[0]),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        observation = attempt(document)["deregistration"]["transaction_observations"][0]
        self.assertEqual(observation["scope"], "CONTACT_SCOPED")
        self.assertTrue(observation["request_valid"])

    def test_expires_zero_without_contact_is_not_removal(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", expires=0),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["scope"], "NONE")
        self.assertFalse(deregistration["valid_all_bindings_request"])
        self.assertIn("EXPIRES_WITHOUT_CONTACT", deregistration["invalidity"])
        self.assertEqual(deregistration["outcome"], "DEREGISTRATION_OUTCOME_UNPROVED")

    def test_expires_zero_with_one_non_wildcard_contact_is_contact_scoped(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", expires=0, contact_non_wildcard=True),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        observation = attempt(document)["deregistration"]["transaction_observations"][0]
        self.assertEqual(observation["scope"], "CONTACT_SCOPED")
        self.assertFalse(observation["valid_all_bindings_request"])

    def test_expires_zero_with_several_contacts_is_contact_scoped(self) -> None:
        document, _ = run(
            [
                rec(
                    1,
                    method="REGISTER",
                    expires=0,
                    contact_expiration_values=[None, None, None],
                ),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["scope"], "CONTACT_SCOPED")
        self.assertFalse(deregistration["valid_all_bindings_request"])
        self.assertEqual(deregistration["contact_entry_count"], 3)

    def test_positive_contact_expiration_overrides_expires_zero(self) -> None:
        document, _ = run(
            [
                rec(
                    1,
                    method="REGISTER",
                    expires=0,
                    contact_expiration_values=[3600],
                ),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["scope"], "NONE")
        self.assertFalse(deregistration["valid_all_bindings_request"])
        self.assertIn(
            "CONTACT_EXPIRATION_OVERRIDES_EXPIRES", deregistration["invalidity"]
        )

    def test_two_contacts_with_different_expiration(self) -> None:
        document, _ = run(
            [
                rec(
                    1,
                    method="REGISTER",
                    contact_expiration_values=[0, 3600],
                ),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        observation = deregistration["transaction_observations"][0]
        self.assertEqual(observation["scope"], "CONTACT_SCOPED")
        self.assertTrue(observation["mixed_contact_expiration"])
        self.assertFalse(observation["valid_all_bindings_request"])

    def test_several_contacts_one_zero_others_positive(self) -> None:
        document, _ = run(
            [
                rec(
                    1,
                    method="REGISTER",
                    contact_expiration_values=[0, 1800, 3600],
                ),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertTrue(deregistration["mixed_contact_expiration"])
        self.assertEqual(deregistration["contact_zero_expires_count"], 1)
        self.assertEqual(deregistration["contact_positive_expires_count"], 2)
        self.assertFalse(deregistration["valid_all_bindings_request"])

    def test_malformed_contact_expires_is_retained_without_bindings_claim(self) -> None:
        document, _ = run(
            [
                rec(
                    1,
                    method="REGISTER",
                    contact_expires_present=True,
                    contact_expires_valid=False,
                ),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["scope"], "NONE")
        self.assertFalse(deregistration["valid_all_bindings_request"])
        self.assertIn("CONTACT_EXPIRES_MALFORMED", deregistration["invalidity"])

    def test_invalid_expires_header_is_invalid_evidence(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", expires_present=True, expires_valid=False),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["scope"], "NONE")
        self.assertIn("EXPIRES_MALFORMED", deregistration["invalidity"])

    def test_contact_removal_without_final_response(self) -> None:
        document, _ = run([rec(1, method="REGISTER", contact_expiration_values=[0])])
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["outcome"], "DEREGISTRATION_OUTCOME_UNPROVED")
        observation = deregistration["transaction_observations"][0]
        self.assertFalse(observation["response_observed"])
        self.assertIn("FINAL_RESPONSE_NOT_OBSERVED", observation["missing_evidence"])

    def test_contact_removal_with_matched_200(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", contact_expiration_values=[0]),
                rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        observation = attempt(document)["deregistration"]["transaction_observations"][0]
        self.assertEqual(observation["outcome"], "DEREGISTRATION_ACCEPTED_BY_SIP")
        self.assertEqual(observation["response_code"], 200)

    def test_contact_removal_with_matched_negative_response(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", contact_expiration_values=[0]),
                rec(
                    2,
                    status=403,
                    cseq_method="REGISTER",
                    to_tag="T",
                    outbound=False,
                    reason="Forbidden",
                ),
            ]
        )
        observation = attempt(document)["deregistration"]["transaction_observations"][0]
        self.assertEqual(observation["outcome"], "DEREGISTRATION_RESPONSE_OBSERVED")
        self.assertEqual(observation["response_code"], 403)

    def test_unrelated_200_does_not_establish_removal(self) -> None:
        document, _ = run(
            [
                rec(
                    1,
                    method="REGISTER",
                    branch="z9hG4bK-A",
                    contact_expiration_values=[0],
                ),
                rec(
                    2,
                    method="REGISTER",
                    branch="z9hG4bK-B",
                    expires=3600,
                ),
                rec(
                    3,
                    status=200,
                    branch="z9hG4bK-B",
                    cseq_method="REGISTER",
                    to_tag="T",
                    outbound=False,
                ),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(deregistration["outcome"], "DEREGISTRATION_OUTCOME_UNPROVED")
        self.assertFalse(deregistration["accepted_by_sip"])
        self.assertFalse(deregistration["valid_all_bindings_request"])
        self.assertEqual(len(deregistration["transaction_observations"]), 1)
        self.assertIsNone(
            deregistration["transaction_observations"][0]["response_event_reference"]
        )

    def test_repeated_retransmissions_do_not_duplicate_removal_claims(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", contact_expiration_values=[0]),
                rec(2, method="REGISTER", contact_expiration_values=[0]),
                rec(3, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        deregistration = attempt(document)["deregistration"]
        self.assertEqual(len(deregistration["transaction_observations"]), 1)
        self.assertEqual(
            len(
                {
                    item["transaction_reference"]
                    for item in deregistration["transaction_observations"]
                }
            ),
            1,
        )

    def test_mid_capture_removal_remains_incomplete(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", contact_expiration_values=[0], truncated=True)]
        )
        item = attempt(document)
        self.assertEqual(item["sip_outcome"], "OPEN_IN_CAPTURE")
        self.assertEqual(item["deregistration"]["outcome"], "DEREGISTRATION_OUTCOME_UNPROVED")
        self.assertIn("FINAL_RESPONSE_NOT_OBSERVED", item["missing_evidence"])


class ChallengeTemporalOrdering(unittest.TestCase):
    def _association(self, challenge_status: int, **overrides) -> dict:
        synthetic = {
            "transactions": [
                {
                    "transaction_reference": "sip-transaction:test:request:1.1",
                    "final_response_status_codes": [challenge_status],
                    "request_event_references": ["sip-event:test:1.1"],
                    "final_response_event_references": ["sip-event:test:2.1"],
                },
                {
                    "transaction_reference": "sip-transaction:test:request:3.1",
                    "final_response_status_codes": [200],
                    "request_event_references": ["sip-event:test:3.1"],
                    "final_response_event_references": ["sip-event:test:4.1"],
                },
            ],
            "request_matches": [
                {"cseq_number": 1, "authorization_count": 0, "proxy_authorization_count": 0},
                {"cseq_number": 2, "authorization_count": 1, "proxy_authorization_count": 1},
            ],
        }
        synthetic.update(overrides)
        return ims_registration_model._challenge_retry_association(
            synthetic,
            {
                "sip-event:test:1.1": {"status_code": None},
                "sip-event:test:2.1": {"status_code": challenge_status},
                "sip-event:test:3.1": {"status_code": None},
                "sip-event:test:5.1": {"status_code": challenge_status},
                "sip-event:test:6.1": {"status_code": challenge_status},
            },
        )

    def test_register_401_authorized_register(self) -> None:
        association = self._association(401)
        self.assertEqual(association["status"], "ASSOCIATED")
        self.assertIn("challenge_response_precedes_retry", association["basis"])

    def test_register_407_proxy_authorized_register(self) -> None:
        association = self._association(407)
        self.assertEqual(association["status"], "ASSOCIATED")

    def test_authorized_retry_before_delayed_challenge_is_not_associated(self) -> None:
        association = self._association(
            401,
            transactions=[
                {
                    "transaction_reference": "sip-transaction:test:request:1.1",
                    "final_response_status_codes": [401],
                    "request_event_references": ["sip-event:test:1.1"],
                    "final_response_event_references": ["sip-event:test:5.1"],
                },
                {
                    "transaction_reference": "sip-transaction:test:request:3.1",
                    "final_response_status_codes": [200],
                    "request_event_references": ["sip-event:test:3.1"],
                    "final_response_event_references": ["sip-event:test:4.1"],
                },
            ],
        )
        self.assertEqual(association["status"], "NOT_ASSOCIATED")
        self.assertIn(
            "CHALLENGE_RESPONSE_NOT_BEFORE_RETRY", association["conflict_findings"]
        )

    def test_out_of_order_packet_records_are_insufficient(self) -> None:
        association = self._association(
            401,
            transactions=[
                {
                    "transaction_reference": "sip-transaction:test:request:4.1",
                    "final_response_status_codes": [401],
                    "request_event_references": ["sip-event:test:4.1"],
                    "final_response_event_references": ["sip-event:test:6.1"],
                },
                {
                    "transaction_reference": "sip-transaction:test:request:2.1",
                    "final_response_status_codes": [200],
                    "request_event_references": ["sip-event:test:2.1"],
                    "final_response_event_references": ["sip-event:test:3.1"],
                },
            ],
        )
        self.assertNotEqual(association["status"], "ASSOCIATED")
        self.assertIn(
            "CHALLENGE_RESPONSE_NOT_BEFORE_RETRY", association["conflict_findings"]
        )

    def test_missing_challenge_response_reference_is_insufficient(self) -> None:
        association = self._association(
            401,
            transactions=[
                {
                    "transaction_reference": "sip-transaction:test:request:1.1",
                    "final_response_status_codes": [401],
                    "request_event_references": ["sip-event:test:1.1"],
                    "final_response_event_references": [],
                },
                {
                    "transaction_reference": "sip-transaction:test:request:3.1",
                    "final_response_status_codes": [200],
                    "request_event_references": ["sip-event:test:3.1"],
                    "final_response_event_references": ["sip-event:test:4.1"],
                },
            ],
        )
        self.assertEqual(association["status"], "CHALLENGE_WITHOUT_RETRY")
        self.assertIn("FINAL_RESPONSE_NOT_OBSERVED", association["missing_evidence"])

    def test_multiple_messages_in_one_frame_use_occurrence_order(self) -> None:
        synthetic = {
            "transactions": [
                {
                    "transaction_reference": "sip-transaction:test:request:1.1",
                    "final_response_status_codes": [401],
                    "request_event_references": ["sip-event:test:1.1"],
                    "final_response_event_references": ["sip-event:test:2.1"],
                },
                {
                    "transaction_reference": "sip-transaction:test:request:2.2",
                    "final_response_status_codes": [200],
                    "request_event_references": ["sip-event:test:2.2"],
                    "final_response_event_references": ["sip-event:test:3.1"],
                },
            ],
            "request_matches": [
                {"cseq_number": 1, "authorization_count": 0},
                {"cseq_number": 2, "authorization_count": 1},
            ],
        }
        association = ims_registration_model._challenge_retry_association(
            synthetic,
            {"sip-event:test:2.1": {"status_code": 401}},
        )
        self.assertEqual(association["status"], "ASSOCIATED")
        self.assertEqual(
            association["retry_request_event_reference"], "sip-event:test:2.2"
        )

    def test_repeated_challenge_response_keeps_single_retry(self) -> None:
        synthetic = {
            "transactions": [
                {
                    "transaction_reference": "sip-transaction:test:request:1.1",
                    "final_response_status_codes": [401],
                    "request_event_references": ["sip-event:test:1.1"],
                    "final_response_event_references": [
                        "sip-event:test:2.1",
                        "sip-event:test:2.1",
                    ],
                },
                {
                    "transaction_reference": "sip-transaction:test:request:3.1",
                    "final_response_status_codes": [200],
                    "request_event_references": ["sip-event:test:3.1"],
                    "final_response_event_references": ["sip-event:test:4.1"],
                },
            ],
            "request_matches": [
                {"cseq_number": 1, "authorization_count": 0},
                {"cseq_number": 2, "authorization_count": 1},
            ],
        }
        association = ims_registration_model._challenge_retry_association(
            synthetic, {"sip-event:test:2.1": {"status_code": 401}}
        )
        self.assertEqual(association["status"], "ASSOCIATED")
        self.assertEqual(
            association["challenge_response_event_reference"], "sip-event:test:2.1"
        )

    def test_competing_retries_are_ambiguous(self) -> None:
        synthetic = {
            "transactions": [
                {
                    "transaction_reference": "sip-transaction:test:request:1.1",
                    "final_response_status_codes": [401],
                    "request_event_references": ["sip-event:test:1.1"],
                    "final_response_event_references": ["sip-event:test:2.1"],
                },
                {
                    "transaction_reference": "sip-transaction:test:request:3.1",
                    "final_response_status_codes": [200],
                    "request_event_references": ["sip-event:test:3.1"],
                    "final_response_event_references": ["sip-event:test:4.1"],
                },
                {
                    "transaction_reference": "sip-transaction:test:request:5.1",
                    "final_response_status_codes": [200],
                    "request_event_references": ["sip-event:test:5.1"],
                    "final_response_event_references": ["sip-event:test:6.1"],
                },
            ],
            "request_matches": [
                {"cseq_number": 1, "authorization_count": 0},
                {"cseq_number": 2, "authorization_count": 1},
                {"cseq_number": 3, "authorization_count": 1},
            ],
        }
        association = ims_registration_model._challenge_retry_association(
            synthetic, {"sip-event:test:2.1": {"status_code": 401}}
        )
        self.assertEqual(association["status"], "AMBIGUOUS")
        self.assertIn("MULTIPLE_RETRY_CANDIDATES", association["conflict_findings"])

    def test_different_capture_identities_are_not_associated(self) -> None:
        synthetic = {
            "transactions": [
                {
                    "transaction_reference": "sip-transaction:one:request:1.1",
                    "final_response_status_codes": [401],
                    "request_event_references": ["sip-event:one:1.1"],
                    "final_response_event_references": ["sip-event:one:2.1"],
                },
                {
                    "transaction_reference": "sip-transaction:two:request:3.1",
                    "final_response_status_codes": [200],
                    "request_event_references": ["sip-event:two:3.1"],
                    "final_response_event_references": ["sip-event:two:4.1"],
                },
            ],
            "request_matches": [
                {"cseq_number": 1, "authorization_count": 0},
                {"cseq_number": 2, "authorization_count": 1},
            ],
        }
        association = ims_registration_model._challenge_retry_association(
            synthetic, {"sip-event:one:2.1": {"status_code": 401}}
        )
        self.assertNotEqual(association["status"], "ASSOCIATED")
        self.assertIn("CAPTURE_IDENTITY_MISMATCH", association["conflict_findings"])

    def test_association_source_references_are_observed_events(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", cseq=1),
                rec(
                    2,
                    status=401,
                    cseq=1,
                    cseq_method="REGISTER",
                    to_tag="T1",
                    outbound=False,
                    www_auth=1,
                ),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2, auth=1),
            ]
        )
        item = attempt(document)
        association = item["challenge_retry_association"]
        self.assertEqual(association["status"], "ASSOCIATED")
        self.assertIn(
            association["challenge_response_event_reference"],
            item["response_event_references"],
        )
        self.assertIn(
            association["retry_request_event_reference"],
            item["request_event_references"],
        )


def _xml_attr(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\n", "&#10;")
    )


def _pdml_request_packet(
    frame: int,
    *,
    contact_lines: list[str],
    expires_line: str | None,
    branch: str = "z9hG4bK-A",
    cseq: int = 1,
) -> str:
    lines = [
        f"Via: SIP/2.0/UDP 192.0.2.10:5060;branch={branch}",
        "Max-Forwards: 70",
        "From: <sip:alice@example.com>;tag=FTAG",
        "To: <sip:registrar.example.com>",
        "Call-ID: CALL",
        f"CSeq: {cseq} REGISTER",
        *contact_lines,
    ]
    if expires_line is not None:
        lines.append(expires_line)
    lines.append("Content-Length: 0")
    raw_header = "\n".join(lines) + "\n"
    contact_fields = "\n".join(
        f'      <field name="sip.Contact" show="{_xml_attr(line.split(":", 1)[1].strip())}"/>'
        for line in contact_lines
    )
    expires_field = ""
    if expires_line is not None:
        expires_field = (
            f'      <field name="sip.Expires" show="'
            f'{_xml_attr(expires_line.split(":", 1)[1].strip())}"/>\n'
        )
    return f"""<packet>
  <proto name="frame">
    <field name="frame.number" show="{frame}"/>
    <field name="frame.time_epoch" show="1700000300.{frame:09d}"/>
    <field name="frame.time_relative" show="{frame}.000000000"/>
    <field name="frame.cap_len" show="512"/>
    <field name="frame.len" show="512"/>
  </proto>
  <proto name="ip">
    <field name="ip.src" show="192.0.2.10"/>
    <field name="ip.dst" show="192.0.2.20"/>
  </proto>
  <proto name="udp">
    <field name="udp.srcport" show="5060"/>
    <field name="udp.dstport" show="5060"/>
  </proto>
  <proto name="sip">
    <field name="sip.Request-Line" show="REGISTER sip:registrar.example.com SIP/2.0">
      <field name="sip.Method" show="REGISTER"/>
      <field name="sip.r-uri" show="sip:registrar.example.com"/>
    </field>
    <field name="sip.msg_hdr" show="{_xml_attr(raw_header)}"/>
    <field name="sip.Via" show="SIP/2.0/UDP 192.0.2.10:5060;branch={branch}">
      <field name="sip.Via.transport" show="UDP"/>
      <field name="sip.Via.sent-by.address" show="192.0.2.10"/>
      <field name="sip.Via.sent-by.port" show="5060"/>
      <field name="sip.Via.branch" show="{branch}"/>
    </field>
    <field name="sip.Max-Forwards" show="70"/>
    <field name="sip.From" show="&lt;sip:alice@example.com&gt;;tag=FTAG">
      <field name="sip.from.addr" show="sip:alice@example.com"/>
      <field name="sip.from.tag" show="FTAG"/>
    </field>
    <field name="sip.To" show="&lt;sip:registrar.example.com&gt;">
      <field name="sip.to.addr" show="sip:registrar.example.com"/>
    </field>
    <field name="sip.Call-ID" show="CALL"/>
    <field name="sip.CSeq" show="{cseq} REGISTER">
      <field name="sip.CSeq.seq" show="{cseq}"/>
      <field name="sip.CSeq.method" show="REGISTER"/>
    </field>
{contact_fields}
{expires_field}    <field name="sip.Content-Length" show="0"/>
  </proto>
</packet>"""


def _pdml_response_packet(
    frame: int, *, branch: str = "z9hG4bK-A", cseq: int = 1
) -> str:
    raw_header = "\n".join(
        [
            f"Via: SIP/2.0/UDP 192.0.2.10:5060;branch={branch}",
            "From: <sip:alice@example.com>;tag=FTAG",
            "To: <sip:registrar.example.com>;tag=T",
            "Call-ID: CALL",
            f"CSeq: {cseq} REGISTER",
            "Content-Length: 0",
        ]
    ) + "\n"
    return f"""<packet>
  <proto name="frame">
    <field name="frame.number" show="{frame}"/>
    <field name="frame.time_epoch" show="1700000300.{frame:09d}"/>
    <field name="frame.time_relative" show="{frame}.000000000"/>
    <field name="frame.cap_len" show="512"/>
    <field name="frame.len" show="512"/>
  </proto>
  <proto name="ip">
    <field name="ip.src" show="192.0.2.20"/>
    <field name="ip.dst" show="192.0.2.10"/>
  </proto>
  <proto name="udp">
    <field name="udp.srcport" show="5060"/>
    <field name="udp.dstport" show="5060"/>
  </proto>
  <proto name="sip">
    <field name="sip.Status-Line" show="SIP/2.0 200 OK">
      <field name="sip.Status-Code" show="200"/>
    </field>
    <field name="sip.msg_hdr" show="{_xml_attr(raw_header)}"/>
    <field name="sip.Via" show="SIP/2.0/UDP 192.0.2.10:5060;branch={branch}">
      <field name="sip.Via.transport" show="UDP"/>
      <field name="sip.Via.sent-by.address" show="192.0.2.10"/>
      <field name="sip.Via.sent-by.port" show="5060"/>
      <field name="sip.Via.branch" show="{branch}"/>
    </field>
    <field name="sip.From" show="&lt;sip:alice@example.com&gt;;tag=FTAG">
      <field name="sip.from.addr" show="sip:alice@example.com"/>
      <field name="sip.from.tag" show="FTAG"/>
    </field>
    <field name="sip.To" show="&lt;sip:registrar.example.com&gt;;tag=T">
      <field name="sip.to.addr" show="sip:registrar.example.com"/>
      <field name="sip.to.tag" show="T"/>
    </field>
    <field name="sip.Call-ID" show="CALL"/>
    <field name="sip.CSeq" show="{cseq} REGISTER">
      <field name="sip.CSeq.seq" show="{cseq}"/>
      <field name="sip.CSeq.method" show="REGISTER"/>
    </field>
    <field name="sip.Content-Length" show="0"/>
  </proto>
</packet>"""


def _pdml_document(request: str, response: str) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<pdml version="0" capture_file="raw-contact-cases.pcapng">\n'
        f"{request}\n{response}\n</pdml>\n"
    )


class RawContactWildcardBoundary(unittest.TestCase):
    CASES = (
        (
            "sole-wildcard",
            ["Contact: *"],
            "Expires: 0",
            "ALL_BINDINGS",
            "SOLE",
            None,
            True,
        ),
        (
            "wildcard-mixed-one-line",
            ["Contact: *, <sip:alice@device.example>"],
            "Expires: 0",
            "NONE",
            "MIXED",
            "WILDCARD_WITH_ADDITIONAL_CONTACT",
            False,
        ),
        (
            "wildcard-mixed-separate-fields",
            ["Contact: *", "Contact: <sip:alice@device.example>"],
            "Expires: 0",
            "NONE",
            "MIXED",
            "WILDCARD_WITH_ADDITIONAL_CONTACT",
            False,
        ),
        (
            "duplicate-wildcard-fields",
            ["Contact: *", "Contact: *"],
            "Expires: 0",
            "NONE",
            "DUPLICATE",
            "WILDCARD_DUPLICATE_CONTACT",
            False,
        ),
        (
            "duplicate-wildcard-values",
            ["Contact: *, *"],
            "Expires: 0",
            "NONE",
            "DUPLICATE",
            "WILDCARD_DUPLICATE_CONTACT",
            False,
        ),
        (
            "wildcard-nonzero-expires",
            ["Contact: *"],
            "Expires: 3600",
            "NONE",
            "SOLE",
            "WILDCARD_WITH_NONZERO_EXPIRES",
            False,
        ),
        (
            "wildcard-without-expires",
            ["Contact: *"],
            None,
            "NONE",
            "SOLE",
            "WILDCARD_WITHOUT_EXPIRES",
            False,
        ),
        (
            "wildcard-malformed-expires",
            ["Contact: *"],
            "Expires: abc",
            "NONE",
            "SOLE",
            "EXPIRES_MALFORMED",
            False,
        ),
        (
            "wildcard-malformed-token",
            ["Contact: *;expires=abc"],
            "Expires: 0",
            "NONE",
            "MALFORMED",
            "WILDCARD_WITH_MALFORMED_EXPIRES",
            False,
        ),
        (
            "wildcard-then-ordinary",
            ["Contact: *", "Contact: <sip:other@device.example>"],
            "Expires: 0",
            "NONE",
            "MIXED",
            "WILDCARD_WITH_ADDITIONAL_CONTACT",
            False,
        ),
        (
            "ordinary-single-zero",
            ["Contact: <sip:alice@device.example>"],
            "Expires: 0",
            "CONTACT_SCOPED",
            "NONE",
            None,
            True,
        ),
        (
            "ordinary-multiple-default-zero",
            ["Contact: <sip:a@device.example>, <sip:b@device.example>"],
            "Expires: 0",
            "CONTACT_SCOPED",
            "NONE",
            None,
            True,
        ),
        (
            "ordinary-multiple-mixed",
            ["Contact: <sip:a@device.example>;expires=0, <sip:b@device.example>;expires=3600"],
            None,
            "CONTACT_SCOPED",
            "NONE",
            None,
            True,
        ),
        (
            "bracketed-uri-comma",
            ["Contact: <sip:alice,smith@device.example>;expires=0"],
            "Expires: 0",
            "CONTACT_SCOPED",
            "NONE",
            None,
            True,
        ),
        (
            "unbracketed-uri-comma",
            ["Contact: sip:alice,smith@device.example;expires=0"],
            None,
            "NONE",
            "UNRESOLVED",
            "CONTACT_BOUNDARY_UNRESOLVED",
            False,
        ),
        (
            "repeated-ordinary-fields",
            [
                "Contact: <sip:a@device.example>;expires=0",
                "Contact: <sip:a@device.example>;expires=0",
            ],
            None,
            "CONTACT_SCOPED",
            "NONE",
            None,
            True,
        ),
        (
            "truncated-contact",
            ["Contact: <sip:alice@device.example;expires=0"],
            None,
            "NONE",
            "UNRESOLVED",
            "CONTACT_BOUNDARY_UNRESOLVED",
            False,
        ),
    )

    def test_raw_contact_cases_through_producer_and_domain(self) -> None:
        sip_schema = json.loads(SIP_SCHEMA.read_text(encoding="utf-8"))
        for name, contacts, expires, scope, wildcard_boundary, invalidity, accepted in self.CASES:
            with self.subTest(case=name):
                pdml = _pdml_document(
                    _pdml_request_packet(1, contact_lines=contacts, expires_line=expires),
                    _pdml_response_packet(2),
                )
                records = sip_model.parse_pdml_messages(pdml)
                event = records[0]["event"]
                self.assertEqual(event["frame_number"], 1)
                entries = event["headers"]["contact_entries"]
                self.assertEqual(entries["wildcard_boundary"], wildcard_boundary)
                if wildcard_boundary == "UNRESOLVED":
                    self.assertEqual(entries["boundary_status"], "UNRESOLVED")
                if jsonschema is not None:
                    jsonschema.validate(event, sip_schema)

                directory = Path(tempfile.mkdtemp())
                source = directory / "raw-case.pdml"
                source.write_text(pdml, encoding="utf-8")
                output = directory / "analysis.json"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPTS / "analyze-ims-registration.py"),
                        "--sip-input",
                        str(source),
                        "--input-format",
                        "pdml",
                        "--output",
                        str(output),
                        "--force",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                document = json.loads(output.read_text(encoding="utf-8"))
                attempt = document["registration_attempts"][0]
                deregistration = attempt["deregistration"]
                observations = deregistration["transaction_observations"]
                self.assertEqual(len(observations), 1)
                observation = observations[0]
                self.assertEqual(observation["scope"], scope)
                self.assertEqual(
                    observation["valid_all_bindings_request"],
                    scope == "ALL_BINDINGS",
                )
                if invalidity is None:
                    self.assertEqual(observation["invalidity"], [])
                else:
                    self.assertIn(invalidity, observation["invalidity"])
                if accepted:
                    self.assertEqual(
                        observation["outcome"], "DEREGISTRATION_ACCEPTED_BY_SIP"
                    )
                    self.assertEqual(
                        deregistration["outcome"], "DEREGISTRATION_ACCEPTED_BY_SIP"
                    )
                else:
                    self.assertNotEqual(
                        observation["outcome"], "DEREGISTRATION_ACCEPTED_BY_SIP"
                    )
                    self.assertFalse(deregistration["valid_all_bindings_request"])


class NegativeOutcomes(unittest.TestCase):
    def test_negative_statuses_are_observed(self) -> None:
        for status, reason in (
            (403, "Forbidden"),
            (404, "Not Found"),
            (408, "Request Timeout"),
            (423, "Interval Too Brief"),
            (500, "Server Internal Error"),
            (503, "Service Unavailable"),
        ):
            with self.subTest(status=status):
                document, _ = run(
                    [rec(1, method="REGISTER"), rec(2, status=status, cseq_method="REGISTER", to_tag="T", outbound=False, reason=reason)]
                )
                self.assertEqual(attempt(document)["sip_outcome"], "NEGATIVE_RESPONSE_OBSERVED")

    def test_423_min_expires_and_retry(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER", cseq=1),
                rec(2, status=423, cseq=1, cseq_method="REGISTER", to_tag="T1", outbound=False, reason="Interval Too Brief", min_expires=120),
                rec(3, method="REGISTER", branch="z9hG4bK-B", cseq=2, expires=120),
                rec(4, status=200, branch="z9hG4bK-B", cseq=2, cseq_method="REGISTER", to_tag="T2", outbound=False),
            ]
        )
        self.assertEqual(len(document["registration_attempts"]), 1)
        self.assertEqual(attempt(document)["min_expires_evidence"], {"present": True, "seconds": 120})
        self.assertEqual(attempt(document)["sip_outcome"], "SUCCESS_RESPONSE_OBSERVED")

    def test_unknown_final_status_is_not_rejected(self) -> None:
        document, _ = run([rec(1, method="REGISTER"), rec(2, status=599, cseq_method="REGISTER", to_tag="T", outbound=False)])
        self.assertEqual(attempt(document)["sip_outcome"], "NEGATIVE_RESPONSE_OBSERVED")

    def test_missing_response_is_not_a_timeout(self) -> None:
        document, _ = run([rec(1, method="REGISTER")])
        self.assertEqual(attempt(document)["sip_outcome"], "OPEN_IN_CAPTURE")
        self.assertNotIn("timeout_inferred", json.dumps(document).lower())


class DiameterEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = run_fixture(diameter=True)

    def test_diameter_inventory_and_commands(self) -> None:
        self.assertEqual(len(self.document["diameter_ims_inventory"]), 11)
        commands = {item["command_code"] for item in self.document["diameter_ims_inventory"]}
        self.assertEqual(commands, {300, 301, 302, 303, 304, 305})

    def test_open_response_only_and_ambiguous_are_retained(self) -> None:
        statuses = {item["transaction_status"] for item in self.document["diameter_ims_inventory"]}
        self.assertEqual(statuses, {"MATCHED", "OPEN_REQUEST", "AMBIGUOUS", "RESPONSE_ONLY"})

    def test_experimental_results_are_retained(self) -> None:
        codes = {
            item["experimental_result_code"]
            for item in self.document["diameter_ims_inventory"]
            if item["experimental_result_code"] is not None
        }
        self.assertTrue({2001, 2002, 5010}.issubset(codes))

    def test_unassigned_and_wrong_vendor_are_unresolved(self) -> None:
        by_code = {item["experimental_result_code"]: item for item in self.document["diameter_ims_inventory"]}
        self.assertEqual(by_code[5010]["application_result"], "UNRESOLVED")
        self.assertEqual(by_code[2002]["application_result"], "UNRESOLVED")

    def test_negative_cx_result_is_retained(self) -> None:
        failures = [
            item for item in self.document["diameter_ims_inventory"] if item["application_result"] == "FAILURE_REPORTED"
        ]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["result_namespace"], "BASE_RFC6733")

    def test_diameter_success_does_not_prove_sip_outcome(self) -> None:
        self.assertTrue(any("not proof of the SIP registration outcome" in item for item in self.document["not_confirmed"]))

    def test_diameter_is_optional(self) -> None:
        document = run_fixture(diameter=False)
        self.assertEqual(document["diameter_ims_inventory"], [])
        self.assertEqual(document["input_provenance"]["diameter_status"], "NOT_SUPPLIED")

    def test_missing_diameter_is_not_a_failure(self) -> None:
        document = run_fixture(diameter=False)
        self.assertEqual(document["capability"]["capability_status"], "IMS_REGISTRATION_DOMAIN_IMPLEMENTED")


class CrossProtocolEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = run_fixture(diameter=True)

    def test_no_established_association(self) -> None:
        statuses = {item["association_status"] for item in self.document["cross_protocol_associations"]}
        self.assertEqual(statuses, {"NOT_ESTABLISHED"})

    def test_no_fabricated_identity_bridge(self) -> None:
        for item in self.document["cross_protocol_associations"]:
            self.assertIn("SUBSCRIBER_IDENTITY_BRIDGE_UNAVAILABLE", item["missing_evidence"])
            self.assertIn("no_privacy_safe_subscriber_identity_bridge", item["association_basis"])

    def test_nearby_frames_do_not_create_association(self) -> None:
        self.assertFalse(self.document["input_provenance"]["common_capture_verified"])

    def test_identical_filename_is_not_proof(self) -> None:
        text = json.dumps(self.document)
        self.assertNotIn('"association_status": "ESTABLISHED"', text)
        self.assertNotIn('"association_status": "SUPPORTED"', text)

    def test_same_success_statuses_are_not_joined(self) -> None:
        successes = [
            item for item in self.document["cross_protocol_associations"]
            if item["association_status"] == "NOT_ESTABLISHED"
        ]
        self.assertTrue(successes)

    def test_different_capture_identity(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER"), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)],
            diameter=DIAMETER_FIXTURE,
        )
        for item in document["cross_protocol_associations"]:
            self.assertIn("COMMON_CAPTURE_NOT_VERIFIED", item["missing_evidence"])

    def test_invalid_diameter_artifact_is_not_absence(self) -> None:
        directory = Path(tempfile.mkdtemp())
        invalid = directory / "invalid.json"
        invalid.write_text('{"analysis_name": "other"}', encoding="utf-8")
        source = directory / "sip.jsonl"
        source.write_text(json.dumps(rec(1, method="REGISTER")) + "\n", encoding="utf-8")
        output = directory / "out.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "analyze-ims-registration.py"),
                "--sip-input",
                str(source),
                "--diameter-ims",
                str(invalid),
                "--output",
                str(output),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertFalse(output.exists())


class MultiHopAndIncomplete(unittest.TestCase):
    def test_multi_hop_candidate_is_not_a_new_attempt(self) -> None:
        document = run_fixture()
        candidates = [item for item in document["registration_attempts"] if item["multi_hop_candidate"]]
        self.assertEqual(len(candidates), 1)
        self.assertGreaterEqual(len(candidates[0]["transaction_references"]), 2)

    def test_proxy_role_is_unproved(self) -> None:
        document = run_fixture()
        candidate = [item for item in document["registration_attempts"] if item["multi_hop_candidate"]][0]
        self.assertTrue(any("not proved" in item for item in candidate["limitations"]))

    def test_capture_begins_after_challenge(self) -> None:
        document, _ = run([rec(1, method="REGISTER", auth=1), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)])
        self.assertEqual(attempt(document)["authentication_evidence_status"], "RETRY_WITHOUT_OBSERVED_CHALLENGE")

    def test_capture_ends_before_final_response(self) -> None:
        document, _ = run([rec(1, method="REGISTER")])
        self.assertEqual(attempt(document)["sip_outcome"], "OPEN_IN_CAPTURE")

    def test_truncated_message_is_retained(self) -> None:
        document, _ = run([rec(1, method="REGISTER", truncated=True)])
        self.assertEqual(len(document["registration_attempts"]), 1)

    def test_unsupported_encrypted_traffic_is_not_fabricated(self) -> None:
        document, _ = run([rec(1, method="REGISTER")])
        self.assertNotIn("RTP", json.dumps(document["registration_attempts"][0]["sip_outcome"]))


class IntegrityAndPrivacy(unittest.TestCase):
    def test_actual_output_passes_strict_schema(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        document = run_fixture(diameter=True)
        jsonschema.validate(document, json.loads(SCHEMA.read_text(encoding="utf-8")))

    def test_invalid_source_reference_is_rejected(self) -> None:
        document = run_fixture()
        document["registration_attempts"][0]["request_event_references"].append("sip-event:missing:1.1")
        with self.assertRaises(ims_registration_model.InputError):
            ims_registration_model.validate_analysis(
                document,
                sip_event_references={"sip-event:synthetic-ims-registration.pcapng:1.1"},
            )

    def test_invalid_transaction_reference_is_rejected(self) -> None:
        document = run_fixture()
        document["registration_attempts"][0]["transaction_references"] = ["invalid"]
        with self.assertRaises(ims_registration_model.InputError):
            ims_registration_model.validate_analysis(document)

    def test_duplicate_attempt_reference_is_rejected(self) -> None:
        document = run_fixture()
        document["registration_attempts"][1]["attempt_reference"] = document["registration_attempts"][0][
            "attempt_reference"
        ]
        with self.assertRaises(ims_registration_model.InputError):
            ims_registration_model.validate_analysis(document)

    def test_bounded_inventory_accounting(self) -> None:
        document = run_fixture()
        completeness = document["completeness"]
        self.assertEqual(completeness["attempt_count"], len(document["registration_attempts"]))
        self.assertEqual(completeness["association_count"], len(document["cross_protocol_associations"]))
        self.assertEqual(completeness["timeline_row_count"], len(document["timeline"]["rows"]))

    def test_deterministic_replay(self) -> None:
        records = [
            rec(1, method="REGISTER"),
            rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
        ]
        first, _ = run(records)
        second, _ = run(records)
        self.assertEqual(first, second)

    def test_no_sensitive_identity_leakage(self) -> None:
        document, artifacts = run(
            [
                rec(1, method="REGISTER", call_id="PRIVATE-CALL-ID", from_tag="PRIVATE-FROM-TAG", from_uri="sip:private-user@example.com", request_uri="sip:private-user@example.com"),
                rec(2, status=200, call_id="PRIVATE-CALL-ID", from_tag="PRIVATE-FROM-TAG", from_uri="sip:private-user@example.com", request_uri="sip:private-user@example.com", cseq_method="REGISTER", to_tag="PRIVATE-TO-TAG", outbound=False),
            ]
        )
        combined = json.dumps(document) + artifacts["stdout"] + artifacts["stderr"] + artifacts["report"]
        for secret in ("PRIVATE-CALL-ID", "PRIVATE-FROM-TAG", "PRIVATE-TO-TAG", "private-user"):
            self.assertNotIn(secret, combined)
        for field in ('"call_id"', '"from_tag"', '"to_tag"', '"request_uri"'):
            self.assertNotIn(field, combined)

    def test_no_ims_session_or_rtp_verdict(self) -> None:
        document = run_fixture(diameter=True)
        capability = document["capability"]
        self.assertIn("IMS_SESSION_DOMAIN", capability["not_implemented"])
        text = json.dumps(document)
        for token in ("call_success", "rtp_delivered", "session_established"):
            self.assertNotIn(token, text)

    def test_no_sensitive_values_in_errors(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = directory / "bad.jsonl"
        source.write_text(
            '{"capture_file":"x","frame_number":1,"transport":{},"headers":{"call_id":"PRIVATE-CALL-ID"}}\n',
            encoding="utf-8",
        )
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "analyze-ims-registration.py"),
                "--sip-input",
                str(source),
                "--output",
                str(directory / "out.json"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        combined = completed.stdout + completed.stderr
        self.assertNotIn("PRIVATE-CALL-ID", combined)
        self.assertNotIn("sip:", combined)


class ExistingTransactionPreservation(unittest.TestCase):
    def test_register_inventory_uses_accepted_transactions(self) -> None:
        document = run_fixture()
        inventory = document["sip_registration_inventory"]
        self.assertTrue(all(item["transaction_method"] == "REGISTER" for item in inventory))
        self.assertTrue(all(item["transaction_reference"].startswith("sip-transaction:") for item in inventory))

    def test_no_duplicate_transaction_across_attempts(self) -> None:
        document = run_fixture()
        assigned = []
        for item in document["registration_attempts"]:
            assigned.extend(item["transaction_references"])
        self.assertEqual(len(assigned), len(set(assigned)))


class TimelineOrderingTests(unittest.TestCase):
    def test_sip_only_single_capture(self) -> None:
        document, _ = run([rec(1, method="REGISTER"), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)])
        timeline = document["timeline"]
        self.assertTrue(timeline["global_order_proven"])
        self.assertEqual(timeline["ordering_scope"], "SIP_ONLY_SINGLE_CAPTURE")
        self.assertEqual(timeline["ordering_basis"], "SINGLE_CAPTURE_FRAME_ORDER")

    def test_sip_and_diameter_from_different_captures(self) -> None:
        document = run_fixture(diameter=True)
        timeline = document["timeline"]
        self.assertFalse(timeline["global_order_proven"])
        self.assertEqual(timeline["ordering_scope"], "CROSS_SOURCE_UNVERIFIED")
        self.assertEqual(timeline["ordering_basis"], "SOURCE_LOCAL_ONLY")
        self.assertGreater(timeline["sip_row_count"], 0)
        self.assertGreater(timeline["diameter_row_count"], 0)

    def test_identical_filename_is_not_verified_common_capture(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER")],
            diameter=_write_diameter(_diameter_document(1, capture="sip-ims.pcapng")),
        )
        self.assertFalse(document["timeline"]["global_order_proven"])
        self.assertEqual(
            document["timeline"]["ordering_scope"], "CROSS_SOURCE_UNVERIFIED"
        )

    def test_matching_frame_numbers_do_not_prove_common_capture(self) -> None:
        document = run_fixture(diameter=True)
        frame_overlap = {
            row["frame_number"]
            for row in document["timeline"]["rows"]
            if row["event_kind"].startswith("SIP_")
        } & {
            row["frame_number"]
            for row in document["timeline"]["rows"]
            if not row["event_kind"].startswith("SIP_")
        }
        self.assertFalse(document["timeline"]["global_order_proven"])
        self.assertTrue(frame_overlap)

    def test_overlapping_timestamps_do_not_prove_common_capture(self) -> None:
        document = run_fixture(diameter=True)
        self.assertFalse(document["input_provenance"]["common_capture_verified"])
        self.assertFalse(document["timeline"]["global_order_proven"])

    def test_missing_capture_identity_is_not_proof(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER")],
            diameter=_write_diameter(_diameter_document(1, capture=None)),
        )
        self.assertFalse(document["timeline"]["global_order_proven"])

    def test_source_local_order_is_preserved(self) -> None:
        document = run_fixture(diameter=True)
        rows = document["timeline"]["rows"]
        keys = [(row["capture_identity"], row["frame_number"]) for row in rows]
        self.assertEqual(keys, sorted(keys))

    def test_no_invented_cross_protocol_causality(self) -> None:
        document = run_fixture(diameter=True)
        for row in document["timeline"]["rows"]:
            if row["event_kind"].startswith("UNASSOCIATED_DIAMETER"):
                self.assertIsNone(row["attempt_reference"])

    def test_global_order_does_not_create_association(self) -> None:
        document = run_fixture(diameter=True)
        self.assertFalse(document["timeline"]["global_order_proven"])
        self.assertEqual(
            {item["association_status"] for item in document["cross_protocol_associations"]},
            {"NOT_ESTABLISHED"},
        )


class CliCollisionTests(unittest.TestCase):
    def _run(self, *arguments: object) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "analyze-ims-registration.py"), *map(str, arguments)],
            capture_output=True,
            text=True,
            check=False,
        )

    def _source(self, directory: Path) -> Path:
        import shutil

        source = directory / "source.jsonl"
        shutil.copyfile(
            SKILL / "examples" / "input" / "registration-cases.jsonl", source
        )
        return source

    def test_json_output_equals_sip_input(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        before = source.read_bytes()
        completed = self._run("--sip-input", source, "--output", source, "--force")
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(source.read_bytes(), before)

    def test_json_output_equals_diameter_input(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        diameter = directory / "diameter.json"
        diameter.write_bytes(DIAMETER_FIXTURE.read_bytes())
        before = diameter.read_bytes()
        completed = self._run(
            "--sip-input", source, "--diameter-ims", diameter, "--output", diameter, "--force"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(diameter.read_bytes(), before)

    def test_report_equals_sip_input(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        completed = self._run(
            "--sip-input", source, "--output", directory / "out.json", "--report", source, "--force"
        )
        self.assertNotEqual(completed.returncode, 0)

    def test_report_equals_diameter_input(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        diameter = directory / "diameter.json"
        diameter.write_bytes(DIAMETER_FIXTURE.read_bytes())
        completed = self._run(
            "--sip-input", source, "--diameter-ims", diameter,
            "--output", directory / "out.json", "--report", diameter, "--force"
        )
        self.assertNotEqual(completed.returncode, 0)

    def test_json_and_report_same_nonexistent_file(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        target = directory / "same.json"
        completed = self._run(
            "--sip-input", source, "--output", target, "--report", target, "--force"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(target.exists())

    def test_json_and_report_same_existing_file(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        target = directory / "same.json"
        target.write_text("existing", encoding="utf-8")
        completed = self._run(
            "--sip-input", source, "--output", target, "--report", target, "--force"
        )
        self.assertNotEqual(completed.returncode, 0)

    def test_relative_and_absolute_aliases(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        relative = Path(os.path.relpath(source, Path.cwd()))
        completed = self._run("--sip-input", source, "--output", relative, "--force")
        self.assertNotEqual(completed.returncode, 0)

    def test_symlink_alias_is_rejected(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        alias = directory / "alias.jsonl"
        alias.symlink_to(source)
        completed = self._run("--sip-input", source, "--output", alias, "--force")
        self.assertNotEqual(completed.returncode, 0)

    def test_force_does_not_override_input_protection(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        completed = self._run("--sip-input", source, "--output", source, "--force")
        self.assertNotEqual(completed.returncode, 0)

    def test_existing_safe_output_without_force_fails(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        target = directory / "out.json"
        target.write_text("existing", encoding="utf-8")
        completed = self._run("--sip-input", source, "--output", target)
        self.assertNotEqual(completed.returncode, 0)

    def test_existing_safe_output_with_force_succeeds(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        target = directory / "out.json"
        target.write_text("existing", encoding="utf-8")
        completed = self._run("--sip-input", source, "--output", target, "--force")
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_separate_safe_destinations_succeed(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        completed = self._run(
            "--sip-input", source,
            "--output", directory / "out.json",
            "--report", directory / "report.txt",
            "--force",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_failed_preflight_leaves_inputs_unchanged(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        before = source.read_bytes()
        self._run("--sip-input", source, "--output", source, "--report", source, "--force")
        self.assertEqual(source.read_bytes(), before)

    def test_failure_does_not_claim_publication(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = self._source(directory)
        completed = self._run("--sip-input", source, "--output", source, "--force")
        self.assertNotIn("wrote", completed.stdout)

    def test_no_sensitive_path_or_payload_in_diagnostics(self) -> None:
        directory = Path(tempfile.mkdtemp())
        source = directory / "PRIVATE-SIP-INPUT.jsonl"
        source.write_bytes((SKILL / "examples" / "input" / "registration-cases.jsonl").read_bytes())
        completed = self._run("--sip-input", source, "--output", source, "--force")
        self.assertNotIn("PRIVATE-SIP-INPUT", completed.stderr)
        self.assertNotIn("call_id", completed.stderr)


class BoundedAccountingTests(unittest.TestCase):
    def test_zero_register_items(self) -> None:
        document, _ = run([rec(1, method="OPTIONS")])
        self.assertEqual(document["sip_registration_inventory"], [])
        self.assertEqual(document["registration_attempts"], [])
        self.assertEqual(document["completeness"]["attempt_count"], 0)

    def test_attempt_boundary_conservation(self) -> None:
        for count in (255, 256, 257):
            with self.subTest(count=count):
                records = [
                    rec(
                        index * 2 + 1,
                        method="REGISTER",
                        call_id=f"CALL-{index}",
                        branch=f"z9hG4bK-{index}",
                    )
                    for index in range(count)
                ]
                document, _ = run(records)
                completeness = document["completeness"]
                self.assertEqual(completeness["attempt_count"], count)
                self.assertEqual(len(document["registration_attempts"]), min(count, 256))
                self.assertEqual(
                    completeness["attempt_count"],
                    len(document["registration_attempts"])
                    + completeness["attempts_omitted"],
                )

    def test_diameter_observation_conservation(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER")],
            diameter=_write_diameter(_diameter_document(300)),
        )
        completeness = document["completeness"]
        self.assertEqual(completeness["diameter_observation_count"], 300)
        self.assertEqual(len(document["diameter_ims_inventory"]), 256)
        self.assertEqual(completeness["diameter_observations_omitted"], 44)
        self.assertEqual(
            completeness["association_count"],
            len(document["cross_protocol_associations"])
            + completeness["associations_omitted"],
        )

    def test_timeline_above_limit_conserves_rows(self) -> None:
        records = []
        for index in range(256):
            call_id = f"CALL-{index}"
            branch = f"z9hG4bK-{index}"
            records.append(rec(index * 4 + 1, method="REGISTER", call_id=call_id, branch=branch))
            if index == 0:
                records.append(rec(index * 4 + 2, method="REGISTER", call_id=call_id, branch=branch + "-HOP"))
            records.append(
                rec(
                    index * 4 + 3,
                    status=200,
                    call_id=call_id,
                    branch=branch,
                    cseq_method="REGISTER",
                    to_tag="T",
                    outbound=False,
                )
            )
        document, _ = run(records)
        timeline = document["timeline"]
        self.assertGreater(timeline["row_count"], 512)
        self.assertEqual(
            timeline["row_count"], len(timeline["rows"]) + timeline["rows_omitted"]
        )
        self.assertEqual(timeline["sip_row_count"] + timeline["diameter_row_count"], timeline["row_count"])
        self.assertEqual(timeline["sip_row_count"], timeline["row_count"])

    def test_request_reference_omission_is_counted(self) -> None:
        records = [
            rec(index + 1, method="REGISTER", branch="z9hG4bK-REF", call_id="CALL-REF")
            for index in range(70)
        ]
        records.append(
            rec(100, status=200, branch="z9hG4bK-REF", call_id="CALL-REF", cseq_method="REGISTER", to_tag="T", outbound=False)
        )
        document, _ = run(records)
        item = attempt(document)
        self.assertEqual(len(item["request_event_references"]), 64)
        self.assertGreaterEqual(item["omitted_request_event_count"], 6)

    def test_response_reference_omission_is_counted(self) -> None:
        records = [rec(1, method="REGISTER", branch="z9hG4bK-RESP", call_id="CALL-RESP")]
        records.extend(
            rec(
                index + 2,
                status=200,
                branch="z9hG4bK-RESP",
                call_id="CALL-RESP",
                cseq_method="REGISTER",
                to_tag="T",
                outbound=False,
            )
            for index in range(70)
        )
        document, _ = run(records)
        item = attempt(document)
        self.assertEqual(len(item["response_event_references"]), 64)
        self.assertGreaterEqual(item["omitted_response_event_count"], 6)

    def test_duplicate_source_references_do_not_inflate_counts(self) -> None:
        document, _ = run(
            [
                rec(1, method="REGISTER"),
                rec(2, method="REGISTER"),
                rec(3, status=200, cseq_method="REGISTER", to_tag="T", outbound=False),
            ]
        )
        item = attempt(document)
        self.assertEqual(len(item["request_event_references"]), len(set(item["request_event_references"])))
        self.assertEqual(len(item["transaction_references"]), 1)

    def test_bounded_output_passes_schema_and_semantics(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        records = [
            rec(index * 2 + 1, method="REGISTER", call_id=f"CALL-{index}", branch=f"z9hG4bK-{index}")
            for index in range(257)
        ]
        document, _ = run(records)
        jsonschema.validate(document, json.loads(SCHEMA.read_text(encoding="utf-8")))
        ims_registration_model.validate_analysis(document)
        attempts = {item["attempt_reference"] for item in document["registration_attempts"]}
        for association in document["cross_protocol_associations"]:
            self.assertIn(association["sip_attempt_reference"], attempts)
        for row in document["timeline"]["rows"]:
            if row["attempt_reference"] is not None:
                self.assertIn(row["attempt_reference"], attempts)

    def test_boundary_replay_is_deterministic(self) -> None:
        records = [
            rec(index * 2 + 1, method="REGISTER", call_id=f"CALL-{index}", branch=f"z9hG4bK-{index}")
            for index in range(256)
        ]
        first, _ = run(records)
        second, _ = run(records)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()