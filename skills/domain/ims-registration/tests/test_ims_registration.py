#!/usr/bin/env python3
"""IMS registration Domain evidence tests."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
DOMAIN = SKILL.parents[1]
SCRIPTS = SKILL / "scripts"
SIP_SCRIPTS = SKILL.parents[1] / "protocol" / "sip" / "scripts"
SCHEMA = SKILL / "schemas" / "ims-registration-analysis.schema.json"
DIAMETER_FIXTURE = SKILL / "examples" / "input" / "diameter-ims-cases.json"
for path in (SCRIPTS, SIP_SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import ims_registration_model  # noqa: E402

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
    contact_wildcard: bool = False,
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
        "contact_count": 0,
        "contact_wildcard": contact_wildcard,
    }
    for key, value in (
        ("expires_seconds", expires),
        ("contact_expires_seconds", contact_expires),
        ("min_expires_seconds", min_expires),
    ):
        if value is not None:
            headers[key] = value
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

    def test_expires_zero_is_deregistration(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", expires=0), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        self.assertEqual(attempt(document)["registration_type"], "DEREGISTRATION_REQUESTED")
        self.assertTrue(attempt(document)["deregistration"]["accepted_by_sip"])

    def test_contact_specific_expiration(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", contact_expires=0), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        self.assertTrue(attempt(document)["deregistration"]["request_observed"])

    def test_wildcard_contact_deregistration(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", contact_wildcard=True), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        self.assertTrue(attempt(document)["deregistration"]["contact_wildcard"])

    def test_missing_expiration_evidence(self) -> None:
        document, _ = run([rec(1, method="REGISTER")])
        self.assertIn("EXPIRATION_NOT_OBSERVED", attempt(document)["missing_evidence"])

    def test_deregistration_with_200(self) -> None:
        document, _ = run(
            [rec(1, method="REGISTER", expires=0), rec(2, status=200, cseq_method="REGISTER", to_tag="T", outbound=False)]
        )
        self.assertEqual(attempt(document)["deregistration"]["outcome"], "DEREGISTRATION_ACCEPTED_BY_SIP")

    def test_deregistration_without_final_response(self) -> None:
        document, _ = run([rec(1, method="REGISTER", expires=0)])
        self.assertEqual(attempt(document)["deregistration"]["outcome"], "DEREGISTRATION_OUTCOME_UNPROVED")


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


if __name__ == "__main__":
    unittest.main()