#!/usr/bin/env python3
"""Package-local test suite for the bounded nas-5gs Protocol Skill.

Tests never require tshark and never assert a mandatory Registration
message order; they verify message-local semantics, security-envelope
handling, privacy defaults, and deterministic bounded extraction.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
sys.path.insert(0, str(SCRIPTS))

import nas5gs_model as MODEL


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


EXTRACT = load_script("extract-nas5gs")
TIMELINE = load_script("nas5gs_timeline")

EXTRACTED = PACKAGE / "examples" / "extracted"
EXPECTED = PACKAGE / "examples" / "expected"

# Fixtures that produce deterministic expected output (error fixtures excluded).
FIXTURE_NAMES = (
    "registration-flow",
    "rejection-flow",
    "service-flow",
    "protection-variants",
    "deferred-unknown",
    "mobility-types",
    "sm-establishment-request",
    "sm-establishment-accept",
    "sm-establishment-accept-multi-qfi",
    "sm-establishment-reject",
    "sm-modification",
    "sm-release",
    "sm-status",
    "sm-recognition",
    "sm-session-identity",
    "sm-protection",
)


def events_of(name: str, include_sensitive: bool = False) -> list[dict]:
    return [
        MODEL.normalize_record(record, name, include_sensitive=include_sensitive)
        for record in MODEL.read_jsonl(EXTRACTED / name)
    ]


class MessageIdentityTests(unittest.TestCase):
    def test_supported_message_mapping(self):
        identity = MODEL.resolve_message(65, None)
        self.assertEqual(identity.nas_family, "5GMM")
        self.assertEqual(identity.message_type, "Registration request")
        self.assertEqual(identity.support_status, "SUPPORTED")
        self.assertEqual(identity.direction, "ue-to-amf")
        self.assertEqual(identity.direction_basis, "message-definition")
        self.assertEqual(identity.result, "REQUEST")
        self.assertEqual(identity.procedure_family, "REGISTRATION")

    def test_directions_follow_reviewed_definitions(self):
        self.assertEqual(MODEL.resolve_message(91, None).direction, "amf-to-ue")
        self.assertEqual(MODEL.resolve_message(92, None).direction, "ue-to-amf")
        self.assertEqual(MODEL.resolve_message(93, None).direction, "amf-to-ue")
        self.assertEqual(MODEL.resolve_message(94, None).direction, "ue-to-amf")
        self.assertIsNone(MODEL.resolve_message(100, None).direction)

    def test_unknown_message_type_stays_unknown(self):
        identity = MODEL.resolve_message(150, None)
        self.assertEqual(identity.support_status, "UNKNOWN")
        self.assertIsNone(identity.message_type)
        self.assertIsNone(identity.direction)
        self.assertEqual(identity.derivations, ("nas_family",))

    def test_known_unsupported_preserves_name_only(self):
        identity = MODEL.resolve_message(69, None)
        self.assertEqual(identity.support_status, "UNSUPPORTED")
        self.assertEqual(identity.message_type, "Deregistration request (UE originating)")
        self.assertIsNone(identity.direction)
        self.assertIsNone(identity.result)

    def test_supported_5gsm_message_mapping(self):
        identity = MODEL.resolve_message(None, 193)
        self.assertEqual(identity.nas_family, "5GSM")
        self.assertEqual(identity.support_status, "SUPPORTED")
        self.assertEqual(identity.message_type, "PDU session establishment request")
        self.assertEqual(identity.direction, "ue-to-smf")
        self.assertEqual(identity.direction_basis, "message-definition")
        self.assertEqual(identity.result, "REQUEST")
        self.assertEqual(identity.procedure_family, "PDU_SESSION_ESTABLISHMENT")

    def test_5gsm_directions_follow_reviewed_definitions(self):
        self.assertEqual(MODEL.resolve_message(None, 194).direction, "smf-to-ue")
        self.assertEqual(MODEL.resolve_message(None, 211).direction, "smf-to-ue")
        self.assertEqual(MODEL.resolve_message(None, 212).direction, "ue-to-smf")
        self.assertIsNone(MODEL.resolve_message(None, 214).direction)

    def test_both_message_types_is_ambiguous(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.resolve_message(65, 193)

    def test_missing_message_type_is_unknown(self):
        identity = MODEL.resolve_message(None, None)
        self.assertEqual(identity.support_status, "UNKNOWN")
        self.assertIsNone(identity.nas_family)


class SecurityEnvelopeTests(unittest.TestCase):
    def test_plain_header(self):
        security = MODEL.resolve_security_header(0)
        self.assertEqual(security["header_name"], "plain NAS message, not security protected")
        self.assertFalse(security["integrity_protected"])
        self.assertFalse(security["ciphered"])
        self.assertTrue(security["integrity_protected"] is False)

    def test_plain_message_inner_available(self):
        event = MODEL.normalize_record(
            {"frame.number": "9", "frame.time_epoch": "0", "nas-5gs.security_header_type": "0", "nas-5gs.mm.message_type": "100"},
            "x.jsonl",
        )
        self.assertTrue(event["security"]["inner_message_available"])
        self.assertEqual(event["security"]["decode_basis"], "plain-message")

    def test_protected_header_states(self):
        for code, ciphered, new_context in ((1, False, False), (2, True, False), (3, False, True), (4, True, True)):
            security = MODEL.resolve_security_header(code)
            self.assertTrue(security["integrity_protected"])
            self.assertEqual(security["ciphered"], ciphered)
            self.assertEqual(security["new_security_context"], new_context)
            self.assertTrue(security["integrity_protected"])
        self.assertTrue(MODEL.resolve_security_header(3)["new_security_context"])
        self.assertTrue(MODEL.resolve_security_header(4)["new_security_context"])

    def test_invalid_header_rejected(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.resolve_security_header(9)

    def test_ciphered_inner_unavailable_not_guessed(self):
        event = events_of("protection-variants.jsonl")[1]
        self.assertFalse(event["security"]["inner_message_available"])
        self.assertIsNone(event["security"]["decode_basis"])
        self.assertIsNone(event["message_type"])

    def test_dissector_decoded_inner_recorded(self):
        event = events_of("service-flow.jsonl")[0]
        self.assertTrue(event["security"]["inner_message_available"])
        self.assertEqual(event["security"]["decode_basis"], "dissector-decoded")

    def test_sequence_and_mac_and_index_preserved(self):
        event = events_of("service-flow.jsonl")[0]
        security = event["security"]
        self.assertEqual(security["sequence_number"], 37)
        self.assertTrue(security["message_authentication_code_present"])
        self.assertEqual(security["security_parameter_index"], 65501)
        self.assertNotIn("message_authentication_code_value", json.dumps(security))


class RegistrationSemanticsTests(unittest.TestCase):
    def test_registration_types_normalized(self):
        events = events_of("registration-flow.jsonl")
        self.assertEqual(events[0]["registration"], {"type_code": 1, "type_name": "initial registration", "follow_on_request": True})
        self.assertEqual(events[0]["ngksi"], {"key_set_id": 2})

    def test_mobility_and_periodic_updates(self):
        events = events_of("mobility-types.jsonl")
        self.assertEqual(events[0]["registration"]["type_name"], "mobility registration updating")
        self.assertEqual(events[1]["registration"]["type_name"], "periodic registration updating")
        self.assertFalse(events[0]["registration"]["follow_on_request"])

    def test_unknown_registration_type_stays_unknown(self):
        event = MODEL.normalize_record(
            {"frame.number": "5", "frame.time_epoch": "0", "nas-5gs.mm.message_type": "65", "nas-5gs.mm.5gs_reg_type": "9"},
            "x.jsonl",
        )
        self.assertEqual(event["registration"]["type_name"], "UNKNOWN")

    def test_registration_reject_preserves_cause(self):
        event = events_of("rejection-flow.jsonl")[0]
        self.assertEqual(event["message_type"], "Registration reject")
        self.assertEqual(event["result"], "REJECT")
        self.assertEqual(event["cause"], {"code": 22, "name": "Congestion", "family": "5GMM"})

    def test_unknown_cause_code_preserves_number(self):
        event = MODEL.normalize_record(
            {"frame.number": "6", "frame.time_epoch": "0", "nas-5gs.mm.message_type": "68", "nas-5gs.mm.5gmm_cause": "99"},
            "x.jsonl",
        )
        self.assertEqual(event["cause"], {"code": 99, "name": None, "family": "5GMM"})


class IdentityPrivacyTests(unittest.TestCase):
    def test_identity_presence_and_type_without_value(self):
        events = events_of("registration-flow.jsonl")
        self.assertEqual(events[0]["identity"], {"present": True, "type_code": 1, "type_name": "SUCI", "value": None})
        self.assertEqual(events[7]["identity"]["type_name"], "5G-GUTI")

    def test_identity_types_table(self):
        self.assertEqual(MODEL.IDENTITY_TYPES[1], "SUCI")
        self.assertEqual(MODEL.IDENTITY_TYPES[2], "5G-GUTI")
        self.assertEqual(MODEL.IDENTITY_TYPES[3], "IMEI")
        self.assertEqual(MODEL.IDENTITY_TYPES[4], "5G-S-TMSI")
        self.assertEqual(MODEL.IDENTITY_TYPES[5], "IMEISV")

    def test_imei_and_imeisv_presence_only(self):
        event = MODEL.normalize_record(
            {"frame.number": "7", "frame.time_epoch": "0", "nas-5gs.mm.message_type": "65", "nas-5gs.mm.imei": "490154203237518"},
            "x.jsonl",
        )
        self.assertTrue(event["identity"]["present"])
        self.assertIsNone(event["identity"]["type_code"])
        self.assertIsNone(event["identity"]["value"])
        self.assertNotIn("490154203237518", json.dumps(event))

    def test_sensitive_value_redacted_by_default(self):
        record = {
            "frame.number": "3",
            "frame.time_epoch": "0",
            "nas-5gs.mm.message_type": "92",
            "nas-5gs.mm.type_id": "1",
            "identity_value": "suci-0-001-01-0000-000000001",
        }
        default = MODEL.normalize_record(record, "x.jsonl")
        opt_in = MODEL.normalize_record(record, "x.jsonl", include_sensitive=True)
        self.assertIsNone(default["identity"]["value"])
        self.assertEqual(opt_in["identity"]["value"], "suci-0-001-01-0000-000000001")

    def test_suci_is_not_supi(self):
        self.assertNotIn("SUPI", json.dumps(MODEL.IDENTITY_TYPES))
        self.assertIn("SUCI", json.dumps(MODEL.IDENTITY_TYPES))


class AuthenticationSafetyTests(unittest.TestCase):
    def test_authentication_messages_recognized(self):
        events = events_of("registration-flow.jsonl")
        self.assertEqual(events[3]["message_type"], "Authentication request")
        self.assertEqual(events[4]["message_type"], "Authentication response")

    def test_parameter_presence_only(self):
        events = events_of("registration-flow.jsonl")
        self.assertEqual(events[3]["authentication"], {"rand_present": True, "autn_present": True, "res_present": None, "auts_present": None})
        self.assertEqual(events[4]["authentication"]["res_present"], True)

    def test_no_secret_material_emitted(self):
        for name in ("registration-flow.jsonl", "rejection-flow.jsonl", "service-flow.jsonl", "protection-variants.jsonl"):
            blob = json.dumps(events_of(name))
            for forbidden in ("rand_value", "autn_value", "res_value", "auts_value", "kseaf", "kamf", "knas"):
                self.assertNotIn(forbidden, blob)

    def test_authentication_failure_cause(self):
        event = events_of("rejection-flow.jsonl")[1]
        self.assertEqual(event["message_type"], "Authentication failure")
        self.assertEqual(event["cause"], {"code": 21, "name": "Synch failure", "family": "5GMM"})
        self.assertTrue(event["authentication"]["auts_present"])
        self.assertEqual(event["result"], "FAILURE")

    def test_no_key_derivation_constants_exist(self):
        model_text = (SCRIPTS / "nas5gs_model.py").read_text(encoding="utf-8")
        self.assertNotIn("KDF", model_text)
        self.assertNotIn("hmac", model_text.lower())


class SecurityModeTests(unittest.TestCase):
    def test_algorithm_mapping(self):
        events = events_of("registration-flow.jsonl")
        self.assertEqual(
            events[5]["security_mode"],
            {
                "ciphering_algorithm_code": 2,
                "ciphering_algorithm_name": "128-5G-EA2",
                "integrity_algorithm_code": 2,
                "integrity_algorithm_name": "128-5G-IA2",
            },
        )

    def test_algorithm_names_derived(self):
        event = events_of("registration-flow.jsonl")[5]
        self.assertIn("algorithm_names", event["derivations"])

    def test_security_mode_reject_cause(self):
        event = events_of("rejection-flow.jsonl")[2]
        self.assertEqual(event["message_type"], "Security mode reject")
        self.assertEqual(event["cause"], {"code": 23, "name": "UE security capabilities mismatch", "family": "5GMM"})

    def test_no_cryptographic_verification_claim(self):
        blob = json.dumps(events_of("registration-flow.jsonl"))
        self.assertNotIn("verified", blob.lower())
        self.assertNotIn("mac_valid", blob.lower())


class ServiceTests(unittest.TestCase):
    def test_service_request_type(self):
        events = events_of("service-flow.jsonl")
        self.assertEqual(events[0]["service"], {"type_code": 0, "type_name": "signalling"})
        self.assertEqual(events[0]["direction"], "ue-to-amf")

    def test_service_reject_cause(self):
        event = events_of("rejection-flow.jsonl")[3]
        self.assertEqual(event["message_type"], "Service reject")
        self.assertEqual(event["cause"], {"code": 22, "name": "Congestion", "family": "5GMM"})


class FamilyBoundaryTests(unittest.TestCase):
    def test_known_unsupported_5gsm_preserves_name_only(self):
        events = events_of("deferred-unknown.jsonl")
        event = events[0]
        self.assertEqual(event["nas_family"], "5GSM")
        self.assertEqual(event["support_status"], "UNSUPPORTED")
        self.assertEqual(event["message_type"], "PDU session authentication command")
        self.assertIsNone(event["result"])
        self.assertIsNone(event["procedure_family"])

    def test_unknown_5gsm_message_stays_unknown(self):
        events = events_of("deferred-unknown.jsonl")
        event = events[3]
        self.assertEqual(event["nas_family"], "5GSM")
        self.assertEqual(event["support_status"], "UNKNOWN")
        self.assertIsNone(event["message_type"])
        self.assertIsNone(event["result"])

    def test_projection_never_fabricates_seid_or_teid(self):
        for name in ("deferred-unknown.jsonl", "sm-establishment-accept.jsonl", "sm-establishment-request.jsonl"):
            for event in events_of(name):
                projected = MODEL.project_trace_event(event)
                self.assertNotIn("subscriber", projected)
                session = projected.get("session", {})
                for forbidden in ("seid", "teid", "apn", "bearer_id"):
                    self.assertNotIn(forbidden, session)

    def test_unknown_family_frame(self):
        event = events_of("protection-variants.jsonl")[1]
        self.assertEqual(event["support_status"], "UNKNOWN")
        self.assertIsNone(event["nas_family"])


class ProtocolDiscriminatorTests(unittest.TestCase):
    def test_5gmm_and_5gsm_discriminators_differ(self):
        mm = events_of("registration-flow.jsonl")[0]
        sm = events_of("sm-establishment-request.jsonl")[0]
        self.assertEqual(mm["protocol_discriminator"], 126)
        self.assertEqual(sm["protocol_discriminator"], 46)
        self.assertNotEqual(mm["protocol_discriminator"], sm["protocol_discriminator"])

    def test_observed_discriminator_preserved(self):
        event = MODEL.normalize_record(
            {"frame.number": "1", "frame.time_epoch": "0", "nas-5gs.epd": "46", "nas-5gs.sm.message_type": "193"},
            "x.jsonl",
        )
        self.assertEqual(event["protocol_discriminator"], 46)

    def test_conflicting_family_and_discriminator_fails_loudly(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.normalize_record(
                {"frame.number": "1", "frame.time_epoch": "0", "nas-5gs.epd": "126", "nas-5gs.sm.message_type": "193"},
                "x.jsonl",
            )


class SessionManagementTests(unittest.TestCase):
    def test_establishment_request_fields(self):
        event = events_of("sm-establishment-request.jsonl")[0]
        sm = event["session_management"]
        self.assertEqual(event["message_type"], "PDU session establishment request")
        self.assertEqual(sm["pdu_session_id"], 5)
        self.assertEqual(sm["pti"], 1)
        self.assertEqual(sm["request_type"], {"code": 1, "name": "initial request"})
        self.assertEqual(sm["pdu_session_type"], {"code": 3, "name": "IPv4v6"})
        self.assertEqual(sm["ssc_mode"], {"code": 1, "name": "SSC mode 1"})
        self.assertEqual(sm["dnn"], "internet")
        self.assertEqual(sm["snssai"], {"sst": 1, "sd": 1})

    def test_establishment_accept_fields(self):
        event = events_of("sm-establishment-accept.jsonl")[0]
        sm = event["session_management"]
        self.assertEqual(sm["pdu_address"], "192.0.2.10")
        self.assertEqual(sm["dnn"], "internet")
        self.assertTrue(sm["authorized_qos_rules"]["present"])
        self.assertEqual(sm["authorized_qos_rules"]["rule_ids"], [1])
        self.assertTrue(sm["qos_flow_descriptions"]["present"])
        self.assertEqual(sm["qos_flow_descriptions"]["qfi_values"], [1])
        self.assertEqual(sm["qos_flow_descriptions"]["five_qi_values"], [9])
        self.assertEqual(sm["always_on"]["indicated"], True)

    def test_establishment_reject_cause(self):
        event = events_of("sm-establishment-reject.jsonl")[0]
        self.assertEqual(event["message_type"], "PDU session establishment reject")
        self.assertEqual(event["result"], "REJECT")
        self.assertEqual(event["cause"], {"code": 27, "name": "Missing or unknown DNN", "family": "5GSM"})

    def test_modification_messages(self):
        events = events_of("sm-modification.jsonl")
        self.assertEqual([e["message_type"] for e in events], [
            "PDU session modification request",
            "PDU session modification reject",
            "PDU session modification command",
            "PDU session modification complete",
            "PDU session modification command reject",
        ])
        self.assertEqual(events[0]["procedure_family"], "PDU_SESSION_MODIFICATION")
        self.assertEqual(events[3]["direction"], "ue-to-smf")

    def test_release_messages(self):
        events = events_of("sm-release.jsonl")
        self.assertEqual([e["message_type"] for e in events], [
            "PDU session release request",
            "PDU session release reject",
            "PDU session release command",
            "PDU session release complete",
        ])
        self.assertEqual(events[2]["cause"]["name"], "Regular deactivation")

    def test_5gsm_status(self):
        event = events_of("sm-status.jsonl")[0]
        self.assertEqual(event["message_type"], "5GSM status")
        self.assertEqual(event["result"], "STATUS")
        self.assertEqual(event["procedure_family"], "SESSION_MANAGEMENT_STATUS")
        self.assertEqual(event["cause"]["name"], "Semantically incorrect message")

    def test_unknown_values_stay_explicit(self):
        events = events_of("sm-recognition.jsonl")
        reserved = events[2]["session_management"]
        self.assertEqual(reserved["pdu_session_type"], {"code": 6, "name": None})
        self.assertEqual(reserved["ssc_mode"], {"code": 5, "name": None})
        self.assertEqual(events[2]["cause"], {"code": 200, "name": None, "family": "5GSM"})

    def test_pdu_session_id_and_pti_are_distinct(self):
        sm = events_of("sm-establishment-request.jsonl")[0]["session_management"]
        self.assertEqual(sm["pdu_session_id"], 5)
        self.assertEqual(sm["pti"], 1)
        self.assertNotEqual(sm["pdu_session_id"], sm["pti"])

    def test_no_global_session_join(self):
        events = events_of("sm-session-identity.jsonl")
        self.assertEqual([e["session_management"]["pdu_session_id"] for e in events], [5, 6, 5])
        self.assertEqual(len({e["frame_number"] for e in events}), 3)

    def test_protected_inner_available_and_unavailable(self):
        events = events_of("sm-protection.jsonl")
        self.assertTrue(events[0]["security"]["inner_message_available"])
        self.assertEqual(events[0]["security"]["decode_basis"], "dissector-decoded")
        self.assertFalse(events[1]["security"]["inner_message_available"])
        self.assertIsNone(events[1]["message_type"])

    def test_malformed_session_metadata_fails_loudly(self):
        with self.assertRaises(MODEL.InputError):
            events_of("sm-malformed.jsonl")


class SessionProjectionTests(unittest.TestCase):
    def test_single_qfi_projected(self):
        projected = MODEL.project_trace_event(events_of("sm-establishment-accept.jsonl")[0])
        self.assertEqual(projected["session"], {"pdu_session_id": 5, "dnn": "internet", "qfi": 1})

    def test_multiple_qfi_omits_qfi(self):
        event = events_of("sm-establishment-accept-multi-qfi.jsonl")[0]
        self.assertEqual(event["session_management"]["qos_flow_descriptions"]["qfi_values"], [1, 2, 3])
        projected = MODEL.project_trace_event(event)
        self.assertEqual(projected["session"], {"pdu_session_id": 5, "dnn": "internet"})
        self.assertNotIn("qfi", projected["session"])

    def test_5gmm_events_carry_no_session(self):
        for event in events_of("registration-flow.jsonl"):
            self.assertNotIn("session_management", event)
            self.assertNotIn("session", MODEL.project_trace_event(event))


class ProjectionTests(unittest.TestCase):
    def test_trace_projection_fields(self):
        projected = MODEL.project_trace_event(events_of("registration-flow.jsonl")[0])
        self.assertEqual(projected["protocol"], "NAS-5GS")
        self.assertEqual(projected["interface"], "N1")
        self.assertEqual(projected["procedure"], "REGISTRATION")
        self.assertEqual(projected["message_type"], "Registration request")
        self.assertEqual(projected["packet"], {"frame_number": 1, "capture_file": "registration-flow.jsonl"})
        self.assertEqual(projected["evidence"]["level"], "DERIVED")

    def test_subscriber_and_session_omitted(self):
        for event in events_of("registration-flow.jsonl"):
            projected = MODEL.project_trace_event(event)
            self.assertNotIn("subscriber", projected)
            self.assertNotIn("session", projected)

    def test_reject_cause_projected(self):
        projected = MODEL.project_trace_event(events_of("rejection-flow.jsonl")[0])
        self.assertEqual(projected["result"], {"status": "REJECT", "cause": "Congestion", "code": 22})

    def test_plain_status_message_keeps_status_not_verdict(self):
        event = events_of("protection-variants.jsonl")[3]
        projected = MODEL.project_trace_event(event)
        self.assertEqual(projected["result"]["status"], "STATUS")
        self.assertEqual(projected["result"]["cause"], "Tracking area not allowed")

    def test_ngap_identifiers_not_emitted(self):
        blob = json.dumps(events_of("registration-flow.jsonl"))
        for forbidden in ("amf_ue_ngap_id", "ran_ue_ngap_id", "AMF-UE-NGAP-ID", "RAN-UE-NGAP-ID"):
            self.assertNotIn(forbidden, blob)


class FixtureAndDeterminismTests(unittest.TestCase):
    def test_expected_detailed_fixture_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in FIXTURE_NAMES:
                output = Path(directory) / f"{name}.jsonl"
                EXTRACT.write_events(EXTRACTED / f"{name}.jsonl", "fields-jsonl", output, False, False)
                expected = [json.loads(line) for line in (EXPECTED / f"{name}-events.jsonl").read_text(encoding="utf-8").splitlines()]
                actual = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
                self.assertEqual(actual, expected, name)

    def test_expected_trace_fixture_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "trace.jsonl"
            EXTRACT.write_projection(EXPECTED / "registration-flow-events.jsonl", output, False)
            expected = [json.loads(line) for line in (EXPECTED / "registration-flow-trace.jsonl").read_text(encoding="utf-8").splitlines()]
            actual = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(actual, expected)

    def test_deterministic_output(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "a.jsonl"
            second = Path(directory) / "b.jsonl"
            EXTRACT.write_events(EXTRACTED / "registration-flow.jsonl", "fields-jsonl", first, False, False)
            EXTRACT.write_events(EXTRACTED / "registration-flow.jsonl", "fields-jsonl", second, False, False)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_refuses_overwrite_and_self_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "events.jsonl"
            EXTRACT.write_events(EXTRACTED / "registration-flow.jsonl", "fields-jsonl", output, False, False)
            with self.assertRaises(OSError):
                EXTRACT.write_events(EXTRACTED / "registration-flow.jsonl", "fields-jsonl", output, False, False)
            with self.assertRaises(OSError):
                EXTRACT.write_events(EXTRACTED / "registration-flow.jsonl", "fields-jsonl", EXTRACTED / "registration-flow.jsonl", True, False)


class MalformedInputTests(unittest.TestCase):
    def test_malformed_records_fail_loudly(self):
        with self.assertRaises(MODEL.InputError):
            list(MODEL.read_jsonl(EXTRACTED / "malformed.jsonl"))

    def test_missing_required_fields_fail_semantically(self):
        with self.assertRaises(MODEL.InputError):
            events_of("missing-required.jsonl")

    def test_invalid_key_set_identifier_rejected(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.normalize_record(
                {"frame.number": "1", "frame.time_epoch": "0", "nas-5gs.mm.message_type": "65", "nas-5gs.mm.nas_key_set_id": "9"},
                "x.jsonl",
            )

    def test_invalid_carrier_direction_rejected(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.normalize_record(
                {"frame.number": "1", "frame.time_epoch": "0", "nas-5gs.mm.message_type": "65", "carrier_direction": "sideways"},
                "x.jsonl",
            )

    def test_missing_file_fails(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.records_for_input(PACKAGE / "absent.jsonl", "fields-jsonl")


class TsharkBoundaryTests(unittest.TestCase):
    def test_tshark_unavailable_is_clear(self):
        with mock.patch.object(MODEL.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(MODEL.ToolUnavailable):
                MODEL.tshark_version()
        with mock.patch.object(MODEL.subprocess, "Popen", side_effect=FileNotFoundError):
            with self.assertRaises(MODEL.ToolUnavailable):
                list(MODEL.tshark_records(Path("sample.pcapng")))

    def test_subprocess_uses_argument_list(self):
        command = MODEL.build_tshark_fields_command(Path("sample.pcapng"))
        self.assertEqual(command[:4], ["tshark", "-n", "-r", "sample.pcapng"])
        self.assertIn("-Y", command)
        self.assertIn("nas-5gs", command)
        self.assertIn("nas-5gs.mm.message_type", command)
        self.assertNotIn("shell=True", command)


class TimelineTests(unittest.TestCase):
    def test_text_timeline_renders_bounded_columns(self):
        events = [json.loads(line) for line in (EXPECTED / "registration-flow-events.jsonl").read_text(encoding="utf-8").splitlines()]
        text = TIMELINE.render_text(events)
        self.assertIn("Registration request", text)
        self.assertIn("ue-to-amf", text)
        self.assertIn("SUCI", text)
        self.assertIn("initial registration", text)
        self.assertIn("plain", text)

    def test_timeline_reject_cause_and_no_success_verdict(self):
        events = [json.loads(line) for line in (EXPECTED / "rejection-flow-events.jsonl").read_text(encoding="utf-8").splitlines()]
        text = TIMELINE.render_text(events)
        self.assertIn("Congestion(22)", text)
        self.assertNotIn("SUCCESS", text.upper().replace("SUCCESSFUL", ""))

    def test_5gsm_timeline_columns_and_no_verdict(self):
        events = [json.loads(line) for line in (EXPECTED / "sm-release-events.jsonl").read_text(encoding="utf-8").splitlines()]
        text = TIMELINE.render_text(events)
        self.assertIn("PDU session release command", text)
        self.assertIn("psi=5", text)
        self.assertIn("Regular deactivation(36)", text)
        upper = text.upper()
        for forbidden in ("PDU SESSION SUCCESS", "PDU SESSION FAILURE", "SMF FAILURE", "UPF FAILURE"):
            self.assertNotIn(forbidden, upper)

    def test_json_timeline_structure(self):
        events = [json.loads(line) for line in (EXPECTED / "registration-flow-events.jsonl").read_text(encoding="utf-8").splitlines()]
        document = json.loads(TIMELINE.render_json(events))
        self.assertEqual(len(document["events"]), len(events))
        for entry in document["events"]:
            self.assertNotIn("identity_value", entry)
            self.assertNotIn("value", json.dumps(entry.get("cause", {})))


class SchemaTests(unittest.TestCase):
    def test_expected_events_conform_structurally(self):
        schema = json.loads((PACKAGE / "schemas" / "nas5gs-event.schema.json").read_text(encoding="utf-8"))
        allowed = set(schema["properties"])
        required = set(schema["required"])
        for name in FIXTURE_NAMES:
            for event in [json.loads(line) for line in (EXPECTED / f"{name}-events.jsonl").read_text(encoding="utf-8").splitlines()]:
                self.assertTrue(required <= set(event), name)
                self.assertTrue(set(event) <= allowed, name)
                self.assertEqual(event["evidence"]["level"], "OBSERVED")
                self.assertIn(event["support_status"], {"SUPPORTED", "UNSUPPORTED", "UNKNOWN", "DEFERRED"})
                self.assertIsNone(event["identity"]["value"])
                for derivation in event["derivations"]:
                    self.assertIn(derivation, schema["properties"]["derivations"]["items"]["enum"])

    def test_session_management_only_on_5gsm(self):
        for name in FIXTURE_NAMES:
            for event in [json.loads(line) for line in (EXPECTED / f"{name}-events.jsonl").read_text(encoding="utf-8").splitlines()]:
                if event["nas_family"] == "5GSM":
                    self.assertIn("session_management", event, name)
                else:
                    self.assertNotIn("session_management", event, name)

    def test_trace_projection_conforms(self):
        schema = json.loads((PACKAGE / "schemas" / "trace-event.schema.json").read_text(encoding="utf-8"))
        allowed = set(schema["properties"])
        for projected in [json.loads(line) for line in (EXPECTED / "registration-flow-trace.jsonl").read_text(encoding="utf-8").splitlines()]:
            self.assertTrue(set(projected) <= allowed)
            self.assertEqual(projected["protocol"], "NAS-5GS")
            self.assertEqual(projected["evidence"]["level"], "DERIVED")

    def test_package_schemas_parse(self):
        for name in ("nas5gs-event.schema.json", "trace-event.schema.json"):
            document = json.loads((PACKAGE / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_package_local_trace_schema_matches_shared_when_available(self):
        shared = PACKAGE.parents[2] / "shared" / "schemas" / "trace-event.schema.json"
        local = PACKAGE / "schemas" / "trace-event.schema.json"
        if not shared.is_file():
            self.skipTest("shared schema not present in standalone copy")
        self.assertEqual(local.read_bytes(), shared.read_bytes())


class StandaloneTests(unittest.TestCase):
    def test_standalone_copy_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "nas-5gs"
            shutil.copytree(PACKAGE, copied)
            for name in ("extract-nas5gs.py", "nas5gs_timeline.py"):
                result = subprocess.run([sys.executable, str(copied / "scripts" / name), "--help"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            events = copied / "events.jsonl"
            result = subprocess.run(
                [sys.executable, str(copied / "scripts" / "extract-nas5gs.py"), str(copied / "examples" / "extracted" / "registration-flow.jsonl"), "--input-format", "fields-jsonl", "--output", str(events)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            timeline = subprocess.run([sys.executable, str(copied / "scripts" / "nas5gs_timeline.py"), str(events)], capture_output=True, text=True)
            self.assertEqual(timeline.returncode, 0, timeline.stderr)
            self.assertIn("Registration request", timeline.stdout)


if __name__ == "__main__":
    unittest.main()
