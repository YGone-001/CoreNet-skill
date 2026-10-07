#!/usr/bin/env python3
"""Comprehensive test suite for the standalone sbi-http2 Protocol Skill."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PACKAGE_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import sbi_model
from sbi_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    EXIT_TOOL_UNAVAILABLE,
    InputError,
    ToolUnavailable,
    connection_context,
    correlate_events,
    normalize_record,
    project_trace_event,
    transaction_key,
)


class ManifestAndSchemaTests(unittest.TestCase):
    def test_manifest_structure(self):
        manifest_path = PACKAGE_ROOT / "manifest.yaml"
        self.assertTrue(manifest_path.is_file())
        text = manifest_path.read_text(encoding="utf-8")
        self.assertIn("name: sbi-http2", text)
        self.assertIn("version: 0.2.1", text)
        self.assertIn("category: protocol", text)
        self.assertIn("interfaces:\n  - N11", text)
        self.assertIn("protocols:\n  - HTTP/2\n  - 3GPP-SBI", text)
        self.assertIn("required: []", text)
        self.assertIn("network_functions: []", text)

    def test_schemas_are_valid_json(self):
        for name in ("sbi-http2-event.schema.json", "sbi-http2-correlation.schema.json", "trace-event.schema.json"):
            schema_path = PACKAGE_ROOT / "schemas" / name
            self.assertTrue(schema_path.is_file(), f"missing schema {name}")
            data = json.loads(schema_path.read_text(encoding="utf-8"))
            self.assertEqual(data["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_event_schema_requires_core_fields(self):
        schema_path = PACKAGE_ROOT / "schemas" / "sbi-http2-event.schema.json"
        data = json.loads(schema_path.read_text(encoding="utf-8"))
        required = data.get("required", [])
        for field in ("timestamp", "frame_number", "capture_file", "connection", "http2", "sbi", "session_management", "privacy", "multipart_parts", "problem_details", "transport_error", "support_status", "result", "evidence", "derivations", "limitations"):
            self.assertIn(field, required)


class Http2StreamAndConnectionIsolationTests(unittest.TestCase):
    def test_same_stream_on_different_connections_does_not_correlate(self):
        req_conn_a = {
            "frame_number": 1,
            "timestamp": "2026-10-02T10:00:00.000000Z",
            "tcp_stream": 0,
            "connection_id": "conn-A",
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "192.0.2.20",
            "destination_port": 80,
            "stream_id": 1,
            "frame_type": "HEADERS",
            "method": "POST",
            "path": "/nsmf-pdusession/v1/sm-contexts",
            "headers": {"content-type": "application/json"},
            "json_body": {"pduSessionId": 1},
        }
        rsp_conn_a = {
            "frame_number": 2,
            "timestamp": "2026-10-02T10:00:00.020000Z",
            "tcp_stream": 0,
            "connection_id": "conn-A",
            "source_address": "192.0.2.20",
            "source_port": 80,
            "destination_address": "192.0.2.10",
            "destination_port": 50000,
            "stream_id": 1,
            "frame_type": "HEADERS",
            "status": 201,
            "headers": {"location": "http://smf.example.org/nsmf-pdusession/v1/sm-contexts/ctx-A1"},
        }
        req_conn_b = {
            "frame_number": 3,
            "timestamp": "2026-10-02T10:00:01.000000Z",
            "tcp_stream": 1,
            "connection_id": "conn-B",
            "source_address": "198.51.100.10",
            "source_port": 50001,
            "destination_address": "198.51.100.20",
            "destination_port": 80,
            "stream_id": 1,
            "frame_type": "HEADERS",
            "method": "POST",
            "path": "/nsmf-pdusession/v1/sm-contexts/ctx-B1/release",
            "headers": {"content-type": "application/json"},
            "json_body": {"cause": "REL_DUE_TO_DUPLICATE_PDU_ID"},
        }
        rsp_conn_b = {
            "frame_number": 4,
            "timestamp": "2026-10-02T10:00:01.025000Z",
            "tcp_stream": 1,
            "connection_id": "conn-B",
            "source_address": "198.51.100.20",
            "source_port": 80,
            "destination_address": "198.51.100.10",
            "destination_port": 50001,
            "stream_id": 1,
            "frame_type": "HEADERS",
            "status": 204,
            "headers": {"content-length": "0"},
        }

        ev1 = normalize_record(req_conn_a, "test.pcap")
        ev2 = normalize_record(rsp_conn_a, "test.pcap")
        ev3 = normalize_record(req_conn_b, "test.pcap")
        ev4 = normalize_record(rsp_conn_b, "test.pcap")

        key1 = transaction_key(ev1)
        key3 = transaction_key(ev3)
        self.assertNotEqual(key1, key3, "same stream ID on different connections must produce different transaction keys")

        summary = correlate_events([ev1, ev2, ev3, ev4])
        txs = summary["transactions"]
        self.assertEqual(len(txs), 2)
        tx_keys = {tx["transaction_key"] for tx in txs}
        self.assertIn("sbi-tx:test.pcap:tcp-stream:0:stream1", tx_keys)
        self.assertIn("sbi-tx:test.pcap:tcp-stream:1:stream1", tx_keys)


class NsmfPDUSessionSemanticsTests(unittest.TestCase):
    def test_create_sm_context_success_and_transition(self):
        req = {
            "frame_number": 1,
            "timestamp": "2026-10-02T10:00:00.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "192.0.2.20",
            "destination_port": 80,
            "stream_id": 1,
            "method": "POST",
            "path": "/nsmf-pdusession/v1/sm-contexts",
            "headers": {"content-type": "application/json"},
            "json_body": {
                "pduSessionId": 5,
                "dnn": "internet",
                "sNssai": {"sst": 1, "sd": "A1B2C3"},
                "requestType": "INITIAL_REQUEST",
                "anType": "3GPP_ACCESS",
                "ratType": "NR",
            },
        }
        rsp = {
            "frame_number": 2,
            "timestamp": "2026-10-02T10:00:00.020000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.20",
            "source_port": 80,
            "destination_address": "192.0.2.10",
            "destination_port": 50000,
            "stream_id": 1,
            "status": 201,
            "headers": {
                "content-type": "application/json",
                "location": "http://smf.example.org/nsmf-pdusession/v1/sm-contexts/ctx-9999",
            },
            "json_body": {"pduSessionId": 5, "upCnxState": "ACTIVATED"},
        }
        ev1 = normalize_record(req, "test.pcap")
        ev2 = normalize_record(rsp, "test.pcap")

        self.assertEqual(ev1["sbi"]["operation"], "CreateSMContext")
        self.assertEqual(ev1["support_status"], "SUPPORTED")
        self.assertIsNone(ev1["sbi"]["sm_context_ref"], "initial Create request must not require sm_context_ref")
        self.assertEqual(ev1["session_management"]["pdu_session_id"], 5)
        self.assertEqual(ev1["session_management"]["dnn"], "internet")
        self.assertEqual(ev1["session_management"]["snssai"], {"sst": 1, "sd": "A1B2C3"})
        self.assertEqual(ev1["session_management"]["request_type"], "INITIAL_REQUEST")
        self.assertEqual(ev1["session_management"]["access_type"], "3GPP_ACCESS")
        self.assertEqual(ev1["session_management"]["rat_type"], "NR")

        self.assertEqual(ev2["http2"]["status"], 201)
        self.assertEqual(ev2["result"], "RESPONSE")
        self.assertNotEqual(ev2["result"], "PDU_SESSION_SUCCESS", "HTTP 2xx must not become PDU_SESSION_SUCCESS")
        self.assertEqual(ev2["sbi"]["sm_context_ref"], "ctx-9999")

        summary = correlate_events([ev1, ev2])
        self.assertEqual(len(summary["transactions"]), 1)
        tx = summary["transactions"][0]
        self.assertEqual(tx["sm_context_ref"], "ctx-9999")
        self.assertEqual(tx["correlation_strength"], "STRONG")

    def test_update_sm_context_modify_path(self):
        req = {
            "frame_number": 10,
            "timestamp": "2026-10-02T10:00:05.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "192.0.2.20",
            "destination_port": 80,
            "stream_id": 3,
            "method": "POST",
            "path": "/nsmf-pdusession/v1/sm-contexts/ctx-9999/modify",
            "headers": {"content-type": "application/json"},
            "json_body": {"upCnxState": "DEACTIVATED"},
        }
        rsp = {
            "frame_number": 11,
            "timestamp": "2026-10-02T10:00:05.015000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.20",
            "source_port": 80,
            "destination_address": "192.0.2.10",
            "destination_port": 50000,
            "stream_id": 3,
            "status": 204,
            "headers": {"content-length": "0"},
        }
        ev1 = normalize_record(req, "test.pcap")
        ev2 = normalize_record(rsp, "test.pcap")
        self.assertEqual(ev1["sbi"]["operation"], "UpdateSMContext")
        self.assertEqual(ev1["sbi"]["sm_context_ref"], "ctx-9999")
        self.assertEqual(ev2["http2"]["status"], 204)

    def test_release_sm_context_release_path(self):
        req = {
            "frame_number": 20,
            "timestamp": "2026-10-02T10:01:00.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "192.0.2.20",
            "destination_port": 80,
            "stream_id": 5,
            "method": "POST",
            "path": "/nsmf-pdusession/v1/sm-contexts/ctx-9999/release",
            "headers": {"content-type": "application/json"},
            "json_body": {"cause": "REL_DUE_TO_DUPLICATE_PDU_ID"},
        }
        rsp = {
            "frame_number": 21,
            "timestamp": "2026-10-02T10:01:00.020000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.20",
            "source_port": 80,
            "destination_address": "192.0.2.10",
            "destination_port": 50000,
            "stream_id": 5,
            "status": 204,
            "headers": {"content-length": "0"},
        }
        ev1 = normalize_record(req, "test.pcap")
        ev2 = normalize_record(rsp, "test.pcap")
        self.assertEqual(ev1["sbi"]["operation"], "ReleaseSMContext")
        self.assertEqual(ev1["sbi"]["sm_context_ref"], "ctx-9999")
        self.assertEqual(ev2["http2"]["status"], 204)


class MultipartBindingTests(unittest.TestCase):
    def test_multipart_content_id_binding_independent_of_order(self):
        record = {
            "frame_number": 100,
            "timestamp": "2026-10-02T10:02:00.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "192.0.2.20",
            "destination_port": 80,
            "stream_id": 1,
            "method": "POST",
            "path": "/nsmf-pdusession/v1/sm-contexts/ctx-1/modify",
            "headers": {"content-type": "multipart/related"},
            "json_body": {
                "pduSessionId": 1,
                "n1SmMsg": {"contentId": "cid-n1"},
                "n2SmInfo": {"contentId": "cid-n2"},
            },
            # Ordered inversely in multipart array: n2 first, then n1!
            "multipart_parts": [
                {"content_id": "jsonData", "content_type": "application/json", "length": 150},
                {"content_id": "<cid-n2>", "content_type": "application/vnd.3gpp.ngap", "length": 80},
                {"content_id": "<cid-n1>", "content_type": "application/vnd.3gpp.5gnas", "length": 45},
            ],
        }
        ev = normalize_record(record, "test.pcap")
        parts = ev["multipart_parts"]
        self.assertEqual(len(parts), 3)

        part_by_cid = {p["content_id"]: p for p in parts}
        self.assertEqual(part_by_cid["jsonData"]["semantic_role"], "JSON_METADATA")
        self.assertEqual(part_by_cid["jsonData"]["reference_basis"], "ROOT_JSON")

        self.assertEqual(part_by_cid["cid-n2"]["semantic_role"], "N2_SM_INFO")
        self.assertEqual(part_by_cid["cid-n2"]["reference_basis"], "EXPLICIT_CONTENT_ID")

        self.assertEqual(part_by_cid["cid-n1"]["semantic_role"], "N1_SM_INFO")
        self.assertEqual(part_by_cid["cid-n1"]["reference_basis"], "EXPLICIT_CONTENT_ID")

    def test_missing_referenced_content_id(self):
        record = {
            "frame_number": 101,
            "timestamp": "2026-10-02T10:02:01.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "192.0.2.20",
            "destination_port": 80,
            "stream_id": 1,
            "method": "POST",
            "path": "/nsmf-pdusession/v1/sm-contexts",
            "json_body": {"n1SmMsg": {"contentId": "absent-part"}},
            "multipart_parts": [{"content_id": "jsonData", "content_type": "application/json", "length": 100}],
        }
        ev = normalize_record(record, "test.pcap")
        self.assertTrue(any("absent-part" in lim for lim in ev["limitations"]))

    def test_duplicate_content_id_marked_ambiguous(self):
        record = {
            "frame_number": 102,
            "timestamp": "2026-10-02T10:02:02.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "192.0.2.20",
            "destination_port": 80,
            "stream_id": 1,
            "method": "POST",
            "path": "/nsmf-pdusession/v1/sm-contexts",
            "json_body": {"n1SmMsg": {"contentId": "dup-part"}},
            "multipart_parts": [
                {"content_id": "jsonData", "content_type": "application/json", "length": 100},
                {"content_id": "dup-part", "content_type": "application/vnd.3gpp.5gnas", "length": 30},
                {"content_id": "dup-part", "content_type": "application/vnd.3gpp.5gnas", "length": 32},
            ],
        }
        ev = normalize_record(record, "test.pcap")
        dup_parts = [p for p in ev["multipart_parts"] if p["content_id"] == "dup-part"]
        self.assertEqual(len(dup_parts), 2)
        for dp in dup_parts:
            self.assertEqual(dp["semantic_role"], "UNRESOLVED")
            self.assertEqual(dp["reference_basis"], "AMBIGUOUS_CONTENT_ID")
        self.assertTrue(any("duplicate Content-ID" in lim for lim in ev["limitations"]))


class PrivacyAndSecurityTests(unittest.TestCase):
    def test_subscriber_identities_are_redacted(self):
        raw_supi = "imsi-001010000000001"
        raw_gpsi = "msisdn-10000000001"
        raw_pei = "imeisv-1234567890123456"
        record = {
            "frame_number": 200,
            "timestamp": "2026-10-02T10:03:00.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "192.0.2.20",
            "destination_port": 80,
            "stream_id": 1,
            "method": "POST",
            "path": "/nsmf-pdusession/v1/sm-contexts",
            "json_body": {
                "pduSessionId": 1,
                "supi": raw_supi,
                "gpsi": raw_gpsi,
                "pei": raw_pei,
            },
        }
        ev = normalize_record(record, "test.pcap")
        ev_str = json.dumps(ev)
        self.assertTrue(ev["privacy"]["subscriber_identity_present"])
        self.assertIn(ev["privacy"]["subscriber_identity_type"], ("SUPI", "GPSI", "PEI"))
        self.assertNotIn(raw_supi, ev_str, "raw SUPI must be redacted")
        self.assertNotIn(raw_gpsi, ev_str, "raw GPSI must be redacted")
        self.assertNotIn(raw_pei, ev_str, "raw PEI must be redacted")

        # Projected trace must not have subscriber identities
        projected = project_trace_event(ev)
        self.assertNotIn("subscriber", projected, "generic trace must not populate subscriber from SBI")

    def test_authorization_header_is_stripped(self):
        token = "Bearer secret-bearer-token-12345678"
        record = {
            "frame_number": 201,
            "timestamp": "2026-10-02T10:03:01.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "192.0.2.20",
            "destination_port": 80,
            "stream_id": 1,
            "method": "POST",
            "path": "/nsmf-pdusession/v1/sm-contexts",
            "headers": {
                "content-type": "application/json",
                "authorization": token,
            },
        }
        ev = normalize_record(record, "test.pcap")
        ev_str = json.dumps(ev)
        self.assertNotIn(token, ev_str)
        self.assertNotIn("authorization", ev["sbi"]["selected_headers"])


class ErrorHandlingAndBoundariesTests(unittest.TestCase):
    def test_http_400_problem_details_does_not_blame_smf(self):
        record = {
            "frame_number": 300,
            "timestamp": "2026-10-02T10:04:00.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.20",
            "source_port": 80,
            "destination_address": "192.0.2.10",
            "destination_port": 50000,
            "stream_id": 1,
            "status": 400,
            "headers": {"content-type": "application/problem+json"},
            "problem_details": {
                "status": 400,
                "cause": "DNN_NOT_SUPPORTED",
                "title": "Data Network Name not supported",
            },
        }
        ev = normalize_record(record, "test.pcap")
        self.assertEqual(ev["result"], "HTTP_ERROR")
        self.assertNotEqual(ev["result"], "SMF_FAILURE")
        self.assertEqual(ev["problem_details"]["cause"], "DNN_NOT_SUPPORTED")

    def test_rst_stream_transport_error(self):
        record = {
            "frame_number": 301,
            "timestamp": "2026-10-02T10:04:01.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.20",
            "source_port": 80,
            "destination_address": "192.0.2.10",
            "destination_port": 50000,
            "stream_id": 5,
            "frame_type": "RST_STREAM",
            "rst_stream_error": 8,
        }
        ev = normalize_record(record, "test.pcap")
        self.assertEqual(ev["result"], "RESET")
        self.assertIsNotNone(ev["transport_error"])
        self.assertEqual(ev["transport_error"]["type"], "RST_STREAM")
        self.assertEqual(ev["transport_error"]["error_code"], 8)

    def test_goaway_transport_error(self):
        record = {
            "frame_number": 302,
            "timestamp": "2026-10-02T10:04:02.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.20",
            "source_port": 80,
            "destination_address": "192.0.2.10",
            "destination_port": 50000,
            "stream_id": 0,
            "frame_type": "GOAWAY",
            "last_stream_id": 7,
            "goaway_error": 0,
            "debug_data_present": True,
        }
        ev = normalize_record(record, "test.pcap")
        self.assertEqual(ev["result"], "GOAWAY")
        self.assertIsNotNone(ev["transport_error"])
        self.assertEqual(ev["transport_error"]["type"], "GOAWAY")
        self.assertEqual(ev["transport_error"]["last_stream_id"], 7)

    def test_tls_encrypted_payload_limitation(self):
        record = {
            "frame_number": 303,
            "timestamp": "2026-10-02T10:04:03.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "192.0.2.20",
            "destination_port": 80,
            "tls_encrypted": True,
        }
        ev = normalize_record(record, "test.pcap")
        self.assertEqual(ev["result"], "PAYLOAD_UNAVAILABLE")
        self.assertTrue(any("HTTP/2/SBI payload unavailable" in lim for lim in ev["limitations"]))
        self.assertNotEqual(ev["sbi"]["operation"], sbi_model.OP_CREATE_SM_CONTEXT)


class RecognitionAndUnsupportedServicesTests(unittest.TestCase):
    def test_unknown_operation_under_nsmf_pdusession(self):
        record = {
            "frame_number": 400,
            "timestamp": "2026-10-02T10:05:00.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "192.0.2.20",
            "destination_port": 80,
            "stream_id": 1,
            "method": "POST",
            "path": "/nsmf-pdusession/v1/sm-contexts/ctx-1/unrecognized-custom-op",
        }
        ev = normalize_record(record, "test.pcap")
        self.assertEqual(ev["sbi"]["service_name"], "Nsmf_PDUSession")
        self.assertEqual(ev["sbi"]["operation"], "UNKNOWN")
        self.assertEqual(ev["support_status"], "UNKNOWN")

    def test_unsupported_other_sbi_service(self):
        record = {
            "frame_number": 401,
            "timestamp": "2026-10-02T10:05:01.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "192.0.2.30",
            "destination_port": 80,
            "stream_id": 1,
            "method": "POST",
            "path": "/namf-comm/v1/ue-contexts",
        }
        ev = normalize_record(record, "test.pcap")
        self.assertEqual(ev["sbi"]["service_name"], "Namf_Communication")
        self.assertEqual(ev["support_status"], "UNSUPPORTED")

    def test_generic_non_sbi_http2_traffic(self):
        record = {
            "frame_number": 402,
            "timestamp": "2026-10-02T10:05:02.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 50000,
            "destination_address": "203.0.113.50",
            "destination_port": 80,
            "stream_id": 1,
            "method": "GET",
            "path": "/index.html",
        }
        ev = normalize_record(record, "test.pcap")
        self.assertIsNone(ev["sbi"]["service_name"])
        self.assertEqual(ev["support_status"], "UNSUPPORTED")


class NamfCommunicationDeliveryTests(unittest.TestCase):
    def test_n1n2_message_transfer_request_normalization(self):
        record = {
            "frame_number": 10,
            "timestamp": "2026-10-02T10:10:00.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.20",
            "source_port": 50000,
            "destination_address": "192.0.2.10",
            "destination_port": 80,
            "stream_id": 1,
            "frame_type": "HEADERS",
            "method": "POST",
            "path": "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages",
            "headers": {"content-type": "multipart/related; boundary=boundary-1"},
            "json_body": {
                "n1MessageContainer": {"n1MessageClass": "5GMM", "n1MessageContent": {"contentId": "n1-msg"}},
                "n2InfoContainer": {
                    "n2InformationClass": "SM",
                    "smInfo": {
                        "pduSessionId": 1,
                        "n2SmInfoType": "PDU_RES_SETUP_REQ",
                        "n2InfoContent": {"contentId": "n2-info"},
                    },
                },
                "n1n2FailureTxfNotifURI": "http://smf.example.org/callback/v1/n1-n2-failure-notify",
            },
            "multipart_parts": [
                {"content_id": "jsonData", "content_type": "application/json", "length": 220},
                {"content_id": "n1-msg", "content_type": "application/vnd.3gpp.5gnas", "length": 45},
                {"content_id": "n2-info", "content_type": "application/vnd.3gpp.ngap", "length": 65},
            ],
        }
        ev = normalize_record(record, "namf-transfer.pcap")
        self.assertEqual(ev["sbi"]["service_name"], "Namf_Communication")
        self.assertEqual(ev["sbi"]["operation"], "N1N2MessageTransfer")
        self.assertEqual(ev["sbi"]["resource"], "ue-contexts/{ueContextId}/n1-n2-messages")
        self.assertEqual(ev["http2"]["path"], "/namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages")
        self.assertEqual(ev["result"], "REQUEST")
        self.assertEqual(ev["support_status"], "SUPPORTED")

        namf = ev["namf_communication"]
        self.assertIsNotNone(namf)
        self.assertTrue(namf["ue_context_id_present"])
        self.assertEqual(namf["ue_context_id_type"], "SUPI")
        self.assertEqual(namf["n1_message_class"], "5GMM")
        self.assertEqual(namf["n2_information_class"], "SM")
        self.assertEqual(namf["n2_sm_info_type"], "PDU_RES_SETUP_REQ")
        self.assertEqual(namf["n1_content_id"], "n1-msg")
        self.assertEqual(namf["n2_content_id"], "n2-info")
        self.assertTrue(namf["failure_notification_uri_present"])

        parts = ev["multipart_parts"]
        self.assertEqual(len(parts), 3)
        part_roles = {p["content_id"]: p["semantic_role"] for p in parts}
        self.assertEqual(part_roles["jsonData"], "JSON_METADATA")
        self.assertEqual(part_roles["n1-msg"], "N1_MESSAGE")
        self.assertEqual(part_roles["n2-info"], "N2_SM_INFO")

        sm = ev["session_management"]
        self.assertEqual(sm["pdu_session_id"], 1)
        self.assertEqual(sm["n2_sm_info_type"], "PDU_RES_SETUP_REQ")

    def test_n1n2_message_transfer_200_ok(self):
        record = {
            "frame_number": 11,
            "timestamp": "2026-10-02T10:10:00.020000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 80,
            "destination_address": "192.0.2.20",
            "destination_port": 50000,
            "stream_id": 1,
            "frame_type": "HEADERS",
            "status": 200,
            "headers": {"content-type": "application/json"},
            "json_body": {"cause": "N1_N2_TRANSFER_INITIATED"},
            "service_name": "Namf_Communication",
            "operation": "N1N2MessageTransfer",
        }
        ev = normalize_record(record, "namf-transfer.pcap")
        self.assertEqual(ev["result"], "RESPONSE")
        self.assertEqual(ev["http2"]["status"], 200)
        namf = ev["namf_communication"]
        self.assertIsNotNone(namf)
        self.assertEqual(namf["transfer_cause"], "N1_N2_TRANSFER_INITIATED")

    def test_n1n2_message_transfer_202_accepted_pending(self):
        record = {
            "frame_number": 12,
            "timestamp": "2026-10-02T10:10:01.025000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 80,
            "destination_address": "192.0.2.20",
            "destination_port": 50000,
            "stream_id": 3,
            "frame_type": "HEADERS",
            "status": 202,
            "headers": {
                "content-type": "application/json",
                "location": "http://amf.example.org/namf-comm/v1/ue-contexts/imsi-001010000000002/n1-n2-messages/txfr-002",
            },
            "json_body": {"cause": "WAITING_FOR_ASYNCHRONOUS_TRANSFER"},
        }
        ev = normalize_record(record, "namf-transfer.pcap")
        self.assertEqual(ev["result"], "N1N2_TRANSFER_ACCEPTED_PENDING")
        self.assertIn("n1n2_transfer_accepted_pending", ev["derivations"])
        self.assertEqual(
            ev["sbi"]["n1n2_transfer_ref"],
            "/namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages/txfr-002",
        )
        self.assertEqual(
            ev["sbi"]["selected_headers"]["location"],
            "/namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages/txfr-002",
        )
        self.assertEqual(ev["namf_communication"]["transfer_cause"], "WAITING_FOR_ASYNCHRONOUS_TRANSFER")

    def test_n1n2_failure_notification_callback(self):
        req_record = {
            "frame_number": 20,
            "timestamp": "2026-10-02T10:20:05.000000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.10",
            "source_port": 80,
            "destination_address": "192.0.2.20",
            "destination_port": 50000,
            "stream_id": 3,
            "frame_type": "HEADERS",
            "method": "POST",
            "path": "/notification/n1-n2-failure-notify",
            "headers": {"content-type": "application/json"},
            "json_body": {
                "cause": "UE_NOT_RESPONDING",
                "n1n2MsgDataUri": "http://amf.example.org/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages/txfr-001",
            },
        }
        ev_req = normalize_record(req_record, "namf-failure.pcap")
        self.assertEqual(ev_req["sbi"]["service_name"], "Namf_Communication")
        self.assertEqual(ev_req["sbi"]["operation"], "N1N2TransferFailureNotification")
        self.assertEqual(ev_req["result"], "FAILURE_NOTIFICATION")
        self.assertEqual(
            ev_req["sbi"]["n1n2_transfer_ref"],
            "/namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages/txfr-001",
        )
        self.assertEqual(ev_req["namf_communication"]["failure_cause"], "UE_NOT_RESPONDING")

        rsp_record = {
            "frame_number": 21,
            "timestamp": "2026-10-02T10:20:05.010000Z",
            "tcp_stream": 0,
            "source_address": "192.0.2.20",
            "source_port": 50000,
            "destination_address": "192.0.2.10",
            "destination_port": 80,
            "stream_id": 3,
            "frame_type": "HEADERS",
            "status": 204,
            "operation": "N1N2TransferFailureNotification",
        }
        ev_rsp = normalize_record(rsp_record, "namf-failure.pcap")
        self.assertEqual(ev_rsp["result"], "RESPONSE")
        self.assertIn("failure_notification_acknowledged", ev_rsp["derivations"])

    def test_deterministic_transfer_to_callback_correlation(self):
        ev_txfr_req = normalize_record({
            "frame_number": 1,
            "timestamp": "2026-10-02T10:20:00.000000Z",
            "tcp_stream": 0,
            "stream_id": 1,
            "method": "POST",
            "path": "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages",
            "json_body": {"n1MessageContainer": {"n1MessageClass": "5GMM"}},
        }, "test.pcap")
        ev_txfr_rsp = normalize_record({
            "frame_number": 2,
            "timestamp": "2026-10-02T10:20:00.030000Z",
            "tcp_stream": 0,
            "stream_id": 1,
            "status": 202,
            "headers": {"location": "http://amf.example.org/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages/txfr-001"},
            "json_body": {"cause": "ATTEMPTING_TO_REACH_UE"},
        }, "test.pcap")
        ev_cb_req = normalize_record({
            "frame_number": 3,
            "timestamp": "2026-10-02T10:20:05.000000Z",
            "tcp_stream": 0,
            "stream_id": 3,
            "method": "POST",
            "path": "/notification/n1-n2-failure-notify",
            "json_body": {
                "cause": "UE_NOT_RESPONDING",
                "n1n2MsgDataUri": "http://amf.example.org/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages/txfr-001",
            },
        }, "test.pcap")
        ev_cb_rsp = normalize_record({
            "frame_number": 4,
            "timestamp": "2026-10-02T10:20:05.010000Z",
            "tcp_stream": 0,
            "stream_id": 3,
            "status": 204,
            "operation": "N1N2TransferFailureNotification",
        }, "test.pcap")

        summary = correlate_events([ev_txfr_req, ev_txfr_rsp, ev_cb_req, ev_cb_rsp])
        txs = summary["transactions"]
        self.assertEqual(len(txs), 2)
        txfr_tx = next(t for t in txs if t["stream_id"] == 1)
        self.assertIn("failure_notification", txfr_tx)
        fn = txfr_tx["failure_notification"]
        self.assertEqual(fn["frame_number"], 3)
        self.assertEqual(fn["cause"], "UE_NOT_RESPONDING")
        self.assertTrue(fn["acknowledged"])
        self.assertEqual(summary.get("unbound_callbacks", []), [])

    def test_unbound_callback_is_not_matched_by_timestamp(self):
        ev_txfr_req = normalize_record({
            "frame_number": 1,
            "timestamp": "2026-10-02T10:20:00.000000Z",
            "tcp_stream": 0,
            "stream_id": 1,
            "method": "POST",
            "path": "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages",
            "json_body": {"n1MessageContainer": {"n1MessageClass": "5GMM"}},
        }, "test.pcap")
        ev_txfr_rsp = normalize_record({
            "frame_number": 2,
            "timestamp": "2026-10-02T10:20:00.030000Z",
            "tcp_stream": 0,
            "stream_id": 1,
            "status": 202,
            "headers": {"location": "http://amf.example.org/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages/txfr-001"},
            "json_body": {"cause": "ATTEMPTING_TO_REACH_UE"},
        }, "test.pcap")
        ev_cb_req = normalize_record({
            "frame_number": 3,
            "timestamp": "2026-10-02T10:20:05.000000Z",
            "tcp_stream": 0,
            "stream_id": 3,
            "method": "POST",
            "path": "/notification/n1-n2-failure-notify",
            "json_body": {
                "cause": "AN_NOT_RESPONDING",
                "n1n2MsgDataUri": "http://amf.example.org/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages/txfr-999",
            },
        }, "test.pcap")
        summary = correlate_events([ev_txfr_req, ev_txfr_rsp, ev_cb_req])
        txfr_tx = next(t for t in summary["transactions"] + summary["open_transactions"] if t["stream_id"] == 1)
        self.assertNotIn("failure_notification", txfr_tx)
        self.assertEqual(len(summary.get("unbound_callbacks", [])), 1)
        self.assertEqual(summary["unbound_callbacks"][0]["cause"], "AN_NOT_RESPONDING")

    def test_privacy_sanitizes_various_ue_context_ids(self):
        for raw_id, expected_type in (
            ("imsi-001010000000001", "SUPI"),
            ("supi-001010000000002", "SUPI"),
            ("001010000000003", "SUPI"),
            ("imeisv-1234567890123456", "PEI"),
            ("pei-987654321098765", "PEI"),
            ("guti-5g-12345", "GUTI"),
            ("ctx-generic-99", "GENERIC"),
        ):
            record = {
                "frame_number": 1,
                "timestamp": "2026-10-02T10:00:00.000000Z",
                "tcp_stream": 0,
                "stream_id": 1,
                "method": "POST",
                "path": f"/namf-comm/v1/ue-contexts/{raw_id}/n1-n2-messages",
            }
            ev = normalize_record(record, "test.pcap")
            self.assertEqual(ev["http2"]["path"], "/namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages")
            self.assertEqual(ev["sbi"]["resource"], "ue-contexts/{ueContextId}/n1-n2-messages")
            self.assertEqual(ev["privacy"]["subscriber_identity_type"], expected_type)
            self.assertNotIn(raw_id, json.dumps(ev))

    def test_trace_projection_namf_events(self):
        ev_req = normalize_record({
            "frame_number": 1,
            "timestamp": "2026-10-02T10:10:00.000000Z",
            "tcp_stream": 0,
            "stream_id": 1,
            "method": "POST",
            "path": "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages",
            "json_body": {"n1MessageContainer": {"n1MessageClass": "5GMM"}},
        }, "test.pcap")
        trace_req = project_trace_event(ev_req)
        self.assertEqual(trace_req["protocol"], "3GPP-SBI")
        self.assertEqual(trace_req["interface"], "N11")
        self.assertEqual(trace_req["message_type"], "N1N2MessageTransfer Request")

        ev_rsp = normalize_record({
            "frame_number": 2,
            "timestamp": "2026-10-02T10:10:00.020000Z",
            "tcp_stream": 0,
            "stream_id": 1,
            "status": 202,
            "operation": "N1N2MessageTransfer",
            "headers": {"location": "http://amf.example.org/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages/txfr-001"},
            "json_body": {"cause": "WAITING_FOR_ASYNCHRONOUS_TRANSFER"},
        }, "test.pcap")
        trace_rsp = project_trace_event(ev_rsp)
        self.assertEqual(trace_rsp["protocol"], "3GPP-SBI")
        self.assertEqual(trace_rsp["interface"], "N11")
        self.assertEqual(trace_rsp["message_type"], "N1N2MessageTransfer 202 Accepted")


class StandaloneCopyTests(unittest.TestCase):
    def test_package_functions_when_copied_outside_repository(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dest = Path(tmp_dir) / "sbi-http2"
            shutil.copytree(PACKAGE_ROOT, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

            # Test scripts compile and run in copied location
            extract_script = dest / "scripts" / "extract-sbi-http2.py"
            input_fixture = dest / "examples" / "extracted" / "create-sm-context.jsonl"
            out_events = dest / "test-events.jsonl"
            out_trace = dest / "test-trace.jsonl"

            proc = subprocess.run(
                [sys.executable, str(extract_script), str(input_fixture), "--output", str(out_events), "--trace-output", str(out_trace)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f"extract failed in standalone copy: {proc.stderr}")
            self.assertTrue(out_events.is_file())
            self.assertTrue(out_trace.is_file())

            correlate_script = dest / "scripts" / "correlate-sbi-http2.py"
            out_corr = dest / "test-corr.json"
            proc_corr = subprocess.run(
                [sys.executable, str(correlate_script), str(out_events), "--output", str(out_corr)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc_corr.returncode, 0, f"correlate failed in standalone copy: {proc_corr.stderr}")
            self.assertTrue(out_corr.is_file())

            timeline_script = dest / "scripts" / "sbi_timeline.py"
            proc_tl = subprocess.run(
                [sys.executable, str(timeline_script), str(out_events)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc_tl.returncode, 0, f"timeline failed in standalone copy: {proc_tl.stderr}")
            tl_text = proc_tl.stdout
            self.assertIn("CreateSMContext", tl_text)
            self.assertNotIn("SMF FAILURE", tl_text)
            self.assertNotIn("PDU SESSION SUCCESS", tl_text)
            self.assertNotIn("PDU SESSION FAILED", tl_text)


class SbiHttp2FieldResolutionTests(unittest.TestCase):
    def tearDown(self):
        sbi_model.set_discovery_overrides(None, None)

    def test_candidate_aliases_fallback(self):
        sbi_model.set_discovery_overrides({
            "frame.number",
            "frame.time_epoch",
            "http2.length",
            "http2.goaway.last_stream_id",
            "json.member",
        })
        mappings, _ = sbi_model.resolve_field_specs(sbi_model.FIELD_SPECS, sbi_model.get_available_fields(), "test-ver")
        resolved = dict(mappings)
        self.assertIn("http2.length", resolved)
        self.assertEqual(resolved["http2.length"], "http2.data.length")
        self.assertIn("http2.goaway.last_stream_id", resolved)
        self.assertEqual(resolved["http2.goaway.last_stream_id"], "http2.goaway.last_streamid")
        self.assertIn("json.member", resolved)
        self.assertEqual(resolved["json.member"], "json.member_name")

    def test_missing_required_field_raises(self):
        sbi_model.set_discovery_overrides({"http2.streamid"})
        with self.assertRaises(sbi_model.TsharkError):
            sbi_model.resolve_field_specs(sbi_model.FIELD_SPECS, sbi_model.get_available_fields(), "test-ver")


if __name__ == "__main__":
    unittest.main()
