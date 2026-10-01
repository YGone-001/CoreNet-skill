import hashlib
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
import pcap_normalize as NORMALIZE


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


EXTRACT = load_script("extract-events")
INVENTORY = load_script("capture-inventory")
FIXTURES = PACKAGE / "examples"


class CoreNetworkPcapTests(unittest.TestCase):
    def records(self):
        return list(NORMALIZE.read_jsonl(FIXTURES / "extracted" / "frames.jsonl"))

    def events(self):
        return [NORMALIZE.normalize_record(record, "frames.jsonl")[0] for record in self.records()]

    def test_expected_fixture_normalizes_deterministically(self):
        expected = [json.loads(line) for line in (FIXTURES / "expected" / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(self.events(), expected)
        self.assertEqual(self.events(), self.events())

    def test_ipv4_ipv6_and_transport_metadata(self):
        events = self.events()
        self.assertEqual(events[0]["source"]["address"], "192.0.2.10")
        self.assertEqual(events[1]["source"]["address"], "2001:db8::10")
        self.assertEqual(events[0]["protocol"], "PFCP")
        self.assertEqual(events[2]["protocol"], "NGAP")
        self.assertEqual(events[3]["protocol"], "HTTP2")
        self.assertEqual(events[5]["protocol"], "TCP")

    def test_unknown_and_missing_optional_address(self):
        events = self.events()
        self.assertEqual(events[4]["protocol"], "UNKNOWN")
        self.assertIsNone(events[5]["source"]["address"])
        self.assertEqual(events[5]["source"]["port"], 34000)

    def test_timestamp_is_utc_and_microsecond_precise(self):
        self.assertEqual(self.events()[0]["timestamp"], "2024-01-02T03:04:05.123457Z")
        self.assertEqual(NORMALIZE.normalize_timestamp("0"), "1970-01-01T00:00:00.000000Z")

    def test_capture_provenance_and_no_semantic_fabrication(self):
        event = self.events()[0]
        self.assertEqual(event["packet"], {"frame_number": 1, "capture_file": "frames.jsonl"})
        self.assertEqual(event["evidence"]["level"], "OBSERVED")
        self.assertNotIn("subscriber", event)
        self.assertNotIn("session", event)
        self.assertNotIn("procedure", event)
        self.assertNotIn("message_type", event)

    def test_malformed_and_missing_required_input(self):
        with self.assertRaises(NORMALIZE.InputError):
            list(NORMALIZE.read_jsonl(FIXTURES / "extracted" / "malformed.jsonl"))
        record = next(NORMALIZE.read_jsonl(FIXTURES / "extracted" / "missing-required.jsonl"))
        with self.assertRaises(NORMALIZE.InputError):
            NORMALIZE.normalize_record(record, "missing-required.jsonl")
        with self.assertRaises(NORMALIZE.InputError):
            NORMALIZE.records_for_input(PACKAGE / "missing.jsonl", "fields-jsonl")

    def test_no_frames_does_not_publish_output(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "empty.jsonl"
            empty.write_text("", encoding="utf-8")
            output = Path(directory) / "events.jsonl"
            with self.assertRaises(NORMALIZE.InputError):
                EXTRACT.write_events(empty, "fields-jsonl", output, False)
            self.assertFalse(output.exists())

    def test_tshark_unavailable_is_clear(self):
        with mock.patch.object(NORMALIZE.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(NORMALIZE.ToolUnavailable):
                NORMALIZE.tshark_version()

    def test_tshark_command_is_argument_list(self):
        command = NORMALIZE.build_tshark_fields_command(Path("sample.pcapng"))
        self.assertEqual(command[:6], ["tshark", "-n", "-r", "sample.pcapng", "-T", "fields"])
        self.assertIn("frame.number", command)
        self.assertIn("separator=/t", command)
        self.assertNotIn("shell=True", command)

    def test_inventory_is_metadata_only(self):
        data = INVENTORY.inventory(FIXTURES / "extracted" / "frames.jsonl", "fields-jsonl")
        self.assertEqual(data["frame_count"], 6)
        self.assertEqual(data["address_families"], ["IPv4", "IPv6"])
        self.assertEqual(data["transport_protocols"], ["SCTP", "TCP", "UDP"])
        self.assertIn("ngap", data["dissector_protocol_names"])
        self.assertIn("http2", data["dissector_protocol_names"])
        self.assertIn("UNKNOWN", data["dissector_protocols"])
        self.assertIsNone(data["tshark_version"])

    def test_extract_output_and_safe_overwrite_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "events.jsonl"
            count = EXTRACT.write_events(FIXTURES / "extracted" / "frames.jsonl", "fields-jsonl", output, False)
            self.assertEqual(count, 6)
            self.assertEqual([json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()], self.events())
            with self.assertRaises(OSError):
                EXTRACT.write_events(FIXTURES / "extracted" / "frames.jsonl", "fields-jsonl", output, False)
            with self.assertRaises(OSError):
                EXTRACT.write_events(FIXTURES / "extracted" / "frames.jsonl", "fields-jsonl", FIXTURES / "extracted" / "frames.jsonl", True)

    def test_package_local_schema_is_present(self):
        schema = PACKAGE / "schemas" / "trace-event.schema.json"
        self.assertTrue(schema.is_file())
        data = json.loads(schema.read_text(encoding="utf-8"))
        self.assertEqual(data["required"], ["timestamp", "protocol"])
        self.assertIn("packet", data["properties"])

    def test_standalone_copy_runs_help_and_fixture_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "core-network-pcap"
            shutil.copytree(PACKAGE, copied)
            help_result = subprocess.run([sys.executable, copied / "scripts" / "extract-events.py", "--help"], capture_output=True, text=True)
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            output = copied / "events.jsonl"
            result = subprocess.run([sys.executable, copied / "scripts" / "extract-events.py", copied / "examples" / "extracted" / "frames.jsonl", "--input-format", "fields-jsonl", "--output", output], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 6)
