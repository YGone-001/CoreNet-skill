#!/usr/bin/env python3
"""Package-local test suite for cross-protocol-evidence correlation."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
sys.path.insert(0, str(SCRIPTS))

import correlate_events as MODEL


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


CORRELATE = load_script("correlate-events")
TIMELINE = load_script("evidence-timeline")

NGAP_INPUT = PACKAGE / "examples" / "ngap-input"
NAS_INPUT = PACKAGE / "examples" / "nas-input"
EXPECTED = PACKAGE / "examples" / "expected"


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def correlate_files(ngap: list[Path], nas: list[Path], window: float | None = None) -> list[dict]:
    ngap_events = []
    for path in ngap:
        ngap_events.extend(MODEL.load_events(path, "NGAP"))
    nas_events = []
    for path in nas:
        nas_events.extend(MODEL.load_events(path, "NAS-5GS"))
    return MODEL.correlate(ngap_events, nas_events, window)


class LoadingTests(unittest.TestCase):
    def test_ngap_input_loads(self):
        events = MODEL.load_events(NGAP_INPUT / "join-flow.jsonl", "NGAP")
        self.assertEqual(len(events), 4)
        for event in events:
            self.assertEqual(event["protocol"], "NGAP")
        self.assertEqual(events[0]["message_type"], "InitialUEMessage")

    def test_nas_input_loads(self):
        events = MODEL.load_events(NAS_INPUT / "join-flow.jsonl", "NAS-5GS")
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["message_type"], "Registration request")
        self.assertEqual(events[0]["identity"]["value"], None)

    def test_missing_provenance_rejected(self):
        for missing in ("timestamp", "frame_number", "capture_file"):
            record = {"timestamp": "2024-01-02T03:04:10Z", "frame_number": 1, "capture_file": "x.pcapng"}
            del record[missing]
            with self.assertRaises(MODEL.InputError):
                MODEL.load_event(record, "NGAP", 0)

    def test_bad_frame_and_capture_rejected(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.load_event({"timestamp": "t", "frame_number": 0, "capture_file": "x"}, "NGAP", 0)
        with self.assertRaises(MODEL.InputError):
            MODEL.load_event({"timestamp": "t", "frame_number": True, "capture_file": "x"}, "NGAP", 0)
        with self.assertRaises(MODEL.InputError):
            MODEL.load_event({"timestamp": "t", "frame_number": 1, "capture_file": ""}, "NGAP", 0)

    def test_bad_timestamp_rejected(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.parse_timestamp("not-a-time", 0)
        with self.assertRaises(MODEL.InputError):
            MODEL.parse_timestamp("2024-01-02T03:04:05", 0)  # naive, no offset

    def test_sensitive_keys_rejected(self):
        for key in ("imsi", "suci", "supi", "msisdn", "rand", "autn", "kseaf", "identity_value"):
            record = {"timestamp": "2024-01-02T03:04:10Z", "frame_number": 1, "capture_file": "x.pcapng", key: "value"}
            with self.assertRaises(MODEL.InputError):
                MODEL.load_event(record, "NAS-5GS", 0)

    def test_nonredacted_identity_value_rejected(self):
        record = {
            "timestamp": "2024-01-02T03:04:10Z",
            "frame_number": 1,
            "capture_file": "x.pcapng",
            "identity": {"present": True, "type_name": "SUCI", "value": "suci-0-001"},
        }
        with self.assertRaises(MODEL.InputError):
            MODEL.load_event(record, "NAS-5GS", 0)

    def test_ngap_foreign_ids_preserved(self):
        events = MODEL.load_events(NGAP_INPUT / "join-flow.jsonl", "NGAP")
        self.assertEqual(events[0]["ran_ue_ngap_id"], 1)
        self.assertEqual(events[0]["amf_ue_ngap_id"], 2)
        blob = json.dumps(events)
        self.assertNotIn("subscriber", blob.lower())
        self.assertNotIn("imsi", blob.lower())


class CorrelationTests(unittest.TestCase):
    def test_strong_same_capture_same_frame(self):
        groups = correlate_files([NGAP_INPUT / "join-flow.jsonl"], [NAS_INPUT / "join-flow.jsonl"])
        strong = [g for g in groups if g["correlation_strength"] == "STRONG"]
        self.assertEqual(len(strong), 1)
        group = strong[0]
        self.assertEqual(group["frame_numbers"], [10])
        self.assertEqual(group["protocol_sources"], ["NAS-5GS", "NGAP"])
        self.assertEqual(len(group["events"]), 2)
        self.assertEqual(group["evidence"]["level"], "DERIVED")
        self.assertIn("frame_number", group["evidence"]["basis"])

    def test_medium_same_capture_within_window(self):
        groups = correlate_files([NGAP_INPUT / "join-flow.jsonl"], [NAS_INPUT / "join-flow.jsonl"])
        medium = [g for g in groups if g["correlation_strength"] == "MEDIUM"]
        self.assertEqual(len(medium), 1)
        self.assertEqual(medium[0]["frame_numbers"], [11, 12])
        self.assertEqual(medium[0]["protocol_sources"], ["NAS-5GS", "NGAP"])

    def test_no_merge_across_captures(self):
        groups = correlate_files([NGAP_INPUT / "join-flow.jsonl"], [NAS_INPUT / "join-flow.jsonl"])
        captures = {g["capture_file"] for g in groups}
        self.assertEqual(captures, {"join-capture.pcapng", "other-capture.pcapng"})
        for group in groups:
            self.assertEqual(len({event["capture_file"] for event in group["events"]}), 1)
        other = [g for g in groups if g["capture_file"] == "other-capture.pcapng"]
        self.assertEqual(len(other), 1)
        self.assertEqual(other[0]["correlation_strength"], "WEAK")

    def test_ngap_only_partial_timeline(self):
        groups = correlate_files([NGAP_INPUT / "ngap-only.jsonl"], [])
        self.assertEqual(len(groups), 3)
        for group in groups:
            self.assertEqual(group["correlation_strength"], "WEAK")
            self.assertEqual(group["protocol_sources"], ["NGAP"])

    def test_nas_only_partial_timeline(self):
        groups = correlate_files([], [NAS_INPUT / "nas-only.jsonl"])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["correlation_strength"], "MEDIUM")
        self.assertEqual(groups[0]["protocol_sources"], ["NAS-5GS"])

    def test_out_of_order_timestamps_preserved(self):
        groups = correlate_files([NGAP_INPUT / "out-of-order.jsonl"], [])
        self.assertEqual(len(groups), 1)
        frames = [event["frame_number"] for event in groups[0]["events"]]
        self.assertEqual(frames, [1, 2, 3])
        timestamps = [event["timestamp"] for event in groups[0]["events"]]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_duplicate_events_deterministic(self):
        first = correlate_files([NGAP_INPUT / "duplicates.jsonl"], [])
        second = correlate_files([NGAP_INPUT / "duplicates.jsonl"], [])
        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["correlation_strength"], "STRONG")
        self.assertEqual(len(first[0]["events"]), 2)

    def test_window_zero_disables_medium(self):
        groups = correlate_files([NGAP_INPUT / "join-flow.jsonl"], [NAS_INPUT / "join-flow.jsonl"], window=0)
        self.assertFalse(any(g["correlation_strength"] == "MEDIUM" for g in groups))

    def test_every_event_in_exactly_one_group(self):
        groups = correlate_files([NGAP_INPUT / "join-flow.jsonl"], [NAS_INPUT / "join-flow.jsonl"])
        placed = [(event["protocol"], event["input_order"]) for group in groups for event in group["events"]]
        self.assertEqual(len(placed), 6)
        self.assertEqual(len(set(placed)), 6)

    def test_no_verdict_fields(self):
        blob = json.dumps(correlate_files([NGAP_INPUT / "join-flow.jsonl"], [NAS_INPUT / "join-flow.jsonl"]))
        for forbidden in ("root_cause", "success", "failure", "registration_state", "subscriber_id"):
            self.assertNotIn(forbidden, blob.lower())


class ExpectedFixtureTests(unittest.TestCase):
    CASES = (
        (("join-flow.jsonl",), ("join-flow.jsonl",), "join-flow-correlation.jsonl"),
        (("ngap-only.jsonl",), (), "ngap-only-correlation.jsonl"),
        ((), ("nas-only.jsonl",), "nas-only-correlation.jsonl"),
        (("out-of-order.jsonl",), (), "out-of-order-correlation.jsonl"),
        (("duplicates.jsonl",), (), "duplicates-correlation.jsonl"),
    )

    def test_expected_outputs_match(self):
        with tempfile.TemporaryDirectory() as directory:
            for ngap_names, nas_names, expected_name in self.CASES:
                output = Path(directory) / expected_name
                CORRELATE.write_groups(
                    [NGAP_INPUT / name for name in ngap_names],
                    [NAS_INPUT / name for name in nas_names],
                    output, False, None,
                )
                expected = jsonl(EXPECTED / expected_name)
                self.assertEqual(jsonl(output), expected, expected_name)


class SchemaTests(unittest.TestCase):
    def test_expected_groups_conform_structurally(self):
        schema = json.loads((PACKAGE / "schemas" / "correlation-event.schema.json").read_text(encoding="utf-8"))
        for name in ("join-flow-correlation", "ngap-only-correlation", "nas-only-correlation", "out-of-order-correlation", "duplicates-correlation"):
            for group in jsonl(EXPECTED / f"{name}.jsonl"):
                self.assertEqual(set(group), set(schema["properties"]), name)
                self.assertIn(group["correlation_strength"], {"STRONG", "MEDIUM", "WEAK"})
                self.assertEqual(group["evidence"]["level"], "DERIVED")
                self.assertTrue(group["protocol_sources"])
                for event in group["events"]:
                    self.assertIn(event["protocol"], {"NGAP", "NAS-5GS"})

    def test_trace_schema_matches_shared_when_available(self):
        shared = PACKAGE.parents[3] / "shared" / "schemas" / "trace-event.schema.json"
        local = PACKAGE / "schemas" / "trace-event.schema.json"
        if not shared.is_file():
            self.skipTest("shared schema not present in standalone copy")
        self.assertEqual(local.read_bytes(), shared.read_bytes())


class TimelineTests(unittest.TestCase):
    def test_text_timeline_lists_evidence_and_missing(self):
        groups = jsonl(EXPECTED / "join-flow-correlation.jsonl")
        text = TIMELINE.render_text(groups)
        self.assertIn("[STRONG]", text)
        self.assertIn("NAS-5GS: Registration request", text)
        self.assertIn("NGAP: InitialUEMessage", text)
        self.assertIn("missing evidence in this group: NAS-5GS", text)
        self.assertNotIn("SUCCESS", text.upper())
        self.assertNotIn("FAILURE", text.upper())

    def test_json_timeline_structure(self):
        groups = jsonl(EXPECTED / "join-flow-correlation.jsonl")
        document = json.loads(TIMELINE.render_json(groups))
        self.assertEqual(len(document["timeline"]), len(groups))
        weak = [entry for entry in document["timeline"] if entry["correlation_strength"] == "WEAK"]
        self.assertTrue(weak)
        self.assertIn("NAS-5GS", weak[0]["missing_protocol_sources"])
        for entry in document["timeline"]:
            self.assertNotIn("root_cause", json.dumps(entry))

    def test_read_groups_rejects_bad_input(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.jsonl"
            bad.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(MODEL.InputError):
                TIMELINE.read_groups(bad)
            bad.write_text("", encoding="utf-8")
            with self.assertRaises(MODEL.InputError):
                TIMELINE.read_groups(bad)


class CliTests(unittest.TestCase):
    def test_cli_join_and_timeline(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            output = directory / "groups.jsonl"
            result = subprocess.run(
                [sys.executable, str(SCRIPTS / "correlate-events.py"),
                 "--ngap-events", str(NGAP_INPUT / "join-flow.jsonl"),
                 "--nas-events", str(NAS_INPUT / "join-flow.jsonl"),
                 "--output", str(output)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            timeline = subprocess.run(
                [sys.executable, str(SCRIPTS / "evidence-timeline.py"), str(output)],
                capture_output=True, text=True,
            )
            self.assertEqual(timeline.returncode, 0, timeline.stderr)
            self.assertIn("[STRONG]", timeline.stdout)

    def test_cli_requires_input_and_force(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            output = directory / "groups.jsonl"
            none = subprocess.run(
                [sys.executable, str(SCRIPTS / "correlate-events.py"), "--output", str(output)],
                capture_output=True, text=True,
            )
            self.assertEqual(none.returncode, MODEL.EXIT_NO_EVENTS)
            ok = subprocess.run(
                [sys.executable, str(SCRIPTS / "correlate-events.py"),
                 "--ngap-events", str(NGAP_INPUT / "ngap-only.jsonl"), "--output", str(output)],
                capture_output=True, text=True,
            )
            self.assertEqual(ok.returncode, 0)
            again = subprocess.run(
                [sys.executable, str(SCRIPTS / "correlate-events.py"),
                 "--ngap-events", str(NGAP_INPUT / "ngap-only.jsonl"), "--output", str(output)],
                capture_output=True, text=True,
            )
            self.assertEqual(again.returncode, MODEL.EXIT_OUTPUT_FAILURE)


class StandaloneTests(unittest.TestCase):
    def test_standalone_copy_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "cross-protocol-evidence"
            shutil.copytree(PACKAGE, copied)
            for name in ("correlate-events.py", "evidence-timeline.py"):
                result = subprocess.run([sys.executable, str(copied / "scripts" / name), "--help"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            output = copied / "groups.jsonl"
            result = subprocess.run(
                [sys.executable, str(copied / "scripts" / "correlate-events.py"),
                 "--ngap-events", str(copied / "examples" / "ngap-input" / "join-flow.jsonl"),
                 "--nas-events", str(copied / "examples" / "nas-input" / "join-flow.jsonl"),
                 "--output", str(output)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            timeline = subprocess.run(
                [sys.executable, str(copied / "scripts" / "evidence-timeline.py"), str(output)],
                capture_output=True, text=True,
            )
            self.assertEqual(timeline.returncode, 0, timeline.stderr)
            self.assertIn("[STRONG]", timeline.stdout)


if __name__ == "__main__":
    unittest.main()
