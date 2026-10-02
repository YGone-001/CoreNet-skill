"""Package-local test suite for the procedure evidence framework."""

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

import procedure_model as MODEL

STAGES = PACKAGE / "examples" / "stages"
EXPECTED = PACKAGE / "examples" / "expected"


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


TIMELINE = load_script("procedure_timeline")


def records(name: str) -> list[dict]:
    return MODEL.load_records(STAGES / name)


def record(**overrides) -> dict:
    base = {
        "procedure_name": "example-signaling-procedure",
        "procedure_version": "1.0",
        "observation_group": "capture-group-1",
        "stage": {
            "stage_id": "stage-01",
            "stage_name": "initial contact",
            "expected_protocols": ["NGAP"],
            "expected_message_types": ["GenericInitialMessage"],
        },
        "expected_evidence": ["an initial message is present"],
        "observed_evidence": ["an initial message was observed at frame 10"],
        "missing_evidence": [],
        "evidence_basis": "OBSERVED",
        "confidence": "HIGH",
        "limitations": [],
    }
    base.update(overrides)
    return base


class SchemaConformanceTests(unittest.TestCase):
    def test_expected_fixtures_conform_structurally(self):
        schema = json.loads((PACKAGE / "schemas" / "procedure-evidence.schema.json").read_text(encoding="utf-8"))
        for name in ("observed-flow.jsonl", "missing-evidence.jsonl", "derived-flow.jsonl"):
            for record in records(name):
                self.assertEqual(set(record), set(schema["properties"]), name)
                self.assertEqual(set(record["stage"]), set(schema["properties"]["stage"]["properties"]))
                self.assertIn(record["evidence_basis"], ("OBSERVED", "DERIVED"))
                self.assertIn(record["confidence"], ("HIGH", "MEDIUM", "LOW"))

    def test_schema_has_no_verdict_fields(self):
        schema = json.loads((PACKAGE / "schemas" / "procedure-evidence.schema.json").read_text(encoding="utf-8"))
        blob = json.dumps(schema["properties"]).lower()
        for forbidden in ("success", "failed", "root_cause", "root cause"):
            self.assertNotIn(forbidden, blob.lower())

    def test_schema_confidence_has_no_causal_values(self):
        schema = json.loads((PACKAGE / "schemas" / "procedure-evidence.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["confidence"]["enum"], ["HIGH", "MEDIUM", "LOW"])


class RecordValidationTests(unittest.TestCase):
    def test_missing_evidence_stays_missing(self):
        flow = records("missing-evidence.jsonl")
        self.assertTrue(all(record["missing_evidence"] for record in flow))
        self.assertTrue(all(record["observed_evidence"] == [] for record in flow))
        blob = json.dumps(flow).lower()
        self.assertNotIn("failed", blob)
        self.assertNotIn("success", blob)

    def test_observed_and_derived_separation(self):
        observed = records("observed-flow.jsonl")
        derived = records("derived-flow.jsonl")
        self.assertTrue(all(record["evidence_basis"] == "OBSERVED" for record in observed))
        self.assertEqual(derived[0]["evidence_basis"], "DERIVED")

    def test_malformed_records_rejected(self):
        with self.assertRaises(MODEL.InputError):
            records("malformed.jsonl")

    def test_invalid_basis_and_confidence_rejected(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.validate_record(record(evidence_basis="CONFIRMED"), 0)
        with self.assertRaises(MODEL.InputError):
            MODEL.validate_record(record(confidence="CERTAIN"), 0)

    def test_missing_required_field_rejected(self):
        bad = record()
        del bad["observation_group"]
        with self.assertRaises(MODEL.InputError):
            MODEL.validate_record(bad, 0)

    def test_non_object_line_rejected(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.validate_record("not-an-object", 0)

    def test_empty_stage_field_rejected(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.validate_record(record(stage={"stage_id": "", "stage_name": "x", "expected_protocols": [], "expected_message_types": []}), 0)


class VerdictBoundaryTests(unittest.TestCase):
    def test_verdict_wording_rejected_in_evidence(self):
        for field in ("expected_evidence", "observed_evidence", "missing_evidence", "limitations"):
            with self.assertRaises(MODEL.InputError):
                MODEL.validate_record(record(**{field: ["the procedure failed"]}), 0)

    def test_verdict_wording_rejected_in_names(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.validate_record(record(stage={"stage_id": "s", "stage_name": "successful stage", "expected_protocols": [], "expected_message_types": []}), 0)
        with self.assertRaises(MODEL.InputError):
            MODEL.validate_record(record(procedure_name="root cause finder"), 0)

    def test_timeline_output_never_contains_verdicts(self):
        for name in ("observed-flow.jsonl", "missing-evidence.jsonl", "derived-flow.jsonl"):
            text = MODEL.render_text(MODEL.timeline_entries(records(name)))
            for token in ("SUCCESS", "FAILED", "ROOT_CAUSE", "successful"):
                self.assertNotIn(token, text.upper() if token.isupper() else text)

    def test_protocol_cause_names_are_not_verdicts(self):
        allowed = MODEL.validate_record(record(observed_evidence=["lower layer reported a Synch failure cause"]), 0)
        self.assertEqual(allowed["observed_evidence"], ["lower layer reported a Synch failure cause"])


class PrivacyBoundaryTests(unittest.TestCase):
    def test_no_subscriber_or_session_fields(self):
        blob = json.dumps(records("observed-flow.jsonl")).lower()
        for forbidden in ("imsi", "supi", "suci", "msisdn", "guti", "subscriber", "pdu_session", "dnn", "qfi"):
            self.assertNotIn(forbidden, blob)

    def test_identity_keys_rejected_in_evidence_text(self):
        # The framework has no subscriber/session handling at all; evidence
        # statements stay at observation level.
        entry = MODEL.timeline_entries(records("observed-flow.jsonl"))[0]
        self.assertNotIn("identity", entry)


class TimelineTests(unittest.TestCase):
    def test_deterministic_ordering(self):
        first = MODEL.render_text(MODEL.timeline_entries(records("observed-flow.jsonl")))
        second = MODEL.render_text(MODEL.timeline_entries(records("observed-flow.jsonl")))
        self.assertEqual(first, second)
        self.assertIn("stage=stage-01", first)
        self.assertIn("stage=stage-03", first)
        self.assertLess(first.index("stage=stage-01"), first.index("stage=stage-03"))

    def test_expected_timeline_fixtures_match(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "observed.txt"
            entries = MODEL.timeline_entries(records("observed-flow.jsonl"))
            output.write_text(MODEL.render_text(entries), encoding="utf-8")
            expected = (EXPECTED / "observed-timeline.txt").read_text(encoding="utf-8")
            self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_json_timeline_fixture_matches(self):
        document = json.loads(MODEL.render_json(MODEL.timeline_entries(records("derived-flow.jsonl"))))
        expected = json.loads((EXPECTED / "derived-timeline.json").read_text(encoding="utf-8"))
        self.assertEqual(document, expected)

    def test_missing_evidence_shown_in_timeline(self):
        text = MODEL.render_text(MODEL.timeline_entries(records("missing-evidence.jsonl")))
        self.assertIn("missing evidence:", text)
        self.assertIn("not observed", text)


class CliTests(unittest.TestCase):
    def test_cli_text_json_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            text = subprocess.run(
                [sys.executable, str(SCRIPTS / "procedure_timeline.py"), str(STAGES / "observed-flow.jsonl")],
                capture_output=True, text=True,
            )
            self.assertEqual(text.returncode, 0, text.stderr)
            self.assertIn("missing evidence:", text.stdout)
            out_file = directory / "timeline.json"
            as_json = subprocess.run(
                [sys.executable, str(SCRIPTS / "procedure_timeline.py"), str(STAGES / "derived-flow.jsonl"), "--format", "json", "--output", str(out_file)],
                capture_output=True, text=True,
            )
            self.assertEqual(as_json.returncode, 0, as_json.stderr)
            self.assertTrue(out_file.is_file())
            malformed = subprocess.run(
                [sys.executable, str(SCRIPTS / "procedure_timeline.py"), str(STAGES / "malformed.jsonl")],
                capture_output=True, text=True,
            )
            self.assertEqual(malformed.returncode, MODEL.EXIT_MALFORMED_INPUT)
            empty = Path(directory) / "empty.jsonl"
            empty.write_text("", encoding="utf-8")
            no_records = subprocess.run(
                [sys.executable, str(SCRIPTS / "procedure_timeline.py"), str(empty)],
                capture_output=True, text=True,
            )
            self.assertEqual(no_records.returncode, MODEL.EXIT_NO_RECORDS)
            again = subprocess.run(
                [sys.executable, str(SCRIPTS / "procedure_timeline.py"), str(STAGES / "derived-flow.jsonl"), "--format", "json", "--output", str(out_file)],
                capture_output=True, text=True,
            )
            self.assertEqual(again.returncode, MODEL.EXIT_OUTPUT_FAILURE)

    def test_cli_output_has_no_verdict_tokens(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "procedure_timeline.py"), str(STAGES / "observed-flow.jsonl")],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        for token in ("SUCCESS", "FAILED", "ROOT_CAUSE"):
            self.assertNotIn(token, result.stdout.upper())


class NoProtocolDecodingTests(unittest.TestCase):
    def test_model_has_no_protocol_parsing(self):
        model_text = (SCRIPTS / "procedure_model.py").read_text(encoding="utf-8")
        for token in ("nas-5gs.", "ngap.", "procedureCode", "message_type_code", "5gmm_cause"):
            self.assertNotIn(token, model_text)

    def test_no_implementation_references(self):
        for script in SCRIPTS.glob("*.py"):
            text = script.read_text(encoding="utf-8").lower()
            for token in ("open5gs", "free5gc", "kamailio", "freeswitch", "rtpengine"):
                self.assertNotIn(token, text)


class StandaloneTests(unittest.TestCase):
    def test_standalone_copy_runs(self):
        # Runs the copied package's CLI and structure only; never re-runs the
        # test suite recursively (that would nest standalone copies forever).
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "procedure-evidence"
            shutil.copytree(PACKAGE, copied, ignore=shutil.ignore_patterns("__pycache__"))
            result = subprocess.run(
                [sys.executable, str(copied / "scripts" / "procedure_timeline.py"), "--help"],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((copied / "schemas" / "procedure-evidence.schema.json").is_file())
            self.assertTrue((copied / "references" / "evidence-model.md").is_file())
            timeline = subprocess.run(
                [sys.executable, str(copied / "scripts" / "procedure_timeline.py"), str(copied / "examples" / "stages" / "observed-flow.jsonl")],
                capture_output=True, text=True,
            )
            self.assertEqual(timeline.returncode, 0, timeline.stderr)
            self.assertIn("missing evidence:", timeline.stdout)


if __name__ == "__main__":
    unittest.main()
