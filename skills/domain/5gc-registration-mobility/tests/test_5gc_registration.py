"""Package-local test suite for 5gc-registration-mobility."""

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
RULES = PACKAGE / "rules"
INPUTS = PACKAGE / "examples" / "inputs"
EXPECTED = PACKAGE / "examples" / "expected"
sys.path.insert(0, str(SCRIPTS))

import procedure_model as MODEL


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ANALYZE = load_script("analyze-registration")
TIMELINE = load_script("registration_timeline")


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_scenario(name: str, directory: Path) -> tuple[dict, list[dict]]:
    source = INPUTS / name
    analysis_path = directory / f"{name}-analysis.json"
    stages_path = directory / f"{name}-stages.jsonl"
    argv = ["--ngap", str(source / "ngap.jsonl"), "--nas", str(source / "nas.jsonl"),
            "--output", str(analysis_path), "--stage-output", str(stages_path), "--force"]
    if (source / "correlation.jsonl").stat().st_size > 0:
        argv.extend(["--correlation", str(source / "correlation.jsonl")])
    rc = ANALYZE.main(argv)
    assert rc == 0, f"scenario {name} failed with {rc}"
    return json.loads(analysis_path.read_text(encoding="utf-8")), jsonl(stages_path)


def first_instance(analysis: dict) -> dict:
    return analysis["analyses"][0]


from pathlib import Path as _Path
_policy_module_path = _Path(__file__).resolve().parents[4] / "scripts" / "implementation_policy.py"
_policy_spec = importlib.util.spec_from_file_location(
    "implementation_policy", _policy_module_path)
_POLICY = importlib.util.module_from_spec(_policy_spec)
assert _policy_spec.loader is not None
_policy_spec.loader.exec_module(_POLICY)

class ScenarioExpectedTests(unittest.TestCase):
    """Every committed scenario reproduces its committed expected output."""

    def test_all_scenarios_match_expected(self):
        for source in sorted(path for path in INPUTS.iterdir() if path.is_dir()):
            name = source.name
            with self.subTest(scenario=name):
                with tempfile.TemporaryDirectory() as directory:
                    analysis, stages = run_scenario(name, Path(directory))
                    expected_analysis = json.loads((EXPECTED / f"{name}-analysis.json").read_text(encoding="utf-8"))
                    expected_stages = jsonl(EXPECTED / f"{name}-stages.jsonl")
                    self.assertEqual(analysis, expected_analysis, name)
                    self.assertEqual(stages, expected_stages, name)

    def test_deterministic_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            first = run_scenario("full-registration", Path(directory))
            second = run_scenario("full-registration", Path(directory))
            self.assertEqual(first, second)


class ProcedureModelTests(unittest.TestCase):
    def test_rules_load_and_stay_conditional(self):
        rules = MODEL.load_rules(RULES)
        by_id = {stage["stage_id"]: stage for stage in rules["stages"]}
        for stage_id in ("identity", "authentication", "security-mode"):
            self.assertTrue(by_id[stage_id]["conditional"], stage_id)
        # A hard-coded mandatory linear chain would make these unconditional.
        self.assertFalse(by_id["registration-initiation"]["conditional"])

    def test_initiation_and_decision_observed(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("full-registration", Path(directory))
            instance = first_instance(analysis)
            stage_ids = {record["stage"]["stage_id"] for record in instance["stage_records"]}
            self.assertIn("registration-initiation", stage_ids)
            self.assertIn("registration-decision", stage_ids)
            self.assertIn("registration-completion", stage_ids)

    def test_conditional_branches_validly_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario in ("skip-identity", "skip-authentication"):
                analysis, _stages = run_scenario(scenario, Path(directory))
                instance = first_instance(analysis)
                self.assertEqual(instance["terminal"]["observation"], MODEL.TERMINAL_COMPLETE, scenario)
                self.assertEqual(instance["confidence"], "HIGH", scenario)
                self.assertEqual(instance["deviations"], [], scenario)

    def test_identity_branch_entered(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, stages = run_scenario("identity-branch", Path(directory))
            instance = first_instance(analysis)
            stage_ids = {record["stage"]["stage_id"] for record in instance["stage_records"]}
            self.assertIn("identity", stage_ids)
            self.assertEqual(instance["terminal"]["observation"], MODEL.TERMINAL_COMPLETE)

    def test_registration_reject_with_cause_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("registration-reject", Path(directory))
            instance = first_instance(analysis)
            self.assertEqual(instance["terminal"]["observation"], MODEL.TERMINAL_REJECT)
            self.assertIn(MODEL.DEVIATION_PROTOCOL_REJECT, {d["type"] for d in instance["deviations"]})
            causes = [f for f in instance["field_findings"] if f["field_name"] == "5GMM cause"]
            self.assertTrue(causes)
            self.assertEqual(causes[0]["normalized_value"], "Congestion")
            self.assertEqual(causes[0]["observed_value"]["code"], 22)

    def test_authentication_failure_and_reject(self):
        for scenario, deviation in (("auth-failure", MODEL.DEVIATION_UNSUCCESSFUL), ("auth-reject", MODEL.DEVIATION_PROTOCOL_REJECT)):
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as directory:
                    analysis, _stages = run_scenario(scenario, Path(directory))
                    instance = first_instance(analysis)
                    self.assertIn(deviation, {d["type"] for d in instance["deviations"]})
                    self.assertTrue(any(f["field_name"] == "5GMM cause" for f in instance["field_findings"]) or scenario == "auth-reject")

    def test_security_mode_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("security-reject", Path(directory))
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_PROTOCOL_REJECT, {d["type"] for d in instance["deviations"]})
            self.assertTrue(any(f["field_name"] == "5GMM cause" for f in instance["field_findings"]))

    def test_missing_expected_counterpart(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario in ("security-command-truncated", "auth-truncated", "accept-no-complete"):
                analysis, _stages = run_scenario(scenario, Path(directory))
                instance = first_instance(analysis)
                self.assertIn(MODEL.DEVIATION_MISSING_COUNTERPART, {d["type"] for d in instance["deviations"]}, scenario)

    def test_initial_context_setup_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            _a, _s = run_scenario("ics-success", Path(directory))
            success = json.loads((EXPECTED / "ics-success-analysis.json").read_text(encoding="utf-8"))
            self.assertTrue(success["analyses"])
            analysis, _stages = run_scenario("ics-failure", Path(directory))
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, {d["type"] for d in instance["deviations"]})
            ngap_causes = [f for f in instance["field_findings"] if f["field_name"] == "NGAP cause"]
            self.assertTrue(ngap_causes)
            self.assertEqual(ngap_causes[0]["normalized_value"], "radioNetwork:3")

    def test_release_initiator_is_not_root_cause(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("complete-then-release", Path(directory))
            instance = first_instance(analysis)
            # Completion evidence survives the later release untouched.
            self.assertEqual(instance["terminal"]["observation"], MODEL.TERMINAL_COMPLETE)
            blob = json.dumps(instance).lower()
            self.assertNotIn("root_cause", blob)
            self.assertNotIn("root cause", blob)
            self.assertNotIn("caused", blob)

    def test_paging_without_response_and_service(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("release-paging-no-response", Path(directory))
            blob = json.dumps(analysis).lower()
            self.assertIn("not observed within the available observation window", blob)
            self.assertNotIn("paging failed", blob)
            _a, _s = run_scenario("paging-then-service", Path(directory))
            _b, _t = run_scenario("service-reject", Path(directory))
            reject = _b["analyses"][0]
            self.assertIn(MODEL.DEVIATION_PROTOCOL_REJECT, {d["type"] for d in reject["deviations"]})


class MultiUeSafetyTests(unittest.TestCase):
    def test_two_interleaved_ues_stay_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("two-ue", Path(directory))
            self.assertEqual(len(analysis["analyses"]), 2)
            for instance in analysis["analyses"]:
                self.assertEqual(instance["terminal"]["observation"], MODEL.TERMINAL_COMPLETE)
                ran_ids = {event.get("ran_ue_ngap_id") for event in instance["events"] if event["protocol"] == "NGAP"}
                self.assertEqual(len(ran_ids), 1)

    def test_same_numeric_id_across_associations_do_not_merge(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("cross-association", Path(directory))
            self.assertEqual(len(analysis["analyses"]), 2)
            associations = {instance["context"]["association"] for instance in analysis["analyses"]}
            self.assertEqual(len(associations), 2)

    def test_binding_conflict_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("binding-conflict", Path(directory))
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_CORRELATION_CONFLICT, {d["type"] for d in instance["deviations"]})
            self.assertEqual(instance["confidence"], "LOW")
            self.assertTrue(analysis["correlation_conflicts"])


class EvidenceBoundaryTests(unittest.TestCase):
    def test_out_of_order_normalized_and_flagged(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("out-of-order", Path(directory))
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_OUT_OF_ORDER, {d["type"] for d in instance["deviations"]})
            timestamps = [event["timestamp"] for event in instance["events"]]
            self.assertEqual(timestamps, sorted(timestamps))
            self.assertEqual(instance["terminal"]["observation"], MODEL.TERMINAL_COMPLETE)

    def test_duplicate_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("duplicate", Path(directory))
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_DUPLICATE, {d["type"] for d in instance["deviations"]})

    def test_partial_capture_flagged(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("partial-start", Path(directory))
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_PARTIAL_CAPTURE, {d["type"] for d in instance["deviations"]})

    def test_protected_inner_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("protected-unavailable", Path(directory))
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_PROTECTED_UNAVAILABLE, {d["type"] for d in instance["deviations"]})

    def test_unknown_and_unsupported_preserved(self):
        for scenario in ("unsupported-nas", "unknown-ngap"):
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as directory:
                    analysis, _stages = run_scenario(scenario, Path(directory))
                    instance = first_instance(analysis)
                    self.assertIn(MODEL.DEVIATION_UNKNOWN_VALUE, {d["type"] for d in instance["deviations"]})

    def test_unbound_evidence_stays_unbound(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            ngap_path = directory / "ngap.jsonl"
            nas_path = directory / "nas.jsonl"
            ngap_path.write_text(json.dumps({
                "timestamp": "2024-01-02T03:04:10Z", "frame_number": 10, "capture_file": "c.pcapng",
                "message_type": "InitialUEMessage", "procedure_name": "InitialUEMessage",
                "support_status": "SUPPORTED", "ran_ue_ngap_id": 1, "amf_ue_ngap_id": None,
                "sctp": {"association_id": 0}, "cause": None,
            }) + "\n", encoding="utf-8")
            nas_path.write_text(json.dumps({
                "timestamp": "2024-01-02T03:04:30Z", "frame_number": 30, "capture_file": "c.pcapng",
                "nas_family": "5GMM", "message_type": "Registration accept", "support_status": "SUPPORTED",
                "cause": {"code": None, "name": None},
                "security": {"inner_message_available": True}, "security_mode": {}, "registration": {}, "identity": {"value": None},
            }) + "\n", encoding="utf-8")
            result = MODEL.analyze(MODEL.load_ngap_events(ngap_path), MODEL.load_nas_events(nas_path), [], RULES)
            self.assertEqual(len(result["unbound_records"]), 1)
            self.assertIn("UNBOUND", result["unbound_records"][0]["stage"]["stage_name"])
            self.assertIn("no association was invented", result["unbound_records"][0]["limitations"][0])

    def test_observation_window_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _stages = run_scenario("full-registration", Path(directory))
            window = first_instance(analysis)["observation_window"]
            self.assertEqual(window["first_frame"], 10)
            self.assertEqual(window["last_frame"], 21)

    def test_no_verdict_fields_anywhere(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario in ("full-registration", "registration-reject", "release-paging-no-response"):
                analysis, stages = run_scenario(scenario, Path(directory))
                blob = json.dumps([analysis, stages]).lower()
                for forbidden in ("root_cause", "root cause", "implementation_bug", "vendor", "product_bug"):
                    self.assertNotIn(forbidden, blob, scenario)

    def test_stage_records_match_generic_contract(self):
        schema = json.loads((PACKAGE / "schemas" / "procedure-evidence.schema.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            _analysis, stages = run_scenario("full-registration", Path(directory))
            for record in stages:
                self.assertEqual(set(record), set(schema["properties"]))
                self.assertIn(record["evidence_basis"], ("OBSERVED", "DERIVED"))
                self.assertIn(record["confidence"], ("HIGH", "MEDIUM", "LOW"))


class LoadingAndSafetyTests(unittest.TestCase):
    def test_5gsm_family_refused(self):
        record = {"timestamp": "t", "frame_number": 1, "capture_file": "c", "nas_family": "5GSM", "message_type": "x"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nas.jsonl"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaises(MODEL.InputError):
                MODEL.load_nas_events(path)

    def test_missing_provenance_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ngap.jsonl"
            path.write_text(json.dumps({"timestamp": "t", "frame_number": 0, "capture_file": "c", "message_type": "x"}) + "\n", encoding="utf-8")
            with self.assertRaises(MODEL.InputError):
                MODEL.load_ngap_events(path)

    def test_sanitizer_rejects_verdict_output(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.sanitize_output({"summary": "the root cause was found"})

    def test_no_vendor_mapping_in_sources(self):
        for script in SCRIPTS.glob("*.py"):
            text = script.read_text(encoding="utf-8").lower()
            for token in sorted(_POLICY.PROHIBITED_TOKENS) + ["ueransim", "srsran", "tshark"]:
                self.assertNotIn(token, text)


class CliTests(unittest.TestCase):
    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            none = subprocess.run([sys.executable, str(SCRIPTS / "analyze-registration.py"), "--output", str(directory / "a.json")], capture_output=True, text=True)
            self.assertEqual(none.returncode, MODEL.EXIT_NO_EVENTS)
            malformed = subprocess.run(
                [sys.executable, str(SCRIPTS / "analyze-registration.py"),
                 "--ngap", str(INPUTS / "full-registration" / "ngap.jsonl"),
                 "--output", str(directory / "b.json"), "--force"],
                capture_output=True, text=True,
            )
            self.assertEqual(malformed.returncode, 0)
            again = subprocess.run(
                [sys.executable, str(SCRIPTS / "analyze-registration.py"),
                 "--ngap", str(INPUTS / "full-registration" / "ngap.jsonl"),
                 "--output", str(directory / "b.json")],
                capture_output=True, text=True,
            )
            self.assertEqual(again.returncode, MODEL.EXIT_OUTPUT_FAILURE)

    def test_timeline_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            analysis_path = directory / "a.json"
            ANALYZE.main(["--ngap", str(INPUTS / "full-registration" / "ngap.jsonl"),
                          "--nas", str(INPUTS / "full-registration" / "nas.jsonl"),
                          "--correlation", str(INPUTS / "full-registration" / "correlation.jsonl"),
                          "--output", str(analysis_path), "--force"])
            text = subprocess.run([sys.executable, str(SCRIPTS / "registration_timeline.py"), str(analysis_path)], capture_output=True, text=True)
            self.assertEqual(text.returncode, 0, text.stderr)
            self.assertIn("instance=5gc-reg:", text.stdout)
            self.assertIn("Registration accept", text.stdout)
            self.assertNotIn("NETWORK OK", text.stdout.upper())
            self.assertNotIn("AMF FAILURE", text.stdout.upper())
            as_json = subprocess.run([sys.executable, str(SCRIPTS / "registration_timeline.py"), str(analysis_path), "--format", "json"], capture_output=True, text=True)
            self.assertEqual(as_json.returncode, 0)
            document = json.loads(as_json.stdout)
            self.assertEqual(len(document["timeline"]), 1)


class StandaloneTests(unittest.TestCase):
    def test_standalone_copy_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "5gc-registration-mobility"
            shutil.copytree(PACKAGE, copied, ignore=shutil.ignore_patterns("__pycache__"))
            result = subprocess.run(
                [sys.executable, str(copied / "scripts" / "analyze-registration.py"),
                 "--ngap", str(copied / "examples" / "inputs" / "two-ue" / "ngap.jsonl"),
                 "--nas", str(copied / "examples" / "inputs" / "two-ue" / "nas.jsonl"),
                 "--correlation", str(copied / "examples" / "inputs" / "two-ue" / "correlation.jsonl"),
                 "--output", str(copied / "analysis.json"), "--stage-output", str(copied / "stages.jsonl")],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads((copied / "analysis.json").read_text(encoding="utf-8"))
            self.assertEqual(len(document["analyses"]), 2)
            timeline = subprocess.run(
                [sys.executable, str(copied / "scripts" / "registration_timeline.py"), str(copied / "analysis.json")],
                capture_output=True, text=True,
            )
            self.assertEqual(timeline.returncode, 0, timeline.stderr)
            self.assertIn("instance=5gc-reg:", timeline.stdout)


if __name__ == "__main__":
    unittest.main()
