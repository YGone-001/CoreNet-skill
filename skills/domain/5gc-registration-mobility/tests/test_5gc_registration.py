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


class NgapInputContractTests(unittest.TestCase):
    """The Domain input contract separates valid unowned evidence from malformed input."""

    @staticmethod
    def ngap_record(**overrides):
        """A canonical detailed NGAP event as emitted by the ngap Skill.

        procedure_code 21 (NGSetup) is recognized by the Protocol Skill but
        intentionally not owned, so identity is null by contract.
        """
        record = {
            "amf_ue_ngap_id": None,
            "capture_file": "reg.pcapng",
            "cause": None,
            "derivations": ["procedure_name"],
            "destination": {"address": "127.0.0.5", "port": 38412},
            "evidence": {"level": "OBSERVED",
                         "source": "capture:reg.pcapng#frame=5; procedure-code=21; tshark-info=NGSetupRequest"},
            "frame_number": 5,
            "message_type": None,
            "nas_pdu_length": None,
            "nas_pdu_present": False,
            "paging_identity_present": False,
            "pdu_type": None,
            "pdu_type_basis": None,
            "procedure_code": 21,
            "procedure_name": "NGSetup",
            "ran_ue_ngap_id": None,
            "result": None,
            "rrc_establishment_cause": None,
            "sctp": {"association_id": 65535, "dstport": 38412, "srcport": 52677, "stream_id": 0},
            "sender_role": None,
            "source": {"address": "127.0.0.1", "port": 52677},
            "support_status": "UNSUPPORTED",
            "timestamp": "2024-01-02T03:04:05.00Z",
            "user_location_information_present": False,
        }
        record.update(overrides)
        return record

    def load(self, directory: Path, records: list[dict], name: str = "ngap.jsonl") -> Path:
        path = directory / name
        path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
        return path

    def scenario_ngap(self, name: str) -> list[dict]:
        return jsonl(INPUTS / name / "ngap.jsonl")

    def analyze_with(self, directory: Path, extra: list[dict], scenario: str = "full-registration"):
        ngap_path = self.load(directory, self.scenario_ngap(scenario) + extra)
        nas_path = INPUTS / scenario / "nas.jsonl"
        return MODEL.analyze(MODEL.load_ngap_events(ngap_path), MODEL.load_nas_events(nas_path), [], RULES)

    def test_case_a_supported_with_identity_is_accepted(self):
        record = self.ngap_record(support_status="SUPPORTED", message_type="InitialUEMessage")
        with tempfile.TemporaryDirectory() as directory:
            events = MODEL.load_ngap_events(self.load(Path(directory), [record]))
            self.assertEqual(len(events), 1)
            self.assertFalse(MODEL.is_unowned_ngap_event(events[0]))

    def test_case_c_recognized_unsupported_is_accepted_as_unowned(self):
        with tempfile.TemporaryDirectory() as directory:
            events = MODEL.load_ngap_events(self.load(Path(directory), [self.ngap_record()]))
            self.assertEqual(len(events), 1)
            self.assertTrue(MODEL.is_unowned_ngap_event(events[0]))
            self.assertIsNone(events[0]["message_type"])
            self.assertEqual(events[0]["frame_number"], 5)
            self.assertEqual(events[0]["capture_file"], "reg.pcapng")

    def test_case_b_supported_without_identity_fails_loudly(self):
        record = self.ngap_record(support_status="SUPPORTED")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODEL.InputError, "support_status SUPPORTED"):
                MODEL.load_ngap_events(self.load(Path(directory), [record]))

    def test_case_d_unknown_status_without_identity_fails_loudly(self):
        record = self.ngap_record(support_status="UNKNOWN", procedure_name=None, derivations=[])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODEL.InputError, "not a reviewed Protocol ownership declaration"):
                MODEL.load_ngap_events(self.load(Path(directory), [record]))

    def test_case_d_absent_status_without_identity_fails_loudly(self):
        record = self.ngap_record(support_status=None)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODEL.InputError, "not a reviewed Protocol ownership declaration"):
                MODEL.load_ngap_events(self.load(Path(directory), [record]))

    def test_reviewed_contradictory_status_with_identity_stays_owned(self):
        # Reviewed decision: identity decides usability, matching the Protocol
        # health contract, so a named message is never reclassified as unowned.
        record = self.ngap_record(message_type="HandoverSuccess")
        with tempfile.TemporaryDirectory() as directory:
            events = MODEL.load_ngap_events(self.load(Path(directory), [record]))
            self.assertFalse(MODEL.is_unowned_ngap_event(events[0]))

    def test_missing_mandatory_provenance_fails_loudly(self):
        record = self.ngap_record()
        del record["capture_file"]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODEL.InputError, "capture_file"):
                MODEL.load_ngap_events(self.load(Path(directory), [record]))

    def test_malformed_frame_number_fails_loudly(self):
        for bad in (0, "5", True, None):
            with self.subTest(frame=bad):
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaisesRegex(MODEL.InputError, "frame_number"):
                        MODEL.load_ngap_events(self.load(Path(directory), [self.ngap_record(frame_number=bad)]))

    def test_unsupported_only_capture_creates_no_procedure(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            result = self.analyze_with(directory, [self.ngap_record()], scenario="full-registration")
            baseline = MODEL.analyze(MODEL.load_ngap_events(INPUTS / "full-registration" / "ngap.jsonl"),
                                     MODEL.load_nas_events(INPUTS / "full-registration" / "nas.jsonl"), [], RULES)
            self.assertEqual(len(baseline["analyses"]), 1)
            unowned_only = MODEL.analyze(
                MODEL.load_ngap_events(self.load(directory, [self.ngap_record()], "unowned-only.jsonl")), [], [], RULES)
            self.assertEqual(unowned_only["analyses"], [])
            self.assertEqual(unowned_only["stage_records"], [])

    def test_unsupported_preamble_does_not_block_registration_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            baseline = MODEL.analyze(MODEL.load_ngap_events(INPUTS / "full-registration" / "ngap.jsonl"),
                                     MODEL.load_nas_events(INPUTS / "full-registration" / "nas.jsonl"), [], RULES)
            with_preamble = self.analyze_with(directory, [self.ngap_record()])
            self.assertEqual(len(with_preamble["analyses"]), 1)
            self.assertEqual(with_preamble["analyses"], baseline["analyses"])
            self.assertEqual(with_preamble["stage_records"], baseline["stage_records"])

    def test_unsupported_preamble_sharing_the_association_stays_out_of_the_instance(self):
        shared = self.ngap_record(sctp={"association_id": 0, "dstport": 38412, "srcport": 52677, "stream_id": 0})
        with tempfile.TemporaryDirectory() as directory:
            result = self.analyze_with(Path(directory), [shared])
            instance = result["analyses"][0]
            self.assertEqual(instance["context"]["ngap_context"]["ran_ue_ngap_id"], 1)
            self.assertEqual(instance["observation_window"]["first_frame"], 10)
            self.assertEqual(instance["observation_window"]["last_frame"], 21)

    def test_repeated_unsupported_records_create_no_duplicate_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.analyze_with(Path(directory), [self.ngap_record(), self.ngap_record()])
            self.assertEqual(len(result["analyses"]), 1)
            for instance in result["analyses"]:
                self.assertNotIn(MODEL.DEVIATION_DUPLICATE, {d["type"] for d in instance["deviations"]})

    def test_unsupported_records_do_not_merge_ue_contexts(self):
        unowned = [self.ngap_record(frame_number=5),
                   self.ngap_record(frame_number=6, timestamp="2024-01-02T03:04:06.00Z")]
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            ngap_path = self.load(directory, self.scenario_ngap("two-ue") + unowned)
            result = MODEL.analyze(MODEL.load_ngap_events(ngap_path),
                                   MODEL.load_nas_events(INPUTS / "two-ue" / "nas.jsonl"), [], RULES)
            self.assertEqual(len(result["analyses"]), 2)
            self.assertEqual({i["context"]["ngap_context"]["ran_ue_ngap_id"] for i in result["analyses"]}, {1, 2})

    def test_unsupported_records_do_not_merge_sctp_associations(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            baseline = MODEL.analyze(MODEL.load_ngap_events(INPUTS / "cross-association" / "ngap.jsonl"),
                                     MODEL.load_nas_events(INPUTS / "cross-association" / "nas.jsonl"), [], RULES)
            ngap_path = self.load(directory, self.scenario_ngap("cross-association")
                                  + [self.ngap_record(sctp={"association_id": 7, "dstport": 38412,
                                                            "srcport": 52677, "stream_id": 0})])
            with_unowned = MODEL.analyze(MODEL.load_ngap_events(ngap_path),
                                         MODEL.load_nas_events(INPUTS / "cross-association" / "nas.jsonl"), [], RULES)
            self.assertEqual(with_unowned["analyses"], baseline["analyses"])

    def test_unsupported_record_is_not_an_identifier_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.analyze_with(Path(directory),
                                       [self.ngap_record(ran_ue_ngap_id=1, amf_ue_ngap_id=99)])
            instance = result["analyses"][0]
            self.assertEqual(instance["context"]["ngap_context"]["amf_ue_ngap_id"], 2)
            self.assertEqual(result["correlation_conflicts"], [])


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


class ProtectedEnvelopeCarrierTests(unittest.TestCase):
    """corr-01: a ciphered NAS envelope is reported once, not twice.

    A security-protected record exposes no message-type octet at all, so its
    lower-layer UNKNOWN status is the protected-envelope limitation itself and
    must not also surface as an unknown or reserved protocol value. A genuinely
    dissected message-type byte the Domain does not own keeps its protocol-value
    deviation.
    """

    FIXTURE = "ciphered-envelope-unknown-status"

    @staticmethod
    def types(deviations):
        return [deviation["type"] for deviation in deviations]

    def fixture_events(self):
        source = INPUTS / self.FIXTURE
        return (MODEL.load_ngap_events(source / "ngap.jsonl"),
                MODEL.load_nas_events(source / "nas.jsonl"),
                MODEL.load_correlation_groups(source / "correlation.jsonl"))

    def deviations_for(self, nas_events, correlation=None):
        ngap, _nas, own_corr = self.fixture_events()
        document = MODEL.analyze(ngap, nas_events,
                                 own_corr if correlation is None else correlation, RULES)
        return document["analyses"][0]["deviations"]

    def test_ciphered_envelopes_report_only_the_protected_limitation(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario(self.FIXTURE, Path(directory))
        deviations = analysis["analyses"][0]["deviations"]
        self.assertEqual(self.types(deviations).count("UNKNOWN_OR_RESERVED_PROTOCOL_VALUE"), 0)
        self.assertEqual(self.types(deviations).count("PROTECTED_INNER_MESSAGE_UNAVAILABLE"), 2)
        frames = sorted(ref["frame_number"] for deviation in deviations
                        if deviation["type"] == "PROTECTED_INNER_MESSAGE_UNAVAILABLE"
                        for ref in deviation["evidence_refs"])
        self.assertEqual(frames, [12, 13])

    def test_one_physical_observation_never_yields_two_deviation_types(self):
        carriers = [deviation for deviation in self.deviations_for(self.fixture_events()[1])
                    if deviation["type"] in ("UNKNOWN_OR_RESERVED_PROTOCOL_VALUE",
                                             "PROTECTED_INNER_MESSAGE_UNAVAILABLE")]
        by_frame: dict[int, set] = {}
        for deviation in carriers:
            for ref in deviation["evidence_refs"]:
                by_frame.setdefault(ref["frame_number"], set()).add(deviation["type"])
        self.assertEqual(by_frame, {12: {"PROTECTED_INNER_MESSAGE_UNAVAILABLE"},
                                    13: {"PROTECTED_INNER_MESSAGE_UNAVAILABLE"}})

    def test_unknown_support_without_security_object_still_reports_protocol_value(self):
        _ngap, nas, _corr = self.fixture_events()
        stripped = [{key: value for key, value in event.items() if key != "security"}
                    if event.get("support_status") == "UNKNOWN" else event for event in nas]
        types = self.types(self.deviations_for(stripped, correlation=[]))
        self.assertEqual(types.count("UNKNOWN_OR_RESERVED_PROTOCOL_VALUE"), 2,
                         "an unknown status with no stated protected envelope stays reported")
        self.assertEqual(types.count("PROTECTED_INNER_MESSAGE_UNAVAILABLE"), 0)

    def test_genuinely_dissected_unsupported_message_type_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("unsupported-nas", Path(directory))
        deviations = analysis["analyses"][0]["deviations"]
        unknown = [d for d in deviations if d["type"] == "UNKNOWN_OR_RESERVED_PROTOCOL_VALUE"]
        self.assertEqual(len(unknown), 1)
        ref = unknown[0]["evidence_refs"][0]
        self.assertEqual([ref["frame_number"], ref["message_type"]], [11, "Deregistration request (UE originating)"])
        self.assertEqual(self.types(deviations).count("PROTECTED_INNER_MESSAGE_UNAVAILABLE"), 0)

    def test_unowned_ngap_unknown_record_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("unknown-ngap", Path(directory))
        deviations = analysis["analyses"][0]["deviations"]
        unknown = [d for d in deviations if d["type"] == "UNKNOWN_OR_RESERVED_PROTOCOL_VALUE"]
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0]["evidence_refs"][0]["message_type"], "UnknownProcedure")

    def test_supported_protected_envelope_family_shape_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("protected-unavailable", Path(directory))
        deviations = analysis["analyses"][0]["deviations"]
        self.assertEqual(self.types(deviations).count("PROTECTED_INNER_MESSAGE_UNAVAILABLE"), 1)
        self.assertEqual(self.types(deviations).count("UNKNOWN_OR_RESERVED_PROTOCOL_VALUE"), 0)

    def test_confidence_and_terminal_are_unaffected_by_the_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario(self.FIXTURE, Path(directory))
        instance = analysis["analyses"][0]
        self.assertEqual(instance["confidence"], "LOW")
        self.assertEqual(instance["terminal"]["observation"],
                         "NO_REGISTRATION_TERMINAL_OBSERVATION_IN_WINDOW")


if __name__ == "__main__":
    unittest.main()
