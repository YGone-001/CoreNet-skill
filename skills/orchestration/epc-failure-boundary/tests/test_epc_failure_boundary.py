#!/usr/bin/env python3
"""Functional tests for bounded EPC failure-boundary orchestration."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
INPUTS = SKILL / "examples" / "inputs"
EXPECTED = SKILL / "examples" / "expected"

sys.path.insert(0, str(SCRIPTS))
import epc_boundary_model as model  # noqa: E402


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "analyze_epc_failure_boundary.py"), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def deviation(
    deviation_type: str,
    frame: int | None,
    *,
    refs: list[int] | None = None,
    window: tuple[int, int] | None = (1, 300),
    protocol: str = "GTPv2-C",
    message_type: str = "Create Session Response",
    level: str = "OBSERVED",
    cause_code: int | None = None,
    cause_scope: str | None = None,
    bearer_item_index: int | None = None,
    transaction: str = "tx-1",
) -> dict:
    payload = {
        "deviation_type": deviation_type,
        "frame_number": frame,
        "protocol": protocol,
        "message_type": message_type,
        "evidence_level": level,
        "evidence_refs": [
            {
                "frame_number": number,
                "protocol": protocol,
                "message_type": message_type,
                "evidence_level": level,
            }
            for number in (refs if refs is not None else ([frame] if frame is not None else []))
        ],
        "observation_window": (
            {"start_frame": window[0], "end_frame": window[1]} if window else None
        ),
        "limitations": [],
    }
    if transaction:
        payload["transaction_reference"] = transaction
    if cause_code is not None:
        payload["cause_code"] = cause_code
        payload["cause_scope"] = cause_scope
    if bearer_item_index is not None:
        payload["bearer_item_index"] = bearer_item_index
    return payload


def session_subject(
    reference: str = "epc-session-s11-aaaaaaaa",
    deviations: list[dict] | None = None,
    *,
    omitted: int = 0,
    strength: str = "STRONG",
    interface: str = "S11",
    capture: str = "capture.pcap",
    window: tuple[int, int] = (1, 300),
) -> dict:
    deviations = deviations if deviations is not None else []
    return {
        "subject_reference": reference,
        "subject_type": "EPC_SESSION_CONTROL",
        "interface": interface,
        "interface_evidence": {"interface": interface, "basis": "control_plane_f_teid_in_message"},
        "capture_file": capture,
        "association_strength": strength,
        "transaction_references": sorted({str(item.get("transaction_reference")) for item in deviations if item.get("transaction_reference")}),
        "procedure_local_deviations": deviations,
        "procedure_local_deviation_count": len(deviations) + omitted,
        "procedure_local_deviations_omitted": omitted,
        "observation_window": {"start_frame": window[0], "end_frame": window[1]},
        "limitations": [],
    }


def session_document(subjects: list[dict]) -> dict:
    return {
        "domain": "epc-procedures",
        "analysis_scope": "epc-session-control",
        "domain_version": "0.2.0",
        "control_plane_subjects": subjects,
    }


def attach_instance(
    reference: str,
    deviations: list[dict],
    *,
    capture: str = "capture.pcap",
    strength: str = "STRONG",
    association: str = "sctp-assoc-0",
    first: int = 1,
    last: int = 300,
) -> dict:
    return {
        "procedure_reference": reference,
        "procedure": "eps-attach",
        "attempt_index": 1,
        "association": {
            "basis": "pre_assignment_extension_unique_mme_identifier",
            "strength": strength,
            "capture_file": capture,
            "sctp_association": association,
        },
        "first_frame": first,
        "last_frame": last,
        "stages": [],
        "observations": [],
        "deviations": deviations,
        "evidence_limitations": [],
        "additional_evidence_needed": [],
    }


def attach_document(instances: list[dict]) -> dict:
    return {
        "domain": "epc-procedures",
        "procedure": "eps-attach",
        "domain_version": "0.1.0",
        "instance_count": len(instances),
        "procedure_instances": instances,
    }


class Workspace(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def analyze_docs(self, attach: dict | None = None, session: dict | None = None) -> dict:
        paths: list[Path] = []
        if attach is not None:
            path = self.directory / f"attach-{len(list(self.directory.glob('attach-*.json')))}.json"
            path.write_text(json.dumps(attach), encoding="utf-8")
            paths.append(path)
            return model.analyze(paths, [])
        path = self.directory / f"session-{len(list(self.directory.glob('session-*.json')))}.json"
        path.write_text(json.dumps(session), encoding="utf-8")
        return model.analyze([], [path])

    def group(self, analysis: dict, index: int = 0) -> dict:
        return analysis["diagnostic_groups"][index]


class SourceEvidenceTests(Workspace):
    def test_response_defined_rejection_anchors_at_the_response_frame(self) -> None:
        subject = session_subject(deviations=[deviation("CREATE_SESSION_REJECTED_OBSERVED", 106, refs=[100, 106])])
        analysis = self.analyze_docs(session=session_document([subject]))
        boundary = self.group(analysis)["first_abnormal_boundary"]
        self.assertEqual(boundary["frame_number"], 106)
        self.assertNotEqual(boundary["frame_number"], 100)

    def test_bearer_rejection_keeps_scope_and_item(self) -> None:
        subject = session_subject(
            deviations=[
                deviation(
                    "BEARER_CONTEXT_REJECTED_OBSERVED", 205,
                    cause_code=72, cause_scope="bearer", bearer_item_index=1,
                    message_type="Create Session Response",
                )
            ]
        )
        analysis = self.analyze_docs(session=session_document([subject]))
        boundary = self.group(analysis)["first_abnormal_boundary"]
        self.assertEqual(boundary["frame_number"], 205)
        self.assertEqual(boundary["cause_scope"], "bearer")
        self.assertEqual(boundary["bearer_item_index"], 1)

    def test_message_and_bearer_cause_stay_distinct(self) -> None:
        subject = session_subject(
            deviations=[
                deviation("BEARER_CONTEXT_REJECTED_OBSERVED", 205, cause_code=72, cause_scope="bearer", bearer_item_index=1)
            ]
        )
        analysis = self.analyze_docs(session=session_document([subject]))
        candidates = self.group(analysis)["boundary_candidates"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["deviation_type"], "BEARER_CONTEXT_REJECTED_OBSERVED")
        self.assertNotEqual(candidates[0].get("cause_scope"), "message")

    def test_open_request_is_not_selectable(self) -> None:
        subject = session_subject(deviations=[deviation("OPEN_REQUEST_OBSERVED", 100, refs=[100])])
        analysis = self.analyze_docs(session=session_document([subject]))
        group = self.group(analysis)
        self.assertEqual(group["boundary_selection_status"], "NO_ABNORMAL_BOUNDARY_OBSERVED")
        self.assertEqual(group["boundary_candidates"][0]["selection_eligibility"], "INELIGIBLE")

    def test_response_only_does_not_invent_a_request(self) -> None:
        subject = session_subject(deviations=[deviation("RESPONSE_ONLY_OBSERVED", 106, refs=[106])])
        analysis = self.analyze_docs(session=session_document([subject]))
        candidate = self.group(analysis)["boundary_candidates"][0]
        self.assertEqual(candidate["frame_number"], 106)
        self.assertEqual(candidate["selection_eligibility"], "INELIGIBLE")

    def test_ambiguous_transaction_blocks_selection(self) -> None:
        subject = session_subject(deviations=[deviation("AMBIGUOUS_TRANSACTION_OBSERVED", 300, refs=[300])])
        analysis = self.analyze_docs(session=session_document([subject]))
        self.assertEqual(
            self.group(analysis)["boundary_selection_status"], "INSUFFICIENT_COMPARABLE_EVIDENCE"
        )

    def test_anchor_absent_from_evidence_refs_is_ineligible(self) -> None:
        subject = session_subject(deviations=[deviation("CREATE_SESSION_REJECTED_OBSERVED", 106, refs=[100])])
        analysis = self.analyze_docs(session=session_document([subject]))
        candidate = self.group(analysis)["boundary_candidates"][0]
        self.assertEqual(candidate["selection_eligibility"], "INELIGIBLE")
        self.assertTrue(any("evidence references" in reason for reason in candidate["eligibility_reasons"]))

    def test_anchor_outside_observation_window_is_ineligible(self) -> None:
        subject = session_subject(
            deviations=[deviation("CREATE_SESSION_REJECTED_OBSERVED", 106, refs=[106], window=(200, 300))]
        )
        analysis = self.analyze_docs(session=session_document([subject]))
        candidate = self.group(analysis)["boundary_candidates"][0]
        self.assertEqual(candidate["selection_eligibility"], "INELIGIBLE")
        self.assertTrue(any("observation window" in reason for reason in candidate["eligibility_reasons"]))


class GroupFormationTests(Workspace):
    def test_two_attach_instances_stay_separate(self) -> None:
        document = attach_document([
            attach_instance("epc-attach-0001", [deviation("ATTACH_REJECT_OBSERVED", 47, protocol="NAS-EPS", message_type="Attach reject", transaction=None)]),
            attach_instance("epc-attach-0002", [deviation("ATTACH_REJECT_OBSERVED", 75, protocol="NAS-EPS", message_type="Attach reject", transaction=None)]),
        ])
        analysis = self.analyze_docs(attach=document)
        self.assertEqual(len(analysis["diagnostic_groups"]), 2)
        frames = [group["first_abnormal_boundary"]["frame_number"] for group in analysis["diagnostic_groups"]]
        self.assertEqual(frames, [47, 75])

    def test_repeated_attempts_of_one_ue_stay_separate(self) -> None:
        document = attach_document([
            attach_instance("epc-attach-0001", [deviation("ATTACH_REJECT_OBSERVED", 47, protocol="NAS-EPS", message_type="Attach reject", transaction=None)]),
            attach_instance("epc-attach-0001-attempt-2", [deviation("ATTACH_REJECT_OBSERVED", 111, protocol="NAS-EPS", message_type="Attach reject", transaction=None)]),
        ])
        analysis = self.analyze_docs(attach=document)
        self.assertEqual(len(analysis["diagnostic_groups"]), 2)
        self.assertEqual(
            len({group["diagnostic_group_reference"] for group in analysis["diagnostic_groups"]}), 2
        )

    def test_different_captures_never_merge(self) -> None:
        document = attach_document([
            attach_instance("epc-attach-0001", [deviation("ATTACH_REJECT_OBSERVED", 47, protocol="NAS-EPS", message_type="Attach reject", transaction=None)], capture="a.pcap"),
            attach_instance("epc-attach-0002", [deviation("ATTACH_REJECT_OBSERVED", 47, protocol="NAS-EPS", message_type="Attach reject", transaction=None)], capture="b.pcap"),
        ])
        analysis = self.analyze_docs(attach=document)
        captures = {
            group["source_domain_instances"][0]["capture_file"] for group in analysis["diagnostic_groups"]
        }
        self.assertEqual(captures, {"a.pcap", "b.pcap"})
        self.assertEqual(len(analysis["diagnostic_groups"]), 2)

    def test_different_sctp_associations_never_merge(self) -> None:
        document = attach_document([
            attach_instance("epc-attach-0001", [deviation("ATTACH_REJECT_OBSERVED", 47, protocol="NAS-EPS", message_type="Attach reject", transaction=None)], association="assoc-a"),
            attach_instance("epc-attach-0002", [deviation("ATTACH_REJECT_OBSERVED", 75, protocol="NAS-EPS", message_type="Attach reject", transaction=None)], association="assoc-b"),
        ])
        analysis = self.analyze_docs(attach=document)
        self.assertEqual(len(analysis["diagnostic_groups"]), 2)

    def test_s11_and_s5s8_subjects_stay_separate(self) -> None:
        document = load_json(INPUTS / "session-accepted" / "session-analysis.json")
        analysis = model.analyze([], [INPUTS / "session-accepted" / "session-analysis.json"])
        interfaces = {
            group["source_domain_instances"][0]["interface"] for group in analysis["diagnostic_groups"]
        }
        self.assertIn("S11", interfaces)
        self.assertIn("S5/S8", interfaces)
        self.assertEqual(len(analysis["diagnostic_groups"]), len(document["control_plane_subjects"]))

    def test_unknown_interface_is_not_guessed(self) -> None:
        analysis = model.analyze([], [INPUTS / "session-accepted" / "session-analysis.json"])
        unknown = [
            group for group in analysis["diagnostic_groups"]
            if group["source_domain_instances"][0]["interface"] == "UNKNOWN_INTERFACE"
        ]
        self.assertTrue(unknown)
        for group in unknown:
            self.assertEqual(group["source_domain_instances"][0]["interface"], "UNKNOWN_INTERFACE")

    def test_equal_ebi_does_not_join_subjects(self) -> None:
        first = session_subject("epc-session-s11-11111111", [deviation("CREATE_SESSION_REJECTED_OBSERVED", 106, refs=[106])])
        second = session_subject("epc-session-s5s8-22222222", [deviation("CREATE_SESSION_REJECTED_OBSERVED", 107, refs=[107], transaction="tx-2")], interface="S5/S8")
        analysis = self.analyze_docs(session=session_document([first, second]))
        self.assertEqual(len(analysis["diagnostic_groups"]), 2)
        self.assertEqual(
            [group["first_abnormal_boundary"]["frame_number"] for group in analysis["diagnostic_groups"]],
            [106, 107],
        )

    def test_equal_teid_does_not_merge_generations(self) -> None:
        first = session_subject("epc-session-s11-aaaa1111", [deviation("CREATE_SESSION_REJECTED_OBSERVED", 106, refs=[106])])
        second = session_subject("epc-session-s11-bbbb2222", [deviation("CREATE_SESSION_REJECTED_OBSERVED", 206, refs=[206], transaction="tx-2")])
        analysis = self.analyze_docs(session=session_document([first, second]))
        self.assertEqual(len(analysis["diagnostic_groups"]), 2)

    def test_attach_and_session_subjects_never_merge(self) -> None:
        analysis = model.analyze(
            [INPUTS / "mixed" / "attach-analysis.json"],
            [INPUTS / "mixed" / "session-analysis.json"],
        )
        types = [group["subject_type"] for group in analysis["diagnostic_groups"]]
        self.assertEqual(types.count("EPS_ATTACH"), 4)
        self.assertEqual(types.count("EPC_SESSION_CONTROL"), 1)
        for group in analysis["diagnostic_groups"]:
            self.assertEqual(group["subject_link"]["cross_subject_link"], "NOT_ESTABLISHED")


class SelectionTests(Workspace):
    def test_each_attach_negative_type_is_selectable(self) -> None:
        for deviation_type in sorted(model.ELIGIBLE_ATTACH):
            with self.subTest(deviation_type=deviation_type):
                document = attach_document([
                    attach_instance(
                        "epc-attach-0001",
                        [deviation(deviation_type, 47, protocol="NAS-EPS", message_type="Attach reject", transaction=None)],
                    )
                ])
                analysis = self.analyze_docs(attach=document)
                group = self.group(analysis)
                self.assertEqual(group["boundary_selection_status"], "SELECTED")
                self.assertEqual(group["first_abnormal_boundary"]["frame_number"], 47)
                self.assertEqual(group["boundary_confidence"], "HIGH")

    def test_each_session_negative_type_is_selectable(self) -> None:
        for deviation_type in sorted(model.ELIGIBLE_SESSION):
            with self.subTest(deviation_type=deviation_type):
                subject = session_subject(
                    deviations=[deviation(deviation_type, 106, refs=[106], cause_code=72, cause_scope="message")]
                )
                analysis = self.analyze_docs(session=session_document([subject]))
                group = self.group(analysis)
                self.assertEqual(group["boundary_selection_status"], "SELECTED")
                self.assertEqual(group["first_abnormal_boundary"]["frame_number"], 106)

    def test_earliest_candidate_wins_inside_one_subject(self) -> None:
        subject = session_subject(
            deviations=[
                deviation("DELETE_SESSION_REJECTED_OBSERVED", 210, refs=[210], transaction="tx-2"),
                deviation("CREATE_SESSION_REJECTED_OBSERVED", 106, refs=[106]),
            ]
        )
        analysis = self.analyze_docs(session=session_document([subject]))
        boundary = self.group(analysis)["first_abnormal_boundary"]
        self.assertEqual(boundary["frame_number"], 106)
        self.assertEqual(boundary["deviation_type"], "CREATE_SESSION_REJECTED_OBSERVED")

    def test_same_frame_candidates_are_ambiguous(self) -> None:
        subject = session_subject(
            deviations=[
                deviation("CREATE_SESSION_REJECTED_OBSERVED", 106, refs=[106], cause_code=72, cause_scope="message"),
                deviation("BEARER_CONTEXT_REJECTED_OBSERVED", 106, refs=[106], cause_code=73, cause_scope="bearer", bearer_item_index=0),
            ]
        )
        analysis = self.analyze_docs(session=session_document([subject]))
        group = self.group(analysis)
        self.assertEqual(group["boundary_selection_status"], "AMBIGUOUS_FIRST_BOUNDARY")
        self.assertIsNone(group["first_abnormal_boundary"])
        self.assertTrue(analysis["ambiguities"])

    def test_ordering_never_uses_severity(self) -> None:
        subject = session_subject(
            deviations=[
                deviation("DELETE_SESSION_REJECTED_OBSERVED", 250, refs=[250], transaction="tx-2"),
                deviation("CREATE_SESSION_REJECTED_OBSERVED", 106, refs=[106]),
            ]
        )
        analysis = self.analyze_docs(session=session_document([subject]))
        boundary = self.group(analysis)["first_abnormal_boundary"]
        self.assertEqual(boundary["frame_number"], 106)
        self.assertEqual(boundary["ordering_basis"], "exact_frame_number")

    def test_protected_nas_stays_a_limitation(self) -> None:
        document = attach_document([
            attach_instance(
                "epc-attach-0001",
                [
                    deviation("ATTACH_REJECT_OBSERVED", 47, protocol="NAS-EPS", message_type="Attach reject", transaction=None),
                    deviation("PROTECTED_INNER_MESSAGE_UNAVAILABLE", 47, protocol="NAS-EPS", message_type="Attach reject", transaction=None),
                ],
            )
        ])
        analysis = self.analyze_docs(attach=document)
        group = self.group(analysis)
        self.assertEqual(group["boundary_selection_status"], "SELECTED")
        types = [entry["type"] for entry in group["evidence_limitations"]]
        self.assertIn("PROTECTED_INNER_MESSAGE_UNAVAILABLE", types)
        protected = [item for item in group["boundary_candidates"] if item["deviation_type"] == "PROTECTED_INNER_MESSAGE_UNAVAILABLE"]
        self.assertEqual(protected[0]["selection_eligibility"], "INELIGIBLE")

    def test_missing_counterpart_is_not_a_failure(self) -> None:
        subject = session_subject(deviations=[deviation("OPEN_REQUEST_OBSERVED", 100, refs=[100])])
        analysis = self.analyze_docs(session=session_document([subject]))
        self.assertEqual(self.group(analysis)["boundary_selection_status"], "NO_ABNORMAL_BOUNDARY_OBSERVED")
        self.assertIsNone(self.group(analysis)["first_abnormal_boundary"])

    def test_accepted_cause_is_not_a_negative_result(self) -> None:
        analysis = model.analyze([], [INPUTS / "session-accepted" / "session-analysis.json"])
        for group in analysis["diagnostic_groups"]:
            self.assertEqual(group["boundary_selection_status"], "NO_ABNORMAL_BOUNDARY_OBSERVED")
            for candidate in group["boundary_candidates"]:
                self.assertNotIn(candidate["deviation_type"], model.ELIGIBLE_SESSION)

    def test_absence_of_boundary_does_not_imply_health(self) -> None:
        analysis = model.analyze([], [INPUTS / "session-accepted" / "session-analysis.json"])
        statements = " ".join(analysis["not_confirmed"]).lower()
        self.assertIn("not established", statements)
        self.assertNotIn("success", " ".join(
            group["boundary_selection_status"] for group in analysis["diagnostic_groups"]
        ).lower())

    def test_truncated_candidates_block_selection(self) -> None:
        analysis = model.analyze([], [INPUTS / "omitted" / "session-analysis.json"])
        group = self.group(analysis)
        self.assertEqual(group["boundary_selection_status"], "INSUFFICIENT_COMPARABLE_EVIDENCE")
        self.assertIsNone(group["first_abnormal_boundary"])
        self.assertGreater(group["boundary_candidates_omitted"], 0)

    def test_downstream_observations_are_not_attributed(self) -> None:
        document = attach_document([
            attach_instance(
                "epc-attach-0001",
                [
                    deviation("ATTACH_REJECT_OBSERVED", 47, protocol="NAS-EPS", message_type="Attach reject", transaction=None),
                    deviation("INSUFFICIENT_TERMINAL_EVIDENCE", 53, protocol="NAS-EPS", message_type="UE context release", transaction=None),
                ],
            )
        ])
        analysis = self.analyze_docs(attach=document)
        downstream = self.group(analysis)["downstream_observations"]
        self.assertTrue(downstream)
        for entry in downstream:
            self.assertEqual(entry["relation"], "OBSERVED_AFTER_BOUNDARY")
            self.assertNotIn("caused", entry["description"].lower())


class ArtifactTests(Workspace):
    def test_committed_examples_reproduce_expected_analysis(self) -> None:
        cases = {
            "attach-reject": ["--attach", str(INPUTS / "attach-reject" / "attach-analysis.json")],
            "session-accepted": ["--session", str(INPUTS / "session-accepted" / "session-analysis.json")],
            "session-rejection": ["--session", str(INPUTS / "session-rejection" / "session-analysis.json")],
            "bearer-rejection": ["--session", str(INPUTS / "bearer-rejection" / "session-analysis.json")],
            "ambiguous": ["--session", str(INPUTS / "ambiguous" / "session-analysis.json")],
            "omitted": ["--session", str(INPUTS / "omitted" / "session-analysis.json")],
            "mixed": [
                "--attach", str(INPUTS / "mixed" / "attach-analysis.json"),
                "--session", str(INPUTS / "mixed" / "session-analysis.json"),
            ],
        }
        for name, arguments in cases.items():
            with self.subTest(case=name):
                output = self.directory / f"{name}.json"
                report = self.directory / f"{name}.txt"
                result = run_cli(*arguments, "--output", str(output), "--report", str(report))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    output.read_text(encoding="utf-8"),
                    (EXPECTED / f"{name}-analysis.json").read_text(encoding="utf-8"),
                )
                self.assertEqual(
                    report.read_text(encoding="utf-8"),
                    (EXPECTED / f"{name}-report.txt").read_text(encoding="utf-8"),
                )

    def test_analysis_is_deterministic(self) -> None:
        first = self.directory / "one.json"
        second = self.directory / "two.json"
        for target in (first, second):
            result = run_cli(
                "--attach", str(INPUTS / "mixed" / "attach-analysis.json"),
                "--session", str(INPUTS / "mixed" / "session-analysis.json"),
                "--output", str(target),
                "--force",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_report_renderer_reads_a_stored_analysis(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "epc_boundary_report.py"), str(EXPECTED / "attach-reject-analysis.json")],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("EPC Failure Boundary Orchestration", result.stdout)
        self.assertIn("frame 47", result.stdout)
        self.assertIn("not a root cause", result.stdout)

    def test_no_input_exits_six(self) -> None:
        result = run_cli("--output", str(self.directory / "none.json"))
        self.assertEqual(result.returncode, 6)

    def test_wrong_domain_artifact_exits_five(self) -> None:
        wrong = self.directory / "wrong.json"
        wrong.write_text(json.dumps({"domain": "5gc", "procedure_instances": []}), encoding="utf-8")
        result = run_cli("--attach", str(wrong), "--output", str(self.directory / "out.json"))
        self.assertEqual(result.returncode, 5)

    def test_version_floor_is_enforced(self) -> None:
        document = session_document([session_subject()])
        document["domain_version"] = "0.1.0"
        path = self.directory / "old.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        result = run_cli("--session", str(path), "--output", str(self.directory / "out.json"))
        self.assertEqual(result.returncode, 5)
        self.assertIn("below the supported floor", result.stderr)

    def test_malformed_json_exits_five(self) -> None:
        bad = self.directory / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        result = run_cli("--session", str(bad), "--output", str(self.directory / "out.json"))
        self.assertEqual(result.returncode, 5)

    def test_output_overwrite_is_protected(self) -> None:
        target = self.directory / "protected.json"
        target.write_text("keep\n", encoding="utf-8")
        result = run_cli(
            "--session", str(INPUTS / "session-accepted" / "session-analysis.json"),
            "--output", str(target),
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")

    def test_schema_and_rules_match_the_model(self) -> None:
        schema = load_json(SKILL / "schemas" / "epc-failure-boundary-analysis.schema.json")
        for field in (
            "diagnostic_groups",
            "unbound_domain_analyses",
            "ambiguities",
            "limitations",
            "not_confirmed",
        ):
            self.assertIn(field, schema["required"])
        rules = load_json(SKILL / "rules" / "epc-boundary-rules.json")
        self.assertEqual(set(rules["selectable_attach_deviations"]), set(model.ELIGIBLE_ATTACH))
        self.assertEqual(set(rules["selectable_session_deviations"]), set(model.ELIGIBLE_SESSION))
        self.assertEqual(set(rules["nonselectable_deviations"]), set(model.NONSELECTABLE))
        self.assertEqual(set(rules["selection_statuses"]), set(model.SELECTION_STATUSES))
        self.assertEqual(rules["not_confirmed"], list(model.NOT_CONFIRMED))

    def test_analysis_publishes_no_causal_claim(self) -> None:
        text = (EXPECTED / "attach-reject-analysis.json").read_text(encoding="utf-8").lower()
        for forbidden in ("root cause is", "root-cause chain", "caused by the boundary"):
            self.assertNotIn(forbidden, text)

    def test_analysis_publishes_no_subscriber_identity(self) -> None:
        for path in EXPECTED.glob("*-analysis.json"):
            text = path.read_text(encoding="utf-8")
            for forbidden in ("460020000000001", "1122334455667788", "919000001"):
                self.assertNotIn(forbidden, text)

    def test_sanitizer_rejects_causal_wording(self) -> None:
        with self.assertRaises(model.InputError):
            model.sanitize_output({"text": "the root cause is the MME"})
        self.assertEqual(model.sanitize_output({"text": "observed at frame 47"}), {"text": "observed at frame 47"})


class ModelUnitTests(unittest.TestCase):
    def test_selection_status_vocabulary(self) -> None:
        self.assertEqual(
            set(model.SELECTION_STATUSES),
            {
                "SELECTED",
                "NO_ABNORMAL_BOUNDARY_OBSERVED",
                "AMBIGUOUS_FIRST_BOUNDARY",
                "INSUFFICIENT_COMPARABLE_EVIDENCE",
            },
        )

    def test_eligible_and_nonselectable_sets_do_not_overlap(self) -> None:
        self.assertFalse(model.ELIGIBLE_ATTACH & model.NONSELECTABLE)
        self.assertFalse(model.ELIGIBLE_SESSION & model.NONSELECTABLE)
        self.assertFalse(model.ELIGIBLE_ATTACH & model.ELIGIBLE_SESSION)

    def test_attach_and_session_sets_cover_the_reviewed_types(self) -> None:
        self.assertEqual(len(model.ELIGIBLE_ATTACH), 5)
        self.assertEqual(len(model.ELIGIBLE_SESSION), 4)

    def test_group_summary_counts_statuses(self) -> None:
        analysis = model.analyze([], [INPUTS / "session-accepted" / "session-analysis.json"])
        summary = model.group_summary(analysis)
        self.assertEqual(summary["group_count"], 4)
        self.assertEqual(summary["no_abnormal_count"], 4)
        self.assertEqual(summary["selected_count"], 0)


if __name__ == "__main__":
    unittest.main()
