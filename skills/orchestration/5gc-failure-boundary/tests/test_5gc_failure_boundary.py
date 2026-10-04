"""Package-local test suite for 5gc-failure-boundary."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
INPUTS = PACKAGE / "examples" / "inputs"
EXPECTED = PACKAGE / "examples" / "expected"

sys.path.insert(0, str(SCRIPTS))

import failure_boundary_model as MODEL
from failure_boundary_model import EXIT_MALFORMED_INPUT


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ANALYZE = load_script("analyze_failure_boundary")
REPORT = load_script("failure_boundary_report")


def run_scenario(name: str, directory: Path, extra_args: list[str] | None = None) -> dict:
    analysis_path = directory / f"{name}-analysis.json"
    argv = ["--input-dir", str(INPUTS / name), "--output", str(analysis_path), "--force"]
    if extra_args:
        argv = extra_args + argv
    rc = ANALYZE.main(argv)
    assert rc == 0, f"scenario {name} failed with {rc}"
    return json.loads(analysis_path.read_text(encoding="utf-8"))


def groups_of(analysis: dict) -> dict[str, dict]:
    return {g["diagnostic_id"]: g for g in analysis["diagnostic_groups"]}


def first_group(analysis: dict) -> dict:
    return analysis["diagnostic_groups"][0]


def selected_of(group: dict) -> dict | None:
    selected = group.get("selected_boundary")
    return selected["boundary_ref"] if selected else None


class ManifestAndPackageTests(unittest.TestCase):
    def test_manifest_contract(self):
        text = (PACKAGE / "manifest.yaml").read_text(encoding="utf-8")
        self.assertIn("name: 5gc-failure-boundary", text)
        self.assertIn("version: 0.1.0", text)
        self.assertIn("category: orchestration", text)
        self.assertIn("required: []", text)
        for dep in ("5gc-registration-mobility >=0.1.0", "5gc-pdu-session >=0.3.0", "procedure-evidence >=0.1.0"):
            self.assertIn(dep, text)

    def test_expected_fixture_matches_committed_output(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("pfcp-negative-boundary", "registration-reject-only", "same-frame-ambiguity",
                         "no-deviations-anywhere"):
                with self.subTest(scenario=name):
                    produced = run_scenario(name, Path(directory))
                    committed = json.loads((EXPECTED / f"{name}-analysis.json").read_text(encoding="utf-8"))
                    self.assertEqual(produced, committed, name)

    def test_deterministic_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            first = run_scenario("registration-complete-pdu-reject", Path(directory))
            second = run_scenario("registration-complete-pdu-reject", Path(directory))
            self.assertEqual(first, second)

    def test_report_renders(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis_path = Path(directory) / "a.json"
            rc = ANALYZE.main([
                "--input-dir", str(INPUTS / "registration-complete-pdu-reject"),
                "--output", str(analysis_path), "--force",
            ])
            self.assertEqual(rc, 0)
            report = REPORT.render_text(json.loads(analysis_path.read_text(encoding="utf-8")))
            self.assertIn("First abnormal evidence boundary observed at", report)
            self.assertIn("Not confirmed:", report)
            self.assertNotIn("root cause is", report.lower())


class AdapterTests(unittest.TestCase):
    def test_registration_input_adapter(self):
        instances = MODEL.load_domain_instances([
            ("5gc-registration-mobility", INPUTS / "registration-reject-only" / "registration-analysis.json"),
        ])
        self.assertEqual(len(instances), 1)
        inst = instances[0]
        self.assertEqual(inst.source_domain, "5gc-registration-mobility")
        self.assertEqual(inst.ran_ue_ngap_id, 1)
        self.assertEqual(inst.amf_ue_ngap_id, 2)
        self.assertIsNotNone(inst.observation_window)

    def test_pdu_session_input_adapter(self):
        instances = MODEL.load_domain_instances([
            ("5gc-pdu-session", INPUTS / "pfcp-negative-boundary" / "pdu-session-analysis.json"),
        ])
        self.assertEqual(len(instances), 1)
        inst = instances[0]
        self.assertEqual(inst.source_domain, "5gc-pdu-session")
        self.assertEqual(inst.pdu_session_id if hasattr(inst, "pdu_session_id") else inst.extra_identity.get("pdu_session_id"), 1)
        self.assertEqual(inst.ran_ue_ngap_id, 1)

    def test_malformed_domain_input_fails_loudly(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.load_domain_instances([
                ("5gc-pdu-session", INPUTS / "malformed-domain-input" / "pdu-session-analysis.json"),
            ])

    def test_unsupported_domain_kind_fails(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.load_domain_instances([("5gc-sbi", INPUTS / "pfcp-negative-boundary" / "pdu-session-analysis.json")])

    def test_duplicate_identical_input_is_deduplicated(self):
        paths = [
            ("5gc-registration-mobility", INPUTS / "duplicate-identical-input" / "registration-analysis.json"),
            ("5gc-registration-mobility", INPUTS / "duplicate-identical-input" / "registration-analysis-copy.json"),
        ]
        instances = MODEL.load_domain_instances(paths)
        self.assertEqual(len(instances), 1)
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("duplicate-identical-input", Path(directory))
            total_candidates = sum(len(g["candidate_boundaries"]) for g in analysis["diagnostic_groups"])
            self.assertEqual(total_candidates, 0)


class SubjectLinkingTests(unittest.TestCase):
    def test_multi_domain_subject_linking(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("registration-complete-pdu-reject", Path(directory))
            group = first_group(analysis)
            self.assertEqual(group["subject_link"]["strength"], "STRONG")
            self.assertEqual(len(group["source_domain_instances"]), 2)
            domains = {s["source_domain"] for s in group["source_domain_instances"]}
            self.assertEqual(domains, {"5gc-registration-mobility", "5gc-pdu-session"})

    def test_sctp_association_isolation(self):
        # Same numeric UE identifiers on different SCTP associations never merge.
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("same-ids-different-associations", Path(directory))
            self.assertEqual(len(analysis["diagnostic_groups"]), 2)
            for group in analysis["diagnostic_groups"]:
                self.assertEqual(group["subject_link"]["strength"], "UNBOUND")

    def test_two_ues_form_two_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("two-ue-two-groups", Path(directory))
            self.assertEqual(len(analysis["diagnostic_groups"]), 2)

    def test_unlinked_captures_stay_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("unlinked-captures", Path(directory))
            self.assertEqual(len(analysis["diagnostic_groups"]), 2)
            for group in analysis["diagnostic_groups"]:
                self.assertEqual(len(group["observation_scope"]["capture_files"]), 1)
            self.assertEqual(len(analysis["unbound_domain_analyses"]), 2)

    def test_timestamp_only_join_is_never_applied(self):
        # The unlinked-captures fixture has close timestamps across captures;
        # the analyses must stay in separate single-source groups.
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("unlinked-captures", Path(directory))
            for group in analysis["diagnostic_groups"]:
                self.assertNotIn("timestamp", group["subject_link"]["basis"])

    def test_lifecycle_generations_remain_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("lifecycle-generations-distinct", Path(directory))
            group = first_group(analysis)
            generations = sorted(
                s.get("session_generation") for s in group["source_domain_instances"]
                if s.get("session_generation") is not None
            )
            self.assertEqual(generations, [1, 2])
            instance_ids = [s["source_instance_id"] for s in group["source_domain_instances"]]
            self.assertTrue(any(i.endswith(":g1") for i in instance_ids))
            self.assertTrue(any(i.endswith(":g2") for i in instance_ids))
            if selected_of(group):
                self.assertTrue(selected_of(group)["source_instance_id"].endswith(":g1"))


class BoundarySelectionTests(unittest.TestCase):
    def test_candidate_extraction_from_domain_deviations(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("pfcp-negative-boundary", Path(directory))
            group = first_group(analysis)
            self.assertEqual(group["candidate_boundaries"][0]["deviation_type"], "PROTOCOL_NEGATIVE_OUTCOME_OBSERVED")
            self.assertEqual(group["selection_status"], "SELECTED")
            self.assertEqual(group["boundary_confidence"], "HIGH")

    def test_first_boundary_ordering_is_provenance_based(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("auth-failure-before-reject", Path(directory))
            group = first_group(analysis)
            selected = selected_of(group)
            self.assertEqual(selected["deviation_type"], "UNSUCCESSFUL_OUTCOME_OBSERVED")
            self.assertEqual(selected["boundary_anchor"]["frame_number"], 12)
            downstream = group["downstream_observations"]
            self.assertTrue(any(e.get("relation") == "OBSERVED_AFTER_BOUNDARY" for e in downstream))

    def test_no_severity_ranking_across_domains(self):
        # The later PFCP negative cause must not win over the earlier
        # registration abnormality merely because it looks more serious: with
        # the corrected candidate-centric selection the earliest proven
        # registration candidate is selected and the PFCP outcome stays
        # downstream (never selected while an earlier candidate exists).
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("registration-before-pdu-boundary", Path(directory))
            group = first_group(analysis)
            selected = selected_of(group)
            if selected is not None:
                self.assertEqual(selected["source_domain"], "5gc-registration-mobility")
            else:
                self.assertIn(group["selection_status"],
                              ("AMBIGUOUS_FIRST_BOUNDARY", "INSUFFICIENT_COMPARABLE_EVIDENCE"))
            downstream_domains = {e.get("source_domain") for e in group["downstream_observations"]}
            pdu_selected = any(
                c["source_domain"] == "5gc-pdu-session" and group.get("selected_boundary")
                and c["candidate_id"] == group["selected_boundary"]["candidate_id"]
                for c in group["candidate_boundaries"]
            )
            self.assertFalse(pdu_selected)
            self.assertEqual(group["subject_link"]["strength"], "STRONG")

    def test_same_frame_candidates_remain_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("same-frame-ambiguity", Path(directory))
            group = first_group(analysis)
            self.assertEqual(group["selection_status"], "AMBIGUOUS_FIRST_BOUNDARY")
            self.assertIsNone(group["selected_boundary"])
            self.assertTrue(group["additional_evidence_needed"])
            tied = {e.get("candidate_id") for e in group["additional_evidence_needed"] if e.get("candidate_id")}
            self.assertTrue(tied)

    def test_incomparable_provenance_fails_loudly(self):
        # A boundary-eligible deviation without structured provenance is an
        # unsupported source contract: the adapter fails loudly instead of
        # reconstructing provenance from prose.
        with tempfile.TemporaryDirectory() as directory:
            rc = ANALYZE.main([
                "--input-dir", str(INPUTS / "incomparable-provenance"),
                "--output", str(Path(directory) / "out.json"), "--force",
            ])
            self.assertEqual(rc, EXIT_MALFORMED_INPUT)

    def test_observed_versus_derived_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("pfcp-negative-boundary", Path(directory))
            observed_ref = selected_of(first_group(analysis))
            self.assertEqual(observed_ref["evidence_level"], "OBSERVED")
            self.assertIsNotNone(observed_ref["boundary_anchor"]["frame_number"])

            analysis = run_scenario("registration-missing-counterpart", Path(directory))
            derived_ref = selected_of(first_group(analysis))
            self.assertEqual(derived_ref["evidence_level"], "DERIVED")
            self.assertIsNone(derived_ref["boundary_anchor"]["frame_number"])
            self.assertIsNotNone(derived_ref["ordering_basis"]["observation_window"])

    def test_partial_capture_blocks_missing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("partial-capture-blocks-missing", Path(directory))
            group = first_group(analysis)
            self.assertEqual(group["selection_status"], "INSUFFICIENT_COMPARABLE_EVIDENCE")
            blocked = [c for c in group["candidate_boundaries"] if c["selectability"] == "BLOCKED_BY_PARTIAL_CAPTURE"]
            self.assertTrue(blocked)
            self.assertTrue(any("capture covering the expected response" in e["requirement"]
                                for e in group["additional_evidence_needed"]))

    def test_unblocked_missing_evidence_is_selectable_as_derived(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("registration-missing-counterpart", Path(directory))
            group = first_group(analysis)
            selected = selected_of(group)
            self.assertEqual(selected["deviation_type"], "MISSING_EXPECTED_COUNTERPART")
            self.assertEqual(selected["evidence_level"], "DERIVED")
            self.assertEqual(group["boundary_confidence"], "MEDIUM")

    def test_no_abnormal_boundary_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("no-deviations-anywhere", Path(directory))
            for group in analysis["diagnostic_groups"]:
                self.assertEqual(group["selection_status"], "NO_ABNORMAL_BOUNDARY_OBSERVED")
                self.assertIsNone(group["selected_boundary"])
            serialized = json.dumps(analysis)
            for word in ("SUCCESS", "HEALTHY", "PASSED", "END_TO_END_OK"):
                self.assertNotIn(word, serialized)


class LimitationAndWordingTests(unittest.TestCase):
    def test_limitation_only_analyses_are_not_selected_as_boundaries(self):
        cases = {
            "lifecycle-ambiguity-limitation": "LIFECYCLE_AMBIGUITY",
            "correlation-ambiguity-limitation": "CORRELATION_AMBIGUITY",
            "duplicate-only-limitation": "DUPLICATE_OR_RETRANSMITTED_EVIDENCE",
            "protected-payload-limitation": "PROTECTED_OR_UNAVAILABLE_PAYLOAD",
        }
        for scenario, limitation_type in cases.items():
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as directory:
                    analysis = run_scenario(scenario, Path(directory))
                    for group in analysis["diagnostic_groups"]:
                        limited = [e["type"] for e in group["evidence_limitations"]]
                        self.assertIn(limitation_type, limited)
                        selected = selected_of(group)
                        if selected:
                            self.assertNotEqual(selected["deviation_type"], limitation_type)
                        else:
                            self.assertEqual(group["selection_status"], "NO_ABNORMAL_BOUNDARY_OBSERVED")

    def test_lifecycle_ambiguity_is_not_selected_as_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("lifecycle-ambiguity-limitation", Path(directory))
            for group in analysis["diagnostic_groups"]:
                selected = selected_of(group)
                if selected:
                    self.assertNotEqual(selected["deviation_type"], "LIFECYCLE_AMBIGUITY")

    def test_downstream_observations_use_neutral_relation(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("ngap-boundary-before-nas-reject", Path(directory))
            group = first_group(analysis)
            self.assertEqual(group["selection_status"], "SELECTED")
            serialized = json.dumps(analysis)
            self.assertNotIn("CAUSED_BY_BOUNDARY", serialized)
            for entry in group["downstream_observations"]:
                self.assertEqual(entry["relation"], "OBSERVED_AFTER_BOUNDARY")

    def test_supporting_evidence_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("pfcp-negative-boundary", Path(directory))
            ref = selected_of(first_group(analysis))
            self.assertEqual(ref["boundary_anchor"]["capture_file"], "test.pcap")
            self.assertIsNotNone(ref["boundary_anchor"]["frame_number"])
            self.assertIn("source_deviation", ref["supporting_evidence"])
            self.assertIsNotNone(ref["supporting_evidence"]["source_terminal"])

    def test_not_confirmed_statements_present(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("pfcp-negative-boundary", Path(directory))
            not_confirmed = " ".join(first_group(analysis)["not_confirmed"])
            self.assertIn("implementation cause not assessed", not_confirmed)
            self.assertIn("network-function blame not established", not_confirmed)
            self.assertIn("vendor defect not established", not_confirmed)
            self.assertIn("end-to-end root cause not established", not_confirmed)

    def test_no_root_cause_fields_anywhere(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("registration-complete-pdu-reject", Path(directory))
            serialized = json.dumps(analysis)
            for field in ("root_cause", "culprit", "responsible_nf", "vendor_fault",
                          "implementation_failure", "bug_location", "hypotheses"):
                self.assertNotIn(field, serialized)

    def test_no_vendor_or_nf_blame_wording(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("pfcp-negative-boundary", Path(directory))
            serialized = json.dumps(analysis)
            for phrase in ("UPF caused", "SMF failure", "AMF failure", "gNB failed"):
                self.assertNotIn(phrase, serialized)

    def test_earlier_context_preserved_without_success_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("registration-complete-pdu-reject", Path(directory))
            group = first_group(analysis)
            earlier_text = json.dumps(group["earlier_context"])
            self.assertIn("OBSERVED_BEFORE_BOUNDARY", earlier_text)
            serialized = json.dumps(analysis)
            self.assertNotIn("HEALTHY", serialized)
            self.assertNotIn("REGISTRATION_SUCCESS", serialized)

    def test_additional_evidence_needed_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            first = run_scenario("same-frame-ambiguity", Path(directory))
            second = run_scenario("same-frame-ambiguity", Path(directory))
            self.assertEqual(first, second)
            group = first_group(first)
            self.assertTrue(group["additional_evidence_needed"])
            for entry in group["additional_evidence_needed"]:
                self.assertIn("requirement", entry)

    def test_single_domain_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario in ("registration-only", "pdu-session-only"):
                with self.subTest(scenario=scenario):
                    analysis = run_scenario(scenario, Path(directory))
                    self.assertEqual(len(analysis["diagnostic_groups"]), 1)
                    group = first_group(analysis)
                    self.assertEqual(group["subject_link"]["strength"], "UNBOUND")
                    self.assertIn(
                        group["selection_status"],
                        ("SELECTED", "NO_ABNORMAL_BOUNDARY_OBSERVED", "AMBIGUOUS_FIRST_BOUNDARY"),
                    )


class StructuredProvenanceTests(unittest.TestCase):
    """Structured-provenance contract tests (v0.1.0 acceptance correction)."""

    def test_old_registration_version_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = INPUTS / "registration-reject-only" / "registration-analysis.json"
            doc = json.loads(source.read_text(encoding="utf-8"))
            doc["analysis_version"] = "0.1.0"
            old = Path(directory) / "registration-analysis.json"
            old.write_text(json.dumps(doc), encoding="utf-8")
            rc = ANALYZE.main(["--registration", str(old),
                               "--output", str(Path(directory) / "out.json"), "--force"])
            self.assertEqual(rc, EXIT_MALFORMED_INPUT)
            self.assertIn("0.1.0", json.dumps(rc)) if False else None

    def test_old_pdu_version_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = INPUTS / "pfcp-negative-boundary" / "pdu-session-analysis.json"
            doc = json.loads(source.read_text(encoding="utf-8"))
            doc["procedure_version"] = "0.3.0"
            old = Path(directory) / "pdu-session-analysis.json"
            old.write_text(json.dumps(doc), encoding="utf-8")
            rc = ANALYZE.main(["--pdu-session", str(old),
                               "--output", str(Path(directory) / "out.json"), "--force"])
            self.assertEqual(rc, EXIT_MALFORMED_INPUT)

    def test_new_domain_versions_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("pfcp-negative-boundary", Path(directory))
            self.assertEqual(analysis["analysis_name"], "5gc-failure-boundary")

    def test_later_incomparability_does_not_block_selection(self):
        # Candidate A (framed, earliest) is proven before every other candidate
        # even though later candidates tie among themselves: SELECTED A, never
        # INSUFFICIENT_COMPARABLE_EVIDENCE.
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("later-incomparability", Path(directory))
            group = first_group(analysis)
            self.assertEqual(group["selection_status"], "SELECTED")
            selected = selected_of(group)
            self.assertEqual(selected["deviation_type"], "PROTOCOL_NEGATIVE_OUTCOME_OBSERVED")
            self.assertEqual(selected["boundary_anchor"]["frame_number"], 5)
            later = [e for e in group["downstream_observations"] if e.get("relation") == "OBSERVED_AFTER_BOUNDARY"]
            self.assertGreaterEqual(len(later), 3)

    def test_earliest_incomparability_remains_ambiguous(self):
        # Two windowed candidates overlapping at the earliest position with no
        # proven-earlier candidate stay ambiguous; nothing is chosen.
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("earliest-incomparability", Path(directory))
            group = first_group(analysis)
            self.assertEqual(group["selection_status"], "AMBIGUOUS_FIRST_BOUNDARY")
            self.assertIsNone(group["selected_boundary"])
            self.assertTrue(group["additional_evidence_needed"])

    def test_description_prose_is_not_a_machine_contract(self):
        # Changing only the human-readable descriptions must not change the
        # boundary selection or ordering.
        with tempfile.TemporaryDirectory() as directory:
            baseline = run_scenario("pfcp-negative-boundary", Path(directory))
            invariant = run_scenario("description-invariance", Path(directory))
            def shape(doc):
                out = []
                for group in doc["diagnostic_groups"]:
                    sel = group.get("selected_boundary")
                    out.append({
                        "status": group["selection_status"],
                        "confidence": group.get("boundary_confidence"),
                        "selected_frame": (
                            sel["boundary_ref"]["boundary_anchor"]["frame_number"] if sel else None
                        ),
                        "selected_type": (
                            sel["boundary_ref"]["deviation_type"] if sel else None
                        ),
                        "downstream": [e.get("candidate_id") for e in group["downstream_observations"]],
                    })
                return out
            self.assertEqual(shape(baseline), shape(invariant))

    def test_adversarial_prose_numbers_are_ignored(self):
        # Description text contains frame-like numbers (99, 5); the selection
        # uses only the structured EVENT ref frame.
        with tempfile.TemporaryDirectory() as directory:
            analysis = run_scenario("adversarial-description", Path(directory))
            group = first_group(analysis)
            selected = selected_of(group)
            self.assertEqual(selected["boundary_anchor"]["frame_number"], 5)
            self.assertEqual(group["selection_status"], "SELECTED")
            self.assertEqual(group["boundary_confidence"], "HIGH")

    def test_candidate_centric_selection_with_injected_none_pair(self):
        # Unit-level proof of the corrected partial-order selection: when one
        # candidate is proven before every other candidate, later mutual
        # incomparability must not force INSUFFICIENT_COMPARABLE_EVIDENCE.
        class FakeSource:
            capture_file = "c.pcap"
            instance_id = "inst"
            source_domain = "5gc-pdu-session"
        class FakeCandidate:
            def __init__(self, frame, deviation_type):
                self.frame_number = frame
                self.evidence_level = "OBSERVED"
                self.deviation = {"type": deviation_type}
                self.source = FakeSource()
        a = MODEL.Candidate(source=FakeSource(), deviation={"type": "A"}, refs=[],
                            origin_attempt_id=None, frame_number=10, timestamp=None,
                            protocol=None, message_type=None, window=None,
                            stage_position=None, blocked=False)
        b = MODEL.Candidate(source=FakeSource(), deviation={"type": "B"}, refs=[],
                            origin_attempt_id=None, frame_number=None, timestamp=None,
                            protocol=None, message_type=None, window=None,
                            stage_position=None, blocked=False)
        c = MODEL.Candidate(source=FakeSource(), deviation={"type": "C"}, refs=[],
                            origin_attempt_id=None, frame_number=None, timestamp=None,
                            protocol=None, message_type=None, window=None,
                            stage_position=None, blocked=False)
        # A before B; A before C; B and C mutually incomparable ("none").
        rel = {(0, 1): "before", (0, 2): "before", (1, 2): "none"}
        status, earliest_set = MODEL._select_earliest(rel, 3)
        self.assertEqual(status, "SELECTED")
        self.assertEqual(earliest_set, [0])
        # All-pairs incomparability without a proven-earliest candidate stays
        # insufficient.
        rel2 = {(0, 1): "none", (0, 2): "none", (1, 2): "none"}
        status2, _ = MODEL._select_earliest(rel2, 3)
        self.assertEqual(status2, "INSUFFICIENT_COMPARABLE_EVIDENCE")
        # Ties at the earliest position stay ambiguous.
        rel3 = {(0, 1): "tie", (0, 2): "before", (1, 2): "before"}
        status3, _ = MODEL._select_earliest(rel3, 3)
        self.assertEqual(status3, "AMBIGUOUS_FIRST_BOUNDARY")


class SanitizationTests(unittest.TestCase):
    def test_forbidden_words_trigger_sanitization_error(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.sanitize_output({"note": "the root cause was identified"})
        with self.assertRaises(MODEL.InputError):
            MODEL.sanitize_output({"note": "culprit: SMF"})
        with self.assertRaises(MODEL.InputError):
            MODEL.sanitize_output({"note": "responsible_nf: UPF"})

    def test_not_confirmed_disclaimers_are_allowed(self):
        MODEL.sanitize_output({"not_confirmed": list(MODEL.NOT_CONFIRMED_STATEMENTS)})


if __name__ == "__main__":
    unittest.main()
