#!/usr/bin/env python3
"""User-facing tests for the unified core-network PCAP analysis workflow.

These tests exercise the executable entry point, execution-completeness
classification, multi-subject reporting, report publication safety and privacy.
The two external boundaries (capture inventory and the accepted 5GC pipeline) are
replaced by deterministic fakes, so the workflow is testable without tshark or a
capture corpus. One opt-in smoke test runs the real boundaries against a local
capture when CORENET_SMOKE_CAPTURE is set.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "corenet-analyze.py"
FROZEN_BENCHMARK_DIR = ROOT / "benchmarks" / "golden-captures"
SMOKE_CAPTURE = os.environ.get("CORENET_SMOKE_CAPTURE")


def load_module():
    spec = importlib.util.spec_from_file_location("corenet_analyze_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


MODULE = load_module()

REPORT_KEYS = {
    "report_schema_version",
    "capture",
    "toolchain",
    "requested_domains",
    "observed_protocols",
    "domain_results",
    "overall_execution_status",
    "limitations",
}

DOMAIN_RESULT_KEYS = {
    "domain",
    "implementation_status",
    "execution_status",
    "protocol_evidence",
    "procedure_summaries",
    "diagnostic_groups",
    "first_abnormal_boundary",
    "evidence_limitations",
    "additional_evidence_needed",
}

SUBJECT_KEYS = {
    "diagnostic_group_reference",
    "boundary_selection_status",
    "first_abnormal_boundary",
    "candidate_boundary_count",
    "source_domain_instances",
    "evidence_limitations",
    "additional_evidence_needed",
}

TEXT_SECTIONS = (
    "Capture and Toolchain",
    "Observed Protocols",
    "Domain Detection and Execution",
    "Protocol Extraction Coverage",
    "Procedure Instances",
    "Diagnostic Subjects",
    "First Abnormal Boundary per Subject",
    "Evidence Limitations",
    "Additional Evidence Needed",
    "Execution Failures",
    "Interpretation Boundaries",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def inventory(names: list[str], frames: int = 16) -> dict:
    return {
        "capture_file": "fixture.pcap",
        "frame_count": frames,
        "first_timestamp": "2026-07-29T05:34:37.808757Z",
        "last_timestamp": "2026-07-29T05:34:37.842784Z",
        "duration_seconds": "0.034027",
        "address_families": ["IPv4"],
        "endpoints": [{"address": "127.0.0.1", "port": 38412}],
        "transport_protocols": ["SCTP"],
        "dissector_protocol_names": names,
        "dissector_protocols": [],
        "truncation_indicators": [],
        "tshark_version": "TShark (Wireshark) 4.7.1 (v4.7.1-0-g667ab240e6de).",
        "warnings": [],
    }


def inventory_5gc() -> dict:
    return inventory(["eth", "ip", "sctp", "ngap", "nas-5gs"])


def instance(
    domain: str = "5gc-registration-mobility",
    identity: str = "5gc-reg:fault.pcap:sctp-assoc-65535:r1",
    capture: str = "fixture.pcap",
    **extra,
) -> dict:
    payload = {
        "source_domain": domain,
        "capture_file": capture,
        "source_instance_id": identity,
    }
    payload.update(extra)
    return payload


def subject_link(*identities: str) -> dict:
    return {
        "basis": "capture_sctp_association_and_ngap_ue_context_exact_match",
        "source_contexts": [
            {
                "source_domain": "5gc-registration-mobility",
                "source_instance_id": identity,
                "capture_file": "fixture.pcap",
                "sctp_association": 65535,
                "ran_ue_ngap_id": 1,
                "amf_ue_ngap_id": 2,
            }
            for identity in identities
        ],
    }


def boundary(
    candidate: str = "1-cand-2",
    frame: int = 11,
    protocol: str = "NAS-5GS",
    message: str = "Authentication failure",
    family: str = "5gc-registration-mobility",
    stage: str = "authentication",
) -> dict:
    return {
        "candidate_id": candidate,
        "boundary_ref": {
            "candidate_id": candidate,
            "source_domain": "5gc-registration-mobility",
            "procedure_family": family,
            "procedure_stage": stage,
            "deviation_type": "UNSUCCESSFUL_OUTCOME_OBSERVED",
            "evidence_level": "OBSERVED",
            "description": f"{protocol} {message} observed at frame {frame}",
            "boundary_anchor": {
                "capture_file": "fixture.pcap",
                "frame_number": frame,
                "message_type": message,
                "protocol": protocol,
                "timestamp": "2026-07-29T05:34:47.514322Z",
            },
            "ordering_basis": {
                "frame_number": frame,
                "observation_window": {"start_frame": 9, "end_frame": 15},
                "stage_position": 1,
            },
            "supporting_evidence": {
                "evidence_refs": [
                    {
                        "capture_file": "fixture.pcap",
                        "evidence_level": "OBSERVED",
                        "frame_number": frame,
                        "kind": "EVENT",
                        "message_type": message,
                        "protocol": protocol,
                        "stage_id": stage,
                        "window_first_frame": None,
                        "window_last_frame": None,
                    }
                ]
            },
        },
    }


def group(
    reference: str = "diag-1",
    selection_status: str = "SELECTED",
    selected: dict | None = None,
    instances: list | None = None,
    link: dict | None = None,
    confidence: str = "HIGH",
    limitations: list | None = None,
    additional: list | None = None,
) -> dict:
    payload = {
        "diagnostic_id": reference,
        "selection_status": selection_status,
        "boundary_confidence": confidence if selection_status == "SELECTED" else None,
        "selected_boundary": selected,
        "candidate_boundaries": [] if selected is None else [{"candidate_id": selected["candidate_id"]}],
        "source_domain_instances": instances or [],
        "subject_link": link,
        "evidence_limitations": limitations or [],
        "additional_evidence_needed": additional or [],
    }
    return payload


def orchestration(*groups: dict) -> dict:
    return {"analysis_name": "5gc-failure-boundary", "diagnostic_groups": list(groups)}


def summary_selected() -> dict:
    """Shaped like the accepted pipeline summary for a frame-11 authentication failure."""
    return {
        "case_id": "capture-fixture",
        "selection_status": "SELECTED",
        "selected_boundary": {
            "selected_source_domain": "5gc-registration-mobility",
            "selected_procedure_family": "5gc-registration-mobility",
            "selected_procedure_stage": "authentication",
            "deviation_type": "UNSUCCESSFUL_OUTCOME_OBSERVED",
            "boundary_protocol": "NAS-5GS",
            "boundary_message": "Authentication failure",
            "boundary_frame": 11,
            "boundary_timestamp": "2026-07-29T05:34:47.514322Z",
            "evidence_level": "OBSERVED",
        },
        "boundary_confidence": "HIGH",
        "evidence_limitations": [],
        "additional_evidence_needed": [],
        "candidate_boundaries_count": 2,
        "domain_status": {
            "handover_mobility": {
                "execution_status": "EXECUTED",
                "output_present": True,
                "deviation_count": 0,
                "first_stop_reason": None,
                "handover_attempt_count": 0,
                "path_switch_attempt_count": 0,
            },
            "pdu_session": {
                "execution_status": "EXECUTED",
                "output_present": True,
                "deviation_count": 0,
                "first_stop_reason": None,
                "instance_count": 0,
            },
            "registration": {
                "execution_status": "EXECUTED",
                "output_present": True,
                "deviation_count": 2,
                "first_stop_reason": None,
                "instance_count": 1,
            },
        },
        "orchestration_status": {
            "execution_status": "EXECUTED",
            "output_present": True,
            "diagnostic_group_count": 1,
            "source_domain_instances_count": 1,
            "candidate_boundary_count": 2,
            "consumed_domain_instance_counts": {
                "handover_mobility": 0,
                "pdu_session": 0,
                "registration": 1,
            },
            "consumed_unmapped_source_domain_instance_count": 0,
            "first_stop_reason": None,
        },
        "domain_instances_count": 1,
        "protocol_status": {
            "gtpu": "NOT_OBSERVED_IN_CAPTURE",
            "nas-5gs": "SUCCESS",
            "ngap": "SUCCESS_WITH_UNSUPPORTED_SEMANTICS",
            "pfcp": "NOT_OBSERVED_IN_CAPTURE",
            "sbi-http2": "NOT_OBSERVED_IN_CAPTURE",
        },
    }


def orchestration_selected() -> dict:
    return orchestration(
        group(
            instances=[instance()],
            selected=boundary(),
            link=subject_link("5gc-reg:fault.pcap:sctp-assoc-65535:r1"),
        )
    )


def zero_instances(summary: dict) -> dict:
    """Represent a Domain run that produced no procedure instance."""
    for record in summary["domain_status"].values():
        if "instance_count" in record:
            record["instance_count"] = 0
        if "handover_attempt_count" in record:
            record["handover_attempt_count"] = 0
            record["path_switch_attempt_count"] = 0
    return summary


def epc_payload(instances: int = 1) -> dict:
    """Shaped like the EPC Attach Domain analysis for one rejected attempt."""
    procedure_instances = []
    for index in range(instances):
        procedure_instances.append({
            "procedure_reference": f"epc-attach-{index:010x}",
            "procedure": "eps-attach",
            "attempt_index": 1,
            "association": {
                "basis": "pre_assignment_extension_unique_mme_identifier",
                "strength": "STRONG",
                "capture_file": "fixture.pcap",
                "sctp_association": "sctp-assoc-0",
                "enb_ue_s1ap_id": 24 + index,
                "mme_ue_s1ap_id": 24 + index,
            },
            "first_frame": 33,
            "last_frame": 53,
            "stages": [
                {"stage_id": "attach-initiation", "stage_name": "Attach initiation", "conditional": False,
                 "status": "OBSERVED", "messages": ["Attach request"], "first_frame": 33, "last_frame": 33,
                 "evidence_refs": []},
                {"stage_id": "attach-decision", "stage_name": "Attach decision", "conditional": False,
                 "status": "OBSERVED", "messages": ["Attach reject"], "first_frame": 47, "last_frame": 47,
                 "evidence_refs": []},
            ],
            "observations": [
                {"observation_type": "ATTACH_REQUEST_OBSERVED", "procedure_stage": "attach-initiation",
                 "protocol": "NAS-EPS", "message_type": "Attach request", "frame_number": 33,
                 "evidence_level": "OBSERVED"},
            ],
            "deviations": [
                {"deviation_type": "ATTACH_REJECT_OBSERVED", "procedure_stage": "attach-decision",
                 "protocol": "NAS-EPS", "message_type": "Attach reject", "frame_number": 47,
                 "evidence_level": "OBSERVED",
                 "evidence_refs": [
                     {"protocol": "NAS-EPS", "frame_number": 47, "message_type": "Attach reject",
                      "evidence_level": "OBSERVED"},
                 ],
                 "observation_window": {"start_frame": 33, "end_frame": 47},
                 "explanation": "explicit Attach rejection observed with EMM cause 19 (ESM failure)",
                 "limitations": ["underlying ESM evidence unavailable"]},
            ],
            "evidence_limitations": ["underlying ESM evidence unavailable"],
            "additional_evidence_needed": ["capture the NAS Attach complete for this UE context"],
        })
    return {
        "analysis": {
            "domain": "epc-procedures",
            "domain_version": "0.1.0",
            "procedure_instances": procedure_instances,
            "instance_count": instances,
            "limitations": [
                "No EPC Analysis Orchestration exists, so no global first-abnormal boundary is selected."
            ],
            "additional_evidence_needed": [],
        },
        "s1ap_event_count": 40 * instances,
        "nas_eps_event_count": 32 * instances,
    }


def epc_session_analysis() -> dict:
    """The accepted EPC session-control analysis artifact used as a shaped input."""
    path = ROOT / "skills" / "domain" / "epc-procedures" / "examples" / "gtpv2" / "expected-session-analysis.json"
    return json.loads(path.read_text(encoding="utf-8"))


def epc_payload_with_session(instances: int = 1, gtpv2_events: int = 12) -> dict:
    payload = epc_payload(instances=instances)
    payload["session_analysis"] = epc_session_analysis() if gtpv2_events else None
    payload["gtpv2_event_count"] = gtpv2_events
    payload["gtpv2_transaction_count"] = 6 if gtpv2_events else 0
    return payload


def boundary_group(reference: str, subject_type: str, frame: int, deviation_type: str,
                   protocol: str, message_type: str, *, interface=None) -> dict:
    return {
        "diagnostic_group_reference": reference,
        "subject_type": subject_type,
        "source_domain_instances": [
            {
                "source_domain": "epc-procedures",
                "source_file": "analysis.json",
                "source_instance_id": reference,
                "capture_file": "fixture.pcap",
                "subject_type": subject_type,
                "interface": interface,
                "transaction_references": [],
                "attempt_index": 1,
            }
        ],
        "subject_link": {"strength": "STRONG", "basis": "test", "cross_subject_link": "NOT_ESTABLISHED"},
        "observation_window": {"start_frame": 1, "end_frame": 200},
        "boundary_candidates": [],
        "boundary_candidate_count": 1,
        "boundary_candidates_omitted": 0,
        "boundary_selection_status": "SELECTED",
        "first_abnormal_boundary": {
            "boundary_reference": f"epc-boundary-{abs(hash(reference)) % (10 ** 10):010d}",
            "deviation_type": deviation_type,
            "protocol": protocol,
            "message_type": message_type,
            "frame_number": frame,
            "evidence_level": "OBSERVED",
            "ordering_basis": "exact_frame_number",
            "evidence_refs": [
                {"frame_number": frame, "protocol": protocol, "message_type": message_type,
                 "evidence_level": "OBSERVED"}
            ],
            "observation_window": {"start_frame": 1, "end_frame": 200},
        },
        "boundary_confidence": "HIGH",
        "downstream_observations": [],
        "evidence_limitations": [],
        "additional_evidence_needed": [],
        "not_confirmed": ["the selected boundary is a first observed abnormality, not a root cause"],
        "group_index": 1,
    }


def epc_boundary_payload(attach_count: int = 1, session: bool = True) -> dict:
    payload = epc_payload_with_session(
        instances=attach_count, gtpv2_events=12 if session else 0
    )
    groups = [
        boundary_group(
            f"epc-attach-{index:010x}", "EPS_ATTACH", 47 + index * 28,
            "ATTACH_REJECT_OBSERVED", "NAS-EPS", "Attach reject",
        )
        for index in range(attach_count)
    ]
    if session:
        for subject in epc_session_analysis()["control_plane_subjects"]:
            groups.append(
                boundary_group(
                    subject["subject_reference"], "EPC_SESSION_CONTROL", 106,
                    "CREATE_SESSION_REJECTED_OBSERVED", "GTPv2-C", "Create Session Response",
                    interface=subject["interface"],
                )
            )
    payload["boundary_analysis"] = {
        "analysis_name": "epc-failure-boundary",
        "analysis_version": "0.1.0",
        "diagnostic_groups": groups,
        "unbound_domain_analyses": [],
        "ambiguities": [],
        "limitations": [],
        "additional_evidence_needed": [],
        "not_confirmed": ["the selected boundary is a first observed abnormality, not a root cause"],
    }
    payload["boundary_error"] = None
    return payload


class WorkflowTestCase(unittest.TestCase):
    """Base class wiring deterministic fakes into the two external boundaries."""

    summary_factory = staticmethod(summary_selected)
    orchestration_factory = staticmethod(orchestration_selected)
    inventory_factory = staticmethod(inventory_5gc)

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)
        self.capture = self.base / "fixture.pcap"
        self.capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
        self.work = self.base / "work"
        self.output = self.base / "out"
        self.pipeline_calls: list[tuple[str, str]] = []
        self.epc_pipeline_calls: list[tuple[str, str]] = []
        self._original_inventory = MODULE.inventory_capture
        self._original_pipeline = MODULE.execute_5gc_pipeline
        self._original_epc_pipeline = MODULE.execute_epc_pipeline
        self._original_revision = MODULE.repository_revision
        MODULE.inventory_capture = self.fake_inventory
        MODULE.execute_5gc_pipeline = self.fake_pipeline
        MODULE.execute_epc_pipeline = self.fake_epc_pipeline
        MODULE.repository_revision = lambda root=MODULE.ROOT: "0" * 40

    def tearDown(self) -> None:
        MODULE.inventory_capture = self._original_inventory
        MODULE.execute_5gc_pipeline = self._original_pipeline
        MODULE.execute_epc_pipeline = self._original_epc_pipeline
        MODULE.repository_revision = self._original_revision
        self._temporary.cleanup()

    def fake_inventory(self, path: Path) -> dict:
        return self.inventory_factory()

    def fake_pipeline(self, capture: Path, work_dir: Path, case_id: str):
        self.pipeline_calls.append((str(capture), case_id))
        artifacts = work_dir / "5gc" / "fake-run" / "raw_skill_artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / "nas-5gs-events.jsonl").write_text('{"a":1}\n{"b":2}\n', encoding="utf-8")
        (artifacts / "ngap-events.jsonl").write_text('{"c":3}\n', encoding="utf-8")
        return self.summary_factory(), self.orchestration_factory(), artifacts

    def fake_epc_pipeline(self, capture: Path, work_dir: Path, case_id: str) -> dict:
        self.epc_pipeline_calls.append((str(capture), case_id))
        return epc_payload()

    def run_cli(self, *extra: str, domains: str = "auto") -> int:
        argv = [
            "--capture",
            str(self.capture),
            "--domains",
            domains,
            "--work-dir",
            str(self.work),
            "--output-dir",
            str(self.output),
            *extra,
        ]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return MODULE.main(argv)

    def read_report(self) -> dict:
        return json.loads((self.output / "analysis.json").read_text(encoding="utf-8"))

    def read_text(self) -> str:
        return (self.output / "report.txt").read_text(encoding="utf-8")

    def domain_result(self) -> dict:
        return self.read_report()["domain_results"][0]


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------


class CapabilityContractTests(unittest.TestCase):
    def test_domain_identities_are_fixed(self) -> None:
        self.assertEqual(set(MODULE.DOMAIN_CAPABILITIES), {"5gc", "epc", "ims"})

    def test_implemented_domains_are_declared(self) -> None:
        for domain in ("5gc", "epc"):
            capability = MODULE.DOMAIN_CAPABILITIES[domain]
            self.assertEqual(capability["implementation_status"], "IMPLEMENTED", domain)
            self.assertTrue(capability["entry_point_available"], domain)
            self.assertIsNotNone(capability["entry_point"], domain)
            self.assertTrue(capability["analysis_capabilities"], domain)
        capability = MODULE.DOMAIN_CAPABILITIES["ims"]
        self.assertEqual(capability["implementation_status"], "UNSUPPORTED")
        self.assertIsNone(capability["entry_point"])
        self.assertTrue(capability["unsupported_reason"])

    def test_epc_capability_stays_bounded(self) -> None:
        capability = MODULE.DOMAIN_CAPABILITIES["epc"]
        self.assertIn("eps-attach-procedure-evidence", capability["analysis_capabilities"])
        self.assertIn(
            "gtpv2-session-control-transaction-evidence", capability["analysis_capabilities"]
        )
        for absent in (
            "end-to-end EPC failure-boundary orchestration",
            "full EPS bearer lifecycle",
            "cross-interface S11 to S5/S8 session association",
        ):
            self.assertIn(absent, capability["not_implemented_capabilities"])
        self.assertIn("GTPv2-C", capability["supported_protocol_families"])
        self.assertNotIn("GTPv2-C", capability["planned_protocol_families"])
        self.assertEqual(
            capability["session_entry_point"],
            "skills/domain/epc-procedures/scripts/analyze_epc_session.py",
        )

    def test_5gc_entry_point_is_the_accepted_pipeline(self) -> None:
        capability = MODULE.DOMAIN_CAPABILITIES["5gc"]
        self.assertTrue(capability["entry_point_available"])
        self.assertTrue((ROOT / capability["entry_point"]).is_file())

    def test_unsupported_domains_declare_no_executable_module(self) -> None:
        for domain in ("epc", "ims"):
            self.assertFalse(
                (ROOT / "skills" / "protocol" / domain).exists(),
                f"no {domain} Skill package may exist yet",
            )

    def test_envelope_stays_domain_neutral(self) -> None:
        # No 5gc-specific field may be required at the top level.
        self.assertIn("domain_results", REPORT_KEYS)
        self.assertNotIn("ngap", REPORT_KEYS)
        self.assertNotIn("nas_5gs", REPORT_KEYS)


class CliSurfaceTests(unittest.TestCase):
    def test_help_exits_zero(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                MODULE.main(["--help"])
        self.assertEqual(caught.exception.code, 0)

    def test_invalid_domain_request_fails(self) -> None:
        with self.assertRaises(MODULE.AnalysisError) as caught:
            MODULE.resolve_selection(
                "gprs", MODULE.detect_domains({"protocols": [], "transports": []})
            )
        self.assertEqual(caught.exception.code, "INVALID_DOMAIN")


# ---------------------------------------------------------------------------
# Execution-completeness classification
# ---------------------------------------------------------------------------


class ExecutionClassificationTests(WorkflowTestCase):
    def test_all_components_normal_is_completed(self) -> None:
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "COMPLETED")
        self.assertEqual(self.domain_result()["execution_status"], "COMPLETED")
        self.assertEqual(self.domain_result()["degradation"], [])

    def test_nas_extraction_failure_is_never_completed(self) -> None:
        summary = summary_selected()
        summary["protocol_status"]["nas-5gs"] = "ERROR_127"
        self.summary_factory = lambda: summary
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        result = self.domain_result()
        self.assertEqual(self.read_report()["overall_execution_status"], "PARTIAL")
        self.assertEqual(result["execution_status"], "PARTIAL")
        self.assertEqual(result["failure_code"], "EXTRACTION_PARTIAL")
        self.assertTrue(any("NAS-5GS extraction failed" in item for item in result["degradation"]))

    def test_ngap_extraction_failure_is_never_completed(self) -> None:
        summary = summary_selected()
        summary["protocol_status"]["ngap"] = "ERROR_2"
        self.summary_factory = lambda: summary
        self.run_cli(domains="5gc")
        result = self.domain_result()
        self.assertEqual(result["execution_status"], "PARTIAL")
        self.assertTrue(any("NGAP extraction failed" in item for item in result["degradation"]))

    def test_absent_protocol_is_not_a_failure(self) -> None:
        self.run_cli(domains="5gc")
        statuses = {
            item["protocol"]: item["extraction_status"]
            for item in self.domain_result()["protocol_evidence"]
        }
        self.assertEqual(statuses["pfcp"], "NOT_OBSERVED_IN_CAPTURE")
        self.assertEqual(self.domain_result()["execution_status"], "COMPLETED")

    def test_unsupported_semantics_is_not_a_failure(self) -> None:
        self.run_cli(domains="5gc")
        statuses = {
            item["protocol"]: item["extraction_status"]
            for item in self.domain_result()["protocol_evidence"]
        }
        self.assertEqual(statuses["ngap"], "SUCCESS_WITH_UNSUPPORTED_SEMANTICS")
        self.assertEqual(self.domain_result()["execution_status"], "COMPLETED")

    def test_orchestration_failure_is_not_boundary_localization(self) -> None:
        summary = summary_selected()
        summary["selection_status"] = "ORCHESTRATION_ERROR_2"
        summary["selected_boundary"] = None
        summary["boundary_confidence"] = None
        summary["evidence_limitations"] = ["Orchestrator failed with exit code 2"]
        summary["orchestration_status"]["execution_status"] = "ERROR_2"
        summary["orchestration_status"]["first_stop_reason"] = "orchestrator exited with 2"
        self.summary_factory = lambda: summary
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        report = self.read_report()
        result = self.domain_result()
        self.assertEqual(report["overall_execution_status"], "PARTIAL")
        self.assertEqual(result["execution_status"], "PARTIAL")
        self.assertEqual(result["failure_code"], "ORCHESTRATION_FAILED")
        self.assertIsNone(result["first_abnormal_boundary"])
        self.assertTrue(
            any("orchestration failed" in item for item in result["degradation"])
        )

    def test_skipped_domains_without_input_are_insufficient(self) -> None:
        summary = zero_instances(summary_selected())
        for record in summary["domain_status"].values():
            record["execution_status"] = "SKIPPED_NO_INPUTS"
            record["first_stop_reason"] = "no inputs"
        summary["selection_status"] = "NO_ABNORMAL_BOUNDARY_OBSERVED"
        summary["selected_boundary"] = None
        summary["orchestration_status"]["execution_status"] = "SKIPPED_NO_DOMAIN_OUTPUTS"
        self.summary_factory = lambda: summary
        self.orchestration_factory = lambda: {"diagnostic_groups": []}
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_INSUFFICIENT_EVIDENCE)
        self.assertEqual(self.read_report()["overall_execution_status"], "INSUFFICIENT_EVIDENCE")

    def test_executed_domains_without_procedure_instance_are_insufficient(self) -> None:
        summary = summary_selected()
        for record in summary["domain_status"].values():
            if "instance_count" in record:
                record["instance_count"] = 0
            if "handover_attempt_count" in record:
                record["handover_attempt_count"] = 0
                record["path_switch_attempt_count"] = 0
        summary["selection_status"] = "NO_DOMAIN_INPUTS"
        summary["selected_boundary"] = None
        summary["boundary_confidence"] = None
        self.summary_factory = lambda: summary
        self.orchestration_factory = lambda: {"diagnostic_groups": []}
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_INSUFFICIENT_EVIDENCE)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(report["domain_results"][0]["diagnostic_subject_count"], 0)
        self.assertIsNone(report["domain_results"][0]["first_abnormal_boundary"])

    def test_instances_without_diagnostic_group_are_reported(self) -> None:
        summary = summary_selected()
        summary["selection_status"] = "NO_DOMAIN_INPUTS"
        summary["selected_boundary"] = None
        summary["boundary_confidence"] = None
        self.summary_factory = lambda: summary
        self.orchestration_factory = lambda: {"diagnostic_groups": []}
        self.run_cli(domains="5gc")
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "COMPLETED")
        self.assertTrue(
            any("established no diagnostic subject" in item for item in report["limitations"])
        )

    def test_required_failure_without_domain_result_is_failed(self) -> None:
        summary = zero_instances(summary_selected())
        summary["protocol_status"] = {"nas-5gs": "ERROR_127", "ngap": "ERROR_127"}
        for record in summary["domain_status"].values():
            record["execution_status"] = "SKIPPED_NO_INPUTS"
        self.summary_factory = lambda: summary
        self.orchestration_factory = lambda: {"diagnostic_groups": []}
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        result = self.domain_result()
        self.assertEqual(result["execution_status"], "FAILED")
        self.assertEqual(result["failure_code"], "EXTRACTION_FAILED")

    def test_failure_of_unobserved_protocol_does_not_invalidate(self) -> None:
        summary = summary_selected()
        summary["protocol_status"]["pfcp"] = "ERROR_127"
        self.summary_factory = lambda: summary
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        result = self.domain_result()
        self.assertEqual(result["execution_status"], "COMPLETED")
        self.assertTrue(
            any("not observed in this capture" in item for item in result["degradation"])
        )

    def test_protected_payload_bounds_interpretation(self) -> None:
        summary = summary_selected()
        summary["protocol_status"]["nas-5gs"] = "SUCCESS_WITH_PROTECTED_PAYLOAD"
        self.summary_factory = lambda: summary
        self.run_cli(domains="5gc")
        result = self.domain_result()
        self.assertEqual(result["execution_status"], "COMPLETED")
        self.assertTrue(any("security-protected payload" in item for item in result["degradation"]))

    def test_domain_failure_beside_executed_domain_is_partial(self) -> None:
        summary = summary_selected()
        summary["domain_status"]["pdu_session"]["execution_status"] = "FAILED_INPUT_CONTRACT"
        summary["domain_status"]["pdu_session"]["first_stop_reason"] = "input contract rejected"
        self.summary_factory = lambda: summary
        self.run_cli(domains="5gc")
        result = self.domain_result()
        self.assertEqual(result["execution_status"], "PARTIAL")
        self.assertEqual(result["failure_code"], "DOMAIN_PARTIAL")
        self.assertTrue(any("did not produce analysis" in item for item in result["degradation"]))

    def test_overall_status_aggregation(self) -> None:
        def result(domain: str, status: str) -> dict:
            return {"domain": domain, "execution_status": status}

        aggregate = MODULE.overall_status
        self.assertEqual(aggregate([result("5gc", "COMPLETED")], "explicit", ["5gc"]), "COMPLETED")
        self.assertEqual(
            aggregate([result("5gc", "COMPLETED"), result("ims", "UNSUPPORTED")], "explicit", ["5gc", "ims"]),
            "PARTIAL",
        )
        self.assertEqual(
            aggregate([result("5gc", "FAILED"), result("ims", "UNSUPPORTED")], "explicit", ["5gc", "ims"]),
            "FAILED",
        )
        self.assertEqual(
            aggregate([result("5gc", "FAILED"), result("epc", "COMPLETED")], "explicit", ["5gc", "epc"]),
            "PARTIAL",
        )
        self.assertEqual(aggregate([result("5gc", "PARTIAL")], "explicit", ["5gc"]), "PARTIAL")
        self.assertEqual(aggregate([], "auto", []), "INSUFFICIENT_EVIDENCE")


# ---------------------------------------------------------------------------
# Multi-subject reporting
# ---------------------------------------------------------------------------


class MultiSubjectTests(WorkflowTestCase):
    def test_two_independent_ues_are_both_reported(self) -> None:
        self.orchestration_factory = lambda: orchestration(
            group("diag-1", selected=boundary(frame=11), instances=[instance("5gc-registration-mobility", "reg-ue1")],
                  link=subject_link("reg-ue1")),
            group("diag-2", selected=boundary(candidate="2-cand-1", frame=42, message="Registration reject"),
                  instances=[instance("5gc-registration-mobility", "reg-ue2")],
                  link=subject_link("reg-ue2")),
        )
        self.run_cli(domains="5gc")
        result = self.domain_result()
        self.assertEqual(result["diagnostic_subject_count"], 2)
        references = [subject["diagnostic_group_reference"] for subject in result["diagnostic_subjects"]]
        self.assertEqual(references, ["diag-1", "diag-2"])
        frames = [
            subject["first_abnormal_boundary"]["frame_number"]
            for subject in result["diagnostic_subjects"]
        ]
        self.assertEqual(frames, [11, 42])
        self.assertTrue(SUBJECT_KEYS.issubset(result["diagnostic_subjects"][0]))

    def test_failed_subject_and_no_boundary_subject_keep_own_status(self) -> None:
        self.orchestration_factory = lambda: orchestration(
            group("diag-1", selected=boundary(frame=11), instances=[instance("5gc-registration-mobility", "reg-ue1")]),
            group(
                "diag-2",
                selection_status="NO_ABNORMAL_BOUNDARY_OBSERVED",
                selected=None,
                instances=[instance("5gc-registration-mobility", "reg-ue2")],
            ),
        )
        self.run_cli(domains="5gc")
        subjects = {subject["diagnostic_group_reference"]: subject for subject in self.domain_result()["diagnostic_subjects"]}
        self.assertEqual(subjects["diag-1"]["boundary_selection_status"], "SELECTED")
        self.assertEqual(subjects["diag-2"]["boundary_selection_status"], "NO_ABNORMAL_BOUNDARY_OBSERVED")
        self.assertIsNone(subjects["diag-2"]["first_abnormal_boundary"])
        self.assertIsNotNone(subjects["diag-1"]["first_abnormal_boundary"])

    def test_two_pdu_sessions_are_distinct_subjects(self) -> None:
        self.orchestration_factory = lambda: orchestration(
            group("diag-1", selected=boundary(), instances=[instance("5gc-pdu-session", "psi1")]),
            group("diag-2", selected=boundary(frame=30), instances=[instance("5gc-pdu-session", "psi5")]),
        )
        self.run_cli(domains="5gc")
        result = self.domain_result()
        self.assertEqual(result["diagnostic_subject_count"], 2)
        references = {
            subject["source_domain_instances"][0]["instance_reference"]
            for subject in result["diagnostic_subjects"]
        }
        self.assertEqual(len(references), 2)

    def test_reused_pdu_session_identity_stays_distinct(self) -> None:
        self.orchestration_factory = lambda: orchestration(
            group(
                "diag-1",
                selected=boundary(),
                instances=[
                    instance("5gc-pdu-session", "psi1:generation-1"),
                    instance("5gc-pdu-session", "psi1:generation-2"),
                ],
            )
        )
        self.run_cli(domains="5gc")
        instances = self.domain_result()["diagnostic_subjects"][0]["source_domain_instances"]
        self.assertEqual(len(instances), 2)
        self.assertNotEqual(
            instances[0]["instance_reference"], instances[1]["instance_reference"]
        )

    def test_ambiguous_association_stays_ambiguous(self) -> None:
        self.orchestration_factory = lambda: orchestration(
            group(
                "diag-1",
                selection_status="AMBIGUOUS_FIRST_BOUNDARY",
                selected=None,
                instances=[instance("5gc-registration-mobility", "reg-ambiguous")],
                confidence="LOW",
            )
        )
        self.run_cli(domains="5gc")
        subject = self.domain_result()["diagnostic_subjects"][0]
        self.assertEqual(subject["boundary_selection_status"], "AMBIGUOUS_FIRST_BOUNDARY")
        self.assertIsNone(subject["first_abnormal_boundary"])

    def test_handover_context_bridge_is_preserved(self) -> None:
        self.orchestration_factory = lambda: orchestration(
            group(
                "diag-1",
                selected=boundary(),
                instances=[
                    instance("5gc-handover-mobility", "ho-1"),
                    instance("5gc-pdu-session", "psi1"),
                ],
                link={
                    "basis": "handover_source_target_context_bridge_SUPPORTED",
                    "source_contexts": [
                        {"source_domain": "5gc-handover-mobility", "source_instance_id": "ho-1"},
                        {"source_domain": "5gc-pdu-session", "source_instance_id": "psi1"},
                    ],
                },
            )
        )
        self.run_cli(domains="5gc")
        link = self.domain_result()["diagnostic_subjects"][0]["subject_link"]
        self.assertIn("bridge", link["basis"])
        self.assertEqual(link["context_count"], 2)

    def test_unbound_association_never_joins_another_subject(self) -> None:
        self.orchestration_factory = lambda: orchestration(
            group("diag-1", selected=boundary(), instances=[instance("5gc-registration-mobility", "reg-ue1")]),
            group(
                "diag-2",
                selection_status="INSUFFICIENT_COMPARABLE_EVIDENCE",
                selected=None,
                instances=[instance("5gc-registration-mobility", "reg-unbound")],
                link={"basis": "unbound", "source_contexts": []},
            ),
        )
        self.run_cli(domains="5gc")
        subjects = self.domain_result()["diagnostic_subjects"]
        self.assertEqual(len(subjects), 2)
        self.assertEqual(subjects[1]["boundary_selection_status"], "INSUFFICIENT_COMPARABLE_EVIDENCE")
        self.assertIsNone(subjects[1]["first_abnormal_boundary"])

    def test_raw_orchestration_records_are_not_republished(self) -> None:
        self.orchestration_factory = lambda: orchestration(
            group("diag-1", selected=boundary(), instances=[instance()], link=subject_link("reg-ue1"))
        )
        self.run_cli(domains="5gc")
        published = (self.output / "analysis.json").read_text(encoding="utf-8")
        for forbidden in (
            '"ran_ue_ngap_id":',
            '"amf_ue_ngap_id":',
            '"sctp_association":',
            '"source_instance_id":',
            '"candidate_boundaries":',
            '"selected_boundary":',
        ):
            self.assertNotIn(forbidden, published)

    def test_primary_boundary_is_a_compatibility_view(self) -> None:
        self.orchestration_factory = lambda: orchestration(
            group("diag-1", selected=boundary(frame=11), instances=[instance()]),
            group("diag-2", selected=boundary(candidate="2-cand-1", frame=42), instances=[instance("5gc-registration-mobility", "reg-ue2")]),
        )
        self.run_cli(domains="5gc")
        result = self.domain_result()
        self.assertEqual(result["first_abnormal_boundary"]["frame_number"], 11)
        self.assertEqual(
            [subject["first_abnormal_boundary"]["frame_number"] for subject in result["diagnostic_subjects"]],
            [11, 42],
        )

    def test_subject_cap_is_bounded_and_reported(self) -> None:
        groups = [group(f"diag-{index}", selected=boundary(frame=index + 1), instances=[instance()]) for index in range(MODULE.MAX_DIAGNOSTIC_SUBJECTS + 3)]
        self.orchestration_factory = lambda: orchestration(*groups)
        self.run_cli(domains="5gc")
        result = self.domain_result()
        self.assertEqual(result["diagnostic_subject_count"], MODULE.MAX_DIAGNOSTIC_SUBJECTS)
        self.assertEqual(result["diagnostic_subjects_omitted"], 3)
        self.assertTrue(
            any("truncated" in item for item in self.read_report()["limitations"])
        )


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------


class TextReportTests(WorkflowTestCase):
    def test_required_sections_are_present(self) -> None:
        self.run_cli(domains="5gc")
        text = self.read_text()
        for section in TEXT_SECTIONS:
            self.assertIn(section, text, section)

    def test_subjects_are_enumerated_with_frame_evidence(self) -> None:
        self.orchestration_factory = lambda: orchestration(
            group("diag-1", selected=boundary(frame=11), instances=[instance()]),
            group("diag-2", selection_status="NO_ABNORMAL_BOUNDARY_OBSERVED", selected=None, instances=[instance("5gc-registration-mobility", "reg-ue2")]),
        )
        self.run_cli(domains="5gc")
        text = self.read_text()
        self.assertIn("diag-1", text)
        self.assertIn("diag-2", text)
        self.assertIn("Authentication failure", text)
        self.assertIn("NAS-5GS", text)
        self.assertIn("no subject has a selected abnormal boundary", self._text_without_boundary())

    def _text_without_boundary(self) -> str:
        self.output = self.base / "out-noboundary"
        self.orchestration_factory = lambda: orchestration(
            group("diag-1", selection_status="NO_ABNORMAL_BOUNDARY_OBSERVED", selected=None, instances=[instance()])
        )
        self.run_cli(domains="5gc")
        return self.read_text()

    def test_empty_sections_say_so_explicitly(self) -> None:
        self.orchestration_factory = lambda: {"diagnostic_groups": []}
        self.summary_factory = lambda: {**summary_selected(), "selection_status": "NO_DOMAIN_INPUTS", "selected_boundary": None}
        self.run_cli(domains="5gc")
        text = self.read_text()
        self.assertIn("no diagnostic group was established", text)
        self.assertIn("no component failure was recorded", text)


# ---------------------------------------------------------------------------
# Privacy
# ---------------------------------------------------------------------------


class PrivacyTests(WorkflowTestCase):
    def test_structured_identifiers_are_not_published(self) -> None:
        self.orchestration_factory = lambda: orchestration(
            group(
                "diag-1",
                selected=boundary(),
                instances=[
                    instance(
                        "5gc-registration-mobility",
                        "5gc-reg:/home/analyst/captures/fault.pcap:001010000000001",
                        suci="suci-0-001-01-0000-0-0-0000000001",
                        imsi="001010000000001",
                    )
                ],
                link=subject_link("reg-ue1"),
                limitations=["subscriber 001010000000001 observed at /home/analyst/fault.pcap"],
                additional=["collect C:\\Users\\analyst\\trace.pcap"],
            )
        )
        self.run_cli(domains="5gc")
        published = (self.output / "analysis.json").read_text(encoding="utf-8") + self.read_text()
        for forbidden in ("001010000000001", "suci-0-001", "/home/analyst", "analyst"):
            self.assertNotIn(forbidden, published)

    def test_frame_and_protocol_identity_survive_redaction(self) -> None:
        self.run_cli(domains="5gc")
        report = self.read_report()
        subject = report["domain_results"][0]["diagnostic_subjects"][0]
        self.assertEqual(subject["first_abnormal_boundary"]["frame_number"], 11)
        self.assertEqual(subject["first_abnormal_boundary"]["protocol"], "NAS-5GS")
        self.assertEqual(
            subject["first_abnormal_boundary"]["evidence_references"][0]["frame_number"], 11
        )

    def test_capture_digest_is_published_without_content(self) -> None:
        self.run_cli(domains="5gc")
        report = self.read_report()
        self.assertEqual(
            report["capture"]["sha256"], hashlib.sha256(self.capture.read_bytes()).hexdigest()
        )


# ---------------------------------------------------------------------------
# Path safety and publication
# ---------------------------------------------------------------------------


class PathSafetyTests(WorkflowTestCase):
    def test_identical_work_and_output_directory_is_refused(self) -> None:
        self.output = self.work
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        self.assertEqual(self.pipeline_calls, [])

    def test_nested_work_and_output_directories_are_refused(self) -> None:
        self.output = self.work / "report"
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        self.output = self.base / "outer"
        self.work = self.output / "work"
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        self.assertEqual(self.pipeline_calls, [])

    def test_work_directory_inside_repository_is_refused(self) -> None:
        self.work = ROOT / "tmp-should-never-exist"
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        self.assertFalse(self.work.exists())
        self.assertEqual(self.pipeline_calls, [])

    def test_output_directory_inside_benchmark_is_refused(self) -> None:
        self.output = FROZEN_BENCHMARK_DIR / "cases" / "public-5gc-auth-negative"
        before = sorted(path.name for path in self.output.iterdir())
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        self.assertEqual(sorted(path.name for path in self.output.iterdir()), before)

    def test_symlinked_output_directory_cannot_reach_benchmark(self) -> None:
        link = self.base / "link"
        try:
            link.symlink_to(FROZEN_BENCHMARK_DIR / "cases", target_is_directory=True)
        except (OSError, NotImplementedError):  # pragma: no cover - platform without symlinks
            self.skipTest("symlinks unavailable")
        self.output = link / "public-5gc-auth-negative"
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        self.assertFalse((self.output / "analysis.json").exists())

    def test_input_capture_is_not_modified(self) -> None:
        before = self.capture.read_bytes()
        self.run_cli(domains="5gc")
        self.assertEqual(self.capture.read_bytes(), before)

    def test_run_directories_are_unique(self) -> None:
        first = MODULE.create_run_directory(self.work)
        second = MODULE.create_run_directory(self.work)
        self.assertNotEqual(first, second)
        self.assertTrue(first.is_dir() and second.is_dir())
        self.assertEqual(list(first.iterdir()), [])


class PublicationTests(WorkflowTestCase):
    def test_existing_reports_are_not_overwritten_without_force(self) -> None:
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        original = (self.output / "analysis.json").read_text(encoding="utf-8")
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        self.assertEqual((self.output / "analysis.json").read_text(encoding="utf-8"), original)
        self.assertEqual(self.run_cli("--force", domains="5gc"), 0)

    def test_force_replaces_only_the_report_pair(self) -> None:
        self.work.mkdir(parents=True, exist_ok=True)
        sentinel = self.work / "keep-me.txt"
        sentinel.write_text("keep", encoding="utf-8")
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        self.assertEqual(self.run_cli("--force", domains="5gc"), 0)
        self.assertTrue(sentinel.is_file())
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_text_publication_failure_rolls_back_json(self) -> None:
        self.output.mkdir(parents=True, exist_ok=True)
        previous = '{"previous": true}\n'
        (self.output / "analysis.json").write_text(previous, encoding="utf-8")
        (self.output / "report.txt").mkdir()
        self.assertEqual(self.run_cli("--force", domains="5gc"), MODULE.EXIT_FAILED)
        self.assertEqual((self.output / "analysis.json").read_text(encoding="utf-8"), previous)

    def test_failed_run_after_success_records_a_failure_marker(self) -> None:
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        original = (self.output / "analysis.json").read_text(encoding="utf-8")
        self.capture.write_bytes(b"not a capture")
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        self.assertEqual((self.output / "analysis.json").read_text(encoding="utf-8"), original)
        marker = json.loads((self.output / "analysis.failure.json").read_text(encoding="utf-8"))
        self.assertEqual(marker["overall_execution_status"], "FAILED")
        self.assertEqual(marker["failure"]["code"], "MALFORMED_CAPTURE")

    def test_first_failure_writes_the_report_itself(self) -> None:
        self.capture.write_bytes(b"not a capture")
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        self.assertTrue((self.output / "analysis.json").is_file())
        self.assertFalse((self.output / "analysis.failure.json").exists())


# ---------------------------------------------------------------------------
# Detection and unsupported domains
# ---------------------------------------------------------------------------


class EpcDomainTests(WorkflowTestCase):
    def test_epc_subject_preserves_procedure_local_deviation(self) -> None:
        self.run_cli(domains="epc")
        result = self.domain_result()
        subject = result["diagnostic_subjects"][0]
        self.assertRegex(subject["diagnostic_group_reference"], r"^epc-attach-[0-9a-f]+$")
        self.assertEqual(subject["boundary_selection_status"], "NOT_EVALUATED")
        self.assertIsNone(subject["first_abnormal_boundary"])
        deviations = subject["procedure_deviations"]
        self.assertEqual(deviations[0]["deviation_type"], "ATTACH_REJECT_OBSERVED")
        self.assertEqual(deviations[0]["frame_number"], 47)
        self.assertIn("EMM cause 19", deviations[0]["explanation"])
        self.assertEqual(
            [p["protocol"] for p in result["protocol_evidence"]], ["S1AP", "NAS-EPS", "GTPv2-C"]
        )

    def test_epc_report_states_no_global_boundary(self) -> None:
        self.run_cli(domains="epc")
        report = self.read_report()
        result = self.domain_result()
        self.assertIsNone(result["first_abnormal_boundary"])
        self.assertEqual(result["boundary_selection_status"], "NOT_EVALUATED")
        self.assertTrue(
            any("boundary selection is not evaluated" in item for item in report["limitations"])
        )
        text = self.read_text()
        self.assertIn("NOT_EVALUATED", text)
        self.assertIn("ATTACH_REJECT_OBSERVED", text)

    def test_epc_report_never_claims_bearer_or_service_success(self) -> None:
        self.run_cli(domains="epc")
        published = (self.output / "analysis.json").read_text(encoding="utf-8") + self.read_text()
        lowered = published.lower()
        for forbidden in ("bearer_active", "pdn_connectivity_success", "user_plane_ready", "service_success"):
            self.assertNotIn(forbidden, lowered)
        self.assertIn("does not establish", lowered)

    def test_epc_extraction_failure_is_surfaced(self) -> None:
        def failing(capture, work_dir, case_id):
            raise MODULE.AnalysisError("EXTRACTION_FAILED", "S1AP extraction exited with 4")

        MODULE.execute_epc_pipeline = failing
        self.assertEqual(self.run_cli(domains="epc"), MODULE.EXIT_FAILED)
        result = self.domain_result()
        self.assertEqual(result["execution_status"], "FAILED")
        self.assertEqual(result["failure_code"], "EXTRACTION_FAILED")
        self.assertIsNone(result["first_abnormal_boundary"])

    def test_epc_without_attach_instance_is_insufficient_evidence(self) -> None:
        MODULE.execute_epc_pipeline = lambda capture, work_dir, case_id: epc_payload(instances=0)
        self.assertEqual(self.run_cli(domains="epc"), MODULE.EXIT_INSUFFICIENT_EVIDENCE)
        result = self.domain_result()
        self.assertEqual(result["execution_status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["diagnostic_subject_count"], 0)
        self.assertTrue(result["degradation"])

    def test_mixed_request_keeps_three_domain_results(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "ngap", "nas-5gs", "s1ap"])
        self.assertEqual(self.run_cli(domains="5gc,epc,ims"), 0)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "PARTIAL")
        statuses = {result["domain"]: result["execution_status"] for result in report["domain_results"]}
        self.assertEqual(statuses, {"5gc": "COMPLETED", "epc": "COMPLETED", "ims": "UNSUPPORTED"})

    def test_epc_execution_is_deterministic(self) -> None:
        first, second = self.base / "epc-a", self.base / "epc-b"
        self.output = first
        self.assertEqual(self.run_cli(domains="epc"), 0)
        self.output = second
        self.assertEqual(self.run_cli(domains="epc"), 0)
        for name in ("analysis.json", "report.txt"):
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes(), name)


class EpcCapabilityTruthfulnessTests(WorkflowTestCase):
    def test_epc_report_never_claims_epc_is_unimplemented(self) -> None:
        self.run_cli(domains="epc")
        report = self.read_report()
        scope = report["interpretation"]["domain_scope"]
        self.assertIn("EPC coverage is bounded", scope)
        self.assertNotIn("EPC and IMS analysis are not implemented", scope)
        published = (self.output / "analysis.json").read_text(encoding="utf-8") + self.read_text()
        self.assertNotIn("EPC and IMS analysis are not implemented", published)
        self.assertNotIn("EPC and IMS report", published)

    def test_epc_text_report_states_bounded_scope(self) -> None:
        self.run_cli(domains="epc")
        text = self.read_text()
        self.assertIn("EPC coverage is bounded to EPS Attach procedure evidence", text)
        self.assertIn("IMS analysis is not implemented", text)

    def test_failure_report_does_not_confuse_failure_with_missing_epc(self) -> None:
        self.capture.write_bytes(b"not a capture at all")
        self.assertEqual(self.run_cli(domains="epc"), MODULE.EXIT_FAILED)
        report = self.read_report()
        scope = report["interpretation"]["domain_scope"]
        self.assertIn("does not change which domains are implemented", scope)
        self.assertNotIn("EPC and IMS analysis are not implemented", scope)

    def test_mixed_interpretation_distinguishes_three_capabilities(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "ngap", "nas-5gs", "s1ap"])
        self.assertEqual(self.run_cli(domains="5gc,epc,ims"), 0)
        report = self.read_report()
        scope = report["interpretation"]["domain_scope"]
        for fragment in ("5GC coverage is bounded", "EPC coverage is bounded", "IMS analysis is not implemented"):
            self.assertIn(fragment, scope)
        statuses = {result["domain"]: result["execution_status"] for result in report["domain_results"]}
        self.assertEqual(statuses, {"5gc": "COMPLETED", "epc": "COMPLETED", "ims": "UNSUPPORTED"})

    def test_interpretation_never_claims_full_epc_support(self) -> None:
        self.run_cli(domains="epc")
        scope = self.read_report()["interpretation"]["domain_scope"].lower()
        self.assertIn("epc bearer lifecycle", scope)
        self.assertIn("not implemented", scope)
        for claim in ("complete epc analysis", "full epc support", "root cause engine"):
            self.assertNotIn(claim, scope)


class EpcEvidenceProjectionTests(WorkflowTestCase):
    def deviation(self) -> dict:
        self.run_cli(domains="epc")
        return self.domain_result()["diagnostic_subjects"][0]["procedure_deviations"][0]

    def test_attach_reject_preserves_frame_and_evidence(self) -> None:
        deviation = self.deviation()
        self.assertEqual(deviation["deviation_type"], "ATTACH_REJECT_OBSERVED")
        self.assertEqual(deviation["frame_number"], 47)
        self.assertEqual(len(deviation["evidence_refs"]), 1)
        reference = deviation["evidence_refs"][0]
        self.assertEqual(reference["frame_number"], 47)
        self.assertEqual(reference["protocol"], "NAS-EPS")
        self.assertEqual(reference["message_type"], "Attach reject")
        self.assertEqual(reference["evidence_level"], "OBSERVED")

    def test_observation_window_is_preserved(self) -> None:
        deviation = self.deviation()
        self.assertEqual(deviation["observation_window"], {"start_frame": 33, "end_frame": 47})

    def test_deviation_limitations_are_bounded_and_scrubbed(self) -> None:
        payload = epc_payload()
        payload["analysis"]["procedure_instances"][0]["deviations"][0]["limitations"] = [
            "underlying ESM evidence unavailable at /home/analyst/capture.pcap"
        ]
        MODULE.execute_epc_pipeline = lambda capture, work_dir, case_id: payload
        self.run_cli(domains="epc")
        limitations = self.deviation()["limitations"]
        self.assertEqual(len(limitations), 1)
        self.assertNotIn("/home/analyst", limitations[0])
        self.assertIn("redacted-path", limitations[0])

    def test_missing_source_evidence_is_never_invented(self) -> None:
        payload = epc_payload()
        payload["analysis"]["procedure_instances"][0]["deviations"][0]["evidence_refs"] = []
        payload["analysis"]["procedure_instances"][0]["deviations"][0]["observation_window"] = None
        MODULE.execute_epc_pipeline = lambda capture, work_dir, case_id: payload
        self.run_cli(domains="epc")
        deviation = self.deviation()
        self.assertEqual(deviation["evidence_refs"], [])
        self.assertIsNone(deviation["observation_window"])

    def test_unexpected_nested_evidence_cannot_leak(self) -> None:
        payload = epc_payload()
        deviation = payload["analysis"]["procedure_instances"][0]["deviations"][0]
        deviation["evidence_refs"] = [{
            "frame_number": 47,
            "protocol": "NAS-EPS",
            "message_type": "Attach reject",
            "evidence_level": "OBSERVED",
            "raw_payload": "00" * 40,
            "subscriber": "001010000000001",
            "nested": {"secret": "value"},
        }]
        deviation["observation_window"] = {"start_frame": 33, "end_frame": 47, "note": "extra"}
        MODULE.execute_epc_pipeline = lambda capture, work_dir, case_id: payload
        self.run_cli(domains="epc")
        published = json.dumps(self.domain_result()["diagnostic_subjects"][0])
        self.assertNotIn("raw_payload", published)
        self.assertNotIn("001010000000001", published)
        self.assertNotIn("secret", published)
        self.assertEqual(
            set(self.deviation()["evidence_refs"][0]),
            {"frame_number", "protocol", "message_type", "evidence_level"},
        )
        self.assertEqual(set(self.deviation()["observation_window"]), {"start_frame", "end_frame"})

    def test_evidence_truncation_is_visible(self) -> None:
        payload = epc_payload()
        payload["analysis"]["procedure_instances"][0]["deviations"][0]["evidence_refs"] = [
            {"frame_number": 40 + index, "protocol": "NAS-EPS", "message_type": "Attach reject",
             "evidence_level": "OBSERVED"}
            for index in range(MODULE.MAX_EVIDENCE_REFERENCES + 3)
        ]
        MODULE.execute_epc_pipeline = lambda capture, work_dir, case_id: payload
        self.run_cli(domains="epc")
        deviation = self.deviation()
        self.assertEqual(len(deviation["evidence_refs"]), MODULE.MAX_EVIDENCE_REFERENCES)
        self.assertEqual(deviation["evidence_refs_omitted"], 3)

    def test_subject_order_is_stable_across_runs(self) -> None:
        first, second = self.base / "ord-a", self.base / "ord-b"
        MODULE.execute_epc_pipeline = lambda capture, work_dir, case_id: epc_payload(instances=3)
        self.output = first
        self.assertEqual(self.run_cli(domains="epc"), 0)
        self.output = second
        self.assertEqual(self.run_cli(domains="epc"), 0)
        first_order = [s["diagnostic_group_reference"] for s in self.read_report()["domain_results"][0]["diagnostic_subjects"]]
        self.output = first
        again = [s["diagnostic_group_reference"] for s in self.read_report()["domain_results"][0]["diagnostic_subjects"]]
        self.assertEqual(first_order, again)

    def test_epc_boundary_stays_not_evaluated(self) -> None:
        self.run_cli(domains="epc")
        result = self.domain_result()
        self.assertIsNone(result["first_abnormal_boundary"])
        self.assertEqual(result["boundary_selection_status"], "NOT_EVALUATED")


class DetectionTests(WorkflowTestCase):
    def test_auto_selects_5gc_on_access_signaling(self) -> None:
        self.assertEqual(self.run_cli(domains="auto"), 0)
        report = self.read_report()
        self.assertEqual(report["requested_domains"], ["5gc"])
        self.assertEqual(report["workflow"]["selection_mode"], "auto")
        self.assertEqual(self.domain_result()["detection"]["status"], "CONFIRMED")

    def test_gtp_u_only_is_ambiguous_and_not_analyzed(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "udp", "gtp"])
        self.assertEqual(self.run_cli(domains="auto"), MODULE.EXIT_INSUFFICIENT_EVIDENCE)
        self.assertEqual(self.read_report()["requested_domains"], [])
        self.assertEqual(self.pipeline_calls, [])

    def test_pfcp_only_is_suspected_not_confirmed(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "udp", "pfcp"])
        self.assertEqual(self.run_cli(domains="auto"), MODULE.EXIT_INSUFFICIENT_EVIDENCE)
        self.assertTrue(any("SUSPECTED" in item for item in self.read_report()["limitations"]))

    def test_sip_only_does_not_confirm_ims(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "udp", "sip"])
        self.assertEqual(self.run_cli(domains="auto"), MODULE.EXIT_INSUFFICIENT_EVIDENCE)
        self.assertEqual(self.pipeline_calls, [])

    def test_epc_signaling_selects_the_epc_adapter(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "s1ap", "nas-eps"])
        self.assertEqual(self.run_cli(domains="auto"), 0)
        self.assertEqual(self.read_report()["requested_domains"], ["epc"])
        self.assertEqual(len(self.epc_pipeline_calls), 1)
        self.assertEqual(self.pipeline_calls, [])

    def test_mixed_5gc_and_epc_evidence_is_not_collapsed(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "ngap", "nas-5gs", "s1ap"])
        self.assertEqual(self.run_cli(domains="auto"), 0)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "COMPLETED")
        statuses = {result["domain"]: result["execution_status"] for result in report["domain_results"]}
        self.assertEqual(statuses, {"5gc": "COMPLETED", "epc": "COMPLETED"})
        self.assertEqual(len(self.pipeline_calls), 1)
        self.assertEqual(len(self.epc_pipeline_calls), 1)


class UnsupportedDomainTests(WorkflowTestCase):
    def test_epc_request_runs_bounded_attach_analysis(self) -> None:
        self.assertEqual(self.run_cli(domains="epc"), 0)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "COMPLETED")
        result = report["domain_results"][0]
        self.assertEqual(result["domain"], "epc")
        self.assertEqual(result["execution_status"], "COMPLETED")
        self.assertEqual(result["diagnostic_subject_count"], 1)
        self.assertEqual(len(self.epc_pipeline_calls), 1)
        self.assertEqual(self.pipeline_calls, [])

    def test_ims_request_is_unsupported(self) -> None:
        self.assertEqual(self.run_cli(domains="ims"), MODULE.EXIT_UNSUPPORTED)
        self.assertEqual(self.read_report()["domain_results"][0]["execution_status"], "UNSUPPORTED")
        self.assertEqual(self.pipeline_calls, [])

    def test_mixed_request_is_partial_and_keeps_each_status(self) -> None:
        self.assertEqual(self.run_cli(domains="5gc,ims"), 0)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "PARTIAL")
        statuses = {result["domain"]: result["execution_status"] for result in report["domain_results"]}
        self.assertEqual(statuses, {"5gc": "COMPLETED", "ims": "UNSUPPORTED"})

    def test_failed_domain_keeps_unsupported_domain_visible(self) -> None:
        def failing_pipeline(capture, work_dir, case_id):
            raise MODULE.AnalysisError("PIPELINE_FAILED", "adapter exited with 1")

        MODULE.execute_5gc_pipeline = failing_pipeline
        self.assertEqual(self.run_cli(domains="5gc,ims"), MODULE.EXIT_FAILED)
        report = self.read_report()
        statuses = {result["domain"]: result["execution_status"] for result in report["domain_results"]}
        self.assertEqual(statuses, {"5gc": "FAILED", "ims": "UNSUPPORTED"})
        self.assertEqual(report["overall_execution_status"], "FAILED")

    def test_domain_without_adapter_fails_visibly(self) -> None:
        capability = MODULE.DOMAIN_CAPABILITIES["ims"]
        original = capability["implementation_status"]
        capability["implementation_status"] = "IMPLEMENTED"
        try:
            self.assertEqual(self.run_cli(domains="ims"), MODULE.EXIT_FAILED)
            result = self.read_report()["domain_results"][0]
            self.assertEqual(result["execution_status"], "FAILED")
            self.assertEqual(result["failure_code"], "NO_DOMAIN_ADAPTER")
        finally:
            capability["implementation_status"] = original


# ---------------------------------------------------------------------------
# Determinism and benchmark invariance
# ---------------------------------------------------------------------------


class DeterminismTests(WorkflowTestCase):
    def test_repeated_runs_produce_identical_reports(self) -> None:
        first, second = self.base / "out-a", self.base / "out-b"
        self.output = first
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        self.output = second
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        for name in ("analysis.json", "report.txt"):
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes(), name)

    def test_machine_paths_do_not_appear_in_reports(self) -> None:
        self.run_cli(domains="5gc")
        published = (self.output / "analysis.json").read_text(encoding="utf-8") + self.read_text()
        self.assertNotIn(str(self.base), published)
        self.assertNotIn(str(self.work), published)


class BenchmarkInvarianceTests(WorkflowTestCase):
    def _snapshot(self) -> dict[str, str]:
        return {
            str(path.relative_to(FROZEN_BENCHMARK_DIR)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(FROZEN_BENCHMARK_DIR.rglob("*"))
            if path.is_file()
        }

    def test_analysis_run_does_not_modify_the_frozen_benchmark(self) -> None:
        before = self._snapshot()
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        self.assertEqual(self._snapshot(), before)


@unittest.skipUnless(
    SMOKE_CAPTURE,
    "set CORENET_SMOKE_CAPTURE to a local PCAP/PCAPNG to run the real end-to-end smoke test",
)
class ExternalCaptureSmokeTests(unittest.TestCase):
    """Real boundaries: tshark inventory plus the accepted 5GC pipeline."""

    def test_real_capture_runs_end_to_end(self) -> None:
        capture = Path(SMOKE_CAPTURE)
        self.assertTrue(capture.is_file(), SMOKE_CAPTURE)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "out"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                exit_code = MODULE.main([
                    "--capture",
                    str(capture),
                    "--domains",
                    "5gc",
                    "--work-dir",
                    str(base / "work"),
                    "--output-dir",
                    str(output),
                ])
            self.assertEqual(exit_code, 0)
            report = json.loads((output / "analysis.json").read_text(encoding="utf-8"))
            self.assertEqual(report["overall_execution_status"], "COMPLETED")
            result = report["domain_results"][0]
            self.assertEqual(result["execution_status"], "COMPLETED")
            self.assertGreaterEqual(result["diagnostic_subject_count"], 1)
            for section in TEXT_SECTIONS:
                self.assertIn(section, (output / "report.txt").read_text(encoding="utf-8"))


class EpcSessionAdapterTests(WorkflowTestCase):
    """Unified EPC adapter behaviour for GTPv2-C session-control evidence."""

    def use_payload(self, payload: dict) -> None:
        MODULE.execute_epc_pipeline = lambda capture, work_dir, case_id: payload

    def epc_result(self) -> dict:
        return self.domain_result()

    def test_gtpv2_only_capture_produces_usable_analysis(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "udp", "gtp", "gtpv2"])
        self.use_payload(epc_payload_with_session(instances=0))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        result = self.epc_result()
        self.assertEqual(result["execution_status"], "COMPLETED")
        self.assertEqual(result["diagnostic_subject_count"], 4)
        self.assertTrue(all(s["subject_type"] == "EPC_SESSION_CONTROL" for s in result["diagnostic_subjects"]))
        self.assertIn("no EPS Attach procedure instance", " ".join(result["degradation"]))

    def test_attach_only_capture_keeps_accepted_result(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "s1ap", "nas-eps"])
        self.use_payload(epc_payload_with_session(instances=1, gtpv2_events=0))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        result = self.epc_result()
        statuses = {item["protocol"]: item["extraction_status"] for item in result["protocol_evidence"]}
        self.assertEqual(statuses["GTPv2-C"], "NOT_OBSERVED_IN_CAPTURE")
        self.assertEqual(result["execution_status"], "COMPLETED")
        self.assertTrue(all(s["subject_type"] == "EPS_ATTACH" for s in result["diagnostic_subjects"]))

    def test_mixed_capture_produces_both_subject_classes(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "s1ap", "nas-eps", "gtpv2"])
        self.use_payload(epc_payload_with_session(instances=1))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        types = {s["subject_type"] for s in self.epc_result()["diagnostic_subjects"]}
        self.assertEqual(types, {"EPS_ATTACH", "EPC_SESSION_CONTROL"})

    def test_auto_selection_identifies_epc_from_gtpv2_evidence(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "udp", "gtp", "gtpv2"])
        self.use_payload(epc_payload_with_session(instances=0))
        self.assertEqual(self.run_cli(domains="auto"), 0)
        self.assertEqual(self.read_report()["requested_domains"], ["epc"])

    def test_missing_optional_protocol_is_not_a_failure(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "s1ap", "nas-eps"])
        self.use_payload(epc_payload_with_session(instances=1, gtpv2_events=0))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        self.assertEqual(self.epc_result()["execution_status"], "COMPLETED")

    def test_gtpv2_extraction_failure_is_never_completed(self) -> None:
        def failing(capture, work_dir, case_id):
            raise MODULE.AnalysisError("EXTRACTION_FAILED", "GTPv2-C extraction exited with 4")

        MODULE.execute_epc_pipeline = failing
        self.assertEqual(self.run_cli(domains="epc"), MODULE.EXIT_FAILED)
        result = self.epc_result()
        self.assertEqual(result["execution_status"], "FAILED")
        self.assertEqual(result["failure_code"], "EXTRACTION_FAILED")
        self.assertIn("GTPv2-C extraction", result.get("failure_message") or "")

    def test_correlator_failure_is_surfaced(self) -> None:
        def failing(capture, work_dir, case_id):
            raise MODULE.AnalysisError(
                "EXTRACTION_FAILED", "GTPv2-C transaction correlation exited with 4"
            )

        MODULE.execute_epc_pipeline = failing
        self.assertEqual(self.run_cli(domains="epc"), MODULE.EXIT_FAILED)
        result = self.epc_result()
        self.assertEqual(result["execution_status"], "FAILED")
        self.assertIn("transaction correlation", result.get("failure_message") or "")

    def test_session_domain_failure_is_surfaced(self) -> None:
        def failing(capture, work_dir, case_id):
            raise MODULE.AnalysisError(
                "EXTRACTION_FAILED", "EPC session-control analysis exited with 5"
            )

        MODULE.execute_epc_pipeline = failing
        self.assertEqual(self.run_cli(domains="epc"), MODULE.EXIT_FAILED)
        self.assertEqual(self.epc_result()["failure_code"], "EXTRACTION_FAILED")

    def test_failed_epc_beside_successful_5gc_is_partial(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "ngap", "nas-5gs", "s1ap"])
        MODULE.execute_epc_pipeline = lambda capture, work_dir, case_id: (_ for _ in ()).throw(
            MODULE.AnalysisError("EXTRACTION_FAILED", "GTPv2-C extraction exited with 4")
        )
        self.assertEqual(self.run_cli(domains="5gc,epc"), 0)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "PARTIAL")
        statuses = {result["domain"]: result["execution_status"] for result in report["domain_results"]}
        self.assertEqual(statuses["5gc"], "COMPLETED")
        self.assertEqual(statuses["epc"], "FAILED")

    def test_no_attach_to_session_association_is_invented(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "s1ap", "nas-eps", "gtpv2"])
        self.use_payload(epc_payload_with_session(instances=1))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        subjects = self.epc_result()["diagnostic_subjects"]
        attach = [s for s in subjects if s["subject_type"] == "EPS_ATTACH"]
        session = [s for s in subjects if s["subject_type"] == "EPC_SESSION_CONTROL"]
        self.assertTrue(attach and session)
        attach_references = {s["diagnostic_group_reference"] for s in attach}
        for subject in session:
            self.assertEqual(subject["attach_association"], "NOT_ESTABLISHED")
            self.assertNotIn(subject["diagnostic_group_reference"], attach_references)
            self.assertFalse(
                attach_references & set(subject.get("transaction_references") or [])
            )

    def test_no_s11_to_s5s8_link_is_invented(self) -> None:
        self.use_payload(epc_payload_with_session(instances=0))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        subjects = self.epc_result()["diagnostic_subjects"]
        interfaces = {s["interface"] for s in subjects}
        self.assertIn("S11", interfaces)
        self.assertIn("S5/S8", interfaces)
        for subject in subjects:
            self.assertEqual(subject["cross_interface_association"], "NOT_ESTABLISHED")

    def test_epc_boundary_stays_not_evaluated(self) -> None:
        self.use_payload(epc_payload_with_session(instances=0))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        result = self.epc_result()
        self.assertEqual(result["boundary_selection_status"], "NOT_EVALUATED")
        self.assertIsNone(result["first_abnormal_boundary"])
        for subject in result["diagnostic_subjects"]:
            self.assertEqual(subject["boundary_selection_status"], "NOT_EVALUATED")
            self.assertIsNone(subject["first_abnormal_boundary"])

    def test_session_report_is_deterministic(self) -> None:
        self.use_payload(epc_payload_with_session(instances=1))
        first, second = self.base / "session-a", self.base / "session-b"
        self.output = first
        self.assertEqual(self.run_cli(domains="epc"), 0)
        self.output = second
        self.assertEqual(self.run_cli(domains="epc"), 0)
        for name in ("analysis.json", "report.txt"):
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes(), name)

    def test_session_subjects_publish_no_subscriber_identity(self) -> None:
        self.use_payload(epc_payload_with_session(instances=1))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        published = (self.output / "analysis.json").read_text(encoding="utf-8") + self.read_text()
        for forbidden in ("460020000000001", "1122334455667788", "919000001", "10.45.0.7"):
            self.assertNotIn(forbidden, published)

    def test_text_report_states_session_control_scope(self) -> None:
        self.use_payload(epc_payload_with_session(instances=0))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        text = self.read_text()
        self.assertIn("EPC_SESSION_CONTROL", text)
        self.assertIn("cross-interface association: NOT_ESTABLISHED", text)


class EpcBoundaryAdapterTests(WorkflowTestCase):
    """Unified EPC adapter behaviour for failure-boundary orchestration."""

    def use_payload(self, payload: dict) -> None:
        MODULE.execute_epc_pipeline = lambda capture, work_dir, case_id: payload

    def epc_result(self) -> dict:
        return self.domain_result()

    def test_attach_only_runs_orchestration(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "s1ap", "nas-eps"])
        self.use_payload(epc_boundary_payload(attach_count=2, session=False))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        result = self.epc_result()
        self.assertEqual(result["boundary_selection_status"], "EVALUATED_PER_SUBJECT")
        self.assertEqual(result["boundary_summary"]["status_counts"], {"SELECTED": 2})
        for subject in result["diagnostic_subjects"]:
            self.assertEqual(subject["boundary_selection_status"], "SELECTED")
            self.assertEqual(subject["boundary_confidence"], "HIGH")

    def test_gtpv2_only_runs_orchestration(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "udp", "gtp", "gtpv2"])
        self.use_payload(epc_boundary_payload(attach_count=0))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        result = self.epc_result()
        self.assertEqual(result["boundary_selection_status"], "EVALUATED_PER_SUBJECT")
        session_subjects = [
            subject for subject in result["diagnostic_subjects"]
            if subject["subject_type"] == "EPC_SESSION_CONTROL"
        ]
        self.assertEqual(len(session_subjects), 4)
        for subject in session_subjects:
            self.assertEqual(subject["first_abnormal_boundary"]["frame_number"], 106)

    def test_mixed_capture_keeps_independent_boundaries(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "s1ap", "nas-eps", "gtpv2"])
        self.use_payload(epc_boundary_payload(attach_count=1))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        subjects = self.epc_result()["diagnostic_subjects"]
        attach = [s for s in subjects if s["subject_type"] == "EPS_ATTACH"]
        session = [s for s in subjects if s["subject_type"] == "EPC_SESSION_CONTROL"]
        self.assertEqual(attach[0]["first_abnormal_boundary"]["frame_number"], 47)
        for subject in session:
            self.assertEqual(subject["first_abnormal_boundary"]["frame_number"], 106)
        references = {s["diagnostic_group_reference"] for s in subjects}
        self.assertEqual(len(references), len(subjects))

    def test_selected_boundary_preserves_exact_frame_evidence(self) -> None:
        self.use_payload(epc_boundary_payload(attach_count=1))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        subject = self.epc_result()["diagnostic_subjects"][0]
        boundary = subject["first_abnormal_boundary"]
        self.assertEqual(boundary["frame_number"], 47)
        self.assertEqual(boundary["protocol"], "NAS-EPS")
        self.assertEqual(boundary["message_type"], "Attach reject")
        self.assertEqual(boundary["evidence_level"], "OBSERVED")
        self.assertEqual(boundary["evidence_refs"][0]["frame_number"], 47)
        self.assertEqual(boundary["ordering_basis"], "exact_frame_number")

    def test_no_global_epc_boundary_is_asserted(self) -> None:
        self.use_payload(epc_boundary_payload(attach_count=1))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        result = self.epc_result()
        self.assertIsNone(result["first_abnormal_boundary"])
        self.assertEqual(result["boundary_selection_status"], "EVALUATED_PER_SUBJECT")
        self.assertIn("no single global EPC boundary", result["first_abnormal_boundary_reason"])

    def test_orchestration_failure_degrades_without_losing_domain_evidence(self) -> None:
        payload = epc_boundary_payload(attach_count=1)
        payload["boundary_analysis"] = None
        payload["boundary_error"] = {"code": "ORCHESTRATION_FAILED", "message": "orchestration exited with 5"}
        self.use_payload(payload)
        self.assertEqual(self.run_cli(domains="epc"), 0)
        result = self.epc_result()
        self.assertEqual(result["execution_status"], "PARTIAL")
        self.assertEqual(result["failure_code"], "ORCHESTRATION_FAILED")
        self.assertEqual(result["diagnostic_subject_count"], 5)
        for subject in result["diagnostic_subjects"]:
            self.assertEqual(subject["boundary_selection_status"], "NOT_EVALUATED")
            self.assertIsNone(subject["first_abnormal_boundary"])
        self.assertTrue(any("ORCHESTRATION_FAILED" in item for item in result["degradation"]))

    def test_report_text_shows_the_selected_boundary(self) -> None:
        self.use_payload(epc_boundary_payload(attach_count=1))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        text = self.read_text()
        self.assertIn("boundary: ATTACH_REJECT_OBSERVED at frame 47", text)
        self.assertIn("NAS-EPS Attach reject", text)

    def test_boundary_report_is_deterministic(self) -> None:
        self.use_payload(epc_boundary_payload(attach_count=1))
        first, second = self.base / "boundary-a", self.base / "boundary-b"
        self.output = first
        self.assertEqual(self.run_cli(domains="epc"), 0)
        self.output = second
        self.assertEqual(self.run_cli(domains="epc"), 0)
        for name in ("analysis.json", "report.txt"):
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes(), name)

    def test_boundary_publication_is_privacy_safe(self) -> None:
        self.use_payload(epc_boundary_payload(attach_count=1))
        self.assertEqual(self.run_cli(domains="epc"), 0)
        published = (self.output / "analysis.json").read_text(encoding="utf-8") + self.read_text()
        for forbidden in ("460020000000001", "1122334455667788", "919000001", "10.45.0.7"):
            self.assertNotIn(forbidden, published)

    def test_5gc_boundary_is_untouched_by_epc_orchestration(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "ngap", "nas-5gs", "s1ap"])
        self.use_payload(epc_boundary_payload(attach_count=1))
        self.assertEqual(self.run_cli(domains="5gc,epc"), 0)
        report = self.read_report()
        five = [r for r in report["domain_results"] if r["domain"] == "5gc"][0]
        self.assertEqual(five["execution_status"], "COMPLETED")
        self.assertIn("boundary_selection_status", five)


if __name__ == "__main__":
    unittest.main()
