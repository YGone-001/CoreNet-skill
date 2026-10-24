#!/usr/bin/env python3
"""User-facing tests for the unified core-network PCAP analysis workflow.

These tests exercise the executable entry point, its report contract, its
execution-status semantics and its file-system safety. The two external
boundaries (capture inventory and the accepted 5GC pipeline) are replaced by
deterministic fakes so the workflow is testable without tshark or a capture
corpus. One opt-in smoke test runs the real boundaries against a local capture
when CORENET_SMOKE_CAPTURE is set.
"""

from __future__ import annotations

import contextlib
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


def summary_no_boundary() -> dict:
    summary = summary_selected()
    summary["selection_status"] = "NO_ABNORMAL_BOUNDARY_OBSERVED"
    summary["selected_boundary"] = None
    summary["boundary_confidence"] = None
    summary["candidate_boundaries_count"] = 0
    summary["domain_status"]["registration"]["deviation_count"] = 5
    summary["orchestration_status"]["candidate_boundary_count"] = 0
    return summary


def summary_no_domain_executed() -> dict:
    return {
        "case_id": "capture-fixture",
        "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
        "selected_boundary": None,
        "boundary_confidence": None,
        "evidence_limitations": [],
        "additional_evidence_needed": [],
        "candidate_boundaries_count": 0,
        "domain_status": {
            "registration": {"execution_status": "SKIPPED_NO_INPUTS", "first_stop_reason": "no inputs"},
            "pdu_session": {"execution_status": "SKIPPED_NO_INPUTS", "first_stop_reason": "no inputs"},
            "handover_mobility": {"execution_status": "SKIPPED_NO_INPUTS", "first_stop_reason": "no inputs"},
        },
        "orchestration_status": {
            "execution_status": "SKIPPED_NO_DOMAIN_OUTPUTS",
            "diagnostic_group_count": 0,
        },
        "protocol_status": {"nas-5gs": "SUCCESS", "ngap": "SUCCESS"},
    }


def summary_extraction_failed() -> dict:
    summary = summary_no_domain_executed()
    summary["protocol_status"] = {"nas-5gs": "ERROR_127", "ngap": "ERROR_127"}
    return summary


class WorkflowTestCase(unittest.TestCase):
    """Base class wiring deterministic fakes into the two external boundaries."""

    summary_factory = staticmethod(summary_selected)
    inventory_factory = staticmethod(inventory_5gc)

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)
        self.capture = self.base / "fixture.pcap"
        self.capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
        self.work = self.base / "work"
        self.output = self.base / "out"
        self.pipeline_calls: list[tuple[str, str]] = []
        self._original_inventory = MODULE.inventory_capture
        self._original_pipeline = MODULE.execute_5gc_pipeline
        self._original_revision = MODULE.repository_revision
        MODULE.inventory_capture = self.fake_inventory
        MODULE.execute_5gc_pipeline = self.fake_pipeline
        MODULE.repository_revision = lambda root=MODULE.ROOT: "0" * 40

    def tearDown(self) -> None:
        MODULE.inventory_capture = self._original_inventory
        MODULE.execute_5gc_pipeline = self._original_pipeline
        MODULE.repository_revision = self._original_revision
        self._temporary.cleanup()

    def fake_inventory(self, path: Path) -> dict:
        return self.inventory_factory()

    def fake_pipeline(self, capture: Path, work_dir: Path, case_id: str):
        self.pipeline_calls.append((str(capture), case_id))
        artifacts = work_dir / "5gc" / "raw_skill_artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / "nas-5gs-events.jsonl").write_text('{"a":1}\n{"b":2}\n', encoding="utf-8")
        (artifacts / "ngap-events.jsonl").write_text('{"c":3}\n', encoding="utf-8")
        return self.summary_factory(), artifacts

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


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------


class CapabilityContractTests(unittest.TestCase):
    def test_domain_identities_are_fixed(self) -> None:
        self.assertEqual(set(MODULE.DOMAIN_CAPABILITIES), {"5gc", "epc", "ims"})

    def test_only_5gc_is_implemented(self) -> None:
        self.assertEqual(
            MODULE.DOMAIN_CAPABILITIES["5gc"]["implementation_status"], "IMPLEMENTED"
        )
        for domain in ("epc", "ims"):
            capability = MODULE.DOMAIN_CAPABILITIES[domain]
            self.assertEqual(capability["implementation_status"], "UNSUPPORTED")
            self.assertIsNone(capability["entry_point"])
            self.assertFalse(capability["entry_point_available"])
            self.assertTrue(capability["unsupported_reason"])
            self.assertEqual(capability["supported_protocol_families"], [])
            self.assertEqual(capability["analysis_capabilities"], [])

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


class CliSurfaceTests(unittest.TestCase):
    def test_help_exits_zero(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                MODULE.main(["--help"])
        self.assertEqual(caught.exception.code, 0)

    def test_invalid_domain_request_fails(self) -> None:
        with self.assertRaises(MODULE.AnalysisError) as caught:
            MODULE.resolve_selection("gprs", MODULE.detect_domains({"protocols": [], "transports": []}))
        self.assertEqual(caught.exception.code, "INVALID_DOMAIN")


# ---------------------------------------------------------------------------
# Execution scenarios
# ---------------------------------------------------------------------------


class SupportedExecutionTests(WorkflowTestCase):
    def test_supported_5gc_execution_writes_both_reports(self) -> None:
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        self.assertTrue((self.output / "analysis.json").is_file())
        self.assertTrue((self.output / "report.txt").is_file())
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "COMPLETED")
        self.assertEqual(report["requested_domains"], ["5gc"])
        self.assertTrue(REPORT_KEYS.issubset(report))
        result = report["domain_results"][0]
        self.assertTrue(DOMAIN_RESULT_KEYS.issubset(result))
        self.assertEqual(len(self.pipeline_calls), 1)

    def test_domain_and_orchestration_evidence_is_propagated(self) -> None:
        self.run_cli(domains="5gc")
        result = self.read_report()["domain_results"][0]
        registration = {
            item["procedure_domain"]: item for item in result["procedure_summaries"]
        }["5gc-registration-mobility"]
        self.assertEqual(registration["execution_status"], "EXECUTED")
        self.assertEqual(registration["instance_count"], 1)
        self.assertEqual(registration["deviation_count"], 2)
        self.assertEqual(result["diagnostic_groups"]["diagnostic_group_count"], 1)
        self.assertEqual(
            result["diagnostic_groups"]["consumed_domain_instance_counts"]["registration"], 1
        )
        counts = {item["protocol"]: item["event_count"] for item in result["protocol_evidence"]}
        self.assertEqual(counts["nas-5gs"], 2)
        self.assertEqual(counts["ngap"], 1)
        self.assertIsNone(counts["pfcp"])

    def test_authentication_boundary_evidence_is_preserved(self) -> None:
        self.run_cli(domains="5gc")
        boundary = self.read_report()["domain_results"][0]["first_abnormal_boundary"]
        self.assertEqual(boundary["frame_number"], 11)
        self.assertEqual(boundary["protocol"], "NAS-5GS")
        self.assertEqual(boundary["message_type"], "Authentication failure")
        self.assertEqual(boundary["procedure_stage"], "authentication")
        self.assertEqual(boundary["evidence_level"], "OBSERVED")
        self.assertEqual(boundary["selection_status"], "SELECTED")

    def test_report_envelope_exposes_capture_provenance(self) -> None:
        self.run_cli(domains="5gc")
        report = self.read_report()
        self.assertEqual(report["capture"]["sha256"], hashlib.sha256(self.capture.read_bytes()).hexdigest())
        self.assertEqual(report["capture"]["frame_count"], 16)
        self.assertEqual(report["toolchain"]["decoder"]["name"], "tshark")
        self.assertIn("5gc", [item["domain"] for item in report["domain_capabilities"]])


class NoBoundaryTests(WorkflowTestCase):
    summary_factory = staticmethod(summary_no_boundary)

    def test_no_boundary_is_not_a_health_claim(self) -> None:
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        report = self.read_report()
        result = report["domain_results"][0]
        self.assertEqual(report["overall_execution_status"], "COMPLETED")
        self.assertIsNone(result["first_abnormal_boundary"])
        self.assertEqual(result["boundary_selection_status"], "NO_ABNORMAL_BOUNDARY_OBSERVED")
        text = self.read_text().lower()
        for forbidden in ("network is healthy", "end-to-end success", "service passed", "root cause is"):
            self.assertNotIn(forbidden, text)
        self.assertIn("not evidence that the network", text)
        self.assertTrue(
            any("no supported abnormal boundary" in item for item in report["limitations"])
        )


class UnsupportedDomainTests(WorkflowTestCase):
    def test_epc_request_is_unsupported(self) -> None:
        self.assertEqual(self.run_cli(domains="epc"), MODULE.EXIT_UNSUPPORTED)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "UNSUPPORTED")
        result = report["domain_results"][0]
        self.assertEqual(result["domain"], "epc")
        self.assertEqual(result["execution_status"], "UNSUPPORTED")
        self.assertTrue(result["unsupported_reason"])
        self.assertEqual(self.pipeline_calls, [])

    def test_ims_request_is_unsupported(self) -> None:
        self.assertEqual(self.run_cli(domains="ims"), MODULE.EXIT_UNSUPPORTED)
        result = self.read_report()["domain_results"][0]
        self.assertEqual(result["domain"], "ims")
        self.assertEqual(result["execution_status"], "UNSUPPORTED")
        self.assertEqual(self.pipeline_calls, [])

    def test_mixed_request_is_partial_and_keeps_each_status(self) -> None:
        self.assertEqual(self.run_cli(domains="5gc,ims"), 0)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "PARTIAL")
        statuses = {result["domain"]: result["execution_status"] for result in report["domain_results"]}
        self.assertEqual(statuses, {"5gc": "COMPLETED", "ims": "UNSUPPORTED"})
        self.assertEqual(len(self.pipeline_calls), 1)

    def test_unsupported_domain_stays_visible_when_supported_domain_fails(self) -> None:
        def failing_pipeline(capture, work_dir, case_id):
            raise MODULE.AnalysisError("PIPELINE_FAILED", "adapter exited with 1")

        MODULE.execute_5gc_pipeline = failing_pipeline
        self.assertEqual(self.run_cli(domains="5gc,ims"), MODULE.EXIT_FAILED)
        report = self.read_report()
        statuses = {result["domain"]: result["execution_status"] for result in report["domain_results"]}
        self.assertEqual(statuses, {"5gc": "FAILED", "ims": "UNSUPPORTED"})
        self.assertEqual(report["overall_execution_status"], "FAILED")

    def test_domain_without_adapter_fails_visibly_instead_of_vanishing(self) -> None:
        capability = MODULE.DOMAIN_CAPABILITIES["epc"]
        original = capability["implementation_status"]
        capability["implementation_status"] = "IMPLEMENTED"
        try:
            self.assertEqual(self.run_cli(domains="epc"), MODULE.EXIT_FAILED)
            report = self.read_report()
            result = report["domain_results"][0]
            self.assertEqual(result["domain"], "epc")
            self.assertEqual(result["execution_status"], "FAILED")
            self.assertEqual(result["failure_code"], "NO_DOMAIN_ADAPTER")
        finally:
            capability["implementation_status"] = original


class DetectionTests(WorkflowTestCase):
    def test_auto_selects_5gc_on_access_signaling(self) -> None:
        self.assertEqual(self.run_cli(domains="auto"), 0)
        report = self.read_report()
        self.assertEqual(report["requested_domains"], ["5gc"])
        self.assertEqual(report["workflow"]["selection_mode"], "auto")
        detection = report["domain_results"][0]["detection"]
        self.assertEqual(detection["status"], "CONFIRMED")
        self.assertIn("NGAP", detection["basis"])

    def test_gtp_u_only_is_ambiguous_and_not_analyzed(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "udp", "gtp"])
        self.assertEqual(self.run_cli(domains="auto"), MODULE.EXIT_INSUFFICIENT_EVIDENCE)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(report["requested_domains"], [])
        self.assertEqual(self.pipeline_calls, [])

    def test_pfcp_only_is_suspected_not_confirmed(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "udp", "pfcp"])
        self.assertEqual(self.run_cli(domains="auto"), MODULE.EXIT_INSUFFICIENT_EVIDENCE)
        report = self.read_report()
        self.assertEqual(report["requested_domains"], [])
        self.assertTrue(any("SUSPECTED" in item for item in report["limitations"]))

    def test_sip_only_does_not_confirm_ims(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "udp", "sip"])
        self.assertEqual(self.run_cli(domains="auto"), MODULE.EXIT_INSUFFICIENT_EVIDENCE)
        report = self.read_report()
        self.assertEqual(report["requested_domains"], [])
        self.assertEqual(self.pipeline_calls, [])

    def test_epc_signaling_is_confirmed_but_unsupported(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "s1ap", "nas-eps"])
        self.assertEqual(self.run_cli(domains="auto"), MODULE.EXIT_UNSUPPORTED)
        report = self.read_report()
        self.assertEqual(report["requested_domains"], ["epc"])
        self.assertEqual(report["domain_results"][0]["detection"]["status"], "CONFIRMED")
        self.assertEqual(self.pipeline_calls, [])

    def test_mixed_5gc_and_epc_evidence_is_not_collapsed(self) -> None:
        self.inventory_factory = lambda: inventory(["eth", "ip", "sctp", "ngap", "nas-5gs", "s1ap"])
        self.assertEqual(self.run_cli(domains="auto"), 0)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "PARTIAL")
        statuses = {result["domain"]: result["execution_status"] for result in report["domain_results"]}
        self.assertEqual(statuses, {"5gc": "COMPLETED", "epc": "UNSUPPORTED"})
        self.assertEqual(len(self.pipeline_calls), 1)


class FailureTests(WorkflowTestCase):
    def test_malformed_capture_fails_with_nonzero_exit(self) -> None:
        self.capture.write_bytes(b"not a capture at all")
        self.assertEqual(self.run_cli(domains="auto"), MODULE.EXIT_FAILED)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "FAILED")
        self.assertEqual(report["failure"]["code"], "MALFORMED_CAPTURE")
        self.assertEqual(self.pipeline_calls, [])

    def test_missing_decoder_fails_with_nonzero_exit(self) -> None:
        def unavailable(path: Path) -> dict:
            raise MODULE.AnalysisError("DECODER_UNAVAILABLE", "packet decoder is unavailable")

        MODULE.inventory_capture = unavailable
        self.assertEqual(self.run_cli(domains="auto"), MODULE.EXIT_FAILED)
        self.assertEqual(self.read_report()["failure"]["code"], "DECODER_UNAVAILABLE")

    def test_extraction_failure_never_becomes_no_boundary_evidence(self) -> None:
        self.summary_factory = summary_extraction_failed
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        report = self.read_report()
        result = report["domain_results"][0]
        self.assertEqual(report["overall_execution_status"], "FAILED")
        self.assertEqual(result["execution_status"], "FAILED")
        self.assertEqual(result["failure_code"], "EXTRACTION_FAILED")
        self.assertIsNone(result["first_abnormal_boundary"])

    def test_no_domain_executed_is_insufficient_evidence(self) -> None:
        self.summary_factory = summary_no_domain_executed
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_INSUFFICIENT_EVIDENCE)
        report = self.read_report()
        self.assertEqual(report["overall_execution_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIsNone(report["domain_results"][0]["first_abnormal_boundary"])


class PrivacyAndSafetyTests(WorkflowTestCase):
    def test_identifiers_and_paths_are_redacted(self) -> None:
        def leaky_summary() -> dict:
            summary = summary_selected()
            summary["evidence_limitations"] = [
                "subscriber 001010000000001 observed at /home/analyst/captures/fault.pcap"
            ]
            summary["additional_evidence_needed"] = ["collect C:\\Users\\analyst\\trace.pcap"]
            return summary

        self.summary_factory = leaky_summary
        self.run_cli(domains="5gc")
        published = (self.output / "analysis.json").read_text(encoding="utf-8") + self.read_text()
        self.assertNotIn("001010000000001", published)
        self.assertNotIn("analyst", published)
        self.assertNotIn("/home/", published)

    def test_existing_outputs_are_not_overwritten_silently(self) -> None:
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        first = (self.output / "analysis.json").read_text(encoding="utf-8")
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        self.assertEqual((self.output / "analysis.json").read_text(encoding="utf-8"), first)
        self.assertEqual(self.run_cli("--force", domains="5gc"), 0)

    def test_repository_work_directory_is_refused(self) -> None:
        self.work = ROOT / "tmp-should-never-exist"
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        self.assertFalse(self.work.exists())
        self.assertEqual(self.pipeline_calls, [])

    def test_frozen_benchmark_output_directory_is_refused(self) -> None:
        self.output = FROZEN_BENCHMARK_DIR / "cases" / "public-5gc-auth-negative"
        before = sorted(path.name for path in self.output.iterdir())
        self.assertEqual(self.run_cli(domains="5gc"), MODULE.EXIT_FAILED)
        self.assertEqual(sorted(path.name for path in self.output.iterdir()), before)

    def test_input_capture_is_not_modified(self) -> None:
        before = self.capture.read_bytes()
        self.run_cli(domains="5gc")
        self.assertEqual(self.capture.read_bytes(), before)


class DeterminismTests(WorkflowTestCase):
    def test_repeated_runs_produce_identical_reports(self) -> None:
        first_output, second_output = self.base / "out-a", self.base / "out-b"
        self.output = first_output
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        self.output = second_output
        self.assertEqual(self.run_cli(domains="5gc"), 0)
        for name in ("analysis.json", "report.txt"):
            self.assertEqual(
                (first_output / name).read_bytes(),
                (second_output / name).read_bytes(),
                name,
            )

    def test_machine_paths_do_not_appear_in_reports(self) -> None:
        self.run_cli(domains="5gc")
        published = (self.output / "analysis.json").read_text(encoding="utf-8") + self.read_text()
        self.assertNotIn(str(self.base), published)
        self.assertNotIn(str(self.work), published)


class BenchmarkInvarianceTests(WorkflowTestCase):
    def _snapshot(self) -> dict[str, str]:
        snapshot: dict[str, str] = {}
        for path in sorted(FROZEN_BENCHMARK_DIR.rglob("*")):
            if path.is_file():
                snapshot[str(path.relative_to(FROZEN_BENCHMARK_DIR))] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
        return snapshot

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
            boundary = result["first_abnormal_boundary"]
            if boundary is not None:
                self.assertIsInstance(boundary["frame_number"], int)
                self.assertTrue(boundary["protocol"])
                self.assertTrue(boundary["message_type"])


if __name__ == "__main__":
    unittest.main()
