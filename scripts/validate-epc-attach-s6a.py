#!/usr/bin/env python3
"""Validate the bounded EPS Attach and S6a/S6d joint evidence capability."""

from __future__ import annotations

import json
import hashlib
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "skills" / "domain" / "epc-procedures"
SCRIPTS = PACKAGE / "scripts"
SCHEMA = PACKAGE / "schemas" / "epc-attach-s6a-analysis.schema.json"

REQUIRED = (
    "scripts/analyze_epc_attach_s6a.py",
    "scripts/epc_attach_s6a_model.py",
    "scripts/epc_attach_s6a_report.py",
    "schemas/epc-attach-s6a-analysis.schema.json",
    "tests/test_epc_attach_s6a.py",
)


def run(command):
    return subprocess.run(command, capture_output=True, text=True, check=False)


def main() -> int:
    errors = []
    for relative in REQUIRED:
        if not (PACKAGE / relative).is_file():
            errors.append(f"missing required file: {relative}")
    with tempfile.TemporaryDirectory() as compile_directory:
        for script in ("analyze_epc_attach_s6a.py", "epc_attach_s6a_model.py", "epc_attach_s6a_report.py"):
            try:
                py_compile.compile(
                    str(SCRIPTS / script),
                    cfile=str(Path(compile_directory) / f"{script}.pyc"),
                    doraise=True,
                )
            except py_compile.PyCompileError as exc:
                errors.append(f"compile failure {script}: {exc}")
    try:
        import jsonschema
    except ImportError:
        print("validate-epc-attach-s6a: jsonschema is required", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"validate-epc-attach-s6a: {error}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        attach = {
            "domain": "epc-procedures",
            "domain_version": "1.0.0",
            "model_version": "1.0.0",
            "analysis_scope": "bounded EPS Attach procedure evidence",
            "procedure": "eps-attach",
            "stage_vocabulary": ["attach-initiation"],
            "procedure_instances": [
                {
                    "procedure_reference": "epc-attach-aaaaaaaaaa",
                    "procedure": "eps-attach",
                    "attempt_index": 1,
                    "first_frame": 10,
                    "last_frame": 20,
                    "association": {"capture_file": "capture.pcapng", "strength": "STRONG", "basis": "S1AP", "sctp_association": "assoc"},
                    "stages": [
                        {"stage_id": "attach-initiation", "status": "OBSERVED", "messages": [], "first_frame": 10, "last_frame": 10, "evidence_refs": [], "conditional": False, "stage_name": "Attach Initiation"}
                    ],
                    "observations": [
                        {"observation_type": "nas_message", "procedure_stage": "attach-initiation", "protocol": "NAS-EPS", "message_type": "Attach request", "frame_number": 10, "evidence_level": "OBSERVED"}
                    ],
                    "deviations": [],
                    "evidence_limitations": [],
                    "additional_evidence_needed": [],
                }
            ],
            "instance_count": 1,
            "input_provenance": {"s1ap_events": {"file": "s1ap.jsonl", "event_count": 1}, "nas_eps_events": {"file": "nas.jsonl", "event_count": 1}},
            "unbound_evidence": [],
            "ambiguous_evidence": [],
            "global_first_abnormal_boundary": None,
            "global_boundary_evaluation": "NOT_EVALUATED",
            "limitations": [],
            "additional_evidence_needed": [],
            "not_confirmed": [],
        }
        ref = {
            "event_reference": "diameter-event:11.1",
            "frame_number": 11,
            "message_occurrence": 1,
            "direction": "REQUEST",
            "command_code": 318,
            "command_name": "Authentication-Information",
            "application_id": 16777251,
            "hop_by_hop_id": 11,
            "end_to_end_id": 12,
            "source_endpoint": "10.0.0.1:40000",
            "destination_endpoint": "10.0.0.2:3868",
        }
        diameter = {
            "analysis_name": "diameter-epc",
            "analysis_version": "1.0.0",
            "domain": "protocol",
            "capability": {
                "supported_commands": ["AIR", "AIA", "ULR", "ULA"],
                "recognized_unsupported_commands": ["NOR", "NOA"],
                "application_id": 16777251,
                "application_name": "S6a/S6d",
                "interface_identity": "UNPROVED",
                "interface_identity_basis": ["bounded application evidence"],
            },
            "input_provenance": {
                "capture_files": ["capture.pcapng"],
                "event_count": 1,
                "transaction_count": 1,
                "events_sha256": "0" * 64,
                "transactions_sha256": "1" * 64,
            },
            "command_inventory": [],
            "observations": [
                {
                    "observation_reference": "diameter-epc-observation:capture.pcapng:11.1",
                    "procedure": "AIR",
                    "procedure_family": "AIR",
                    "command_code": 318,
                    "command_name": "Authentication-Information",
                    "message_status": "OBSERVED",
                    "transaction_status": "OPEN_REQUEST",
                    "transaction_reference": "diameter-tx:capture.pcapng:318:11.1",
                    "application_result": "NOT_APPLICABLE",
                    "request": ref,
                    "answer": None,
                    "response_candidates": [],
                    "result": {
                        "core_result_status": "MISSING",
                        "namespace_status": "MISSING",
                        "application_result": "NOT_APPLICABLE",
                        "base_result_code": None,
                        "base_result_code_name": None,
                        "experimental_result_code": None,
                        "experimental_result_code_name": None,
                        "experimental_vendor_id": None,
                        "base_results": [],
                        "experimental_results": [],
                        "limitations": [],
                    },
                    "authentication_information": "NOT_APPLICABLE",
                    "latency_seconds": None,
                    "request_avp_presence": [],
                    "answer_avp_presence": [],
                    "limitations": [],
                    "not_confirmed": [],
                }
            ],
            "completeness": {
                "observation_count": 1,
                "observations_omitted": 0,
                "s6a_event_count": 1,
                "s6a_transaction_count": 1,
                "events_with_avp_omissions": 0,
                "unresolved_core_transactions": 0,
                "truncated_observations": 0,
            },
            "not_confirmed": [],
            "limitations": [],
        }
        attach_path = directory / "attach.json"
        diameter_path = directory / "diameter.json"
        attach_path.write_text(json.dumps(attach), encoding="utf-8")
        diameter_path.write_text(json.dumps(diameter), encoding="utf-8")
        output = directory / "joint.json"
        report = directory / "joint.txt"
        completed = run([
            sys.executable,
            str(SCRIPTS / "analyze_epc_attach_s6a.py"),
            "--attach", str(attach_path),
            "--diameter-epc", str(diameter_path),
            "--output", str(output),
            "--report", str(report),
        ])
        if completed.returncode != 0:
            errors.append(f"joint CLI failed: {completed.stderr.strip()}")
        elif not output.is_file() or not report.is_file():
            errors.append("joint CLI did not produce its outputs")
        else:
            document = json.loads(output.read_text(encoding="utf-8"))
            try:
                jsonschema.validate(document, json.loads(SCHEMA.read_text(encoding="utf-8")))
            except jsonschema.ValidationError as exc:
                errors.append(f"joint schema validation failed: {exc.message}")
            if document["identity_association"]["status"] == "ESTABLISHED":
                errors.append("joint analysis fabricated an established identity association")
            if document["diagnostics"]["root_cause_inferred"]:
                errors.append("joint analysis fabricated a root cause")
            if document["diameter_inventory"][0]["transaction_status"] != "OPEN_REQUEST":
                errors.append("valid OPEN_REQUEST was not preserved")
            if document["input_provenance"]["common_capture"]["status"] != "FILENAME_MATCH_ONLY":
                errors.append("filename equality was not bounded to FILENAME_MATCH_ONLY")
            if "identity association" not in report.read_text(encoding="utf-8").lower():
                errors.append("human-readable report lacks the identity-association section")

        capture_path = directory / "capture.pcapng"
        capture_path.write_bytes(b"synthetic capture bytes")
        observed_output = directory / "joint-observed.json"
        observed = run([
            sys.executable,
            str(SCRIPTS / "analyze_epc_attach_s6a.py"),
            "--attach", str(attach_path),
            "--diameter-epc", str(diameter_path),
            "--capture", str(capture_path),
            "--output", str(observed_output),
        ])
        if observed.returncode != 0:
            errors.append(f"standalone capture observation failed: {observed.stderr.strip()}")
        else:
            common_capture = json.loads(observed_output.read_text(encoding="utf-8"))[
                "input_provenance"
            ]["common_capture"]
            if common_capture["status"] != "CAPTURE_HASH_OBSERVED_UNBOUND":
                errors.append(
                    "a supplied capture without run evidence was not classified as unbound"
                )
            if common_capture["artifacts_bound_to_capture"]:
                errors.append("a supplied capture without run evidence bound its artifacts")

        def digest(path):
            return hashlib.sha256(path.read_bytes()).hexdigest()

        capture_digest = digest(capture_path)
        manifest = {
            "manifest_name": "epc-attach-s6a-coordinated-run",
            "manifest_schema_version": "1.0.0",
            "coordinated_run_id": "validate-coordinated-run",
            "capture": {"file": capture_path.name, "sha256": capture_digest},
            "artifacts": {
                "attach": {
                    "file": attach_path.name,
                    "sha256": digest(attach_path),
                    "producer": "epc-attach-analysis",
                },
                "diameter_epc": {
                    "file": diameter_path.name,
                    "sha256": digest(diameter_path),
                    "producer": "diameter-epc-analysis",
                },
            },
            "producers": {
                "attach": "epc-attach-analysis",
                "diameter_core": "diameter-core-extraction",
                "diameter_epc": "diameter-epc-analysis",
            },
            "executed_invocations": [
                {"producer": "epc-attach-analysis", "capture_sha256": capture_digest},
                {"producer": "diameter-core-extraction", "capture_sha256": capture_digest},
                {"producer": "diameter-epc-analysis", "capture_sha256": capture_digest},
            ],
        }
        manifest_path = directory / "run-manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        verified_output = directory / "joint-verified.json"
        verified = run([
            sys.executable,
            str(SCRIPTS / "analyze_epc_attach_s6a.py"),
            "--attach", str(attach_path),
            "--diameter-epc", str(diameter_path),
            "--capture", str(capture_path),
            "--run-manifest", str(manifest_path),
            "--output", str(verified_output),
        ])
        if verified.returncode != 0:
            errors.append(f"coordinated manifest path failed: {verified.stderr.strip()}")
        else:
            verified_document = json.loads(verified_output.read_text(encoding="utf-8"))
            try:
                jsonschema.validate(
                    verified_document, json.loads(SCHEMA.read_text(encoding="utf-8"))
                )
            except jsonschema.ValidationError as exc:
                errors.append(
                    f"verified joint schema validation failed: {exc.message}"
                )
            common_capture = verified_document["input_provenance"]["common_capture"]
            if common_capture["status"] != "VERIFIED_COORDINATED_CAPTURE_CONTEXT":
                errors.append("a digest-bound coordinated run was not verified")
            if verified_document["timeline_ordering"] != "VERIFIED_COMMON_CAPTURE":
                errors.append("a verified coordinated run did not publish common-capture ordering")
            if verified_document["identity_association"]["status"] == "ESTABLISHED":
                errors.append("verified provenance fabricated a per-UE identity association")

        tampered_manifest = json.loads(json.dumps(manifest))
        tampered_manifest["artifacts"]["attach"]["sha256"] = "f" * 64
        tampered_path = directory / "tampered-manifest.json"
        tampered_path.write_text(json.dumps(tampered_manifest), encoding="utf-8")
        tampered = run([
            sys.executable,
            str(SCRIPTS / "analyze_epc_attach_s6a.py"),
            "--attach", str(attach_path),
            "--diameter-epc", str(diameter_path),
            "--capture", str(capture_path),
            "--run-manifest", str(tampered_path),
            "--output", str(directory / "joint-tampered.json"),
        ])
        if tampered.returncode != 2:
            errors.append("a tampered coordinated-run manifest was not rejected as invalid input")

        other_capture = directory / "other.pcapng"
        other_capture.write_bytes(b"different capture bytes")
        contradiction = run([
            sys.executable,
            str(SCRIPTS / "analyze_epc_attach_s6a.py"),
            "--attach", str(attach_path),
            "--diameter-epc", str(diameter_path),
            "--capture", str(other_capture),
            "--run-manifest", str(manifest_path),
            "--output", str(directory / "joint-contradiction.json"),
        ])
        if contradiction.returncode != 2:
            errors.append("a capture digest contradiction was not rejected as invalid input")

    if errors:
        for error in errors:
            print(f"validate-epc-attach-s6a: {error}", file=sys.stderr)
        return 1
    print("epc-attach-s6a validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())