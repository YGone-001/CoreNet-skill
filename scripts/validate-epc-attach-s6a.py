#!/usr/bin/env python3
"""Validate the bounded EPS Attach and S6a/S6d joint evidence capability."""

from __future__ import annotations

import json
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
            "procedure_instances": [
                {
                    "procedure_reference": "epc-attach-aaaaaaaaaa",
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
            "input_provenance": {"capture_files": ["capture.pcapng"]},
            "observations": [
                {
                    "observation_reference": "diameter-epc-observation:capture.pcapng:11.1",
                    "procedure": "AIR",
                    "command_code": 318,
                    "message_status": "OBSERVED",
                    "transaction_status": "OPEN_REQUEST",
                    "transaction_reference": "diameter-tx:capture.pcapng:318:11.1",
                    "application_result": "NOT_APPLICABLE",
                    "request": ref,
                    "answer": None,
                    "response_candidates": [],
                    "result": {"core_result_status": "MISSING", "namespace_status": "MISSING", "application_result": "NOT_APPLICABLE", "base_result_code": None, "base_result_code_name": None, "experimental_result_code": None, "experimental_result_code_name": None, "experimental_vendor_id": None},
                    "authentication_information": "NOT_APPLICABLE",
                    "latency_seconds": None,
                    "limitations": [],
                }
            ],
            "completeness": {"observation_count": 1},
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
            if "identity association" not in report.read_text(encoding="utf-8").lower():
                errors.append("human-readable report lacks the identity-association section")

    if errors:
        for error in errors:
            print(f"validate-epc-attach-s6a: {error}", file=sys.stderr)
        return 1
    print("epc-attach-s6a validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())