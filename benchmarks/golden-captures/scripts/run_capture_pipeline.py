#!/usr/bin/env python3
"""Execute the automated CoreNet Skill pipeline mechanically on a packet capture.

Runs the existing accepted Skills across Protocol, Correlation, Domain, and
Orchestration layers. Records exit codes and intermediate artifacts in an external
working directory, then emits a sanitized summary. Does NOT perform protocol
decoding or semantic modifications.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_DIR = ROOT / "benchmarks" / "golden-captures"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sanitize_result import sanitize_failure_boundary_result


# Ensure TShark is discoverable on PATH
def ensure_tshark_path() -> None:
    if not shutil.which("tshark"):
        for candidate in (r"D:\Wireshark", r"C:\Program Files\Wireshark", r"C:\Program Files (x86)\Wireshark"):
            if os.path.isdir(candidate):
                os.environ["PATH"] = candidate + os.pathsep + os.environ.get("PATH", "")
                break


def get_tshark_version() -> str:
    ensure_tshark_path()
    try:
        proc = subprocess.run(["tshark", "--version"], capture_output=True, text=True, check=False)
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout.splitlines()[0].strip()
    except OSError:
        pass
    return "tshark (unavailable)"


def get_skill_versions() -> dict[str, str]:
    versions = {}
    skills_dir = ROOT / "skills"
    for manifest_path in skills_dir.rglob("manifest.yaml"):
        skill_name = manifest_path.parent.name
        try:
            for line in manifest_path.read_text(encoding="utf-8").splitlines():
                if line.startswith("version:"):
                    versions[skill_name] = line.split(":", 1)[1].strip().strip('"\'')
                    break
        except OSError:
            pass
    return versions


def validate_work_dir_safety(work_dir: Path, allow_repo_workdir: bool = False) -> None:
    """Refuse a real benchmark work directory located under the CoreNet repository."""
    if allow_repo_workdir:
        return
    resolved_work = work_dir.resolve()
    resolved_root = ROOT.resolve()
    try:
        resolved_work.relative_to(resolved_root)
        raise ValueError(
            f"Work directory {work_dir} is located inside the CoreNet repository. "
            "Benchmark runs must use an external work directory (e.g. /tmp/corenet-golden-run/ or --allow-repo-workdir for tests)."
        )
    except ValueError as exc:
        if "is located inside" in str(exc):
            raise
        # Not relative to ROOT -> safe external directory
        pass


def run_command(cmd: list[str], log_file: Path | None = None) -> tuple[int, str, str, float]:
    start_time = time.monotonic()
    env = os.environ.copy()
    ensure_tshark_path()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
        duration = time.monotonic() - start_time
        stdout = proc.stdout
        stderr = proc.stderr
        rc = proc.returncode
    except Exception as exc:
        duration = time.monotonic() - start_time
        rc = 127
        stdout = ""
        stderr = str(exc)

    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            log_file.write_text(
                f"COMMAND: {' '.join(cmd)}\nEXIT_CODE: {rc}\nDURATION: {duration:.3f}s\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}\n",
                encoding="utf-8",
            )
        except OSError:
            pass
    return rc, stdout, stderr, duration


def run_pipeline(
    capture_path: Path,
    work_dir: Path,
    case_id: str,
    allow_repo_workdir: bool = False,
) -> dict[str, Any]:
    """Execute the full CoreNet automated pipeline mechanically."""
    validate_work_dir_safety(work_dir, allow_repo_workdir)
    work_dir.mkdir(parents=True, exist_ok=True)
    raw_artifacts_dir = work_dir / "raw_skill_artifacts"
    logs_dir = work_dir / "logs"
    raw_artifacts_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    pipeline_log: dict[str, Any] = {
        "case_id": case_id,
        "capture_file": capture_path.name,
        "steps": {},
        "artifacts_produced": [],
    }

    # 1. Protocol Extractors
    proto_extractors = {
        "ngap": ROOT / "skills" / "protocol" / "ngap" / "scripts" / "extract-ngap.py",
        "nas-5gs": ROOT / "skills" / "protocol" / "nas-5gs" / "scripts" / "extract-nas5gs.py",
        "pfcp": ROOT / "skills" / "protocol" / "pfcp" / "scripts" / "extract-pfcp.py",
        "gtpu": ROOT / "skills" / "protocol" / "gtpu" / "scripts" / "extract-gtpu.py",
        "sbi-http2": ROOT / "skills" / "protocol" / "sbi-http2" / "scripts" / "extract-sbi-http2.py",
    }

    protocol_outputs: dict[str, Path] = {}
    for proto_name, script_path in proto_extractors.items():
        out_file = raw_artifacts_dir / f"{proto_name}-events.jsonl"
        trace_file = raw_artifacts_dir / f"{proto_name}-trace.jsonl"
        cmd = [
            sys.executable,
            str(script_path),
            str(capture_path),
            "--output",
            str(out_file),
            "--trace-output",
            str(trace_file),
            "--force",
        ]
        rc, stdout, stderr, dur = run_command(cmd, logs_dir / f"extract_{proto_name}.log")
        step_status = "SUCCESS" if rc == 0 else ("NOT_OBSERVED_IN_CAPTURE" if rc == 6 else f"ERROR_{rc}")
        pipeline_log["steps"][f"extract_{proto_name}"] = {
            "exit_code": rc,
            "status": step_status,
            "duration": dur,
            "output_present": out_file.is_file(),
        }
        if rc == 0 and out_file.is_file():
            protocol_outputs[proto_name] = out_file
            pipeline_log["artifacts_produced"].append(out_file.name)

    # 2. Correlation Layer
    correlation_output: Path | None = None
    if "ngap" in protocol_outputs and "nas-5gs" in protocol_outputs:
        correlate_script = ROOT / "skills" / "correlation" / "cross-protocol-evidence" / "scripts" / "correlate-events.py"
        correlate_out = raw_artifacts_dir / "correlation-groups.jsonl"
        cmd = [
            sys.executable,
            str(correlate_script),
            "--ngap-events",
            str(protocol_outputs["ngap"]),
            "--nas-events",
            str(protocol_outputs["nas-5gs"]),
            "--output",
            str(correlate_out),
            "--force",
        ]
        rc, stdout, stderr, dur = run_command(cmd, logs_dir / "correlate_events.log")
        pipeline_log["steps"]["correlation"] = {
            "exit_code": rc,
            "status": "SUCCESS" if rc == 0 else f"ERROR_{rc}",
            "duration": dur,
            "output_present": correlate_out.is_file(),
        }
        if rc == 0 and correlate_out.is_file():
            correlation_output = correlate_out
            pipeline_log["artifacts_produced"].append(correlate_out.name)
    else:
        pipeline_log["steps"]["correlation"] = {
            "exit_code": 0,
            "status": "SKIPPED_INSUFFICIENT_INPUTS",
            "duration": 0.0,
            "output_present": False,
        }

    # 3. Domain Layer
    domain_outputs: dict[str, Path] = {}

    # 3.1 Registration Domain
    reg_script = ROOT / "skills" / "domain" / "5gc-registration-mobility" / "scripts" / "analyze-registration.py"
    reg_out = raw_artifacts_dir / "5gc-registration-mobility-analysis.json"
    reg_cmd = [sys.executable, str(reg_script), "--output", str(reg_out), "--force"]
    if "ngap" in protocol_outputs:
        reg_cmd.extend(["--ngap", str(protocol_outputs["ngap"])])
    if "nas-5gs" in protocol_outputs:
        reg_cmd.extend(["--nas", str(protocol_outputs["nas-5gs"])])
    if correlation_output:
        reg_cmd.extend(["--correlation", str(correlation_output)])

    if "ngap" in protocol_outputs or "nas-5gs" in protocol_outputs:
        rc, stdout, stderr, dur = run_command(reg_cmd, logs_dir / "analyze_registration.log")
        pipeline_log["steps"]["domain_registration"] = {
            "exit_code": rc,
            "status": "SUCCESS" if rc == 0 else f"ERROR_{rc}",
            "duration": dur,
            "output_present": reg_out.is_file(),
        }
        if rc == 0 and reg_out.is_file():
            domain_outputs["registration"] = reg_out
            pipeline_log["artifacts_produced"].append(reg_out.name)
    else:
        pipeline_log["steps"]["domain_registration"] = {
            "exit_code": 0,
            "status": "SKIPPED_NO_N1_N2",
            "duration": 0.0,
            "output_present": False,
        }

    # 3.2 PDU Session Domain
    pdu_script = ROOT / "skills" / "domain" / "5gc-pdu-session" / "scripts" / "analyze_pdu_session.py"
    pdu_out = raw_artifacts_dir / "5gc-pdu-session-analysis.json"
    pdu_cmd = [sys.executable, str(pdu_script), "--output", str(pdu_out), "--force"]
    if "nas-5gs" in protocol_outputs:
        pdu_cmd.extend(["--nas", str(protocol_outputs["nas-5gs"])])
    if "ngap" in protocol_outputs:
        pdu_cmd.extend(["--ngap", str(protocol_outputs["ngap"])])
    if "pfcp" in protocol_outputs:
        pdu_cmd.extend(["--pfcp", str(protocol_outputs["pfcp"])])
    if "gtpu" in protocol_outputs:
        pdu_cmd.extend(["--gtpu", str(protocol_outputs["gtpu"])])
    if "sbi-http2" in protocol_outputs:
        pdu_cmd.extend(["--sbi", str(protocol_outputs["sbi-http2"])])
    if correlation_output:
        pdu_cmd.extend(["--correlation", str(correlation_output)])

    has_pdu_input = any(p in protocol_outputs for p in ("nas-5gs", "ngap", "pfcp", "gtpu", "sbi-http2"))
    if has_pdu_input:
        rc, stdout, stderr, dur = run_command(pdu_cmd, logs_dir / "analyze_pdu_session.log")
        pipeline_log["steps"]["domain_pdu_session"] = {
            "exit_code": rc,
            "status": "SUCCESS" if rc == 0 else f"ERROR_{rc}",
            "duration": dur,
            "output_present": pdu_out.is_file(),
        }
        if rc == 0 and pdu_out.is_file():
            domain_outputs["pdu_session"] = pdu_out
            pipeline_log["artifacts_produced"].append(pdu_out.name)
    else:
        pipeline_log["steps"]["domain_pdu_session"] = {
            "exit_code": 0,
            "status": "SKIPPED_NO_INPUTS",
            "duration": 0.0,
            "output_present": False,
        }

    # 3.3 Handover Mobility Domain
    ho_script = ROOT / "skills" / "domain" / "5gc-handover-mobility" / "scripts" / "analyze_handover_mobility.py"
    ho_out = raw_artifacts_dir / "5gc-handover-mobility-analysis.json"
    ho_cmd = [sys.executable, str(ho_script), "--output", str(ho_out), "--force"]
    if "ngap" in protocol_outputs:
        ho_cmd.extend(["--ngap", str(protocol_outputs["ngap"])])
    if "pfcp" in protocol_outputs:
        ho_cmd.extend(["--pfcp", str(protocol_outputs["pfcp"])])
    if "gtpu" in protocol_outputs:
        ho_cmd.extend(["--gtpu", str(protocol_outputs["gtpu"])])
    if "sbi-http2" in protocol_outputs:
        ho_cmd.extend(["--sbi", str(protocol_outputs["sbi-http2"])])
    if "pdu_session" in domain_outputs:
        ho_cmd.extend(["--pdu-session", str(domain_outputs["pdu_session"])])

    has_ho_input = any(p in protocol_outputs for p in ("ngap", "pfcp", "gtpu", "sbi-http2"))
    if has_ho_input:
        rc, stdout, stderr, dur = run_command(ho_cmd, logs_dir / "analyze_handover_mobility.log")
        pipeline_log["steps"]["domain_handover_mobility"] = {
            "exit_code": rc,
            "status": "SUCCESS" if rc == 0 else f"ERROR_{rc}",
            "duration": dur,
            "output_present": ho_out.is_file(),
        }
        if rc == 0 and ho_out.is_file():
            domain_outputs["handover_mobility"] = ho_out
            pipeline_log["artifacts_produced"].append(ho_out.name)
    else:
        pipeline_log["steps"]["domain_handover_mobility"] = {
            "exit_code": 0,
            "status": "SKIPPED_NO_INPUTS",
            "duration": 0.0,
            "output_present": False,
        }

    # 4. Orchestration Layer (5gc-failure-boundary)
    orch_script = ROOT / "skills" / "orchestration" / "5gc-failure-boundary" / "scripts" / "analyze_failure_boundary.py"
    orch_out = raw_artifacts_dir / "5gc-failure-boundary-analysis.json"
    orch_report = raw_artifacts_dir / "investigation-report.txt"
    orch_cmd = [
        sys.executable,
        str(orch_script),
        "--output",
        str(orch_out),
        "--report",
        str(orch_report),
        "--force",
    ]
    if "registration" in domain_outputs:
        orch_cmd.extend(["--registration", str(domain_outputs["registration"])])
    if "pdu_session" in domain_outputs:
        orch_cmd.extend(["--pdu-session", str(domain_outputs["pdu_session"])])
    if "handover_mobility" in domain_outputs:
        orch_cmd.extend(["--handover-mobility", str(domain_outputs["handover_mobility"])])

    sanitized_summary: dict[str, Any]
    if domain_outputs:
        rc, stdout, stderr, dur = run_command(orch_cmd, logs_dir / "analyze_failure_boundary.log")
        pipeline_log["steps"]["orchestration"] = {
            "exit_code": rc,
            "status": "SUCCESS" if rc == 0 else f"ERROR_{rc}",
            "duration": dur,
            "output_present": orch_out.is_file(),
        }
        if rc == 0 and orch_out.is_file():
            raw_orch = json.loads(orch_out.read_text(encoding="utf-8"))
            sanitized_summary = sanitize_failure_boundary_result(raw_orch, case_id)
            pipeline_log["artifacts_produced"].extend([orch_out.name, orch_report.name])
        else:
            sanitized_summary = {
                "case_id": case_id,
                "selection_status": f"ORCHESTRATION_ERROR_{rc}",
                "selected_boundary": None,
                "boundary_confidence": None,
                "evidence_limitations": [f"Orchestrator failed with exit code {rc}"],
                "additional_evidence_needed": [],
                "domain_instances_count": len(domain_outputs),
                "candidate_boundaries_count": 0,
            }
    else:
        pipeline_log["steps"]["orchestration"] = {
            "exit_code": 0,
            "status": "NO_DOMAIN_OUTPUTS",
            "duration": 0.0,
            "output_present": False,
        }
        sanitized_summary = {
            "case_id": case_id,
            "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
            "selected_boundary": None,
            "boundary_confidence": None,
            "evidence_limitations": ["No Domain instances formed from capture evidence"],
            "additional_evidence_needed": [],
            "domain_instances_count": 0,
            "candidate_boundaries_count": 0,
        }

    # Populate protocol_status in sanitized_summary
    proto_statuses: dict[str, str] = {}
    for proto in ("ngap", "nas-5gs", "pfcp", "gtpu", "sbi-http2"):
        step_key = f"extract_{proto}"
        if step_key in pipeline_log["steps"]:
            status_val = pipeline_log["steps"][step_key]["status"]
            out_file = raw_artifacts_dir / f"{proto}-events.jsonl"
            if status_val == "SUCCESS" and out_file.is_file():
                try:
                    events = [json.loads(line) for line in out_file.read_text(encoding="utf-8").splitlines() if line.strip()]
                    if events and all(e.get("message_type") is None for e in events):
                        status_val = "MISSING_MESSAGE_TYPE"
                except Exception:
                    pass
            proto_statuses[proto] = status_val
    sanitized_summary["protocol_status"] = proto_statuses

    # Save sanitized summary to work directory
    summary_path = work_dir / "skill-result-summary.json"
    summary_path.write_text(json.dumps(sanitized_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path = work_dir / "pipeline-execution.json"
    log_path.write_text(json.dumps(pipeline_log, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return sanitized_summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, required=True, help="Path to input PCAP capture")
    parser.add_argument("--work-dir", type=Path, required=True, help="External working directory for run artifacts")
    parser.add_argument("--case-id", type=str, required=True, help="Benchmark case identifier")
    parser.add_argument("--allow-repo-workdir", action="store_true", help="Allow work-dir inside repo for synthetic tests")
    args = parser.parse_args(argv)

    try:
        summary = run_pipeline(args.capture, args.work_dir, args.case_id, args.allow_repo_workdir)
        print(f"Pipeline executed successfully for {args.case_id}. Status: {summary.get('selection_status')}")
        return 0
    except Exception as exc:
        print(f"Pipeline failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
