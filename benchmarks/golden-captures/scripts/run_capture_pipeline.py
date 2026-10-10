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
import re
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

# Skill exit-code contract shared by the Protocol and Domain packages.
EXIT_MALFORMED_INPUT = 5
EXIT_NO_EVENTS = 6

# Per-Protocol message-identity contract: where each accepted Protocol Skill
# exposes the message identity it decoded. PFCP and GTP-U carry identity inside
# the bounded `header` object; NGAP, NAS-5GS and SBI-HTTP2 expose it at the top
# level of the detailed event. Probing one shared path for every Protocol
# misreports healthy extraction as MISSING_MESSAGE_TYPE.
MESSAGE_IDENTITY_PATHS: dict[str, tuple[tuple[str, ...], ...]] = {
    "ngap": (("message_type",),),
    "nas-5gs": (("message_type",),),
    "pfcp": (("header", "message_type"), ("header", "message_type_code")),
    "gtpu": (("header", "message_type"), ("header", "message_type_code")),
    "sbi-http2": (("message_type",),),
}

# Protocol extraction statuses. MISSING_MESSAGE_TYPE is deliberately narrow: it
# means a record the Protocol Skill itself classified SUPPORTED exposed no
# message identity, which is an extractor compatibility failure. A record the
# Skill marks UNSUPPORTED or UNKNOWN is bounded-scope behaviour, not a failure.
STATUS_SUCCESS = "SUCCESS"
STATUS_MISSING_MESSAGE_TYPE = "MISSING_MESSAGE_TYPE"
STATUS_UNSUPPORTED_SEMANTICS = "SUCCESS_WITH_UNSUPPORTED_SEMANTICS"
STATUS_PROTECTED_PAYLOAD = "SUCCESS_WITH_PROTECTED_PAYLOAD"

_WORKSTATION_PATH = re.compile(r"[A-Za-z]:[\\/][^\s\"']+")
_POSIX_PATH = re.compile(r"(?:/[^\s\"'/]+){2,}")


def sanitize_reason(text: str | None) -> str | None:
    """Return a bounded, path-free first line of a Skill failure message."""
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        stripped = _WORKSTATION_PATH.sub("<redacted-path>", stripped)
        stripped = _POSIX_PATH.sub("<redacted-path>", stripped)
        return stripped[:200]
    return None


def resolve_message_identity(protocol: str, event: dict[str, Any]) -> Any:
    """Read the message identity from the producing Skill's own contract path."""
    for path in MESSAGE_IDENTITY_PATHS.get(protocol, (("message_type",),)):
        value: Any = event
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
            if value is None:
                break
        if value is not None and value != "":
            return value
    return None


def is_protected_payload(event: dict[str, Any]) -> bool:
    """True when the lower layer reports a security-protected, undecodable payload."""
    security = event.get("security")
    return isinstance(security, dict) and security.get("ciphered") is True


def classify_protocol_extraction(protocol: str, events: list[dict[str, Any]]) -> str:
    """Classify a successful extraction against the required-value contract.

    A required identity field must be both available and usable: identity present
    for every record the Skill claims to support, otherwise a precise
    compatibility failure is raised instead of a nominal SUCCESS.
    """
    if not events:
        return STATUS_SUCCESS
    supported_without_identity = 0
    unowned = 0
    protected = 0
    for event in events:
        if resolve_message_identity(protocol, event) is not None:
            continue
        support = event.get("support_status")
        if support == "SUPPORTED":
            supported_without_identity += 1
        elif is_protected_payload(event):
            protected += 1
        else:
            unowned += 1
    if supported_without_identity:
        return STATUS_MISSING_MESSAGE_TYPE
    if unowned:
        return STATUS_UNSUPPORTED_SEMANTICS
    if protected:
        return STATUS_PROTECTED_PAYLOAD
    return STATUS_SUCCESS


def read_events(path: Path) -> list[dict[str, Any]]:
    """Parse a detailed event JSON Lines artifact; unreadable files yield no events."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            events.append(record)
    return events


def _domain_records(domain: str, payload: dict[str, Any]) -> list[Any]:
    if domain == "registration":
        return list(payload.get("analyses") or [])
    if domain == "pdu_session":
        return list(payload.get("instances") or [])
    if domain == "handover_mobility":
        return list(payload.get("handover_attempts") or []) + list(payload.get("path_switch_attempts") or [])
    return []


def _deviation_count(domain: str, payload: dict[str, Any]) -> int:
    return sum(
        len(record.get("deviations") or [])
        for record in _domain_records(domain, payload)
        if isinstance(record, dict)
    )


def domain_evidence(domain: str) -> dict[str, Any]:
    """Zeroed per-Domain execution evidence record."""
    record: dict[str, Any] = {
        "execution_status": "NOT_RUN",
        "output_present": False,
        "deviation_count": 0,
        "first_stop_reason": None,
    }
    if domain == "handover_mobility":
        record["handover_attempt_count"] = 0
        record["path_switch_attempt_count"] = 0
    else:
        record["instance_count"] = 0
    return record


def record_domain_executed(domain: str, output_path: Path) -> dict[str, Any]:
    """Summarize an executed Domain analysis into bounded execution evidence."""
    record = domain_evidence(domain)
    try:
        payload = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        record["execution_status"] = "OUTPUT_UNREADABLE"
        record["first_stop_reason"] = sanitize_reason(f"Domain analysis output unreadable: {exc}")
        return record
    if not isinstance(payload, dict):
        record["execution_status"] = "OUTPUT_UNREADABLE"
        record["first_stop_reason"] = "Domain analysis output is not an object"
        return record
    record["execution_status"] = "EXECUTED"
    record["output_present"] = True
    record["deviation_count"] = _deviation_count(domain, payload)
    if domain == "handover_mobility":
        record["handover_attempt_count"] = len(payload.get("handover_attempts") or [])
        record["path_switch_attempt_count"] = len(payload.get("path_switch_attempts") or [])
    else:
        record["instance_count"] = len(_domain_records(domain, payload))
    return record


def record_domain_failure(domain: str, exit_code: int, stderr: str) -> dict[str, Any]:
    """Record why a Domain Skill produced no analysis, without inventing a cause."""
    record = domain_evidence(domain)
    if exit_code == EXIT_MALFORMED_INPUT:
        record["execution_status"] = "FAILED_INPUT_CONTRACT"
    elif exit_code == EXIT_NO_EVENTS:
        record["execution_status"] = "NO_RELEVANT_EVENTS"
    else:
        record["execution_status"] = f"ERROR_{exit_code}"
    record["first_stop_reason"] = sanitize_reason(stderr)
    return record


def record_domain_skipped(domain: str, reason: str) -> dict[str, Any]:
    record = domain_evidence(domain)
    record["execution_status"] = "SKIPPED_NO_INPUTS"
    record["first_stop_reason"] = reason
    return record


def produced_domain_instance_count(domain_status: dict[str, dict[str, Any]]) -> int:
    """Total procedure instances produced by executed Domain Skills."""
    total = 0
    for record in domain_status.values():
        for key in ("instance_count", "handover_attempt_count", "path_switch_attempt_count"):
            total += int(record.get(key) or 0)
    return total


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
    domain_status: dict[str, dict[str, Any]] = {}

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
            domain_status["registration"] = record_domain_executed("registration", reg_out)
            pipeline_log["artifacts_produced"].append(reg_out.name)
        else:
            domain_status["registration"] = record_domain_failure("registration", rc, stderr)
    else:
        pipeline_log["steps"]["domain_registration"] = {
            "exit_code": 0,
            "status": "SKIPPED_NO_N1_N2",
            "duration": 0.0,
            "output_present": False,
        }
        domain_status["registration"] = record_domain_skipped(
            "registration", "no NGAP or NAS-5GS protocol evidence extracted"
        )

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
            domain_status["pdu_session"] = record_domain_executed("pdu_session", pdu_out)
            pipeline_log["artifacts_produced"].append(pdu_out.name)
        else:
            domain_status["pdu_session"] = record_domain_failure("pdu_session", rc, stderr)
    else:
        pipeline_log["steps"]["domain_pdu_session"] = {
            "exit_code": 0,
            "status": "SKIPPED_NO_INPUTS",
            "duration": 0.0,
            "output_present": False,
        }
        domain_status["pdu_session"] = record_domain_skipped(
            "pdu_session", "no N1/N2/N3/N4/N11 protocol evidence extracted"
        )

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
            domain_status["handover_mobility"] = record_domain_executed("handover_mobility", ho_out)
            pipeline_log["artifacts_produced"].append(ho_out.name)
        else:
            domain_status["handover_mobility"] = record_domain_failure("handover_mobility", rc, stderr)
    else:
        pipeline_log["steps"]["domain_handover_mobility"] = {
            "exit_code": 0,
            "status": "SKIPPED_NO_INPUTS",
            "duration": 0.0,
            "output_present": False,
        }
        domain_status["handover_mobility"] = record_domain_skipped(
            "handover_mobility", "no NGAP, PFCP, GTP-U or SBI protocol evidence extracted"
        )

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
    orchestration_status: dict[str, Any] = {
        "execution_status": "NOT_RUN",
        "output_present": False,
        "diagnostic_group_count": 0,
        "source_domain_instances_count": 0,
        "candidate_boundary_count": 0,
        "first_stop_reason": None,
    }
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
            groups = raw_orch.get("diagnostic_groups") or []
            primary = groups[0] if groups and isinstance(groups[0], dict) else {}
            orchestration_status.update({
                "execution_status": "EXECUTED",
                "output_present": True,
                "diagnostic_group_count": len(groups),
                "source_domain_instances_count": len(primary.get("source_domain_instances") or []),
                "candidate_boundary_count": len(primary.get("candidate_boundaries") or []),
            })
            pipeline_log["artifacts_produced"].extend([orch_out.name, orch_report.name])
        else:
            sanitized_summary = {
                "case_id": case_id,
                "selection_status": f"ORCHESTRATION_ERROR_{rc}",
                "selected_boundary": None,
                "boundary_confidence": None,
                "evidence_limitations": [f"Orchestrator failed with exit code {rc}"],
                "additional_evidence_needed": [],
                "candidate_boundaries_count": 0,
            }
            orchestration_status.update({
                "execution_status": f"ERROR_{rc}",
                "first_stop_reason": sanitize_reason(stderr),
            })
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
            "evidence_limitations": [],
            "additional_evidence_needed": [],
            "candidate_boundaries_count": 0,
        }
        orchestration_status.update({
            "execution_status": "SKIPPED_NO_DOMAIN_OUTPUTS",
            "first_stop_reason": "no Domain analysis output was produced",
        })

    # Per-Domain and Orchestration execution evidence are reported separately so a
    # single counter never carries both "produced by Domain" and "consumed by
    # Orchestration" meanings.
    sanitized_summary["domain_status"] = domain_status
    sanitized_summary["orchestration_status"] = orchestration_status
    sanitized_summary["domain_instances_count"] = produced_domain_instance_count(domain_status)

    limitations = [str(item) for item in (sanitized_summary.get("evidence_limitations") or [])]
    for domain in sorted(domain_status):
        record = domain_status[domain]
        execution = record.get("execution_status")
        if execution in ("EXECUTED", "SKIPPED_NO_INPUTS", "NOT_RUN"):
            continue
        reason = record.get("first_stop_reason")
        detail = f": {reason}" if reason else ""
        limitations.append(f"{domain} Domain produced no analysis ({execution}{detail})")
    if not any(record.get("execution_status") == "EXECUTED" for record in domain_status.values()):
        limitations.append("No Domain instance was reconstructed from capture evidence")
    sanitized_summary["evidence_limitations"] = limitations

    # Protocol extraction health is judged against each Skill's own identity
    # contract, and a bounded-scope absence of semantics is never reported as an
    # extractor failure.
    proto_statuses: dict[str, str] = {}
    for proto in ("ngap", "nas-5gs", "pfcp", "gtpu", "sbi-http2"):
        step_key = f"extract_{proto}"
        if step_key not in pipeline_log["steps"]:
            continue
        status_val = pipeline_log["steps"][step_key]["status"]
        if status_val == "SUCCESS":
            out_file = raw_artifacts_dir / f"{proto}-events.jsonl"
            status_val = (
                classify_protocol_extraction(proto, read_events(out_file))
                if out_file.is_file()
                else STATUS_SUCCESS
            )
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
