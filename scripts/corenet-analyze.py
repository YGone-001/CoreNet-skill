#!/usr/bin/env python3
"""Unified core-network PCAP analysis workflow.

One executable entry point for mobile core-network signaling analysis across
technology domains. The 5GC path is implemented today and executes the accepted
Protocol, Correlation, Domain and Orchestration Skills through the accepted
capture pipeline. EPC and IMS are declared capabilities only: they are reported
as UNSUPPORTED until their real Protocol and Domain Skills exist.

The workflow is an application-level execution entry point. It owns no telecom
protocol or procedure semantics and never restates a benchmark verdict as a
network verdict. A successful execution means the workflow completed its
supported processing, not that the captured procedure succeeded.

Exit codes:
    0  COMPLETED or PARTIAL analysis
    2  UNSUPPORTED (no requested domain is executable)
    3  INSUFFICIENT_EVIDENCE (executed, but no procedure evidence was reconstructed)
    4  FAILED (malformed input, missing decoder, extraction or pipeline failure,
       unsafe paths, refused overwrite, invalid arguments)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any, Callable

ANALYZER_NAME = "corenet-analyze"
ANALYZER_VERSION = "1.0"
REPORT_SCHEMA_VERSION = "1.0"

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_SCRIPT = ROOT / "skills" / "protocol" / "core-network-pcap" / "scripts" / "capture-inventory.py"
PIPELINE_SCRIPT = ROOT / "benchmarks" / "golden-captures" / "scripts" / "run_capture_pipeline.py"
FROZEN_BENCHMARK_DIR = ROOT / "benchmarks" / "golden-captures"

# Execution status vocabulary. These describe workflow execution or evidence
# sufficiency. None of them is a statement about network or service health.
STATUS_COMPLETED = "COMPLETED"
STATUS_PARTIAL = "PARTIAL"
STATUS_UNSUPPORTED = "UNSUPPORTED"
STATUS_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
STATUS_FAILED = "FAILED"

EXIT_OK = 0
EXIT_UNSUPPORTED = 2
EXIT_INSUFFICIENT_EVIDENCE = 3
EXIT_FAILED = 4

# Detection confidence vocabulary. A protocol observation is not a technology
# verdict: shared protocols cannot identify a domain on their own.
DETECTION_CONFIRMED = "CONFIRMED"
DETECTION_SUSPECTED = "SUSPECTED"
DETECTION_AMBIGUOUS = "AMBIGUOUS"
DETECTION_NOT_OBSERVED = "NOT_OBSERVED"

DOMAIN_5GC = "5gc"
DOMAIN_EPC = "epc"
DOMAIN_IMS = "ims"
DOMAIN_ORDER = (DOMAIN_5GC, DOMAIN_EPC, DOMAIN_IMS)

# Presentation-only mapping from the accepted capture pipeline's Domain keys to
# the Skill names a user sees. It carries no procedure semantics.
DOMAIN_SKILL_NAMES = {
    "registration": "5gc-registration-mobility",
    "pdu_session": "5gc-pdu-session",
    "handover_mobility": "5gc-handover-mobility",
}

# Canonical protocol identities, keyed by dissector stack token.
PROTOCOL_TOKENS = {
    "ngap": "NGAP",
    "nas-5gs": "NAS-5GS",
    "nas_5gs": "NAS-5GS",
    "pfcp": "PFCP",
    "gtp": "GTP-U",
    "gtpu": "GTP-U",
    "gtpv2": "GTPv2-C",
    "gtpv2-c": "GTPv2-C",
    "http2": "SBI-HTTP2",
    "http/2": "SBI-HTTP2",
    "sip": "SIP",
    "sdp": "SDP",
    "rtp": "RTP",
    "diameter": "Diameter",
    "s1ap": "S1AP",
    "nas-eps": "NAS-EPS",
    "nas_eps": "NAS-EPS",
}
TRANSPORT_TOKENS = {"sctp": "SCTP", "tcp": "TCP", "udp": "UDP"}

# Capture container signatures. Checking them keeps a non-capture file a
# deterministic input error instead of an opaque decoder failure.
CAPTURE_MAGIC = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
)

# Domain-specific signaling. Only these justify a confirmed technology verdict.
FIVEGC_ACCESS = frozenset({"NGAP", "NAS-5GS"})
FIVEGC_SUPPORTING = frozenset({"PFCP", "SBI-HTTP2"})
EPC_ACCESS = frozenset({"S1AP", "NAS-EPS", "GTPv2-C"})
IMS_SIGNALING = frozenset({"SIP", "SDP", "RTP"})
# Protocols shared by several technology domains.
SHARED_PROTOCOLS = frozenset({"GTP-U", "Diameter"})

DOMAIN_CAPABILITIES: dict[str, dict[str, Any]] = {
    DOMAIN_5GC: {
        "domain": DOMAIN_5GC,
        "display_name": "5G Core",
        "implementation_status": "IMPLEMENTED",
        "supported_protocol_families": [
            "NGAP", "NAS-5GS", "PFCP", "GTP-U", "SBI-HTTP2", "SCTP",
        ],
        "analysis_capabilities": [
            "protocol-extraction",
            "cross-protocol-correlation",
            "registration-procedure-analysis",
            "pdu-session-procedure-analysis",
            "handover-path-switch-procedure-analysis",
            "failure-boundary-orchestration",
        ],
        "entry_point": "benchmarks/golden-captures/scripts/run_capture_pipeline.py",
        "entry_point_available": True,
        "required_dependencies": ["python3", "tshark"],
        "planned_protocol_families": [],
        "unsupported_reason": None,
    },
    DOMAIN_EPC: {
        "domain": DOMAIN_EPC,
        "display_name": "Evolved Packet Core",
        "implementation_status": "UNSUPPORTED",
        "supported_protocol_families": [],
        "analysis_capabilities": [],
        "entry_point": None,
        "entry_point_available": False,
        "required_dependencies": [],
        "planned_protocol_families": ["NAS-EPS", "S1AP", "GTPv2-C", "GTP-U", "Diameter"],
        "unsupported_reason": (
            "No EPC Protocol Skill (NAS-EPS, S1AP, GTPv2-C, Diameter EPC) and no EPC "
            "Domain procedure Skill is implemented in this repository."
        ),
    },
    DOMAIN_IMS: {
        "domain": DOMAIN_IMS,
        "display_name": "IP Multimedia Subsystem",
        "implementation_status": "UNSUPPORTED",
        "supported_protocol_families": [],
        "analysis_capabilities": [],
        "entry_point": None,
        "entry_point_available": False,
        "required_dependencies": [],
        "planned_protocol_families": ["SIP", "SDP", "RTP", "Diameter IMS", "Diameter Charging"],
        "unsupported_reason": (
            "No SIP, SDP/RTP or Diameter IMS Protocol Skill and no IMS Domain procedure "
            "Skill is implemented in this repository."
        ),
    },
}

# Redaction applied to every string published in a report. The lookbehind keeps
# repository-relative identifiers such as "benchmarks/golden-captures/x" intact
# while still removing absolute workstation and temporary paths.
_WORKSTATION_PATH = re.compile(r"(?<![\w.-])[A-Za-z]:[\\/][^\s\"']*")
_POSIX_PATH = re.compile(r"(?<![\w.-])(?:/[\w.-]+){2,}/?")
_LONG_DIGIT_RUN = re.compile(r"\d{14,}")


class AnalysisError(Exception):
    """A deterministic, reportable workflow failure."""

    def __init__(self, code: str, message: str, exit_code: int = EXIT_FAILED) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


def redact_text(text: str) -> str:
    """Remove workstation paths and long identifier-like digit runs."""
    redacted = _WORKSTATION_PATH.sub("<redacted-path>", text)
    redacted = _POSIX_PATH.sub("<redacted-path>", redacted)
    redacted = _LONG_DIGIT_RUN.sub("<redacted-identifier>", redacted)
    return redacted


def redact_value(value: Any) -> Any:
    """Recursively redact every published string, including nested evidence text."""
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def capture_digest(path: Path) -> str:
    """Deterministic capture identity that never discloses capture content."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_revision(root: Path = ROOT) -> str | None:
    """Read the checked-out revision without running any Git command."""
    git_dir = root / ".git"
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref: "):
            return head or None
        ref = head[5:].strip()
        ref_file = git_dir / ref
        if ref_file.is_file():
            value = ref_file.read_text(encoding="utf-8").strip()
            return value or None
        packed = git_dir / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                if line.endswith(" " + ref):
                    return line.split()[0]
    except OSError:
        return None
    return None


# ---------------------------------------------------------------------------
# Capture inventory
# ---------------------------------------------------------------------------


def inventory_capture(capture: Path) -> dict[str, Any]:
    """Run the accepted capture inventory component and return its JSON record."""
    command = [sys.executable, str(INVENTORY_SCRIPT), str(capture), "--json"]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise AnalysisError("INVENTORY_UNAVAILABLE", f"capture inventory could not start: {exc}") from exc
    if completed.returncode == 0:
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise AnalysisError("INVENTORY_UNREADABLE", "capture inventory produced no usable JSON") from exc
        if not isinstance(payload, dict):
            raise AnalysisError("INVENTORY_UNREADABLE", "capture inventory produced a non-object record")
        return payload
    detail = (completed.stderr or completed.stdout or "").strip().splitlines()
    first = detail[0] if detail else ""
    if completed.returncode == 3:
        raise AnalysisError("DECODER_UNAVAILABLE", f"packet decoder is unavailable: {first}".strip())
    if completed.returncode == 4:
        raise AnalysisError("DECODER_FAILURE", f"packet decoder failed: {first}".strip())
    if completed.returncode == 6:
        raise AnalysisError("EMPTY_CAPTURE", "capture contains no frames")
    raise AnalysisError("MALFORMED_CAPTURE", f"capture could not be read: {first}".strip())


def observed_protocols(inventory: dict[str, Any]) -> dict[str, Any]:
    """Normalize observed dissector evidence into canonical protocol identities."""
    tokens = inventory.get("dissector_protocol_names") or []
    protocols: set[str] = set()
    transports: set[str] = set()
    for token in tokens:
        name = str(token).strip().lower()
        if name in PROTOCOL_TOKENS:
            protocols.add(PROTOCOL_TOKENS[name])
        elif name in TRANSPORT_TOKENS:
            transports.add(TRANSPORT_TOKENS[name])
    return {"protocols": sorted(protocols), "transports": sorted(transports)}


def detect_domains(observed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Infer technology-domain evidence strength from observed protocols only."""
    protocols = set(observed["protocols"])
    detection: dict[str, dict[str, Any]] = {}

    access = sorted(protocols & FIVEGC_ACCESS)
    supporting = sorted(protocols & FIVEGC_SUPPORTING)
    if access:
        detection[DOMAIN_5GC] = {
            "status": DETECTION_CONFIRMED,
            "basis": access,
            "note": "5GC access signaling was observed.",
        }
    elif supporting:
        detection[DOMAIN_5GC] = {
            "status": DETECTION_SUSPECTED,
            "basis": supporting,
            "note": (
                "Only 5GC-supporting protocol evidence was observed without N1/N2 access "
                "signaling, so the capture cannot be attributed to 5GC on this evidence."
            ),
        }
    elif "GTP-U" in protocols:
        detection[DOMAIN_5GC] = {
            "status": DETECTION_AMBIGUOUS,
            "basis": ["GTP-U"],
            "note": "GTP-U is shared by 5GC and EPC and does not identify either technology.",
        }
    else:
        detection[DOMAIN_5GC] = {
            "status": DETECTION_NOT_OBSERVED,
            "basis": [],
            "note": "No 5GC protocol evidence was observed.",
        }

    epc_access = sorted(protocols & EPC_ACCESS)
    if epc_access:
        detection[DOMAIN_EPC] = {
            "status": DETECTION_CONFIRMED,
            "basis": epc_access,
            "note": "EPC access signaling was observed.",
        }
    elif protocols & {"Diameter", "GTP-U"}:
        detection[DOMAIN_EPC] = {
            "status": DETECTION_AMBIGUOUS,
            "basis": sorted(protocols & {"Diameter", "GTP-U"}),
            "note": "Only protocols shared with other technology domains were observed.",
        }
    else:
        detection[DOMAIN_EPC] = {
            "status": DETECTION_NOT_OBSERVED,
            "basis": [],
            "note": "No EPC protocol evidence was observed.",
        }

    ims_signaling = sorted(protocols & IMS_SIGNALING)
    if ims_signaling:
        detection[DOMAIN_IMS] = {
            "status": DETECTION_SUSPECTED,
            "basis": ims_signaling,
            "note": (
                "SIP-family traffic was observed, but SIP signaling alone does not prove an "
                "IMS registration or an IMS session."
            ),
        }
    elif "Diameter" in protocols:
        detection[DOMAIN_IMS] = {
            "status": DETECTION_AMBIGUOUS,
            "basis": ["Diameter"],
            "note": "Diameter is cross-domain and does not identify IMS on its own.",
        }
    else:
        detection[DOMAIN_IMS] = {
            "status": DETECTION_NOT_OBSERVED,
            "basis": [],
            "note": "No IMS protocol evidence was observed.",
        }
    return detection


def resolve_selection(
    spec: str, detection: dict[str, dict[str, Any]]
) -> tuple[str, list[str]]:
    """Resolve the requested domain set from an explicit list or from evidence."""
    normalized = (spec or "").strip().lower()
    if normalized == "auto":
        selected = [
            domain
            for domain in DOMAIN_ORDER
            if detection[domain]["status"] == DETECTION_CONFIRMED
        ]
        return "auto", selected
    parts = [part.strip().lower() for part in normalized.split(",") if part.strip()]
    if not parts:
        raise AnalysisError("INVALID_DOMAIN", "no domain was requested; use auto, 5gc, epc or ims")
    unknown = [part for part in parts if part not in DOMAIN_CAPABILITIES]
    if unknown:
        raise AnalysisError(
            "INVALID_DOMAIN",
            f"unknown domain request: {', '.join(sorted(unknown))}; supported identifiers are "
            f"{', '.join(DOMAIN_ORDER)}",
        )
    ordered: list[str] = []
    for part in parts:
        if part not in ordered:
            ordered.append(part)
    return "explicit", ordered


# ---------------------------------------------------------------------------
# 5GC execution adapter
# ---------------------------------------------------------------------------


def execute_5gc_pipeline(capture: Path, work_dir: Path, case_id: str) -> tuple[dict[str, Any], Path]:
    """Execute the accepted 5GC capture pipeline and return its summary and artifacts."""
    domain_work = work_dir / DOMAIN_5GC
    domain_work.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(PIPELINE_SCRIPT),
        "--capture",
        str(capture),
        "--work-dir",
        str(domain_work),
        "--case-id",
        case_id,
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise AnalysisError("PIPELINE_UNAVAILABLE", f"5GC analysis adapter could not start: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        first = detail[0] if detail else "no diagnostic output"
        raise AnalysisError(
            "PIPELINE_FAILED",
            f"5GC analysis adapter exited with {completed.returncode}: {first}",
        )
    summary_path = domain_work / "skill-result-summary.json"
    if not summary_path.is_file():
        raise AnalysisError("PIPELINE_OUTPUT_MISSING", "5GC analysis adapter produced no summary")
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisError("PIPELINE_OUTPUT_UNREADABLE", f"5GC analysis summary is unreadable: {exc}") from exc
    if not isinstance(summary, dict):
        raise AnalysisError("PIPELINE_OUTPUT_UNREADABLE", "5GC analysis summary is not an object")
    return summary, domain_work / "raw_skill_artifacts"


def count_artifact_records(path: Path) -> int | None:
    """Count extracted events without reading any event content into the report."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return None


def classify_5gc_execution(summary: dict[str, Any]) -> tuple[str, str | None]:
    """Map a 5GC summary onto an execution status without inventing health.

    A failed extractor is never allowed to look like a successful empty
    extraction: when no Domain produced an instance and at least one extractor
    reported an error, the run is a failure rather than an inconclusive result.
    """
    domain_status = summary.get("domain_status") or {}
    executed = [
        key
        for key, record in domain_status.items()
        if isinstance(record, dict) and record.get("execution_status") == "EXECUTED"
    ]
    protocol_status = summary.get("protocol_status") or {}
    extractor_errors = sorted(
        key for key, value in protocol_status.items() if str(value).startswith("ERROR_")
    )
    if executed:
        return STATUS_COMPLETED, None
    if extractor_errors:
        return STATUS_FAILED, "EXTRACTION_FAILED"
    return STATUS_INSUFFICIENT_EVIDENCE, None


def build_protocol_evidence(summary: dict[str, Any], artifacts_dir: Path) -> list[dict[str, Any]]:
    """Per-protocol extraction evidence, including bounded event counts."""
    evidence: list[dict[str, Any]] = []
    for protocol in sorted((summary.get("protocol_status") or {})):
        status = summary["protocol_status"][protocol]
        artifact = artifacts_dir / f"{protocol}-events.jsonl"
        evidence.append({
            "protocol": protocol,
            "extraction_status": status,
            "event_count": count_artifact_records(artifact) if artifact.is_file() else None,
        })
    return evidence


def build_procedure_summaries(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Procedure-level execution evidence produced by the accepted Domain Skills."""
    summaries: list[dict[str, Any]] = []
    domain_status = summary.get("domain_status") or {}
    for key in sorted(domain_status):
        record = domain_status[key]
        if not isinstance(record, dict):
            continue
        entry: dict[str, Any] = {
            "procedure_domain": DOMAIN_SKILL_NAMES.get(key, key),
            "execution_status": record.get("execution_status"),
            "deviation_count": record.get("deviation_count"),
        }
        if "instance_count" in record:
            entry["instance_count"] = record.get("instance_count")
        if "handover_attempt_count" in record:
            entry["handover_attempt_count"] = record.get("handover_attempt_count")
            entry["path_switch_attempt_count"] = record.get("path_switch_attempt_count")
        if record.get("first_stop_reason"):
            entry["stop_reason"] = record.get("first_stop_reason")
        summaries.append(entry)
    return summaries


def build_diagnostic_groups(summary: dict[str, Any]) -> dict[str, Any] | None:
    """Orchestration-level evidence; never a verdict about the network."""
    orchestration = summary.get("orchestration_status")
    if not isinstance(orchestration, dict):
        return None
    return {
        "execution_status": orchestration.get("execution_status"),
        "diagnostic_group_count": orchestration.get("diagnostic_group_count"),
        "candidate_boundary_count": orchestration.get("candidate_boundary_count"),
        "source_domain_instances_count": orchestration.get("source_domain_instances_count"),
        "consumed_domain_instance_counts": orchestration.get("consumed_domain_instance_counts"),
    }


def build_first_abnormal_boundary(summary: dict[str, Any]) -> dict[str, Any] | None:
    """The evidence-supported boundary, or null when none was established."""
    boundary = summary.get("selected_boundary")
    if not isinstance(boundary, dict):
        return None
    return {
        "selection_status": summary.get("selection_status"),
        "confidence": summary.get("boundary_confidence"),
        "frame_number": boundary.get("boundary_frame"),
        "protocol": boundary.get("boundary_protocol"),
        "message_type": boundary.get("boundary_message"),
        "procedure_family": boundary.get("selected_procedure_family"),
        "procedure_stage": boundary.get("selected_procedure_stage"),
        "source_domain": boundary.get("selected_source_domain"),
        "deviation_type": boundary.get("deviation_type"),
        "evidence_level": boundary.get("evidence_level"),
        "timestamp": boundary.get("boundary_timestamp"),
    }


def unsupported_domain_result(domain: str, detection: dict[str, Any]) -> dict[str, Any]:
    """A complete, honest result record for a domain with no analyzer."""
    capability = DOMAIN_CAPABILITIES[domain]
    return {
        "domain": domain,
        "display_name": capability["display_name"],
        "implementation_status": capability["implementation_status"],
        "execution_status": STATUS_UNSUPPORTED,
        "detection": detection,
        "unsupported_reason": capability["unsupported_reason"],
        "planned_protocol_families": capability["planned_protocol_families"],
        "protocol_evidence": [],
        "procedure_summaries": [],
        "diagnostic_groups": None,
        "first_abnormal_boundary": None,
        "boundary_selection_status": "NOT_EVALUATED",
        "evidence_limitations": [],
        "additional_evidence_needed": [
            f"Implement the {capability['display_name']} Protocol and Domain Skills before "
            f"requesting {domain} analysis."
        ],
    }


def failed_domain_result(domain: str, detection: dict[str, Any], error: AnalysisError) -> dict[str, Any]:
    """Keep a failed requested domain visible in the report."""
    capability = DOMAIN_CAPABILITIES[domain]
    return {
        "domain": domain,
        "display_name": capability["display_name"],
        "implementation_status": capability["implementation_status"],
        "execution_status": STATUS_FAILED,
        "detection": detection,
        "unsupported_reason": None,
        "failure_code": error.code,
        "failure_message": error.message,
        "protocol_evidence": [],
        "procedure_summaries": [],
        "diagnostic_groups": None,
        "first_abnormal_boundary": None,
        "boundary_selection_status": "NOT_EVALUATED",
        "evidence_limitations": [],
        "additional_evidence_needed": [
            "Resolve the reported failure and re-run the analysis before drawing any "
            "conclusion from this domain."
        ],
    }


def execute_5gc_domain(
    capture: Path,
    work_dir: Path,
    case_id: str,
    detection: dict[str, Any],
    pipeline: Callable[[Path, Path, str], tuple[dict[str, Any], Path]],
) -> dict[str, Any]:
    """Run the 5GC domain and normalize the accepted pipeline output."""
    summary, artifacts_dir = pipeline(capture, work_dir, case_id)
    execution_status, failure_code = classify_5gc_execution(summary)
    result: dict[str, Any] = {
        "domain": DOMAIN_5GC,
        "display_name": DOMAIN_CAPABILITIES[DOMAIN_5GC]["display_name"],
        "implementation_status": DOMAIN_CAPABILITIES[DOMAIN_5GC]["implementation_status"],
        "execution_status": execution_status,
        "detection": detection,
        "unsupported_reason": None,
        "protocol_evidence": build_protocol_evidence(summary, artifacts_dir),
        "procedure_summaries": build_procedure_summaries(summary),
        "diagnostic_groups": build_diagnostic_groups(summary),
        "first_abnormal_boundary": build_first_abnormal_boundary(summary),
        "boundary_selection_status": summary.get("selection_status"),
        "evidence_limitations": list(summary.get("evidence_limitations") or []),
        "additional_evidence_needed": list(summary.get("additional_evidence_needed") or []),
    }
    if failure_code:
        result["failure_code"] = failure_code
    return result


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------


def overall_status(results: list[dict[str, Any]], selection_mode: str, selected: list[str]) -> str:
    """Combine independent domain outcomes into one workflow status."""
    statuses = [result["execution_status"] for result in results]
    if STATUS_FAILED in statuses:
        return STATUS_FAILED
    if not selected:
        return STATUS_INSUFFICIENT_EVIDENCE
    completed = [status for status in statuses if status == STATUS_COMPLETED]
    if completed and any(status != STATUS_COMPLETED for status in statuses):
        return STATUS_PARTIAL
    if completed:
        return STATUS_COMPLETED
    if STATUS_INSUFFICIENT_EVIDENCE in statuses:
        return STATUS_INSUFFICIENT_EVIDENCE
    if all(status == STATUS_UNSUPPORTED for status in statuses):
        return STATUS_UNSUPPORTED
    if STATUS_UNSUPPORTED in statuses:
        return STATUS_PARTIAL
    return STATUS_INSUFFICIENT_EVIDENCE


def collect_limitations(
    results: list[dict[str, Any]],
    detection: dict[str, dict[str, Any]],
    selection_mode: str,
    selected: list[str],
) -> list[str]:
    """Workflow-level limitations: what was not analyzed and why."""
    limitations: list[str] = []
    if not selected:
        limitations.append(
            "No technology domain was identified with confirmed protocol evidence, so no "
            "domain analysis was executed."
        )
        for domain in DOMAIN_ORDER:
            record = detection[domain]
            if record["status"] in (DETECTION_SUSPECTED, DETECTION_AMBIGUOUS):
                limitations.append(f"{domain} evidence is {record['status']}: {record['note']}")
    if selection_mode == "auto":
        limitations.append(
            "Domain selection was derived from observed protocol evidence, not from the "
            "capture name or a scenario description."
        )
    for result in results:
        if result["execution_status"] == STATUS_UNSUPPORTED:
            limitations.append(f"{result['domain']} analysis is unsupported: {result['unsupported_reason']}")
        elif result["execution_status"] == STATUS_FAILED:
            limitations.append(
                f"{result['domain']} analysis failed with {result.get('failure_code', 'PIPELINE_FAILED')}."
            )
        elif result["execution_status"] == STATUS_INSUFFICIENT_EVIDENCE:
            limitations.append(
                f"{result['domain']} analysis ran but reconstructed no procedure instance from "
                "the observed evidence."
            )
        if result["first_abnormal_boundary"] is None and result["execution_status"] == STATUS_COMPLETED:
            limitations.append(
                f"{result['domain']} reported no supported abnormal boundary within the analyzed "
                "scope; this is not evidence that the procedure or service succeeded."
            )
    return limitations


def build_components(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Record which components actually executed, as opposed to what was observed."""
    extractors: list[dict[str, Any]] = []
    analyzers: list[dict[str, Any]] = []
    orchestration: str | None = None
    for result in results:
        if result["domain"] != DOMAIN_5GC:
            continue
        for item in result.get("protocol_evidence") or []:
            extractors.append({"protocol": item["protocol"], "status": item["extraction_status"]})
        for item in result.get("procedure_summaries") or []:
            analyzers.append(
                {"analyzer": item["procedure_domain"], "status": item["execution_status"]}
            )
        groups = result.get("diagnostic_groups") or {}
        orchestration = groups.get("execution_status")
    return {
        "protocol_extractors": extractors,
        "domain_analyzers": analyzers,
        "orchestration_status": orchestration,
    }


def build_report(
    capture: Path,
    digest: str,
    inventory: dict[str, Any],
    observed: dict[str, Any],
    detection: dict[str, dict[str, Any]],
    selection_mode: str,
    selected: list[str],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assemble the domain-neutral report envelope."""
    status = overall_status(results, selection_mode, selected)
    execution_by_domain = {result["domain"]: result["execution_status"] for result in results}
    report = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "workflow": {
            "name": ANALYZER_NAME,
            "analyzer_version": ANALYZER_VERSION,
            "selection_mode": selection_mode,
        },
        "capture": {
            "name": capture.name,
            "sha256": digest,
            "size_bytes": capture.stat().st_size,
            "frame_count": inventory.get("frame_count"),
            "first_timestamp": inventory.get("first_timestamp"),
            "last_timestamp": inventory.get("last_timestamp"),
            "duration_seconds": inventory.get("duration_seconds"),
        },
        "toolchain": {
            "analyzer_version": ANALYZER_VERSION,
            "repository_revision": repository_revision(),
            "python_version": sys.version.split()[0],
            "decoder": {
                "name": "tshark",
                "version": inventory.get("tshark_version"),
            },
            "components": build_components(results),
            "observed_dissector_stack": sorted((inventory.get("dissector_protocol_names") or [])),
        },
        "requested_domains": selected,
        "observed_protocols": observed["protocols"],
        "observed_transports": observed["transports"],
        "domain_capabilities": [
            {
                "domain": capability["domain"],
                "implementation_status": capability["implementation_status"],
                "supported_protocol_families": capability["supported_protocol_families"],
                "analysis_capabilities": capability["analysis_capabilities"],
                "entry_point": capability["entry_point"],
                "entry_point_available": capability["entry_point_available"],
                "required_dependencies": capability["required_dependencies"],
                "planned_protocol_families": capability["planned_protocol_families"],
                "execution_status": execution_by_domain.get(capability["domain"], "NOT_REQUESTED"),
                "status_explanation": capability["unsupported_reason"],
            }
            for capability in (DOMAIN_CAPABILITIES[domain] for domain in DOMAIN_ORDER)
        ],
        "domain_results": results,
        "overall_execution_status": status,
        "limitations": collect_limitations(results, detection, selection_mode, selected),
        "interpretation": {
            "boundary_scope": (
                "The workflow localizes an evidence-supported abnormal boundary inside the "
                "analyzed capture. It does not establish a root cause."
            ),
            "absence_scope": (
                "Absence of a supported abnormal boundary within the analyzed scope is not "
                "evidence that the network, the procedure or the service succeeded."
            ),
            "domain_scope": (
                "EPC and IMS analysis are not implemented; requesting them reports an "
                "unsupported capability rather than an analysis result."
            ),
        },
    }
    return redact_value(report)


def _format_optional(value: Any) -> str:
    return "not available" if value is None else str(value)


def render_text_report(report: dict[str, Any]) -> str:
    """Render the human-readable companion report with evidence-safe language."""
    capture = report["capture"]
    lines: list[str] = []
    lines.append("CoreNet Skill - Unified Core-Network PCAP Analysis")
    lines.append("=" * 60)
    lines.append("")
    lines.append("Capture")
    lines.append(f"  File            : {_format_optional(capture.get('name'))}")
    lines.append(f"  SHA-256         : {_format_optional(capture.get('sha256'))}")
    lines.append(f"  Size            : {_format_optional(capture.get('size_bytes'))} bytes")
    lines.append(f"  Frames          : {_format_optional(capture.get('frame_count'))}")
    lines.append(f"  First observed  : {_format_optional(capture.get('first_timestamp'))}")
    lines.append(f"  Last observed   : {_format_optional(capture.get('last_timestamp'))}")
    lines.append("")
    lines.append("Toolchain")
    lines.append(f"  Analyzer        : {report['workflow']['name']} {report['workflow']['analyzer_version']}")
    lines.append(f"  Repository      : {_format_optional(report['toolchain'].get('repository_revision'))}")
    lines.append(f"  Python          : {_format_optional(report['toolchain'].get('python_version'))}")
    decoder = report["toolchain"].get("decoder") or {}
    lines.append(f"  Decoder         : {_format_optional(decoder.get('version'))}")
    lines.append("")
    lines.append(f"Selection mode    : {report['workflow']['selection_mode']}")
    lines.append(f"Requested domains : {', '.join(report['requested_domains']) or 'none'}")
    lines.append(f"Overall status    : {report['overall_execution_status']}")
    lines.append(f"Observed protocols: {', '.join(report['observed_protocols']) or 'none'}")
    lines.append(f"Observed transports: {', '.join(report.get('observed_transports') or []) or 'none'}")
    lines.append("")
    lines.append("Domain capabilities")
    for capability in report["domain_capabilities"]:
        entry_point = capability["entry_point"] or "not available"
        lines.append(
            f"  - {capability['domain']}: {capability['implementation_status']} "
            f"(entry point: {entry_point}; execution: "
            f"{_format_optional(capability.get('execution_status'))})"
        )
    lines.append("")

    for result in report["domain_results"]:
        lines.append(f"Domain: {result['domain']} ({result.get('display_name')})")
        lines.append(f"  Implementation : {result['implementation_status']}")
        detection = result.get("detection") or {}
        basis = ", ".join(detection.get("basis") or []) or "none"
        lines.append(f"  Detection      : {detection.get('status')} (basis: {basis})")
        lines.append(f"  Execution      : {result['execution_status']}")
        if result.get("unsupported_reason"):
            lines.append(f"  Unsupported    : {result['unsupported_reason']}")
        if result.get("failure_code"):
            lines.append(f"  Failure code   : {result['failure_code']}")

        evidence = result.get("protocol_evidence") or []
        if evidence:
            lines.append("  Protocol evidence")
            for item in evidence:
                count = item.get("event_count")
                suffix = "" if count is None else f" ({count} events)"
                lines.append(f"    - {item['protocol']}: {item['extraction_status']}{suffix}")

        procedures = result.get("procedure_summaries") or []
        if procedures:
            lines.append("  Procedures reconstructed")
            for item in procedures:
                details: list[str] = []
                if "instance_count" in item:
                    details.append(f"instances={_format_optional(item.get('instance_count'))}")
                if item.get("deviation_count") is not None:
                    details.append(f"deviations={item.get('deviation_count')}")
                if item.get("handover_attempt_count") is not None:
                    details.append(f"handover_attempts={item.get('handover_attempt_count')}")
                if item.get("path_switch_attempt_count") is not None:
                    details.append(f"path_switch_attempts={item.get('path_switch_attempt_count')}")
                lines.append(
                    f"    - {item['procedure_domain']}: {item['execution_status']} "
                    f"({', '.join(details)})"
                )

        groups = result.get("diagnostic_groups")
        if groups:
            consumed = groups.get("consumed_domain_instance_counts") or {}
            consumed_text = ", ".join(f"{key}={value}" for key, value in sorted(consumed.items())) or "none"
            lines.append("  Diagnostic groups")
            lines.append(
                f"    - groups={_format_optional(groups.get('diagnostic_group_count'))}, "
                f"candidate_boundaries={_format_optional(groups.get('candidate_boundary_count'))}, "
                f"consumed_instances={consumed_text}"
            )

        boundary = result.get("first_abnormal_boundary")
        lines.append("  First abnormal boundary")
        if boundary is None:
            lines.append(
                f"    - none established (selection status: "
                f"{_format_optional(result.get('boundary_selection_status'))})"
            )
        else:
            lines.append(f"    - selection_status : {_format_optional(boundary.get('selection_status'))}")
            lines.append(f"    - confidence       : {_format_optional(boundary.get('confidence'))}")
            lines.append(f"    - frame            : {_format_optional(boundary.get('frame_number'))}")
            lines.append(f"    - protocol         : {_format_optional(boundary.get('protocol'))}")
            lines.append(f"    - message          : {_format_optional(boundary.get('message_type'))}")
            lines.append(f"    - procedure family : {_format_optional(boundary.get('procedure_family'))}")
            lines.append(f"    - procedure stage  : {_format_optional(boundary.get('procedure_stage'))}")
            lines.append(f"    - deviation type   : {_format_optional(boundary.get('deviation_type'))}")
            lines.append(f"    - evidence level   : {_format_optional(boundary.get('evidence_level'))}")

        limitations = result.get("evidence_limitations") or []
        lines.append("  Evidence limitations")
        if limitations:
            for item in limitations:
                lines.append(f"    - {item}")
        else:
            lines.append("    - none recorded")
        additional = result.get("additional_evidence_needed") or []
        lines.append("  Additional evidence needed")
        if additional:
            for item in additional:
                lines.append(f"    - {item}")
        else:
            lines.append("    - none recorded")
        lines.append("")

    lines.append("Workflow limitations")
    if report["limitations"]:
        for item in report["limitations"]:
            lines.append(f"  - {item}")
    else:
        lines.append("  - none recorded")
    lines.append("")
    lines.append("Interpretation notes")
    for item in report["interpretation"].values():
        lines.append(f"  - {item}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# File-system safety and output writing
# ---------------------------------------------------------------------------


def _resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path.absolute()


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        _resolved(candidate).relative_to(_resolved(parent))
        return True
    except ValueError:
        return False


def validate_work_dir(work_dir: Path) -> None:
    """Refuse a work directory inside the repository."""
    if _is_within(work_dir, ROOT):
        raise AnalysisError(
            "UNSAFE_WORK_DIR",
            "the work directory must be outside the repository so no tracked artifact is "
            "modified by an analysis run",
        )


def validate_output_dir(output_dir: Path) -> None:
    """Refuse an output directory inside the frozen benchmark tree."""
    if _is_within(output_dir, FROZEN_BENCHMARK_DIR):
        raise AnalysisError(
            "UNSAFE_OUTPUT_DIR",
            "the output directory must not be inside the frozen Golden Capture benchmark tree",
        )


def write_outputs(output_dir: Path, report: dict[str, Any], force: bool) -> tuple[Path, Path]:
    """Write the JSON and text reports without silently replacing existing files."""
    json_path = output_dir / "analysis.json"
    text_path = output_dir / "report.txt"
    existing = [path.name for path in (json_path, text_path) if path.exists()]
    if existing and not force:
        raise AnalysisError(
            "OUTPUT_EXISTS",
            f"output already exists ({', '.join(sorted(existing))}); pass --force to replace it",
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    for path, text in ((json_path, payload), (text_path, render_text_report(report))):
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    return json_path, text_path


# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------


def validate_capture_container(capture: Path) -> None:
    """Reject a file that is not a PCAP or PCAPNG container."""
    try:
        with capture.open("rb") as handle:
            magic = handle.read(4)
    except OSError as exc:
        raise AnalysisError("MALFORMED_CAPTURE", f"the capture file cannot be read: {exc}") from exc
    if magic not in CAPTURE_MAGIC:
        raise AnalysisError(
            "MALFORMED_CAPTURE", "the input file is not a PCAP or PCAPNG capture container"
        )


DomainAdapter = Callable[[Path, Path, str, dict[str, Any]], dict[str, Any]]


def build_domain_adapters(
    pipeline: Callable[[Path, Path, str], tuple[dict[str, Any], Path]],
) -> dict[str, DomainAdapter]:
    """Execution adapters, one per implemented domain.

    Adding a real technology domain means adding its Protocol and Domain Skills and
    one adapter here; the 5GC procedure path and the report contract do not change.
    """
    return {
        DOMAIN_5GC: lambda capture, work_dir, case_id, detection: execute_5gc_domain(
            capture, work_dir, case_id, detection, pipeline
        ),
    }


def analyze(
    capture: Path,
    domains: str,
    work_dir: Path,
    output_dir: Path,
    force: bool = False,
    inventory: Callable[[Path], dict[str, Any]] | None = None,
    pipeline: Callable[[Path, Path, str], tuple[dict[str, Any], Path]] | None = None,
) -> tuple[dict[str, Any], int]:
    """Execute the workflow and return the report and the CLI exit code."""
    inventory_fn = inventory or inventory_capture
    pipeline_fn = pipeline or execute_5gc_pipeline

    validate_work_dir(work_dir)
    validate_output_dir(output_dir)
    if not capture.is_file():
        raise AnalysisError("CAPTURE_NOT_FOUND", "the capture file does not exist")
    if capture.stat().st_size == 0:
        raise AnalysisError("MALFORMED_CAPTURE", "the capture file is empty")
    validate_capture_container(capture)

    digest = capture_digest(capture)
    inventory_record = inventory_fn(capture)
    observed = observed_protocols(inventory_record)
    detection = detect_domains(observed)
    selection_mode, selected = resolve_selection(domains, detection)

    adapters = build_domain_adapters(pipeline_fn)
    case_id = f"capture-{digest[:12]}"
    results: list[dict[str, Any]] = []
    for domain in selected:
        if DOMAIN_CAPABILITIES[domain]["implementation_status"] != "IMPLEMENTED":
            results.append(unsupported_domain_result(domain, detection[domain]))
            continue
        adapter = adapters.get(domain)
        if adapter is None:
            results.append(
                failed_domain_result(
                    domain,
                    detection[domain],
                    AnalysisError(
                        "NO_DOMAIN_ADAPTER",
                        f"no execution adapter is registered for the {domain} domain",
                    ),
                )
            )
            continue
        try:
            results.append(adapter(capture, work_dir, case_id, detection[domain]))
        except AnalysisError as error:
            results.append(failed_domain_result(domain, detection[domain], error))

    report = build_report(
        capture, digest, inventory_record, observed, detection, selection_mode, selected, results
    )
    status = report["overall_execution_status"]
    write_outputs(output_dir, report, force)

    exit_codes = {
        STATUS_COMPLETED: EXIT_OK,
        STATUS_PARTIAL: EXIT_OK,
        STATUS_UNSUPPORTED: EXIT_UNSUPPORTED,
        STATUS_INSUFFICIENT_EVIDENCE: EXIT_INSUFFICIENT_EVIDENCE,
        STATUS_FAILED: EXIT_FAILED,
    }
    return report, exit_codes[status]


def build_failure_report(capture: Path | None, error: AnalysisError) -> dict[str, Any]:
    """A minimal, honest report for a run that could not analyze the capture."""
    return redact_value({
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "workflow": {
            "name": ANALYZER_NAME,
            "analyzer_version": ANALYZER_VERSION,
            "selection_mode": "unknown",
        },
        "capture": {
            "name": capture.name if capture is not None else None,
            "sha256": None,
            "size_bytes": None,
            "frame_count": None,
            "first_timestamp": None,
            "last_timestamp": None,
            "duration_seconds": None,
        },
        "toolchain": {
            "analyzer_version": ANALYZER_VERSION,
            "repository_revision": repository_revision(),
            "python_version": sys.version.split()[0],
            "decoder": {"name": "tshark", "version": None},
        },
        "requested_domains": [],
        "observed_protocols": [],
        "observed_transports": [],
        "domain_capabilities": [],
        "domain_results": [],
        "overall_execution_status": STATUS_FAILED,
        "failure": {"code": error.code, "message": error.message},
        "limitations": ["The workflow stopped before any domain analysis was executed."],
        "interpretation": {
            "boundary_scope": "No boundary conclusion is available for this run.",
            "absence_scope": (
                "A failed run is not evidence about the captured network procedure in any "
                "direction."
            ),
            "domain_scope": "EPC and IMS analysis are not implemented in this repository.",
        },
    })


class _ArgumentParser(argparse.ArgumentParser):
    """Argument parser whose usage errors use the workflow FAILED exit code."""

    def error(self, message: str) -> None:  # pragma: no cover - argparse contract
        self.print_usage(sys.stderr)
        self.exit(EXIT_FAILED, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="corenet-analyze.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes:\n"
            "  0  analysis completed, or completed for the supported domains (PARTIAL)\n"
            "  2  no requested domain is executable (UNSUPPORTED)\n"
            "  3  executed, but no procedure evidence was reconstructed "
            "(INSUFFICIENT_EVIDENCE)\n"
            "  4  failure: malformed input, missing decoder, extraction or pipeline "
            "failure,\n     unsafe path, refused overwrite, or invalid arguments\n"
        ),
    )
    parser.add_argument("--capture", type=Path, required=True, help="input PCAP or PCAPNG capture")
    parser.add_argument(
        "--domains",
        default="auto",
        help="domain request: auto, 5gc, epc, ims, or a comma-separated list (default: auto)",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        required=True,
        help="external scratch directory for intermediate extraction artifacts",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="directory for the analysis.json and report.txt outputs",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace existing analysis.json and report.txt in the output directory",
    )
    return parser


def _write_failure_report(args: argparse.Namespace, error: AnalysisError) -> None:
    """Publish a failure report when the destination is safe to write."""
    try:
        validate_output_dir(args.output_dir)
    except AnalysisError:
        return
    try:
        write_outputs(args.output_dir, build_failure_report(args.capture, error), args.force)
    except (AnalysisError, OSError):
        return


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report, exit_code = analyze(
            args.capture, args.domains, args.work_dir, args.output_dir, force=args.force
        )
    except AnalysisError as error:
        _write_failure_report(args, error)
        print(f"{ANALYZER_NAME}: {error.code}: {error.message}", file=sys.stderr)
        return error.exit_code
    except Exception:  # pragma: no cover - unexpected defect, reported loudly
        traceback.print_exc()
        print(f"{ANALYZER_NAME}: INTERNAL_ERROR: unexpected failure", file=sys.stderr)
        return EXIT_FAILED
    status = report["overall_execution_status"]
    print(f"{ANALYZER_NAME}: {status} -> {args.output_dir}")
    if status == STATUS_PARTIAL:
        print(
            f"{ANALYZER_NAME}: requested domains not analyzed: "
            + ", ".join(
                result["domain"]
                for result in report["domain_results"]
                if result["execution_status"] == STATUS_UNSUPPORTED
            ),
            file=sys.stderr,
        )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
