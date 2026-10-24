#!/usr/bin/env python3
"""Unified core-network PCAP analysis workflow.

One executable entry point for mobile core-network signaling analysis across
technology domains. The 5GC path executes the accepted Protocol, Correlation,
Domain and Orchestration Skills through the accepted capture pipeline. The EPC path
executes bounded EPS Attach procedure evidence over the accepted S1AP and NAS-EPS
Protocol Skills. IMS remains a declared capability and is reported as UNSUPPORTED
until its real Protocol and Domain Skills exist.

The workflow is an application-level execution entry point. It owns no telecom
protocol or procedure semantics and never restates a benchmark verdict as a
network verdict. A successful execution means the workflow completed its
supported processing, not that the captured procedure succeeded.

Execution statuses describe the workflow, never the network:
    COMPLETED              every requested implemented domain completed cleanly
    PARTIAL                usable evidence exists, but at least one component failed
                           or one requested domain is unsupported
    UNSUPPORTED            no requested domain is executable
    INSUFFICIENT_EVIDENCE  processing ran but no procedure instance was reconstructed
    FAILED                 no trustworthy usable result (input, decoder, extraction,
                           Domain or adapter failure, unsafe path, refused overwrite)

Exit codes:
    0  COMPLETED or PARTIAL
    2  UNSUPPORTED
    3  INSUFFICIENT_EVIDENCE
    4  FAILED
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
import uuid
from pathlib import Path
from typing import Any, Callable

ANALYZER_NAME = "corenet-analyze"
ANALYZER_VERSION = "1.1"
REPORT_SCHEMA_VERSION = "1.1"

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_SCRIPT = ROOT / "skills" / "protocol" / "core-network-pcap" / "scripts" / "capture-inventory.py"
PIPELINE_SCRIPT = ROOT / "benchmarks" / "golden-captures" / "scripts" / "run_capture_pipeline.py"
S1AP_EXTRACT_SCRIPT = ROOT / "skills" / "protocol" / "s1ap" / "scripts" / "extract-s1ap.py"
NAS_EPS_EXTRACT_SCRIPT = ROOT / "skills" / "protocol" / "nas-eps" / "scripts" / "extract-nas-eps.py"
EPC_ANALYZE_SCRIPT = ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_attach.py"
FROZEN_BENCHMARK_DIR = ROOT / "benchmarks" / "golden-captures"

STATUS_COMPLETED = "COMPLETED"
STATUS_PARTIAL = "PARTIAL"
STATUS_UNSUPPORTED = "UNSUPPORTED"
STATUS_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
STATUS_FAILED = "FAILED"

EXIT_OK = 0
EXIT_UNSUPPORTED = 2
EXIT_INSUFFICIENT_EVIDENCE = 3
EXIT_FAILED = 4

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

# Accepted extraction-status vocabulary produced by the capture pipeline.
EXTRACTION_SUCCESS = "SUCCESS"
EXTRACTION_MISSING_IDENTITY = "MISSING_MESSAGE_TYPE"
EXTRACTION_UNSUPPORTED_SEMANTICS = "SUCCESS_WITH_UNSUPPORTED_SEMANTICS"
EXTRACTION_PROTECTED_PAYLOAD = "SUCCESS_WITH_PROTECTED_PAYLOAD"
EXTRACTION_NOT_OBSERVED = "NOT_OBSERVED_IN_CAPTURE"
EXTRACTION_ERROR_PREFIX = "ERROR_"

# Which protocol each accepted extractor covers, so an extractor failure can be
# judged against the protocols actually observed in the capture.
EXTRACTOR_PROTOCOLS = {
    "ngap": "NGAP",
    "nas-5gs": "NAS-5GS",
    "pfcp": "PFCP",
    "gtpu": "GTP-U",
    "sbi-http2": "SBI-HTTP2",
}

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
        "implementation_status": "IMPLEMENTED",
        "supported_protocol_families": ["S1AP", "NAS-EPS", "SCTP"],
        "analysis_capabilities": [
            "protocol-extraction",
            "eps-attach-procedure-evidence",
            "authentication-observation",
            "security-mode-observation",
            "explicit-attach-rejection",
            "bounded-s1-context-and-release-observations",
        ],
        "entry_point": "skills/domain/epc-procedures/scripts/analyze_epc_attach.py",
        "entry_point_available": True,
        "required_dependencies": ["python3", "tshark"],
        "planned_protocol_families": ["GTPv2-C", "Diameter EPC"],
        "not_implemented_capabilities": [
            "GTPv2-C session signalling",
            "Diameter EPC",
            "full EPS bearer lifecycle",
            "complete ESM semantics",
            "end-to-end EPC failure-boundary orchestration",
            "user-plane success verification",
        ],
        "unsupported_reason": None,
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

# Free-text scrubbing. Structured fields are published through explicit
# allowlists instead of being scrubbed, so evidence identity survives redaction.
_WORKSTATION_PATH = re.compile(r"(?<![\w.-])[A-Za-z]:[\\/][^\s\"']*")
_POSIX_PATH = re.compile(r"(?<![\w.-])(?:/[\w.-]+){2,}/?")
_LONG_DIGIT_RUN = re.compile(r"\d{14,}")

MAX_DIAGNOSTIC_SUBJECTS = 64
MAX_EVIDENCE_REFERENCES = 10
MAX_LIST_ITEMS = 20


class AnalysisError(Exception):
    """A deterministic, reportable workflow failure."""

    def __init__(self, code: str, message: str, exit_code: int = EXIT_FAILED) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


def scrub_free_text(value: Any) -> str | None:
    """Remove workstation paths and long identifier-like digit runs from prose."""
    if value is None:
        return None
    text = str(value)
    text = _WORKSTATION_PATH.sub("<redacted-path>", text)
    text = _POSIX_PATH.sub("<redacted-path>", text)
    text = _LONG_DIGIT_RUN.sub("<redacted-identifier>", text)
    return text


def scrub_list(values: Any, limit: int = MAX_LIST_ITEMS) -> list[str]:
    """Bounded, scrubbed list of free-text evidence statements."""
    if not values:
        return []
    result: list[str] = []
    for item in list(values)[:limit]:
        if isinstance(item, dict):
            text = item.get("description") or item.get("type") or item.get("statement")
            text = text if text is not None else json.dumps(item, sort_keys=True)
        else:
            text = str(item)
        scrubbed = scrub_free_text(text)
        if scrubbed:
            result.append(scrubbed)
    return result


def stable_reference(prefix: str, identity: Any) -> str:
    """Deterministic pseudonymous reference derived from an internal identity."""
    digest = hashlib.sha256(str(identity).encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{digest}"


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


# ---------------------------------------------------------------------------
# Capture inventory and domain detection
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
# Component evaluation
# ---------------------------------------------------------------------------


def evaluate_5gc_components(
    summary: dict[str, Any], observed: set[str]
) -> dict[str, Any]:
    """Judge the 5GC run from actual component outcomes.

    A failed extractor is only a lost-evidence failure when the protocol it owns
    was actually observed in the capture. A Domain that executed on reduced input
    still yields usable evidence, but the run is then PARTIAL and every lost
    component is reported, so a failure can never masquerade as a clean run.
    """
    protocol_status = summary.get("protocol_status") or {}
    domain_status = summary.get("domain_status") or {}
    orchestration = summary.get("orchestration_status") or {}
    selection_status = str(summary.get("selection_status") or "")

    failed_extractors: list[dict[str, Any]] = []
    protected_protocols: list[str] = []
    unsupported_semantics: list[str] = []
    for key in sorted(protocol_status):
        status = str(protocol_status[key])
        protocol = EXTRACTOR_PROTOCOLS.get(key, key)
        if status.startswith(EXTRACTION_ERROR_PREFIX):
            failed_extractors.append({
                "extractor": key,
                "protocol": protocol,
                "status": status,
                "observed_in_capture": protocol in observed,
            })
        elif status == EXTRACTION_PROTECTED_PAYLOAD:
            protected_protocols.append(protocol)
        elif status == EXTRACTION_UNSUPPORTED_SEMANTICS:
            unsupported_semantics.append(protocol)

    executed = sorted(
        key for key, record in domain_status.items()
        if isinstance(record, dict) and record.get("execution_status") == "EXECUTED"
    )
    skipped = sorted(
        key for key, record in domain_status.items()
        if isinstance(record, dict)
        and str(record.get("execution_status") or "").startswith("SKIPPED")
    )
    failed_domains = sorted(
        key for key, record in domain_status.items()
        if isinstance(record, dict)
        and record.get("execution_status") not in ("EXECUTED", "NOT_RUN")
        and not str(record.get("execution_status") or "").startswith("SKIPPED")
    )
    orchestration_failed = (
        str(orchestration.get("execution_status") or "").startswith(EXTRACTION_ERROR_PREFIX)
        or selection_status.startswith("ORCHESTRATION_ERROR_")
    )

    required_failures = [item for item in failed_extractors if item["observed_in_capture"]]
    optional_failures = [item for item in failed_extractors if not item["observed_in_capture"]]
    produced_instances = 0
    for record in domain_status.values():
        if not isinstance(record, dict):
            continue
        for key in ("instance_count", "handover_attempt_count", "path_switch_attempt_count"):
            value = record.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                produced_instances += value

    degradation: list[str] = []
    for item in required_failures:
        degradation.append(
            f"{item['protocol']} extraction failed ({item['status']}) while that protocol was "
            "observed in the capture; procedure evidence for it is unavailable."
        )
    for item in optional_failures:
        degradation.append(
            f"{item['protocol']} extraction failed ({item['status']}) for a protocol not observed "
            "in this capture; no observed evidence was lost."
        )
    for domain in failed_domains:
        record = domain_status.get(domain) or {}
        reason = scrub_free_text(record.get("first_stop_reason"))
        detail = f": {reason}" if reason else ""
        degradation.append(
            f"{DOMAIN_SKILL_NAMES.get(domain, domain)} did not produce analysis "
            f"({record.get('execution_status')}{detail})."
        )
    if orchestration_failed:
        reason = scrub_free_text(orchestration.get("first_stop_reason"))
        detail = f": {reason}" if reason else ""
        degradation.append(
            f"failure-boundary orchestration failed ({orchestration.get('execution_status')}{detail}); "
            "no boundary localization is available for this run."
        )
    for protocol in protected_protocols:
        degradation.append(
            f"{protocol} extraction met a security-protected payload; messages inside the "
            "protected envelope cannot be interpreted, so any conclusion stays bounded."
        )

    # A Domain that ran but reconstructed no procedure instance is not usable
    # evidence: the workflow completed its processing without a procedure result.
    status = STATUS_COMPLETED
    failure_code: str | None = None
    if required_failures and not produced_instances:
        status, failure_code = STATUS_FAILED, "EXTRACTION_FAILED"
    elif failed_domains and not produced_instances:
        status, failure_code = STATUS_FAILED, "DOMAIN_FAILED"
    elif not produced_instances:
        status = STATUS_INSUFFICIENT_EVIDENCE
    elif orchestration_failed:
        status, failure_code = STATUS_PARTIAL, "ORCHESTRATION_FAILED"
    elif required_failures:
        status, failure_code = STATUS_PARTIAL, "EXTRACTION_PARTIAL"
    elif failed_domains:
        status, failure_code = STATUS_PARTIAL, "DOMAIN_PARTIAL"

    return {
        "status": status,
        "failure_code": failure_code,
        "produced_instances": produced_instances,
        "executed_domains": executed,
        "skipped_domains": skipped,
        "failed_domains": failed_domains,
        "failed_extractors": failed_extractors,
        "required_failures": required_failures,
        "optional_failures": optional_failures,
        "protected_protocols": protected_protocols,
        "unsupported_semantics": unsupported_semantics,
        "orchestration_failed": orchestration_failed,
        "degradation": degradation,
    }


# ---------------------------------------------------------------------------
# Bounded projections from accepted component output
# ---------------------------------------------------------------------------


def count_artifact_records(path: Path) -> int | None:
    """Count extracted events without reading any event content into the report."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return None


def project_protocol_evidence(
    summary: dict[str, Any], artifacts_dir: Path
) -> list[dict[str, Any]]:
    """Per-protocol extraction coverage, including bounded event counts."""
    evidence: list[dict[str, Any]] = []
    for protocol in sorted((summary.get("protocol_status") or {})):
        status = str(summary["protocol_status"][protocol])
        artifact = artifacts_dir / f"{protocol}-events.jsonl"
        evidence.append({
            "protocol": protocol,
            "extraction_status": status,
            "observed_in_capture": status != EXTRACTION_NOT_OBSERVED,
            "event_count": count_artifact_records(artifact) if artifact.is_file() else None,
        })
    return evidence


def project_procedure_summaries(summary: dict[str, Any]) -> list[dict[str, Any]]:
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
            entry["stop_reason"] = scrub_free_text(record.get("first_stop_reason"))
        summaries.append(entry)
    return summaries


def project_diagnostic_groups(summary: dict[str, Any]) -> dict[str, Any] | None:
    """Orchestration-level aggregate evidence; never a verdict about the network."""
    orchestration = summary.get("orchestration_status")
    if not isinstance(orchestration, dict):
        return None
    consumed = orchestration.get("consumed_domain_instance_counts")
    if isinstance(consumed, dict):
        consumed = {str(key): int(value) for key, value in consumed.items() if isinstance(value, int)}
    else:
        consumed = None
    return {
        "execution_status": orchestration.get("execution_status"),
        "diagnostic_group_count": orchestration.get("diagnostic_group_count"),
        "candidate_boundary_count": orchestration.get("candidate_boundary_count"),
        "source_domain_instances_count": orchestration.get("source_domain_instances_count"),
        "consumed_domain_instance_counts": consumed,
    }


def _project_evidence_references(supporting: Any) -> list[dict[str, Any]]:
    """Allowlisted traceability references from a candidate's supporting evidence."""
    if not isinstance(supporting, dict):
        return []
    references = supporting.get("evidence_refs")
    if not isinstance(references, list):
        return []
    projected: list[dict[str, Any]] = []
    for reference in references[:MAX_EVIDENCE_REFERENCES]:
        if not isinstance(reference, dict):
            continue
        projected.append({
            "frame_number": reference.get("frame_number"),
            "protocol": reference.get("protocol"),
            "message_type": reference.get("message_type"),
            "kind": reference.get("kind"),
            "evidence_level": reference.get("evidence_level"),
            "stage_id": reference.get("stage_id"),
            "window_first_frame": reference.get("window_first_frame"),
            "window_last_frame": reference.get("window_last_frame"),
        })
    return projected


def project_selected_boundary(group: dict[str, Any]) -> dict[str, Any] | None:
    """Project one diagnostic group's selected boundary through an allowlist."""
    if group.get("selection_status") != "SELECTED":
        return None
    selected = group.get("selected_boundary")
    if not isinstance(selected, dict):
        return None
    reference = selected.get("boundary_ref")
    if not isinstance(reference, dict):
        return None
    anchor = reference.get("boundary_anchor")
    if not isinstance(anchor, dict):
        return None
    ordering = reference.get("ordering_basis") if isinstance(reference.get("ordering_basis"), dict) else {}
    window = ordering.get("observation_window") if isinstance(ordering.get("observation_window"), dict) else None
    return {
        "selection_status": "SELECTED",
        "confidence": group.get("boundary_confidence"),
        "candidate_reference": selected.get("candidate_id"),
        "frame_number": anchor.get("frame_number"),
        "capture_file": anchor.get("capture_file"),
        "protocol": anchor.get("protocol"),
        "message_type": anchor.get("message_type"),
        "timestamp": anchor.get("timestamp"),
        "procedure_family": reference.get("procedure_family"),
        "procedure_stage": reference.get("procedure_stage"),
        "source_domain": reference.get("source_domain"),
        "deviation_type": reference.get("deviation_type"),
        "evidence_level": reference.get("evidence_level"),
        "description": scrub_free_text(reference.get("description")),
        "observation_window": (
            {"start_frame": window.get("start_frame"), "end_frame": window.get("end_frame")}
            if window else None
        ),
        "evidence_references": _project_evidence_references(reference.get("supporting_evidence")),
    }


def project_source_instances(instances: Any) -> list[dict[str, Any]]:
    """Bounded, pseudonymous per-instance references for one diagnostic subject."""
    if not isinstance(instances, list):
        return []
    projected: list[dict[str, Any]] = []
    for instance in instances[:MAX_LIST_ITEMS]:
        if not isinstance(instance, dict):
            continue
        identity = instance.get("source_instance_id")
        projected.append({
            "source_domain": instance.get("source_domain"),
            "capture_file": instance.get("capture_file"),
            "instance_reference": stable_reference("inst", identity) if identity else None,
        })
    return projected


def project_subject_link(link: Any) -> dict[str, Any] | None:
    """Bounded subject-association evidence; raw UE identifiers are not published."""
    if not isinstance(link, dict):
        return None
    contexts = link.get("source_contexts")
    identities: list[str] = []
    if isinstance(contexts, list):
        for context in contexts:
            if isinstance(context, dict):
                identities.append(
                    f"{context.get('source_domain')}|{context.get('source_instance_id')}"
                )
    return {
        "basis": link.get("basis"),
        "context_count": len(identities),
        "subject_reference": stable_reference("subj", "|".join(sorted(identities))) if identities else None,
    }


def project_diagnostic_subjects(raw_orchestration: Any) -> tuple[list[dict[str, Any]], int]:
    """Publish every independently established diagnostic subject.

    Returns the projected subjects and the number of groups omitted by the cap.
    Raw Orchestration JSON is never republished: every field below is projected
    through an explicit allowlist, and instance identities become pseudonymous
    references.
    """
    if not isinstance(raw_orchestration, dict):
        return [], 0
    groups = raw_orchestration.get("diagnostic_groups")
    if not isinstance(groups, list):
        return [], 0
    omitted = max(0, len(groups) - MAX_DIAGNOSTIC_SUBJECTS)
    subjects: list[dict[str, Any]] = []
    for index, group in enumerate(groups[:MAX_DIAGNOSTIC_SUBJECTS]):
        if not isinstance(group, dict):
            continue
        candidates = group.get("candidate_boundaries")
        subjects.append({
            "diagnostic_group_reference": group.get("diagnostic_id") or f"diag-{index + 1}",
            "boundary_selection_status": group.get("selection_status"),
            "boundary_confidence": group.get("boundary_confidence"),
            "first_abnormal_boundary": project_selected_boundary(group),
            "candidate_boundary_count": len(candidates) if isinstance(candidates, list) else 0,
            "source_domain_instances": project_source_instances(group.get("source_domain_instances")),
            "subject_link": project_subject_link(group.get("subject_link")),
            "evidence_limitations": scrub_list(group.get("evidence_limitations")),
            "additional_evidence_needed": scrub_list(group.get("additional_evidence_needed")),
        })
    return subjects, omitted


def project_primary_boundary(summary: dict[str, Any]) -> dict[str, Any] | None:
    """Compatibility view: the accepted sanitized primary boundary, or null."""
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


# ---------------------------------------------------------------------------
# 5GC execution adapter
# ---------------------------------------------------------------------------


def create_run_directory(work_dir: Path, domain: str = DOMAIN_5GC) -> Path:
    """Create a fresh, uniquely named scratch directory for one domain run.

    A run-scoped directory guarantees that an interrupted or failed run can never
    be read as fresh evidence from an earlier run, and nothing is ever deleted to
    achieve that.
    """
    run_dir = work_dir / domain / "runs" / uuid.uuid4().hex[:16]
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def execute_5gc_pipeline(
    capture: Path, work_dir: Path, case_id: str
) -> tuple[dict[str, Any], Any, Path]:
    """Execute the accepted 5GC capture pipeline in a run-scoped directory.

    Each run gets its own directory so a failed or interrupted run can never be
    read as fresh evidence from an earlier one.
    """
    run_dir = create_run_directory(work_dir)
    command = [
        sys.executable,
        str(PIPELINE_SCRIPT),
        "--capture",
        str(capture),
        "--work-dir",
        str(run_dir),
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
            f"5GC analysis adapter exited with {completed.returncode}: {scrub_free_text(first)}",
        )
    summary_path = run_dir / "skill-result-summary.json"
    if not summary_path.is_file():
        raise AnalysisError("PIPELINE_OUTPUT_MISSING", "5GC analysis adapter produced no summary")
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisError("PIPELINE_OUTPUT_UNREADABLE", f"5GC analysis summary is unreadable: {exc}") from exc
    if not isinstance(summary, dict):
        raise AnalysisError("PIPELINE_OUTPUT_UNREADABLE", "5GC analysis summary is not an object")

    artifacts_dir = run_dir / "raw_skill_artifacts"
    raw_orchestration: Any = None
    orchestration_path = artifacts_dir / "5gc-failure-boundary-analysis.json"
    if orchestration_path.is_file():
        try:
            raw_orchestration = json.loads(orchestration_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw_orchestration = None
    return summary, raw_orchestration, artifacts_dir


def execute_5gc_domain(
    capture: Path,
    work_dir: Path,
    case_id: str,
    detection: dict[str, Any],
    observed: set[str],
    pipeline: Callable[[Path, Path, str], tuple[dict[str, Any], Any, Path]],
) -> dict[str, Any]:
    """Run the 5GC domain and normalize the accepted pipeline output."""
    summary, raw_orchestration, artifacts_dir = pipeline(capture, work_dir, case_id)
    components = evaluate_5gc_components(summary, observed)
    subjects, omitted = project_diagnostic_subjects(raw_orchestration)
    result: dict[str, Any] = {
        "domain": DOMAIN_5GC,
        "display_name": DOMAIN_CAPABILITIES[DOMAIN_5GC]["display_name"],
        "implementation_status": DOMAIN_CAPABILITIES[DOMAIN_5GC]["implementation_status"],
        "execution_status": components["status"],
        "detection": detection,
        "unsupported_reason": None,
        "protocol_evidence": project_protocol_evidence(summary, artifacts_dir),
        "procedure_summaries": project_procedure_summaries(summary),
        "diagnostic_groups": project_diagnostic_groups(summary),
        "diagnostic_subject_count": len(subjects),
        "diagnostic_subjects": subjects,
        "first_abnormal_boundary": project_primary_boundary(summary),
        "boundary_selection_status": summary.get("selection_status"),
        "evidence_limitations": scrub_list(summary.get("evidence_limitations")),
        "additional_evidence_needed": scrub_list(summary.get("additional_evidence_needed")),
        "degradation": components["degradation"],
    }
    if components["failure_code"]:
        result["failure_code"] = components["failure_code"]
    if omitted:
        result["diagnostic_subjects_omitted"] = omitted
    return result


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
        "diagnostic_subject_count": 0,
        "diagnostic_subjects": [],
        "first_abnormal_boundary": None,
        "boundary_selection_status": "NOT_EVALUATED",
        "evidence_limitations": [],
        "additional_evidence_needed": [
            f"Implement the {capability['display_name']} Protocol and Domain Skills before "
            f"requesting {domain} analysis."
        ],
        "degradation": [],
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
        "failure_message": scrub_free_text(error.message),
        "protocol_evidence": [],
        "procedure_summaries": [],
        "diagnostic_groups": None,
        "diagnostic_subject_count": 0,
        "diagnostic_subjects": [],
        "first_abnormal_boundary": None,
        "boundary_selection_status": "NOT_EVALUATED",
        "evidence_limitations": [],
        "additional_evidence_needed": [
            "Resolve the reported failure and re-run the analysis before drawing any "
            "conclusion from this domain."
        ],
        "degradation": [f"analysis did not run: {error.code}"],
    }


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------


def overall_status(results: list[dict[str, Any]], selection_mode: str, selected: list[str]) -> str:
    """Combine independent domain outcomes into one workflow status."""
    statuses = [result["execution_status"] for result in results]
    if not selected:
        return STATUS_INSUFFICIENT_EVIDENCE
    usable = [status for status in statuses if status in (STATUS_COMPLETED, STATUS_PARTIAL)]
    if usable:
        return STATUS_COMPLETED if all(status == STATUS_COMPLETED for status in statuses) else STATUS_PARTIAL
    if STATUS_FAILED in statuses:
        return STATUS_FAILED
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
        elif result["execution_status"] == STATUS_PARTIAL:
            limitations.append(
                f"{result['domain']} analysis is partial: usable evidence exists, but at least one "
                "component failed or one requested capability is unavailable."
            )
        if (
            result["first_abnormal_boundary"] is None
            and result.get("boundary_selection_status") == "NOT_EVALUATED"
            and result["execution_status"] in (STATUS_COMPLETED, STATUS_PARTIAL)
        ):
            limitations.append(
                f"{result['domain']} boundary selection is not evaluated: no {result['domain']} "
                "Analysis Orchestration exists, so deviations stay procedure-local."
            )
        elif result["first_abnormal_boundary"] is None and result["execution_status"] in (
            STATUS_COMPLETED, STATUS_PARTIAL
        ):
            limitations.append(
                f"{result['domain']} reported no supported abnormal boundary within the analyzed "
                "scope; this is not evidence that the procedure or service succeeded."
            )
        if (
            result["execution_status"] in (STATUS_COMPLETED, STATUS_PARTIAL)
            and result.get("diagnostic_subject_count") == 0
        ):
            limitations.append(
                f"{result['domain']} established no diagnostic subject, so no boundary "
                "conclusion is available for this capture."
            )
        if result.get("diagnostic_subjects_omitted"):
            limitations.append(
                f"{result['domain']} diagnostic subjects were truncated: "
                f"{result['diagnostic_subjects_omitted']} group(s) were not published."
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
    return {
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
                "version": scrub_free_text(inventory.get("tshark_version")),
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
                "not_implemented_capabilities": capability.get("not_implemented_capabilities") or [],
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
                "The workflow localizes evidence-supported abnormal boundaries inside the "
                "analyzed capture. It does not establish a root cause."
            ),
            "subject_scope": (
                "Each diagnostic subject keeps its own boundary status. A boundary selected for "
                "one subject is never the result of another subject."
            ),
            "absence_scope": (
                "Absence of a supported abnormal boundary within the analyzed scope is not "
                "evidence that the network, the procedure or the service succeeded."
            ),
            "domain_scope": (
                "Implemented domains run their bounded analysis paths and unimplemented "
                "domains report an unsupported capability rather than an analysis result. "
                "5GC coverage is bounded to the accepted registration, PDU session and "
                "mobility chain with its failure-boundary orchestration. EPC coverage is "
                "bounded to EPS Attach procedure evidence; EPC bearer lifecycle, session "
                "signalling, complete ESM semantics and global EPC boundary selection are "
                "not implemented. IMS analysis is not implemented."
            ),
        },
    }


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------


def _value(value: Any) -> str:
    return "not available" if value is None else str(value)


def _section(lines: list[str], title: str) -> None:
    lines.append("")
    lines.append(title)
    lines.append("-" * len(title))


def _empty(lines: list[str], reason: str) -> None:
    lines.append(f"  none recorded ({reason})")


def _render_boundary(lines: list[str], boundary: dict[str, Any], indent: str = "    ") -> None:
    lines.append(f"{indent}frame            : {_value(boundary.get('frame_number'))}")
    lines.append(f"{indent}protocol         : {_value(boundary.get('protocol'))}")
    lines.append(f"{indent}message          : {_value(boundary.get('message_type'))}")
    lines.append(f"{indent}procedure family : {_value(boundary.get('procedure_family'))}")
    lines.append(f"{indent}procedure stage  : {_value(boundary.get('procedure_stage'))}")
    lines.append(f"{indent}deviation type   : {_value(boundary.get('deviation_type'))}")
    lines.append(f"{indent}evidence level   : {_value(boundary.get('evidence_level'))}")
    lines.append(f"{indent}confidence       : {_value(boundary.get('confidence'))}")
    lines.append(f"{indent}capture file     : {_value(boundary.get('capture_file'))}")
    lines.append(f"{indent}candidate ref    : {_value(boundary.get('candidate_reference'))}")
    window = boundary.get("observation_window")
    if window:
        lines.append(
            f"{indent}observation span : frames {_value(window.get('start_frame'))}"
            f"-{_value(window.get('end_frame'))}"
        )
    references = boundary.get("evidence_references") or []
    if references:
        lines.append(f"{indent}evidence refs    :")
        for reference in references:
            lines.append(
                f"{indent}  - frame {_value(reference.get('frame_number'))} "
                f"{_value(reference.get('protocol'))} "
                f"{_value(reference.get('message_type'))} "
                f"({_value(reference.get('kind'))}, {_value(reference.get('evidence_level'))})"
            )


def render_text_report(report: dict[str, Any]) -> str:
    """Render the human-readable companion report with evidence-safe language."""
    capture = report["capture"]
    results = report["domain_results"]
    lines: list[str] = []
    lines.append("CoreNet Skill - Unified Core-Network PCAP Analysis")
    lines.append("=" * 60)

    _section(lines, "Capture and Toolchain")
    lines.append(f"  Capture file    : {_value(capture.get('name'))}")
    lines.append(f"  SHA-256         : {_value(capture.get('sha256'))}")
    lines.append(f"  Size            : {_value(capture.get('size_bytes'))} bytes")
    lines.append(f"  Frames          : {_value(capture.get('frame_count'))}")
    lines.append(f"  First observed  : {_value(capture.get('first_timestamp'))}")
    lines.append(f"  Last observed   : {_value(capture.get('last_timestamp'))}")
    lines.append(f"  Analyzer        : {report['workflow']['name']} {report['workflow']['analyzer_version']}")
    lines.append(f"  Repository      : {_value(report['toolchain'].get('repository_revision'))}")
    lines.append(f"  Python          : {_value(report['toolchain'].get('python_version'))}")
    decoder = report["toolchain"].get("decoder") or {}
    lines.append(f"  Decoder         : {_value(decoder.get('version'))}")
    lines.append(f"  Selection mode  : {report['workflow']['selection_mode']}")
    lines.append(f"  Requested       : {', '.join(report['requested_domains']) or 'none'}")
    lines.append(f"  Overall status  : {report['overall_execution_status']}")

    _section(lines, "Observed Protocols")
    lines.append(f"  Protocols       : {', '.join(report['observed_protocols']) or 'none'}")
    lines.append(f"  Transports      : {', '.join(report.get('observed_transports') or []) or 'none'}")
    stack = report["toolchain"].get("observed_dissector_stack") or []
    lines.append(f"  Dissector stack : {', '.join(stack) or 'none'}")

    _section(lines, "Domain Detection and Execution")
    capability_by_domain = {item["domain"]: item for item in report["domain_capabilities"]}
    for capability in report["domain_capabilities"]:
        entry = capability_by_domain[capability["domain"]]
        lines.append(
            f"  - {capability['domain']}: {capability['implementation_status']}, "
            f"execution {_value(entry.get('execution_status'))}, "
            f"entry point {_value(capability['entry_point'])}"
        )
    for result in results:
        detection = result.get("detection") or {}
        basis = ", ".join(detection.get("basis") or []) or "none"
        lines.append(
            f"    {result['domain']} detection: {_value(detection.get('status'))} (basis: {basis})"
        )
        if result.get("unsupported_reason"):
            lines.append(f"    {result['domain']} unsupported: {result['unsupported_reason']}")

    _section(lines, "Protocol Extraction Coverage")
    coverage_any = False
    for result in results:
        evidence = result.get("protocol_evidence") or []
        if not evidence:
            continue
        coverage_any = True
        lines.append(f"  {result['domain']}:")
        for item in evidence:
            count = item.get("event_count")
            suffix = "" if count is None else f", {count} events"
            lines.append(f"    - {item['protocol']}: {item['extraction_status']}{suffix}")
    if not coverage_any:
        _empty(lines, "no protocol extraction was executed")

    _section(lines, "Procedure Instances")
    procedure_any = False
    for result in results:
        procedures = result.get("procedure_summaries") or []
        if not procedures:
            continue
        procedure_any = True
        lines.append(f"  {result['domain']}:")
        for item in procedures:
            details: list[str] = []
            if "instance_count" in item:
                details.append(f"instances={_value(item.get('instance_count'))}")
            if item.get("deviation_count") is not None:
                details.append(f"deviations={item.get('deviation_count')}")
            if item.get("handover_attempt_count") is not None:
                details.append(f"handover_attempts={item.get('handover_attempt_count')}")
            if item.get("path_switch_attempt_count") is not None:
                details.append(f"path_switch_attempts={item.get('path_switch_attempt_count')}")
            if item.get("stop_reason"):
                details.append(f"stop_reason={item['stop_reason']}")
            lines.append(
                f"    - {item['procedure_domain']}: {item['execution_status']} "
                f"({', '.join(details) or 'no instance detail'})"
            )
    if not procedure_any:
        _empty(lines, "no Domain procedure instance was produced")

    _section(lines, "Diagnostic Subjects")
    subject_any = False
    for result in results:
        subjects = result.get("diagnostic_subjects") or []
        if not subjects:
            continue
        subject_any = True
        lines.append(f"  {result['domain']}: {len(subjects)} diagnostic subject(s)")
        for subject in subjects:
            instances = subject.get("source_domain_instances") or []
            domains = sorted({str(item.get("source_domain")) for item in instances if item.get("source_domain")})
            lines.append(
                f"    - {subject['diagnostic_group_reference']}: "
                f"{_value(subject.get('boundary_selection_status'))} "
                f"(confidence {_value(subject.get('boundary_confidence'))}, "
                f"candidates {_value(subject.get('candidate_boundary_count'))}, "
                f"source domains {', '.join(domains) or 'none'})"
            )
            link = subject.get("subject_link") or {}
            if link:
                lines.append(
                    f"      subject link: {_value(link.get('basis'))} "
                    f"({_value(link.get('context_count'))} context(s), "
                    f"reference {_value(link.get('subject_reference'))})"
                )
            for stage in subject.get("procedure_stages") or []:
                marker = "conditional" if stage.get("conditional") else "required"
                first, last = stage.get("first_frame"), stage.get("last_frame")
                span = f"frames {first}-{last}" if first is not None else "no frame observed"
                lines.append(
                    f"      stage {stage.get('stage_id')}: {stage.get('status')} "
                    f"({marker}, {span})"
                )
            for deviation in subject.get("procedure_deviations") or []:
                window = deviation.get("observation_window") or {}
                span = (
                    f" (window {window.get('start_frame')}-{window.get('end_frame')})"
                    if window
                    else ""
                )
                lines.append(
                    f"      deviation {deviation.get('deviation_type')} at frame "
                    f"{_value(deviation.get('frame_number'))}{span}: "
                    f"{_value(deviation.get('explanation'))}"
                )
    if not subject_any:
        _empty(lines, "no diagnostic group was established")

    _section(lines, "First Abnormal Boundary per Subject")
    boundary_any = False
    for result in results:
        for subject in result.get("diagnostic_subjects") or []:
            boundary = subject.get("first_abnormal_boundary")
            if not boundary:
                continue
            boundary_any = True
            lines.append(f"  {result['domain']} / {subject['diagnostic_group_reference']}:")
            _render_boundary(lines, boundary)
    if not boundary_any:
        _empty(lines, "no subject has a selected abnormal boundary")

    _section(lines, "Evidence Limitations")
    limitation_any = False
    for result in results:
        items = result.get("evidence_limitations") or []
        if not items:
            continue
        limitation_any = True
        lines.append(f"  {result['domain']}:")
        for item in items:
            lines.append(f"    - {item}")
    for item in report.get("limitations") or []:
        limitation_any = True
        lines.append(f"  workflow: {item}")
    if not limitation_any:
        _empty(lines, "no evidence limitation was recorded")

    _section(lines, "Additional Evidence Needed")
    additional_any = False
    for result in results:
        items = result.get("additional_evidence_needed") or []
        if not items:
            continue
        additional_any = True
        lines.append(f"  {result['domain']}:")
        for item in items:
            lines.append(f"    - {item}")
    if not additional_any:
        _empty(lines, "the accepted components requested no additional evidence")

    _section(lines, "Execution Failures")
    failure_any = False
    for result in results:
        for item in result.get("degradation") or []:
            failure_any = True
            lines.append(f"  {result['domain']}: {item}")
        if result.get("failure_code"):
            failure_any = True
            lines.append(
                f"  {result['domain']}: failure code {result['failure_code']}"
                + (f" ({result['failure_message']})" if result.get("failure_message") else "")
            )
    if not failure_any:
        _empty(lines, "no component failure was recorded")

    _section(lines, "Interpretation Boundaries")
    for item in report["interpretation"].values():
        lines.append(f"  - {item}")
    lines.append(
        "  - A successful command exit means the workflow completed its supported processing, "
        "not that the captured procedure succeeded."
    )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Path safety and output publication
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


def validate_paths(capture: Path, work_dir: Path, output_dir: Path) -> None:
    """Reject unsafe or overlapping work and output locations.

    Resolution happens before comparison, so a symlink cannot be used to reach a
    protected directory.
    """
    work = _resolved(work_dir)
    output = _resolved(output_dir)
    root = _resolved(ROOT)
    frozen = _resolved(FROZEN_BENCHMARK_DIR)

    if work == output:
        raise AnalysisError(
            "UNSAFE_PATH_OVERLAP", "the work directory and the output directory must differ"
        )
    if _is_within(output, work) or _is_within(work, output):
        raise AnalysisError(
            "UNSAFE_PATH_OVERLAP",
            "the work directory and the output directory must not contain one another, so final "
            "reports never sit among raw intermediate artifacts",
        )
    if work == root or _is_within(work, root):
        raise AnalysisError(
            "UNSAFE_WORK_DIR",
            "the work directory must be outside the repository so no tracked artifact is "
            "modified by an analysis run",
        )
    if output == root:
        raise AnalysisError(
            "UNSAFE_OUTPUT_DIR", "the output directory must not be the repository root"
        )
    if _is_within(output, frozen):
        raise AnalysisError(
            "UNSAFE_OUTPUT_DIR",
            "the output directory must not be inside the frozen Golden Capture benchmark tree",
        )
    if _is_within(capture, work) or _is_within(capture, output):
        raise AnalysisError(
            "UNSAFE_INPUT_PATH",
            "the input capture must not live inside the work or output directory",
        )


def _temporary_path(target: Path) -> Path:
    token = f"{os.getpid()}.{uuid.uuid4().hex[:8]}"
    return target.with_name(f".{target.name}.{token}.tmp")


def publish_reports(output_dir: Path, json_text: str, text_text: str, force: bool) -> tuple[Path, Path]:
    """Publish the report pair without silently replacing existing files.

    Publication is sequential with rollback: both payloads are staged first, then
    replaced one after the other, and a failed second replacement restores the
    first file's previous bytes. It is not transactional against process death
    between the two replacements; the failure-recovery contract is that the JSON
    report is authoritative and the text report is regenerated on the next run.
    """
    json_path = output_dir / "analysis.json"
    text_path = output_dir / "report.txt"
    existing = [path.name for path in (json_path, text_path) if path.exists()]
    if existing and not force:
        raise AnalysisError(
            "OUTPUT_EXISTS",
            f"output already exists ({', '.join(sorted(existing))}); pass --force to replace it",
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    json_temp = _temporary_path(json_path)
    text_temp = _temporary_path(text_path)
    previous_json: bytes | None = json_path.read_bytes() if json_path.exists() else None
    try:
        json_temp.write_text(json_text, encoding="utf-8")
        text_temp.write_text(text_text, encoding="utf-8")
        os.replace(json_temp, json_path)
        try:
            os.replace(text_temp, text_path)
        except OSError:
            if previous_json is None:
                json_path.unlink(missing_ok=True)
            else:
                json_path.write_bytes(previous_json)
            raise AnalysisError(
                "OUTPUT_PUBLICATION_FAILED",
                "the text report could not be published; the previous report pair was restored",
            )
    except AnalysisError:
        raise
    except OSError as exc:
        raise AnalysisError("OUTPUT_WRITE_FAILED", f"report publication failed: {exc}") from exc
    finally:
        for temporary in (json_temp, text_temp):
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return json_path, text_path


def publish_failure_report(
    output_dir: Path, report: dict[str, Any], force: bool
) -> str | None:
    """Record a failed attempt without destroying an earlier successful report.

    When no report exists yet the failure becomes `analysis.json`. When a report
    already exists it is left untouched and the failure is written to
    `analysis.failure.json`, so a stale successful report is never silently
    presented as the result of the failed run.
    """
    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)
    if not (output_dir / "analysis.json").exists():
        publish_reports(
            output_dir,
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            render_text_report(report),
            force,
        )
        return "analysis.json"
    marker = output_dir / "analysis.failure.json"
    marker.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return marker.name


# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------


def build_failure_report(capture: Path | None, error: AnalysisError) -> dict[str, Any]:
    """A minimal, honest report for a run that could not analyze the capture."""
    return {
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
        "failure": {"code": error.code, "message": scrub_free_text(error.message)},
        "limitations": ["The workflow stopped before any domain analysis was executed."],
        "interpretation": {
            "boundary_scope": "No boundary conclusion is available for this run.",
            "subject_scope": "No diagnostic subject was established for this run.",
            "absence_scope": (
                "A failed run is not evidence about the captured network procedure in any "
                "direction."
            ),
            "domain_scope": (
                "A failed run does not change which domains are implemented; it means this "
                "invocation produced no result. IMS analysis is not implemented."
            ),
        },
    }


DomainAdapter = Callable[[Path, Path, str, dict[str, Any], set[str]], dict[str, Any]]


def _run_component(command: list[str], label: str, allow_empty: bool = False) -> bool:
    """Run one accepted component; return False only for a legitimate empty result."""
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise AnalysisError("COMPONENT_UNAVAILABLE", f"{label} could not start: {exc}") from exc
    if completed.returncode == 0:
        return True
    if allow_empty and completed.returncode == 6:
        return False
    detail = (completed.stderr or completed.stdout or "").strip().splitlines()
    first = detail[0] if detail else "no diagnostic output"
    raise AnalysisError(
        "EXTRACTION_FAILED", f"{label} exited with {completed.returncode}: {scrub_free_text(first)}"
    )


def _count_lines(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def execute_epc_pipeline(capture: Path, work_dir: Path, case_id: str) -> dict[str, Any]:
    """Execute the accepted EPC chain: S1AP extraction, NAS-EPS extraction, Attach analysis."""
    run_dir = create_run_directory(work_dir, DOMAIN_EPC)
    s1ap_events = run_dir / "s1ap-events.jsonl"
    nas_events = run_dir / "nas-eps-events.jsonl"
    analysis_path = run_dir / "epc-attach-analysis.json"

    s1ap_present = _run_component(
        [sys.executable, str(S1AP_EXTRACT_SCRIPT), str(capture), "--output", str(s1ap_events), "--force"],
        "S1AP extraction",
        allow_empty=True,
    )
    nas_present = _run_component(
        [sys.executable, str(NAS_EPS_EXTRACT_SCRIPT), str(capture), "--output", str(nas_events), "--force"],
        "NAS-EPS extraction",
        allow_empty=True,
    )
    if not s1ap_present:
        s1ap_events.write_text("", encoding="utf-8")
    if not nas_present:
        nas_events.write_text("", encoding="utf-8")

    _run_component(
        [
            sys.executable,
            str(EPC_ANALYZE_SCRIPT),
            "--s1ap",
            str(s1ap_events),
            "--nas",
            str(nas_events),
            "--output",
            str(analysis_path),
            "--force",
        ],
        "EPC Attach analysis",
        allow_empty=True,
    )
    if not analysis_path.is_file():
        raise AnalysisError("PIPELINE_OUTPUT_MISSING", "EPC Attach analysis produced no result")
    try:
        analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisError("PIPELINE_OUTPUT_UNREADABLE", f"EPC Attach analysis is unreadable: {exc}") from exc
    if not isinstance(analysis, dict):
        raise AnalysisError("PIPELINE_OUTPUT_UNREADABLE", "EPC Attach analysis is not an object")
    return {
        "analysis": analysis,
        "s1ap_event_count": _count_lines(s1ap_events),
        "nas_eps_event_count": _count_lines(nas_events),
    }


def _bounded_evidence_refs(references: Any) -> tuple[list[dict[str, Any]], int]:
    """Project accepted evidence references through an allowlist with a hard cap."""
    if not isinstance(references, list):
        return [], 0
    projected: list[dict[str, Any]] = []
    for reference in references:
        if not isinstance(reference, dict):
            continue
        projected.append({
            "frame_number": reference.get("frame_number"),
            "protocol": reference.get("protocol"),
            "message_type": reference.get("message_type"),
            "evidence_level": reference.get("evidence_level"),
        })
    omitted = max(0, len(projected) - MAX_EVIDENCE_REFERENCES)
    return projected[:MAX_EVIDENCE_REFERENCES], omitted


def _bounded_observation_window(window: Any) -> dict[str, Any] | None:
    """Project an accepted observation window; never infer a missing one."""
    if not isinstance(window, dict):
        return None
    start = window.get("start_frame")
    end = window.get("end_frame")
    if isinstance(start, bool) or not isinstance(start, int):
        return None
    if isinstance(end, bool) or not isinstance(end, int):
        return None
    return {"start_frame": start, "end_frame": end}


def _bounded_limitations(items: Any) -> tuple[list[str], int]:
    """Scrub and cap a limitation list, reporting any omission."""
    if not isinstance(items, list):
        return [], 0
    projected = [
        text for text in (scrub_free_text(item) for item in items if isinstance(item, str)) if text
    ]
    omitted = max(0, len(projected) - MAX_LIST_ITEMS)
    return projected[:MAX_LIST_ITEMS], omitted


def _project_epc_deviations(deviations: Any) -> list[dict[str, Any]]:
    """Project procedure-local deviations with their accepted structured evidence."""
    projected: list[dict[str, Any]] = []
    if not isinstance(deviations, list):
        return projected
    for deviation in deviations:
        if not isinstance(deviation, dict):
            continue
        references, references_omitted = _bounded_evidence_refs(deviation.get("evidence_refs"))
        limitations, limitations_omitted = _bounded_limitations(deviation.get("limitations"))
        entry: dict[str, Any] = {
            "deviation_type": deviation.get("deviation_type"),
            "procedure_stage": deviation.get("procedure_stage"),
            "protocol": deviation.get("protocol"),
            "message_type": deviation.get("message_type"),
            "frame_number": deviation.get("frame_number"),
            "evidence_level": deviation.get("evidence_level"),
            "evidence_refs": references,
            "observation_window": _bounded_observation_window(deviation.get("observation_window")),
            "explanation": scrub_free_text(deviation.get("explanation")),
            "limitations": limitations,
        }
        if references_omitted:
            entry["evidence_refs_omitted"] = references_omitted
        if limitations_omitted:
            entry["limitations_omitted"] = limitations_omitted
        projected.append(entry)
    return projected


def _project_epc_subject(instance: dict[str, Any]) -> dict[str, Any]:
    """Publish one Attach procedure instance as a diagnostic subject."""
    reference = instance.get("procedure_reference")
    association = instance.get("association") or {}
    return {
        "diagnostic_group_reference": reference,
        "boundary_selection_status": "NOT_EVALUATED",
        "boundary_confidence": None,
        "first_abnormal_boundary": None,
        "candidate_boundary_count": 0,
        "source_domain_instances": [
            {
                "source_domain": "epc-procedures",
                "capture_file": association.get("capture_file"),
                "instance_reference": reference,
            }
        ],
        "subject_link": {
            "basis": association.get("basis"),
            "context_count": 1,
            "subject_reference": reference,
        },
        "attempt_index": instance.get("attempt_index"),
        "association_strength": association.get("strength"),
        "procedure_stages": [
            {
                "stage_id": stage.get("stage_id"),
                "status": stage.get("status"),
                "conditional": stage.get("conditional"),
                "first_frame": stage.get("first_frame"),
                "last_frame": stage.get("last_frame"),
                "messages": stage.get("messages"),
            }
            for stage in instance.get("stages") or []
        ],
        "procedure_deviations": _project_epc_deviations(instance.get("deviations")),
        "observations": [
            observation.get("observation_type") for observation in instance.get("observations") or []
        ],
        "evidence_limitations": scrub_list(instance.get("evidence_limitations")),
        "additional_evidence_needed": scrub_list(instance.get("additional_evidence_needed")),
    }


def execute_epc_domain(
    capture: Path,
    work_dir: Path,
    case_id: str,
    detection: dict[str, Any],
    pipeline: Callable[[Path, Path, str], dict[str, Any]],
) -> dict[str, Any]:
    """Run the bounded EPC Attach analysis and normalize its output."""
    payload = pipeline(capture, work_dir, case_id)
    analysis = payload["analysis"]
    instances = analysis.get("procedure_instances") or []
    deviations = sum(len(instance.get("deviations") or []) for instance in instances)
    status = STATUS_COMPLETED if instances else STATUS_INSUFFICIENT_EVIDENCE
    result: dict[str, Any] = {
        "domain": DOMAIN_EPC,
        "display_name": DOMAIN_CAPABILITIES[DOMAIN_EPC]["display_name"],
        "implementation_status": DOMAIN_CAPABILITIES[DOMAIN_EPC]["implementation_status"],
        "execution_status": status,
        "detection": detection,
        "unsupported_reason": None,
        "protocol_evidence": [
            {
                "protocol": "S1AP",
                "extraction_status": EXTRACTION_SUCCESS,
                "observed_in_capture": payload.get("s1ap_event_count", 0) > 0,
                "event_count": payload.get("s1ap_event_count", 0),
            },
            {
                "protocol": "NAS-EPS",
                "extraction_status": EXTRACTION_SUCCESS,
                "observed_in_capture": payload.get("nas_eps_event_count", 0) > 0,
                "event_count": payload.get("nas_eps_event_count", 0),
            },
        ],
        "procedure_summaries": [
            {
                "procedure_domain": "epc-procedures",
                "procedure": "eps-attach",
                "execution_status": "EXECUTED",
                "instance_count": len(instances),
                "deviation_count": deviations,
            }
        ],
        "diagnostic_groups": None,
        "diagnostic_subject_count": len(instances),
        "diagnostic_subjects": [_project_epc_subject(instance) for instance in instances],
        "first_abnormal_boundary": None,
        "boundary_selection_status": "NOT_EVALUATED",
        "evidence_limitations": scrub_list(analysis.get("limitations")),
        "additional_evidence_needed": scrub_list(analysis.get("additional_evidence_needed")),
        "degradation": [],
    }
    if not instances:
        result["degradation"] = [
            "no EPS Attach procedure instance was reconstructed from the observed evidence"
        ]
    return result


def build_domain_adapters(
    pipeline: Callable[[Path, Path, str], tuple[dict[str, Any], Any, Path]],
    epc_pipeline: Callable[[Path, Path, str], dict[str, Any]],
) -> dict[str, DomainAdapter]:
    """Execution adapters, one per implemented domain.

    Adding a real technology domain means adding its Protocol and Domain Skills and
    one adapter here; the 5GC procedure path and the report contract do not change.
    """
    return {
        DOMAIN_5GC: lambda capture, work_dir, case_id, detection, observed: execute_5gc_domain(
            capture, work_dir, case_id, detection, observed, pipeline
        ),
        DOMAIN_EPC: lambda capture, work_dir, case_id, detection, observed: execute_epc_domain(
            capture, work_dir, case_id, detection, epc_pipeline
        ),
    }


def analyze(
    capture: Path,
    domains: str,
    work_dir: Path,
    output_dir: Path,
    force: bool = False,
    inventory: Callable[[Path], dict[str, Any]] | None = None,
    pipeline: Callable[[Path, Path, str], tuple[dict[str, Any], Any, Path]] | None = None,
    epc_pipeline: Callable[[Path, Path, str], dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], int]:
    """Execute the workflow and return the report and the CLI exit code."""
    inventory_fn = inventory or inventory_capture
    pipeline_fn = pipeline or execute_5gc_pipeline
    epc_pipeline_fn = epc_pipeline or execute_epc_pipeline

    validate_paths(capture, work_dir, output_dir)
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

    adapters = build_domain_adapters(pipeline_fn, epc_pipeline_fn)
    case_id = f"capture-{digest[:12]}"
    observed_set = set(observed["protocols"])
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
            results.append(adapter(capture, work_dir, case_id, detection[domain], observed_set))
        except AnalysisError as error:
            results.append(failed_domain_result(domain, detection[domain], error))

    report = build_report(
        capture, digest, inventory_record, observed, detection, selection_mode, selected, results
    )
    status = report["overall_execution_status"]
    publish_reports(
        output_dir,
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        render_text_report(report),
        force,
    )

    exit_codes = {
        STATUS_COMPLETED: EXIT_OK,
        STATUS_PARTIAL: EXIT_OK,
        STATUS_UNSUPPORTED: EXIT_UNSUPPORTED,
        STATUS_INSUFFICIENT_EVIDENCE: EXIT_INSUFFICIENT_EVIDENCE,
        STATUS_FAILED: EXIT_FAILED,
    }
    return report, exit_codes[status]


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
    """Publish a failure record when the destination is safe to write."""
    try:
        validate_paths(args.capture, args.work_dir, args.output_dir)
    except AnalysisError:
        return
    try:
        publish_failure_report(
            args.output_dir, build_failure_report(args.capture, error), args.force
        )
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
        unavailable = [
            result["domain"]
            for result in report["domain_results"]
            if result["execution_status"] in (STATUS_UNSUPPORTED, STATUS_FAILED)
        ]
        if unavailable:
            print(
                f"{ANALYZER_NAME}: not fully analyzed: {', '.join(unavailable)}", file=sys.stderr
            )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
