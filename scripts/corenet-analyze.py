#!/usr/bin/env python3
"""Unified core-network PCAP analysis workflow.

One executable entry point for mobile core-network signaling analysis across
technology domains. The 5GC path executes the accepted Protocol, Correlation,
Domain and Orchestration Skills through the accepted capture pipeline. The EPC path
executes bounded EPS Attach procedure evidence over the accepted S1AP and NAS-EPS
Protocol Skills. IMS executes the accepted SIP, Diameter IMS, IMS Registration and
IMS Session components through a bounded application-level adapter.

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
import importlib.util
import json
import os
import re
import subprocess
import sys
import traceback
import uuid
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ims_media_pipeline  # noqa: E402

ANALYZER_NAME = "corenet-analyze"
ANALYZER_VERSION = "1.1"
REPORT_SCHEMA_VERSION = "1.2"

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_SCRIPT = ROOT / "skills" / "protocol" / "core-network-pcap" / "scripts" / "capture-inventory.py"
PIPELINE_SCRIPT = ROOT / "benchmarks" / "golden-captures" / "scripts" / "run_capture_pipeline.py"
S1AP_EXTRACT_SCRIPT = ROOT / "skills" / "protocol" / "s1ap" / "scripts" / "extract-s1ap.py"
NAS_EPS_EXTRACT_SCRIPT = ROOT / "skills" / "protocol" / "nas-eps" / "scripts" / "extract-nas-eps.py"
EPC_ANALYZE_SCRIPT = ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_attach.py"
EPC_SESSION_ANALYZE_SCRIPT = (
    ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_session.py"
)
GTPV2_EXTRACT_SCRIPT = ROOT / "skills" / "protocol" / "gtpv2" / "scripts" / "extract-gtpv2.py"
GTPV2_CORRELATE_SCRIPT = ROOT / "skills" / "protocol" / "gtpv2" / "scripts" / "correlate-gtpv2.py"
GTPU_EXTRACT_SCRIPT = ROOT / "skills" / "protocol" / "gtpu" / "scripts" / "extract-gtpu.py"
GTPU_SUMMARIZE_SCRIPT = ROOT / "skills" / "protocol" / "gtpu" / "scripts" / "summarize-gtpu.py"
EPC_S1U_ANALYZE_SCRIPT = ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_s1u.py"
EPC_LIFECYCLE_ANALYZE_SCRIPT = (
    ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_bearer_lifecycle.py"
)
EPC_SESSION_IDENTITY_ANALYZE_SCRIPT = (
    ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_session_identity.py"
)
DIAMETER_CORE_EXTRACT_SCRIPT = ROOT / "skills" / "protocol" / "diameter-core" / "scripts" / "extract-diameter-core.py"
DIAMETER_CORE_CORRELATE_SCRIPT = ROOT / "skills" / "protocol" / "diameter-core" / "scripts" / "correlate-diameter-core.py"
DIAMETER_EPC_ANALYZE_SCRIPT = ROOT / "skills" / "protocol" / "diameter-epc" / "scripts" / "analyze-diameter-epc.py"
SIP_EXTRACT_SCRIPT = ROOT / "skills" / "protocol" / "sip" / "scripts" / "extract-sip.py"
DIAMETER_IMS_ANALYZE_SCRIPT = ROOT / "skills" / "protocol" / "diameter-ims" / "scripts" / "analyze-diameter-ims.py"
IMS_REGISTRATION_ANALYZE_SCRIPT = ROOT / "skills" / "domain" / "ims-registration" / "scripts" / "analyze-ims-registration.py"
IMS_SESSION_ANALYZE_SCRIPT = ROOT / "skills" / "domain" / "ims-session" / "scripts" / "analyze-ims-session.py"
IMS_STAGE_FAILURE_PREFIX = "IMS_"
MAX_IMS_REFERENCES = 10
EPC_ATTACH_S6A_ANALYZE_SCRIPT = ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_attach_s6a.py"
DIAMETER_CORE_EXTRACTION_FAILURE = "DIAMETER_CORE_EXTRACTION_FAILED"
DIAMETER_CORE_CORRELATION_FAILURE = "DIAMETER_CORE_CORRELATION_FAILED"
DIAMETER_EPC_ANALYSIS_FAILURE = "DIAMETER_EPC_ANALYSIS_FAILED"
ATTACH_S6A_JOINT_FAILURE = "ATTACH_S6A_JOINT_ANALYSIS_FAILED"
ATTACH_S6A_FAILURE_STAGES = {
    DIAMETER_CORE_EXTRACTION_FAILURE: "DIAMETER_CORE_EXTRACTION",
    DIAMETER_CORE_CORRELATION_FAILURE: "DIAMETER_CORE_CORRELATION",
    DIAMETER_EPC_ANALYSIS_FAILURE: "DIAMETER_EPC_APPLICATION",
    ATTACH_S6A_JOINT_FAILURE: "ATTACH_S6A_JOINT",
}
ATTACH_S6A_MANIFEST_NAME = "epc-attach-s6a-coordinated-run"
ATTACH_S6A_MANIFEST_SCHEMA_VERSION = "1.0.0"
EPC_DEFAULT_BEARER_ANALYZE_SCRIPT = (
    ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_default_bearer.py"
)
EPC_RELEASE_NARRATIVE_ANALYZE_SCRIPT = (
    ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_release_narrative.py"
)
EPC_EVIDENCE_AUDIT_ANALYZE_SCRIPT = (
    ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_evidence_audit.py"
)
EPC_BOUNDARY_SCRIPT = (
    ROOT / "skills" / "orchestration" / "epc-failure-boundary" / "scripts" / "analyze_epc_failure_boundary.py"
)
EPC_DEDICATED_BEARER_ANALYZE_SCRIPT = (
    ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_dedicated_bearer_control.py"
)
EPC_DEDICATED_BEARER_CONTRACT_SCRIPT = ROOT / "scripts" / "epc_dedicated_bearer_contract.py"
EPC_DEDICATED_BEARER_TIMELINE_SCRIPT = (
    ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_dedicated_bearer_timeline.py"
)
EPC_DEDICATED_BEARER_TIMELINE_CONTRACT_SCRIPT = (
    ROOT / "scripts" / "epc_dedicated_bearer_timeline_contract.py"
)
EPC_DEDICATED_BEARER_ATTRIBUTION_SCRIPT = (
    ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "analyze_epc_dedicated_bearer_attribution.py"
)
EPC_DEDICATED_BEARER_ATTRIBUTION_CONTRACT_SCRIPT = (
    ROOT / "scripts" / "epc_dedicated_bearer_attribution_contract.py"
)
DEDICATED_BEARER_FAMILIES = ("create-bearer", "update-bearer", "delete-bearer")
DEDICATED_BEARER_FAILURE_CODE = "DEDICATED_BEARER_CONTROL_FAILED"
DEDICATED_BEARER_TIMELINE_FAILURE_CODE = "DEDICATED_BEARER_TIMELINE_FAILED"
DEDICATED_BEARER_ATTRIBUTION_FAILURE_CODE = "DEDICATED_BEARER_ATTRIBUTION_FAILED"
DEDICATED_BEARER_NOT_OBSERVED = "NOT_OBSERVED_IN_CAPTURE"
MAX_DEDICATED_TIMELINE_ENTRIES = 128
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
        "supported_protocol_families": ["S1AP", "NAS-EPS", "GTPv2-C", "SCTP"],
        "analysis_capabilities": [
            "protocol-extraction",
            "eps-attach-procedure-evidence",
            "authentication-observation",
            "security-mode-observation",
            "explicit-attach-rejection",
            "bounded-s1-context-and-release-observations",
            "gtpv2-session-control-transaction-evidence",
            "item-scoped-bearer-context-evidence",
            "bounded-session-control-subject-analysis",
        ],
        "entry_point": "skills/domain/epc-procedures/scripts/analyze_epc_attach.py",
        "session_entry_point": "skills/domain/epc-procedures/scripts/analyze_epc_session.py",
        "entry_point_available": True,
        "required_dependencies": ["python3", "tshark"],
        "planned_protocol_families": ["Diameter EPC"],
        "not_implemented_capabilities": [
            "Diameter EPC",
            "full EPS bearer lifecycle",
            "complete ESM semantics",
            "cross-interface S11 to S5/S8 session association",
            "end-to-end EPC failure-boundary orchestration",
            "user-plane success verification",
        ],
        "unsupported_reason": None,
    },
    DOMAIN_IMS: {
        "domain": DOMAIN_IMS,
        "display_name": "IP Multimedia Subsystem",
        "implementation_status": "IMPLEMENTED",
        "supported_protocol_families": ["SIP", "Diameter", "TCP", "UDP"],
        "analysis_capabilities": [
            "protocol-extraction",
            "ims-registration-procedure-evidence",
            "ims-session-establishment-and-release-evidence",
            "diameter-ims-cx-dx-evidence",
        ],
        "entry_point": "scripts/corenet-analyze.py",
        "entry_point_available": True,
        "required_dependencies": ["python3", "tshark"],
        "planned_protocol_families": ["SDP", "RTP", "Diameter Rx", "Diameter Charging"],
        "not_implemented_capabilities": [
            "SDP offer/answer semantics",
            "RTP media and QoS evidence",
            "IMS session modification",
            "Diameter Rx",
            "Diameter charging",
            "subscriber identity bridging",
            "end-to-end IMS fault isolation",
        ],
        "unsupported_reason": None,
    },
}

# Free-text scrubbing. Structured fields are published through explicit
# allowlists instead of being scrubbed, so evidence identity survives redaction.
_WORKSTATION_PATH = re.compile(r"(?<![\w.-])[A-Za-z]:[\\/][^\s\"']*")
_POSIX_PATH = re.compile(r"(?<![\w.-])(?:/[\w.-]+){2,}/?")
_LONG_DIGIT_RUN = re.compile(r"\d{14,}")

# The EPC Attach Domain still publishes its pre-orchestration scope note. Once the
# accepted Orchestration Skill has run, that note is superseded and must not be
# republished as if no orchestration existed.
STALE_EPC_BOUNDARY_NOTE = "No EPC Analysis Orchestration exists"

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
        # SIP observation makes the bounded IMS evidence path eligible without
        # upgrading IMS technology attribution from SUSPECTED to CONFIRMED.
        ims_detection = detection.get(DOMAIN_IMS) or {}
        if (
            ims_detection.get("status") == DETECTION_SUSPECTED
            and "SIP" in (ims_detection.get("basis") or [])
            and DOMAIN_IMS not in selected
        ):
            selected.append(DOMAIN_IMS)
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


def _read_5gc_registration_evidence(artifacts_dir: Path) -> dict[str, Any]:
    """Read bounded, sanitized registration evidence from the accepted artifacts."""
    registration_path = artifacts_dir / "5gc-registration-mobility-analysis.json"
    nas_path = artifacts_dir / "nas-5gs-events.jsonl"
    evidence: dict[str, Any] = {}
    if registration_path.is_file():
        try:
            document = json.loads(registration_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            document = {}
        analyses = document.get("analyses") if isinstance(document, dict) else None
        analysis = analyses[0] if isinstance(analyses, list) and analyses else {}
        if isinstance(analysis, dict):
            evidence["procedure_completeness_confidence"] = analysis.get("confidence")
            events = [item for item in analysis.get("events") or [] if isinstance(item, dict)]
            evidence["events"] = [
                {
                    "frame_number": item.get("frame_number"),
                    "protocol": item.get("protocol"),
                    "message_type": item.get("message_type"),
                    "cause": item.get("cause"),
                }
                for item in events
                if item.get("message_type") in {
                    "Authentication request",
                    "Authentication failure",
                    "Authentication reject",
                    "Security mode complete",
                    "Security mode reject",
                    "Registration reject",
                }
            ]
    if nas_path.is_file():
        requested: list[dict[str, Any]] = []
        inner: list[dict[str, Any]] = []
        auth_fields: dict[str, Any] = {}
        for line in nas_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            for item in event.get("requested_nssai") or []:
                if isinstance(item, dict):
                    requested.append({
                        "frame_number": event.get("frame_number"),
                        "sst": item.get("sst"),
                        "sd": item.get("sd"),
                    })
            for item in event.get("inner_nas_messages") or []:
                if isinstance(item, dict) and item.get("message_type") == "Security mode complete":
                    inner.append({
                        "frame_number": event.get("frame_number"),
                        "message_type": item.get("message_type"),
                        "message_type_code": item.get("message_type_code"),
                    })
            if event.get("message_type") == "Security mode complete":
                inner.append({
                    "frame_number": event.get("frame_number"),
                    "message_type": event.get("message_type"),
                    "message_type_code": event.get("message_type_code"),
                })
            if event.get("message_type") == "Authentication request" and isinstance(event.get("authentication"), dict):
                auth_fields = {
                    "frame_number": event.get("frame_number"),
                    **event.get("authentication"),
                }
        evidence["requested_nssai"] = requested[:MAX_LIST_ITEMS]
        evidence["security_mode_complete_frames"] = inner[:MAX_LIST_ITEMS]
        evidence["authentication_request"] = auth_fields
    return evidence


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
    registration_evidence = _read_5gc_registration_evidence(artifacts_dir)
    for subject in subjects:
        if any(
            _dict(instance).get("source_domain") == "5gc-registration-mobility"
            for instance in subject.get("source_domain_instances") or []
        ):
            subject["procedure_completeness_confidence"] = registration_evidence.get(
                "procedure_completeness_confidence"
            )
    result: dict[str, Any] = {
        "domain": DOMAIN_5GC,
        "display_name": DOMAIN_CAPABILITIES[DOMAIN_5GC]["display_name"],
        "implementation_status": DOMAIN_CAPABILITIES[DOMAIN_5GC]["implementation_status"],
        "execution_status": components["status"],
        "detection": detection,
        "unsupported_reason": None,
        "protocol_evidence": project_protocol_evidence(summary, artifacts_dir),
        "procedure_summaries": project_procedure_summaries(summary),
        "registration_evidence": registration_evidence,
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
        boundary_status = result.get("boundary_selection_status")
        if (
            result["first_abnormal_boundary"] is None
            and boundary_status == "NOT_EVALUATED"
            and result["execution_status"] in (STATUS_COMPLETED, STATUS_PARTIAL)
        ):
            limitations.append(
                f"{result['domain']} boundary selection is not evaluated: the "
                f"{result['domain']} Analysis Orchestration did not run or did not succeed, so "
                "deviations stay procedure-local."
            )
        elif boundary_status == "EVALUATED_PER_SUBJECT" and result["execution_status"] in (
            STATUS_COMPLETED,
            STATUS_PARTIAL,
        ):
            summary = result.get("boundary_summary") or {}
            limitations.append(
                f"{result['domain']} boundary selection is evaluated per diagnostic subject "
                f"({summary.get('group_count', 0)} subject(s)); no single global "
                f"{result['domain']} boundary is asserted."
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
        for item in result.get("protocol_evidence") or []:
            extractors.append({"protocol": item["protocol"], "status": item["extraction_status"]})
        for item in result.get("procedure_summaries") or []:
            analyzers.append(
                {"analyzer": item["procedure_domain"], "status": item["execution_status"]}
            )
        if result["domain"] == DOMAIN_5GC:
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
                "bounded to EPS Attach procedure evidence and bounded GTPv2-C session-control "
                "transaction evidence; EPC bearer lifecycle, complete ESM semantics, "
                "cross-interface session association and global EPC boundary selection are "
                "not implemented. IMS coverage is bounded to SIP extraction, Diameter Cx/Dx "
                "evidence, IMS Registration evidence and IMS Session establishment/release "
                "evidence; SDP, RTP, Diameter Rx/charging, session modification, subscriber "
                "identity bridging and end-to-end IMS diagnosis are not implemented."
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


def _render_ims_media(lines: list[str], media: dict[str, Any]) -> None:
    if not isinstance(media, dict) or not media.get("requested"):
        return
    sdp = media.get("sdp") or {}
    signaling = media.get("media_signaling") or {}
    rtp = media.get("rtp_rtcp") or {}
    sequence = rtp.get("sequence") or {}
    correlation = media.get("transport_correlation") or {}
    session = media.get("ims_media_session") or {}
    lines.append(
        f"  Media pipeline  : {_value(media.get('media_status'))}; "
        f"offline={'yes' if media.get('offline') else 'no'}; "
        f"network_required={'yes' if media.get('network_required') else 'no'}; "
        f"endpoint_key={_value(media.get('endpoint_key_status'))}"
    )
    lines.append(
        f"  SDP             : {_value(sdp.get('analysis_status'))}, "
        f"{_value(sdp.get('message_count'))} message(s), "
        f"{_value(sdp.get('media_section_count'))} media section(s), "
        f"types {', '.join(f'{k}={v}' for k, v in (sdp.get('media_type_counts') or {}).items()) or 'none'}, "
        f"directions {', '.join(f'{k}={v}' for k, v in (sdp.get('direction_counts') or {}).items()) or 'none'}"
    )
    lines.append(
        f"  Media signaling : {_value(signaling.get('analysis_status'))}, "
        f"offers={_value(signaling.get('observed_offer_count'))}, "
        f"answers={_value(signaling.get('observed_answer_count'))}, "
        f"established={_value(signaling.get('established_exchange_count'))}, "
        f"incomplete={_value(signaling.get('incomplete_exchange_count'))}, "
        f"ambiguous={_value(signaling.get('ambiguous_exchange_count'))}, "
        f"out_of_scope={_value(signaling.get('out_of_scope_observation_count'))}"
    )
    lines.append(
        f"  RTP / RTCP      : {_value(rtp.get('analysis_status'))}, "
        f"{_value(rtp.get('rtp_packet_count'))} RTP packet(s), "
        f"{_value(rtp.get('rtcp_component_count'))} RTCP component(s), "
        f"{_value(rtp.get('udp_stream_count'))} UDP stream(s), "
        f"{_value(rtp.get('ssrc_reference_count'))} SSRC reference(s), "
        f"frames {_value(rtp.get('first_frame_number'))}..{_value(rtp.get('last_frame_number'))}"
    )
    lines.append(
        f"  RTP sequence    : {_value(sequence.get('source_stream_count'))} source stream(s), "
        f"validated={_value(sequence.get('validated_stream_count'))}, "
        f"probation={_value(sequence.get('probation_stream_count'))}, "
        f"ambiguous={_value(sequence.get('ambiguous_stream_count'))}, "
        f"wraps={_value(sequence.get('sequence_wrap_count'))}, "
        f"duplicates={_value(sequence.get('duplicate_observation_count'))}, "
        f"out_of_order={_value(sequence.get('out_of_order_observation_count'))}, "
        f"gaps={_value(sequence.get('sequence_gap_count'))}, "
        f"unobserved_slots={_value(sequence.get('unobserved_sequence_number_slot_count'))}, "
        f"restarts={_value(sequence.get('restart_pattern_count'))}"
    )
    lines.append(
        f"  SDP/RTP match   : {_value(correlation.get('matched_correlation_count'))}/"
        f"{_value(correlation.get('correlation_count'))} matched, "
        f"{_value(correlation.get('ambiguous_correlation_count'))} ambiguous, "
        f"{_value(correlation.get('unmatched_correlation_count'))} unmatched, "
        f"{_value(correlation.get('out_of_scope_correlation_count'))} out-of-scope, "
        f"{_value(correlation.get('unmatched_stream_count'))} unmatched stream(s)"
    )
    lines.append(
        f"  IMS media       : {_value(session.get('attempt_count'))} attempt(s), "
        f"{_value(session.get('exchange_count'))} exchange(s), "
        f"established={_value(session.get('established_exchange_count'))}, "
        f"attempt_bound={_value(session.get('attempt_bound_observation_count'))}, "
        f"branch_bound={_value(session.get('branch_bound_observation_count'))}, "
        f"observations={_value(session.get('transport_observation_count'))}, "
        f"temporal={_value(session.get('temporal_association_status'))}"
    )
    for item in (correlation.get("matched_correlations") or [])[:8]:
        lines.append(
            f"    matched       : {_value(item.get('correlation_reference'))} "
            f"[{_value(item.get('association_status'))}] streams "
            f"{', '.join(item.get('rtp_udp_stream_references') or []) or '-'} directions "
            f"{', '.join(item.get('match_directions') or []) or '-'}"
        )
    for item in (session.get("associated_observations") or [])[:8]:
        lines.append(
            f"    media obs     : {_value(item.get('observation_reference'))} "
            f"{_value(item.get('association_scope'))}/{_value(item.get('association_status'))} "
            f"attempt={_value(item.get('attempt_reference'))} "
            f"branch={_value(item.get('dialog_branch_reference'))}"
        )
    call_summary = media.get("call_evidence_summary") or {}
    if call_summary.get("attempt_count"):
        lines.append(
            f"  Per-call evidence: {_value(call_summary.get('attempt_count'))} attempt(s), "
            f"supported={_value(call_summary.get('supported_attempt_count'))}, "
            f"partial={_value(call_summary.get('partial_attempt_count'))}, "
            f"ambiguous={_value(call_summary.get('ambiguous_attempt_count'))}, "
            f"signaling_only={_value(call_summary.get('signaling_only_attempt_count'))}, "
            f"insufficient={_value(call_summary.get('insufficient_attempt_count'))}, "
            f"unsupported={_value(call_summary.get('unsupported_attempt_count'))}; "
            f"all_supported={'yes' if call_summary.get('all_attempts_supported') else 'no'}"
        )
        for attempt in (media.get("per_call_attempts") or [])[:8]:
            lines.append(
                f"    call: {_value(attempt.get('attempt_reference'))} / "
                f"{_value(attempt.get('evidence_status'))} / "
                f"ownership={_value((attempt.get('transport') or {}).get('ownership_status'))} / "
                f"sdp={_value((attempt.get('sdp') or {}).get('offer_answer_status'))} / "
                f"streams={len((attempt.get('rtp') or {}).get('source_stream_references') or [])}"
            )
            temporal = attempt.get("temporal") or {}
            lines.append(
                f"      temporal: {_value(temporal.get('temporal_association_status'))}; "
                f"SIP frames {_value(temporal.get('first_sip_frame'))}..{_value(temporal.get('last_sip_frame'))}; "
                f"RTP frames {_value(temporal.get('first_rtp_frame'))}..{_value(temporal.get('last_rtp_frame'))}"
            )
            last = (attempt.get("diagnostic") or {}).get("last_supported_evidence") or {}
            if last:
                lines.append(
                    f"      last: {_value(last.get('stage'))} {_value(last.get('reference'))} "
                    f"frame {_value(last.get('frame_number'))}"
                )
            if attempt.get("missing_evidence"):
                lines.append(
                    "      missing: " + ", ".join(attempt.get("missing_evidence")[:6])
                )
        for branch in (media.get("per_call_branches") or [])[:6]:
            lines.append(
                f"    branch: {_value(branch.get('branch_reference'))} / "
                f"{_value(branch.get('evidence_status'))} / scope={_value(branch.get('ownership_scope'))} / "
                f"temporal={_value((branch.get('temporal') or {}).get('temporal_association_status'))}"
            )
    duplicate = media.get("duplicate_observation_investigation") or {}
    if duplicate:
        lines.append(
            f"  RTP duplicates  : raw={_value(duplicate.get('raw_rtp_observation_count'))}, "
            f"distinct_packet_identities={_value(duplicate.get('distinct_packet_identity_count'))}, "
            f"multi_vantage={_value(duplicate.get('multi_vantage_event_count'))}, "
            f"duplicate_packet={_value(duplicate.get('duplicate_packet_event_count'))}, "
            f"sequence_only={_value(duplicate.get('sequence_only_duplicate_event_count'))}, "
            f"rtp_stream_reported={_value(duplicate.get('rtp_stream_reported_duplicate_sequence_observation_count'))}"
        )
    rtcp = media.get("rtcp_association") or {}
    if rtcp:
        lines.append(
            f"  RTCP association: components={_value(rtcp.get('component_count'))}, "
            f"associations={_value(rtcp.get('association_count'))}, "
            f"unbound={_value(rtcp.get('unbound_component_count'))}, "
            f"status="
            + ", ".join(
                f"{key.removeprefix('RTCP_STREAM_ASSOCIATION_').lower()}={value}"
                for key, value in (rtcp.get("status_counts") or {}).items()
            )
        )
        for report in (rtcp.get("receiver_reported_quality") or [])[:4]:
            lines.append(
                f"    receiver report: {_value(report.get('source_event_reference'))} / "
                f"fraction_lost={_value(report.get('fraction_lost'))} / "
                f"cumulative_lost={_value(report.get('cumulative_packets_lost'))} / "
                f"jitter_rtp={_value(report.get('interarrival_jitter_rtp_units'))} / "
                f"jitter_ms={_value(report.get('jitter_ms'))} / "
                f"origin={_value(report.get('measurement_origin'))}"
            )
    for item in (media.get("ambiguity_inventory") or [])[:5]:
        lines.append(
            f"    ambiguity: {_value(item.get('scope'))} {_value(item.get('reference'))} "
            f"{_value(item.get('reason_code'))}"
        )

    diagnostics = media.get("diagnostics") or {}
    for label, key in (
        ("observed", "observed"),
        ("missing", "missing"),
        ("ambiguous", "ambiguous"),
        ("unsupported", "unsupported"),
    ):
        for item in (diagnostics.get(key) or [])[:MAX_LIST_ITEMS]:
            lines.append(f"    {label:<13} : {scrub_free_text(item)}")
    last = diagnostics.get("last_supported_evidence") or {}
    if last:
        lines.append(
            f"    last evidence : {_value(last.get('stage'))} "
            f"{_value(last.get('reference'))} frame {_value(last.get('frame_number'))}"
        )
    for stage, error in (media.get("stage_errors") or {}).items():
        lines.append(f"    media failure : {stage}: {scrub_free_text(error)}")
    for item in (media.get("limitations") or [])[:MAX_LIST_ITEMS]:
        lines.append(f"    media limit   : {scrub_free_text(item)}")


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

    ims_blocks = [
        result for result in results if result.get("domain") == DOMAIN_IMS
    ]
    if ims_blocks:
        _section(lines, "IMS Evidence")
    for result in ims_blocks:
        evidence = result.get("ims_evidence") or {}
        sip = evidence.get("sip_protocol") or {}
        diameter = evidence.get("diameter_protocol") or {}
        registration = evidence.get("registration") or {}
        session = evidence.get("session") or {}
        cxdx = evidence.get("diameter_ims") or {}
        lines.append(
            f"  IMS execution   : {_value(result.get('execution_status'))}; "
            f"technology attribution {_value((result.get('detection') or {}).get('status'))}"
        )
        lines.append(
            f"  SIP             : {_value(sip.get('extraction_status'))}, "
            f"{_value(sip.get('event_count'))} event(s), "
            f"{_value(sip.get('transaction_count'))} transaction(s), "
            f"{_value(sip.get('dialog_count'))} dialog(s), "
            f"{_value(sip.get('extraction_executions'))} extraction execution(s)"
        )
        lines.append(
            f"  Diameter        : {_value(diameter.get('extraction_status'))}, "
            f"{_value(diameter.get('event_count'))} event(s), "
            f"{_value(diameter.get('transaction_count'))} transaction(s)"
        )
        lines.append(
            f"  Cx/Dx           : {_value(cxdx.get('analysis_status'))}, "
            f"{_value(cxdx.get('observation_count'))} observation(s)"
        )
        lines.append(
            f"  Registration    : {_value(registration.get('analysis_status'))}, "
            f"{_value(registration.get('attempt_count'))} attempt(s), "
            f"registration types {', '.join(registration.get('registration_types') or []) or 'none'}"
        )
        if registration.get("attempt_references"):
            lines.append(
                "    references   : "
                + ", ".join(registration.get("attempt_references") or [])
            )
        lines.append(
            f"  Session         : {_value(session.get('analysis_status'))}, "
            f"{_value(session.get('attempt_count'))} attempt(s), "
            f"{_value(session.get('early_dialog_count'))} Early Dialog(s), "
            f"{_value(session.get('confirmed_dialog_count'))} Confirmed Dialog(s)"
        )
        lines.append(
            f"  CANCEL / BYE    : {_value(session.get('cancel_observation_count'))} CANCEL "
            f"observation(s), {_value(session.get('bye_release_observation_count'))} BYE "
            "release observation(s)"
        )
        lines.append(
            "  Cross-protocol  : NOT_ESTABLISHED "
            "(SIP registration, Diameter Cx/Dx and SIP session inventories remain independent)"
        )
        for item in (evidence.get("limitations") or [])[:MAX_LIST_ITEMS]:
            lines.append(f"    limitation   : {scrub_free_text(item)}")
        _render_ims_media(lines, evidence.get("media") or {})
        for item in result.get("degradation") or []:
            lines.append(f"    failure      : {scrub_free_text(item)}")

    registration_any = False
    for result in results:
        evidence = result.get("registration_evidence") or {}
        if not evidence:
            continue
        if not registration_any:
            _section(lines, "5GC Registration Evidence")
            registration_any = True
        boundary = result.get("first_abnormal_boundary") or {}
        lines.append(
            f"  {result['domain']}: boundary confidence "
            f"{_value(boundary.get('confidence'))}; procedure completeness confidence "
            f"{_value(evidence.get('procedure_completeness_confidence'))}"
        )
        for frame in evidence.get("security_mode_complete_frames") or []:
            lines.append(
                f"    Security mode complete: frame {_value(frame.get('frame_number'))}"
            )
        for nssai in evidence.get("requested_nssai") or []:
            lines.append(
                f"    Requested S-NSSAI: frame {_value(nssai.get('frame_number'))}, "
                f"SST {_value(nssai.get('sst'))}, SD {_value(nssai.get('sd'))}"
            )
        auth = evidence.get("authentication_request") or {}
        if auth:
            lines.append(
                f"    Authentication request: frame {_value(auth.get('frame_number'))}, "
                f"RAND present {_value(auth.get('rand_present'))}, "
                f"AUTN present {_value(auth.get('autn_present'))}"
            )
        events = evidence.get("events") or []
        for event in events:
            cause = event.get("cause") or {}
            if event.get("message_type") in (
                "Authentication failure",
                "Authentication reject",
                "Registration reject",
            ):
                lines.append(
                    f"    {event.get('message_type')}: frame {_value(event.get('frame_number'))}, "
                    f"cause {_value(cause.get('family'))} {_value(cause.get('code'))} "
                    f"{_value(cause.get('name'))}"
                )
        authentication_context = bool(auth) or any(
            event.get("message_type") in ("Authentication failure", "Authentication reject")
            for event in events
        )
        cause_20_observed = any(
            (event.get("cause") or {}).get("family") == "5GMM"
            and (event.get("cause") or {}).get("code") == 20
            for event in events
        )
        if authentication_context:
            lines.append(
                "    interpretation: Authentication Reject may omit a 5GMM Cause; MAC failure and "
                "Synch failure are distinct; a Cause 20 does not by itself prove a K/OPc mismatch"
            )
        elif cause_20_observed:
            lines.append(
                "    interpretation: Cause 20 reports MAC failure; it does not by itself prove a K/OPc mismatch"
            )
        else:
            lines.append(
                "    next checks: inspect AMF NAS parsing and registration handling logs as external "
                "evidence for deeper diagnosis"
            )

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
                f"    - {subject['diagnostic_group_reference']} "
                f"[{_value(subject.get('subject_type'))}]: "
                f"{_value(subject.get('boundary_selection_status'))} "
                f"(boundary confidence {_value(subject.get('boundary_confidence'))}, "
                f"procedure completeness confidence {_value(subject.get('procedure_completeness_confidence'))}, "
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
            if subject.get("subject_type") == "EPC_S1U_OBSERVATION":
                evidence = subject.get("interface_evidence") or {}
                lines.append(
                    f"      S1-U stream: {_value(subject.get('direction'))} "
                    f"({_value((evidence.get('interfaces') or [None])[0])}, "
                    f"basis {_value(evidence.get('basis'))}), "
                    f"endpoint match {_value(subject.get('receiving_endpoint_match_status'))}, "
                    f"bearer association {_value(subject.get('bearer_association_status'))}"
                )
                lines.append(
                    f"      packets: {_value(subject.get('observed_g_pdu_packet_count'))} G-PDU, "
                    f"{_value(subject.get('observed_payload_byte_count'))} payload octets "
                    f"(frames {_value(subject.get('request_frame'))}-{_value(subject.get('response_frame'))})"
                )
                bearer = (subject.get("subject_link") or {}).get("bearer_subject_reference")
                if bearer:
                    lines.append(f"      bearer subject: {bearer}")
            if subject.get("subject_type") == "EPS_DEFAULT_BEARER":
                evidence = subject.get("interface_evidence") or {}
                lines.append(
                    f"      default bearer: interfaces {', '.join(evidence.get('interfaces') or [])} "
                    f"(basis {_value(evidence.get('basis'))}), "
                    f"association {_value(subject.get('association_strength'))}, "
                    f"attach {_value(subject.get('attach_association'))}, "
                    f"tunnel {_value(subject.get('cross_interface_association'))}"
                )
                lines.append(
                    f"      ESM: request frame {_value(subject.get('request_frame'))} -> "
                    f"response frame {_value(subject.get('response_frame'))}, "
                    f"cause {_value((subject.get('message_cause') or {}).get('cause_code'))}"
                )
                for outcome in subject.get("outcomes") or []:
                    lines.append(f"      outcome: {outcome}")
            for release_cause in subject.get("s1ap_release_causes") or []:
                lines.append(
                    f"      S1AP release cause: {_value(release_cause.get('category'))} "
                    f"{_value(release_cause.get('value'))} at frame "
                    f"{_value(release_cause.get('frame_number'))}"
                )
            for stage in subject.get("procedure_stages") or []:
                lines.append(
                    f"      stage {stage.get('stage_id')}: {_value(stage.get('status'))}"
                )
            if subject.get("subject_type") == "EPC_SESSION_CONTROL":
                evidence = subject.get("interface_evidence") or {}
                lines.append(
                    f"      session control: interface {_value(subject.get('interface'))} "
                    f"(basis {_value(evidence.get('basis'))}), "
                    f"association {_value(subject.get('association_strength'))}, "
                    f"transactions {len(subject.get('transaction_references') or [])}"
                )
                primary = subject.get("primary_transaction") or {}
                if primary:
                    lines.append(
                        f"      primary: {_value(primary.get('procedure_family'))} "
                        f"request frame {_value(primary.get('request_frame'))} -> "
                        f"response frame {_value(primary.get('response_frame'))}, "
                        f"outcome {_value(primary.get('outcome'))}"
                    )
                for family in subject.get("procedure_families") or []:
                    lines.append(f"      procedure: {family}")
                lines.append("      cross-interface association: NOT_ESTABLISHED")
            boundary = subject.get("first_abnormal_boundary")
            if isinstance(boundary, dict):
                lines.append(
                    f"      boundary: {boundary.get('deviation_type')} at frame "
                    f"{_value(boundary.get('frame_number'))} "
                    f"({_value(boundary.get('protocol'))} {_value(boundary.get('message_type'))}), "
                    f"confidence {_value(subject.get('boundary_confidence'))}"
                )
                if boundary.get("cause_code") is not None:
                    lines.append(
                        f"      cause: {_value(boundary.get('cause_family'))} "
                        f"{_value(boundary.get('cause_code'))} "
                        f"{_value(boundary.get('cause_name'))} "
                        f"(scope {_value(boundary.get('cause_scope'))})"
                    )
            elif subject.get("boundary_selection_status") not in (None, "NOT_EVALUATED"):
                lines.append(f"      boundary: {subject.get('boundary_selection_status')}")
            for release_cause in subject.get("s1ap_release_causes") or []:
                lines.append(
                    f"      S1AP release cause: {_value(release_cause.get('category'))} "
                    f"{_value(release_cause.get('value'))} at frame "
                    f"{_value(release_cause.get('frame_number'))}"
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
                if deviation.get("cause_code") is not None:
                    lines.append(
                        f"        cause: {_value(deviation.get('cause_family'))} "
                        f"{_value(deviation.get('cause_code'))} "
                        f"{_value(deviation.get('cause_name'))} "
                        f"(scope {_value(deviation.get('cause_scope'))})"
                    )
    if not subject_any:
        _empty(lines, "no diagnostic group was established")

    lifecycle_blocks = [
        (result, result.get("bearer_lifecycle"))
        for result in results
        if isinstance(result.get("bearer_lifecycle"), dict)
    ]
    if lifecycle_blocks:
        _section(lines, "Bearer Lifecycle Evidence")
    for result, block in lifecycle_blocks:
        accounting = block.get("accounting") or {}
        lines.append(
            f"  {result['domain']}: {_value(block.get('advertisement_family_count'))} advertisement "
            f"family(ies), {_value(block.get('lifecycle_subject_count'))} generation(s), "
            f"{_value(block.get('generation_boundary_count'))} proved boundary(ies), "
            f"{_value(block.get('release_observation_count'))} release observation(s)"
        )
        lines.append(
            f"    packets: {_value(accounting.get('attributed_g_pdu_count'))} attributed + "
            f"{_value(accounting.get('unresolved_g_pdu_count'))} unresolved = "
            f"{_value(accounting.get('aggregate_g_pdu_count'))} observed G-PDU "
            f"(conserved {_value(accounting.get('conserved_g_pdu'))})"
        )
        lines.append(
            f"    octets: {_value(accounting.get('attributed_payload_octets'))} attributed + "
            f"{_value(accounting.get('unresolved_payload_octets'))} unresolved = "
            f"{_value(accounting.get('aggregate_payload_octets'))} observed payload octets "
            f"(conserved {_value(accounting.get('conserved_payload_octets'))})"
        )
        for classification in sorted(set((block.get("advertisement_family_classifications") or {}).values())):
            count = sum(
                1
                for item in (block.get("advertisement_family_classifications") or {}).values()
                if item == classification
            )
            lines.append(f"    family classification: {classification} x{count}")
        for generation in block.get("generations") or []:
            window = generation.get("observation_window") or {}
            lines.append(
                f"    generation {generation.get('generation_reference')} "
                f"[{_value(generation.get('receiving_endpoint_role'))}, "
                f"interface type {_value(generation.get('reviewed_interface_type'))}]: "
                f"{_value(generation.get('generation_state'))}, "
                f"frames {_value(window.get('start_frame'))}-{_value(window.get('end_frame'))}, "
                f"observations {', '.join(generation.get('observations') or []) or 'none'}"
            )
        lines.append(
            "    boundary selection: NOT_APPLICABLE "
            "(a lifecycle generation boundary is not an abnormal failure boundary)"
        )

    joint_blocks = [
        (result, result.get("attach_s6a"))
        for result in results
        if isinstance(result.get("attach_s6a"), dict)
    ]
    if joint_blocks:
        _section(lines, "EPC Attach and S6a/S6d Joint Evidence")
    for result, block in joint_blocks:
        lines.append(
            f"  {result['domain']}: {_value(block.get('execution_status'))} "
            f"(analysis {_value(block.get('analysis_status'))}), "
            f"{_value(block.get('attach_instance_count'))} Attach instance(s), "
            f"{_value(block.get('diameter_observation_count'))} Diameter observation(s), "
            f"{_value(block.get('diameter_matched_count'))} matched"
        )
        lines.append(
            f"    identity association: {_value(block.get('identity_association_status'))}; "
            f"common capture: {_value(block.get('common_capture_status'))}; "
            f"artifacts bound to capture: {_value(block.get('common_capture_artifacts_bound'))}; "
            f"run manifest: {_value(block.get('run_manifest_present'))}"
        )
        if block.get("execution_status") == "EXECUTED":
            for label, prefix in (
                ("timeline", "timeline"),
                ("Attach inventory", "attach"),
                ("Diameter inventory", "diameter"),
            ):
                published_key = (
                    "timeline_row_count"
                    if prefix == "timeline"
                    else "attach_published_count"
                    if prefix == "attach"
                    else "diameter_published_count"
                )
                source_key = (
                    "timeline_source_row_count"
                    if prefix == "timeline"
                    else "attach_source_instance_count"
                    if prefix == "attach"
                    else "diameter_source_observation_count"
                )
                omitted_key = (
                    "timeline_rows_omitted"
                    if prefix == "timeline"
                    else "attach_instances_omitted"
                    if prefix == "attach"
                    else "diameter_observations_omitted"
                )
                producer_key = f"{omitted_key}_by_producer"
                projection_key = f"{omitted_key}_by_projection"
                conserved_key = f"{prefix}_accounting_conserved"
                lines.append(
                    f"    {label} accounting: published {_value(block.get(published_key))} of "
                    f"source {_value(block.get(source_key))} "
                    f"(producer omitted {_value(block.get(producer_key))}, "
                    f"projection omitted {_value(block.get(projection_key))}, "
                    f"total omitted {_value(block.get(omitted_key))}, "
                    f"conserved {_value(block.get(conserved_key))})"
                )
            if block.get("source_artifact"):
                lines.append(
                    f"    complete joint artifact: {_value(block.get('source_artifact'))}"
                )
        if block.get("failure_code"):
            lines.append(
                f"    failure [{_value(block.get('failure_stage'))}]: "
                f"{_value(block.get('failure_code'))} {_value(block.get('failure_message'))}"
            )
        for item in (block.get("attach_inventory") or [])[:MAX_LIST_ITEMS]:
            lines.append(
                f"    Attach {item.get('procedure_reference')}: "
                f"frames {_value(item.get('first_frame'))}-{_value(item.get('last_frame'))}, "
                f"status {_value(item.get('status'))}, deviations {_value(item.get('deviation_count'))}"
            )
        for item in (block.get("diameter_inventory") or [])[:MAX_LIST_ITEMS]:
            request = item.get("request") or {}
            answer = item.get("answer") or {}
            result_block = item.get("result") or {}
            lines.append(
                f"    Diameter {item.get('procedure')}: {item.get('transaction_status')}, "
                f"req {_value(request.get('frame_number'))}.{_value(request.get('message_occurrence'))}, "
                f"ans {_value(answer.get('frame_number'))}.{_value(answer.get('message_occurrence'))}, "
                f"result {_value(result_block.get('base_result_code') or result_block.get('experimental_result_code'))}, "
                f"latency {_value(item.get('latency_seconds'))}"
            )
        for row in (block.get("timeline") or [])[:MAX_LIST_ITEMS]:
            occurrence = "" if row.get("message_occurrence") is None else f".{row.get('message_occurrence')}"
            lines.append(
                f"    {row.get('frame_number')}{occurrence} {row.get('family')} "
                f"{row.get('event_type')} ({row.get('status')})"
            )
        lines.append(
            "    limitation: the shared timeline is ordering evidence only; no per-UE "
            "Attach/S6a association is established without reviewed identity evidence"
        )

    dedicated_blocks = [
        (result, result.get("dedicated_bearer_control"))
        for result in results
        if isinstance(result.get("dedicated_bearer_control"), dict)
    ]
    if dedicated_blocks:
        _section(lines, "EPC Dedicated Bearer Control")
    for result, block in dedicated_blocks:
        status = block.get("execution_status")
        lines.append(
            f"  {result['domain']}: {_value(status)}, "
            f"{_value(block.get('control_transaction_count'))} control transaction(s), "
            f"{_value(block.get('bearer_item_observation_count'))} bearer item(s), "
            f"{_value(block.get('item_association_count'))} item association(s)"
        )
        if status == "EXECUTED":
            families = block.get("transaction_family_counts") or {}
            lines.append(
                f"    transactions: create {_value(families.get('create-bearer'))}, "
                f"update {_value(families.get('update-bearer'))}, "
                f"delete {_value(families.get('delete-bearer'))}"
            )
            lines.append(
                f"    correlation: {json.dumps(block.get('correlation_status_counts') or {}, sort_keys=True)}"
            )
            lines.append(
                f"    message outcomes: {json.dumps(block.get('message_outcome_counts') or {}, sort_keys=True)}"
            )
            lines.append(
                f"    transaction outcomes: {json.dumps(block.get('transaction_outcome_counts') or {}, sort_keys=True)}"
            )
            lines.append(
                f"    item outcomes: {json.dumps(block.get('item_outcome_counts') or {}, sort_keys=True)}"
            )
            lines.append(
                f"    item associations: {json.dumps(block.get('item_association_status_counts') or {}, sort_keys=True)}"
            )
            omitted = block.get("omitted_counts") or {}
            lines.append(
                f"    source completeness {_value(block.get('source_completeness_status'))}; "
                f"omitted transactions {_value(omitted.get('control_transactions'))}, "
                f"items {_value(omitted.get('bearer_items'))}, "
                f"associations {_value(omitted.get('item_associations'))}"
            )
            for limitation in (block.get("evidence_limitations") or [])[:MAX_LIST_ITEMS]:
                lines.append(f"    limitation: {_value(limitation)}")
            lines.append(
                "    Observed GTPv2-C dedicated-bearer control outcomes do not prove "
                "end-to-end dedicated-bearer activation."
            )
        elif status == "FAILED":
            lines.append(
                f"    failure: {_value(block.get('failure_code'))} "
                f"{_value(block.get('failure_message'))}"
            )
        else:
            lines.append(
                "    no dedicated-bearer control transaction was observed in this capture; "
                "this is not a parser failure or fabricated success."
            )

    timeline_blocks = [
        (result, result.get("dedicated_bearer_timeline"))
        for result in results
        if isinstance(result.get("dedicated_bearer_timeline"), dict)
    ]
    if timeline_blocks:
        _section(lines, "EPC Dedicated Bearer Cross-Layer Timeline")
    for result, block in timeline_blocks:
        lines.append(
            f"  {result['domain']}: {_value(block.get('execution_status'))}, "
            f"{_value(block.get('entry_count'))} timeline entry(ies), "
            f"unresolved {_value(block.get('unresolved_evidence_count'))}"
        )
        if block.get("execution_status") == "EXECUTED":
            lines.append(
                f"    association statuses: {json.dumps(block.get('association_status_counts') or {}, sort_keys=True)}; "
                f"source completeness {_value(block.get('source_completeness_status'))} "
                f"(control {_value(block.get('control_source_completeness'))}, "
                f"NAS {_value(block.get('nas_input_status'))}, "
                f"S1AP {_value(block.get('s1ap_input_status'))}, "
                f"exhaustive {_value(block.get('exhaustive_coverage_proven'))})"
            )
            for entry in (block.get("entries") or [])[:MAX_DEDICATED_TIMELINE_ENTRIES]:
                lines.append(
                    f"    {_value(entry.get('procedure_family'))} "
                    f"{_value(entry.get('control_transaction_reference'))}: "
                    f"request frame {_value(entry.get('request_frame'))}, "
                    f"response frame {_value(entry.get('response_frame'))}, "
                    f"control outcome {_value(entry.get('message_outcome'))}, "
                    f"NAS {_value(entry.get('nas_esm_association_status'))}, "
                    f"S1AP {_value(entry.get('s1ap_erab_association_status'))}, "
                    f"cross-layer {_value(entry.get('cross_layer_association_status'))}, "
                    f"summary {_value(entry.get('cross_layer_relationship_summary'))}"
                )
                lines.append(
                    "      NAS-ESM: "
                    + (
                        ", ".join(
                            f"frame {_value(ref.get('frame_number'))} "
                            f"{_value(ref.get('result'))} EBI {_value(ref.get('eps_bearer_identity'))}"
                            for ref in entry.get("observed_nas_esm_references") or []
                        )
                        or "not observed"
                    )
                    + "; S1AP E-RAB: "
                    + (
                        ", ".join(
                            f"frame {_value(ref.get('frame_number'))} "
                            f"{_value(ref.get('operation'))} "
                            f"E-RAB {_value(ref.get('erab_id'))} "
                            f"{_value(ref.get('result'))}"
                            for ref in entry.get("observed_s1ap_erab_references") or []
                        )
                        or "not observed"
                    )
                )
                for basis in (entry.get("association_evidence_basis") or [])[:MAX_LIST_ITEMS]:
                    lines.append(f"      basis: {_value(basis)}")
                for limitation in (entry.get("limitations") or [])[:MAX_LIST_ITEMS]:
                    lines.append(f"      limitation: {_value(limitation)}")
                lines.append(
                    "      not confirmed: control-plane outcome and observed access signaling "
                    "do not prove UE acceptance, radio setup or user-plane delivery"
                )
        elif block.get("execution_status") == "FAILED":
            lines.append(
                f"    failure: {_value(block.get('failure_code'))} "
                f"{_value(block.get('failure_message'))}"
            )
        else:
            lines.append(
                "    timeline not evaluated because no dedicated-bearer control transaction "
                "was observed in this capture"
            )

    attribution_blocks = [
        (result, result.get("dedicated_bearer_attribution"))
        for result in results
        if isinstance(result.get("dedicated_bearer_attribution"), dict)
    ]
    if attribution_blocks:
        _section(lines, "EPC Control-to-Access Attribution Feasibility")
    for result, block in attribution_blocks:
        lines.append(
            f"  {result['domain']}: {_value(block.get('execution_status'))}, "
            f"{_value(block.get('entry_count'))} attribution entry(ies), "
            f"established-link counts {json.dumps(block.get('established_link_counts') or {}, sort_keys=True)}"
        )
        if block.get("execution_status") == "EXECUTED":
            lines.append(
                f"    control-to-session: {json.dumps(block.get('control_session_status_counts') or {}, sort_keys=True)}; "
                f"session-to-access: {json.dumps(block.get('session_access_status_counts') or {}, sort_keys=True)}"
            )
            lines.append(
                f"    NAS ownership: {json.dumps(block.get('nas_access_status_counts') or {}, sort_keys=True)}; "
                f"S1AP E-RAB: {json.dumps(block.get('s1ap_access_status_counts') or {}, sort_keys=True)}; "
                f"overall: {json.dumps(block.get('overall_status_counts') or {}, sort_keys=True)}"
            )
            for entry in (block.get("entries") or [])[:MAX_DEDICATED_TIMELINE_ENTRIES]:
                lines.append(
                    f"    {_value(entry.get('procedure_family'))} "
                    f"{_value(entry.get('control_transaction_reference'))}: "
                    f"frames {_value(entry.get('request_frame'))}/{_value(entry.get('response_frame'))}, "
                    f"control={_value(entry.get('control_outcome'))}"
                )
                lines.append(
                    f"      control-to-session {_value(entry.get('control_session_status'))} "
                    f"context={_value(entry.get('control_session_context'))} "
                    f"interface={_value(entry.get('control_session_interface'))}; "
                    f"session-to-access {_value(entry.get('session_access_status'))} "
                    f"related={_value(entry.get('session_access_related_contexts'))}"
                )
                lines.append(
                    f"      NAS ownership {_value(entry.get('nas_access_status'))} "
                    f"owner={_value(entry.get('nas_owner_s1ap_context'))}; "
                    f"S1AP E-RAB {_value(entry.get('s1ap_access_status'))} "
                    f"endpoint matches={_value(entry.get('s1ap_endpoint_matches'))}"
                )
                lines.append(
                    f"      overall {_value(entry.get('overall_status'))}; "
                    f"established links={_value(entry.get('established_links'))}"
                )
                for limiting in (entry.get("limiting_evidence") or [])[:MAX_LIST_ITEMS]:
                    lines.append(f"      limiting evidence: {_value(limiting)}")
                for needed in (entry.get("additional_evidence_needed") or [])[:MAX_LIST_ITEMS]:
                    lines.append(f"      additional evidence needed: {_value(needed)}")
                lines.append(
                    "      not confirmed: control Cause, endpoint equality or NAS ownership alone "
                    "does not prove a complete UE identity chain or user-plane delivery"
                )
        elif block.get("execution_status") == "FAILED":
            lines.append(
                f"    failure: {_value(block.get('failure_code'))} "
                f"{_value(block.get('failure_message'))}"
            )
        else:
            lines.append(
                "    attribution not evaluated because no dedicated-bearer control transaction "
                "was observed in this capture"
            )

    narrative_blocks = [
        (result, result.get("release_narrative"))
        for result in results
        if isinstance(result.get("release_narrative"), dict)
    ]
    if narrative_blocks:
        _section(lines, "Release Narrative and Temporal Evidence")
    for result, block in narrative_blocks:
        accounting = block.get("temporal_accounting") or {}
        lines.append(
            f"  {result['domain']}: {_value(block.get('release_narrative_count'))} release "
            f"narrative(s), {_value(block.get('narrative_subject_count'))} subject(s), "
            f"{_value(len(block.get('narrative_groups') or []))} narrative group(s), "
            f"source completeness {_value(block.get('source_completeness_status'))}"
        )
        for narrative in block.get("release_narratives") or []:
            lines.append(
                f"    {narrative.get('release_transaction_reference')} frames "
                f"{_value(narrative.get('release_request_frame'))}->"
                f"{_value(narrative.get('release_confirmation_frame'))}: "
                f"outcome {_value(narrative.get('release_outcome_status'))}, "
                f"binding {_value(narrative.get('release_session_binding_status'))}, "
                f"generation closure {_value(narrative.get('generation_closure_status'))}, "
                f"effective instant proved "
                f"{_value(narrative.get('release_effective_frame_proven'))}"
            )
        lines.append(
            f"    temporal: frame-level evidence "
            f"{_value(accounting.get('frame_level_evidence_supplied'))}, "
            f"{_value(accounting.get('assigned_to_release_window_count'))} of "
            f"{_value(accounting.get('observed_g_pdu_event_count'))} G-PDU event(s) assigned, "
            f"duplicates {_value(accounting.get('duplicate_assignment_count'))}, "
            f"conserved {_value(accounting.get('conserved'))}"
        )
        lines.append(
            "    boundary selection: NOT_APPLICABLE "
            "(a release narrative is not an abnormal failure boundary)"
        )

    audit_blocks = [
        (result, result.get("evidence_audit"))
        for result in results
        if isinstance(result.get("evidence_audit"), dict)
    ]
    if audit_blocks:
        _section(lines, "Evidence Audit Ledger")
    for result, block in audit_blocks:
        references = block.get("reference_integrity") or {}
        temporal = block.get("temporal_integrity") or {}
        accounting = block.get("accounting_integrity") or {}
        lines.append(
            f"  {result['domain']}: {_value(block.get('overall_status'))}, "
            f"{_value(block.get('audit_record_count'))} audit record(s), source completeness "
            f"{_value(block.get('source_completeness_status'))}, "
            f"{_value(block.get('unresolved_audit_finding_count'))} unresolved finding(s)"
        )
        lines.append(
            f"    references: {_value(references.get('references_checked'))} checked, "
            f"{_value(references.get('references_resolved'))} resolved, "
            f"{_value(references.get('references_missing'))} missing, "
            f"{_value(references.get('references_ambiguous'))} ambiguous, "
            f"{_value(references.get('references_contradictory'))} contradictory"
        )
        lines.append(
            f"    captures cross-capture rejections "
            f"{_value((block.get('capture_scope') or {}).get('cross_capture_rejections'))}, "
            f"value collisions kept separate "
            f"{_value((block.get('capture_scope') or {}).get('cross_capture_value_collisions'))}; "
            f"temporal verified placements "
            f"{_value(temporal.get('audit_verified_placement_count'))}, missing frame evidence "
            f"{_value(temporal.get('missing_frame_evidence_count'))}"
        )
        lines.append(
            f"    accounting: producer counts unchanged "
            f"{_value(accounting.get('producer_counts_unchanged'))}, audit-derived "
            f"{_value(accounting.get('audit_derived_g_pdu_count'))} G-PDU / "
            f"{_value(accounting.get('audit_derived_payload_octets'))} payload octets, "
            f"{_value(accounting.get('accounting_records_inconsistent'))} inconsistent record(s)"
        )
        for finding in (block.get("unresolved_audit_findings") or [])[:MAX_LIST_ITEMS]:
            lines.append(
                f"    finding {finding.get('audit_status')} "
                f"{finding.get('audit_category')} {finding.get('audit_record_reference')}: "
                f"{_value(finding.get('limitation'))}"
            )
        lines.append(
            "    boundary selection: NOT_APPLICABLE "
            "(an audit finding is not an abnormal failure boundary)"
        )

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
                "invocation produced no result. IMS remains a bounded evidence path even "
                "when a SIP, Diameter or IMS component fails in this invocation."
            ),
        },
    }


DomainAdapter = Callable[[Path, Path, str, dict[str, Any], set[str]], dict[str, Any]]


def _run_component(
    command: list[str],
    label: str,
    allow_empty: bool = False,
    empty_exit_codes: tuple[int, ...] = (6,),
) -> bool:
    """Run one accepted component; return False only for a legitimate empty result."""
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise AnalysisError("COMPONENT_UNAVAILABLE", f"{label} could not start: {exc}") from exc
    if completed.returncode == 0:
        return True
    if allow_empty and completed.returncode in empty_exit_codes:
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


def _require_component_artifact(path: Path, label: str, failure_code: str) -> None:
    """Fail closed when a component reports success but publishes no artifact."""
    if not path.is_file():
        raise AnalysisError(
            failure_code, f"{label} reported success but produced no output artifact"
        )


def _read_component_artifact(
    path: Path, label: str, failure_code: str
) -> dict[str, Any]:
    """Read a component artifact; a missing or unreadable result is a failure."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisError(
            failure_code, f"{label} output is unreadable: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise AnalysisError(failure_code, f"{label} output is not an object")
    return payload


def _count_component_events(path: Path, label: str, failure_code: str) -> int:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError as exc:
        raise AnalysisError(
            failure_code, f"{label} event artifact is unreadable: {exc}"
        ) from exc


def _run_named_stage(
    command: list[str],
    label: str,
    failure_code: str,
    *,
    allow_empty: bool = False,
) -> bool:
    """Run a component and preserve the responsible stage in a failure code."""
    try:
        return _run_component(
            command,
            label,
            allow_empty=allow_empty,
            empty_exit_codes=(3,) if allow_empty else (),
        )
    except AnalysisError as exc:
        raise AnalysisError(failure_code, exc.message) from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _attach_s6a_run_manifest(
    run_dir: Path,
    capture: Path,
    attach_path: Path,
    diameter_path: Path,
) -> dict[str, Any]:
    """Record the controlled producer invocations that generated the joint evidence."""
    capture_digest = _sha256_file(capture)
    return {
        "manifest_name": ATTACH_S6A_MANIFEST_NAME,
        "manifest_schema_version": ATTACH_S6A_MANIFEST_SCHEMA_VERSION,
        "coordinated_run_id": run_dir.name,
        "capture": {"file": capture.name, "sha256": capture_digest},
        "artifacts": {
            "attach": {
                "file": attach_path.name,
                "sha256": _sha256_file(attach_path),
                "producer": "epc-attach-analysis",
            },
            "diameter_epc": {
                "file": diameter_path.name,
                "sha256": _sha256_file(diameter_path),
                "producer": "diameter-epc-analysis",
            },
        },
        "producers": {
            "attach": "epc-attach-analysis",
            "diameter_core": "diameter-core-extraction",
            "diameter_epc": "diameter-epc-analysis",
        },
        "executed_invocations": [
            {"producer": "diameter-core-extraction", "capture_sha256": capture_digest},
            {"producer": "diameter-core-correlation", "capture_sha256": capture_digest},
            {"producer": "diameter-epc-analysis", "capture_sha256": capture_digest},
            {"producer": "epc-attach-analysis", "capture_sha256": capture_digest},
        ],
        "accepted_source_contracts": {
            "attach": {"domain": "epc-procedures", "model_version": "1.0.0"},
            "diameter_epc": {"analysis_name": "diameter-epc", "analysis_version": "1.0.0"},
        },
    }


def _dedicated_bearer_transaction_counts(path: Path) -> dict[str, int]:
    """Count accepted dedicated-bearer transaction families without re-correlating."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisError(
            "PIPELINE_OUTPUT_UNREADABLE", f"GTPv2-C correlation is unreadable: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise AnalysisError("PIPELINE_OUTPUT_UNREADABLE", "GTPv2-C correlation is not an object")
    counts = {family: 0 for family in DEDICATED_BEARER_FAMILIES}
    for transaction in payload.get("transactions") or []:
        if not isinstance(transaction, dict):
            continue
        family = transaction.get("procedure_family")
        if family in counts:
            counts[family] += 1
    return counts


def _dedicated_bearer_requested(counts: dict[str, int]) -> bool:
    return any(counts.get(family, 0) > 0 for family in DEDICATED_BEARER_FAMILIES)


_DEDICATED_BEARER_CONTRACT: Any = None


def _load_dedicated_bearer_contract():
    global _DEDICATED_BEARER_CONTRACT
    if _DEDICATED_BEARER_CONTRACT is None:
        spec = importlib.util.spec_from_file_location(
            "corenet_epc_dedicated_bearer_contract",
            EPC_DEDICATED_BEARER_CONTRACT_SCRIPT,
        )
        if spec is None or spec.loader is None:
            raise AnalysisError(
                "COMPONENT_UNAVAILABLE",
                "the Dedicated Bearer artifact contract validator is unavailable",
            )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            raise AnalysisError(
                "COMPONENT_UNAVAILABLE",
                f"the Dedicated Bearer artifact contract validator could not load: {exc}",
            ) from exc
        _DEDICATED_BEARER_CONTRACT = module
    return _DEDICATED_BEARER_CONTRACT


def _validate_dedicated_bearer_artifact(analysis: dict[str, Any]) -> None:
    """Enforce the complete accepted Domain output contract before publication."""
    contract = _load_dedicated_bearer_contract()
    try:
        contract.validate_artifact(analysis)
    except contract.ContractValidationError as exc:
        raise AnalysisError(
            DEDICATED_BEARER_FAILURE_CODE,
            f"EPC dedicated-bearer control analysis artifact is invalid: {exc.code}: {exc.message}",
        ) from exc


def _run_dedicated_bearer_stage(
    gtpv2_events: Path,
    gtpv2_transactions: Path,
    output: Path,
    session_identity: Path | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Invoke the accepted Domain CLI and validate its published artifact."""
    command = [
        sys.executable,
        str(EPC_DEDICATED_BEARER_ANALYZE_SCRIPT),
        "--gtpv2",
        str(gtpv2_events),
        "--transactions",
        str(gtpv2_transactions),
        "--output",
        str(output),
        "--force",
    ]
    if session_identity is not None and session_identity.is_file():
        command.extend(["--session-identity", str(session_identity)])
    try:
        _run_component(command, "EPC dedicated-bearer control analysis")
        if not output.is_file():
            raise AnalysisError(
                "PIPELINE_OUTPUT_MISSING",
                "EPC dedicated-bearer control analysis produced no artifact",
            )
        analysis = json.loads(output.read_text(encoding="utf-8"))
        if not isinstance(analysis, dict):
            raise AnalysisError(
                "PIPELINE_OUTPUT_UNREADABLE",
                "EPC dedicated-bearer control analysis is not an object",
            )
        if analysis.get("analysis_name") != "epc-dedicated-bearer-control":
            raise AnalysisError(
                "PIPELINE_OUTPUT_UNREADABLE",
                "EPC dedicated-bearer control analysis has an incompatible analysis name",
            )
        _validate_dedicated_bearer_artifact(analysis)
        if not isinstance(analysis.get("control_transaction_count"), int):
            raise AnalysisError(
                "PIPELINE_OUTPUT_UNREADABLE",
                "EPC dedicated-bearer control analysis has no bounded transaction count",
            )
        if analysis["control_transaction_count"] <= 0:
            raise AnalysisError(
                DEDICATED_BEARER_FAILURE_CODE,
                "relevant dedicated-bearer transactions were present but the Domain Producer published no control transaction",
            )
        return analysis, None
    except (AnalysisError, OSError, json.JSONDecodeError) as exc:
        return None, {
            "code": DEDICATED_BEARER_FAILURE_CODE,
            "message": scrub_free_text(str(exc)),
        }


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _count_values(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = item.get(key)
        if isinstance(value, str):
            counts[value] = counts.get(value, 0) + 1
    return {name: counts[name] for name in sorted(counts)}


def _strict_nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None


_TIMELINE_CONTRACT: Any = None


def _load_timeline_contract():
    global _TIMELINE_CONTRACT
    if _TIMELINE_CONTRACT is None:
        spec = importlib.util.spec_from_file_location(
            "corenet_epc_dedicated_bearer_timeline_contract",
            EPC_DEDICATED_BEARER_TIMELINE_CONTRACT_SCRIPT,
        )
        if spec is None or spec.loader is None:
            raise AnalysisError(
                "COMPONENT_UNAVAILABLE",
                "the Dedicated Bearer timeline contract validator is unavailable",
            )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            raise AnalysisError(
                "COMPONENT_UNAVAILABLE",
                f"the Dedicated Bearer timeline contract validator could not load: {exc}",
            ) from exc
        _TIMELINE_CONTRACT = module
    return _TIMELINE_CONTRACT


def _validate_timeline_artifact(analysis: dict[str, Any]) -> None:
    contract = _load_timeline_contract()
    try:
        contract.validate_artifact(analysis)
    except contract.ContractValidationError as exc:
        raise AnalysisError(
            DEDICATED_BEARER_TIMELINE_FAILURE_CODE,
            f"EPC dedicated-bearer timeline artifact is invalid: {exc.code}: {exc.message}",
        ) from exc


def _run_dedicated_bearer_timeline_stage(
    control: Path,
    nas_events: Path,
    s1ap_events: Path,
    output: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    command = [
        sys.executable,
        str(EPC_DEDICATED_BEARER_TIMELINE_SCRIPT),
        "--control",
        str(control),
        "--nas-events",
        str(nas_events),
        "--s1ap-events",
        str(s1ap_events),
        "--output",
        str(output),
        "--force",
    ]
    try:
        _run_component(command, "EPC dedicated-bearer timeline")
        if not output.is_file():
            raise AnalysisError(
                "PIPELINE_OUTPUT_MISSING",
                "EPC dedicated-bearer timeline produced no artifact",
            )
        analysis = json.loads(output.read_text(encoding="utf-8"))
        if not isinstance(analysis, dict):
            raise AnalysisError(
                "PIPELINE_OUTPUT_UNREADABLE",
                "EPC dedicated-bearer timeline is not an object",
            )
        if analysis.get("analysis_name") != "epc-dedicated-bearer-timeline":
            raise AnalysisError(
                "PIPELINE_OUTPUT_UNREADABLE",
                "EPC dedicated-bearer timeline has an incompatible analysis name",
            )
        _validate_timeline_artifact(analysis)
        if not isinstance(analysis.get("timeline_entry_count"), int):
            raise AnalysisError(
                "PIPELINE_OUTPUT_UNREADABLE",
                "EPC dedicated-bearer timeline has no bounded entry count",
            )
        return analysis, None
    except (AnalysisError, OSError, json.JSONDecodeError) as exc:
        return None, {
            "code": DEDICATED_BEARER_TIMELINE_FAILURE_CODE,
            "message": scrub_free_text(str(exc)),
        }


_ATTRIBUTION_CONTRACT: Any = None


def _load_attribution_contract():
    global _ATTRIBUTION_CONTRACT
    if _ATTRIBUTION_CONTRACT is None:
        spec = importlib.util.spec_from_file_location(
            "corenet_epc_dedicated_bearer_attribution_contract",
            EPC_DEDICATED_BEARER_ATTRIBUTION_CONTRACT_SCRIPT,
        )
        if spec is None or spec.loader is None:
            raise AnalysisError(
                "COMPONENT_UNAVAILABLE",
                "the Dedicated Bearer attribution contract validator is unavailable",
            )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            raise AnalysisError(
                "COMPONENT_UNAVAILABLE",
                f"the Dedicated Bearer attribution contract validator could not load: {exc}",
            ) from exc
        _ATTRIBUTION_CONTRACT = module
    return _ATTRIBUTION_CONTRACT


def _validate_attribution_artifact(analysis: dict[str, Any]) -> None:
    contract = _load_attribution_contract()
    try:
        contract.validate_artifact(analysis)
    except contract.ContractValidationError as exc:
        raise AnalysisError(
            DEDICATED_BEARER_ATTRIBUTION_FAILURE_CODE,
            f"EPC dedicated-bearer attribution artifact is invalid: {exc.code}: {exc.message}",
        ) from exc


def _run_dedicated_bearer_attribution_stage(
    control: Path,
    identity: Path,
    gtpv2_events: Path,
    nas_events: Path,
    s1ap_events: Path,
    output: Path,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    command = [
        sys.executable,
        str(EPC_DEDICATED_BEARER_ATTRIBUTION_SCRIPT),
        "--control",
        str(control),
        "--session-identity",
        str(identity),
        "--gtpv2-events",
        str(gtpv2_events),
        "--nas-events",
        str(nas_events),
        "--s1ap-events",
        str(s1ap_events),
        "--output",
        str(output),
        "--force",
    ]
    try:
        _run_component(command, "EPC dedicated-bearer attribution")
        if not output.is_file():
            raise AnalysisError(
                "PIPELINE_OUTPUT_MISSING",
                "EPC dedicated-bearer attribution produced no artifact",
            )
        analysis = json.loads(output.read_text(encoding="utf-8"))
        if not isinstance(analysis, dict):
            raise AnalysisError(
                "PIPELINE_OUTPUT_UNREADABLE",
                "EPC dedicated-bearer attribution is not an object",
            )
        if analysis.get("analysis_name") != "epc-dedicated-bearer-attribution":
            raise AnalysisError(
                "PIPELINE_OUTPUT_UNREADABLE",
                "EPC dedicated-bearer attribution has an incompatible analysis name",
            )
        _validate_attribution_artifact(analysis)
        if not isinstance(analysis.get("attribution_entry_count"), int):
            raise AnalysisError(
                "PIPELINE_OUTPUT_UNREADABLE",
                "EPC dedicated-bearer attribution has no bounded entry count",
            )
        return analysis, None
    except (AnalysisError, OSError, json.JSONDecodeError) as exc:
        return None, {
            "code": DEDICATED_BEARER_ATTRIBUTION_FAILURE_CODE,
            "message": scrub_free_text(str(exc)),
        }


def _dedicated_declared_total(
    analysis: dict[str, Any], key: str, published: list[dict[str, Any]]
) -> int:
    declared = _strict_nonnegative_int(analysis.get(key))
    return declared if declared is not None else len(published)


def _producer_outcome_counts(
    analysis: dict[str, Any], key: str
) -> dict[str, int] | None:
    summary = analysis.get("outcome_summary")
    if not isinstance(summary, dict):
        return None
    raw = summary.get(key)
    if not isinstance(raw, dict):
        return None
    counts: dict[str, int] = {}
    for name, value in raw.items():
        if not isinstance(name, str):
            return None
        strict = _strict_nonnegative_int(value)
        if strict is None:
            return None
        counts[name] = strict
    return {name: counts[name] for name in sorted(counts)}


def _non_negative_count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _collection_accounting(
    source_total: int,
    producer_published: int,
    published: int,
    producer_omitted: int,
) -> dict[str, Any]:
    """Publish one conservation model for a bounded collection.

    total_source_records = published_records
                         + records_omitted_by_producer
                         + records_omitted_by_projection
    """
    projection_omitted = max(0, producer_published - published)
    total_omitted = producer_omitted + projection_omitted
    return {
        "source_total": source_total,
        "producer_published": producer_published,
        "published": published,
        "omitted_by_producer": producer_omitted,
        "omitted_by_projection": projection_omitted,
        "omitted_total": total_omitted,
        "conserved": published + total_omitted == source_total,
    }


def _project_attach_s6a(
    joint: Any,
    diameter_status: Any,
    error: Any,
    diameter_event_count: int,
    diameter_observation_count: int,
) -> dict[str, Any]:
    """Project bounded joint Attach/S6a evidence without inventing identity."""
    status = diameter_status if isinstance(diameter_status, str) else "NOT_OBSERVED_IN_CAPTURE"
    payload: dict[str, Any] = {
        "execution_status": (
            "EXECUTED"
            if isinstance(joint, dict) and status == "EXECUTED"
            else "FAILED"
            if isinstance(error, dict) or status == "COMPONENT_FAILED"
            else status
        ),
        "analysis_status": status,
        "diameter_event_count": max(0, diameter_event_count),
        "diameter_observation_count": max(0, diameter_observation_count),
        "attach_instance_count": 0,
        "attach_source_instance_count": 0,
        "attach_published_count": 0,
        "attach_instances_omitted": 0,
        "attach_instances_omitted_by_producer": 0,
        "attach_instances_omitted_by_projection": 0,
        "attach_accounting_conserved": True,
        "attach_incomplete_instance_count": 0,
        "diameter_matched_count": 0,
        "diameter_failure_reported_count": 0,
        "diameter_open_or_ambiguous_count": 0,
        "diameter_source_observation_count": 0,
        "diameter_published_count": 0,
        "diameter_observations_omitted": 0,
        "diameter_observations_omitted_by_producer": 0,
        "diameter_observations_omitted_by_projection": 0,
        "diameter_accounting_conserved": True,
        "identity_association_status": "NOT_APPLICABLE",
        "common_capture_status": None,
        "common_capture_artifacts_bound": False,
        "run_manifest_present": False,
        "source_artifact": None,
        "timeline_ordering": None,
        "timeline_row_count": 0,
        "timeline_source_row_count": 0,
        "timeline_producer_published_count": 0,
        "timeline_rows_omitted": 0,
        "timeline_rows_omitted_by_producer": 0,
        "timeline_rows_omitted_by_projection": 0,
        "timeline_accounting_conserved": True,
        "cross_protocol_attribution_established": False,
        "root_cause_inferred": False,
        "attach_inventory": [],
        "diameter_inventory": [],
        "timeline": [],
        "limitations": [],
        "not_confirmed": [],
    }
    if isinstance(error, dict):
        payload["failure_code"] = error.get("code")
        payload["failure_stage"] = error.get("stage") or error.get("code")
        payload["failure_message"] = error.get("message")
    if not isinstance(joint, dict):
        return payload
    provenance = _dict(joint.get("input_provenance"))
    common_capture = _dict(provenance.get("common_capture"))
    diagnostics = _dict(joint.get("diagnostics"))
    association = _dict(joint.get("identity_association"))
    attach_inventory = _list(joint.get("attach_inventory"))
    diameter_inventory = _list(joint.get("diameter_inventory"))
    timeline = _list(joint.get("timeline"))
    published_attach = attach_inventory[:MAX_LIST_ITEMS]
    published_diameter = diameter_inventory[:MAX_LIST_ITEMS]
    published_timeline = timeline[:MAX_LIST_ITEMS]
    attach_accounting = _collection_accounting(
        len(attach_inventory) + _non_negative_count(joint.get("attach_instances_omitted")),
        len(attach_inventory),
        len(published_attach),
        _non_negative_count(joint.get("attach_instances_omitted")),
    )
    diameter_accounting = _collection_accounting(
        len(diameter_inventory)
        + _non_negative_count(joint.get("diameter_observations_omitted")),
        len(diameter_inventory),
        len(published_diameter),
        _non_negative_count(joint.get("diameter_observations_omitted")),
    )
    timeline_accounting = _collection_accounting(
        len(timeline) + _non_negative_count(joint.get("timeline_rows_omitted")),
        len(timeline),
        len(published_timeline),
        _non_negative_count(joint.get("timeline_rows_omitted")),
    )
    payload.update(
        {
            "attach_instance_count": len(attach_inventory),
            "attach_source_instance_count": attach_accounting["source_total"],
            "attach_published_count": attach_accounting["published"],
            "attach_instances_omitted": attach_accounting["omitted_total"],
            "attach_instances_omitted_by_producer": attach_accounting["omitted_by_producer"],
            "attach_instances_omitted_by_projection": attach_accounting["omitted_by_projection"],
            "attach_accounting_conserved": attach_accounting["conserved"],
            "attach_incomplete_instance_count": diagnostics.get(
                "attach_incomplete_instance_count", 0
            ),
            "diameter_matched_count": diagnostics.get("diameter_matched_count", 0),
            "diameter_failure_reported_count": diagnostics.get(
                "diameter_failure_reported_count", 0
            ),
            "diameter_open_or_ambiguous_count": diagnostics.get(
                "diameter_open_or_ambiguous_count", 0
            ),
            "diameter_source_observation_count": diameter_accounting["source_total"],
            "diameter_published_count": diameter_accounting["published"],
            "diameter_observations_omitted": diameter_accounting["omitted_total"],
            "diameter_observations_omitted_by_producer": diameter_accounting[
                "omitted_by_producer"
            ],
            "diameter_observations_omitted_by_projection": diameter_accounting[
                "omitted_by_projection"
            ],
            "diameter_accounting_conserved": diameter_accounting["conserved"],
            "identity_association_status": association.get("status"),
            "common_capture_status": common_capture.get("status"),
            "common_capture_artifacts_bound": bool(
                common_capture.get("artifacts_bound_to_capture")
            ),
            "run_manifest_present": isinstance(common_capture.get("coordinated_run"), dict),
            "source_artifact": "epc-attach-s6a-analysis.json",
            "timeline_ordering": joint.get("timeline_ordering"),
            "timeline_row_count": timeline_accounting["published"],
            "timeline_source_row_count": timeline_accounting["source_total"],
            "timeline_producer_published_count": timeline_accounting["producer_published"],
            "timeline_rows_omitted": timeline_accounting["omitted_total"],
            "timeline_rows_omitted_by_producer": timeline_accounting["omitted_by_producer"],
            "timeline_rows_omitted_by_projection": timeline_accounting["omitted_by_projection"],
            "timeline_accounting_conserved": timeline_accounting["conserved"],
            "cross_protocol_attribution_established": bool(
                diagnostics.get("cross_protocol_attribution_established")
            ),
            "root_cause_inferred": bool(diagnostics.get("root_cause_inferred")),
            "attach_inventory": published_attach,
            "diameter_inventory": published_diameter,
            "timeline": published_timeline,
            "limitations": _list(joint.get("limitations"))[:MAX_LIST_ITEMS],
            "not_confirmed": _list(joint.get("not_confirmed"))[:MAX_LIST_ITEMS],
        }
    )
    return payload


def _project_dedicated_bearer_control(
    analysis: dict[str, Any] | None,
    error: dict[str, Any] | None,
) -> dict[str, Any]:
    """Publish the Producer-declared totals and explicitly labelled breakdowns."""
    if isinstance(analysis, dict):
        transactions = [
            item for item in analysis.get("control_transactions") or [] if isinstance(item, dict)
        ]
        items = [
            item
            for item in analysis.get("bearer_item_observations") or []
            if isinstance(item, dict)
        ]
        associations = [
            item for item in analysis.get("item_associations") or [] if isinstance(item, dict)
        ]
        family_counts = {family: 0 for family in DEDICATED_BEARER_FAMILIES}
        for transaction in transactions:
            family = transaction.get("procedure_family")
            if family in family_counts:
                family_counts[family] += 1
        completeness = analysis.get("source_completeness") or {}

        transaction_outcome_counts = _producer_outcome_counts(
            analysis, "transaction_classification_counts"
        )
        message_outcome_counts = _producer_outcome_counts(analysis, "message_outcome_counts")
        item_outcome_counts = _producer_outcome_counts(analysis, "item_outcome_counts")
        association_status_counts = _producer_outcome_counts(
            analysis, "item_association_status_counts"
        )
        outcome_counts_basis = {
            "transaction_outcome_counts": (
                "SOURCE_DECLARED"
                if transaction_outcome_counts is not None
                else "VISIBLE_SUBSET_ONLY"
            ),
            "message_outcome_counts": (
                "SOURCE_DECLARED"
                if message_outcome_counts is not None
                else "VISIBLE_SUBSET_ONLY"
            ),
            "item_outcome_counts": (
                "SOURCE_DECLARED" if item_outcome_counts is not None else "VISIBLE_SUBSET_ONLY"
            ),
            "item_association_status_counts": (
                "SOURCE_DECLARED"
                if association_status_counts is not None
                else "VISIBLE_SUBSET_ONLY"
            ),
            "transaction_family_counts": "VISIBLE_SUBSET_ONLY",
            "correlation_status_counts": "VISIBLE_SUBSET_ONLY",
        }
        visible_subset_only = [
            name for name, basis in outcome_counts_basis.items() if basis == "VISIBLE_SUBSET_ONLY"
        ]
        return {
            "execution_status": "EXECUTED",
            "source_artifact": "epc-dedicated-bearer-control-analysis.json",
            "analysis_name": analysis.get("analysis_name"),
            "analysis_version": analysis.get("analysis_version"),
            "control_transaction_count": _dedicated_declared_total(
                analysis, "control_transaction_count", transactions
            ),
            "bearer_item_observation_count": _dedicated_declared_total(
                analysis, "bearer_item_observation_count", items
            ),
            "item_association_count": _dedicated_declared_total(
                analysis, "item_association_count", associations
            ),
            "producer_published_counts": {
                "control_transactions": len(transactions),
                "bearer_items": len(items),
                "item_associations": len(associations),
            },
            "transaction_family_counts": family_counts,
            "correlation_status_counts": _count_values(transactions, "correlation_status"),
            "transaction_outcome_counts": (
                transaction_outcome_counts
                if transaction_outcome_counts is not None
                else _count_values(transactions, "transaction_outcome")
            ),
            "message_outcome_counts": (
                message_outcome_counts
                if message_outcome_counts is not None
                else _count_values(
                    [item.get("message_outcome") or {} for item in transactions], "status"
                )
            ),
            "item_outcome_counts": (
                item_outcome_counts
                if item_outcome_counts is not None
                else _count_values(items, "item_outcome")
            ),
            "item_association_status_counts": (
                association_status_counts
                if association_status_counts is not None
                else _count_values(associations, "status")
            ),
            "outcome_counts_basis": outcome_counts_basis,
            "visible_subset_only_breakdowns": sorted(visible_subset_only),
            "source_completeness_status": completeness.get("status"),
            "exhaustive_coverage_proven": completeness.get("exhaustive_coverage_proven"),
            "omitted_counts": {
                "control_transactions": analysis.get("control_transactions_omitted", 0),
                "bearer_items": analysis.get("bearer_item_observations_omitted", 0),
                "item_associations": analysis.get("item_associations_omitted", 0),
            },
            "evidence_limitations": (
                analysis.get("evidence_limitations") or []
            )[:MAX_LIST_ITEMS],
            "not_confirmed": (analysis.get("not_confirmed") or [])[:MAX_LIST_ITEMS],
            "failure_code": None,
        }
    if isinstance(error, dict):
        return {
            "execution_status": "FAILED",
            "source_artifact": None,
            "analysis_name": None,
            "analysis_version": None,
            "control_transaction_count": 0,
            "bearer_item_observation_count": 0,
            "item_association_count": 0,
            "producer_published_counts": {
                "control_transactions": 0,
                "bearer_items": 0,
                "item_associations": 0,
            },
            "transaction_family_counts": {family: 0 for family in DEDICATED_BEARER_FAMILIES},
            "correlation_status_counts": {},
            "transaction_outcome_counts": {},
            "message_outcome_counts": {},
            "item_outcome_counts": {},
            "item_association_status_counts": {},
            "outcome_counts_basis": {},
            "visible_subset_only_breakdowns": [],
            "source_completeness_status": None,
            "exhaustive_coverage_proven": None,
            "omitted_counts": {
                "control_transactions": 0,
                "bearer_items": 0,
                "item_associations": 0,
            },
            "evidence_limitations": [],
            "not_confirmed": [],
            "failure_code": error.get("code", DEDICATED_BEARER_FAILURE_CODE),
            "failure_message": scrub_free_text(error.get("message")),
        }
    return {
        "execution_status": DEDICATED_BEARER_NOT_OBSERVED,
        "source_artifact": None,
        "analysis_name": None,
        "analysis_version": None,
        "control_transaction_count": 0,
        "bearer_item_observation_count": 0,
        "item_association_count": 0,
        "producer_published_counts": {
            "control_transactions": 0,
            "bearer_items": 0,
            "item_associations": 0,
        },
        "transaction_family_counts": {family: 0 for family in DEDICATED_BEARER_FAMILIES},
        "correlation_status_counts": {},
        "transaction_outcome_counts": {},
        "message_outcome_counts": {},
        "item_outcome_counts": {},
        "item_association_status_counts": {},
        "outcome_counts_basis": {},
        "visible_subset_only_breakdowns": [],
        "source_completeness_status": None,
        "exhaustive_coverage_proven": None,
        "omitted_counts": {
            "control_transactions": 0,
            "bearer_items": 0,
            "item_associations": 0,
        },
        "evidence_limitations": [],
        "not_confirmed": [],
        "failure_code": None,
    }


def _project_dedicated_bearer_timeline(
    analysis: dict[str, Any] | None,
    error: dict[str, Any] | None,
) -> dict[str, Any]:
    if isinstance(analysis, dict):
        entries = [
            item for item in analysis.get("timeline_entries") or [] if isinstance(item, dict)
        ]
        projected: list[dict[str, Any]] = []
        for item in entries[:MAX_DEDICATED_TIMELINE_ENTRIES]:
            nas = [
                ref
                for ref in item.get("observed_nas_esm_references") or []
                if isinstance(ref, dict)
            ][:MAX_LIST_ITEMS]
            s1ap_refs = [
                ref
                for ref in item.get("observed_s1ap_erab_references") or []
                if isinstance(ref, dict)
            ][:MAX_LIST_ITEMS]
            projected.append(
                {
                    "entry_reference": item.get("entry_reference"),
                    "control_transaction_reference": item.get("control_transaction_reference"),
                    "procedure_family": item.get("procedure_family"),
                    "request_frame": item.get("request_frame"),
                    "response_frame": item.get("response_frame"),
                    "correlation_status": item.get("correlation_status"),
                    "message_outcome": item.get("message_outcome"),
                    "bearer_item_outcome_summary": item.get(
                        "bearer_item_outcome_summary", {}
                    ),
                    "nas_esm_association_status": _dict(item.get("nas_esm_association")).get(
                        "status"
                    ),
                    "s1ap_erab_association_status": _dict(
                        item.get("s1ap_erab_association")
                    ).get("status"),
                    "cross_layer_association_status": item.get(
                        "cross_layer_association_status"
                    ),
                    "cross_layer_relationship_summary": item.get(
                        "cross_layer_relationship_summary"
                    ),
                    "association_evidence_basis": item.get("association_evidence_basis", [])[
                        :MAX_LIST_ITEMS
                    ],
                    "observed_nas_esm_references": [
                        {
                            "reference": ref.get("reference"),
                            "frame_number": ref.get("frame_number"),
                            "result": ref.get("result"),
                            "eps_bearer_identity": ref.get("eps_bearer_identity"),
                            "support_status": ref.get("support_status"),
                            "protection_state": ref.get("protection_state"),
                            "ue_context_reference": ref.get("ue_context_reference"),
                        }
                        for ref in nas
                    ],
                    "observed_s1ap_erab_references": [
                        {
                            "reference": ref.get("reference"),
                            "frame_number": ref.get("frame_number"),
                            "operation": ref.get("operation"),
                            "result": ref.get("result"),
                            "erab_id": ref.get("erab_id"),
                            "ue_context_reference": ref.get("ue_context_reference"),
                        }
                        for ref in s1ap_refs
                    ],
                    "source_completeness_status": item.get("source_completeness_status"),
                    "limitations": item.get("limitations", [])[:MAX_LIST_ITEMS],
                    "not_confirmed": item.get("not_confirmed", [])[:MAX_LIST_ITEMS],
                }
            )
        return {
            "execution_status": analysis.get("execution_status"),
            "source_artifact": "epc-dedicated-bearer-timeline-analysis.json",
            "entry_count": analysis.get("timeline_entry_count", 0),
            "omitted_entry_count": analysis.get("timeline_entries_omitted", 0),
            "association_status_counts": analysis.get("association_status_counts", {}),
            "unresolved_evidence_count": len(analysis.get("unresolved_evidence") or []),
            "source_completeness_status": _dict(analysis.get("source_completeness")).get(
                "status"
            ),
            "control_source_completeness": _dict(
                analysis.get("source_completeness")
            ).get("control_source_completeness"),
            "nas_input_status": _dict(analysis.get("source_completeness")).get(
                "nas_input_status"
            ),
            "s1ap_input_status": _dict(analysis.get("source_completeness")).get(
                "s1ap_input_status"
            ),
            "exhaustive_coverage_proven": _dict(
                analysis.get("source_completeness")
            ).get("exhaustive_coverage_proven"),
            "entries": projected,
            "not_confirmed": analysis.get("not_confirmed", [])[:MAX_LIST_ITEMS],
            "failure_code": None,
        }
    if error:
        return {
            "execution_status": "FAILED",
            "source_artifact": None,
            "entry_count": 0,
            "omitted_entry_count": 0,
            "association_status_counts": {},
            "unresolved_evidence_count": 0,
            "source_completeness_status": None,
            "entries": [],
            "not_confirmed": [],
            "failure_code": error.get("code", DEDICATED_BEARER_TIMELINE_FAILURE_CODE),
            "failure_message": scrub_free_text(error.get("message")),
        }
    return {
        "execution_status": "NOT_EVALUATED",
        "source_artifact": None,
        "entry_count": 0,
        "omitted_entry_count": 0,
        "association_status_counts": {},
        "unresolved_evidence_count": 0,
        "source_completeness_status": None,
        "entries": [],
        "not_confirmed": [],
        "failure_code": None,
    }


def _project_dedicated_bearer_attribution(
    analysis: dict[str, Any] | None,
    error: dict[str, Any] | None,
) -> dict[str, Any]:
    if isinstance(analysis, dict):
        entries = [
            item
            for item in analysis.get("attribution_entries") or []
            if isinstance(item, dict)
        ]
        projected = []
        for entry in entries[:MAX_DEDICATED_TIMELINE_ENTRIES]:
            control_session = _dict(entry.get("control_session"))
            session_access = _dict(entry.get("session_access"))
            nas_access = _dict(entry.get("nas_access"))
            s1ap_access = _dict(entry.get("s1ap_access"))
            projected.append(
                {
                    "entry_reference": entry.get("entry_reference"),
                    "control_transaction_reference": entry.get(
                        "control_transaction_reference"
                    ),
                    "procedure_family": entry.get("procedure_family"),
                    "request_frame": entry.get("request_frame"),
                    "response_frame": entry.get("response_frame"),
                    "control_outcome": entry.get("control_outcome"),
                    "control_session_status": control_session.get("status"),
                    "control_session_context": control_session.get(
                        "session_context_reference"
                    ),
                    "control_session_interface": control_session.get("interface_class"),
                    "control_session_candidates": control_session.get(
                        "candidate_contexts", []
                    )[:MAX_LIST_ITEMS],
                    "session_access_status": session_access.get("status"),
                    "session_access_related_contexts": session_access.get(
                        "related_session_contexts", []
                    )[:MAX_LIST_ITEMS],
                    "session_access_endpoint_correspondences": session_access.get(
                        "endpoint_correspondence_references", []
                    )[:MAX_LIST_ITEMS],
                    "nas_access_status": nas_access.get("status"),
                    "nas_owner_s1ap_context": nas_access.get("owner_s1ap_context"),
                    "nas_observed_reference_count": len(
                        _list(nas_access.get("observed_references"))
                    ),
                    "s1ap_access_status": s1ap_access.get("status"),
                    "s1ap_endpoint_matches": s1ap_access.get("endpoint_matches", [])[
                        :MAX_LIST_ITEMS
                    ],
                    "s1ap_candidate_contexts": s1ap_access.get(
                        "candidate_contexts", []
                    )[:MAX_LIST_ITEMS],
                    "overall_status": entry.get("overall_status"),
                    "established_links": entry.get("established_links", [])[
                        :MAX_LIST_ITEMS
                    ],
                    "limiting_evidence": entry.get("limiting_evidence", [])[
                        :MAX_LIST_ITEMS
                    ],
                    "additional_evidence_needed": entry.get(
                        "additional_evidence_needed", []
                    )[:MAX_LIST_ITEMS],
                }
            )
        return {
            "execution_status": analysis.get("execution_status"),
            "source_artifact": "epc-dedicated-bearer-attribution-analysis.json",
            "entry_count": analysis.get("attribution_entry_count", 0),
            "omitted_entry_count": analysis.get("attribution_entries_omitted", 0),
            "control_session_status_counts": analysis.get(
                "control_session_status_counts", {}
            ),
            "session_access_status_counts": analysis.get(
                "session_access_status_counts", {}
            ),
            "nas_access_status_counts": analysis.get(
                "nas_access_status_counts", {}
            ),
            "s1ap_access_status_counts": analysis.get(
                "s1ap_access_status_counts", {}
            ),
            "overall_status_counts": analysis.get("overall_status_counts", {}),
            "established_link_counts": analysis.get("established_link_counts", {}),
            "unresolved_evidence_count": len(
                _list(analysis.get("unresolved_evidence"))
            ),
            "source_completeness_status": _dict(analysis.get("source_completeness")).get(
                "status"
            ),
            "entries": projected,
            "not_confirmed": analysis.get("not_confirmed", [])[:MAX_LIST_ITEMS],
            "failure_code": None,
        }
    if error:
        return {
            "execution_status": "FAILED",
            "source_artifact": None,
            "entry_count": 0,
            "omitted_entry_count": 0,
            "control_session_status_counts": {},
            "session_access_status_counts": {},
            "nas_access_status_counts": {},
            "s1ap_access_status_counts": {},
            "overall_status_counts": {},
            "established_link_counts": {},
            "unresolved_evidence_count": 0,
            "source_completeness_status": None,
            "entries": [],
            "not_confirmed": [],
            "failure_code": error.get("code", DEDICATED_BEARER_ATTRIBUTION_FAILURE_CODE),
            "failure_message": scrub_free_text(error.get("message")),
        }
    return {
        "execution_status": "NOT_EVALUATED",
        "source_artifact": None,
        "entry_count": 0,
        "omitted_entry_count": 0,
        "control_session_status_counts": {},
        "session_access_status_counts": {},
        "nas_access_status_counts": {},
        "s1ap_access_status_counts": {},
        "overall_status_counts": {},
        "established_link_counts": {},
        "unresolved_evidence_count": 0,
        "source_completeness_status": None,
        "entries": [],
        "not_confirmed": [],
        "failure_code": None,
    }


def _transaction_count(path: Path) -> int:
    """Count accepted transactions without trusting an unreadable artifact."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisError("PIPELINE_OUTPUT_UNREADABLE", f"GTPv2-C correlation is unreadable: {exc}") from exc
    if not isinstance(payload, dict):
        raise AnalysisError("PIPELINE_OUTPUT_UNREADABLE", "GTPv2-C correlation is not an object")
    transactions = payload.get("transactions")
    return len(transactions) if isinstance(transactions, list) else 0


def execute_epc_pipeline(capture: Path, work_dir: Path, case_id: str) -> dict[str, Any]:
    """Execute the EPC chain: S1AP, NAS-EPS, GTPv2-C, Attach and session control.

    A protocol that is genuinely absent from the capture is not a failure. An
    extraction or correlation failure of an observed protocol is never hidden.
    """
    run_dir = create_run_directory(work_dir, DOMAIN_EPC)
    s1ap_events = run_dir / "s1ap-events.jsonl"
    nas_events = run_dir / "nas-eps-events.jsonl"
    gtpv2_events = run_dir / "gtpv2-events.jsonl"
    gtpv2_transactions = run_dir / "gtpv2-transactions.json"
    analysis_path = run_dir / "epc-attach-analysis.json"
    session_path = run_dir / "epc-session-analysis.json"

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

    gtpv2_present = _run_component(
        [sys.executable, str(GTPV2_EXTRACT_SCRIPT), str(capture), "--output", str(gtpv2_events), "--force"],
        "GTPv2-C extraction",
        allow_empty=True,
    )
    gtpv2_event_count = _count_lines(gtpv2_events) if gtpv2_present else 0
    transaction_count = 0
    if gtpv2_event_count:
        _run_component(
            [
                sys.executable,
                str(GTPV2_CORRELATE_SCRIPT),
                str(gtpv2_events),
                "--output",
                str(gtpv2_transactions),
                "--force",
            ],
            "GTPv2-C transaction correlation",
        )
        transaction_count = _transaction_count(gtpv2_transactions)

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

    diameter_status = "NOT_OBSERVED_IN_CAPTURE"
    diameter_event_count = 0
    diameter_observation_count = 0
    diameter_epc_analysis: dict[str, Any] | None = None
    diameter_epc_error: dict[str, Any] | None = None
    attach_s6a_analysis: dict[str, Any] | None = None
    attach_s6a_error: dict[str, Any] | None = None
    diameter_events = run_dir / "diameter-events.jsonl"
    diameter_trace = run_dir / "diameter-trace.jsonl"
    diameter_transactions = run_dir / "diameter-transactions.json"
    diameter_epc_path = run_dir / "diameter-epc-analysis.json"
    attach_s6a_path = run_dir / "epc-attach-s6a-analysis.json"
    attach_s6a_report_path = run_dir / "epc-attach-s6a-report.txt"
    attach_s6a_manifest_path = run_dir / "epc-attach-s6a-run-manifest.json"
    # A stale artifact from an earlier invocation is never accepted as this run's evidence.
    for stale in (
        diameter_events,
        diameter_trace,
        diameter_transactions,
        diameter_epc_path,
        attach_s6a_path,
        attach_s6a_report_path,
        attach_s6a_manifest_path,
    ):
        stale.unlink(missing_ok=True)
    try:
        # Exit 3 is the Diameter CLI's only legitimate empty result. Exit 2, 4,
        # 5, 6 and any unexpected code are component failures, never absence.
        diameter_present = _run_named_stage(
            [
                sys.executable,
                str(DIAMETER_CORE_EXTRACT_SCRIPT),
                str(capture),
                "--output",
                str(diameter_events),
                "--trace-output",
                str(diameter_trace),
                "--force",
            ],
            "Diameter Core extraction",
            DIAMETER_CORE_EXTRACTION_FAILURE,
            allow_empty=True,
        )
        if diameter_present:
            _require_component_artifact(
                diameter_events, "Diameter Core extraction", DIAMETER_CORE_EXTRACTION_FAILURE
            )
            diameter_event_count = _count_component_events(
                diameter_events,
                "Diameter Core extraction",
                DIAMETER_CORE_EXTRACTION_FAILURE,
            )
            if not diameter_event_count:
                raise AnalysisError(
                    DIAMETER_CORE_EXTRACTION_FAILURE,
                    "Diameter Core extraction reported success with no Diameter events",
                )
        if diameter_event_count:
            _run_named_stage(
                [
                    sys.executable,
                    str(DIAMETER_CORE_CORRELATE_SCRIPT),
                    str(diameter_events),
                    "--output",
                    str(diameter_transactions),
                    "--force",
                ],
                "Diameter Core correlation",
                DIAMETER_CORE_CORRELATION_FAILURE,
            )
            _require_component_artifact(
                diameter_transactions,
                "Diameter Core correlation",
                DIAMETER_CORE_CORRELATION_FAILURE,
            )
            epc_present = _run_named_stage(
                [
                    sys.executable,
                    str(DIAMETER_EPC_ANALYZE_SCRIPT),
                    "--events",
                    str(diameter_events),
                    "--transactions",
                    str(diameter_transactions),
                    "--output",
                    str(diameter_epc_path),
                    "--force",
                ],
                "Diameter EPC analysis",
                DIAMETER_EPC_ANALYSIS_FAILURE,
                allow_empty=True,
            )
            if epc_present:
                _require_component_artifact(
                    diameter_epc_path,
                    "Diameter EPC analysis",
                    DIAMETER_EPC_ANALYSIS_FAILURE,
                )
                diameter_epc_analysis = _read_component_artifact(
                    diameter_epc_path,
                    "Diameter EPC analysis",
                    DIAMETER_EPC_ANALYSIS_FAILURE,
                )
                diameter_observation_count = len(
                    diameter_epc_analysis.get("observations") or []
                )
                if not diameter_observation_count:
                    raise AnalysisError(
                        DIAMETER_EPC_ANALYSIS_FAILURE,
                        "Diameter EPC analysis reported success with no S6a/S6d observation",
                    )
            if diameter_observation_count:
                try:
                    manifest = _attach_s6a_run_manifest(
                        run_dir, capture, analysis_path, diameter_epc_path
                    )
                    attach_s6a_manifest_path.write_text(
                        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                except OSError as exc:
                    raise AnalysisError(
                        ATTACH_S6A_JOINT_FAILURE,
                        f"coordinated run manifest could not be written: {exc}",
                    ) from exc
                _run_named_stage(
                    [
                        sys.executable,
                        str(EPC_ATTACH_S6A_ANALYZE_SCRIPT),
                        "--attach",
                        str(analysis_path),
                        "--diameter-epc",
                        str(diameter_epc_path),
                        "--capture",
                        str(capture),
                        "--run-manifest",
                        str(attach_s6a_manifest_path),
                        "--output",
                        str(attach_s6a_path),
                        "--report",
                        str(attach_s6a_report_path),
                        "--force",
                    ],
                    "EPC Attach/S6a joint analysis",
                    ATTACH_S6A_JOINT_FAILURE,
                )
                _require_component_artifact(
                    attach_s6a_path,
                    "EPC Attach/S6a joint analysis",
                    ATTACH_S6A_JOINT_FAILURE,
                )
                attach_s6a_analysis = _read_component_artifact(
                    attach_s6a_path,
                    "EPC Attach/S6a joint analysis",
                    ATTACH_S6A_JOINT_FAILURE,
                )
                diameter_status = "EXECUTED"
            else:
                diameter_status = "NO_S6A_OBSERVATIONS"
    except AnalysisError as exc:
        diameter_status = "COMPONENT_FAILED"
        diameter_epc_error = {
            "code": exc.code,
            "stage": ATTACH_S6A_FAILURE_STAGES.get(exc.code, exc.code),
            "message": scrub_free_text(exc.message),
        }
        attach_s6a_error = diameter_epc_error

    session_analysis: dict[str, Any] | None = None
    if gtpv2_event_count:
        _run_component(
            [
                sys.executable,
                str(EPC_SESSION_ANALYZE_SCRIPT),
                "--gtpv2",
                str(gtpv2_events),
                "--transactions",
                str(gtpv2_transactions),
                "--output",
                str(session_path),
                "--force",
            ],
            "EPC session-control analysis",
            allow_empty=True,
        )
        if session_path.is_file():
            try:
                session_analysis = json.loads(session_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise AnalysisError(
                    "PIPELINE_OUTPUT_UNREADABLE", f"EPC session-control analysis is unreadable: {exc}"
                ) from exc
            if not isinstance(session_analysis, dict):
                raise AnalysisError(
                    "PIPELINE_OUTPUT_UNREADABLE", "EPC session-control analysis is not an object"
                )

    gtpu_events = run_dir / "gtpu-events.jsonl"
    gtpu_streams = run_dir / "gtpu-streams.json"
    gtpu_present = _run_component(
        [
            sys.executable,
            str(GTPU_EXTRACT_SCRIPT),
            str(capture),
            "--output",
            str(gtpu_events),
            "--user-plane-interface",
            "unknown",
            "--force",
        ],
        "GTP-U extraction",
        allow_empty=True,
    )
    gtpu_event_count = _count_lines(gtpu_events) if gtpu_present else 0
    gtpu_stream_count = 0
    if gtpu_event_count:
        _run_component(
            [
                sys.executable,
                str(GTPU_SUMMARIZE_SCRIPT),
                str(gtpu_events),
                "--output",
                str(gtpu_streams),
                "--force",
            ],
            "GTP-U stream summarization",
        )
        try:
            stream_document = json.loads(gtpu_streams.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AnalysisError(
                "PIPELINE_OUTPUT_UNREADABLE", f"GTP-U stream summary is unreadable: {exc}"
            ) from exc
        streams = stream_document.get("streams") if isinstance(stream_document, dict) else None
        gtpu_stream_count = len(streams) if isinstance(streams, list) else 0

    default_bearer_analysis: dict[str, Any] | None = None
    default_bearer_error: dict[str, Any] | None = None
    default_bearer_path = run_dir / "epc-default-bearer-analysis.json"
    if _count_lines(nas_events) or _count_lines(s1ap_events):
        command = [
            sys.executable,
            str(EPC_DEFAULT_BEARER_ANALYZE_SCRIPT),
            "--nas",
            str(nas_events),
            "--s1ap",
            str(s1ap_events),
            "--output",
            str(default_bearer_path),
            "--force",
        ]
        if analysis_path.is_file():
            command.extend(["--attach", str(analysis_path)])
        if session_path.is_file():
            command.extend(["--session", str(session_path)])
        if gtpv2_event_count:
            command.extend(["--gtpv2", str(gtpv2_events)])
        if gtpv2_transactions.is_file():
            command.extend(["--transactions", str(gtpv2_transactions)])
        try:
            # Exit 6 means "no default-bearer instance", which is a valid result
            # for a capture without readable ESM evidence, not a failure.
            _run_component(command, "EPC default-bearer analysis", allow_empty=True)
            if default_bearer_path.is_file():
                default_bearer_analysis = json.loads(default_bearer_path.read_text(encoding="utf-8"))
                if not isinstance(default_bearer_analysis, dict):
                    raise AnalysisError(
                        "PIPELINE_OUTPUT_UNREADABLE",
                        "EPC default-bearer analysis is not an object",
                    )
        except (AnalysisError, OSError, json.JSONDecodeError) as exc:
            default_bearer_analysis = None
            default_bearer_error = {
                "code": "DEFAULT_BEARER_FAILED",
                "message": scrub_free_text(str(exc)),
            }

    s1u_analysis: dict[str, Any] | None = None
    s1u_error: dict[str, Any] | None = None
    # The artifact path is defined for every capture: a GTPv2-C capture without
    # GTP-U must still be able to reference a non-existent S1-U observation.
    s1u_path = run_dir / "epc-s1u-observation.json"
    if gtpu_stream_count:
        s1u_command = [
            sys.executable,
            str(EPC_S1U_ANALYZE_SCRIPT),
            "--gtpu",
            str(gtpu_events),
            "--streams",
            str(gtpu_streams),
            "--output",
            str(s1u_path),
            "--force",
        ]
        if default_bearer_path.is_file():
            s1u_command.extend(["--default-bearer", str(default_bearer_path)])
        if gtpv2_event_count:
            s1u_command.extend(["--gtpv2", str(gtpv2_events)])
        try:
            _run_component(s1u_command, "EPC S1-U observation", allow_empty=True)
            if s1u_path.is_file():
                s1u_analysis = json.loads(s1u_path.read_text(encoding="utf-8"))
                if not isinstance(s1u_analysis, dict):
                    raise AnalysisError(
                        "PIPELINE_OUTPUT_UNREADABLE", "EPC S1-U observation is not an object"
                    )
        except (AnalysisError, OSError, json.JSONDecodeError) as exc:
            s1u_analysis = None
            s1u_error = {"code": "S1U_OBSERVATION_FAILED", "message": scrub_free_text(str(exc))}

    identity_analysis: dict[str, Any] | None = None
    identity_error: dict[str, Any] | None = None
    identity_path = run_dir / "epc-session-identity-analysis.json"
    if gtpv2_event_count and gtpv2_transactions.is_file():
        identity_command = [
            sys.executable,
            str(EPC_SESSION_IDENTITY_ANALYZE_SCRIPT),
            "--gtpv2",
            str(gtpv2_events),
            "--transactions",
            str(gtpv2_transactions),
            "--output",
            str(identity_path),
            "--force",
        ]
        if session_path.is_file():
            identity_command.extend(["--session", str(session_path)])
        if default_bearer_path.is_file():
            identity_command.extend(["--default-bearer", str(default_bearer_path)])
        try:
            _run_component(identity_command, "EPC session-identity analysis", allow_empty=True)
            if identity_path.is_file():
                identity_analysis = json.loads(identity_path.read_text(encoding="utf-8"))
                if not isinstance(identity_analysis, dict):
                    raise AnalysisError(
                        "PIPELINE_OUTPUT_UNREADABLE",
                        "EPC session-identity analysis is not an object",
                    )
        except (AnalysisError, OSError, json.JSONDecodeError) as exc:
            # Attach, session-control, default-bearer and S1-U evidence is
            # preserved; the failure is reported, never silently completed.
            identity_analysis = None
            identity_error = {
                "code": "SESSION_IDENTITY_FAILED",
                "message": scrub_free_text(str(exc)),
            }

    dedicated_bearer_analysis: dict[str, Any] | None = None
    dedicated_bearer_error: dict[str, Any] | None = None
    dedicated_bearer_counts = {family: 0 for family in DEDICATED_BEARER_FAMILIES}
    dedicated_bearer_path = run_dir / "epc-dedicated-bearer-control-analysis.json"
    if gtpv2_transactions.is_file():
        dedicated_bearer_counts = _dedicated_bearer_transaction_counts(gtpv2_transactions)
    if _dedicated_bearer_requested(dedicated_bearer_counts):
        dedicated_bearer_analysis, dedicated_bearer_error = _run_dedicated_bearer_stage(
            gtpv2_events,
            gtpv2_transactions,
            dedicated_bearer_path,
            identity_path if isinstance(identity_analysis, dict) else None,
        )

    timeline_analysis: dict[str, Any] | None = None
    timeline_error: dict[str, Any] | None = None
    timeline_path = run_dir / "epc-dedicated-bearer-timeline-analysis.json"
    if isinstance(dedicated_bearer_analysis, dict):
        timeline_analysis, timeline_error = _run_dedicated_bearer_timeline_stage(
            dedicated_bearer_path, nas_events, s1ap_events, timeline_path
        )

    attribution_analysis: dict[str, Any] | None = None
    attribution_error: dict[str, Any] | None = None
    attribution_path = run_dir / "epc-dedicated-bearer-attribution-analysis.json"
    if isinstance(dedicated_bearer_analysis, dict) and isinstance(identity_analysis, dict):
        attribution_analysis, attribution_error = _run_dedicated_bearer_attribution_stage(
            dedicated_bearer_path,
            identity_path,
            gtpv2_events,
            nas_events,
            s1ap_events,
            attribution_path,
        )

    lifecycle_analysis: dict[str, Any] | None = None
    lifecycle_error: dict[str, Any] | None = None
    if gtpv2_event_count and gtpv2_transactions.is_file():
        lifecycle_path = run_dir / "epc-bearer-lifecycle-analysis.json"
        lifecycle_command = [
            sys.executable,
            str(EPC_LIFECYCLE_ANALYZE_SCRIPT),
            "--gtpv2",
            str(gtpv2_events),
            "--transactions",
            str(gtpv2_transactions),
            "--output",
            str(lifecycle_path),
            "--force",
        ]
        if session_path.is_file():
            lifecycle_command.extend(["--session", str(session_path)])
        if default_bearer_path.is_file():
            lifecycle_command.extend(["--default-bearer", str(default_bearer_path)])
        if s1u_path.is_file():
            lifecycle_command.extend(["--s1u", str(s1u_path)])
        if gtpu_event_count:
            lifecycle_command.extend(["--gtpu", str(gtpu_events)])
        if identity_path.is_file():
            lifecycle_command.extend(["--session-identity", str(identity_path)])
        try:
            _run_component(lifecycle_command, "EPC bearer lifecycle analysis", allow_empty=True)
            if lifecycle_path.is_file():
                lifecycle_analysis = json.loads(lifecycle_path.read_text(encoding="utf-8"))
                if not isinstance(lifecycle_analysis, dict):
                    raise AnalysisError(
                        "PIPELINE_OUTPUT_UNREADABLE",
                        "EPC bearer lifecycle analysis is not an object",
                    )
        except (AnalysisError, OSError, json.JSONDecodeError) as exc:
            # Usable Attach, session-control, default-bearer and S1-U evidence is
            # preserved; the failure is reported, never silently completed.
            lifecycle_analysis = None
            lifecycle_error = {
                "code": "BEARER_LIFECYCLE_FAILED",
                "message": scrub_free_text(str(exc)),
            }

    narrative_analysis: dict[str, Any] | None = None
    narrative_error: dict[str, Any] | None = None
    narrative_path = run_dir / "epc-release-narrative-analysis.json"
    if identity_path.is_file() and lifecycle_path.is_file():
        narrative_command = [
            sys.executable,
            str(EPC_RELEASE_NARRATIVE_ANALYZE_SCRIPT),
            "--session-identity",
            str(identity_path),
            "--lifecycle",
            str(lifecycle_path),
            "--output",
            str(narrative_path),
            "--force",
        ]
        if s1u_path.is_file():
            narrative_command.extend(["--s1u", str(s1u_path)])
        if gtpv2_event_count:
            narrative_command.extend(["--gtpv2", str(gtpv2_events)])
        if gtpu_event_count:
            narrative_command.extend(["--gtpu", str(gtpu_events)])
        try:
            _run_component(narrative_command, "EPC release narrative", allow_empty=True)
            if narrative_path.is_file():
                narrative_analysis = json.loads(narrative_path.read_text(encoding="utf-8"))
                if not isinstance(narrative_analysis, dict):
                    raise AnalysisError(
                        "PIPELINE_OUTPUT_UNREADABLE",
                        "EPC release narrative analysis is not an object",
                    )
        except (AnalysisError, OSError, json.JSONDecodeError) as exc:
            # Every earlier EPC artifact is preserved. A narrative failure is a
            # component-level limitation and never an EPC protocol failure.
            narrative_analysis = None
            narrative_error = {
                "code": "RELEASE_NARRATIVE_FAILED",
                "message": scrub_free_text(str(exc)),
            }

    boundary_analysis: dict[str, Any] | None = None
    boundary_error: dict[str, Any] | None = None
    audit_analysis: dict[str, Any] | None = None
    audit_error: dict[str, Any] | None = None
    audit_path = run_dir / "epc-evidence-audit-analysis.json"
    if identity_path.is_file() and lifecycle_path.is_file() and narrative_path.is_file():
        audit_command = [
            sys.executable,
            str(EPC_EVIDENCE_AUDIT_ANALYZE_SCRIPT),
            "--session-identity",
            str(identity_path),
            "--lifecycle",
            str(lifecycle_path),
            "--release-narrative",
            str(narrative_path),
            "--output",
            str(audit_path),
            "--force",
        ]
        if s1u_path.is_file():
            audit_command.extend(["--s1u", str(s1u_path)])
        if gtpv2_event_count:
            audit_command.extend(["--gtpv2", str(gtpv2_events)])
        if gtpu_event_count:
            audit_command.extend(["--gtpu", str(gtpu_events)])
        try:
            _run_component(audit_command, "EPC evidence audit", allow_empty=True)
            if audit_path.is_file():
                audit_analysis = json.loads(audit_path.read_text(encoding="utf-8"))
                if not isinstance(audit_analysis, dict):
                    raise AnalysisError(
                        "PIPELINE_OUTPUT_UNREADABLE",
                        "EPC evidence audit analysis is not an object",
                    )
        except (AnalysisError, OSError, json.JSONDecodeError) as exc:
            # Every accepted producer artifact is already on disk. An audit
            # failure is a component-level limitation, never a protocol failure.
            audit_analysis = None
            audit_error = {
                "code": "EVIDENCE_AUDIT_FAILED",
                "message": scrub_free_text(str(exc)),
            }
    has_subjects = (
        bool(analysis.get("procedure_instances"))
        or bool((session_analysis or {}).get("control_plane_subjects"))
        or bool((default_bearer_analysis or {}).get("default_bearer_instances"))
    )
    if has_subjects:
        boundary_path = run_dir / "epc-boundary-analysis.json"
        boundary_command = [
            sys.executable,
            str(EPC_BOUNDARY_SCRIPT),
            "--output",
            str(boundary_path),
            "--force",
        ]
        if analysis.get("procedure_instances"):
            boundary_command.extend(["--attach", str(analysis_path)])
        if (session_analysis or {}).get("control_plane_subjects"):
            boundary_command.extend(["--session", str(session_path)])
        if (default_bearer_analysis or {}).get("default_bearer_instances"):
            boundary_command.extend(["--default-bearer", str(default_bearer_path)])
        try:
            _run_component(boundary_command, "EPC failure-boundary orchestration")
            boundary_analysis = json.loads(boundary_path.read_text(encoding="utf-8"))
            if not isinstance(boundary_analysis, dict):
                raise AnalysisError(
                    "PIPELINE_OUTPUT_UNREADABLE", "EPC failure-boundary analysis is not an object"
                )
        except (AnalysisError, OSError, json.JSONDecodeError) as exc:
            # Usable Domain evidence is preserved; the degraded status is reported
            # by the domain adapter instead of discarding the analysis.
            boundary_analysis = None
            boundary_error = {
                "code": "ORCHESTRATION_FAILED",
                "message": scrub_free_text(str(exc)),
            }


    return {
        "analysis": analysis,
        "session_analysis": session_analysis,
        "default_bearer_analysis": default_bearer_analysis,
        "default_bearer_error": default_bearer_error,
        "s1u_analysis": s1u_analysis,
        "s1u_error": s1u_error,
        "gtpu_event_count": gtpu_event_count,
        "gtpu_stream_count": gtpu_stream_count,
        "boundary_analysis": boundary_analysis,
        "boundary_error": boundary_error,
        "lifecycle_analysis": lifecycle_analysis,
        "lifecycle_error": lifecycle_error,
        "identity_analysis": identity_analysis,
        "identity_error": identity_error,
        "release_narrative_analysis": narrative_analysis,
        "release_narrative_error": narrative_error,
        "evidence_audit_analysis": audit_analysis,
        "evidence_audit_error": audit_error,
        "dedicated_bearer_analysis": dedicated_bearer_analysis,
        "dedicated_bearer_error": dedicated_bearer_error,
        "dedicated_bearer_timeline_analysis": timeline_analysis,
        "dedicated_bearer_timeline_error": timeline_error,
        "dedicated_bearer_attribution_analysis": attribution_analysis,
        "dedicated_bearer_attribution_error": attribution_error,
        "dedicated_bearer_transaction_counts": dedicated_bearer_counts,
        "s1ap_event_count": _count_lines(s1ap_events),
        "nas_eps_event_count": _count_lines(nas_events),
        "gtpv2_event_count": gtpv2_event_count,
        "gtpv2_transaction_count": transaction_count,
        "diameter_status": diameter_status,
        "diameter_event_count": diameter_event_count,
        "diameter_observation_count": diameter_observation_count,
        "diameter_epc_analysis": diameter_epc_analysis,
        "diameter_epc_error": diameter_epc_error,
        "attach_s6a_analysis": attach_s6a_analysis,
        "attach_s6a_error": attach_s6a_error,
        "attach_s6a_report_path": str(attach_s6a_report_path) if attach_s6a_path.is_file() else None,
        "attach_s6a_manifest_path": (
            str(attach_s6a_manifest_path)
            if attach_s6a_manifest_path.is_file()
            else None
        ),
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
        for cause_key in ("cause_code", "cause_name", "cause_family", "cause_scope"):
            if deviation.get(cause_key) is not None:
                entry[cause_key] = deviation[cause_key]
        if references_omitted:
            entry["evidence_refs_omitted"] = references_omitted
        if limitations_omitted:
            entry["limitations_omitted"] = limitations_omitted
        projected.append(entry)
    return projected


def _project_boundary(boundary: Any) -> dict[str, Any] | None:
    """Publish a selected boundary with exact frame and protocol evidence."""
    if not isinstance(boundary, dict):
        return None
    references, references_omitted = _bounded_evidence_refs(boundary.get("evidence_refs"))
    payload: dict[str, Any] = {
        "boundary_reference": boundary.get("boundary_reference"),
        "deviation_type": boundary.get("deviation_type"),
        "protocol": boundary.get("protocol"),
        "message_type": boundary.get("message_type"),
        "frame_number": boundary.get("frame_number"),
        "evidence_level": boundary.get("evidence_level"),
        "ordering_basis": boundary.get("ordering_basis"),
        "evidence_refs": references,
        "observation_window": _bounded_observation_window(boundary.get("observation_window")),
    }
    for key in (
        "transaction_reference",
        "cause_code",
        "cause_name",
        "cause_family",
        "cause_scope",
        "bearer_item_index",
        "procedure_family_or_stage",
    ):
        if boundary.get(key) is not None:
            payload[key] = boundary[key]
    if references_omitted:
        payload["evidence_refs_omitted"] = references_omitted
    return payload


def _boundary_fields(group: Any) -> dict[str, Any]:
    """Per-subject boundary fields; unevaluated when orchestration did not run."""
    if not isinstance(group, dict):
        return {
            "boundary_selection_status": "NOT_EVALUATED",
            "boundary_confidence": None,
            "first_abnormal_boundary": None,
            "candidate_boundary_count": 0,
        }
    return {
        "boundary_selection_status": group.get("boundary_selection_status"),
        "boundary_confidence": group.get("boundary_confidence"),
        "first_abnormal_boundary": _project_boundary(group.get("first_abnormal_boundary")),
        "candidate_boundary_count": group.get("boundary_candidate_count", 0),
    }


def _boundary_summary(boundary: Any) -> dict[str, Any] | None:
    """Count per-subject boundary statuses; never a global EPC boundary."""
    if not isinstance(boundary, dict):
        return None
    counts: dict[str, int] = {}
    for group in boundary.get("diagnostic_groups") or []:
        if not isinstance(group, dict):
            continue
        status = group.get("boundary_selection_status")
        if isinstance(status, str):
            counts[status] = counts.get(status, 0) + 1
    return {"group_count": sum(counts.values()), "status_counts": counts}


def _project_epc_subject(
    instance: dict[str, Any], group: Any = None
) -> dict[str, Any]:
    """Publish one Attach procedure instance as a diagnostic subject."""
    reference = instance.get("procedure_reference")
    association = instance.get("association") or {}
    return {
        "diagnostic_group_reference": reference,
        "subject_type": "EPS_ATTACH",
        **_boundary_fields(group),
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
        "s1ap_release_causes": [
            {
                "frame_number": item.get("frame_number"),
                "category": item.get("category"),
                "value": item.get("value"),
            }
            for item in instance.get("s1ap_release_causes") or []
            if isinstance(item, dict)
        ],
        "observations": [
            observation.get("observation_type") for observation in instance.get("observations") or []
        ],
        "evidence_limitations": scrub_list(instance.get("evidence_limitations")),
        "additional_evidence_needed": scrub_list(instance.get("additional_evidence_needed")),
    }


def _project_primary_transaction(transaction: Any) -> dict[str, Any] | None:
    """Allowlisted projection of one subject's earliest transaction."""
    if not isinstance(transaction, dict):
        return None
    cause = transaction.get("message_cause")
    return {
        "transaction_reference": transaction.get("transaction_reference"),
        "procedure_family": transaction.get("procedure_family"),
        "outcome": transaction.get("outcome"),
        "request_frame": transaction.get("request_frame"),
        "response_frame": transaction.get("response_frame"),
        "message_cause": (
            {
                "cause_code": cause.get("cause_code"),
                "cause_name": scrub_free_text(cause.get("cause_name")),
                "scope": cause.get("scope"),
            }
            if isinstance(cause, dict)
            else None
        ),
    }


def _project_session_bearer_contexts(contexts: Any) -> list[dict[str, Any]]:
    """Allowlisted item-scoped bearer evidence with a hard cap."""
    projected: list[dict[str, Any]] = []
    if not isinstance(contexts, list):
        return projected
    for context in contexts:
        if not isinstance(context, dict):
            continue
        cause = context.get("cause")
        projected.append(
            {
                "transaction_reference": context.get("transaction_reference"),
                "item_index": context.get("item_index"),
                "ebi": context.get("ebi"),
                "scope": "bearer",
                "cause": (
                    {
                        "cause_code": cause.get("cause_code"),
                        "cause_name": scrub_free_text(cause.get("cause_name")),
                        "scope": "bearer",
                    }
                    if isinstance(cause, dict)
                    else None
                ),
                "f_teids": [
                    {
                        "interface_type": item.get("interface_type"),
                        "interface_type_name": scrub_free_text(item.get("interface_type_name")),
                        "teid": item.get("teid"),
                    }
                    for item in context.get("f_teids") or []
                    if isinstance(item, dict)
                ][:MAX_LIST_ITEMS],
                "binding_basis": context.get("binding_basis"),
            }
        )
    return projected[:MAX_LIST_ITEMS]


def _project_session_f_teids(items: Any) -> list[dict[str, Any]]:
    """Allowlisted message-scope F-TEID evidence with a hard cap."""
    projected: list[dict[str, Any]] = []
    if not isinstance(items, list):
        return projected
    for item in items:
        if not isinstance(item, dict):
            continue
        projected.append(
            {
                "transaction_reference": item.get("transaction_reference"),
                "scope": item.get("scope"),
                "interface_type": item.get("interface_type"),
                "interface_type_name": scrub_free_text(item.get("interface_type_name")),
                "teid": item.get("teid"),
            }
        )
    return projected[:MAX_LIST_ITEMS]


def _project_epc_session_subject(
    subject: dict[str, Any], analysis: dict[str, Any], group: Any = None
) -> dict[str, Any]:
    """Publish one GTPv2-C session-control subject as a diagnostic subject."""
    reference = subject.get("subject_reference")
    interface_evidence = subject.get("interface_evidence") or {}
    transaction_references = [
        item for item in (subject.get("transaction_references") or []) if isinstance(item, str)
    ]
    reference_set = set(transaction_references)
    deviations = [
        deviation
        for deviation in (analysis.get("procedure_local_deviations") or [])
        if isinstance(deviation, dict) and deviation.get("transaction_reference") in reference_set
    ]
    evidence_refs, references_omitted = _bounded_evidence_refs(subject.get("evidence_refs"))
    limitations, limitations_omitted = _bounded_limitations(subject.get("limitations"))
    observations: list[str] = []
    for payload in (subject.get("procedure_observations") or {}).values():
        if not isinstance(payload, dict):
            continue
        for outcome in payload.get("outcomes") or []:
            if isinstance(outcome, str) and outcome not in observations:
                observations.append(outcome)
    entry: dict[str, Any] = {
        "diagnostic_group_reference": reference,
        "subject_type": "EPC_SESSION_CONTROL",
        **_boundary_fields(group),
        "source_domain_instances": [
            {
                "source_domain": "epc-procedures",
                "capture_file": subject.get("capture_file"),
                "instance_reference": reference,
            }
        ],
        "subject_link": {
            "basis": interface_evidence.get("basis"),
            "context_count": len(transaction_references),
            "subject_reference": reference,
        },
        "attempt_index": None,
        "association_strength": subject.get("association_strength"),
        "interface": subject.get("interface"),
        "interface_label": subject.get("interface_label"),
        "interface_evidence": {
            "interface": interface_evidence.get("interface"),
            "basis": interface_evidence.get("basis"),
            "evidence_message": interface_evidence.get("evidence_message"),
            "supporting_interface_types": interface_evidence.get("supporting_interface_types") or [],
            "supporting_frames": interface_evidence.get("supporting_frames") or [],
        },
        "procedure_families": [
            item for item in (subject.get("procedure_families") or []) if isinstance(item, str)
        ],
        "transaction_references": transaction_references,
        "primary_transaction": _project_primary_transaction(subject.get("primary_transaction")),
        "procedure_stages": [],
        "procedure_deviations": _project_epc_deviations(deviations),
        "bearer_contexts": _project_session_bearer_contexts(subject.get("bearer_contexts")),
        "f_teid_evidence": _project_session_f_teids(subject.get("f_teid_evidence")),
        "cross_interface_association": "NOT_ESTABLISHED",
        "attach_association": "NOT_ESTABLISHED",
        "observations": observations,
        "evidence_refs": evidence_refs,
        "observation_window": _bounded_observation_window(subject.get("observation_window")),
        "evidence_limitations": limitations,
        "additional_evidence_needed": [],
    }
    if references_omitted:
        entry["evidence_refs_omitted"] = references_omitted
    if limitations_omitted:
        entry["limitations_omitted"] = limitations_omitted
    return entry


def _single_value(values: Any) -> Any:
    """Return the one distinct non-null value, or None when the values disagree."""
    distinct = {value for value in values if value is not None}
    return next(iter(distinct)) if len(distinct) == 1 else None


def _project_default_bearer_subject(
    instance: dict[str, Any], analysis: dict[str, Any], group: Any = None
) -> dict[str, Any]:
    """Publish one EPS default-bearer instance as a diagnostic subject."""
    reference = instance.get("instance_reference")
    stages = instance.get("stages") or []
    by_stage = {stage.get("stage_id"): stage for stage in stages if isinstance(stage, dict)}
    activation_request = by_stage.get("default-bearer-activation-request") or {}
    activation_response = by_stage.get("default-bearer-activation-response") or {}
    pdn_request = by_stage.get("pdn-connectivity-request") or {}
    response_messages = [
        message for message in activation_response.get("messages") or [] if isinstance(message, dict)
    ]
    cause = None
    for message in response_messages:
        if isinstance(message.get("esm_cause"), dict):
            cause = {
                "cause_code": message["esm_cause"].get("value"),
                "cause_name": scrub_free_text(message["esm_cause"].get("name")),
                "scope": "esm",
            }
            break
    if cause is None:
        for message in pdn_request.get("messages") or []:
            if isinstance(message, dict) and isinstance(message.get("esm_cause"), dict):
                cause = {
                    "cause_code": message["esm_cause"].get("value"),
                    "cause_name": scrub_free_text(message["esm_cause"].get("name")),
                    "scope": "esm",
                }
                break
    deviations = [
        {
            "deviation_type": item.get("deviation_type"),
            "frame_number": item.get("frame_number"),
            "protocol": item.get("protocol"),
            "message_type": scrub_free_text(item.get("message_type")),
            "esm_cause_code": item.get("esm_cause_code"),
            "esm_cause_name": scrub_free_text(item.get("esm_cause_name")),
        }
        for item in instance.get("deviations") or []
        if isinstance(item, dict)
    ]
    evidence_refs, references_omitted = _bounded_evidence_refs(instance.get("evidence_refs"))
    limitations, limitations_omitted = _bounded_limitations(instance.get("limitations"))
    bearer = instance.get("bearer_context") or {}
    entry: dict[str, Any] = {
        "diagnostic_group_reference": reference,
        "subject_type": "EPS_DEFAULT_BEARER",
        **_boundary_fields(group),
        "source_domain_instances": [
            {
                "source_domain": "epc-procedures",
                "capture_file": (instance.get("ue_context") or {}).get("capture_file"),
                "instance_reference": reference,
            }
        ],
        "subject_link": {
            "basis": instance.get("association_basis"),
            "context_count": 1,
            "subject_reference": reference,
            "attach_status": (instance.get("attach_link") or {}).get("status"),
            "attach_subject_reference": (instance.get("attach_link") or {}).get("target_subject_reference"),
        },
        "attempt_index": None,
        "association_strength": instance.get("association_strength"),
        "procedure_families": ["eps-default-bearer"],
        "transaction_references": [],
        "primary_transaction": None,
        "interface_evidence": {
            "interfaces": ["S1-MME", "S1-U"],
            "basis": "s1ap_ue_context_and_esm_container",
            "evidence_message": None,
        },
        "procedure_stages": [
            {
                "stage_id": stage.get("stage_id"),
                "status": stage.get("status"),
                "conditional": stage.get("conditional"),
                "first_frame": stage.get("first_frame"),
                "last_frame": stage.get("last_frame"),
                "messages": [
                    {
                        "protocol": message.get("protocol"),
                        "frame_number": message.get("frame_number"),
                        "message_type": scrub_free_text(message.get("message_type")),
                        "result": message.get("result"),
                    }
                    for message in stage.get("messages") or []
                    if isinstance(message, dict)
                ][:MAX_LIST_ITEMS],
            }
            for stage in stages
            if isinstance(stage, dict)
        ],
        "procedure_deviations": _project_epc_deviations(deviations),
        "request_frame": activation_request.get("first_frame") or pdn_request.get("first_frame"),
        "response_frame": activation_response.get("first_frame"),
        "message_cause": cause,
        "bearer_contexts": [
            {
                "item_index": 0,
                "ebi": bearer.get("eps_bearer_identity"),
                "scope": "bearer",
                "cause": None,
                "ebi_basis": bearer.get("eps_bearer_identity_basis"),
                "pdn_type": scrub_free_text(bearer.get("pdn_type")),
                "apn_present": bearer.get("apn_present"),
                "apn_length": bearer.get("apn_length"),
                "pdn_address_present": bearer.get("pdn_address_present"),
                "pdn_address_family": scrub_free_text(bearer.get("pdn_address_family")),
                "qos_present": bearer.get("qos_present"),
                "pco_present": bearer.get("pco_present"),
                "f_teids": [],
            }
        ],
        "f_teid_evidence": [
            {
                "scope": "bearer",
                # An S1AP E-RAB item advertises a transport address and a TEID,
                # never a GTPv2-C interface type. The receiving role, not an
                # interface type, is what the S1AP message fixes.
                "endpoint_role": item.get("endpoint_role"),
                "endpoint_role_basis": item.get("endpoint_role_basis"),
                "source_protocols": ["S1AP"],
                "interface_type": None,
                "interface_type_name": None,
                "interface_type_basis": "s1ap_erab_item_advertises_no_gtpv2_interface_type",
                "teid": item.get("gtp_teid"),
                "transport_layer_address": item.get("transport_layer_address"),
                "erab_id": item.get("erab_id"),
                "qci": item.get("qci"),
                "frame_number": item.get("frame_number"),
                "binding_basis": item.get("binding_basis"),
            }
            for item in instance.get("erab_items") or []
            if isinstance(item, dict)
        ][:MAX_LIST_ITEMS],
        "outcomes": [
            item for item in instance.get("outcomes") or [] if isinstance(item, str)
        ],
        "cross_interface_association": "SUPPORTED"
        if any(
            isinstance(link, dict) and link.get("status") == "SUPPORTED"
            for link in instance.get("tunnel_links") or []
        )
        else "NOT_ESTABLISHED",
        "attach_association": (instance.get("attach_link") or {}).get("status") or "NOT_ESTABLISHED",
        "observations": [],
        "evidence_refs": evidence_refs,
        "observation_window": _bounded_observation_window(instance.get("observation_window")),
        "evidence_limitations": limitations,
        "additional_evidence_needed": scrub_list(instance.get("additional_evidence_needed")),
    }
    if references_omitted:
        entry["evidence_refs_omitted"] = references_omitted
    if limitations_omitted:
        entry["limitations_omitted"] = limitations_omitted
    return entry


def _project_s1u_subject(stream: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    """Publish one directed S1-U GTP-U stream as a diagnostic subject."""
    reference = stream.get("stream_reference")
    evidence_refs, references_omitted = _bounded_evidence_refs(stream.get("evidence_refs"))
    limitations, limitations_omitted = _bounded_limitations(stream.get("limitations"))
    entry: dict[str, Any] = {
        "diagnostic_group_reference": reference,
        "subject_type": "EPC_S1U_OBSERVATION",
        "boundary_selection_status": "NOT_APPLICABLE",
        "boundary_confidence": None,
        "first_abnormal_boundary": None,
        "candidate_boundary_count": 0,
        "source_domain_instances": [
            {
                "source_domain": "epc-procedures",
                "capture_file": stream.get("capture_file"),
                "instance_reference": reference,
            }
        ],
        "subject_link": {
            "basis": stream.get("association_basis"),
            "context_count": 1,
            "subject_reference": reference,
            "bearer_subject_reference": stream.get("matched_subject_reference"),
        },
        "attempt_index": None,
        "association_strength": stream.get("association_status"),
        "procedure_families": ["eps-s1u-observation"],
        "transaction_references": [],
        "primary_transaction": None,
        "interface_evidence": {
            "interfaces": [stream.get("user_plane_interface")],
            "basis": stream.get("interface_basis"),
            "evidence_message": None,
        },
        "direction": stream.get("direction"),
        "procedure_stages": [],
        "procedure_deviations": [],
        "request_frame": stream.get("first_frame"),
        "response_frame": stream.get("last_frame"),
        "message_cause": None,
        "bearer_contexts": [],
        "f_teid_evidence": [
            {
                "scope": "bearer",
                "endpoint_role": stream.get("matched_endpoint_role"),
                "endpoint_role_basis": stream.get("matched_endpoint_role_basis"),
                "source_protocols": [
                    item
                    for item in stream.get("matched_endpoint_source_protocols") or []
                    if isinstance(item, str)
                ],
                # Only a GTPv2-C F-TEID advertisement carries an interface type.
                "interface_type": _single_value(stream.get("matched_endpoint_interface_types") or []),
                "interface_type_name": _single_value(
                    stream.get("matched_endpoint_interface_type_names") or []
                ),
                "interface_type_basis": "matched_endpoint_advertisement",
                "teid": stream.get("teid"),
                "transport_layer_address": stream.get("outer_destination"),
                "frame_number": stream.get("matched_endpoint_frames")[0]
                if stream.get("matched_endpoint_frames")
                else None,
                "binding_basis": "gtpu_receiving_endpoint",
            }
        ]
        if stream.get("association_status") == "SUPPORTED"
        else [],
        "outcomes": [item for item in stream.get("outcomes") or [] if isinstance(item, str)],
        "observed_g_pdu_packet_count": stream.get("observed_g_pdu_packet_count"),
        "observed_payload_byte_count": stream.get("observed_payload_byte_count"),
        "byte_count_definition": stream.get("byte_count_definition"),
        "message_types": [item for item in stream.get("message_types") or [] if isinstance(item, str)],
        "error_indication_frames": stream.get("error_indication_frames") or [],
        "end_marker_frames": stream.get("end_marker_frames") or [],
        "receiving_endpoint_match_status": stream.get("receiving_endpoint_match_status"),
        "receiving_endpoint_match_basis": stream.get("receiving_endpoint_match_basis"),
        "bearer_association_status": stream.get("bearer_association_status"),
        "cross_interface_association": stream.get("association_status"),
        "attach_association": "NOT_ESTABLISHED",
        "observations": [item for item in stream.get("outcomes") or [] if isinstance(item, str)],
        "evidence_refs": evidence_refs,
        "observation_window": _bounded_observation_window(stream.get("observation_window")),
        "evidence_limitations": limitations,
        "additional_evidence_needed": [],
    }
    if references_omitted:
        entry["evidence_refs_omitted"] = references_omitted
    if limitations_omitted:
        entry["limitations_omitted"] = limitations_omitted
    return entry


def _project_bearer_lifecycle(lifecycle: Any) -> dict[str, Any] | None:
    """Bounded lifecycle-generation evidence, projected without new subjects."""
    if not isinstance(lifecycle, dict):
        return None
    families = lifecycle.get("advertisement_families") or []
    generations = lifecycle.get("lifecycle_subjects") or []
    accounting = lifecycle.get("accounting") or {}
    return {
        "analysis_name": lifecycle.get("analysis_name"),
        "analysis_version": lifecycle.get("analysis_version"),
        "advertisement_family_count": lifecycle.get("advertisement_family_count", 0),
        "advertisement_family_classifications": {
            item.get("advertisement_family_reference"): item.get("family_classification")
            for item in families[:MAX_LIST_ITEMS]
            if isinstance(item, dict)
        },
        "lifecycle_subject_count": lifecycle.get("lifecycle_subject_count", 0),
        "generations": [
            {
                "generation_reference": item.get("generation_reference"),
                "capture_file": item.get("capture_file"),
                "receiving_endpoint_role": item.get("receiving_endpoint_role"),
                "reviewed_interface_type": item.get("reviewed_interface_type"),
                "generation_state": item.get("generation_state"),
                "observations": item.get("observations") or [],
                "observation_window": item.get("observation_window"),
            }
            for item in generations[:MAX_LIST_ITEMS]
            if isinstance(item, dict)
        ],
        "generation_boundary_count": lifecycle.get("generation_boundary_count", 0),
        "release_observation_count": lifecycle.get("release_observation_count", 0),
        "endpoint_reuse_observation_count": lifecycle.get("endpoint_reuse_observation_count", 0),
        "generation_scoped_observation_count": lifecycle.get("generation_scoped_observation_count", 0),
        "unresolved_packet_observation_count": lifecycle.get(
            "unresolved_packet_observation_count", 0
        ),
        "accounting": {
            "aggregate_g_pdu_count": accounting.get("aggregate_g_pdu_count"),
            "attributed_g_pdu_count": accounting.get("attributed_g_pdu_count"),
            "unresolved_g_pdu_count": accounting.get("unresolved_g_pdu_count"),
            "aggregate_payload_octets": accounting.get("aggregate_payload_octets"),
            "attributed_payload_octets": accounting.get("attributed_payload_octets"),
            "unresolved_payload_octets": accounting.get("unresolved_payload_octets"),
            "conserved_g_pdu": accounting.get("conserved_g_pdu"),
            "conserved_payload_octets": accounting.get("conserved_payload_octets"),
        },
        "boundary_selection_status": lifecycle.get("boundary_selection_status"),
        "not_confirmed": (lifecycle.get("not_confirmed") or [])[:MAX_LIST_ITEMS],
    }


def _project_release_narrative(narrative: Any) -> dict[str, Any] | None:
    """Bounded release-narrative evidence, projected without new subjects."""
    if not isinstance(narrative, dict):
        return None
    completeness = narrative.get("source_completeness") or {}
    accounting = narrative.get("temporal_accounting") or {}
    narratives = narrative.get("release_narratives") or []
    return {
        "analysis_name": narrative.get("analysis_name"),
        "analysis_version": narrative.get("analysis_version"),
        "source_completeness_status": completeness.get("status"),
        "exhaustive_coverage_proven": completeness.get("exhaustive_coverage_proven"),
        "narrative_subject_count": narrative.get("narrative_subject_count", 0),
        "narrative_groups": sorted(
            {
                item.get("narrative_group_reference")
                for item in narrative.get("narrative_subjects") or []
                if isinstance(item, dict) and item.get("narrative_group_reference")
            }
        )[:MAX_LIST_ITEMS],
        "release_narrative_count": narrative.get("release_narrative_count", 0),
        "release_narratives": [
            {
                "release_narrative_reference": item.get("release_narrative_reference"),
                "capture_file": item.get("capture_file"),
                "release_transaction_reference": item.get("release_transaction_reference"),
                "release_request_frame": item.get("release_request_frame"),
                "release_confirmation_frame": item.get("release_confirmation_frame"),
                "release_outcome_status": item.get("release_outcome_status"),
                "release_session_binding_status": item.get(
                    "release_session_binding_status"
                ),
                "generation_closure_status": item.get("generation_closure_status"),
                "release_effective_frame_proven": item.get("release_effective_frame_proven"),
                "proved_generation_references": [
                    generation.get("generation_reference")
                    for generation in item.get("proved_generations") or []
                    if isinstance(generation, dict)
                ],
                "provenance_status": item.get("provenance_status"),
            }
            for item in narratives[:MAX_LIST_ITEMS]
            if isinstance(item, dict)
        ],
        "temporal_observation_count": narrative.get("temporal_observation_count", 0),
        "temporal_accounting": {
            "frame_level_evidence_supplied": accounting.get("frame_level_evidence_supplied"),
            "observed_g_pdu_event_count": accounting.get("observed_g_pdu_event_count"),
            "assigned_to_release_window_count": accounting.get(
                "assigned_to_release_window_count"
            ),
            "unassigned_g_pdu_event_count": accounting.get("unassigned_g_pdu_event_count"),
            "duplicate_assignment_count": accounting.get("duplicate_assignment_count"),
            "conserved": accounting.get("conserved"),
        },
        "boundary_selection_status": narrative.get("boundary_selection_status"),
        "not_confirmed": (narrative.get("not_confirmed") or [])[:MAX_LIST_ITEMS],
    }


def _project_evidence_audit(audit: Any) -> dict[str, Any] | None:
    """Bounded read-only evidence-audit summary, projected without new subjects."""
    if not isinstance(audit, dict):
        return None
    summary = audit.get("audit_summary") or {}
    completeness = audit.get("source_completeness") or {}
    references = audit.get("reference_integrity_summary") or {}
    captures = audit.get("capture_scope_summary") or {}
    temporal = audit.get("temporal_integrity_summary") or {}
    accounting = audit.get("accounting_integrity_summary") or {}
    audit_derived = accounting.get("audit_derived") or {}
    return {
        "analysis_name": audit.get("analysis_name"),
        "analysis_version": audit.get("analysis_version"),
        "overall_status": summary.get("overall_status"),
        "audit_record_count": audit.get("audit_record_count", 0),
        "audit_records_omitted": audit.get("audit_records_omitted", 0),
        "unresolved_audit_finding_count": audit.get("unresolved_audit_finding_count", 0),
        "source_completeness_status": completeness.get("status"),
        "exhaustive_coverage_proven": completeness.get("exhaustive_coverage_proven"),
        "status_counts": {
            key: value for key, value in (summary.get("status_counts") or {}).items()
        },
        "category_counts": {
            key: value for key, value in (summary.get("category_counts") or {}).items()
        },
        "reference_integrity": {
            "references_checked": references.get("references_checked"),
            "references_resolved": references.get("references_resolved"),
            "references_missing": references.get("references_missing"),
            "references_ambiguous": references.get("references_ambiguous"),
            "references_contradictory": references.get("references_contradictory"),
            "references_not_independently_verifiable": references.get(
                "references_not_independently_verifiable"
            ),
        },
        "capture_scope": {
            "capture_count": captures.get("capture_count"),
            "cross_capture_rejections": captures.get("cross_capture_rejections"),
            "cross_capture_value_collisions": captures.get(
                "cross_capture_value_collisions"
            ),
        },
        "temporal_integrity": {
            "established_placement_count": temporal.get("established_placement_count"),
            "not_established_placement_count": temporal.get(
                "not_established_placement_count"
            ),
            "conflicted_partition_count": temporal.get("conflicted_partition_count"),
            "audit_verified_placement_count": temporal.get(
                "audit_verified_placement_count"
            ),
            "missing_frame_evidence_count": temporal.get("missing_frame_evidence_count"),
            "frame_level_evidence_supplied": temporal.get("frame_level_evidence_supplied"),
        },
        "accounting_integrity": {
            "producer_counts_unchanged": audit_derived.get("source_counts_unchanged"),
            "audit_derived_g_pdu_count": audit_derived.get("gtpu_event_g_pdu_count"),
            "audit_derived_payload_octets": audit_derived.get(
                "gtpu_event_payload_octets"
            ),
            "accounting_records_verified": audit_derived.get(
                "accounting_records_verified"
            ),
            "accounting_records_inconsistent": audit_derived.get(
                "accounting_records_inconsistent"
            ),
        },
        "unresolved_audit_findings": [
            {
                "audit_record_reference": item.get("audit_record_reference"),
                "audit_category": item.get("audit_category"),
                "audit_status": item.get("audit_status"),
                "limitation": item.get("limitation"),
            }
            for item in (audit.get("unresolved_audit_findings") or [])[:MAX_LIST_ITEMS]
            if isinstance(item, dict)
        ],
        "evidence_limitations": (audit.get("evidence_limitations") or [])[:MAX_LIST_ITEMS],
        "additional_evidence_needed": (audit.get("additional_evidence_needed") or [])[
            :MAX_LIST_ITEMS
        ],
        "boundary_selection_status": audit.get("boundary_selection_status"),
        "not_confirmed": (audit.get("not_confirmed") or [])[:MAX_LIST_ITEMS],
    }


def execute_epc_domain(
    capture: Path,
    work_dir: Path,
    case_id: str,
    detection: dict[str, Any],
    pipeline: Callable[[Path, Path, str], dict[str, Any]],
) -> dict[str, Any]:
    """Run the bounded EPC Attach and session-control analyses and normalize them."""
    payload = pipeline(capture, work_dir, case_id)
    analysis = payload.get("analysis") or {}
    attach_s6a = payload.get("attach_s6a_analysis")
    attach_s6a_error = payload.get("attach_s6a_error")
    diameter_status = payload.get("diameter_status", "NOT_OBSERVED_IN_CAPTURE")
    diameter_event_count = payload.get("diameter_event_count", 0) or 0
    diameter_observation_count = payload.get("diameter_observation_count", 0) or 0
    attach_s6a_summary = _project_attach_s6a(
        attach_s6a,
        diameter_status,
        attach_s6a_error,
        diameter_event_count,
        diameter_observation_count,
    )
    session = payload.get("session_analysis")
    instances = analysis.get("procedure_instances") or []
    session_subjects = (session or {}).get("control_plane_subjects") or []
    default_bearer = payload.get("default_bearer_analysis")
    default_bearer_error = payload.get("default_bearer_error")
    default_bearer_instances = (default_bearer or {}).get("default_bearer_instances") or []
    s1u = payload.get("s1u_analysis")
    s1u_error = payload.get("s1u_error")
    s1u_streams = (s1u or {}).get("stream_observations") or []
    gtpu_event_count = payload.get("gtpu_event_count", 0) or 0
    gtpu_stream_count = payload.get("gtpu_stream_count", 0) or 0
    boundary = payload.get("boundary_analysis")
    boundary_error = payload.get("boundary_error")
    lifecycle = payload.get("lifecycle_analysis")
    lifecycle_error = payload.get("lifecycle_error")
    identity = payload.get("identity_analysis")
    identity_error = payload.get("identity_error")
    narrative = payload.get("release_narrative_analysis")
    narrative_error = payload.get("release_narrative_error")
    audit = payload.get("evidence_audit_analysis")
    audit_error = payload.get("evidence_audit_error")
    dedicated = payload.get("dedicated_bearer_analysis")
    dedicated_error = payload.get("dedicated_bearer_error")
    dedicated_summary = _project_dedicated_bearer_control(dedicated, dedicated_error)
    timeline = payload.get("dedicated_bearer_timeline_analysis")
    timeline_error = payload.get("dedicated_bearer_timeline_error")
    timeline_summary = _project_dedicated_bearer_timeline(timeline, timeline_error)
    attribution = payload.get("dedicated_bearer_attribution_analysis")
    attribution_error = payload.get("dedicated_bearer_attribution_error")
    attribution_summary = _project_dedicated_bearer_attribution(
        attribution, attribution_error
    )
    groups_by_reference: dict[str, Any] = {}
    if isinstance(boundary, dict):
        for group in boundary.get("diagnostic_groups") or []:
            if isinstance(group, dict) and isinstance(group.get("diagnostic_group_reference"), str):
                groups_by_reference[group["diagnostic_group_reference"]] = group
    attach_deviations = sum(len(instance.get("deviations") or []) for instance in instances)
    session_deviations = (session or {}).get("procedure_local_deviation_count", 0) or 0
    default_bearer_deviations = (default_bearer or {}).get("procedure_local_deviation_count", 0) or 0
    gtpv2_event_count = payload.get("gtpv2_event_count", 0) or 0
    gtpv2_transaction_count = payload.get("gtpv2_transaction_count", 0) or 0

    subjects: list[dict[str, Any]] = [
        _project_epc_subject(instance, groups_by_reference.get(instance.get("procedure_reference")))
        for instance in instances
    ]
    subjects.extend(
        _project_epc_session_subject(
            subject, session or {}, groups_by_reference.get(subject.get("subject_reference"))
        )
        for subject in session_subjects
    )
    subjects.extend(
        _project_default_bearer_subject(
            instance,
            default_bearer or {},
            groups_by_reference.get(instance.get("instance_reference")),
        )
        for instance in default_bearer_instances
    )
    s1u_subjects = [_project_s1u_subject(stream, s1u or {}) for stream in s1u_streams]
    # A stream is attached to a default-bearer subject only when the corrected
    # receiving-endpoint contract publishes a supported association.
    stream_refs_by_subject: dict[str, list[str]] = {}
    for subject in s1u_subjects:
        bearer = (subject.get("subject_link") or {}).get("bearer_subject_reference")
        if isinstance(bearer, str) and subject.get("association_strength") == "SUPPORTED":
            stream_refs_by_subject.setdefault(bearer, []).append(
                subject["diagnostic_group_reference"]
            )
    for subject in subjects:
        if subject.get("subject_type") != "EPS_DEFAULT_BEARER":
            continue
        references = stream_refs_by_subject.get(subject["diagnostic_group_reference"])
        if references:
            subject["s1u_stream_references"] = references[:MAX_LIST_ITEMS]
    subjects.extend(s1u_subjects)
    omitted_subjects = max(0, len(subjects) - MAX_DIAGNOSTIC_SUBJECTS)
    subjects = subjects[:MAX_DIAGNOSTIC_SUBJECTS]

    if (
        boundary_error
        or default_bearer_error
        or s1u_error
        or lifecycle_error
        or identity_error
        or narrative_error
        or audit_error
    ) and (
        instances or session_subjects or default_bearer_instances or s1u_subjects
    ):
        status = STATUS_PARTIAL
    elif instances or session_subjects or default_bearer_instances or s1u_subjects:
        status = STATUS_COMPLETED
    else:
        status = STATUS_INSUFFICIENT_EVIDENCE
    if dedicated_error or timeline_error or attribution_error or attach_s6a_error:
        status = (
            STATUS_PARTIAL
            if (
                instances
                or session_subjects
                or default_bearer_instances
                or s1u_subjects
                or gtpv2_transaction_count
            )
            else STATUS_FAILED
        )

    boundary_evaluated = isinstance(boundary, dict) and not boundary_error
    limitations: list[str] = [
        item
        for item in (analysis.get("limitations") or [])
        if not (boundary_evaluated and isinstance(item, str) and item.startswith(STALE_EPC_BOUNDARY_NOTE))
    ]
    if boundary_evaluated:
        limitations.append(
            "EPC boundary selection is evaluated per diagnostic subject; independent Attach, S11 "
            "and S5/S8 subjects keep separate boundaries and no single global EPC boundary is asserted."
        )
    additional: list[str] = list(analysis.get("additional_evidence_needed") or [])
    if isinstance(session, dict):
        limitations.extend(session.get("evidence_limitations") or [])
        additional.extend(session.get("additional_evidence_needed") or [])
    if isinstance(default_bearer, dict):
        limitations.extend(default_bearer.get("evidence_limitations") or [])
        additional.extend(default_bearer.get("additional_evidence_needed") or [])
    if isinstance(s1u, dict):
        limitations.extend(s1u.get("evidence_limitations") or [])
        additional.extend(s1u.get("additional_evidence_needed") or [])
    if isinstance(lifecycle, dict):
        limitations.extend(lifecycle.get("evidence_limitations") or [])
        additional.extend(lifecycle.get("additional_evidence_needed") or [])
    if isinstance(narrative, dict):
        limitations.extend(narrative.get("evidence_limitations") or [])
        additional.extend(narrative.get("additional_evidence_needed") or [])
    if isinstance(audit, dict):
        limitations.extend(audit.get("evidence_limitations") or [])
        additional.extend(audit.get("additional_evidence_needed") or [])
    if isinstance(dedicated, dict):
        limitations.extend(dedicated.get("evidence_limitations") or [])
    bounded_limitations, _ = _bounded_limitations(list(dict.fromkeys(limitations)))
    bounded_additional, _ = _bounded_limitations(list(dict.fromkeys(additional)))

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
            {
                "protocol": "GTPv2-C",
                "extraction_status": EXTRACTION_SUCCESS if gtpv2_event_count else EXTRACTION_NOT_OBSERVED,
                "observed_in_capture": gtpv2_event_count > 0,
                "event_count": gtpv2_event_count,
                "transaction_count": gtpv2_transaction_count,
            },
            {
                "protocol": "GTP-U",
                "extraction_status": EXTRACTION_SUCCESS if gtpu_event_count else EXTRACTION_NOT_OBSERVED,
                "observed_in_capture": gtpu_event_count > 0,
                "event_count": gtpu_event_count,
                "stream_count": gtpu_stream_count,
            },
        ],
        "procedure_summaries": [
            {
                "procedure_domain": "epc-procedures",
                "procedure": "eps-attach",
                "execution_status": "EXECUTED",
                "instance_count": len(instances),
                "deviation_count": attach_deviations,
            },
            {
                "procedure_domain": "epc-procedures",
                "procedure": "epc-attach-s6a-joint",
                "execution_status": attach_s6a_summary.get("execution_status"),
                "instance_count": attach_s6a_summary.get("attach_instance_count", 0),
                "incomplete_attach_instance_count": attach_s6a_summary.get(
                    "attach_incomplete_instance_count", 0
                ),
                "diameter_observation_count": attach_s6a_summary.get(
                    "diameter_observation_count", 0
                ),
                "diameter_matched_count": attach_s6a_summary.get(
                    "diameter_matched_count", 0
                ),
                "identity_association_status": attach_s6a_summary.get(
                    "identity_association_status"
                ),
                "common_capture_status": attach_s6a_summary.get("common_capture_status"),
                "timeline_row_count": attach_s6a_summary.get("timeline_row_count", 0),
                "timeline_source_row_count": attach_s6a_summary.get(
                    "timeline_source_row_count", 0
                ),
                "timeline_rows_omitted": attach_s6a_summary.get(
                    "timeline_rows_omitted", 0
                ),
            },
            {
                "procedure_domain": "epc-procedures",
                "procedure": "epc-session-control",
                "execution_status": "EXECUTED" if session_subjects else "NO_SUBJECT",
                "instance_count": len(session_subjects),
                "transaction_count": gtpv2_transaction_count,
                "deviation_count": session_deviations,
            },
            {
                "procedure_domain": "epc-procedures",
                "procedure": "eps-default-bearer",
                "execution_status": "EXECUTED" if default_bearer_instances else "NO_SUBJECT",
                "instance_count": len(default_bearer_instances),
                "esm_observation_count": (default_bearer or {}).get("esm_observation_count", 0),
                "erab_observation_count": (default_bearer or {}).get("s1_erab_observation_count", 0),
                "established_link_count": sum(
                    1
                    for instance in default_bearer_instances
                    for link in (instance or {}).get("tunnel_links") or []
                    if isinstance(link, dict) and link.get("status") == "SUPPORTED"
                ),
                "deviation_count": default_bearer_deviations,
            },
            {
                "procedure_domain": "epc-procedures",
                "procedure": "eps-s1u-observation",
                "execution_status": "EXECUTED" if s1u_subjects else "NO_SUBJECT",
                "instance_count": len(s1u_subjects),
                "stream_count": gtpu_stream_count,
                "supported_stream_count": (s1u or {}).get("supported_stream_count", 0),
                "ambiguous_stream_count": (s1u or {}).get("ambiguous_stream_count", 0),
                "unbound_stream_count": (s1u or {}).get("unbound_stream_count", 0),
                "observed_g_pdu_packet_count": (s1u or {}).get("observed_g_pdu_packet_count", 0),
            },
            {
                "procedure_domain": "epc-procedures",
                "procedure": "epc-session-identity",
                "execution_status": (
                    "EXECUTED"
                    if isinstance(identity, dict) and identity.get("hop_local_context_count")
                    else "NO_SUBJECT"
                ),
                "instance_count": (identity or {}).get("hop_local_context_count", 0),
                "established_context_count": (identity or {}).get(
                    "established_hop_local_context_count", 0
                ),
                "endpoint_correspondence_count": (identity or {}).get(
                    "endpoint_correspondence_count", 0
                ),
                "session_identity_count": (identity or {}).get("session_identity_count", 0),
                "release_session_binding_count": (identity or {}).get(
                    "release_session_binding_count", 0
                ),
                "generation_closure_candidate_count": (identity or {}).get(
                    "generation_closure_candidate_count", 0
                ),
            },
            {
                "procedure_domain": "epc-procedures",
                "procedure": "epc-release-narrative",
                "execution_status": (
                    "EXECUTED"
                    if isinstance(narrative, dict) and narrative.get("release_narrative_count")
                    else "NO_SUBJECT"
                ),
                "instance_count": (narrative or {}).get("release_narrative_count", 0),
                "narrative_subject_count": (narrative or {}).get("narrative_subject_count", 0),
                "temporal_observation_count": (narrative or {}).get(
                    "temporal_observation_count", 0
                ),
                "accepted_release_count": sum(
                    1
                    for item in (narrative or {}).get("release_narratives") or []
                    if isinstance(item, dict)
                    and item.get("release_outcome_status") == "ACCEPTED"
                ),
                "established_binding_count": sum(
                    1
                    for item in (narrative or {}).get("release_narratives") or []
                    if isinstance(item, dict)
                    and item.get("release_session_binding_status") == "ESTABLISHED"
                ),
                "proved_generation_closure_count": sum(
                    len(item.get("proved_generations") or [])
                    for item in (narrative or {}).get("release_narratives") or []
                    if isinstance(item, dict)
                ),
            },
            {
                "procedure_domain": "epc-procedures",
                "procedure": "epc-evidence-audit",
                "execution_status": (
                    "EXECUTED"
                    if isinstance(audit, dict) and audit.get("audit_record_count")
                    else "NO_SUBJECT"
                ),
                "instance_count": (audit or {}).get("audit_record_count", 0),
                "overall_audit_status": ((audit or {}).get("audit_summary") or {}).get(
                    "overall_status"
                ),
                "inconsistent_count": ((audit or {}).get("audit_summary") or {}).get(
                    "inconsistent_count", 0
                ),
                "ambiguous_count": ((audit or {}).get("audit_summary") or {}).get(
                    "ambiguous_count", 0
                ),
                "unresolved_audit_finding_count": (audit or {}).get(
                    "unresolved_audit_finding_count", 0
                ),
                "source_completeness_status": ((audit or {}).get("source_completeness") or {}).get(
                    "status"
                ),
            },
            {
                "procedure_domain": "epc-procedures",
                "procedure": "epc-dedicated-bearer-control",
                "execution_status": (
                    "EXECUTED"
                    if isinstance(dedicated, dict)
                    else "FAILED"
                    if dedicated_error
                    else "NO_SUBJECT"
                ),
                "instance_count": dedicated_summary.get("control_transaction_count", 0),
                "create_bearer_transaction_count": (
                    dedicated_summary.get("transaction_family_counts") or {}
                ).get("create-bearer", 0),
                "update_bearer_transaction_count": (
                    dedicated_summary.get("transaction_family_counts") or {}
                ).get("update-bearer", 0),
                "delete_bearer_transaction_count": (
                    dedicated_summary.get("transaction_family_counts") or {}
                ).get("delete-bearer", 0),
                "bearer_item_observation_count": dedicated_summary.get(
                    "bearer_item_observation_count", 0
                ),
                "item_association_count": dedicated_summary.get(
                    "item_association_count", 0
                ),
                "source_completeness_status": dedicated_summary.get(
                    "source_completeness_status"
                ),
            },
            {
                "procedure_domain": "epc-procedures",
                "procedure": "epc-dedicated-bearer-timeline",
                "execution_status": (
                    "EXECUTED"
                    if isinstance(timeline, dict)
                    and timeline.get("execution_status") == "EXECUTED"
                    else "FAILED"
                    if timeline_error
                    else "NO_SUBJECT"
                ),
                "instance_count": timeline_summary.get("entry_count", 0),
                "omitted_entry_count": timeline_summary.get("omitted_entry_count", 0),
                "association_status_counts": timeline_summary.get(
                    "association_status_counts", {}
                ),
                "unresolved_evidence_count": timeline_summary.get(
                    "unresolved_evidence_count", 0
                ),
                "nas_source_present": _dict((timeline or {}).get("source_completeness")).get(
                    "nas_source_present"
                ),
                "s1ap_source_present": _dict((timeline or {}).get("source_completeness")).get(
                    "s1ap_source_present"
                ),
                "source_completeness_status": timeline_summary.get(
                    "source_completeness_status"
                ),
            },
            {
                "procedure_domain": "epc-procedures",
                "procedure": "epc-dedicated-bearer-attribution",
                "execution_status": (
                    "EXECUTED"
                    if isinstance(attribution, dict)
                    and attribution.get("execution_status") == "EXECUTED"
                    else "FAILED"
                    if attribution_error
                    else "NO_SUBJECT"
                ),
                "instance_count": attribution_summary.get("entry_count", 0),
                "omitted_entry_count": attribution_summary.get(
                    "omitted_entry_count", 0
                ),
                "overall_status_counts": attribution_summary.get(
                    "overall_status_counts", {}
                ),
                "established_link_counts": attribution_summary.get(
                    "established_link_counts", {}
                ),
                "unresolved_evidence_count": attribution_summary.get(
                    "unresolved_evidence_count", 0
                ),
                "source_completeness_status": attribution_summary.get(
                    "source_completeness_status"
                ),
            },
            {
                "procedure_domain": "epc-procedures",
                "procedure": "eps-bearer-lifecycle",
                "execution_status": (
                    "EXECUTED"
                    if isinstance(lifecycle, dict) and lifecycle.get("lifecycle_subject_count")
                    else "NO_SUBJECT"
                ),
                "instance_count": (lifecycle or {}).get("lifecycle_subject_count", 0),
                "advertisement_family_count": (lifecycle or {}).get("advertisement_family_count", 0),
                "generation_boundary_count": (lifecycle or {}).get("generation_boundary_count", 0),
                "endpoint_reuse_observation_count": (lifecycle or {}).get(
                    "endpoint_reuse_observation_count", 0
                ),
                "generation_scoped_observation_count": (lifecycle or {}).get(
                    "generation_scoped_observation_count", 0
                ),
                "unresolved_packet_observation_count": (lifecycle or {}).get(
                    "unresolved_packet_observation_count", 0
                ),
                "deviation_count": (lifecycle or {}).get("procedure_local_deviation_count", 0),
            },
        ],
        "diagnostic_groups": None,
        "diagnostic_subject_count": len(subjects),
        "diagnostic_subjects": subjects,
        "first_abnormal_boundary": None,
        "boundary_selection_status": (
            "EVALUATED_PER_SUBJECT"
            if isinstance(boundary, dict) and not boundary_error
            else "NOT_EVALUATED"
        ),
        "boundary_summary": _boundary_summary(boundary) if not boundary_error else None,
        "first_abnormal_boundary_reason": (
            "each diagnostic subject keeps its own boundary; no single global EPC boundary is asserted"
            if isinstance(boundary, dict) and not boundary_error
            else None
        ),
        "bearer_lifecycle": _project_bearer_lifecycle(lifecycle),
        "release_narrative": _project_release_narrative(narrative),
        "evidence_audit": _project_evidence_audit(audit),
        "dedicated_bearer_control": dedicated_summary,
        "dedicated_bearer_timeline": timeline_summary,
        "dedicated_bearer_attribution": attribution_summary,
        "attach_s6a": attach_s6a_summary,
        "evidence_limitations": bounded_limitations,
        "additional_evidence_needed": bounded_additional,
        "degradation": [],
    }

    degradation: list[str] = []
    if not instances:
        degradation.append(
            "no EPS Attach procedure instance was reconstructed from the observed evidence"
        )
    if not session_subjects:
        degradation.append(
            "no GTPv2-C session-control subject was reconstructed from the observed evidence"
        )
    if not default_bearer_instances:
        degradation.append(
            "no EPS default-bearer subject was reconstructed from the observed evidence"
        )
    if not s1u_subjects:
        degradation.append(
            "no S1-U GTP-U stream was observed in the capture; user-plane packets are not inferred"
        )
    if omitted_subjects:
        degradation.append(
            f"{omitted_subjects} diagnostic subject(s) were omitted by the publication cap"
        )
    if s1u_error:
        result["failure_code"] = "S1U_OBSERVATION_FAILED"
        degradation.append(
            "EPC S1-U observation failed: "
            f"{s1u_error.get('code')} {s1u_error.get('message')}".strip()
        )
    if default_bearer_error:
        result["failure_code"] = "DEFAULT_BEARER_FAILED"
        degradation.append(
            "EPC default-bearer analysis failed: "
            f"{default_bearer_error.get('code')} {default_bearer_error.get('message')}".strip()
        )
    if identity_error:
        result["failure_code"] = "SESSION_IDENTITY_FAILED"
        degradation.append(
            "EPC session-identity analysis failed: "
            f"{identity_error.get('code')} {identity_error.get('message')}".strip()
        )
    if boundary_error:
        result["failure_code"] = "ORCHESTRATION_FAILED"
        degradation.append(
            "EPC failure-boundary orchestration failed: "
            f"{boundary_error.get('code')} {boundary_error.get('message')}".strip()
        )
    if lifecycle_error:
        result["failure_code"] = "BEARER_LIFECYCLE_FAILED"
        degradation.append(
            "EPC bearer lifecycle analysis failed: "
            f"{lifecycle_error.get('code')} {lifecycle_error.get('message')}".strip()
        )
    if narrative_error:
        result["failure_code"] = "RELEASE_NARRATIVE_FAILED"
        degradation.append(
            "EPC release narrative failed: "
            f"{narrative_error.get('code')} {narrative_error.get('message')}".strip()
            + "; earlier EPC evidence is preserved and no EPC protocol failure is asserted"
        )
    if dedicated_error:
        result["failure_code"] = DEDICATED_BEARER_FAILURE_CODE
        degradation.append(
            "EPC dedicated-bearer control analysis failed: "
            f"{dedicated_error.get('code')} {dedicated_error.get('message')}".strip()
            + "; earlier EPC evidence is preserved and a failed observed component is never reported COMPLETED"
        )
    if attribution_error:
        result["failure_code"] = DEDICATED_BEARER_ATTRIBUTION_FAILURE_CODE
        degradation.append(
            "EPC dedicated-bearer attribution failed: "
            f"{attribution_error.get('code')} {attribution_error.get('message')}".strip()
            + "; the control and timeline artifacts are preserved and the attribution failure is not hidden"
        )
    if timeline_error:
        result["failure_code"] = DEDICATED_BEARER_TIMELINE_FAILURE_CODE
        degradation.append(
            "EPC dedicated-bearer timeline failed: "
            f"{timeline_error.get('code')} {timeline_error.get('message')}".strip()
            + "; the accepted control artifact is preserved and the timeline failure is not hidden"
        )
    if audit_error:
        result["failure_code"] = "EVIDENCE_AUDIT_FAILED"
        degradation.append(
            "EPC evidence audit failed: "
            f"{audit_error.get('code')} {audit_error.get('message')}".strip()
            + "; every producer artifact is preserved, no EPC protocol failure is asserted "
            "and an audit failure is not a network failure"
        )
    if attach_s6a_error:
        result["failure_code"] = "ATTACH_S6A_JOINT_ANALYSIS_FAILED"
        degradation.append(
            "EPC Attach/S6a joint analysis failed: "
            f"{attach_s6a_error.get('code')} {attach_s6a_error.get('message')}".strip()
            + "; EPS Attach and Diameter evidence are preserved and the joint limitation is not hidden"
        )
    result["degradation"] = degradation
    return result



# ---------------------------------------------------------------------------
# IMS execution adapter
# ---------------------------------------------------------------------------


def _ims_stage(command: list[str], label: str) -> tuple[int, str]:
    """Run one accepted IMS component without converting its exit code to a verdict."""
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        return EXIT_FAILED, f"{label} could not start: {exc}"
    detail = (completed.stderr or completed.stdout or "").strip().splitlines()
    return completed.returncode, scrub_free_text(detail[0] if detail else "")


def _ims_status(returncode: int, *, empty_code: int | None = None) -> str:
    if returncode == 0:
        return "SUCCESS"
    if empty_code is not None and returncode == empty_code:
        return "NOT_OBSERVED_IN_CAPTURE"
    return "FAILED"


def _load_ims_json(path: Path, label: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"{label} output is unreadable: {exc}"
    if not isinstance(payload, dict):
        return None, f"{label} output is not an object"
    return payload, None


def _ims_registration_evidence(document: dict[str, Any] | None) -> dict[str, Any]:
    if document is None:
        return {
            "analysis_status": "FAILED",
            "attempt_count": 0,
            "attempt_references": [],
            "registration_types": [],
            "cross_protocol_association": "NOT_ESTABLISHED",
        }
    attempts = [item for item in document.get("registration_attempts") or [] if isinstance(item, dict)]
    return {
        "analysis_status": "COMPLETED" if attempts else "INSUFFICIENT_EVIDENCE",
        "attempt_count": len(attempts),
        "attempt_references": [
            item["attempt_reference"]
            for item in attempts[:MAX_IMS_REFERENCES]
            if isinstance(item.get("attempt_reference"), str)
        ],
        "registration_types": sorted(
            {
                str(item.get("registration_type"))
                for item in attempts
                if item.get("registration_type")
            }
        ),
        "cross_protocol_association": "NOT_ESTABLISHED",
    }


def _ims_session_evidence(document: dict[str, Any] | None) -> dict[str, Any]:
    if document is None:
        return {
            "analysis_status": "FAILED",
            "attempt_count": 0,
            "early_dialog_count": 0,
            "confirmed_dialog_count": 0,
            "cancel_observation_count": 0,
            "bye_release_observation_count": 0,
            "attempt_references": [],
            "limitations": [],
        }
    attempts = [item for item in document.get("session_attempts") or [] if isinstance(item, dict)]
    early: set[str] = set()
    confirmed: set[str] = set()
    cancel_count = 0
    bye_count = 0
    for attempt in attempts:
        stages = attempt.get("stage_evidence") or {}
        early.update(
            ref for ref in stages.get("early_dialog_references") or [] if isinstance(ref, str)
        )
        confirmed.update(
            ref for ref in stages.get("confirmed_dialog_references") or [] if isinstance(ref, str)
        )
        cancel = attempt.get("cancel_evidence") or {}
        if cancel.get("outcome") not in (None, "NO_CANCEL_OBSERVED"):
            cancel_count += 1
        for branch in attempt.get("branches") or []:
            for observation in (branch.get("release") or {}).get("observations") or []:
                if observation.get("bye_transaction_reference"):
                    bye_count += 1
    return {
        "analysis_status": "COMPLETED" if attempts else "INSUFFICIENT_EVIDENCE",
        "attempt_count": len(attempts),
        "early_dialog_count": len(early),
        "confirmed_dialog_count": len(confirmed),
        "cancel_observation_count": cancel_count,
        "bye_release_observation_count": bye_count,
        "attempt_references": [
            item["attempt_reference"]
            for item in attempts[:MAX_IMS_REFERENCES]
            if isinstance(item.get("attempt_reference"), str)
        ],
        "limitations": list(document.get("limitations") or []),
    }


def execute_ims_pipeline(
    capture: Path,
    work_dir: Path,
    case_id: str,
    observed: set[str] | None = None,
    *,
    with_media: bool = False,
    offline: bool = False,
    endpoint_key_file: Path | None = None,
) -> dict[str, Any]:
    """Execute the accepted SIP, Diameter and IMS Domain components.

    Every stage keeps its own status. A failed Diameter or Domain stage never
    discards a valid independent SIP or Diameter result.
    """
    observed_set = observed or set()
    run_dir = create_run_directory(work_dir, DOMAIN_IMS)
    sip_events = run_dir / "sip-events.jsonl"
    sip_transactions = run_dir / "sip-transactions.json"
    sip_dialogs = run_dir / "sip-dialogs.json"
    sip_trace = run_dir / "sip-trace.jsonl"
    diameter_events = run_dir / "diameter-events.jsonl"
    diameter_trace = run_dir / "diameter-trace.jsonl"
    diameter_transactions = run_dir / "diameter-transactions.json"
    diameter_ims = run_dir / "diameter-ims-analysis.json"
    diameter_ims_timeline = run_dir / "diameter-ims-timeline.txt"
    registration = run_dir / "ims-registration-analysis.json"
    registration_report = run_dir / "ims-registration-report.txt"
    session = run_dir / "ims-session-analysis.json"
    session_report = run_dir / "ims-session-report.txt"

    degradation: list[str] = []
    limitations: list[str] = []
    sip_status = "NOT_OBSERVED_IN_CAPTURE"
    sip_error: str | None = None
    sip_counts = {"event_count": 0, "transaction_count": 0, "dialog_count": 0}
    sip_executions = 0
    if "SIP" in observed_set:
        sip_executions += 1
        code, detail = _ims_stage(
            [
                sys.executable,
                str(SIP_EXTRACT_SCRIPT),
                str(capture),
                "--input-format",
                "capture",
                "--output",
                str(sip_events),
                "--transaction-output",
                str(sip_transactions),
                "--dialog-output",
                str(sip_dialogs),
                "--trace-output",
                str(sip_trace),
                "--force",
            ],
            "SIP extractor",
        )
        if code == 0:
            if not sip_events.is_file() or not sip_transactions.is_file() or not sip_dialogs.is_file():
                sip_status = "FAILED"
                sip_error = "SIP extractor reported success but did not publish all expected artifacts"
            else:
                transaction_document, error = _load_ims_json(sip_transactions, "SIP transaction")
                dialog_document, dialog_error = _load_ims_json(sip_dialogs, "SIP dialog")
                if error or dialog_error:
                    sip_status = "FAILED"
                    sip_error = error or dialog_error
                else:
                    sip_status = "SUCCESS"
                    sip_counts = {
                        "event_count": _count_lines(sip_events),
                        "transaction_count": int(transaction_document.get("transaction_count") or 0),
                        "dialog_count": int(dialog_document.get("dialog_count") or 0),
                    }
        elif code == 3:
            sip_status = "NO_PLAINTEXT_EVENTS"
            sip_error = "SIP was observed in the capture inventory but no plaintext SIP messages were extracted"
        else:
            sip_status = "FAILED"
            sip_error = detail or f"SIP extractor exited with {code}"
        if sip_status == "FAILED":
            degradation.append(f"SIP extraction failed: {sip_error}")
    else:
        limitations.append("SIP was not observed in the capture inventory; SIP extraction was not run.")

    # IMS Registration performs its own accepted SIP extraction against the original
    # capture; this second execution is reported explicitly rather than hidden.
    registration_evidence = {
        "analysis_status": "NOT_RUN",
        "attempt_count": 0,
        "attempt_references": [],
        "registration_types": [],
        "cross_protocol_association": "NOT_ESTABLISHED",
    }
    registration_error: str | None = None
    diameter_ims_supplied = False
    registration_command = [
        sys.executable,
        str(IMS_REGISTRATION_ANALYZE_SCRIPT),
        "--sip-input",
        str(capture),
        "--input-format",
        "capture",
        "--output",
        str(registration),
        "--report",
        str(registration_report),
        "--force",
    ]

    # Diameter extraction and Cx/Dx analysis.
    diameter_status = "NOT_OBSERVED_IN_CAPTURE"
    diameter_error: str | None = None
    diameter_counts = {"event_count": 0, "transaction_count": 0, "observation_count": 0}
    diameter_ims_evidence: dict[str, Any] = {
        "analysis_status": "NOT_OBSERVED_IN_CAPTURE",
        "observation_count": 0,
    }
    if "Diameter" in observed_set:
        code, detail = _ims_stage(
            [
                sys.executable,
                str(DIAMETER_CORE_EXTRACT_SCRIPT),
                str(capture),
                "--input-format",
                "capture",
                "--output",
                str(diameter_events),
                "--trace-output",
                str(diameter_trace),
                "--force",
            ],
            "Diameter Core extractor",
        )
        if code == 0 and diameter_events.is_file():
            diameter_status = "SUCCESS"
            diameter_counts["event_count"] = _count_lines(diameter_events)
            code, detail = _ims_stage(
                [
                    sys.executable,
                    str(DIAMETER_CORE_CORRELATE_SCRIPT),
                    str(diameter_events),
                    "--output",
                    str(diameter_transactions),
                    "--force",
                ],
                "Diameter Core correlator",
            )
            if code == 0 and diameter_transactions.is_file():
                correlation, error = _load_ims_json(diameter_transactions, "Diameter transaction")
                if error:
                    diameter_status = "FAILED"
                    diameter_error = error
                else:
                    diameter_status = "SUCCESS"
                    diameter_counts["transaction_count"] = int(
                        (correlation or {}).get("transaction_count") or 0
                    )
            else:
                diameter_status = "FAILED"
                diameter_error = detail or f"Diameter Core correlator exited with {code}"
        elif code == 3:
            diameter_status = "NO_PLAINTEXT_EVENTS"
            diameter_error = "Diameter was observed but no plaintext Diameter messages were extracted"
        else:
            diameter_status = "FAILED"
            diameter_error = detail or f"Diameter Core extractor exited with {code}"

        if diameter_status == "SUCCESS":
            code, detail = _ims_stage(
                [
                    sys.executable,
                    str(DIAMETER_IMS_ANALYZE_SCRIPT),
                    "--events",
                    str(diameter_events),
                    "--transactions",
                    str(diameter_transactions),
                    "--output",
                    str(diameter_ims),
                    "--timeline-output",
                    str(diameter_ims_timeline),
                    "--force",
                ],
                "Diameter IMS analyzer",
            )
            if code == 0 and diameter_ims.is_file():
                document, error = _load_ims_json(diameter_ims, "Diameter IMS analysis")
                if error:
                    diameter_ims_evidence = {"analysis_status": "FAILED", "observation_count": 0}
                    diameter_error = error
                else:
                    if document is not None:
                        completeness = document.get("completeness") or {}
                        count = int(completeness.get("observation_count") or len(document.get("observations") or []))
                    else:
                        count = 0
                    diameter_counts["observation_count"] = count
                    diameter_ims_evidence = {
                        "analysis_status": "COMPLETED" if count else "NO_CXD_OBSERVATIONS",
                        "observation_count": count,
                        "analysis_reference": "diameter-ims-analysis.json",
                    }
                    if count:
                        diameter_ims_supplied = True
            elif code == 3:
                diameter_ims_evidence = {
                    "analysis_status": "NO_CXD_OBSERVATIONS",
                    "observation_count": 0,
                }
            else:
                diameter_ims_evidence = {
                    "analysis_status": "FAILED",
                    "observation_count": 0,
                }
                diameter_error = detail or f"Diameter IMS analyzer exited with {code}"
        if diameter_status == "FAILED" or diameter_ims_evidence.get("analysis_status") == "FAILED":
            degradation.append(f"Diameter IMS evidence unavailable: {diameter_error}")
    else:
        limitations.append("Diameter was not observed in the capture inventory; Cx/Dx analysis was not run.")

    if diameter_ims_supplied:
        registration_command.extend(["--diameter-ims", str(diameter_ims)])

    if sip_status == "SUCCESS":
        code, detail = _ims_stage(registration_command, "IMS Registration analyzer")
        if code == 0:
            document, error = _load_ims_json(registration, "IMS Registration")
            if error or document is None:
                registration_evidence["analysis_status"] = "FAILED"
                registration_error = error or "IMS Registration produced no analysis object"
            else:
                registration_evidence = _ims_registration_evidence(document)
        else:
            registration_evidence["analysis_status"] = "FAILED"
            registration_error = detail or f"IMS Registration analyzer exited with {code}"
        if registration_evidence["analysis_status"] == "FAILED":
            degradation.append(f"IMS Registration analysis failed: {registration_error}")
    else:
        registration_evidence["analysis_status"] = "UNAVAILABLE_SIP"
        limitations.append("IMS Registration did not run because no accepted SIP evidence was available.")

    session_evidence = {
        "analysis_status": "NOT_RUN",
        "attempt_count": 0,
        "early_dialog_count": 0,
        "confirmed_dialog_count": 0,
        "cancel_observation_count": 0,
        "bye_release_observation_count": 0,
        "attempt_references": [],
        "limitations": [],
    }
    session_error: str | None = None
    if sip_status == "SUCCESS":
        code, detail = _ims_stage(
            [
                sys.executable,
                str(IMS_SESSION_ANALYZE_SCRIPT),
                "--sip-events",
                str(sip_events),
                "--sip-transactions",
                str(sip_transactions),
                "--sip-dialogs",
                str(sip_dialogs),
                "--output",
                str(session),
                "--report",
                str(session_report),
                "--force",
            ],
            "IMS Session analyzer",
        )
        if code == 0:
            document, error = _load_ims_json(session, "IMS Session")
            if error or document is None:
                session_evidence = {**session_evidence, "analysis_status": "FAILED"}
                session_error = error or "IMS Session produced no analysis object"
            else:
                session_evidence = _ims_session_evidence(document)
        else:
            session_evidence = {**session_evidence, "analysis_status": "FAILED"}
            session_error = detail or f"IMS Session analyzer exited with {code}"
        if session_evidence["analysis_status"] == "FAILED":
            degradation.append(f"IMS Session analysis failed: {session_error}")
    else:
        session_evidence["analysis_status"] = "UNAVAILABLE_SIP"
        limitations.append("IMS Session did not run because no accepted SIP event artifacts were available.")

    media_evidence: dict[str, Any] = {
        "requested": bool(with_media),
        "media_status": "NOT_REQUESTED" if not with_media else "INSUFFICIENT_EVIDENCE",
        "offline": bool(offline),
    }
    media_error: str | None = None
    if with_media:
        if not (sip_status == "SUCCESS" and sip_events.is_file()):
            media_evidence = {
                "requested": True,
                "media_status": "UNSUPPORTED",
                "offline": bool(offline),
                "reason": "SIP plaintext events are unavailable for SDP extraction",
            }
            limitations.append(
                "IMS media analysis was requested but no accepted plaintext SIP event artifact was available."
            )
        elif not session.is_file():
            media_evidence = {
                "requested": True,
                "media_status": "UNSUPPORTED",
                "offline": bool(offline),
                "reason": "IMS Session analysis is unavailable for media composition",
            }
            limitations.append(
                "IMS media analysis was requested but the accepted IMS Session artifact was unavailable."
            )
        else:
            try:
                media_evidence = ims_media_pipeline.execute_media_pipeline(
                    capture=capture,
                    run_dir=run_dir,
                    sip_events=sip_events,
                    ims_session=session,
                    capture_sha256=capture_digest(capture),
                    offline=offline,
                    endpoint_key_file=endpoint_key_file,
                )
            except Exception as exc:  # pragma: no cover - defensive orchestration guard
                media_error = scrub_free_text(str(exc)) or "media pipeline failed"
                media_evidence = {
                    "requested": True,
                    "media_status": "FAILED",
                    "offline": bool(offline),
                    "stage_errors": {"media_pipeline": media_error},
                }
                degradation.append(f"IMS media pipeline failed: {media_error}")
            limitations.extend(media_evidence.get("limitations") or [])
            for stage, error in (media_evidence.get("stage_errors") or {}).items():
                degradation.append(f"Media stage {stage} failed: {error}")

    registration_status = registration_evidence["analysis_status"]
    session_status = session_evidence["analysis_status"]
    usable_registration = registration_status in ("COMPLETED", "INSUFFICIENT_EVIDENCE")
    usable_session = session_status in ("COMPLETED", "INSUFFICIENT_EVIDENCE")
    diameter_usable = diameter_counts["observation_count"] > 0
    failed_stages = [
        (label, status)
        for label, status in (
            ("SIP extraction", sip_status),
            ("Diameter extraction", diameter_status),
            ("Diameter IMS analysis", diameter_ims_evidence.get("analysis_status")),
            ("IMS Registration", registration_status),
            ("IMS Session", session_status),
        )
        if status == "FAILED"
    ]
    if (registration_status == "FAILED" and session_status == "FAILED" and not diameter_usable):
        execution_status = STATUS_FAILED
    elif sip_status == "FAILED" and not diameter_usable:
        execution_status = STATUS_FAILED
    elif failed_stages:
        execution_status = STATUS_PARTIAL
    elif usable_registration or usable_session or diameter_usable:
        attempts = registration_evidence["attempt_count"] + session_evidence["attempt_count"]
        execution_status = STATUS_COMPLETED if attempts or diameter_usable else STATUS_INSUFFICIENT_EVIDENCE
    else:
        execution_status = STATUS_INSUFFICIENT_EVIDENCE

    media_status = media_evidence.get("media_status")
    if with_media:
        if media_status == "FAILED":
            if execution_status == STATUS_COMPLETED:
                execution_status = STATUS_PARTIAL
        elif media_status != "SUCCESS":
            if execution_status == STATUS_COMPLETED:
                execution_status = STATUS_PARTIAL
            elif execution_status == STATUS_FAILED:
                execution_status = STATUS_FAILED
    protocol_evidence = [
        {
            "protocol": "SIP",
            "extraction_status": sip_status,
            "event_count": sip_counts["event_count"],
            "transaction_count": sip_counts["transaction_count"],
            "dialog_count": sip_counts["dialog_count"],
        },
        {
            "protocol": "Diameter",
            "extraction_status": diameter_status,
            "event_count": diameter_counts["event_count"],
            "transaction_count": diameter_counts["transaction_count"],
            "observation_count": diameter_counts["observation_count"],
        },
    ]
    procedure_summaries = [
        {
            "procedure_domain": "ims-registration",
            "execution_status": registration_status,
            "instance_count": registration_evidence["attempt_count"],
        },
        {
            "procedure_domain": "ims-session",
            "execution_status": session_status,
            "instance_count": session_evidence["attempt_count"],
        },
    ]
    if with_media:
        media_stages = media_evidence.get("stage_statuses") or {}
        procedure_summaries.extend(
            [
                {
                    "procedure_domain": "ims-media-signaling",
                    "execution_status": media_stages.get("ims_media_signaling", "SKIPPED"),
                    "instance_count": (media_evidence.get("media_signaling") or {}).get("exchange_count", 0),
                },
                {
                    "procedure_domain": "ims-media-session",
                    "execution_status": media_stages.get("ims_media_session", "SKIPPED"),
                    "instance_count": (media_evidence.get("ims_media_session") or {}).get("transport_observation_count", 0),
                },
            ]
        )
        protocol_evidence.extend(
            [
                {
                    "protocol": "SDP",
                    "extraction_status": media_stages.get("sdp_extraction", "SKIPPED"),
                    "event_count": (media_evidence.get("sdp") or {}).get("message_count", 0),
                    "media_section_count": (media_evidence.get("sdp") or {}).get("media_section_count", 0),
                },
                {
                    "protocol": "RTP",
                    "extraction_status": media_stages.get("rtp_extraction", "SKIPPED"),
                    "event_count": (media_evidence.get("rtp_rtcp") or {}).get("rtp_packet_count", 0),
                    "source_stream_count": ((media_evidence.get("rtp_rtcp") or {}).get("sequence") or {}).get("source_stream_count", 0),
                },
                {
                    "protocol": "RTCP",
                    "extraction_status": media_stages.get("rtp_extraction", "SKIPPED"),
                    "event_count": (media_evidence.get("rtp_rtcp") or {}).get("rtcp_component_count", 0),
                },
            ]
        )
    ims_evidence = {
        "sip_protocol": {
            **sip_counts,
            "extraction_status": sip_status,
            "extraction_executions": sip_executions,
            "error": sip_error,
        },
        "diameter_protocol": {
            **diameter_counts,
            "extraction_status": diameter_status,
            "error": diameter_error,
        },
        "registration": registration_evidence,
        "session": session_evidence,
        "diameter_ims": diameter_ims_evidence,
        "media": media_evidence,
        "cross_protocol_association": "NOT_ESTABLISHED",
        "analysis_status": execution_status,
        "limitations": limitations,
    }
    if not failed_stages and execution_status == STATUS_COMPLETED:
        limitations.append(
            "Workflow completion means bounded IMS evidence processing completed; it is not an IMS network, call or service success verdict."
        )
    return {
        "execution_status": execution_status,
        "protocol_evidence": protocol_evidence,
        "procedure_summaries": procedure_summaries,
        "ims_evidence": ims_evidence,
        "evidence_limitations": list(limitations),
        "degradation": degradation,
    }


def execute_ims_domain(
    capture: Path,
    work_dir: Path,
    case_id: str,
    detection: dict[str, Any],
    observed: set[str],
    pipeline: Callable[[Path, Path, str, set[str]], dict[str, Any]] | None = None,
    *,
    with_media: bool = False,
    offline: bool = False,
    endpoint_key_file: Path | None = None,
) -> dict[str, Any]:
    """Execute IMS and attach its evidence to the domain-neutral envelope."""
    runner = pipeline or execute_ims_pipeline
    if with_media:
        payload = runner(
            capture,
            work_dir,
            case_id,
            observed,
            with_media=True,
            offline=offline,
            endpoint_key_file=endpoint_key_file,
        )
    else:
        # Preserve the historical four-argument contract for all non-media runs.
        payload = runner(capture, work_dir, case_id, observed)
    capability = DOMAIN_CAPABILITIES[DOMAIN_IMS]
    result = {
        "domain": DOMAIN_IMS,
        "display_name": capability["display_name"],
        "implementation_status": capability["implementation_status"],
        "execution_status": payload.get("execution_status", STATUS_FAILED),
        "detection": detection,
        "unsupported_reason": None,
        "protocol_evidence": payload.get("protocol_evidence") or [],
        "procedure_summaries": payload.get("procedure_summaries") or [],
        "diagnostic_groups": None,
        "diagnostic_subject_count": 0,
        "diagnostic_subjects": [],
        "first_abnormal_boundary": None,
        "boundary_selection_status": "NOT_EVALUATED",
        "evidence_limitations": payload.get("evidence_limitations") or [],
        "additional_evidence_needed": [],
        "degradation": payload.get("degradation") or [],
        "ims_evidence": payload.get("ims_evidence") or {},
    }
    if result["execution_status"] == STATUS_FAILED:
        result["additional_evidence_needed"] = [
            "Resolve the failed IMS component and re-run the capture; independent SIP or Diameter evidence that was already usable is preserved when available."
        ]
    elif result["execution_status"] in (STATUS_COMPLETED, STATUS_PARTIAL):
        media = (result.get("ims_evidence") or {}).get("media") or {}
        if media.get("requested") and media.get("media_status") not in ("SUCCESS", None):
            result["additional_evidence_needed"] = [
                "Provide a capture that exposes the missing SDP answer, RTP transport or media-association evidence; encrypted/IPsec media remains inaccessible."
            ]
        else:
            result["additional_evidence_needed"] = [
                "Diameter Rx, charging, session modification, temporal media association and end-to-end IMS fault isolation remain outside the implemented scope."
            ]
    return result


def build_domain_adapters(
    pipeline: Callable[[Path, Path, str], tuple[dict[str, Any], Any, Path]],
    epc_pipeline: Callable[[Path, Path, str], dict[str, Any]],
    ims_pipeline: Callable[[Path, Path, str, set[str]], dict[str, Any]] | None = None,
    ims_media: dict[str, Any] | None = None,
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
        DOMAIN_IMS: lambda capture, work_dir, case_id, detection, observed: execute_ims_domain(
            capture,
            work_dir,
            case_id,
            detection,
            observed,
            ims_pipeline,
            with_media=bool((ims_media or {}).get("enabled")),
            offline=bool((ims_media or {}).get("offline")),
            endpoint_key_file=(ims_media or {}).get("endpoint_key_file"),
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
    ims_pipeline: Callable[[Path, Path, str, set[str]], dict[str, Any]] | None = None,
    with_media: bool = False,
    offline: bool = False,
    endpoint_key_file: Path | None = None,
    expected_capture_sha256: str | None = None,
) -> tuple[dict[str, Any], int]:
    """Execute the workflow and return the report and the CLI exit code."""
    inventory_fn = inventory or inventory_capture
    pipeline_fn = pipeline or execute_5gc_pipeline
    epc_pipeline_fn = epc_pipeline or execute_epc_pipeline
    ims_pipeline_fn = ims_pipeline or execute_ims_pipeline

    validate_paths(capture, work_dir, output_dir)
    if not capture.is_file():
        raise AnalysisError("CAPTURE_NOT_FOUND", "the capture file does not exist")
    if capture.stat().st_size == 0:
        raise AnalysisError("MALFORMED_CAPTURE", "the capture file is empty")
    validate_capture_container(capture)

    digest = capture_digest(capture)
    if expected_capture_sha256 is not None:
        if (
            not isinstance(expected_capture_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_capture_sha256)
            or digest != expected_capture_sha256
        ):
            raise AnalysisError(
                "CAPTURE_SHA256_MISMATCH",
                "the capture SHA-256 does not match the pinned expectation",
            )
    inventory_record = inventory_fn(capture)
    observed = observed_protocols(inventory_record)
    detection = detect_domains(observed)
    selection_mode, selected = resolve_selection(domains, detection)

    adapters = build_domain_adapters(
        pipeline_fn,
        epc_pipeline_fn,
        ims_pipeline_fn,
        {
            "enabled": bool(with_media),
            "offline": bool(offline),
            "endpoint_key_file": endpoint_key_file,
        },
    )
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
    parser.add_argument(
        "--with-media",
        action="store_true",
        help="run the bounded offline SDP/RTP/IMS media pipeline after IMS signaling",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="assert that the analysis path requires no external network service",
    )
    parser.add_argument(
        "--endpoint-key-file",
        type=Path,
        help="owner-only 32-byte local HMAC endpoint key for capture-scoped media matching",
    )
    parser.add_argument(
        "--expected-capture-sha256",
        help="optional pinned SHA-256 of the capture; a mismatch fails before analysis",
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
            args.capture,
            args.domains,
            args.work_dir,
            args.output_dir,
            force=args.force,
            with_media=args.with_media,
            offline=args.offline,
            endpoint_key_file=args.endpoint_key_file,
            expected_capture_sha256=args.expected_capture_sha256,
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
