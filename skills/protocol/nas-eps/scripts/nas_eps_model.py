#!/usr/bin/env python3
"""Shared, standalone helpers for bounded NAS-EPS semantic extraction.

The EPS NAS message identities and field semantics below were reviewed against
3GPP TS 24.301 and verified against the TShark 4.7.1 NAS-EPS dissector (Git
commit 667ab240e6de) through `tshark -G fields` and `tshark -G values`.

Support is intentionally bounded to the EPS attach, identity, authentication and
NAS security mode control message set. ESM container content is never decoded:
only presence and length are retained. Subscriber identities, authentication
parameters and NAS payload bytes are never published.

Timestamp normalization matches the core-network-pcap convention; the helper is
duplicated on purpose so this package stays standalone when other Skills are not
installed.
"""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from pathlib import Path
from typing import Any, Iterable, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nas_eps_esm

EXIT_TOOL_UNAVAILABLE = 3
EXIT_TSHARK_FAILURE = 4
EXIT_MALFORMED_INPUT = 5
EXIT_NO_EVENTS = 6
EXIT_OUTPUT_FAILURE = 7

SCHEMA_NAME = "nas-eps-event"
PROTOCOL = "NAS-EPS"
INTERFACE = "N1"


@dataclass(frozen=True)
class FieldSpec:
    canonical_name: str
    tshark_candidates: tuple[str, ...]
    required: bool = False


FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "sctp.srcport",
    "sctp.dstport",
    "sctp.assoc_index",
    "_ws.col.Info",
    "nas-eps.nas_msg_emm_type",
    "nas-eps.security_header_type",
    "nas-eps.emm.cause",
    "nas-eps.emm.eps_att_type",
    "nas-eps.emm.type_of_id",
    "nas-eps.emm.esm_msg_cont",
    "nas-eps.ciphered_msg",
    "nas-eps.msg_auth_code",
    "s1ap.procedureCode",
    "s1ap.initiatingMessage_element",
    "s1ap.successfulOutcome_element",
    "s1ap.unsuccessfulOutcome_element",
    "nas-eps.nas_msg_esm_type",
    "nas-eps.bearer_id",
    "nas-eps.esm.proc_trans_id",
    "nas-eps.esm.cause",
    "nas-eps.esm_pdn_type",
    "nas-eps.esm.request_type",
    "nas-eps.esm.qci",
)

FIELD_SPECS: tuple[FieldSpec, ...] = tuple(
    FieldSpec(
        canonical_name=name,
        tshark_candidates=("_ws.col.Info", "_ws.col.info") if name == "_ws.col.Info" else (name,),
        required=name in {"frame.number", "frame.time_epoch"},
    )
    for name in FIELDS
)

FILTER_CANDIDATES: tuple[str, ...] = ("nas-eps",)

# Reviewed TS 24.301 message identities, verified against the TShark 4.7.1
# value table for nas-eps.nas_msg_emm_type.
KNOWN_MESSAGES = {
    65: "Attach request",
    66: "Attach accept",
    67: "Attach complete",
    68: "Attach reject",
    69: "Detach request",
    70: "Detach accept",
    72: "Tracking area update request",
    73: "Tracking area update accept",
    74: "Tracking area update complete",
    75: "Tracking area update reject",
    76: "Extended service request",
    77: "Control plane service request",
    78: "Service reject",
    79: "Service accept",
    80: "GUTI reallocation command",
    81: "GUTI reallocation complete",
    82: "Authentication request",
    83: "Authentication response",
    84: "Authentication reject",
    85: "Identity request",
    86: "Identity response",
    92: "Authentication failure",
    93: "Security mode command",
    94: "Security mode complete",
    95: "Security mode reject",
    96: "EMM status",
    97: "EMM information",
    98: "Downlink NAS transport",
    99: "Uplink NAS transport",
    100: "CS service notification",
    104: "Downlink generic NAS transport",
    105: "Uplink generic NAS transport",
}

# Bounded support: EPS attach, identity, authentication, NAS security mode.
SUPPORTED_MESSAGES = frozenset({
    65, 66, 67, 68,
    82, 83, 84,
    85, 86,
    92,
    93, 94, 95,
})

# Authentication and security mode control stay separate procedures: they share
# no identity and are never merged into one stage label.
MESSAGE_PROCEDURE = {
    65: "eps-attach",
    66: "eps-attach",
    67: "eps-attach",
    68: "eps-attach",
    85: "identity",
    86: "identity",
    82: "authentication",
    83: "authentication",
    84: "authentication",
    92: "authentication",
    93: "security-mode-control",
    94: "security-mode-control",
    95: "security-mode-control",
}

# Local normalized role labels (not 3GPP wire values).
MESSAGE_RESULTS = {
    "Attach request": "REQUEST",
    "Attach accept": "ACCEPT",
    "Attach complete": "COMPLETE",
    "Attach reject": "REJECT",
    "Identity request": "REQUEST",
    "Identity response": "RESPONSE",
    "Authentication request": "REQUEST",
    "Authentication response": "RESPONSE",
    "Authentication reject": "REJECT",
    "Authentication failure": "FAILURE",
    "Security mode command": "COMMAND",
    "Security mode complete": "COMPLETE",
    "Security mode reject": "REJECT",
}

# TS 24.301 §9.3.1 security header type.
SECURITY_HEADER_TYPES = {
    0: ("PLAIN", "Plain NAS message, not security protected"),
    1: ("INTEGRITY_PROTECTED", "Integrity protected"),
    2: ("INTEGRITY_AND_CIPHERED", "Integrity protected and ciphered"),
    3: ("INTEGRITY_PROTECTED_NEW_CONTEXT", "Integrity protected with new EPS security context"),
    4: ("INTEGRITY_AND_CIPHERED_NEW_CONTEXT", "Integrity protected and ciphered with new EPS security context"),
    5: ("PARTIALLY_CIPHERED", "Integrity protected and partially ciphered NAS message"),
    11: ("EMM_TRANSPORT", "Security header for the EMM transport message"),
    12: ("SERVICE_REQUEST", "Security header for the service request message"),
}

# Reviewed TS 24.301 §9.9.3.2 EPS attach type values.
ATTACH_TYPES = {
    1: "EPS attach",
    2: "Combined EPS/IMSI attach",
    3: "EPS RLOS attach",
    6: "EPS emergency attach",
    7: "Disaster roaming attach",
}

# Reviewed TS 24.301 §9.9.3.9 EMM cause values, verified against the decoder
# value table for nas-eps.emm.cause.
EMM_CAUSES = {
    2: "IMSI unknown in HSS",
    3: "Illegal UE",
    5: "IMEI not accepted",
    6: "Illegal ME",
    7: "EPS services not allowed",
    8: "EPS services and non-EPS services not allowed",
    9: "UE identity cannot be derived by the network",
    10: "Implicitly detached",
    11: "PLMN not allowed",
    12: "Tracking area not allowed",
    13: "Roaming not allowed in this tracking area",
    14: "EPS services not allowed in this PLMN",
    15: "No suitable cells in tracking area",
    16: "MSC temporarily not reachable",
    17: "Network failure",
    18: "CS domain not available",
    19: "ESM failure",
    20: "MAC failure",
    21: "Synch failure",
    22: "Congestion",
    23: "UE security capabilities mismatch",
    24: "Security mode rejected, unspecified",
    25: "Not authorized for this CSG",
    26: "Non-EPS authentication unacceptable",
    31: "Redirection to 5GCN required",
    35: "Requested service option not authorized in this PLMN",
    36: "IAB-node operation not authorized",
    39: "CS service temporarily not available",
    40: "No EPS bearer context activated",
    42: "Severe network failure",
}

# Enclosing S1AP procedure codes that carry NAS in a known direction. The S1AP
# message identity is used only as an encapsulation direction hint; NAS-EPS owns
# no S1AP semantics and works without this field.
S1AP_DIRECTION = {11: "downlink", 12: "uplink", 13: "uplink", 18: "uplink"}

# TS 36.413 fixes which signaling side sends each message, so the enclosing
# procedure plus its PDU category also fixes the direction of the carried NAS.
# Only reviewed pairs are listed; anything else stays unresolved.
PROCEDURE_DIRECTION = {
    (9, "initiatingMessage"): "downlink",
    (9, "successfulOutcome"): "uplink",
    (9, "unsuccessfulOutcome"): "uplink",
    (11, "initiatingMessage"): "downlink",
    (12, "initiatingMessage"): "uplink",
    (13, "initiatingMessage"): "uplink",
    (17, "initiatingMessage"): "uplink",
    (17, "successfulOutcome"): "downlink",
    (23, "initiatingMessage"): "downlink",
    (23, "successfulOutcome"): "uplink",
}

PDU_TYPE_FIELDS = (
    ("initiatingMessage", "s1ap.initiatingMessage_element"),
    ("successfulOutcome", "s1ap.successfulOutcome_element"),
    ("unsuccessfulOutcome", "s1ap.unsuccessfulOutcome_element"),
)

SUPPORT_STATUSES = ("SUPPORTED", "UNSUPPORTED", "UNKNOWN", "PROTECTED_INNER_MESSAGE_UNAVAILABLE")


class InputError(ValueError):
    """Raised when a supported structured input cannot be normalized."""


class ToolUnavailable(RuntimeError):
    """Raised when tshark is required but unavailable."""


class TsharkError(RuntimeError):
    """Raised when tshark cannot produce the requested fields."""


def safe_capture_name(path: Path) -> str:
    """Return a basename so outputs do not disclose workstation paths."""
    return path.name


def clean(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def first_token(value: object) -> str | None:
    """Return the first comma-joined occurrence of a repeated field."""
    text = clean(value)
    if text is None:
        return None
    return text.split(",")[0].strip() or None


def parse_int(value: object, field: str) -> int:
    text = clean(value)
    if text is None:
        raise InputError(f"{field} is required")
    try:
        return int(text, 10)
    except ValueError as exc:
        raise InputError(f"{field} must be an integer") from exc


def parse_number(value: object, field: str) -> int:
    """Parse an integer exported as decimal or hexadecimal."""
    text = first_token(value)
    if text is None:
        raise InputError(f"{field} is required")
    try:
        return int(text, 0)
    except ValueError as exc:
        raise InputError(f"{field} must be an integer") from exc


def optional_number(value: object) -> int | None:
    text = first_token(value)
    if text is None:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def parse_port(value: object, field: str) -> int | None:
    text = clean(value)
    if text is None:
        return None
    try:
        port = int(text)
    except ValueError as exc:
        raise InputError(f"{field} must be an integer port") from exc
    if not 0 <= port <= 65535:
        raise InputError(f"{field} is outside the valid port range")
    return port


def normalize_timestamp(value: object) -> str:
    """Convert tshark epoch seconds to UTC ISO-8601 with microsecond precision."""
    text = clean(value)
    if text is None:
        raise InputError("frame.time_epoch is required")
    try:
        epoch = Decimal(text)
    except InvalidOperation as exc:
        raise InputError("frame.time_epoch is not a valid epoch timestamp") from exc
    if not epoch.is_finite():
        raise InputError("frame.time_epoch must be finite")
    microseconds = int((epoch * Decimal("1000000")).to_integral_value(rounding=ROUND_HALF_EVEN))
    try:
        instant = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)
    except OverflowError as exc:
        raise InputError("frame.time_epoch is outside the supported UTC range") from exc
    return instant.isoformat(timespec="microseconds").replace("+00:00", "Z")


def byte_length(raw: object) -> int | None:
    """Hex string length in bytes; the payload itself is never retained."""
    text = clean(raw)
    if text is None:
        return None
    compact = text.replace(":", "").replace(" ", "").replace(",", "")
    if not compact:
        return None
    if len(compact) % 2:
        compact = compact[:-1]
    return len(compact) // 2


def endpoint(record: dict[str, object], direction: str) -> dict[str, object] | None:
    address = clean(record.get(f"ip.{direction}")) or clean(record.get(f"ipv6.{direction}"))
    port = parse_port(record.get(f"sctp.{direction}port"), f"sctp.{direction}port")
    if address is None and port is None:
        return None
    return {"address": address, "port": port}


def sctp_metadata(record: dict[str, object]) -> dict[str, object] | None:
    association = optional_number(record.get("sctp.assoc_index"))
    if association is None:
        return None
    return {"association_id": association}


def protection_profile(security_header_type: int | None) -> tuple[str | None, str | None]:
    if security_header_type is None:
        return None, None
    mapped = SECURITY_HEADER_TYPES.get(security_header_type)
    if mapped is not None:
        return mapped
    if 6 <= security_header_type <= 10 or 13 <= security_header_type <= 15:
        return "RESERVED", "Reserved security header type value"
    return "UNKNOWN", None


def pdu_type_hint(record: dict[str, object]) -> str | None:
    for pdu_type, field in PDU_TYPE_FIELDS:
        if first_token(record.get(field)) is not None:
            return pdu_type
    return None


def direction_hint(record: dict[str, object]) -> tuple[str | None, str]:
    """Direction from the enclosing S1AP message, when the decoder exposes it."""
    code = optional_number(record.get("s1ap.procedureCode"))
    pdu_type = pdu_type_hint(record)
    if code is not None and pdu_type is not None:
        reviewed = PROCEDURE_DIRECTION.get((code, pdu_type))
        if reviewed is not None:
            return reviewed, "enclosing_s1ap_procedure_and_pdu_type"
    if code is not None and code in S1AP_DIRECTION:
        return S1AP_DIRECTION[code], "enclosing_s1ap_procedure"
    return None, "unavailable"


def resolve_message(code: int | None, protection: str | None) -> tuple[str | None, str, str | None]:
    """Return (message name, support status, procedure family)."""
    if code is None:
        if protection is not None and protection != "PLAIN":
            return None, "PROTECTED_INNER_MESSAGE_UNAVAILABLE", None
        return None, "UNKNOWN", None
    name = KNOWN_MESSAGES.get(code)
    if name is None:
        return None, "UNKNOWN", None
    if code in SUPPORTED_MESSAGES:
        return name, "SUPPORTED", MESSAGE_PROCEDURE.get(code)
    return name, "UNSUPPORTED", None


def _esm_messages(
    record: dict[str, object],
    capture_file: str,
    frame_number: int,
    esm_index: dict[int, list[dict[str, Any]]] | None,
    protection: str | None,
    direction: str | None,
) -> list[dict[str, Any]]:
    """ESM messages for this frame, with the enclosing NAS context applied."""
    if esm_index is not None:
        items = [dict(item) for item in esm_index.get(frame_number, [])]
    else:
        items = nas_eps_esm.flat_esm_messages(record, capture_file)
    for item in items:
        # An ESM message always travels inside this NAS message, so its
        # protection and direction are the enclosing message's, never guessed.
        item["protection_state"] = protection
        item["protection_state_basis"] = "enclosing_nas_security_header"
        if item.get("direction") is None:
            item["direction"] = direction
            item["direction_basis"] = "enclosing_nas_message" if direction else "unavailable"
    return items


def normalize_record(
    record: object,
    capture_file: str,
    esm_index: dict[int, list[dict[str, Any]]] | None = None,
) -> dict[str, object]:
    """Project one structured NAS-EPS observation into the detailed event."""
    if not isinstance(record, dict):
        raise InputError("structured NAS-EPS record must be a JSON object")
    frame_number = parse_int(record.get("frame.number"), "frame.number")
    if frame_number < 1:
        raise InputError("frame.number must be at least 1")
    timestamp = normalize_timestamp(record.get("frame.time_epoch"))

    security_header_type = optional_number(record.get("nas-eps.security_header_type"))
    protection, protection_description = protection_profile(security_header_type)
    message_code = optional_number(record.get("nas-eps.nas_msg_emm_type"))
    message_name, support_status, procedure = resolve_message(message_code, protection)

    emm_cause_value = optional_number(record.get("nas-eps.emm.cause"))
    emm_cause = None
    if emm_cause_value is not None:
        emm_cause = {"value": emm_cause_value, "name": EMM_CAUSES.get(emm_cause_value)}

    attach_type_value = optional_number(record.get("nas-eps.emm.eps_att_type"))
    attach_type = None
    if attach_type_value is not None:
        attach_type = {"value": attach_type_value, "name": ATTACH_TYPES.get(attach_type_value)}

    identity_type_value = optional_number(record.get("nas-eps.emm.type_of_id"))

    esm_length = byte_length(record.get("nas-eps.emm.esm_msg_cont"))
    ciphered_present = byte_length(record.get("nas-eps.ciphered_msg")) is not None
    mac_present = byte_length(record.get("nas-eps.msg_auth_code")) is not None
    direction, direction_basis = direction_hint(record)

    observed_message = clean(record.get("_ws.col.Info")) or clean(record.get("_ws.col.info"))
    source_ref = f"capture:{capture_file}#frame={frame_number}"
    if message_code is not None:
        source_ref += f"; emm-message-type={message_code}"
    if security_header_type is not None:
        source_ref += f"; security-header-type={security_header_type}"
    if observed_message is not None:
        source_ref += f"; tshark-info={observed_message}"

    derivations: list[str] = []
    if protection is not None and protection != "PLAIN":
        derivations.append(
            "the message is security protected; ciphered inner content is never decoded"
        )
    if support_status == "PROTECTED_INNER_MESSAGE_UNAVAILABLE":
        derivations.append(
            "no inner NAS message identity is observable inside the protected envelope"
        )
    if identity_type_value is not None:
        derivations.append(
            "only the identity type value is reported; the identity value itself is never read"
        )

    event: dict[str, object] = {
        "timestamp": timestamp,
        "frame_number": frame_number,
        "capture_file": capture_file,
        "protocol_discriminator": "EPS_MOBILITY_MANAGEMENT",
        "protocol_discriminator_basis": "decoder_dissection",
        "security_header_type": security_header_type,
        "protection": protection,
        "protection_description": protection_description,
        "message_type_code": message_code,
        "message_type": message_name,
        "support_status": support_status,
        "procedure": procedure,
        "result": MESSAGE_RESULTS.get(message_name) if message_name else None,
        "direction": direction,
        "direction_basis": direction_basis,
        "emm_cause": emm_cause,
        "attach_type": attach_type,
        "identity_type_value": identity_type_value,
        "esm_container_present": esm_length is not None,
        "esm_container_length": esm_length,
        "ciphered_payload_present": ciphered_present,
        "message_authentication_code_present": mac_present,
        "protected_inner_message_unavailable": support_status == "PROTECTED_INNER_MESSAGE_UNAVAILABLE",
        "esm_messages": _esm_messages(
            record, capture_file, frame_number, esm_index, protection, direction
        ),
        "evidence": {"level": "OBSERVED", "source": source_ref},
        "derivations": derivations,
    }
    source = endpoint(record, "src")
    destination = endpoint(record, "dst")
    sctp = sctp_metadata(record)
    if source is not None:
        event["source"] = source
    if destination is not None:
        event["destination"] = destination
    if sctp is not None:
        event["sctp"] = sctp
    return event


def project_trace_event(event: dict[str, object]) -> dict[str, object]:
    """Project a detailed NAS-EPS event into the shared trace-event contract."""
    projected: dict[str, object] = {
        "timestamp": event["timestamp"],
        "protocol": PROTOCOL,
        "interface": INTERFACE,
        "procedure": event.get("procedure"),
        "message_type": event.get("message_type"),
        "packet": {"frame_number": event["frame_number"], "capture_file": event["capture_file"]},
        "evidence": {
            "level": "DERIVED",
            "source": f"nas-eps-event:{event['capture_file']}#frame={event['frame_number']}",
        },
    }
    for role in ("source", "destination"):
        if event.get(role) is not None:
            projected[role] = event[role]
    cause = event.get("emm_cause")
    if isinstance(cause, dict):
        code = cause.get("value") if isinstance(cause.get("value"), int) else None
        cause_text = None
        if code is not None:
            cause_text = f"emm:{code}" + (f":{cause['name']}" if cause.get("name") else "")
        projected["result"] = {"status": event.get("result"), "cause": cause_text, "code": code}
    elif event.get("result") is not None:
        projected["result"] = {"status": event.get("result"), "cause": None, "code": None}
    return projected


def read_jsonl(path: Path) -> Iterator[dict[str, object]]:
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON Lines record at line {line_number}: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise InputError(f"JSON Lines record at line {line_number} is not an object")
            yield record


def resolve_tshark_executable() -> str:
    found = shutil.which("tshark")
    if found:
        return found
    if sys.platform == "win32":
        for candidate in (
            r"D:\Wireshark\tshark.exe",
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ):
            if Path(candidate).is_file():
                return candidate
    return "tshark"


_AVAILABLE_FIELDS_OVERRIDE: set[str] | None = None
_AVAILABLE_PROTOCOLS_OVERRIDE: set[str] | None = None
_AVAILABLE_FIELDS_CACHE: set[str] | None = None
_AVAILABLE_PROTOCOLS_CACHE: set[str] | None = None


def set_discovery_overrides(
    fields: set[str] | None = None, protocols: set[str] | None = None
) -> None:
    global _AVAILABLE_FIELDS_OVERRIDE, _AVAILABLE_PROTOCOLS_OVERRIDE
    _AVAILABLE_FIELDS_OVERRIDE = fields
    _AVAILABLE_PROTOCOLS_OVERRIDE = protocols


def get_available_fields(tshark_bin: str | None = None) -> set[str] | None:
    if _AVAILABLE_FIELDS_OVERRIDE is not None:
        return _AVAILABLE_FIELDS_OVERRIDE
    global _AVAILABLE_FIELDS_CACHE
    if _AVAILABLE_FIELDS_CACHE is not None:
        return _AVAILABLE_FIELDS_CACHE
    exe = tshark_bin or resolve_tshark_executable()
    try:
        proc = subprocess.run(
            [exe, "-G", "fields"], capture_output=True, encoding="utf-8", errors="replace", check=False
        )
        if proc.returncode == 0 and proc.stdout:
            fields = set()
            for line in proc.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3:
                    fields.add(parts[2])
            _AVAILABLE_FIELDS_CACHE = fields
            return fields
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def get_available_protocols(tshark_bin: str | None = None) -> set[str] | None:
    if _AVAILABLE_PROTOCOLS_OVERRIDE is not None:
        return _AVAILABLE_PROTOCOLS_OVERRIDE
    global _AVAILABLE_PROTOCOLS_CACHE
    if _AVAILABLE_PROTOCOLS_CACHE is not None:
        return _AVAILABLE_PROTOCOLS_CACHE
    exe = tshark_bin or resolve_tshark_executable()
    try:
        proc = subprocess.run(
            [exe, "-G", "protocols"], capture_output=True, encoding="utf-8", errors="replace", check=False
        )
        if proc.returncode == 0 and proc.stdout:
            protocols = set()
            for line in proc.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3:
                    protocols.add(parts[2].strip())
            _AVAILABLE_PROTOCOLS_CACHE = protocols
            return protocols
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def resolve_filter(candidates: tuple[str, ...], available_protocols: set[str] | None) -> str:
    if available_protocols is not None:
        for cand in candidates:
            if cand in available_protocols:
                return cand
        raise TsharkError(
            f"tshark compatibility error: none of the protocol filter candidates {candidates} "
            "are supported by installed TShark"
        )
    return candidates[0]


def resolve_field_specs(
    specs: tuple[FieldSpec, ...], available_fields: set[str] | None, tshark_ver: str
) -> tuple[list[tuple[str, str]], list[str]]:
    resolved_mappings: list[tuple[str, str]] = []
    unresolved_optional: list[str] = []
    for spec in specs:
        resolved_field: str | None = None
        if available_fields is not None:
            for cand in spec.tshark_candidates:
                if cand in available_fields:
                    resolved_field = cand
                    break
        else:
            resolved_field = spec.tshark_candidates[0]
        if resolved_field is not None:
            resolved_mappings.append((resolved_field, spec.canonical_name))
        elif spec.required:
            raise TsharkError(
                f"tshark compatibility error: required field '{spec.canonical_name}' "
                f"(candidates: {spec.tshark_candidates}) is not available in installed TShark {tshark_ver}"
            )
        else:
            unresolved_optional.append(spec.canonical_name)
    return resolved_mappings, unresolved_optional


def tshark_version() -> str:
    exe = resolve_tshark_executable()
    try:
        completed = subprocess.run(
            [exe, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False
        )
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown tshark failure"
        raise TsharkError(f"tshark --version failed: {detail}")
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "tshark (version unavailable)"


def build_tshark_fields_command(
    capture: Path,
    mappings: list[tuple[str, str]] | None = None,
    display_filter: str = "nas-eps",
) -> list[str]:
    exe = resolve_tshark_executable()
    command = [
        exe,
        "-n",
        "-r",
        str(capture),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=a",
        "-Y",
        display_filter,
    ]
    if mappings is None:
        mappings = [(s.tshark_candidates[0], s.canonical_name) for s in FIELD_SPECS]
    for actual, _ in mappings:
        command.extend(["-e", actual])
    return command


def tshark_records(capture: Path) -> Iterator[dict[str, object]]:
    exe = resolve_tshark_executable()
    ver = tshark_version()
    avail_fields = get_available_fields(exe)
    avail_protos = get_available_protocols(exe)
    resolved_filter = resolve_filter(FILTER_CANDIDATES, avail_protos)
    mappings, unresolved_optional = resolve_field_specs(FIELD_SPECS, avail_fields, ver)
    command = build_tshark_fields_command(capture, mappings, resolved_filter)
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    assert process.stdout is not None
    reader = csv.reader(process.stdout, delimiter="\t")
    header = next(reader, None)
    if header is None:
        stderr = process.stderr.read().strip() if process.stderr else ""
        return_code = process.wait()
        if return_code != 0:
            raise TsharkError(f"tshark returned no field header: {stderr or 'no output'}")
        return
    expected_headers = [actual for actual, _ in mappings]
    if list(header) != expected_headers:
        stderr = process.stderr.read().strip() if process.stderr else ""
        process.wait()
        raise TsharkError(
            f"tshark returned unexpected field header: expected {expected_headers}, got {header}: {stderr}"
        )
    for row in reader:
        if len(row) > len(mappings):
            raise TsharkError("tshark returned more columns than the requested NAS-EPS field set")
        padded = row + [""] * (len(mappings) - len(row))
        record = {canonical: padded[i] for i, (_, canonical) in enumerate(mappings)}
        for optional in unresolved_optional:
            record[optional] = ""
        yield record
    stderr = process.stderr.read().strip() if process.stderr else ""
    return_code = process.wait()
    if return_code != 0:
        raise TsharkError(f"tshark capture parsing failed: {stderr or f'exit {return_code}'}")


def pdml_dissection(capture: Path) -> str:
    """Run a PDML dissection so ESM container boundaries stay provable."""
    exe = resolve_tshark_executable()
    command = [
        exe,
        "-n",
        "-r",
        str(capture),
        "-T",
        "pdml",
        "-Y",
        resolve_filter(FILTER_CANDIDATES, get_available_protocols(exe)),
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False
        )
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "unknown tshark failure"
        raise TsharkError(f"tshark PDML dissection failed: {detail}")
    return completed.stdout


def esm_index_for_capture(capture: Path) -> dict[int, list[dict[str, Any]]]:
    """ESM messages per frame, read from the dissector tree of this capture."""
    try:
        return nas_eps_esm.pdml_esm_index(pdml_dissection(capture), safe_capture_name(capture))
    except ValueError as exc:
        raise TsharkError(f"tshark PDML dissection is unreadable: {exc}") from exc


def input_kind(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    if path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
        return "capture"
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        return "fields-jsonl"
    raise InputError("cannot infer input format; use --input-format capture or fields-jsonl")


def records_for_input(path: Path, requested: str) -> tuple[Iterable[dict[str, object]], str | None]:
    if not path.is_file():
        raise InputError(f"input file does not exist: {path}")
    kind = input_kind(path, requested)
    if kind == "fields-jsonl":
        return read_jsonl(path), None
    if kind == "capture":
        return tshark_records(path), tshark_version()
    raise InputError(f"unsupported extracted format: {kind}")
