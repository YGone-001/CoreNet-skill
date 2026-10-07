#!/usr/bin/env python3
"""Validate the standalone gtpu Protocol Skill contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import py_compile
import re
import sys
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from implementation_policy import IMPLEMENTATION_TOKEN_PATTERN

SKILL = Path("skills/protocol/gtpu")
REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/protocol-model.md",
    "references/message-map.md",
    "references/field-reference.md",
    "references/teid-model.md",
    "references/pdu-session-container.md",
    "references/stream-correlation.md",
    "references/failure-cases.md",
    "scripts/gtpu_model.py",
    "scripts/extract-gtpu.py",
    "scripts/summarize-gtpu.py",
    "scripts/gtpu_timeline.py",
    "schemas/gtpu-event.schema.json",
    "schemas/gtpu-stream.schema.json",
    "schemas/trace-event.schema.json",
    "filters/wireshark.txt",
    "examples/extracted/g-pdu-basic.jsonl",
    "examples/extracted/pdu-session-container.jsonl",
    "examples/extracted/teid-scope.jsonl",
    "examples/extracted/control-messages.jsonl",
    "examples/extracted/recognition.jsonl",
    "examples/extracted/inner-packets.jsonl",
    "examples/extracted/ordering.jsonl",
    "examples/extracted/malformed.jsonl",
    "examples/expected/g-pdu-basic-events.jsonl",
    "examples/expected/pdu-session-container-events.jsonl",
    "examples/expected/teid-scope-events.jsonl",
    "examples/expected/control-messages-events.jsonl",
    "examples/expected/recognition-events.jsonl",
    "examples/expected/inner-packets-events.jsonl",
    "examples/expected/ordering-events.jsonl",
    "tests/test_gtpu.py",
)
EXPECTED_EVENTS = (
    "examples/expected/g-pdu-basic-events.jsonl",
    "examples/expected/pdu-session-container-events.jsonl",
    "examples/expected/teid-scope-events.jsonl",
    "examples/expected/control-messages-events.jsonl",
    "examples/expected/recognition-events.jsonl",
    "examples/expected/inner-packets-events.jsonl",
    "examples/expected/ordering-events.jsonl",
)
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
IMPLEMENTATION_ASSET = re.compile(
    IMPLEMENTATION_TOKEN_PATTERN +
    r"|openairinterface|srsran|ueransim|nokia|ericsson|huawei|zte|(?:upf|gnb|smf)\.(?:c|cc|cpp|h|go|py)\b")
SUBSCRIBER_FIELD = re.compile(r"(?i)[\"']?(?:imsi|msisdn|suci|supi|fiveg?[-_]guti|guti)[\"']?\s*[:=]")
SECRET_FIELD = re.compile(r"(?i)[\"']?(?:password|passwd|secret|api[_-]?key|private[_-]?key|token)[\"']?\s*[:=]\s*[\"'][^\"']{6,}")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s+[0-9]+\b|\bmilestone\s+b?[0-9]+\b")
# A byte-level GTP-U decoder is explicitly out of scope.
RAW_DECODER = re.compile(r"(?i)struct\.unpack|int\.from_bytes|bytes\.fromhex|memoryview\(|def\s+parse_gtpu")
# Cross-protocol joins and other-layer semantics must not appear as code.
PFCP_JOIN = re.compile(r"(?i)f_teid_join|match_pfcp|pfcp_f_teid|f_teid\s*==")
NGAP_JOIN = re.compile(r"(?i)ngap_teid|match_ngap|transport_tunnel_join|amf_ue_ngap_id|ran_ue_ngap_id")
NAS_JOIN = re.compile(r"(?i)match_nas|nas_session_join|pdu_session_id\s*==|decode_nas")
SBI_SEMANTICS = re.compile(r"(?i)nsmf_pdusession|sbi_client|http2|sm_context_request")
# Application payload persistence and application protocol decoding are
# forbidden. The pattern targets assignment/persistence in any of the common
# shapes (dict key, subscript assignment, keyword argument), and deliberately
# does NOT match the bare string literals used by the rejection list that
# refuses such keys.
APP_PAYLOAD = re.compile(
    r"(?i)[\x22\x27]?(?:payload|payload_bytes|application_payload|inner_payload)[\x22\x27]?\]?\s*[:=]\s*[^=]"
    r"|decode_sip|decode_rtp|decode_dns|decode_http|decode_tls|decode_quic"
)
# A packet-loss verdict is forbidden; only a non-conclusive candidate is allowed.
PACKET_LOSS_VERDICT = re.compile(r"(?i)packet_loss|loss_confirmed|lost_packets|lost_packet_count")
# The directed stream key must include capture, endpoints and TEID.
DIRECTED_KEY_MARKER = "gtpu-path:"
IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
DOC_IPV4_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
TEXT_SUFFIXES = {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_value(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def manifest_list(text: str, key: str) -> list[str]:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*\[([^\]]*)\]", text)
    if match is None:
        return []
    return [item.strip() for item in match.group(1).split(",") if item.strip()]


def jsonl_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    skill = root / SKILL
    if not skill.is_dir():
        return [f"missing Skill directory: {SKILL}"]
    for relative in REQUIRED:
        if not (skill / relative).is_file():
            errors.append(f"missing required package file: {relative}")
    if errors:
        return errors

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    for key, expected in (("name", "gtpu"), ("version", "0.1.1"), ("category", "protocol")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"manifest {key} must be {expected}")
    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append("manifest must not require another CoreNet Skill")
    protocols = manifest_list(manifest, "protocols")
    if "GTP-U" not in protocols:
        errors.append("manifest protocols must include GTP-U")
    interfaces = manifest_list(manifest, "interfaces")
    if interfaces and interfaces != ["N3"]:
        errors.append("manifest interface ownership must be N3 only")
    if manifest_value(manifest, "network_functions") not in (None, "[]"):
        errors.append("manifest network_functions must stay empty for a Protocol Skill")

    model_text = (skill / "scripts" / "gtpu_model.py").read_text(encoding="utf-8")
    if "FieldSpec" not in model_text:
        errors.append("gtpu_model.py must implement FieldSpec compatibility model")
    if "resolve_field_specs" not in model_text:
        errors.append("gtpu_model.py must provide resolve_field_specs")

    local_trace = skill / "schemas" / "trace-event.schema.json"
    shared_trace = root / "shared" / "schemas" / "trace-event.schema.json"
    if not shared_trace.is_file() or digest(local_trace) != digest(shared_trace):
        errors.append("package-local trace schema must match the authoritative shared schema bytes")

    try:
        event_schema = json.loads((skill / "schemas" / "gtpu-event.schema.json").read_text(encoding="utf-8"))
        required = event_schema.get("required", [])
        for key in ("timestamp", "frame_number", "capture_file", "header", "support_status", "outer", "extension_headers", "pdu_session_container", "inner_packet", "evidence", "derivations"):
            if key not in required:
                errors.append(f"gtpu-event schema must require {key}")
        properties = event_schema.get("properties", {})
        if properties.get("evidence", {}).get("properties", {}).get("level", {}).get("const") != "OBSERVED":
            errors.append("gtpu-event schema evidence.level must stay OBSERVED")
        if properties.get("extension_headers", {}).get("type") != "array":
            errors.append("gtpu-event schema extension_headers must be an array")
        if "teid_expected_zero" not in properties.get("header", {}).get("properties", {}):
            errors.append("gtpu-event schema header must expose teid_expected_zero")
        if "opaque" not in properties.get("inner_packet", {}).get("properties", {}):
            errors.append("gtpu-event schema inner_packet must expose the opacity flag")
    except json.JSONDecodeError as exc:
        errors.append(f"gtpu-event schema is invalid JSON: {exc}")

    try:
        stream_schema = json.loads((skill / "schemas" / "gtpu-stream.schema.json").read_text(encoding="utf-8"))
        stream_required = set(stream_schema.get("$defs", {}).get("stream", {}).get("required", []))
        for key in ("stream_key", "teid", "observed_g_pdu_packet_count", "observed_payload_byte_count", "byte_count_definition", "sequence_discontinuity_candidate", "limitations"):
            if key not in stream_required:
                errors.append(f"gtpu-stream schema must require {key}")
    except json.JSONDecodeError as exc:
        errors.append(f"gtpu-stream schema is invalid JSON: {exc}")

    g_pdu_present = False
    container_qfi_present = False
    error_indication_present = False
    end_marker_present = False
    teid_reuse_present = False
    opposite_direction_present = False
    for relative in EXPECTED_EVENTS:
        try:
            events = jsonl_records(skill / relative)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"expected fixture is invalid: {relative}: {exc}")
            continue
        contexts: dict[int, set[tuple[object, object]]] = {}
        directions: dict[int, set[tuple[object, object]]] = {}
        for event in events:
            header = event.get("header") or {}
            outer = event.get("outer") or {}
            if header.get("message_type") == "G-PDU":
                g_pdu_present = True
            container = event.get("pdu_session_container")
            if isinstance(container, dict) and container.get("qfi") is not None:
                container_qfi_present = True
            if event.get("error_indication") is not None:
                error_indication_present = True
            if event.get("end_marker") is not None:
                end_marker_present = True
            teid = header.get("teid")
            source = outer.get("source_address")
            destination = outer.get("destination_address")
            if teid is not None and source is not None and destination is not None:
                contexts.setdefault(teid, set()).add((source, destination))
                directions.setdefault(teid, set()).add((source, destination))
                directions[teid].add((destination, source))
        for teid, pairs in contexts.items():
            if len(pairs) >= 2:
                teid_reuse_present = True
        for teid, pairs in directions.items():
            forward = {(source, destination) for source, destination in pairs}
            if any((destination, source) in forward and (source, destination) != (destination, source) for source, destination in forward):
                opposite_direction_present = True
    for flag, message in (
        (g_pdu_present, "at least one expected fixture must contain an observed G-PDU"),
        (container_qfi_present, "at least one expected fixture must contain a PDU Session Container with a QFI"),
        (error_indication_present, "at least one expected fixture must contain an Error Indication"),
        (end_marker_present, "at least one expected fixture must contain an End Marker"),
        (teid_reuse_present, "at least one expected fixture must reuse one TEID on different endpoint contexts"),
        (opposite_direction_present, "at least one expected fixture must contain the same TEID in opposite directions"),
    ):
        if not flag:
            errors.append(message)

    for path in skill.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if path.suffix.lower() in CAPTURE_SUFFIXES:
            errors.append(f"binary capture fixture is not allowed: {relative}")
        if path.suffix in TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8")
            if "../../../" in text or "third_party/" in text:
                errors.append(f"repository-root runtime reference in {relative}")
            if ABSOLUTE_PATH.search(text):
                errors.append(f"absolute workstation path in {relative}")
            if IMPLEMENTATION_ASSET.search(text):
                errors.append(f"implementation mapping asset or reference in {relative}")
            if LIFECYCLE_MARKER.search(text):
                errors.append(f"lifecycle marker must stay in task coordination, not the repository: {relative}")
            if path.parent.name == "scripts":
                if RAW_DECODER.search(text):
                    errors.append(f"a byte-level GTP-U decoder must not appear in {relative}")
                if PFCP_JOIN.search(text):
                    errors.append(f"PFCP join logic must not appear in {relative}")
                if NGAP_JOIN.search(text):
                    errors.append(f"NGAP join logic must not appear in {relative}")
                if NAS_JOIN.search(text):
                    errors.append(f"NAS join logic must not appear in {relative}")
                if SBI_SEMANTICS.search(text):
                    errors.append(f"SBI semantics must not appear in {relative}")
                if APP_PAYLOAD.search(text):
                    errors.append(f"application payload handling must not appear in {relative}")
                if PACKET_LOSS_VERDICT.search(text):
                    errors.append(f"a packet-loss verdict must not appear in {relative}")
            if path.name == "gtpu_model.py" and DIRECTED_KEY_MARKER not in text:
                errors.append("the directed stream key must include capture, endpoints and TEID")
            if path.parent.name in {"extracted", "expected"}:
                if SUBSCRIBER_FIELD.search(text):
                    errors.append(f"subscriber identity field in fixture {relative}")
                if SECRET_FIELD.search(text):
                    errors.append(f"credential-like material in fixture {relative}")
                for match in IPV4.finditer(text):
                    if not match.group(0).startswith(DOC_IPV4_PREFIXES):
                        errors.append(f"non-documentation IP address {match.group(0)} in fixture {relative}")
                        break

    for directory, label in ((skill / "scripts", "script"), (skill / "tests", "test")):
        for script in directory.glob("*.py"):
            try:
                py_compile.compile(str(script), doraise=True)
            except py_compile.PyCompileError as exc:
                errors.append(f"{label} does not compile: {script.name}: {exc.msg}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("gtpu validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("gtpu validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
