#!/usr/bin/env python3
"""Validate the standalone ngap Protocol Skill contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import py_compile
import re
import sys
from pathlib import Path

SKILL = Path("skills/protocol/ngap")
REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/protocol-model.md",
    "references/procedure-map.md",
    "references/field-reference.md",
    "references/correlation.md",
    "references/failure-cases.md",
    "scripts/ngap_model.py",
    "scripts/extract-ngap.py",
    "scripts/correlate-ngap.py",
    "scripts/ngap_timeline.py",
    "schemas/ngap-event.schema.json",
    "schemas/trace-event.schema.json",
    "filters/wireshark.txt",
    "examples/extracted/ue-context-flow.jsonl",
    "examples/extracted/multi-association.jsonl",
    "examples/extracted/conflict-binding.jsonl",
    "examples/extracted/malformed.jsonl",
    "examples/extracted/missing-required.jsonl",
    "examples/extracted/pdu-session-setup.jsonl",
    "examples/extracted/pdu-session-modify.jsonl",
    "examples/extracted/pdu-session-release.jsonl",
    "examples/extracted/initial-context-resources.jsonl",
    "examples/extracted/pdu-session-qfi.jsonl",
    "examples/extracted/pdu-session-identity.jsonl",
    "examples/extracted/pdu-session-recognition.jsonl",
    "examples/extracted/pdu-session-ordering.jsonl",
    "examples/expected/ue-context-events.jsonl",
    "examples/expected/ue-context-trace.jsonl",
    "examples/expected/multi-association-correlation.json",
    "examples/expected/conflict-binding-correlation.json",
    "examples/expected/pdu-session-setup-events.jsonl",
    "examples/expected/pdu-session-modify-events.jsonl",
    "examples/expected/pdu-session-release-events.jsonl",
    "examples/expected/initial-context-resources-events.jsonl",
    "examples/expected/pdu-session-qfi-events.jsonl",
    "examples/expected/pdu-session-identity-events.jsonl",
    "examples/expected/pdu-session-recognition-events.jsonl",
    "examples/expected/pdu-session-ordering-events.jsonl",
    "tests/test_ngap.py",
)
SUPPORTED_FIXTURES = (
    "examples/extracted/ue-context-flow.jsonl",
    "examples/extracted/multi-association.jsonl",
    "examples/extracted/conflict-binding.jsonl",
    "examples/extracted/pdu-session-setup.jsonl",
    "examples/extracted/pdu-session-modify.jsonl",
    "examples/extracted/pdu-session-release.jsonl",
    "examples/extracted/initial-context-resources.jsonl",
    "examples/extracted/pdu-session-qfi.jsonl",
)
RESOURCE_EXPECTED = (
    "examples/expected/pdu-session-setup-events.jsonl",
    "examples/expected/pdu-session-modify-events.jsonl",
    "examples/expected/pdu-session-release-events.jsonl",
    "examples/expected/initial-context-resources-events.jsonl",
    "examples/expected/pdu-session-qfi-events.jsonl",
    "examples/expected/pdu-session-identity-events.jsonl",
    "examples/expected/pdu-session-recognition-events.jsonl",
    "examples/expected/pdu-session-ordering-events.jsonl",
)
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
IMPLEMENTATION_ASSET = re.compile(r"(?i)open5gs|free5gc|openairinterface|srsran|ueransim|nokia|ericsson|huawei|zte|amf_?(?:smf|n2|ngap)?\.(?:c|cc|cpp|h|go|py)\b")
SUBSCRIBER_FIELD = re.compile(r"(?i)[\"']?(?:imsi|msisdn|suci|supi|fiveg?[-_]guti|guti)[\"']?\s*[:=]")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s+[0-9]+\b|\bmilestone\s+b?[0-9]+\b")
# Other-layer ownership must not leak into this Protocol Skill's implementation.
FOREIGN_SEMANTICS = re.compile(r"(?i)\b(?:pfcp|gtp-?u|gtpv2|teid|seid|sbi|nsmf_pdusession)\w*")
ASN1_DECODER = re.compile(r"(?i)pyasn1|asn1tools|asn1crypto|import\s+asn1\b")
NAS_DECODER = re.compile(r"(?i)decode_nas|nas_decoder|parse_nas|dissect_nas|decode_nas_pdu")
# Generic session fields NGAP must never fabricate from N2 evidence.
FABRICATED_SESSION_FIELD = re.compile(r"(?i)[\"'](?:seid|teid|bearer_id|apn|dnn|pti)[\"']\s*:")
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
    for key, expected in (("name", "ngap"), ("version", "0.2.0"), ("category", "protocol")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"manifest {key} must be {expected}")
    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append("manifest must not require another CoreNet Skill")
    protocols = manifest_list(manifest, "protocols")
    if "NGAP" not in protocols:
        errors.append("manifest protocols must include NGAP")
    interfaces = manifest_list(manifest, "interfaces")
    if interfaces and "N2" not in interfaces:
        errors.append("manifest interface ownership must be N2")
    if manifest_value(manifest, "network_functions") not in (None, "[]"):
        errors.append("manifest network_functions must stay empty for a Protocol Skill")

    local_trace = skill / "schemas" / "trace-event.schema.json"
    shared_trace = root / "shared" / "schemas" / "trace-event.schema.json"
    if not shared_trace.is_file() or digest(local_trace) != digest(shared_trace):
        errors.append("package-local trace schema must match the authoritative shared schema bytes")

    try:
        ngap_schema = json.loads((skill / "schemas" / "ngap-event.schema.json").read_text(encoding="utf-8"))
        required = ngap_schema.get("required", [])
        for key in ("timestamp", "frame_number", "capture_file", "procedure_code", "support_status", "evidence", "nas_pdu_present"):
            if key not in required:
                errors.append(f"ngap-event schema must require {key}")
        properties = ngap_schema.get("properties", {})
        if ngap_schema.get("properties", {}).get("evidence", {}).get("properties", {}).get("level", {}).get("const") != "OBSERVED":
            errors.append("ngap-event schema evidence.level must stay OBSERVED")
        if "pdu_session_resources" not in properties:
            errors.append("ngap-event schema must expose the optional pdu_session_resources array")
        if "pdu_session_resources" in required:
            errors.append("pdu_session_resources must stay optional so 0.1.0 events remain valid")
        if properties.get("pdu_session_resources", {}).get("type") != "array":
            errors.append("pdu_session_resources must be an array so multiple PDU Sessions are representable")
        resource_item = ngap_schema.get("$defs", {}).get("resourceItem", {})
        item_properties = resource_item.get("properties", {})
        for key in ("pdu_session_id", "resource_operation", "resource_list_role", "snssai", "nas_pdu_present", "transfer", "qfi_values", "cause", "binding_basis"):
            if key not in item_properties:
                errors.append(f"resourceItem schema must model {key}")
        if "unbound_resource_metadata" not in properties:
            errors.append("ngap-event schema must expose unbound_resource_metadata for unsafely bound nested values")
    except json.JSONDecodeError as exc:
        errors.append(f"ngap-event schema is invalid JSON: {exc}")

    for name in SUPPORTED_FIXTURES:
        try:
            if not jsonl_records(skill / name):
                errors.append(f"fixture must not be empty: {name}")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"fixture is invalid: {name}: {exc}")

    multi_resource = False
    mixed_outcome = False
    ambiguous_unbound = False
    for name in RESOURCE_EXPECTED:
        try:
            for event in jsonl_records(skill / name):
                items = event.get("pdu_session_resources")
                if isinstance(items, list):
                    if len(items) >= 2:
                        multi_resource = True
                    roles = {item.get("resource_list_role") for item in items if isinstance(item, dict)}
                    if "SUCCESS" in roles and "FAILED" in roles:
                        mixed_outcome = True
                unbound = event.get("unbound_resource_metadata")
                if isinstance(unbound, dict) and unbound.get("qfi_values"):
                    ambiguous_unbound = True
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"expected fixture is invalid: {name}: {exc}")
    if not multi_resource:
        errors.append("at least one expected fixture must contain a message with two or more PDU Session resources")
    if not mixed_outcome:
        errors.append("at least one expected fixture must contain a response mixing successful and failed resource items")
    if not ambiguous_unbound:
        errors.append("at least one expected fixture must preserve ambiguous (unbound) nested resource metadata")

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
                if FOREIGN_SEMANTICS.search(text):
                    errors.append(f"foreign protocol semantics (PFCP/GTP-U/TEID/SEID/SBI) must not appear in {relative}")
                if ASN1_DECODER.search(text):
                    errors.append(f"a raw ASN.1 decoder must not appear in {relative}")
                if NAS_DECODER.search(text):
                    errors.append(f"NAS decoding must not appear in {relative}")
                if FABRICATED_SESSION_FIELD.search(text):
                    errors.append(f"session field fabrication (TEID/SEID/DNN/PTI/APN) is not allowed in {relative}")
            if path.parent.name in {"extracted", "expected"}:
                if SUBSCRIBER_FIELD.search(text):
                    errors.append(f"subscriber identity field in fixture {relative}")
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
        print("ngap validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("ngap validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
