#!/usr/bin/env python3
"""Validate the standalone nas-5gs Protocol Skill package contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import py_compile
import re
import sys
from pathlib import Path

SKILL = Path("skills/protocol/nas-5gs")
REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/protocol-model.md",
    "references/message-map.md",
    "references/field-reference.md",
    "references/security-envelope.md",
    "references/identity-privacy.md",
    "references/failure-cases.md",
    "scripts/nas5gs_model.py",
    "scripts/extract-nas5gs.py",
    "scripts/nas5gs_timeline.py",
    "schemas/nas5gs-event.schema.json",
    "schemas/trace-event.schema.json",
    "filters/wireshark.txt",
    "examples/extracted/registration-flow.jsonl",
    "examples/extracted/rejection-flow.jsonl",
    "examples/extracted/service-flow.jsonl",
    "examples/extracted/protection-variants.jsonl",
    "examples/extracted/deferred-unknown.jsonl",
    "examples/extracted/mobility-types.jsonl",
    "examples/extracted/malformed.jsonl",
    "examples/extracted/missing-required.jsonl",
    "examples/extracted/sm-establishment-request.jsonl",
    "examples/extracted/sm-establishment-accept.jsonl",
    "examples/extracted/sm-establishment-accept-multi-qfi.jsonl",
    "examples/extracted/sm-establishment-reject.jsonl",
    "examples/extracted/sm-modification.jsonl",
    "examples/extracted/sm-release.jsonl",
    "examples/extracted/sm-status.jsonl",
    "examples/extracted/sm-recognition.jsonl",
    "examples/extracted/sm-session-identity.jsonl",
    "examples/extracted/sm-protection.jsonl",
    "examples/extracted/sm-malformed.jsonl",
    "examples/expected/registration-flow-events.jsonl",
    "examples/expected/registration-flow-trace.jsonl",
    "examples/expected/rejection-flow-events.jsonl",
    "examples/expected/service-flow-events.jsonl",
    "examples/expected/protection-variants-events.jsonl",
    "examples/expected/deferred-unknown-events.jsonl",
    "examples/expected/mobility-types-events.jsonl",
    "examples/expected/sm-establishment-request-events.jsonl",
    "examples/expected/sm-establishment-accept-events.jsonl",
    "examples/expected/sm-establishment-accept-multi-qfi-events.jsonl",
    "examples/expected/sm-establishment-reject-events.jsonl",
    "examples/expected/sm-modification-events.jsonl",
    "examples/expected/sm-release-events.jsonl",
    "examples/expected/sm-status-events.jsonl",
    "examples/expected/sm-recognition-events.jsonl",
    "examples/expected/sm-session-identity-events.jsonl",
    "examples/expected/sm-protection-events.jsonl",
    "tests/test_nas5gs.py",
)
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
IMPLEMENTATION_ASSET = re.compile(r"(?i)open5gs|free5gc|openairinterface|srsran|amf_?(?:smf|n2|ngap)?\.(?:c|cc|cpp|h|go|py)\b")
NGAP_IDS = re.compile(r"(?i)AMF-UE-NGAP-ID|RAN-UE-NGAP-ID|amf_ue_ngap_id|ran_ue_ngap_id")
SUBSCRIBER_FIELD = re.compile(r"(?i)[\"']?(?:imsi|msisdn|suci|supi|fiveg?[-_]guti|guti|imei)[\"']?\s*[:=]")
SECRET_FIELD = re.compile(r"(?i)[\"']?(?:rand|autn|res|auts|kseaf|kamf|knas[_a-z]*)[\"']?\s*[:=]\s*[\"'][0-9a-fA-F]{8,}")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s+[0-9]+\b|\bmilestone\s+b?[0-9]+\b")
# Other-layer semantic ownership must not leak into this Protocol Skill.
FOREIGN_SEMANTICS = re.compile(r"(?i)\b(?:pfcp|gtp-?u|gtpv2|n3\s*tunnel|sbi|nsmf_pdusession|http/?2\s*service)\w*")
# Session fields the shared projection must never fabricate from NAS evidence.
FABRICATED_SESSION_FIELD = re.compile(r"(?i)[\"'](?:seid|teid|bearer_id)[\"']\s*:")
IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
DOC_IPV4_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap", ".pcapng.gz"}
TEXT_SUFFIXES = {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}
EVENTS_SCHEMA_REQUIRED = (
    "timestamp", "frame_number", "capture_file", "nas_family", "security",
    "message_type_code", "support_status", "cause", "identity", "evidence", "derivations",
)
# Required 5GSM expansion markers in the detailed event contract.
REQUIRED_PROCEDURE_FAMILIES = (
    "PDU_SESSION_ESTABLISHMENT", "PDU_SESSION_MODIFICATION", "PDU_SESSION_RELEASE", "SESSION_MANAGEMENT_STATUS",
)
REQUIRED_DIRECTIONS = ("ue-to-smf", "smf-to-ue")
SUPPORTED_5GSM_FIXTURES = (
    "examples/extracted/sm-establishment-request.jsonl",
    "examples/extracted/sm-establishment-accept.jsonl",
    "examples/extracted/sm-modification.jsonl",
    "examples/extracted/sm-release.jsonl",
    "examples/extracted/sm-status.jsonl",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_value(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def manifest_list(text: str, key: str) -> list[str]:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*\[([^\]]*)\]", text)
    if match is not None:
        return [item.strip() for item in match.group(1).split(",") if item.strip()]
    block = re.search(rf"(?m)^{re.escape(key)}:\s*\n((?:\s+-\s+.+\n?)+)", text)
    if block is None:
        return []
    return [line.strip().lstrip("-").strip() for line in block.group(1).splitlines() if line.strip()]


# Ownership duplication is checked in implementation assets only; docs and
# tests legitimately mention NGAP identifiers when declaring or testing the
# boundary.
OWNERSHIP_DIRS = {"scripts", "schemas"}


def jsonl_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def check_documentation_addresses(text: str) -> list[str]:
    problems: list[str] = []
    for match in IPV4.finditer(text):
        address = match.group(0)
        if not address.startswith(DOC_IPV4_PREFIXES):
            problems.append(address)
    return problems


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    skill = root / SKILL
    if not skill.is_dir():
        return [f"missing package directory: {SKILL}"]
    for relative in REQUIRED:
        if not (skill / relative).is_file():
            errors.append(f"missing required package file: {relative}")
    if errors:
        return errors

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    for key, expected in (("name", "nas-5gs"), ("version", "0.2.0"), ("category", "protocol")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"manifest {key} must be {expected}")
    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append("manifest must not require another CoreNet Skill")
    if "NAS-5GS" not in manifest_list(manifest, "protocols"):
        errors.append("manifest protocols must include NAS-5GS")
    if "N1" not in manifest_list(manifest, "interfaces"):
        errors.append("manifest interfaces must include N1")
    if manifest_value(manifest, "network_functions") != "[]":
        errors.append("manifest network_functions must stay empty for a Protocol Skill")

    local_trace = skill / "schemas" / "trace-event.schema.json"
    shared_trace = root / "shared" / "schemas" / "trace-event.schema.json"
    if not shared_trace.is_file() or digest(local_trace) != digest(shared_trace):
        errors.append("package-local trace schema must match the authoritative shared schema bytes")

    try:
        schema = json.loads((skill / "schemas" / "nas5gs-event.schema.json").read_text(encoding="utf-8"))
        required = schema.get("required", [])
        for key in EVENTS_SCHEMA_REQUIRED:
            if key not in required:
                errors.append(f"nas5gs-event schema must require {key}")
        evidence_level = schema.get("properties", {}).get("evidence", {}).get("properties", {}).get("level", {})
        if evidence_level.get("const") != "OBSERVED":
            errors.append("nas5gs-event schema evidence.level must stay OBSERVED")
        identity_value = schema.get("properties", {}).get("identity", {}).get("properties", {}).get("value", {})
        if identity_value.get("type") != ["string", "null"]:
            errors.append("nas5gs-event schema identity.value must stay nullable for redaction")
        properties = schema.get("properties", {})
        if "session_management" not in properties:
            errors.append("nas5gs-event schema must expose the optional session_management object")
        if "session_management" in required:
            errors.append("session_management must stay optional so 5GMM events keep the 0.1.0 shape")
        epd = properties.get("protocol_discriminator", {})
        if 46 not in epd.get("enum", []) or 126 not in epd.get("enum", []):
            errors.append("nas5gs-event schema protocol_discriminator must allow both 5GMM (126) and 5GSM (46)")
        directions = properties.get("direction", {}).get("enum", [])
        for direction in REQUIRED_DIRECTIONS:
            if direction not in directions:
                errors.append(f"nas5gs-event schema direction must include {direction}")
        families = properties.get("procedure_family", {}).get("enum", [])
        for family in REQUIRED_PROCEDURE_FAMILIES:
            if family not in families:
                errors.append(f"nas5gs-event schema procedure_family must include {family}")
        cause_properties = properties.get("cause", {}).get("properties", {})
        if "family" not in cause_properties:
            errors.append("nas5gs-event schema cause must expose the optional family distinction")
    except json.JSONDecodeError as exc:
        errors.append(f"nas5gs-event schema is invalid JSON: {exc}")

    for relative in REQUIRED:
        if relative.startswith("examples/expected/") and relative.endswith("-events.jsonl"):
            try:
                records = jsonl_records(skill / relative)
                if not records:
                    errors.append(f"expected events fixture must not be empty: {relative}")
                for index, record in enumerate(records, start=1):
                    if record.get("evidence", {}).get("level") != "OBSERVED":
                        errors.append(f"{relative} event {index} must preserve observed evidence")
                    if record.get("identity", {}).get("value") is not None:
                        errors.append(f"{relative} event {index} must not carry a raw identity value")
                    if record.get("nas_family") == "5GSM" and "session_management" not in record:
                        errors.append(f"{relative} event {index} must carry session_management for a 5GSM record")
                    if record.get("nas_family") != "5GSM" and "session_management" in record:
                        errors.append(f"{relative} event {index} must not carry session_management for a non-5GSM record")
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"expected fixture is invalid: {relative}: {exc}")

    for relative in SUPPORTED_5GSM_FIXTURES:
        if not (skill / relative).is_file():
            errors.append(f"supported 5GSM fixture is missing: {relative}")

    for path in skill.rglob("*"):
        if not path.is_file():
            continue
        name = path.relative_to(root)
        if path.suffix.lower() in CAPTURE_SUFFIXES:
            errors.append(f"binary capture fixture is not allowed: {name}")
        if path.suffix in TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8")
            if "../../../" in text or "third_party/" in text:
                errors.append(f"repository-root runtime reference in {name}")
            if ABSOLUTE_PATH.search(text):
                errors.append(f"absolute workstation path in {name}")
            if IMPLEMENTATION_ASSET.search(text):
                errors.append(f"implementation mapping asset or reference in {name}")
            if path.parent.name in OWNERSHIP_DIRS and NGAP_IDS.search(text):
                errors.append(f"NGAP identifier ownership duplicated in {name}")
            if path.parent.name == "scripts" and FOREIGN_SEMANTICS.search(text):
                errors.append(f"foreign protocol semantics (PFCP/GTP-U/SBI) must not appear in {name}")
            if path.parent.name == "scripts" and FABRICATED_SESSION_FIELD.search(text):
                errors.append(f"session field fabrication (SEID/TEID/bearer_id) is not allowed in {name}")
            if LIFECYCLE_MARKER.search(text):
                errors.append(f"lifecycle marker must stay in task coordination, not the repository: {name}")
            if path.parent.name == "extracted":
                if SUBSCRIBER_FIELD.search(text):
                    errors.append(f"raw subscriber identity field in fixture {name}")
                if SECRET_FIELD.search(text):
                    errors.append(f"authentication secret material in fixture {name}")
            if path.parent.name in {"extracted", "expected"}:
                for address in check_documentation_addresses(text):
                    errors.append(f"non-documentation IP address {address} in fixture {name}")

    for forbidden in ("5gsm-pdu-session", "5gc-pdu-session"):
        if (root / "skills" / "protocol" / forbidden).exists() or (root / "skills" / "domain" / forbidden).exists():
            errors.append(f"{forbidden} must not be created in this milestone")

    for directory in (skill / "scripts", skill / "tests"):
        for script in directory.glob("*.py"):
            try:
                py_compile.compile(str(script), doraise=True)
            except py_compile.PyCompileError as exc:
                errors.append(f"script does not compile: {script.name}: {exc.msg}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("nas-5gs validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("nas-5gs validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
