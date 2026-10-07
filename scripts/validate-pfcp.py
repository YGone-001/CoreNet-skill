#!/usr/bin/env python3
"""Validate the standalone pfcp Protocol Skill contract."""

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

SKILL = Path("skills/protocol/pfcp")
REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/protocol-model.md",
    "references/message-map.md",
    "references/field-reference.md",
    "references/session-identifiers.md",
    "references/rule-model.md",
    "references/correlation.md",
    "references/failure-cases.md",
    "scripts/pfcp_model.py",
    "scripts/extract-pfcp.py",
    "scripts/correlate-pfcp.py",
    "scripts/pfcp_timeline.py",
    "schemas/pfcp-event.schema.json",
    "schemas/pfcp-correlation.schema.json",
    "schemas/trace-event.schema.json",
    "filters/wireshark.txt",
    "examples/extracted/node-signaling.jsonl",
    "examples/extracted/establishment.jsonl",
    "examples/extracted/modification.jsonl",
    "examples/extracted/deletion.jsonl",
    "examples/extracted/transactions.jsonl",
    "examples/extracted/rule-binding.jsonl",
    "examples/extracted/recognition.jsonl",
    "examples/extracted/addresses.jsonl",
    "examples/extracted/malformed.jsonl",
    "examples/expected/node-signaling-events.jsonl",
    "examples/expected/establishment-events.jsonl",
    "examples/expected/modification-events.jsonl",
    "examples/expected/deletion-events.jsonl",
    "examples/expected/transactions-events.jsonl",
    "examples/expected/transactions-correlation.json",
    "examples/expected/rule-binding-events.jsonl",
    "examples/expected/recognition-events.jsonl",
    "examples/expected/addresses-events.jsonl",
    "tests/test_pfcp.py",
)
REQUIRED_FIXTURES = (
    "examples/extracted/establishment.jsonl",
    "examples/extracted/modification.jsonl",
    "examples/extracted/deletion.jsonl",
    "examples/extracted/node-signaling.jsonl",
)
EXPECTED_EVENTS = (
    "examples/expected/node-signaling-events.jsonl",
    "examples/expected/establishment-events.jsonl",
    "examples/expected/modification-events.jsonl",
    "examples/expected/deletion-events.jsonl",
    "examples/expected/transactions-events.jsonl",
    "examples/expected/rule-binding-events.jsonl",
    "examples/expected/recognition-events.jsonl",
    "examples/expected/addresses-events.jsonl",
)
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
IMPLEMENTATION_ASSET = re.compile(
    IMPLEMENTATION_TOKEN_PATTERN +
    r"|openairinterface|srsran|ueransim|nokia|ericsson|huawei|zte|smf\.(?:c|cc|cpp|h|go|py)\b|upf\.(?:c|cc|cpp|h|go|py)\b")
SUBSCRIBER_FIELD = re.compile(r"(?i)[\"']?(?:imsi|msisdn|suci|supi|fiveg?[-_]guti|guti)[\"']?\s*[:=]")
SECRET_FIELD = re.compile(r"(?i)[\"']?(?:password|passwd|secret|api[_-]?key|private[_-]?key|token)[\"']?\s*[:=]\s*[\"'][^\"']{6,}")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s+[0-9]+\b|\bmilestone\s+b?[0-9]+\b")
# Other-layer semantics must not leak into this Protocol Skill. The tokens
# below are implementation identifiers, not boundary prose: a docstring that
# says "never decodes GTP-U" must stay allowed.
FOREIGN_SEMANTICS = re.compile(r"(?i)\b(?:gtpu|gtp_?u_|parse_gtp|sbi_client|http2|nsmf_pdusession|teid_forwarding|user_plane_packet)\w*")
# A hand-written binary PFCP decoder is explicitly out of scope.
RAW_DECODER = re.compile(r"(?i)struct\.unpack|int\.from_bytes|bytes\.fromhex|memoryview\(|def\s+parse_pfcp_header")
# Positional zipping of repeated grouped fields is forbidden.
ZIP_LOGIC = re.compile(r"(?i)\bzip\(\s*(?:pdr|far|qer|urr|teid|qfi|rule)|for\s+\w+\s*,\s*\w+\s+in\s+zip\(")
NAS_OR_NGAP = re.compile(r"(?i)\bdecode_nas|nas_decoder|dissect_nas|amf_ue_ngap_id|ran_ue_ngap_id|fivegmm|fivegsm\b")
IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
DOC_IPV4_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
TEXT_SUFFIXES = {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}
RULE_ARRAYS = ("pdrs", "fars", "qers", "urrs")


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
    for key, expected in (("name", "pfcp"), ("version", "0.1.1"), ("category", "protocol")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"manifest {key} must be {expected}")
    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append("manifest must not require another CoreNet Skill")
    if "PFCP" not in manifest_list(manifest, "protocols"):
        errors.append("manifest protocols must include PFCP")
    interfaces = manifest_list(manifest, "interfaces")
    if interfaces and "N4" not in interfaces:
        errors.append("manifest interface ownership must be N4")
    if manifest_value(manifest, "network_functions") not in (None, "[]"):
        errors.append("manifest network_functions must stay empty for a Protocol Skill")

    model_text = (skill / "scripts" / "pfcp_model.py").read_text(encoding="utf-8")
    if "FieldSpec" not in model_text:
        errors.append("pfcp_model.py must implement FieldSpec compatibility model")
    if "resolve_field_specs" not in model_text:
        errors.append("pfcp_model.py must provide resolve_field_specs")

    local_trace = skill / "schemas" / "trace-event.schema.json"
    shared_trace = root / "shared" / "schemas" / "trace-event.schema.json"
    if not shared_trace.is_file() or digest(local_trace) != digest(shared_trace):
        errors.append("package-local trace schema must match the authoritative shared schema bytes")

    try:
        event_schema = json.loads((skill / "schemas" / "pfcp-event.schema.json").read_text(encoding="utf-8"))
        required = event_schema.get("required", [])
        for key in ("timestamp", "frame_number", "capture_file", "header", "support_status", "cause", "rule_operations", "evidence", "derivations"):
            if key not in required:
                errors.append(f"pfcp-event schema must require {key}")
        properties = event_schema.get("properties", {})
        if properties.get("evidence", {}).get("properties", {}).get("level", {}).get("const") != "OBSERVED":
            errors.append("pfcp-event schema evidence.level must stay OBSERVED")
        rule_operations = properties.get("rule_operations", {})
        for key in RULE_ARRAYS:
            if rule_operations.get("properties", {}).get(key, {}).get("type") != "array":
                errors.append(f"pfcp-event schema rule_operations.{key} must be an array")
        if "unbound_ie_metadata" not in properties:
            errors.append("pfcp-event schema must expose unbound_ie_metadata")
        session_properties = properties.get("session", {}).get("properties", {})
        for key in ("cp_f_seid", "up_f_seid"):
            if key not in session_properties:
                errors.append(f"pfcp-event schema session must model {key}")
        if "seid_expected_zero" not in properties.get("header", {}).get("properties", {}):
            errors.append("pfcp-event schema header must expose seid_expected_zero")
    except json.JSONDecodeError as exc:
        errors.append(f"pfcp-event schema is invalid JSON: {exc}")

    try:
        json.loads((skill / "schemas" / "pfcp-correlation.schema.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"pfcp-correlation schema is invalid JSON: {exc}")

    for relative in REQUIRED_FIXTURES:
        try:
            if not jsonl_records(skill / relative):
                errors.append(f"fixture must not be empty: {relative}")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"fixture is invalid: {relative}: {exc}")

    multi_rule = False
    ambiguous_binding = False
    transaction_isolation = False
    for relative in EXPECTED_EVENTS:
        try:
            for event in jsonl_records(skill / relative):
                rules = event.get("rule_operations")
                if isinstance(rules, dict):
                    total = sum(len(rules.get(key) or []) for key in RULE_ARRAYS)
                    if total >= 2:
                        multi_rule = True
                unbound = event.get("unbound_ie_metadata")
                if isinstance(unbound, dict) and (unbound.get("teids") or unbound.get("qfis")):
                    ambiguous_binding = True
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"expected fixture is invalid: {relative}: {exc}")
    try:
        correlation = json.loads((skill / "examples" / "expected" / "transactions-correlation.json").read_text(encoding="utf-8"))
        keys = [item["transaction_key"] for item in correlation.get("transactions", []) + correlation.get("open_transactions", [])]
        if len(keys) != len(set(keys)):
            errors.append("transaction correlation fixture must keep same-sequence transactions separate")
        families = [item for item in correlation.get("open_transactions", [])]
        if len(families) >= 2:
            transaction_isolation = True
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"correlation fixture is invalid: {exc}")
    if not multi_rule:
        errors.append("at least one expected fixture must contain a message with two or more rule groups")
    if not ambiguous_binding:
        errors.append("at least one expected fixture must preserve ambiguous (unbound) nested rule metadata")
    if not transaction_isolation:
        errors.append("the correlation fixture must prove endpoint-scoped transaction isolation")

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
                    errors.append(f"foreign protocol semantics (GTP-U/SBI/NAS/NGAP) must not appear in {relative}")
                if RAW_DECODER.search(text):
                    errors.append(f"a hand-written binary PFCP decoder must not appear in {relative}")
                if ZIP_LOGIC.search(text):
                    errors.append(f"positional zipping of repeated grouped fields must not appear in {relative}")
                if NAS_OR_NGAP.search(text):
                    errors.append(f"NAS/NGAP decoding must not appear in {relative}")
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
        print("pfcp validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("pfcp validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
