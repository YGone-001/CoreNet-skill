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
    "examples/expected/ue-context-events.jsonl",
    "examples/expected/ue-context-trace.jsonl",
    "examples/expected/multi-association-correlation.json",
    "examples/expected/conflict-binding-correlation.json",
    "tests/test_ngap.py",
)
SUPPORTED_FIXTURES = (
    "examples/extracted/ue-context-flow.jsonl",
    "examples/extracted/multi-association.jsonl",
    "examples/extracted/conflict-binding.jsonl",
)
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
IMPLEMENTATION_ASSET = re.compile(r"(?i)open5gs|free5gc|openairinterface|srsran|amf_?(?:smf|n2|ngap)?\.(?:c|cc|cpp|h|go|py)\b")
SUBSCRIBER_FIELD = re.compile(r"(?i)[\"']?(?:imsi|msisdn|suci|supi|fiveg?[-_]guti|guti)[\"']?\s*[:=]")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s+[0-9]+\b|\bmilestone\s+b?[0-9]+\b")
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}


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
    for key, expected in (("name", "ngap"), ("version", "0.1.0"), ("category", "protocol")):
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
        if ngap_schema.get("properties", {}).get("evidence", {}).get("properties", {}).get("level", {}).get("const") != "OBSERVED":
            errors.append("ngap-event schema evidence.level must stay OBSERVED")
    except json.JSONDecodeError as exc:
        errors.append(f"ngap-event schema is invalid JSON: {exc}")

    for name in SUPPORTED_FIXTURES:
        try:
            records = [json.loads(line) for line in (skill / name).read_text(encoding="utf-8").splitlines() if line.strip()]
            if not records:
                errors.append(f"fixture must not be empty: {name}")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"fixture is invalid: {name}: {exc}")

    for path in skill.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if path.suffix.lower() in CAPTURE_SUFFIXES:
            errors.append(f"binary capture fixture is not allowed: {relative}")
        if path.suffix in {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}:
            text = path.read_text(encoding="utf-8")
            if "../../../" in text or "third_party/" in text:
                errors.append(f"repository-root runtime reference in {relative}")
            if ABSOLUTE_PATH.search(text):
                errors.append(f"absolute workstation path in {relative}")
            if IMPLEMENTATION_ASSET.search(text):
                errors.append(f"implementation mapping asset or reference in {relative}")
            if LIFECYCLE_MARKER.search(text):
                errors.append(f"lifecycle marker must stay in task coordination, not the repository: {relative}")
            if path.parent.name == "extracted" and SUBSCRIBER_FIELD.search(text):
                errors.append(f"subscriber identity field in fixture {relative}")

    if (root / "skills/domain/5gc-registration-mobility").exists():
        errors.append("5gc-registration-mobility must not exist; ngap owns no Domain semantics")

    for script in (skill / "scripts").glob("*.py"):
        try:
            py_compile.compile(str(script), doraise=True)
        except py_compile.PyCompileError as exc:
            errors.append(f"script does not compile: {script.name}: {exc.msg}")

    for script in (skill / "tests").glob("*.py"):
        try:
            py_compile.compile(str(script), doraise=True)
        except py_compile.PyCompileError as exc:
            errors.append(f"test does not compile: {script.name}: {exc.msg}")
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
