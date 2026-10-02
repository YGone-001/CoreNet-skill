#!/usr/bin/env python3
"""Validate the standalone cross-protocol-evidence Correlation package."""

from __future__ import annotations

import argparse
import hashlib
import json
import py_compile
import re
import sys
from pathlib import Path

SKILL = Path("skills/correlation/cross-protocol-evidence")
REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/correlation-model.md",
    "references/provenance.md",
    "references/timeline-model.md",
    "references/failure-boundaries.md",
    "scripts/correlate_events.py",
    "scripts/correlate-events.py",
    "scripts/evidence-timeline.py",
    "schemas/correlation-event.schema.json",
    "schemas/trace-event.schema.json",
    "examples/ngap-input/join-flow.jsonl",
    "examples/ngap-input/ngap-only.jsonl",
    "examples/ngap-input/out-of-order.jsonl",
    "examples/ngap-input/duplicates.jsonl",
    "examples/nas-input/join-flow.jsonl",
    "examples/nas-input/nas-only.jsonl",
    "examples/expected/join-flow-correlation.jsonl",
    "examples/expected/ngap-only-correlation.jsonl",
    "examples/expected/nas-only-correlation.jsonl",
    "examples/expected/out-of-order-correlation.jsonl",
    "examples/expected/duplicates-correlation.jsonl",
    "tests/test_cross_protocol_evidence.py",
)
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
IMPLEMENTATION_ASSET = re.compile(r"(?i)open5gs|free5gc|openairinterface|srsran|amf_?(?:smf|n2|ngap)?\.(?:c|cc|cpp|h|go|py)\b")
SENSITIVE_FIELD = re.compile(r"(?i)[\"']?(?:imsi|msisdn|suci|supi|fiveg?[-_]guti|guti|imei|rand|autn|res|auts|kseaf|kamf|identity_value)[\"']?\s*[:=]")
PROTOCOL_OWNERSHIP = re.compile(r"(?i)def\s+\w*(?:parse|decode)\w*(?:nas|ngap)|nas_payload\s*=|procedure_code\s*=\s*int")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s+[0-9]+\b|\bmilestone\s+b?[0-9]+\b")
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
TEXT_SUFFIXES = {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_value(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def manifest_block_or_flow(text: str, key: str) -> list[str]:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*\[([^\]]*)\]", text)
    if match is not None:
        return [item.strip() for item in match.group(1).split(",") if item.strip()]
    block = re.search(rf"(?m)^{re.escape(key)}:\s*\n((?:\s+-\s+.+\n?)+)", text)
    if block is None:
        return []
    return [line.strip().lstrip("-").strip() for line in block.group(1).splitlines() if line.strip()]


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
    for key, expected in (("name", "cross-protocol-evidence"), ("version", "0.1.0"), ("category", "correlation")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"manifest {key} must be {expected}")
    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append("manifest must not require another CoreNet Skill")
    for key in ("protocols", "interfaces", "network_functions"):
        if manifest_block_or_flow(manifest, key) != []:
            errors.append(f"manifest {key} must stay empty: this package owns correlation only")

    local_trace = skill / "schemas" / "trace-event.schema.json"
    shared_trace = root / "shared" / "schemas" / "trace-event.schema.json"
    if not shared_trace.is_file() or digest(local_trace) != digest(shared_trace):
        errors.append("package-local trace schema must match the authoritative shared schema bytes")

    try:
        schema = json.loads((skill / "schemas" / "correlation-event.schema.json").read_text(encoding="utf-8"))
        required = schema.get("required", [])
        for key in ("timestamp", "capture_file", "frame_number", "protocol_sources", "events", "correlation_strength", "evidence"):
            if key not in required:
                errors.append(f"correlation-event schema must require {key}")
        properties = schema.get("properties", {})
        if set(properties.get("correlation_strength", {}).get("enum", [])) != {"STRONG", "MEDIUM", "WEAK"}:
            errors.append("correlation-event schema strength must be STRONG/MEDIUM/WEAK")
        forbidden = [key for key in properties if re.search(r"(?i)root_cause|success|failure|status|subscriber|session", key)]
        if forbidden:
            errors.append(f"correlation-event schema must not own verdict fields: {forbidden}")
    except json.JSONDecodeError as exc:
        errors.append(f"correlation-event schema is invalid JSON: {exc}")

    for name in ("join-flow-correlation", "ngap-only-correlation", "nas-only-correlation", "out-of-order-correlation", "duplicates-correlation"):
        try:
            records = [json.loads(line) for line in (skill / "examples" / "expected" / f"{name}.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            if not records:
                errors.append(f"expected correlation fixture must not be empty: {name}")
            for index, record in enumerate(records, start=1):
                if record.get("evidence", {}).get("level") != "DERIVED":
                    errors.append(f"{name} record {index} must label derived correlation evidence")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"expected correlation fixture is invalid: {name}: {exc}")

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
            if LIFECYCLE_MARKER.search(text):
                errors.append(f"lifecycle marker must stay in task coordination, not the repository: {name}")
            if path.suffix == ".py" and PROTOCOL_OWNERSHIP.search(text):
                errors.append(f"protocol ownership duplication in {name}")
            if path.parent.name in {"ngap-input", "nas-input", "expected"} and SENSITIVE_FIELD.search(text):
                errors.append(f"sensitive field in fixture {name}")

    # Domain-layer ownership is enforced by scripts/validate-architecture.py
    # (layer direction: correlation must never depend on a Domain Skill); no
    # domain-directory ban is needed here.

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
        print("cross-protocol-evidence validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("cross-protocol-evidence validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
