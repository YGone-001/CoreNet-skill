#!/usr/bin/env python3
"""Validate the standalone core-network-pcap Protocol Skill contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import py_compile
import re
import sys
from pathlib import Path


SKILL = Path("skills/protocol/core-network-pcap")
REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/capture-model.md",
    "references/classification.md",
    "references/correlation-boundaries.md",
    "references/tshark-fields.md",
    "scripts/pcap_normalize.py",
    "scripts/extract-events.py",
    "scripts/capture-inventory.py",
    "filters/README.md",
    "schemas/trace-event.schema.json",
    "examples/extracted/frames.jsonl",
    "examples/expected/events.jsonl",
    "tests/test_core_network_pcap.py",
)
ALLOWED_EVENT_KEYS = {"timestamp", "protocol", "interface", "procedure", "message_type", "source", "destination", "subscriber", "session", "correlation", "result", "packet", "evidence"}
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
SEMANTIC_ASSET = re.compile(r"(?i)(?:^|[-_])(ie|avp|dictionary|message-map)(?:[-_]|$)")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_value(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+)$", text)
    return match.group(1).strip() if match else None


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    skill = root / SKILL
    for relative in REQUIRED:
        if not (skill / relative).is_file():
            errors.append(f"missing required package file: {relative}")
    if errors:
        return errors

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    for key, expected in (("name", "core-network-pcap"), ("version", "0.1.0"), ("category", "protocol")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"manifest {key} must be {expected}")
    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append("manifest must not require another CoreNet Skill")
    for key in ("protocols", "interfaces", "network_functions"):
        if manifest_value(manifest, key) != "[]":
            errors.append(f"manifest {key} must be empty")

    local_schema = skill / "schemas" / "trace-event.schema.json"
    shared_schema = root / "shared" / "schemas" / "trace-event.schema.json"
    if not shared_schema.is_file() or digest(local_schema) != digest(shared_schema):
        errors.append("package-local trace schema must match the authoritative shared schema bytes")
    else:
        try:
            schema = json.loads(local_schema.read_text(encoding="utf-8"))
            if schema.get("required") != ["timestamp", "protocol"]:
                errors.append("package-local trace schema has an incompatible required-event contract")
        except json.JSONDecodeError as exc:
            errors.append(f"package-local trace schema is invalid JSON: {exc}")

    for path in skill.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
            errors.append(f"binary capture fixture is not allowed: {path.relative_to(root)}")
        if path.is_file() and SEMANTIC_ASSET.search(path.stem):
            errors.append(f"prohibited protocol-semantic asset name: {path.relative_to(root)}")
        if path.is_file() and path.suffix in {".md", ".py", ".yaml", ".json"}:
            text = path.read_text(encoding="utf-8")
            if "../../../" in text or "third_party/" in text:
                errors.append(f"repository-root runtime reference in {path.relative_to(root)}")
            if ABSOLUTE_PATH.search(text):
                errors.append(f"absolute workstation path in {path.relative_to(root)}")

    for script in (skill / "scripts").glob("*.py"):
        try:
            py_compile.compile(str(script), doraise=True)
        except py_compile.PyCompileError as exc:
            errors.append(f"script does not compile: {script.name}: {exc.msg}")

    expected = skill / "examples" / "expected" / "events.jsonl"
    try:
        records = [json.loads(line) for line in expected.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not records:
            errors.append("expected events fixture must not be empty")
        for index, record in enumerate(records, start=1):
            if not isinstance(record, dict) or not {"timestamp", "protocol", "packet", "evidence"}.issubset(record):
                errors.append(f"expected event {index} lacks the minimum trace contract")
            elif set(record).difference(ALLOWED_EVENT_KEYS):
                errors.append(f"expected event {index} has unsupported trace keys")
            elif record["evidence"].get("level") != "OBSERVED":
                errors.append(f"expected event {index} must preserve observed capture evidence")
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"expected events fixture is invalid: {exc}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("core-network-pcap validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("core-network-pcap validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
