#!/usr/bin/env python3
"""Validate the standalone procedure-evidence Domain framework package."""

from __future__ import annotations

import argparse
import json
import py_compile
import re
import sys
from pathlib import Path

SKILL = Path("skills/domain/procedure-evidence")
REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/evidence-model.md",
    "scripts/procedure_model.py",
    "scripts/procedure_timeline.py",
    "schemas/procedure-evidence.schema.json",
    "examples/stages/observed-flow.jsonl",
    "examples/stages/missing-evidence.jsonl",
    "examples/stages/derived-flow.jsonl",
    "examples/stages/malformed.jsonl",
    "examples/expected/observed-timeline.txt",
    "examples/expected/missing-timeline.txt",
    "examples/expected/derived-timeline.json",
    "tests/test_procedure_evidence.py",
)
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
IMPLEMENTATION_ASSET = re.compile(r"(?i)open5gs|free5gc|kamailio|freeswitch|rtpengine|openairinterface|srsran|amf_?(?:smf|n2|ngap)?\.(?:c|cc|cpp|h|go|py)\b")
SUBSCRIBER_FIELD = re.compile(r"(?i)[\"']?(?:imsi|msisdn|suci|supi|fiveg?[-_]guti|guti|imei|subscriber)[\"']?\s*[:=]")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s+[0-9]+\b|\bmilestone\s+b?[0-9]+\b")
VERDICT_WORDING = re.compile(r"(?i)\b(?:success(?:ful)?|failed|root[ _-]?cause)\b")
PROCEDURE_NAMES = re.compile(r"(?i)\b(?:5gc[ -]?registration|epc[ -]?attach|ims[ -]?registration|voice[ -]?call)\b")
TEXT_SUFFIXES = {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}


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
    for key, expected in (("name", "procedure-evidence"), ("version", "0.1.0"), ("category", "domain")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"manifest {key} must be {expected}")
    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append("manifest must not require another CoreNet Skill")
    for key in ("protocols", "interfaces", "network_functions"):
        if manifest_block_or_flow(manifest, key) != []:
            errors.append(f"manifest {key} must stay empty: no protocol, interface, or network-function ownership")

    try:
        schema = json.loads((skill / "schemas" / "procedure-evidence.schema.json").read_text(encoding="utf-8"))
        required = schema.get("required", [])
        for key in ("procedure_name", "stage", "expected_evidence", "observed_evidence", "missing_evidence", "evidence_basis", "confidence", "limitations"):
            if key not in required:
                errors.append(f"procedure-evidence schema must require {key}")
        properties = schema.get("properties", {})
        if properties.get("evidence_basis", {}).get("enum") != ["OBSERVED", "DERIVED"]:
            errors.append("procedure-evidence schema evidence_basis must be OBSERVED/DERIVED only")
        if properties.get("confidence", {}).get("enum") != ["HIGH", "MEDIUM", "LOW"]:
            errors.append("procedure-evidence schema confidence must be HIGH/MEDIUM/LOW only")
        verdict_keys = [key for key in properties if re.search(r"(?i)success|failure|failed|root_cause|verdict", key)]
        if verdict_keys:
            errors.append(f"procedure-evidence schema must not own verdict fields: {verdict_keys}")
    except json.JSONDecodeError as exc:
        errors.append(f"procedure-evidence schema is invalid JSON: {exc}")

    for path in skill.rglob("*"):
        if not path.is_file():
            continue
        name = path.relative_to(root)
        if path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
            errors.append(f"binary capture fixture is not allowed: {name}")
        if path.suffix in TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8")
            if "../../../" in text or "third_party/" in text:
                errors.append(f"repository-root runtime reference in {name}")
            if ABSOLUTE_PATH.search(text):
                errors.append(f"absolute workstation path in {name}")
            if path.parent.name != "tests" and IMPLEMENTATION_ASSET.search(text):
                errors.append(f"implementation mapping asset or reference in {name}")
            if LIFECYCLE_MARKER.search(text):
                errors.append(f"lifecycle marker must stay in task coordination, not the repository: {name}")
            if path.suffix == ".py" and PROCEDURE_NAMES.search(text):
                errors.append(f"concrete telecom procedure name in implementation code: {name}")

    for fixture in sorted((skill / "examples" / "stages").glob("*.jsonl")):
        if fixture.name == "malformed.jsonl":
            continue
        try:
            records = [json.loads(line) for line in fixture.read_text(encoding="utf-8").splitlines() if line.strip()]
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"fixture is invalid: {fixture.name}: {exc}")
            continue
        if not records:
            errors.append(f"fixture must not be empty: {fixture.name}")
        for index, record in enumerate(records, start=1):
            if record.get("evidence_basis") not in ("OBSERVED", "DERIVED"):
                errors.append(f"{fixture.name} record {index} must use OBSERVED or DERIVED basis")
            for field in ("expected_evidence", "observed_evidence", "missing_evidence", "limitations"):
                for item in record.get(field, []):
                    if VERDICT_WORDING.search(item):
                        errors.append(f"{fixture.name} record {index} {field} carries verdict wording")

    for script_dir in (skill / "scripts", skill / "tests"):
        for script in script_dir.glob("*.py"):
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
        print("procedure-evidence validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("procedure-evidence validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
