#!/usr/bin/env python3
"""Validate the standalone 5GC PDU Session Domain Skill."""

from __future__ import annotations

import argparse
import hashlib
import json
import py_compile
import re
import sys
from pathlib import Path

SKILL = Path("skills/domain/5gc-pdu-session")
PROCEDURE_EVIDENCE_SCHEMA = Path("skills/domain/procedure-evidence/schemas/procedure-evidence.schema.json")

REQUIRED = (
    "SKILL.md", "README.md", "manifest.yaml",
    "references/procedure-model.md", "references/stage-model.md",
    "references/association-model.md", "references/deviation-model.md",
    "references/field-findings.md", "references/failure-cases.md",
    "scripts/pdu_session_model.py", "scripts/analyze_pdu_session.py", "scripts/pdu_session_timeline.py",
    "schemas/5gc-pdu-session-analysis.schema.json", "schemas/procedure-evidence.schema.json",
    "tests/test_5gc_pdu_session.py",
)

SCENARIOS = {
    "normal-establishment", "establishment-reject", "create-sm-context-error",
    "pfcp-negative-cause", "ngap-failed-resource", "ngap-mixed-resources",
    "namf-pending-202", "namf-failure-notification", "no-gtpu-traffic",
    "multi-ue-same-psi", "sbi-ambiguity", "teid-reuse-different-endpoints",
    "address-and-qfi-conflict", "partial-capture",
}

CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
TEXT_SUFFIXES = {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
SUBSCRIBER_VALUE = re.compile(r'(?i)"(?:imsi|supi|suci|msisdn|imei)"\s*:\s*"[^"\n]+"')
AUTH_VECTOR = re.compile(r'(?i)"(?:rand|autn|res\*?|hxres\*?|kausf|kseaf|kamf)"\s*:\s*"[^"\n]+"')
IMPLEMENTATION_MAPPING = re.compile(r"(?is)(?:open5gs|free5gc|openairinterface|srsran|vendor).{0,120}(?:source|handler|function|path|mapping|module)")
RAW_DECODER = re.compile(r"(?i)def\s+(?:parse|decode)[a-z0-9_]*(?:nas|ngap|pfcp|gtp|packet|payload)|(?:raw_)?(?:nas|ngap|pfcp|gtpu)_payload\s*=")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s*[0-9]+\b|\bmilestone\s*[a-z]?[0-9]+\b")
FORBIDDEN_SCHEMA_FIELDS = re.compile(r"(?i)root_?cause|culprit|implementation|vendor|product_?bug")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_value(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def manifest_block_or_flow(text: str, key: str) -> list[str]:
    match = re.search(rf"(?m)^\s*{re.escape(key)}:\s*\[([^\]]*)\]", text)
    if match:
        return [item.strip() for item in match.group(1).split(",") if item.strip()]
    block = re.search(rf"(?m)^\s*{re.escape(key)}:\s*\n((?:\s+-\s+.+\n?)+)", text)
    if not block:
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
    for key, expected in (("name", "5gc-pdu-session"), ("version", "0.1.0"), ("category", "domain")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"manifest {key} must be {expected}")

    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append("manifest required dependencies must be empty")
    if manifest_block_or_flow(manifest, "protocols") != []:
        errors.append("manifest protocols must remain empty")
    if manifest_block_or_flow(manifest, "network_functions") != []:
        errors.append("manifest network_functions must remain empty")
    if set(manifest_block_or_flow(manifest, "interfaces")) != {"N1", "N2", "N3", "N4", "N11"}:
        errors.append("manifest interfaces must be N1, N2, N3, N4, N11")

    # Check that expected lower Skill dependencies are declared in optional dependencies
    optional_deps = " ".join(manifest_block_or_flow(manifest, "optional"))
    for exp_dep in ("nas-5gs", "ngap", "pfcp", "gtpu", "sbi-http2", "procedure-evidence"):
        if exp_dep not in optional_deps:
            errors.append(f"manifest optional dependencies should include {exp_dep}")

    local_evidence = skill / "schemas/procedure-evidence.schema.json"
    shared_evidence = root / PROCEDURE_EVIDENCE_SCHEMA
    if not shared_evidence.is_file() or digest(local_evidence) != digest(shared_evidence):
        errors.append("package-local procedure-evidence schema must match the generic framework bytes")

    try:
        schema = json.loads((skill / "schemas/5gc-pdu-session-analysis.schema.json").read_text(encoding="utf-8"))
        properties = schema.get("properties", {})
        for field in ("procedure_name", "procedure_version", "instances", "unbound_evidence", "limitations"):
            if field not in properties:
                errors.append(f"analysis schema must define {field}")
        instance = schema.get("$defs", {}).get("instanceAnalysis", {})
        instance_properties = instance.get("properties", {}) if isinstance(instance, dict) else {}
        for field in (
            "instance_id", "association_basis", "association_strength", "ue_context",
            "pdu_session_id", "stages", "terminal_observation", "deviations",
            "earliest_observed_deviation", "field_findings", "plane_bindings",
            "unbound_evidence", "limitations"
        ):
            if field not in instance_properties:
                errors.append(f"analysis schema must define instance {field}")
        forbidden = [field for field in properties if FORBIDDEN_SCHEMA_FIELDS.search(field)]
        if forbidden:
            errors.append(f"analysis schema must not include causal or implementation fields: {forbidden}")
    except json.JSONDecodeError as exc:
        errors.append(f"analysis schema is invalid JSON: {exc}")

    input_root = skill / "examples/inputs"
    actual_scenarios = {path.name for path in input_root.iterdir() if path.is_dir()} if input_root.is_dir() else set()
    if actual_scenarios != SCENARIOS:
        errors.append(f"synthetic input scenarios must cover all 14 bounded cases; found: {actual_scenarios}")

    for scenario in sorted(SCENARIOS):
        sdir = input_root / scenario
        found_any = any((sdir / f).is_file() for f in ("nas.jsonl", "ngap.jsonl", "pfcp.jsonl", "gtpu.jsonl", "sbi.jsonl"))
        if not found_any:
            errors.append(f"missing input files for scenario {scenario}")
        for suffix in ("analysis.json", "stages.jsonl"):
            if not (skill / "examples/expected" / f"{scenario}-{suffix}").is_file():
                errors.append(f"missing expected {suffix} fixture for {scenario}")

    for path in skill.rglob("*"):
        if not path.is_file():
            continue
        name = path.relative_to(root)
        if path.suffix.lower() in CAPTURE_SUFFIXES:
            errors.append(f"binary capture fixture is not allowed: {name}")
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8")
        if "../../../" in text or "third_party/" in text:
            errors.append(f"repository-root runtime reference in {name}")
        if ABSOLUTE_PATH.search(text):
            errors.append(f"absolute workstation path in {name}")
        if LIFECYCLE_MARKER.search(text):
            errors.append(f"repository lifecycle marker in {name}")
        if SUBSCRIBER_VALUE.search(text):
            errors.append(f"subscriber identifier value in {name}")
        if AUTH_VECTOR.search(text):
            errors.append(f"authentication vector value in {name}")
        if path.parent.name != "tests" and path.suffix in {".py", ".json", ".jsonl"} and IMPLEMENTATION_MAPPING.search(text):
            errors.append(f"implementation or vendor source mapping in {name}")
        if path.suffix == ".py" and RAW_DECODER.search(text):
            errors.append(f"raw protocol decoding code in {name}")

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
        print("5gc-pdu-session validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("5gc-pdu-session validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
