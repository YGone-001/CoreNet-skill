#!/usr/bin/env python3
"""Validate the standalone 5GC registration/mobility Domain Skill."""

from __future__ import annotations

import argparse
import hashlib
import json
import py_compile
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from implementation_policy import IMPLEMENTATION_TOKEN_GROUP


SKILL = Path("skills/domain/5gc-registration-mobility")
PROCEDURE_EVIDENCE_SCHEMA = Path("skills/domain/procedure-evidence/schemas/procedure-evidence.schema.json")
REQUIRED = (
    "SKILL.md", "README.md", "manifest.yaml",
    "references/procedure-model.md", "references/registration.md",
    "references/authentication-security.md", "references/context-release-paging.md",
    "references/service-access.md", "references/field-findings.md", "references/limitations.md",
    "rules/registration-model.json", "rules/service-access-model.json", "rules/deviation-rules.json",
    "scripts/procedure_model.py", "scripts/analyze-registration.py", "scripts/registration_timeline.py",
    "schemas/5gc-registration-analysis.schema.json", "schemas/procedure-evidence.schema.json",
    "tests/test_5gc_registration.py",
)
SCENARIOS = {
    "full-registration", "identity-branch", "skip-identity", "skip-authentication",
    "registration-reject", "auth-failure", "auth-reject", "security-reject",
    "security-command-truncated", "accept-no-complete", "ics-success", "ics-failure",
    "complete-then-release", "release-paging-no-response", "paging-then-service", "service-reject",
    "two-ue", "cross-association", "out-of-order", "duplicate", "binding-conflict",
    "unsupported-nas", "unknown-ngap", "partial-start", "auth-truncated", "protected-unavailable",
}
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
TEXT_SUFFIXES = {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
SUBSCRIBER_VALUE = re.compile(r'(?i)"(?:imsi|supi|suci|msisdn|imei)"\s*:\s*"[^"\n]+"')
AUTH_VECTOR = re.compile(r'(?i)"(?:rand|autn|res\*?|hxres\*?|kausf|kseaf|kamf)"\s*:\s*"[^"\n]+"')
IMPLEMENTATION_MAPPING = re.compile(r"(?is)(?:" + IMPLEMENTATION_TOKEN_GROUP + r"|openairinterface|srsran|vendor).{0,120}(?:source|handler|function|path|mapping|module)")
RAW_DECODER = re.compile(r"(?i)def\s+(?:parse|decode)[a-z0-9_]*(?:nas|ngap|packet|payload)|(?:raw_)?(?:nas|ngap)_payload\s*=")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s*[0-9]+\b|\bmilestone\s*[a-z]?[0-9]+\b")
FORBIDDEN_SCHEMA_FIELDS = re.compile(r"(?i)root_?cause|implementation|vendor|product_?bug")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_value(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def manifest_block_or_flow(text: str, key: str) -> list[str]:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*\[([^\]]*)\]", text)
    if match:
        return [item.strip() for item in match.group(1).split(",") if item.strip()]
    block = re.search(rf"(?m)^{re.escape(key)}:\s*\n((?:\s+-\s+.+\n?)+)", text)
    if not block:
        return []
    return [line.strip().lstrip("-").strip() for line in block.group(1).splitlines() if line.strip()]


def check_structured_provenance(root: Path, errors: list[str]) -> None:
    """Every OBSERVED boundary-eligible deviation must carry structured event
    provenance; every MISSING_EXPECTED_COUNTERPART must carry an
    observation-window ref. Prose is never a machine identity contract."""
    expected_dir = root / "skills/domain/5gc-registration-mobility/examples/expected"
    if not expected_dir.is_dir():
        return
    eligible_observed = {
        "PROTOCOL_REJECT_OBSERVED", "UNSUCCESSFUL_OUTCOME_OBSERVED",
        "UNKNOWN_OR_RESERVED_PROTOCOL_VALUE", "PROTECTED_INNER_MESSAGE_UNAVAILABLE",
    }
    for path in sorted(expected_dir.glob("*-analysis.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for analysis in doc.get("analyses", []):
            for deviation in analysis.get("deviations", []):
                refs = deviation.get("evidence_refs")
                if not isinstance(refs, list) or not refs:
                    errors.append(f"{path.name}: deviation {deviation.get('type')} lacks structured evidence_refs")
                    continue
                if deviation.get("type") in eligible_observed and deviation.get("evidence_level") == "OBSERVED":
                    if not any(r.get("kind") == "EVENT" and r.get("frame_number") is not None for r in refs):
                        errors.append(f"{path.name}: OBSERVED deviation {deviation.get('type')} lacks a structured EVENT ref with frame provenance")
                if deviation.get("type") == "MISSING_EXPECTED_COUNTERPART":
                    if not any(r.get("kind") == "OBSERVATION_WINDOW" for r in refs):
                        errors.append(f"{path.name}: MISSING_EXPECTED_COUNTERPART lacks an OBSERVATION_WINDOW ref")
                    if any(r.get("kind") == "EVENT" and r.get("frame_number") is not None for r in refs):
                        errors.append(f"{path.name}: MISSING_EXPECTED_COUNTERPART must not carry a fabricated observed frame")


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
    for key, expected in (("name", "5gc-registration-mobility"), ("version", "0.2.0"), ("category", "domain")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"manifest {key} must be {expected}")
    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append("manifest required dependencies must be empty")
    if manifest_block_or_flow(manifest, "protocols") != []:
        errors.append("manifest protocols must remain empty")
    if manifest_block_or_flow(manifest, "network_functions") != []:
        errors.append("manifest network_functions must remain empty")
    if manifest_block_or_flow(manifest, "interfaces") != ["N1", "N2"]:
        errors.append("manifest interfaces must be limited to N1 and N2")

    local_evidence = skill / "schemas/procedure-evidence.schema.json"
    shared_evidence = root / PROCEDURE_EVIDENCE_SCHEMA
    if not shared_evidence.is_file() or digest(local_evidence) != digest(shared_evidence):
        errors.append("package-local procedure-evidence schema must match the generic framework bytes")
    try:
        schema = json.loads((skill / "schemas/5gc-registration-analysis.schema.json").read_text(encoding="utf-8"))
        properties = schema.get("properties", {})
        for field in ("analysis_version", "procedure_family", "analyses", "unbound_records"):
            if field not in properties:
                errors.append(f"analysis schema must define {field}")
        instance = schema.get("$defs", {}).get("instanceAnalysis", {})
        instance_properties = instance.get("properties", {}) if isinstance(instance, dict) else {}
        for field in ("procedure_instance", "observation_window", "context", "stage_records", "terminal", "deviations", "field_findings", "confidence"):
            if field not in instance_properties:
                errors.append(f"analysis schema must define instance {field}")
        forbidden = [field for field in properties if FORBIDDEN_SCHEMA_FIELDS.search(field)]
        if forbidden:
            errors.append(f"analysis schema must not include causal or implementation fields: {forbidden}")
    except json.JSONDecodeError as exc:
        errors.append(f"analysis schema is invalid JSON: {exc}")

    try:
        model = json.loads((skill / "rules/registration-model.json").read_text(encoding="utf-8"))
        stages = {stage.get("stage_id"): stage for stage in model.get("stages", []) if isinstance(stage, dict)}
        for stage_id in ("identity", "authentication", "security-mode"):
            if stages.get(stage_id, {}).get("conditional") is not True:
                errors.append(f"registration model must keep {stage_id} conditional")
        if any(stage.get("mandatory") is True for stage in stages.values()):
            errors.append("registration model must not encode a mandatory linear procedure chain")
    except json.JSONDecodeError as exc:
        errors.append(f"registration model is invalid JSON: {exc}")

    input_root = skill / "examples/inputs"
    actual_scenarios = {path.name for path in input_root.iterdir() if path.is_dir()} if input_root.is_dir() else set()
    if actual_scenarios != SCENARIOS:
        errors.append("synthetic input scenarios must exactly cover the bounded registration cases")
    for scenario in sorted(SCENARIOS):
        for name in ("ngap.jsonl", "nas.jsonl", "correlation.jsonl"):
            if not (input_root / scenario / name).is_file():
                errors.append(f"missing {name} fixture for {scenario}")
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
    check_structured_provenance(root, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("5gc-registration-mobility validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("5gc-registration-mobility validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
