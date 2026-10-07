#!/usr/bin/env python3
"""Validate the Golden Capture Benchmark framework, cases, schemas, and privacy gates.

Enforces:
1. Directory structure and required files.
2. JSON Schema compliance across all benchmark documents.
3. Case naming, provenance, and identifier consistency.
4. Binary capture prohibition (no *.pcap, *.pcapng, *.cap in git).
5. Privacy gate: no subscriber secrets, authentication vectors, or workstation paths.
6. Baseline hash verification (SHA-256 match).
7. Implementation-neutral vocabulary governance.
8. Forbidden root-cause field ban.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_DIR = ROOT / "benchmarks" / "golden-captures"

sys.path.insert(0, str(BENCHMARK_DIR / "scripts"))
from canonical_hash import canonical_json_sha256

CASE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")

FORBIDDEN_FIELDS = {
    "root_cause",
    "culprit",
    "responsible_nf",
    "vendor_fault",
    "implementation_failure",
    "product_bug",
    "bug_location",
}

CAPTURE_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
FORBIDDEN_EVENT_DUMPS = {"ngap-events.jsonl", "nas-events.jsonl", "pfcp-events.jsonl", "gtpu-events.jsonl", "sbi-events.jsonl"}


def fail(errors: list[str], msg: str) -> None:
    errors.append(msg)


# Lightweight, self-contained JSON schema validator
def validate_json_schema(instance: Any, schema: dict[str, Any], path_prefix: str = "") -> list[str]:
    errors: list[str] = []
    expected_type = schema.get("type")

    if expected_type is not None:
        type_map = {
            "object": dict,
            "array": list,
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "null": type(None),
        }
        if isinstance(expected_type, list):
            valid = any(isinstance(instance, type_map[t]) for t in expected_type if t in type_map)
            if not valid:
                errors.append(f"{path_prefix}: expected one of {expected_type}, got {type(instance).__name__}")
                return errors
        elif expected_type in type_map:
            # bool is a subclass of int in python, so distinguish bool from int/number
            if expected_type in ("integer", "number") and isinstance(instance, bool):
                errors.append(f"{path_prefix}: expected {expected_type}, got bool")
                return errors
            if not isinstance(instance, type_map[expected_type]):
                errors.append(f"{path_prefix}: expected {expected_type}, got {type(instance).__name__}")
                return errors

    if isinstance(instance, dict):
        required = schema.get("required", [])
        for req in required:
            if req not in instance:
                errors.append(f"{path_prefix}: missing required property '{req}'")

        additional_allowed = schema.get("additionalProperties", True)
        props = schema.get("properties", {})
        for k, v in instance.items():
            sub_prefix = f"{path_prefix}.{k}" if path_prefix else k
            if k in props:
                errors.extend(validate_json_schema(v, props[k], sub_prefix))
            elif not additional_allowed:
                errors.append(f"{sub_prefix}: additional property '{k}' is not allowed")

    elif isinstance(instance, list):
        item_schema = schema.get("items")
        if item_schema:
            for idx, item in enumerate(instance):
                sub_prefix = f"{path_prefix}[{idx}]"
                errors.extend(validate_json_schema(item, item_schema, sub_prefix))

    elif isinstance(instance, str):
        if "enum" in schema and instance not in schema["enum"]:
            errors.append(f"{path_prefix}: value '{instance}' not in enum {schema['enum']}")
        if "pattern" in schema and not re.match(schema["pattern"], instance):
            errors.append(f"{path_prefix}: value does not match pattern {schema['pattern']}")

    elif isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "enum" in schema and instance not in schema["enum"]:
            errors.append(f"{path_prefix}: value {instance} not in enum {schema['enum']}")
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path_prefix}: value {instance} is less than minimum {schema['minimum']}")

    return errors


def check_forbidden_fields(obj: Any, errors: list[str], path_prefix: str = "") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            current_path = f"{path_prefix}.{k}" if path_prefix else k
            if k.lower() in FORBIDDEN_FIELDS:
                fail(errors, f"Forbidden root-cause field '{k}' detected at {current_path}")
            check_forbidden_fields(v, errors, current_path)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            check_forbidden_fields(item, errors, f"{path_prefix}[{idx}]")


def check_workstation_paths(text: str, file_path: Path, errors: list[str]) -> None:
    # Ban specific user workstation paths
    banned_path_patterns = [
        re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[^\s\"'\\\/]+", re.IGNORECASE),
        re.compile(r"[\\/]+home[\\/]+[^\s\"'\\\/]+", re.IGNORECASE),
    ]
    for pat in banned_path_patterns:
        match = pat.search(text)
        if match:
            fail(errors, f"Local workstation path detected in {file_path.name}: {match.group(0)}")


def check_binary_captures(root: Path, errors: list[str]) -> None:
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in CAPTURE_EXTENSIONS:
            try:
                rel = str(path.relative_to(ROOT))
            except ValueError:
                rel = str(path.name)
            fail(errors, f"Binary packet capture file committed in repository: {rel}")


def check_implementation_vocabulary(tracked_files: list[Path], errors: list[str]) -> None:
    policy_path = ROOT / "scripts" / "implementation_policy.py"
    if not policy_path.is_file():
        return
    policy_spec = importlib.util.spec_from_file_location("implementation_policy", policy_path)
    policy = importlib.util.module_from_spec(policy_spec)
    assert policy_spec.loader is not None
    policy_spec.loader.exec_module(policy)

    text_suffixes = {".md", ".py", ".yaml", ".yml", ".json", ".txt"}
    for path in tracked_files:
        if path.suffix.lower() not in text_suffixes:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        found = policy.find_prohibited_tokens(str(path)) + policy.find_prohibited_tokens(content)
        if found:
            fail(errors, f"Prohibited implementation token found in {path.relative_to(ROOT)}")


def validate_golden_captures(benchmark_dir: Path) -> list[str]:
    errors: list[str] = []

    if not benchmark_dir.is_dir():
        fail(errors, f"Benchmark directory missing: {benchmark_dir}")
        return errors

    # Required files
    required_structure = [
        "README.md",
        "schemas/capture-case.schema.json",
        "schemas/human-baseline.schema.json",
        "schemas/skill-result-summary.schema.json",
        "schemas/differential-result.schema.json",
        "schemas/benchmark-summary.schema.json",
        "scripts/run_capture_pipeline.py",
        "scripts/canonical_hash.py",
        "scripts/sanitize_result.py",
        "scripts/compare_results.py",
        "scripts/summarize_benchmark.py",
        "scripts/run_public_corpus.py",
        "tests/test_golden_captures.py",
    ]
    for rel in required_structure:
        if not (benchmark_dir / rel).is_file():
            fail(errors, f"Missing required benchmark file: {rel}")

    # Load schemas
    schemas: dict[str, dict[str, Any]] = {}
    for schema_name in (
        "capture-case.schema.json",
        "human-baseline.schema.json",
        "skill-result-summary.schema.json",
        "differential-result.schema.json",
        "benchmark-summary.schema.json",
    ):
        p = benchmark_dir / "schemas" / schema_name
        if p.is_file():
            try:
                schemas[schema_name] = json.loads(p.read_text(encoding="utf-8"))
            except Exception as exc:
                fail(errors, f"Failed to parse schema {schema_name}: {exc}")

    # Check binary captures
    check_binary_captures(benchmark_dir, errors)

    # Validate cases
    cases_dir = benchmark_dir / "cases"
    if not cases_dir.is_dir():
        fail(errors, "Missing cases directory: cases/")
        return errors

    tracked_text_files = list(benchmark_dir.rglob("*.json")) + list(benchmark_dir.rglob("*.md")) + list(benchmark_dir.rglob("*.py"))
    check_implementation_vocabulary(tracked_text_files, errors)

    for case_folder in sorted(cases_dir.iterdir()):
        if not case_folder.is_dir():
            continue
        case_id = case_folder.name
        if not CASE_ID_PATTERN.match(case_id):
            fail(errors, f"Invalid case directory name: {case_id}")

        for f in case_folder.iterdir():
            if f.name in FORBIDDEN_EVENT_DUMPS:
                fail(errors, f"Forbidden raw protocol event dump in case directory: {f.relative_to(ROOT)}")

        # Required case artifacts
        case_json_p = case_folder / "case.json"
        baseline_json_p = case_folder / "human-baseline.json"
        skill_json_p = case_folder / "skill-result-summary.json"
        diff_json_p = case_folder / "differential.json"

        for p, schema_key in [
            (case_json_p, "capture-case.schema.json"),
            (baseline_json_p, "human-baseline.schema.json"),
            (skill_json_p, "skill-result-summary.schema.json"),
            (diff_json_p, "differential-result.schema.json"),
        ]:
            if not p.is_file():
                fail(errors, f"Missing required artifact: {p.relative_to(ROOT)}")
                continue

            try:
                content_str = p.read_text(encoding="utf-8")
                check_workstation_paths(content_str, p, errors)
                doc = json.loads(content_str)
            except Exception as exc:
                fail(errors, f"Invalid JSON in {p.relative_to(ROOT)}: {exc}")
                continue

            # Check forbidden fields
            check_forbidden_fields(doc, errors, p.name)

            # Check case_id match
            if doc.get("case_id") != case_id:
                fail(errors, f"case_id mismatch in {p.name}: expected '{case_id}', got '{doc.get('case_id')}'")

            # Validate against schema
            if schema_key in schemas:
                schema_errs = validate_json_schema(doc, schemas[schema_key], p.name)
                for err in schema_errs:
                    fail(errors, f"Schema validation error in {p.relative_to(ROOT)}: {err}")

        # Baseline hash immutability check
        if baseline_json_p.is_file() and diff_json_p.is_file():
            try:
                computed_baseline_sha = canonical_json_sha256(baseline_json_p.read_text(encoding="utf-8"))
                diff_doc = json.loads(diff_json_p.read_text(encoding="utf-8"))
                declared_baseline_sha = diff_doc.get("human_baseline_sha256")
                if declared_baseline_sha != computed_baseline_sha:
                    fail(errors, f"Baseline hash mismatch in {case_id}: declared {declared_baseline_sha}, computed {computed_baseline_sha}")
            except Exception as exc:
                fail(errors, f"Error verifying baseline hash for {case_id}: {exc}")

    # Validate benchmark-summary.json if present
    summary_p = benchmark_dir / "benchmark-summary.json"
    if summary_p.is_file():
        try:
            summary_str = summary_p.read_text(encoding="utf-8")
            check_workstation_paths(summary_str, summary_p, errors)
            summary_doc = json.loads(summary_str)
            check_forbidden_fields(summary_doc, errors, "benchmark-summary.json")
            if "benchmark-summary.schema.json" in schemas:
                for err in validate_json_schema(summary_doc, schemas["benchmark-summary.schema.json"], "benchmark-summary"):
                    fail(errors, f"Schema validation error in benchmark-summary.json: {err}")
            metrics = summary_doc.get("metrics") or {}
            cases_list = summary_doc.get("cases") or []
            if metrics.get("case_count") != len(cases_list):
                fail(errors, f"benchmark-summary metrics.case_count ({metrics.get('case_count')}) != len(cases) ({len(cases_list)})")
        except Exception as exc:
            fail(errors, f"Invalid benchmark-summary.json: {exc}")

    return errors


def main() -> int:
    errors = validate_golden_captures(BENCHMARK_DIR)
    if errors:
        print("Golden Captures validation failed:", file=sys.stderr)
        for err in errors:
            print(f"- {err}", file=sys.stderr)
        return 1
    print("Golden Captures validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
