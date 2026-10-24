#!/usr/bin/env python3
"""Validate the standalone nas-eps Protocol Skill contract."""

from __future__ import annotations

import argparse
import importlib.util
import json
import py_compile
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/protocol-model.md",
    "references/message-map.md",
    "references/field-reference.md",
    "references/protection-rules.md",
    "references/failure-cases.md",
    "scripts/nas_eps_model.py",
    "scripts/extract-nas-eps.py",
    "scripts/nas_eps_timeline.py",
    "schemas/nas-eps-event.schema.json",
    "schemas/trace-event.schema.json",
    "filters/wireshark.txt",
    "tests/test_nas_eps.py",
)

FIXTURES = {
    "examples/extracted/attach-flow.jsonl": "examples/expected/attach-flow-events.jsonl",
    "examples/extracted/attach-accept-complete.jsonl": "examples/expected/attach-accept-complete-events.jsonl",
    "examples/extracted/authentication.jsonl": "examples/expected/authentication-events.jsonl",
    "examples/extracted/identity.jsonl": "examples/expected/identity-events.jsonl",
    "examples/extracted/auth-failure.jsonl": "examples/expected/auth-failure-events.jsonl",
    "examples/extracted/security-mode.jsonl": "examples/expected/security-mode-events.jsonl",
    "examples/extracted/security-reject.jsonl": "examples/expected/security-reject-events.jsonl",
    "examples/extracted/protected-inner.jsonl": "examples/expected/protected-inner-events.jsonl",
    "examples/extracted/esm-container.jsonl": "examples/expected/esm-container-events.jsonl",
    "examples/extracted/unsupported.jsonl": "examples/expected/unsupported-events.jsonl",
}

ERROR_FIXTURES = (
    "examples/extracted/malformed.jsonl",
    "examples/extracted/missing-required.jsonl",
)

FORBIDDEN_EVENT_KEYS = {
    "imsi",
    "imei",
    "imeisv",
    "guti",
    "tmsi",
    "msisdn",
    "supi",
    "suci",
    "rand",
    "autn",
    "res",
    "xres",
    "key",
    "identity_value",
    "esm_msg_cont",
    "ciphered_msg",
    "msg_auth_code",
    "nas_pdu",
}

LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s*[0-9]+\b|\bmilestone\s*[a-z]?[0-9]+\b")
HEX_BLOB = re.compile(r"\b[0-9a-fA-F]{64,}\b")
LONG_DIGITS = re.compile(r"\d{14,}")


def load_model():
    path = ROOT / "skills" / "protocol" / "nas-eps" / "scripts" / "nas_eps_model.py"
    spec = importlib.util.spec_from_file_location("nas_eps_model_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def read_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path.name} line {number}: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"{path.name} line {number}: record is not an object")
        records.append(record)
    return records


def validate(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    skill = root / "skills" / "protocol" / "nas-eps"

    def fail(message: str) -> None:
        errors.append(message)

    if not skill.is_dir():
        return ["missing Skill directory: skills/protocol/nas-eps"]

    for relative in REQUIRED:
        if not (skill / relative).is_file():
            fail(f"missing required file: skills/protocol/nas-eps/{relative}")
    if errors:
        return errors

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    if not re.search(r"(?m)^name:\s*nas-eps\s*$", manifest):
        fail("manifest name must be nas-eps")
    if not re.search(r"(?m)^category:\s*protocol\s*$", manifest):
        fail("manifest category must be protocol")
    if not re.search(r"(?m)^version:\s*\d+\.\d+\.\d+\s*$", manifest):
        fail("manifest version must be a semantic version")

    for schema_name in ("schemas/nas-eps-event.schema.json", "schemas/trace-event.schema.json"):
        try:
            schema = json.loads((skill / schema_name).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"invalid JSON schema {schema_name}: {exc}")
            continue
        if schema_name.endswith("nas-eps-event.schema.json"):
            required = set(schema.get("required", []))
            for field in ("frame_number", "message_type", "support_status", "protection", "evidence"):
                if field not in required:
                    fail(f"event schema does not require '{field}'")

    skill_md = (skill / "SKILL.md").read_text(encoding="utf-8")
    for section in ("## Scope", "## Non-Goals", "## Inputs", "## Outputs"):
        if section not in skill_md:
            fail(f"SKILL.md is missing the '{section}' section")

    for path in sorted(skill.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if LIFECYCLE_MARKER.search(text):
            fail(f"lifecycle marker in {path.relative_to(root)}")

    for script in (skill / "scripts").glob("*.py"):
        try:
            py_compile.compile(str(script), doraise=True)
        except py_compile.PyCompileError as exc:
            fail(f"script does not compile: {script.name}: {exc}")

    for fixture in ERROR_FIXTURES:
        if not (skill / fixture).is_file():
            fail(f"missing error fixture: {fixture}")

    model = load_model()
    for fixture, expected in FIXTURES.items():
        fixture_path = skill / fixture
        expected_path = skill / expected
        if not fixture_path.is_file() or not expected_path.is_file():
            fail(f"missing fixture or expected file: {fixture} -> {expected}")
            continue
        try:
            records = read_jsonl(fixture_path)
            produced = [model.normalize_record(record, fixture_path.name) for record in records]
            golden = read_jsonl(expected_path)
        except (ValueError, model.InputError) as exc:
            fail(f"{fixture}: {exc}")
            continue
        if produced != golden:
            fail(f"{fixture}: produced events do not match {expected}")
        for event in golden:
            forbidden = FORBIDDEN_EVENT_KEYS & set(event)
            if forbidden:
                fail(f"{expected}: publishes forbidden evidence field(s) {sorted(forbidden)}")
            serialised = json.dumps(event)
            if HEX_BLOB.search(serialised):
                fail(f"{expected}: publishes a long hex payload blob")
            if LONG_DIGITS.search(serialised):
                fail(f"{expected}: publishes a long digit run that may be an identifier")

    protected = read_jsonl(skill / "examples/expected/protected-inner-events.jsonl")
    unavailable = [event for event in protected if event["support_status"] == "PROTECTED_INNER_MESSAGE_UNAVAILABLE"]
    if not unavailable:
        fail("protected inner messages must be reported as unavailable")
    for event in unavailable:
        if event["message_type"] is not None:
            fail("a protected inner message must not be given an invented identity")

    authentication = {event["procedure"] for event in read_jsonl(skill / "examples/expected/authentication-events.jsonl")}
    security = {event["procedure"] for event in read_jsonl(skill / "examples/expected/security-mode-events.jsonl")}
    if authentication != {"authentication"}:
        fail("authentication messages must carry the authentication procedure family")
    if security != {"security-mode-control"}:
        fail("security mode messages must carry the security-mode-control procedure family")

    attach = read_jsonl(skill / "examples/expected/attach-flow-events.jsonl")
    if attach[1]["emm_cause"]["value"] != 19:
        fail("attach reject must preserve the observed EMM cause value")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("nas-eps validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("nas-eps validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
