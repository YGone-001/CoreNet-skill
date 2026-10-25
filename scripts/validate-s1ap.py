#!/usr/bin/env python3
"""Validate the standalone s1ap Protocol Skill contract."""

from __future__ import annotations

import argparse
import importlib.util
import json
import py_compile
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "protocol" / "s1ap"

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/protocol-model.md",
    "references/procedure-map.md",
    "references/field-reference.md",
    "references/correlation.md",
    "references/failure-cases.md",
    "scripts/s1ap_model.py",
    "scripts/s1ap_erab.py",
    "scripts/extract-s1ap.py",
    "scripts/s1ap_timeline.py",
    "schemas/s1ap-event.schema.json",
    "schemas/trace-event.schema.json",
    "filters/wireshark.txt",
    "tests/test_s1ap.py",
    "examples/pdml/erab-items.pdml",
)

FIXTURES = {
    "examples/extracted/s1-setup.jsonl": "examples/expected/s1-setup-events.jsonl",
    "examples/extracted/initial-context-setup.jsonl": "examples/expected/initial-context-setup-events.jsonl",
    "examples/extracted/conflicting-ids.jsonl": "examples/expected/conflicting-ids-events.jsonl",
    "examples/extracted/partial-ids.jsonl": "examples/expected/partial-ids-events.jsonl",
    "examples/extracted/unsupported.jsonl": "examples/expected/unsupported-events.jsonl",
    "examples/extracted/multi-ue.jsonl": "examples/expected/multi-ue-events.jsonl",
    "examples/extracted/ue-context-flow.jsonl": "examples/expected/ue-context-flow-events.jsonl",
    "examples/extracted/nas-transport.jsonl": "examples/expected/nas-transport-events.jsonl",
    "examples/extracted/ue-release.jsonl": "examples/expected/ue-release-events.jsonl",
}

ERROR_FIXTURES = (
    "examples/extracted/malformed.jsonl",
    "examples/extracted/missing-required.jsonl",
)

FORBIDDEN_EVENT_KEYS = {
    "nas_pdu",
    "nas_pdu_bytes",
    "nas_payload",
    "imsi",
    "imei",
    "guti",
    "tmsi",
    "rand",
    "autn",
    "key",
}

LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s*[0-9]+\b|\bmilestone\s*[a-z]?[0-9]+\b")
HEX_BLOB = re.compile(r"\b[0-9a-fA-F]{64,}\b")
LONG_DIGITS = re.compile(r"\d{14,}")


def load_erab_model():
    path = ROOT / "skills" / "protocol" / "s1ap" / "scripts" / "s1ap_erab.py"
    spec = importlib.util.spec_from_file_location("s1ap_erab_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_model():
    path = SKILL / "scripts" / "s1ap_model.py"
    spec = importlib.util.spec_from_file_location("s1ap_model_under_test", path)
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


def manifest_version(text):
    for line in text.splitlines():
        if line.startswith("version:"):
            return line.split(":", 1)[1].strip()
    return None


def validate(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    skill = root / "skills" / "protocol" / "s1ap"

    def fail(message: str) -> None:
        errors.append(message)

    if not skill.is_dir():
        return ["missing Skill directory: skills/protocol/s1ap"]

    for relative in REQUIRED:
        if not (skill / relative).is_file():
            fail(f"missing required file: skills/protocol/s1ap/{relative}")
    if errors:
        return errors

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    if not re.search(r"(?m)^name:\s*s1ap\s*$", manifest):
        fail("manifest name must be s1ap")
    if not re.search(r"(?m)^category:\s*protocol\s*$", manifest):
        fail("manifest category must be protocol")
    if not re.search(r"(?m)^version:\s*\d+\.\d+\.\d+\s*$", manifest):
        fail("manifest version must be a semantic version")

    version = manifest_version(manifest)
    if version is None:
        fail("manifest version must be a semantic version")
    else:
        for name in ("SKILL.md", "README.md"):
            if version not in (skill / name).read_text(encoding="utf-8"):
                fail(f"{name} does not state the manifest version {version}")

    for schema_name in ("schemas/s1ap-event.schema.json", "schemas/trace-event.schema.json"):
        try:
            schema = json.loads((skill / schema_name).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"invalid JSON schema {schema_name}: {exc}")
            continue
        if schema_name.endswith("s1ap-event.schema.json"):
            required = set(schema.get("required", []))
            for field in ("frame_number", "procedure_code", "message_type", "support_status", "evidence"):
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

    erab = load_erab_model()
    try:
        items, nas_frames = erab.pdml_erab_dissection(
            (skill / "examples" / "pdml" / "erab-items.pdml").read_text(encoding="utf-8"),
            "erab-items.pdml",
        )
    except ValueError as exc:
        fail(f"erab-items.pdml: {exc}")
        items, nas_frames = {}, set()
    if tuple(sorted(items)) != (23, 24):
        fail("erab-items.pdml: E-RAB frames do not match the reviewed fixture")
    if sorted(nas_frames) != [23]:
        fail("erab-items.pdml: the nested NAS layer is not detected")
    if len(items.get(23, [])) != 2:
        fail("erab-items.pdml: the two E-RAB items are not kept separate")
    else:
        first, second = items[23]
        if first["gtp_teid"] == second["gtp_teid"]:
            fail("erab-items.pdml: two E-RAB items share one GTP-TEID")
        if first["transport_layer_address"] == second["transport_layer_address"]:
            fail("erab-items.pdml: two E-RAB items share one transport layer address")
        if [first["erab_id"], second["erab_id"]] != [5, 6]:
            fail("erab-items.pdml: the E-RAB identities are not item-scoped")
        for item in (first, second):
            if item["binding_basis"] != "pdml_grouped_ie":
                fail("erab-items.pdml: an E-RAB item lost its dissector binding")
            if item["endpoint_role"] != "enodeb_s1u":
                fail("erab-items.pdml: the S1-U endpoint role is not message-derived")
            serialised = json.dumps(item)
            if "nAS_PDU" in serialised or "27b93f" in serialised:
                fail("erab-items.pdml: an E-RAB item republishes the NAS payload")

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

    correlation = model.build_correlation(
        [model.normalize_record(record, "conflicting-ids.jsonl")
         for record in read_jsonl(skill / "examples/extracted/conflicting-ids.jsonl")]
    )
    strengths = {item["strength"] for item in correlation["contexts"]}
    if "AMBIGUOUS" not in strengths:
        fail("conflicting identifiers must produce an AMBIGUOUS context")
    for item in correlation["contexts"]:
        if item["strength"] == "AMBIGUOUS" and not item["ambiguity_reasons"]:
            fail("an AMBIGUOUS context must carry an ambiguity reason")

    multi = model.build_correlation(
        [model.normalize_record(record, "multi-ue.jsonl")
         for record in read_jsonl(skill / "examples/extracted/multi-ue.jsonl")]
    )
    pairs = {
        (item["enb_ue_s1ap_id"], item["mme_ue_s1ap_id"])
        for item in multi["contexts"]
        if item["strength"] == "STRONG"
    }
    if len(pairs) < 2:
        fail("multiple UEs must stay in separate STRONG contexts")

    unsupported = [
        event for event in read_jsonl(skill / "examples/expected/unsupported-events.jsonl")
    ]
    statuses = {event["support_status"] for event in unsupported}
    if "UNSUPPORTED" not in statuses or "UNKNOWN" not in statuses:
        fail("unsupported and unknown procedures must both be reported explicitly")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("s1ap validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("s1ap validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
