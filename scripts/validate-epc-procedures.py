#!/usr/bin/env python3
"""Validate the standalone epc-procedures Domain Skill contract."""

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
    "references/procedure-model.md",
    "references/stage-map.md",
    "references/evidence-rules.md",
    "references/limitations.md",
    "rules/epc-attach-model.json",
    "schemas/epc-attach-analysis.schema.json",
    "scripts/epc_attach_model.py",
    "scripts/analyze_epc_attach.py",
    "scripts/epc_attach_timeline.py",
    "tests/test_epc_procedures.py",
)

CASES = (
    "attach-reject",
    "auth-failure",
    "smc-reject",
    "conflicting-ids",
    "protected-inner",
)

DEVIATION_FIELDS = (
    "deviation_type",
    "procedure_stage",
    "protocol",
    "message_type",
    "frame_number",
    "evidence_level",
    "evidence_refs",
    "observation_window",
    "explanation",
    "limitations",
)

FORBIDDEN_KEYS = {
    "imsi", "imei", "imeisv", "guti", "tmsi", "msisdn", "supi", "suci",
    "rand", "autn", "res", "xres", "kasme", "key", "nas_pdu", "esm_msg_cont",
}

FORBIDDEN_CLAIMS = (
    "bearer_active",
    "pdn_connectivity_success",
    "user_plane_ready",
    "service_success",
    "root cause is",
)

LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s*[0-9]+\b|\bmilestone\s*[a-z]?[0-9]+\b")
LONG_DIGITS = re.compile(r"\d{14,}")


def load_model(root: Path):
    path = root / "skills" / "domain" / "epc-procedures" / "scripts" / "epc_attach_model.py"
    spec = importlib.util.spec_from_file_location("epc_attach_model_under_test", path)
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
    skill = root / "skills" / "domain" / "epc-procedures"

    def fail(message: str) -> None:
        errors.append(message)

    if not skill.is_dir():
        return ["missing Skill directory: skills/domain/epc-procedures"]

    for relative in REQUIRED:
        if not (skill / relative).is_file():
            fail(f"missing required file: skills/domain/epc-procedures/{relative}")
    if errors:
        return errors

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    if not re.search(r"(?m)^name:\s*epc-procedures\s*$", manifest):
        fail("manifest name must be epc-procedures")
    if not re.search(r"(?m)^category:\s*domain\s*$", manifest):
        fail("manifest category must be domain")
    if not re.search(r"(?m)^version:\s*\d+\.\d+\.\d+\s*$", manifest):
        fail("manifest version must be a semantic version")

    try:
        schema = json.loads((skill / "schemas" / "epc-attach-analysis.schema.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid analysis schema: {exc}")
        schema = {}
    for field in (
        "procedure_instances",
        "instance_count",
        "global_first_abnormal_boundary",
        "global_boundary_evaluation",
        "not_confirmed",
    ):
        if field not in schema.get("required", []):
            fail(f"analysis schema does not require '{field}'")

    try:
        rules = json.loads((skill / "rules" / "epc-attach-model.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid rules model: {exc}")
        rules = {}

    model = load_model(root)
    rule_stages = tuple(stage["stage_id"] for stage in rules.get("stages", []))
    if rule_stages != tuple(model.STAGE_ORDER):
        fail("rules stage vocabulary does not match the implemented stage order")
    if tuple(rules.get("deviations", ())) != tuple(model.DEVIATION_TYPES):
        fail("rules deviation catalogue does not match the implemented deviations")

    for path in sorted(skill.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".md", ".py", ".yaml", ".json", ".jsonl"}:
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

    for case in CASES:
        s1ap_path = skill / "examples" / "extracted" / f"{case}-s1ap.jsonl"
        nas_path = skill / "examples" / "extracted" / f"{case}-nas.jsonl"
        expected_path = skill / "examples" / "expected" / f"{case}-analysis.json"
        if not s1ap_path.is_file() or not nas_path.is_file() or not expected_path.is_file():
            fail(f"missing fixture or expected analysis for case '{case}'")
            continue
        try:
            s1ap_events = read_jsonl(s1ap_path)
            nas_events = read_jsonl(nas_path)
            produced = model.analyze(s1ap_events, nas_events, s1ap_path.name, nas_path.name)
            expected = json.loads(expected_path.read_text(encoding="utf-8"))
        except (ValueError, model.InputError) as exc:
            fail(f"{case}: {exc}")
            continue
        _check_analysis(expected, case, fail)
        if produced != expected:
            fail(f"{case}: produced analysis does not match the committed expected result")

    malformed = skill / "examples" / "extracted" / "malformed-nas.jsonl"
    if not malformed.is_file():
        fail("missing malformed NAS fixture")
    else:
        try:
            model.validate_events(read_jsonl(malformed), "NAS-EPS")
            fail("malformed NAS fixture must be rejected")
        except model.InputError:
            pass

    return errors


def _check_analysis(analysis: dict, case: str, fail) -> None:
    if analysis.get("global_first_abnormal_boundary") is not None:
        fail(f"{case}: a global first abnormal boundary must never be selected")
    if analysis.get("global_boundary_evaluation") != "NOT_EVALUATED":
        fail(f"{case}: global boundary evaluation must be NOT_EVALUATED")
    if not analysis.get("not_confirmed"):
        fail(f"{case}: analysis must state what it does not confirm")

    serialised = json.dumps(analysis).lower()
    for claim in FORBIDDEN_CLAIMS:
        if claim in serialised:
            fail(f"{case}: analysis contains a forbidden success or root-cause claim")
    if LONG_DIGITS.search(serialised):
        fail(f"{case}: analysis publishes a long digit run that may be an identifier")

    for instance in analysis.get("procedure_instances") or []:
        reference = instance.get("procedure_reference", "")
        if not re.fullmatch(r"epc-attach-[0-9a-f]{10}", reference):
            fail(f"{case}: procedure reference is not pseudonymous: {reference}")
        if FORBIDDEN_KEYS & set(instance):
            fail(f"{case}: instance publishes a forbidden evidence field")
        for deviation in instance.get("deviations") or []:
            missing = [field for field in DEVIATION_FIELDS if field not in deviation]
            if missing:
                fail(f"{case}: deviation {deviation.get('deviation_type')} misses {missing}")
            if deviation.get("deviation_type") == "PROTECTED_INNER_MESSAGE_UNAVAILABLE":
                if deviation.get("message_type") is not None:
                    fail(f"{case}: a protected inner message must not be given an identity")
            if deviation.get("evidence_level") == "OBSERVED" and not deviation.get("evidence_refs"):
                fail(f"{case}: observed deviation without an evidence reference")
        for stage in instance.get("stages") or []:
            if stage.get("status") not in ("OBSERVED", "INCOMPLETE", "NOT_OBSERVED", "UNAVAILABLE_PROTECTED"):
                fail(f"{case}: unexpected stage status {stage.get('status')}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("epc-procedures validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("epc-procedures validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
