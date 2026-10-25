#!/usr/bin/env python3
"""Validate the standalone epc-failure-boundary Orchestration Skill contract."""

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
    "references/boundary-model.md",
    "references/ordering-and-confidence.md",
    "references/subject-isolation.md",
    "references/failure-cases.md",
    "rules/epc-boundary-rules.json",
    "schemas/epc-failure-boundary-analysis.schema.json",
    "scripts/epc_boundary_model.py",
    "scripts/analyze_epc_failure_boundary.py",
    "scripts/epc_boundary_report.py",
    "tests/test_epc_failure_boundary.py",
    "examples/inputs/attach-reject/attach-analysis.json",
    "examples/inputs/session-accepted/session-analysis.json",
    "examples/inputs/session-rejection/session-analysis.json",
    "examples/inputs/bearer-rejection/session-analysis.json",
    "examples/inputs/ambiguous/session-analysis.json",
    "examples/inputs/omitted/session-analysis.json",
    "examples/inputs/mixed/attach-analysis.json",
    "examples/inputs/mixed/session-analysis.json",
)

CASES = (
    ("attach-reject", ("--attach", "examples/inputs/attach-reject/attach-analysis.json")),
    ("session-accepted", ("--session", "examples/inputs/session-accepted/session-analysis.json")),
    ("session-rejection", ("--session", "examples/inputs/session-rejection/session-analysis.json")),
    ("bearer-rejection", ("--session", "examples/inputs/bearer-rejection/session-analysis.json")),
    ("ambiguous", ("--session", "examples/inputs/ambiguous/session-analysis.json")),
    ("omitted", ("--session", "examples/inputs/omitted/session-analysis.json")),
    (
        "mixed",
        (
            "--attach", "examples/inputs/mixed/attach-analysis.json",
            "--session", "examples/inputs/mixed/session-analysis.json",
        ),
    ),
)

LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s*[0-9]+\b|\bmilestone\s*[a-z]?[0-9]+\b")
LONG_DIGITS = re.compile(r"\d{14,}")
CAUSAL_PATTERN = re.compile(
    r"(?i)\b(root cause is|root-cause chain|caused by the boundary|downstream failure caused by|"
    r"network function is responsible)\b"
)
FORBIDDEN_KEYS = {"imsi", "msisdn", "imei", "tmsi", "guti", "apn", "apn_name", "paa_address"}


def load_model(root: Path):
    path = root / "skills" / "orchestration" / "epc-failure-boundary" / "scripts" / "epc_boundary_model.py"
    spec = importlib.util.spec_from_file_location("epc_boundary_model_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def validate(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    skill = root / "skills" / "orchestration" / "epc-failure-boundary"

    def fail(message: str) -> None:
        errors.append(message)

    if not skill.is_dir():
        return ["missing Skill directory: skills/orchestration/epc-failure-boundary"]

    for relative in REQUIRED:
        if not (skill / relative).is_file():
            fail(f"missing required file: skills/orchestration/epc-failure-boundary/{relative}")
    if errors:
        return errors

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    if not re.search(r"(?m)^name:\s*epc-failure-boundary\s*$", manifest):
        fail("manifest name must be epc-failure-boundary")
    if not re.search(r"(?m)^category:\s*orchestration\s*$", manifest):
        fail("manifest category must be orchestration")
    if not re.search(r"(?m)^version:\s*\d+\.\d+\.\d+\s*$", manifest):
        fail("manifest version must be a semantic version")

    try:
        schema = json.loads(
            (skill / "schemas" / "epc-failure-boundary-analysis.schema.json").read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        return errors + [f"invalid analysis schema: {exc}"]
    for field in (
        "analysis_name",
        "diagnostic_groups",
        "unbound_domain_analyses",
        "ambiguities",
        "limitations",
        "not_confirmed",
    ):
        if field not in schema.get("required", []):
            fail(f"analysis schema does not require '{field}'")
    group_required = set(schema.get("$defs", {}).get("group", {}).get("required", []))
    for field in (
        "diagnostic_group_reference",
        "subject_type",
        "boundary_candidates",
        "boundary_selection_status",
        "first_abnormal_boundary",
        "boundary_confidence",
        "downstream_observations",
        "evidence_limitations",
    ):
        if field not in group_required:
            fail(f"group schema does not require '{field}'")

    try:
        rules = json.loads((skill / "rules" / "epc-boundary-rules.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return errors + [f"invalid rules model: {exc}"]

    model = load_model(root)
    if set(rules.get("selectable_attach_deviations", ())) != set(model.ELIGIBLE_ATTACH):
        fail("rules Attach selectable set does not match the implemented set")
    if set(rules.get("selectable_session_deviations", ())) != set(model.ELIGIBLE_SESSION):
        fail("rules session selectable set does not match the implemented set")
    if set(rules.get("selectable_default_bearer_deviations", ())) != set(model.ELIGIBLE_DEFAULT_BEARER):
        fail("rules default-bearer selectable set does not match the implemented set")
    if tuple(rules.get("esm_reject_message_types", ())) != tuple(model.ESM_REJECT_MESSAGE_TYPES):
        fail("rules ESM reject identities do not match the reviewed set")
    if "EPS_DEFAULT_BEARER" not in str(schema.get("$defs", {}).get("group", {}).get("properties", {}).get("subject_type")):
        fail("group schema does not declare the EPS_DEFAULT_BEARER subject type")
    if set(rules.get("nonselectable_deviations", ())) != set(model.NONSELECTABLE):
        fail("rules non-selectable set does not match the implemented set")
    if set(rules.get("selection_statuses", ())) != set(model.SELECTION_STATUSES):
        fail("rules selection statuses do not match the implemented statuses")
    if tuple(rules.get("not_confirmed", ())) != tuple(model.NOT_CONFIRMED):
        fail("rules not_confirmed list does not match the implemented list")

    for path in sorted(skill.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".md", ".py", ".yaml", ".json", ".txt"}:
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

    for case, arguments in CASES:
        expected_path = skill / "examples" / "expected" / f"{case}-analysis.json"
        if not expected_path.is_file():
            fail(f"missing expected analysis for case '{case}'")
            continue
        attach_paths: list[Path] = []
        session_paths: list[Path] = []
        index = 0
        while index < len(arguments):
            flag, value = arguments[index], arguments[index + 1]
            target = skill / value
            if flag == "--attach":
                attach_paths.append(target)
            else:
                session_paths.append(target)
            index += 2
        try:
            produced = model.analyze(attach_paths, session_paths)
            expected = json.loads(expected_path.read_text(encoding="utf-8"))
        except (model.InputError, OSError, json.JSONDecodeError) as exc:
            fail(f"{case}: {exc}")
            continue
        if produced != expected:
            fail(f"{case}: produced analysis does not match the committed expected result")
        _check_analysis(expected, case, fail)

    return errors


def _check_analysis(analysis: dict, case: str, fail) -> None:
    if analysis.get("analysis_name") != "epc-failure-boundary":
        fail(f"{case}: analysis_name must be epc-failure-boundary")
    serialized = json.dumps(analysis)
    if CAUSAL_PATTERN.search(serialized):
        fail(f"{case}: analysis publishes a causal claim")
    if LONG_DIGITS.search(serialized):
        fail(f"{case}: analysis publishes a long digit run that may be an identifier")
    groups = analysis.get("diagnostic_groups") or []
    if not groups:
        fail(f"{case}: analysis carries no diagnostic group")
    references = set()
    for group in groups:
        reference = group.get("diagnostic_group_reference")
        if reference in references:
            fail(f"{case}: duplicate diagnostic group reference {reference}")
        references.add(reference)
        link = group.get("subject_link") or {}
        if link.get("cross_subject_link") != "NOT_ESTABLISHED":
            fail(f"{case}: a group must not claim a cross-subject link")
        status = group.get("boundary_selection_status")
        if status not in ("SELECTED", "NO_ABNORMAL_BOUNDARY_OBSERVED",
                          "AMBIGUOUS_FIRST_BOUNDARY", "INSUFFICIENT_COMPARABLE_EVIDENCE"):
            fail(f"{case}: unexpected selection status {status}")
        boundary = group.get("first_abnormal_boundary")
        if status == "SELECTED":
            if not isinstance(boundary, dict):
                fail(f"{case}: a SELECTED group must publish a boundary")
                continue
            frame = boundary.get("frame_number")
            refs = [item.get("frame_number") for item in boundary.get("evidence_refs") or []]
            if frame not in refs:
                fail(f"{case}: boundary frame {frame} is absent from its evidence references")
            window = boundary.get("observation_window") or {}
            if window and not (window.get("start_frame") <= frame <= window.get("end_frame")):
                fail(f"{case}: boundary frame {frame} lies outside its observation window")
            if not boundary.get("protocol") or not boundary.get("message_type"):
                fail(f"{case}: a selected boundary must keep protocol and message identity")
            if group.get("boundary_confidence") not in ("HIGH", "MEDIUM", "LOW"):
                fail(f"{case}: a selected boundary must carry a confidence level")
        else:
            if boundary is not None:
                fail(f"{case}: a non-selected group must not publish a boundary")
            if group.get("boundary_confidence") is not None:
                fail(f"{case}: a non-selected group must not publish a confidence level")
        forbidden = FORBIDDEN_KEYS & set(group)
        if forbidden:
            fail(f"{case}: group publishes forbidden field(s) {sorted(forbidden)}")
        for candidate in group.get("boundary_candidates") or []:
            if candidate.get("selection_eligibility") not in ("ELIGIBLE", "INELIGIBLE"):
                fail(f"{case}: candidate eligibility must be ELIGIBLE or INELIGIBLE")
            if candidate.get("selection_eligibility") == "INELIGIBLE" and not candidate.get("eligibility_reasons"):
                fail(f"{case}: an ineligible candidate must state why")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("epc-failure-boundary validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("epc-failure-boundary validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
