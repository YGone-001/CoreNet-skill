#!/usr/bin/env python3
"""Validate the standalone 5GC Failure Boundary Orchestration Skill."""

from __future__ import annotations

import argparse
import ast
import json
import py_compile
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from implementation_policy import IMPLEMENTATION_TOKEN_GROUP

SKILL = Path("skills/orchestration/5gc-failure-boundary")

REQUIRED = (
    "SKILL.md", "README.md", "manifest.yaml",
    "references/boundary-model.md", "references/subject-linking.md",
    "references/ordering-model.md", "references/confidence-model.md",
    "references/failure-cases.md",
    "scripts/failure_boundary_model.py", "scripts/analyze_failure_boundary.py",
    "scripts/failure_boundary_report.py",
    "schemas/5gc-failure-boundary-analysis.schema.json",
    "tests/test_5gc_failure_boundary.py",
)

EXPECTED_SCENARIOS = {
    "auth-failure-before-reject", "registration-reject-only",
    "registration-complete-pdu-reject", "registration-complete-sm-context-error",
    "pfcp-negative-boundary", "ngap-failed-resource-boundary",
    "namf-202-then-failure-notification", "pdu-no-abnormal-no-traffic",
    "valid-release-no-abnormal", "registration-missing-counterpart",
    "partial-capture-blocks-missing", "two-ue-two-groups",
    "same-ids-different-associations", "unlinked-captures",
    "registration-before-pdu-boundary", "same-frame-ambiguity",
    "incomparable-provenance", "lifecycle-generations-distinct",
    "lifecycle-ambiguity-limitation", "correlation-ambiguity-limitation",
    "duplicate-only-limitation", "protected-payload-limitation",
    "pfcp-boundary-downstream-neutral", "ngap-boundary-before-nas-reject",
    "registration-only", "pdu-session-only", "malformed-domain-input",
    "duplicate-identical-input", "out-of-order-input-order",
    "no-deviations-anywhere", "later-incomparability", "earliest-incomparability",
    "description-invariance", "adversarial-description",
    # Bounded v0.2.0 Mobility integration scenarios.
    "ho-preparation-negative", "ho-resource-allocation-negative",
    "ho-resource-failed-item", "ps-negative-outcome",
    "ho-missing-counterpart-window", "ho-missing-counterpart-partial",
    "ho-cancel-no-deviation", "ho-notify-no-deviation", "ps-ack-no-deviation",
    "mobility-correlation-ambiguity-only", "registration-earlier-than-handover",
    "pdu-earlier-than-handover", "handover-earlier-than-pdu",
    "mobility-pdu-same-frame", "mobility-earlier-incomparable-laters",
    "mobility-context-exact-link", "handover-bridge-strong",
    "handover-bridge-ambiguous", "handover-bridge-candidates",
    "handover-target-only-anchor", "mobility-same-ids-different-associations",
    "mobility-cross-capture", "ps-independent-boundary",
    "ho-then-ps-unbound-relationship", "ho-and-ps-one-group",
    "ho-notify-no-path-switch", "ps-no-handover-missing-outcome",
    "two-handover-attempts-one-subject", "two-path-switch-attempts-one-subject",
    "duplicate-mobility-input", "mobility-out-of-order-input-order",
    "mobility-version-too-old", "mobility-version-floor-accepted",
    "mobility-malformed-json", "unsupported-domain-analysis", "misleading-filename",
}

# Scenarios whose analyzer MUST fail loudly (rc != 0) instead of producing output.
FAILURE_EXPECTED_SCENARIOS = {
    "malformed-domain-input", "incomparable-provenance",
    "mobility-version-too-old", "mobility-malformed-json", "unsupported-domain-analysis",
}

# Exact optional-dependency floors of the published manifest contract. They
# must match the structured-provenance floors enforced by the runtime
# (REGISTRATION_VERSION_FLOOR / PDU_SESSION_VERSION_FLOOR /
# HANDOVER_MOBILITY_VERSION_FLOOR).
EXPECTED_OPTIONAL_DEPENDENCIES = (
    "5gc-registration-mobility >=0.2.0",
    "5gc-pdu-session >=0.4.0",
    "5gc-handover-mobility >=0.1.0",
    "procedure-evidence >=0.1.0",
)

CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
TEXT_SUFFIXES = {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
SUBSCRIBER_VALUE = re.compile(r'(?i)"(?:imsi|supi|suci|msisdn|imei)"\s*:\s*"[^"\n]+"')
AUTH_VECTOR = re.compile(r'(?i)"(?:rand|autn|res\*?|hxres\*?|kausf|kseaf|kamf)"\s*:\s*"[^"\n]+"')
IMPLEMENTATION_MAPPING = re.compile(r"(?is)(?:" + IMPLEMENTATION_TOKEN_GROUP + r"|openairinterface|srsran|vendor).{0,120}(?:source|handler|function|path|mapping|module)")
RAW_DECODER = re.compile(r"(?i)def\s+(?:parse|decode)[a-z0-9_]*(?:nas|ngap|pfcp|gtp|packet|payload)|(?:raw_)?(?:nas|ngap|pfcp|gtpu)_payload\s*=")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s*[0-9]+\b|\bmilestone\s*[a-z]?[0-9]+\b")
FORBIDDEN_SCHEMA_FIELDS = re.compile(r"(?i)root_?cause|culprit|responsible_?nf|vendor|implementation|product_?bug|bug_?location")
FORBIDDEN_RELATION = re.compile(r"(?i)caused[ _-]?by[ _-]?boundary")
TIMESTAMP_ONLY_JOIN = re.compile(r"(?i)\b(?:match|join|link|correlate)_by_timestamp(?:_only)?\b")
SEVERITY_RANKING = re.compile(r"(?i)severity[ _-]?(?:rank|priority|score|order)")
PROSE_FRAME_PARSING = re.compile(r"(?i)frame_from_description|_frame_in_text|observed_evidence")


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
    for key, expected in (("name", "5gc-failure-boundary"), ("version", "0.2.0"), ("category", "orchestration")):
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

    declared_optional = manifest_block_or_flow(manifest, "optional")
    if sorted(declared_optional) != sorted(EXPECTED_OPTIONAL_DEPENDENCIES):
        errors.append(
            "manifest optional dependencies must be exactly: "
            + "; ".join(EXPECTED_OPTIONAL_DEPENDENCIES)
        )

    # Manifest inputs: all three supported Domain analysis sources must be
    # declared; the input contract is Domain analysis JSON only.
    declared_inputs_text = " ".join(manifest_block_or_flow(manifest, "inputs"))
    for domain in ("5gc-registration-mobility", "5gc-pdu-session", "5gc-handover-mobility"):
        if domain not in declared_inputs_text:
            errors.append(f"manifest inputs must declare the {domain} analysis summary source")

    # Manifest catalog integrity: exact set equality with the authoritative
    # scenario contract, duplicate-free, plus every path existing on disk.
    for section in ("fixtures", "expected_results"):
        entries = manifest_block_or_flow(manifest, section)
        duplicates = sorted({entry for entry in entries if entries.count(entry) > 1})
        if duplicates:
            errors.append(f"manifest testing.{section} contains duplicate entries: {duplicates}")
        for relative in entries:
            if not (skill / relative).exists():
                errors.append(f"manifest testing.{section} path does not exist: {relative}")
    expected_fixtures = {f"examples/inputs/{scenario}" for scenario in EXPECTED_SCENARIOS}
    declared_fixtures = set(manifest_block_or_flow(manifest, "fixtures"))
    if declared_fixtures != expected_fixtures:
        missing = sorted(expected_fixtures - declared_fixtures)
        extra = sorted(declared_fixtures - expected_fixtures)
        errors.append(
            "manifest testing.fixtures must exactly match the scenario catalog; "
            f"missing: {missing}; extra: {extra}"
        )
    expected_results = {
        f"examples/expected/{scenario}-analysis.json"
        for scenario in EXPECTED_SCENARIOS - FAILURE_EXPECTED_SCENARIOS
    }
    declared_results = set(manifest_block_or_flow(manifest, "expected_results"))
    if declared_results != expected_results:
        missing = sorted(expected_results - declared_results)
        extra = sorted(declared_results - expected_results)
        errors.append(
            "manifest testing.expected_results must exactly match the expected-output catalog; "
            f"missing: {missing}; extra: {extra}"
        )

    # Failure-expected integrity: input directory exists, no expected output.
    for scenario in sorted(FAILURE_EXPECTED_SCENARIOS):
        if not (skill / "examples/inputs" / scenario).is_dir():
            errors.append(f"fail-loudly scenario input directory is missing: {scenario}")
        if (skill / "examples/expected" / f"{scenario}-analysis.json").is_file():
            errors.append(f"fail-loudly scenario must not declare an expected output: {scenario}")

    try:
        schema = json.loads((skill / "schemas/5gc-failure-boundary-analysis.schema.json").read_text(encoding="utf-8"))
        properties = schema.get("properties", {})
        for field in ("analysis_name", "analysis_version", "diagnostic_groups", "unbound_domain_analyses", "limitations"):
            if field not in properties:
                errors.append(f"analysis schema must define {field}")
        group = schema.get("$defs", {}).get("diagnosticGroup", {})
        if not group:
            errors.append("analysis schema must define $defs/diagnosticGroup")
        else:
            for field in (
                "diagnostic_id", "subject_link", "source_domain_instances", "observation_scope",
                "candidate_boundaries", "selection_status", "selected_boundary", "boundary_confidence",
                "earlier_context", "downstream_observations", "evidence_limitations",
                "additional_evidence_needed", "supporting_anomalies", "not_confirmed", "limitations",
            ):
                if field not in group.get("properties", {}):
                    errors.append(f"diagnosticGroup definition must define {field}")
            status_enum = group.get("properties", {}).get("selection_status", {}).get("enum", [])
            for status in ("SELECTED", "NO_ABNORMAL_BOUNDARY_OBSERVED", "AMBIGUOUS_FIRST_BOUNDARY",
                           "INSUFFICIENT_COMPARABLE_EVIDENCE"):
                if status not in status_enum:
                    errors.append(f"selection_status vocabulary must include {status}")
        forbidden = [field for field in properties if FORBIDDEN_SCHEMA_FIELDS.search(field)]
        if forbidden:
            errors.append(f"analysis schema must not include causal or implementation fields: {forbidden}")
    except json.JSONDecodeError as exc:
        errors.append(f"analysis schema is invalid JSON: {exc}")

    input_root = skill / "examples/inputs"
    actual_scenarios = {path.name for path in input_root.iterdir() if path.is_dir()} if input_root.is_dir() else set()
    if actual_scenarios != EXPECTED_SCENARIOS:
        errors.append(f"synthetic input scenarios must cover all 70 bounded cases; found: {actual_scenarios}")

    for scenario in sorted(EXPECTED_SCENARIOS - FAILURE_EXPECTED_SCENARIOS):
        if not (input_root / scenario).is_dir():
            continue
        found_any = any(path.suffix == ".json" for path in (input_root / scenario).iterdir())
        if not found_any:
            errors.append(f"missing Domain analysis input for scenario {scenario}")
        if not (skill / "examples/expected" / f"{scenario}-analysis.json").is_file():
            errors.append(f"missing expected fixture for {scenario}")

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
        if path.parent.name != "tests" and path.suffix in {".py", ".json", ".jsonl"}:
            for line in text.splitlines():
                if IMPLEMENTATION_MAPPING.search(line):
                    errors.append(f"implementation or vendor source mapping in {name}")
                    break
        if path.suffix == ".py" and RAW_DECODER.search(text):
            errors.append(f"raw protocol decoding code in {name}")
        if path.parent.name != "tests" and path.suffix == ".py":
            for line in text.splitlines():
                lowered = line.lower()
                negated = any(neg in lowered for neg in ("no severity", "never", "not "))
                if TIMESTAMP_ONLY_JOIN.search(line):
                    errors.append(f"timestamp-only subject linking antipattern in {name}")
                if SEVERITY_RANKING.search(line) and not negated:
                    errors.append(f"severity-based candidate ranking antipattern in {name}")
                if FORBIDDEN_RELATION.search(line):
                    errors.append(f"causal downstream relation wording in {name}")
                if path.name == "failure_boundary_model.py" and PROSE_FRAME_PARSING.search(line):
                    errors.append(f"prose frame parsing antipattern in {name}")
                if path.name == "failure_boundary_model.py" and '"observed_evidence"' in line:
                    errors.append(f"orchestration model consumes Domain observed_evidence prose in {name}")

    for script_dir in (skill / "scripts", skill / "tests"):
        for script in script_dir.glob("*.py"):
            try:
                py_compile.compile(str(script), doraise=True)
            except py_compile.PyCompileError as exc:
                errors.append(f"script does not compile: {script.name}: {exc.msg}")

    # Structural source checks: mobility adapter, version floor, bridge gate,
    # and the boundaries the adapter must never cross.
    model_source = (skill / "scripts" / "failure_boundary_model.py").read_text(encoding="utf-8")
    if "def _handover_mobility_instances" not in model_source:
        errors.append("mobility Domain adapter is missing from the orchestration engine")
    if "HANDOVER_MOBILITY_VERSION_FLOOR = (0, 1, 0)" not in model_source:
        errors.append("mobility source-version floor gate is missing")
    if "BRIDGE_AUTHORIZED_STRENGTHS" not in model_source:
        errors.append("the Domain-authorized bridge strength gate is missing")
    try:
        tree = ast.parse(model_source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_handover_mobility_instances":
                adapter_source = ast.get_source_segment(model_source, node) or ""
                if '"stages"' in adapter_source or "'stages'" in adapter_source:
                    errors.append("the mobility adapter must not read stages array positions as ordering")
                if "unbound_mobility_evidence" in adapter_source:
                    errors.append("the mobility adapter must not read unbound_mobility_evidence")
    except SyntaxError as exc:
        errors.append(f"orchestration engine does not parse: {exc}")

    _behavioral_gates(skill, errors)
    return errors


def _load_model(skill: Path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "failure_boundary_model_gate", skill / "scripts" / "failure_boundary_model.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _behavioral_gates(skill: Path, errors: list[str]) -> None:
    """Runtime behavioral gates over committed v0.2.0 scenarios."""
    try:
        model = _load_model(skill)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"behavioral gates could not load the orchestration engine: {exc}")
        return

    def run(scenario: str) -> dict:
        inputs = skill / "examples" / "inputs" / scenario
        registration, pdu_session, handover_mobility = [], [], []
        for path in sorted(inputs.glob("*.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            if document.get("analysis_name") == "5gc-handover-mobility" or document.get("procedure_family") == "5gc-handover-mobility":
                handover_mobility.append(path)
            elif document.get("procedure_family") == "5gc-registration-mobility":
                registration.append(path)
            elif document.get("procedure_name") == "5gc-pdu-session":
                pdu_session.append(path)
            else:
                raise ValueError(f"unrecognized Domain analysis in {scenario}: {path.name}")
        return model.analyze(registration, pdu_session, handover_mobility)

    try:
        bridged = run("handover-bridge-strong")
        groups = bridged["diagnostic_groups"]
        if len(groups) != 1 or groups[0]["subject_link"]["strength"] != "SUPPORTED":
            errors.append("behavioral gate failed: the Domain-authorized source/target bridge did not form one SUPPORTED group")
        elif not groups[0]["subject_link"].get("context_bridges"):
            errors.append("behavioral gate failed: the bridged group lacks structured context-bridge provenance")

        for scenario in ("handover-bridge-ambiguous", "handover-bridge-candidates"):
            document = run(scenario)
            if len(document["diagnostic_groups"]) != 2:
                errors.append(f"behavioral gate failed: {scenario} must not merge groups")
            if any(group["subject_link"].get("context_bridges") for group in document["diagnostic_groups"]):
                errors.append(f"behavioral gate failed: {scenario} produced a context bridge")

        independent = run("ps-independent-boundary")
        if len(independent["diagnostic_groups"]) != 1 or \
                independent["diagnostic_groups"][0]["subject_link"]["strength"] != "UNBOUND":
            errors.append("behavioral gate failed: independent Path Switch was not handled as its own subject")

        for scenario in ("ho-preparation-negative", "ps-negative-outcome"):
            document = run(scenario)
            group = document["diagnostic_groups"][0]
            selected = group.get("selected_boundary")
            if group["selection_status"] != "SELECTED" or selected is None:
                errors.append(f"behavioral gate failed: {scenario} did not select the mobility boundary")
            elif selected["boundary_ref"]["source_domain"] != "5gc-handover-mobility":
                errors.append(f"behavioral gate failed: {scenario} selected a non-mobility boundary")

        partial = run("ho-missing-counterpart-partial")
        if partial["diagnostic_groups"][0]["selection_status"] != "INSUFFICIENT_COMPARABLE_EVIDENCE":
            errors.append("behavioral gate failed: partial-capture missing evidence was not blocked")

        ordering = run("registration-earlier-than-handover")
        group = ordering["diagnostic_groups"][0]
        if group["selection_status"] != "SELECTED" or \
                group["selected_boundary"]["boundary_ref"]["source_domain"] != "5gc-registration-mobility":
            errors.append("behavioral gate failed: exact-context cross-Domain ordering did not select the earlier registration boundary")

        families = run("ho-and-ps-one-group")
        group = families["diagnostic_groups"][0]
        mobility_families = sorted(
            instance.get("mobility_attempt_family")
            for instance in group["source_domain_instances"]
            if instance.get("source_domain") == "5gc-handover-mobility"
        )
        if mobility_families != ["handover", "path-switch"]:
            errors.append("behavioral gate failed: handover and Path Switch attempts were merged into one family")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"behavioral gate execution failed: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("5gc-failure-boundary validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("5gc-failure-boundary validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
