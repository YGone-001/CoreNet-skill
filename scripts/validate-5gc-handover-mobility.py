#!/usr/bin/env python3
"""Validate the standalone 5gc-handover-mobility Domain Skill contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import py_compile
import re
import sys
from pathlib import Path

SKILL = Path("skills/domain/5gc-handover-mobility")

REQUIRED = (
    "SKILL.md", "README.md", "manifest.yaml",
    "references/procedure-model.md", "references/handover-model.md",
    "references/path-switch-model.md", "references/source-target-association.md",
    "references/pdu-session-resource-model.md", "references/n11-n4-n3-evidence.md",
    "references/deviation-model.md", "references/failure-cases.md",
    "schemas/procedure-evidence.schema.json",
    "schemas/5gc-handover-mobility-analysis.schema.json",
    "scripts/mobility_model.py", "scripts/analyze_handover_mobility.py",
    "scripts/mobility_timeline.py",
    "tests/test_5gc_handover_mobility.py",
)
REQUIRED_FIXTURES = (
    "examples/inputs/full-n2-handover",
    "examples/inputs/handover-ack-mixed-resources",
    "examples/inputs/ambiguous-two-targets",
    "examples/inputs/ps-no-handover-evidence",
    "examples/inputs/ps-near-unrelated-handover",
    "examples/inputs/pfcp-unrelated-unbound",
    "examples/inputs/teid-endpoint-mismatch",
    "examples/inputs/no-gtpu-neutral",
    "examples/inputs/malformed-input",
    "examples/inputs/multiple-captures",
)
MIXED_RESOURCE_FIXTURES = (
    "examples/expected/handover-ack-mixed-resources-analysis.json",
    "examples/expected/ps-ack-mixed-resources-analysis.json",
)

ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
IMPLEMENTATION_ASSET = re.compile(r"(?i)open5gs|free5gc|openairinterface|srsran|ueransim|nokia|ericsson|huawei|zte\b")
SUBSCRIBER_FIELD = re.compile(r"(?i)[\"']?(?:imsi|msisdn|suci|supi|fiveg?[-_]guti|guti)[\"']?\s*[:=]")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s+[0-9]+\b|\bmilestone\s+b?[0-9]+\b")
FOREIGN_SEMANTICS = re.compile(r"(?i)\b(?:gtpv2|nsmf_pdusession)\w*|(?:^|[^\w])teid[\"']?\s*[:=]")
PROTOCOL_DECODER = re.compile(r"(?i)pyasn1|asn1tools|asn1crypto|import\s+asn1\b|def\s+(?:parse|decode|dissect)_(?:ngap|nas|pfcp|gtp|packet|payload)")
TRANSFER_DECODER = re.compile(
    r"(?i)handover\w*transfer\s*\[|pathswitch\w*transfer\s*\[|transfer_bytes|raw_transfer|"
    r"def\s+\w*transfer\w*(?:decode|parse)")
TIMESTAMP_JOIN = re.compile(r"(?i)\b(?:match|join|link|associate|correlate)_by_timestamp(?:_only)?\b")
NEAREST_SELECTION = re.compile(r"(?i)nearest[ _-]?(?:in[ _-])?time|min\(\s*(?:\w+,\s*)*key\s*=\s*(?:lambda\s+\w+\s*:\s*)?abs\s*\(")
POSITIONAL_PSI_ZIP = re.compile(
    r"(?i)zip\([^)\n]*(?:p?du_?session|psi)[^)\n]*,\s*[^)\n]*(?:qfi|cause|role|transfer)"
    r"|zip\([^)\n]*(?:qfi|cause|role|transfer)[^)\n]*,\s*[^)\n]*(?:p?du_?session|psi)")
GLOBAL_AMF_IDENTITY = re.compile(r"(?i)global_?ue|amf_id_?only|amf_?ue_?ngap_?id\s*==\s*\w+\s*and\s*not")
RAN_ID_EQUALITY = re.compile(r"(?i)ran_?ue_?ngap_?id\s*==\s*ran_?ue_?ngap_?id")
FORBIDDEN_OUTPUT_FIELDS = re.compile(
    r"(?i)root_?cause|culprit|responsible_?nf|vendor_?fault|implementation_?failure|"
    r"radio_?fault|handover_?success|path_?switch_?success|mobility_?success")
SINGLE_FAMILY_ARRAY = re.compile(r"(?i)[\"']mobility_attempts[\"']\]?\s*[=:]|mobility_attempt\s*=")
MANDATORY_SEQUENCE = re.compile(
    r"(?i)mandatory.*(handover_required|path_switch|handover.*path_switch.*sequence)|"
    r"required_messages\s*=|MISSING_HANDOVER_REQUIRED|MISSING_PATH_SWITCH")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_value(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def manifest_list(text: str, key: str) -> list[str]:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*\[([^\]]*)\]", text)
    if match is not None:
        return [item.strip() for item in match.group(1).split(",") if item.strip()]
    block = re.search(rf"(?m)^\s*{re.escape(key)}:\s*\n((?:\s+-\s+.+\n?)+)", text)
    if block is None:
        return []
    return [line.strip().lstrip("-").strip() for line in block.group(1).splitlines() if line.strip()]


def jsonl_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    skill = root / SKILL
    if not skill.is_dir():
        return [f"missing Skill directory: {SKILL}"]
    for relative in REQUIRED:
        if not (skill / relative).is_file():
            errors.append(f"missing required package file: {relative}")
    for relative in REQUIRED_FIXTURES:
        if not (skill / relative).is_dir():
            errors.append(f"missing required fixture directory: {relative}")
    if errors:
        return errors

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    for key, expected in (("name", "5gc-handover-mobility"), ("version", "0.1.0"), ("category", "domain")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"manifest {key} must be {expected}")
    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append("manifest must not require another CoreNet Skill")
    if manifest_list(manifest, "protocols"):
        errors.append("manifest protocols must stay empty for a Domain Skill")
    interfaces = set(manifest_list(manifest, "interfaces"))
    if interfaces != {"N2", "N3", "N4", "N11"}:
        errors.append("manifest interfaces must be N2, N3, N4, N11")
    if manifest_value(manifest, "network_functions") not in (None, "[]"):
        errors.append("manifest network_functions must stay empty")
    optional = " ".join(manifest_list(manifest, "optional"))
    for dependency in ("procedure-evidence >=0.1.0", "ngap >=0.3.0", "pfcp >=0.1.0",
                       "gtpu >=0.1.0", "sbi-http2 >=0.2.0", "5gc-pdu-session >=0.4.0"):
        if dependency not in optional:
            errors.append(f"manifest optional dependencies must include {dependency}")
    includes = " ".join(manifest_list(manifest, "includes")).lower()
    if "handover_attempts" not in includes or "path_switch_attempts" not in includes:
        errors.append("manifest scope must declare the separated handover_attempts and path_switch_attempts families")

    local_trace = skill / "schemas" / "procedure-evidence.schema.json"
    shared = root / "skills" / "domain" / "procedure-evidence" / "schemas" / "procedure-evidence.schema.json"
    if not shared.is_file() or digest(local_trace) != digest(shared):
        errors.append("procedure-evidence schema copy must match the authoritative framework schema bytes")

    try:
        schema = json.loads((skill / "schemas" / "5gc-handover-mobility-analysis.schema.json").read_text(encoding="utf-8"))
        required = schema.get("required", [])
        for key in ("analysis_name", "analysis_version", "handover_attempts", "path_switch_attempts",
                    "unbound_mobility_evidence", "limitations"):
            if key not in required:
                errors.append(f"analysis schema must require {key}")
        properties = schema.get("properties", {})
        definitions = schema.get("$defs", {})
        for definition, keys in (
            ("handoverAttempt", ("attempt_id", "family", "handover_type", "source_context", "target_context",
                                 "association", "stages", "pdu_session_resources", "terminal_observation",
                                 "deviations", "earliest_observed_deviation", "field_findings", "plane_bindings",
                                 "limitations", "observation_window")),
            ("pathSwitchAttempt", ("attempt_id", "family", "serving_context", "related_handover_attempt_id",
                                   "relationship_basis", "relationship_strength", "stages",
                                   "pdu_session_resources", "terminal_observation", "deviations",
                                   "earliest_observed_deviation", "field_findings", "plane_bindings",
                                   "limitations", "observation_window")),
        ):
            definition_properties = definitions.get(definition, {}).get("properties", {})
            for key in keys:
                if key not in definition_properties:
                    errors.append(f"{definition} schema must model {key}")
        association = definitions.get("handoverAttempt", {}).get("properties", {}).get("association", {})
        strengths = definitions.get("association", {}).get("properties", {}).get("strength", {}).get("enum", [])
        for strength in ("STRONG", "SUPPORTED", "AMBIGUOUS", "UNBOUND"):
            if strength not in strengths:
                errors.append(f"association strength vocabulary must include {strength}")
        terminal_enum = definitions.get("terminalObservation", {}).get("properties", {}).get("observation", {}).get("enum", [])
        for label in ("HANDOVER_NOTIFY_OBSERVED", "HANDOVER_CANCEL_ACK_OBSERVED",
                      "PATH_SWITCH_ACK_OBSERVED", "NO_TERMINAL_MOBILITY_OBSERVATION", "PARTIAL_CAPTURE"):
            if label not in terminal_enum:
                errors.append(f"terminal observation vocabulary must include {label}")
            if "HANDOVER_SUCCESS" in terminal_enum or "PATH_SWITCH_SUCCESS" in terminal_enum:
                errors.append("terminal observation vocabulary must not contain success verdicts")
        deviation_enum = definitions.get("deviation", {}).get("properties", {}).get("type", {}).get("enum", [])
        for deviation in ("PROTOCOL_NEGATIVE_OUTCOME_OBSERVED", "RESOURCE_FAILED_ITEM_OBSERVED",
                          "MISSING_EXPECTED_COUNTERPART", "FIELD_CONFLICT", "PARTIAL_CAPTURE",
                          "CORRELATION_AMBIGUITY"):
            if deviation not in deviation_enum:
                errors.append(f"deviation vocabulary must include {deviation}")
        evidence_ref = definitions.get("evidenceRef", {}).get("properties", {}).get("kind", {}).get("enum", [])
        for kind in ("EVENT", "FIELD_FINDING", "OBSERVATION_WINDOW", "STAGE"):
            if kind not in evidence_ref:
                errors.append(f"evidence ref kinds must include {kind}")
        forbidden = [name for name in list(properties) + list(definitions.get("handoverAttempt", {}).get("properties", {}))
                     + list(definitions.get("pathSwitchAttempt", {}).get("properties", {}))
                     if FORBIDDEN_OUTPUT_FIELDS.search(name)]
        if forbidden:
            errors.append(f"analysis schema must not include verdict or blame fields: {forbidden}")
    except json.JSONDecodeError as exc:
        errors.append(f"analysis schema is invalid JSON: {exc}")

    # Mixed-resource fixtures must keep item-scoped outcomes.
    for name in MIXED_RESOURCE_FIXTURES:
        try:
            document = json.loads((skill / name).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"expected fixture is invalid: {name}: {exc}")
            continue
        attempts = document.get("handover_attempts", []) + document.get("path_switch_attempts", [])
        negative = False
        positive = False
        for attempt in attempts:
            for finding in attempt.get("pdu_session_resources", []):
                outcomes = {item.get("outcome") for item in finding.get("n2_outcomes", [])}
                negative = negative or bool(outcomes & {"RESOURCE_FAILED_ITEM_OBSERVED", "RELEASED_ROLE_OBSERVED"})
                positive = positive or bool(outcomes & {"ADMITTED_ROLE_OBSERVED", "SWITCHED_ROLE_OBSERVED"})
        if not (negative and positive):
            errors.append(f"expected fixture must preserve item-scoped mixed outcomes: {name}")

    # Association-model documentation and family separation must be explicit.
    association_doc = (skill / "references" / "source-target-association.md").read_text(encoding="utf-8").lower()
    for phrase in ("strong", "supported", "ambiguous", "unbound", "amf-ue-ngap-id"):
        if phrase not in association_doc:
            errors.append(f"source-target-association.md must document the {phrase} basis")

    for path in skill.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if path.suffix in {".pcap", ".pcapng", ".cap"}:
            errors.append(f"binary capture fixture is not allowed: {relative}")
        if path.suffix in {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}:
            text = path.read_text(encoding="utf-8")
            if "../../../" in text or "third_party/" in text:
                errors.append(f"repository-root runtime reference in {relative}")
            if ABSOLUTE_PATH.search(text):
                errors.append(f"absolute workstation path in {relative}")
            if IMPLEMENTATION_ASSET.search(text):
                errors.append(f"implementation mapping asset or reference in {relative}")
            if LIFECYCLE_MARKER.search(text):
                errors.append(f"lifecycle marker must stay in task coordination, not the repository: {relative}")
            if path.parent.name == "scripts":
                if PROTOCOL_DECODER.search(text):
                    errors.append(f"protocol decoding must not appear in {relative}")
                if TRANSFER_DECODER.search(text):
                    errors.append(f"NGAP opaque mobility transfer decoding is not allowed in {relative}")
                for line in text.splitlines():
                    if TIMESTAMP_JOIN.search(line):
                        errors.append(f"timestamp-based association joining is not allowed in {relative}")
                        break
                for line in text.splitlines():
                    lowered = line.lower()
                    negated = any(negation in lowered for negation in ("no nearest", "never", "not "))
                    if NEAREST_SELECTION.search(line) and not negated:
                        errors.append(f"nearest-in-time candidate selection is not allowed in {relative}")
                        break
                if POSITIONAL_PSI_ZIP.search(text):
                    errors.append(f"positional PSI-resource zip antipattern is not allowed in {relative}")
                if GLOBAL_AMF_IDENTITY.search(text):
                    errors.append(f"AMF-UE-NGAP-ID must never act as a global identity in {relative}")
                if RAN_ID_EQUALITY.search(text):
                    errors.append(f"RAN-UE-ID equality must never establish identity in {relative}")
                if SINGLE_FAMILY_ARRAY.search(text):
                    errors.append(f"handover and Path Switch must stay separate attempt families in {relative}")
                if MANDATORY_SEQUENCE.search(text):
                    errors.append(f"neither family may be mandatory for the other in {relative}")
            if path.parent.name in {"inputs", "expected"}:
                if SUBSCRIBER_FIELD.search(text):
                    errors.append(f"subscriber identity field in fixture {relative}")

    for directory in (skill / "scripts", skill / "tests"):
        for script in directory.glob("*.py"):
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
        print("5gc-handover-mobility validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("5gc-handover-mobility validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
