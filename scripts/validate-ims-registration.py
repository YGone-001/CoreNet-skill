#!/usr/bin/env python3
"""Validate the standalone ims-registration Domain Skill contract."""

from __future__ import annotations

import copy
import json
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "domain" / "ims-registration"
SCRIPTS = SKILL / "scripts"
EXAMPLES = SKILL / "examples"
EXPECTED = EXAMPLES / "expected"
CLI = SCRIPTS / "analyze-ims-registration.py"
SCHEMA = SKILL / "schemas" / "ims-registration-analysis.schema.json"
SIP_INPUT = EXAMPLES / "input" / "registration-cases.jsonl"
DIAMETER_INPUT = EXAMPLES / "input" / "diameter-ims-cases.json"
SIP_SCRIPTS = ROOT / "skills" / "protocol" / "sip" / "scripts"

sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SIP_SCRIPTS))
import ims_registration_model  # noqa: E402
import sip_model  # noqa: E402
import sip_transactions  # noqa: E402

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/registration-procedures.md",
    "references/authentication-evidence.md",
    "references/diameter-context.md",
    "references/evidence-model.md",
    "references/privacy.md",
    "references/failure-cases.md",
    "schemas/ims-registration-analysis.schema.json",
    "scripts/analyze-ims-registration.py",
    "scripts/ims_registration_model.py",
    "tests/test_ims_registration.py",
    "examples/input/registration-cases.jsonl",
    "examples/input/diameter-ims-cases.json",
    "examples/expected/registration-analysis-sip-only.json",
    "examples/expected/registration-analysis.json",
    "examples/expected/registration-report.txt",
)

PRIVACY_SECRETS = (
    "alice@",
    "registrar.example",
    "FTAG",
    "PRIVATE-CALL-ID",
    "PRIVATE-FROM-TAG",
    "PRIVATE-TO-TAG",
    "private-user",
    "nonce",
    "response=",
    "sip:alice",
)

REQUIRED_TEST_TOKENS = (
    "test_single_register_with_200",
    "test_401_is_a_challenge_not_a_failure",
    "test_407_is_a_challenge_not_a_failure",
    "test_401_retry_200",
    "test_407_retry_200",
    "test_response_only_is_not_a_successful_attempt",
    "test_incompatible_cseq_is_split",
    "test_different_captures_never_share_an_attempt",
    "test_423_min_expires_and_retry",
    "test_no_established_association",
    "test_diameter_is_optional",
    "test_actual_output_passes_strict_schema",
    "test_no_sensitive_identity_leakage",
    "test_deterministic_replay",
    "test_authorized_register_then_401_without_later_register",
    "test_wildcard_without_expires_is_invalid",
    "test_contact_specific_expiration_is_scoped",
    "test_wildcard_contact_deregistration",
    "test_timeline_above_limit_conserves_rows",
    "test_diameter_observation_conservation",
    "test_json_output_equals_diameter_input",
    "test_sip_and_diameter_from_different_captures",
    "test_bounded_output_passes_schema_and_semantics",
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _producer(directory: Path, *, diameter: bool) -> tuple[Path, Path, subprocess.CompletedProcess]:
    output = directory / ("analysis-with-diameter.json" if diameter else "analysis-sip-only.json")
    report = directory / ("report-with-diameter.txt" if diameter else "report-sip-only.txt")
    command = [
        sys.executable,
        str(CLI),
        "--sip-input",
        str(SIP_INPUT),
        "--output",
        str(output),
        "--report",
        str(report),
        "--force",
    ]
    if diameter:
        command.extend(["--diameter-ims", str(DIAMETER_INPUT)])
    return output, report, run(command)


def main() -> int:
    errors: list[str] = []
    for relative in REQUIRED:
        if not (SKILL / relative).is_file():
            errors.append(f"missing required file: {relative}")
    with tempfile.TemporaryDirectory() as compile_directory:
        for script in SCRIPTS.glob("*.py"):
            try:
                py_compile.compile(
                    str(script),
                    cfile=str(Path(compile_directory) / f"{script.stem}.pyc"),
                    doraise=True,
                )
            except py_compile.PyCompileError as exc:
                errors.append(f"compile failure {script.name}: {exc}")
    if errors:
        for error in errors:
            print(f"validate-ims-registration: {error}", file=sys.stderr)
        return 1

    try:
        import jsonschema
    except ImportError:
        print("validate-ims-registration: jsonschema is required", file=sys.stderr)
        return 1

    schema = load_json(SCHEMA)
    if schema.get("additionalProperties") is not False:
        errors.append("schema must set additionalProperties: false")
    for required in (
        "analysis_name",
        "analysis_version",
        "domain",
        "capability",
        "input_provenance",
        "sip_registration_inventory",
        "registration_attempts",
        "diameter_ims_inventory",
        "cross_protocol_associations",
        "timeline",
        "completeness",
        "limitations",
        "not_confirmed",
    ):
        if required not in schema.get("required", []):
            errors.append(f"schema is missing required property: {required}")
    if schema["properties"]["analysis_version"].get("const") != ims_registration_model.ANALYSIS_VERSION:
        errors.append("schema analysis_version diverges from the model constant")
    for definition in (
        "capability",
        "input_provenance",
        "registration_transaction",
        "registration_attempt",
        "diameter_observation",
        "cross_protocol_association",
        "timeline",
        "completeness",
        "challenge_retry_association",
    ):
        if schema["$defs"][definition].get("additionalProperties") is not False:
            errors.append(f"schema definition {definition} is not strict")

    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for token in ("name: ims-registration", "category: domain", "sip >=", "diameter-ims >="):
        if token not in manifest:
            errors.append(f"manifest missing {token}")

    test_source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((SKILL / "tests").glob("test_*.py"))
    )
    for token in REQUIRED_TEST_TOKENS:
        if token not in test_source:
            errors.append(f"test suite is missing required coverage: {token}")

    messages, _ = sip_model.messages_for_input(SIP_INPUT, "fields-jsonl")
    transaction_document = sip_transactions.correlate(messages)
    event_references = {message["match"]["source_reference"] for message in messages}
    transaction_references = {
        transaction["transaction_reference"] for transaction in transaction_document["transactions"]
    }

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        sip_only, sip_report, completed = _producer(directory, diameter=False)
        if completed.returncode != 0:
            errors.append(f"SIP-only producer failed: {completed.stderr.strip()}")
        else:
            if sip_only.read_bytes() != (EXPECTED / "registration-analysis-sip-only.json").read_bytes():
                errors.append("SIP-only output differs from the committed expectation")
            document = load_json(sip_only)
            try:
                jsonschema.validate(document, schema)
                ims_registration_model.validate_analysis(
                    document,
                    sip_event_references=event_references,
                    transaction_references=transaction_references,
                )
            except (jsonschema.ValidationError, ims_registration_model.InputError) as exc:
                errors.append(f"SIP-only schema or semantic validation failed: {exc}")
            text = json.dumps(document) + sip_report.read_text(encoding="utf-8")
            for secret in PRIVACY_SECRETS:
                if secret in text:
                    errors.append(f"SIP-only output leaked a sensitive value: {secret}")
            for field in ('"call_id"', '"from_tag"', '"to_tag"', '"request_uri"', '"authorization"'):
                if field in text:
                    errors.append(f"SIP-only output publishes a raw identity field: {field}")
            if document["input_provenance"]["diameter_status"] != "NOT_SUPPLIED":
                errors.append("SIP-only analysis did not report NOT_SUPPLIED for Diameter")

        output, report, completed = _producer(directory, diameter=True)
        if completed.returncode != 0:
            errors.append(f"producer failed: {completed.stderr.strip()}")
        else:
            for path, expected_name in (
                (output, "registration-analysis.json"),
                (report, "registration-report.txt"),
            ):
                if path.read_bytes() != (EXPECTED / expected_name).read_bytes():
                    errors.append(f"{expected_name} differs from the committed expectation")
            document = load_json(output)
            try:
                jsonschema.validate(document, schema)
                ims_registration_model.validate_analysis(
                    document,
                    sip_event_references=event_references,
                    transaction_references=transaction_references,
                )
            except (jsonschema.ValidationError, ims_registration_model.InputError) as exc:
                errors.append(f"schema or semantic validation failed: {exc}")

            text = json.dumps(document) + report.read_text(encoding="utf-8")
            for secret in PRIVACY_SECRETS:
                if secret in text:
                    errors.append(f"output leaked a sensitive value: {secret}")
            for field in ('"call_id"', '"from_tag"', '"to_tag"', '"request_uri"', '"authorization"'):
                if field in text:
                    errors.append(f"output publishes a raw identity field: {field}")

            completeness = document["completeness"]
            for total_key, published, omitted_key in (
                (
                    "registration_inventory_count",
                    len(document["sip_registration_inventory"]),
                    "registration_inventory_omitted",
                ),
                (
                    "attempt_count",
                    len(document["registration_attempts"]),
                    "attempts_omitted",
                ),
                (
                    "diameter_observation_count",
                    len(document["diameter_ims_inventory"]),
                    "diameter_observations_omitted",
                ),
                (
                    "association_count",
                    len(document["cross_protocol_associations"]),
                    "associations_omitted",
                ),
            ):
                if completeness[total_key] != published + completeness[omitted_key]:
                    errors.append(f"{total_key} does not satisfy count conservation")
            timeline = document["timeline"]
            if timeline["row_count"] != len(timeline["rows"]) + timeline["rows_omitted"]:
                errors.append("timeline count does not satisfy count conservation")
            if timeline["sip_row_count"] + timeline["diameter_row_count"] != timeline["row_count"]:
                errors.append("timeline source rows do not match the total")
            if timeline["sip_row_count"] and timeline["diameter_row_count"] and timeline["global_order_proven"]:
                errors.append("cross-source timeline claims global frame order")
            statuses = {
                item["association_status"] for item in document["cross_protocol_associations"]
            }
            if statuses - {"NOT_ESTABLISHED", "INSUFFICIENT_EVIDENCE"}:
                errors.append(f"cross-protocol associations are not fail-closed: {statuses}")
            if not document["diameter_ims_inventory"]:
                errors.append("supplied Diameter fixture produced no Cx/Dx inventory")
            for attempt in document["registration_attempts"]:
                if attempt["authentication_cryptographically_verified"] is not False:
                    errors.append("an attempt claims cryptographic authentication verification")

            tampered = copy.deepcopy(document)
            tampered["registration_attempts"][0]["attempt_reference"] = "invalid"
            try:
                ims_registration_model.validate_analysis(tampered)
            except ims_registration_model.InputError:
                pass
            else:
                errors.append("invalid attempt reference was not rejected")

            duplicate = copy.deepcopy(document)
            duplicate["registration_attempts"][1]["attempt_reference"] = duplicate[
                "registration_attempts"
            ][0]["attempt_reference"]
            try:
                ims_registration_model.validate_analysis(duplicate)
            except ims_registration_model.InputError:
                pass
            else:
                errors.append("duplicate attempt reference was not rejected")

            established = copy.deepcopy(document)
            established["cross_protocol_associations"][0]["association_status"] = "ESTABLISHED"
            try:
                ims_registration_model.validate_analysis(established)
            except ims_registration_model.InputError:
                pass
            else:
                errors.append("an unsupported ESTABLISHED association was not rejected")

            second = directory / "second-analysis.json"
            rerun = run(
                [
                    sys.executable,
                    str(CLI),
                    "--sip-input",
                    str(SIP_INPUT),
                    "--diameter-ims",
                    str(DIAMETER_INPUT),
                    "--output",
                    str(second),
                    "--force",
                ]
            )
            if rerun.returncode != 0:
                errors.append(f"deterministic rerun failed: {rerun.stderr.strip()}")
            elif second.read_bytes() != output.read_bytes():
                errors.append("analysis is not deterministic")

            invalid = directory / "invalid-diameter.json"
            invalid.write_text('{"analysis_name": "other"}', encoding="utf-8")
            invalid_output = directory / "invalid-output.json"
            invalid_run = run(
                [
                    sys.executable,
                    str(CLI),
                    "--sip-input",
                    str(SIP_INPUT),
                    "--diameter-ims",
                    str(invalid),
                    "--output",
                    str(invalid_output),
                ]
            )
            if invalid_run.returncode != 2:
                errors.append(
                    f"invalid Diameter input did not return exit code 2: {invalid_run.returncode}"
                )
            if invalid_output.exists():
                errors.append("invalid Diameter input still published an analysis document")

        missing_directory = run(
            [
                sys.executable,
                str(CLI),
                "--sip-input",
                str(SIP_INPUT),
                "--output",
                str(directory / "absent" / "analysis.json"),
            ]
        )
        if missing_directory.returncode != 6:
            errors.append(
                f"missing output directory did not return exit code 6: {missing_directory.returncode}"
            )

        existing = directory / "existing.json"
        existing.write_text("existing", encoding="utf-8")
        refused = run(
            [
                sys.executable,
                str(CLI),
                "--sip-input",
                str(SIP_INPUT),
                "--output",
                str(existing),
            ]
        )
        if refused.returncode != 6:
            errors.append(
                f"existing output without --force did not return exit code 6: {refused.returncode}"
            )

        import hashlib
        import shutil

        source_copy = directory / "source.jsonl"
        shutil.copyfile(SIP_INPUT, source_copy)
        source_hash = hashlib.sha256(source_copy.read_bytes()).hexdigest()
        diameter_copy = directory / "diameter.json"
        shutil.copyfile(DIAMETER_INPUT, diameter_copy)
        diameter_hash = hashlib.sha256(diameter_copy.read_bytes()).hexdigest()

        collision_cases = (
            (
                "output equals Diameter input",
                ["--sip-input", str(source_copy), "--diameter-ims", str(diameter_copy), "--output", str(diameter_copy)],
            ),
            (
                "report equals JSON output",
                [
                    "--sip-input",
                    str(source_copy),
                    "--output",
                    str(directory / "same.json"),
                    "--report",
                    str(directory / "same.json"),
                ],
            ),
            (
                "force does not override input protection",
                ["--sip-input", str(source_copy), "--output", str(source_copy), "--force"],
            ),
        )
        for label, arguments in collision_cases:
            completed = run([sys.executable, str(CLI), *arguments])
            if completed.returncode == 0:
                errors.append(f"destination collision was not rejected: {label}")
        if hashlib.sha256(source_copy.read_bytes()).hexdigest() != source_hash:
            errors.append("destination collision modified the SIP source")
        if hashlib.sha256(diameter_copy.read_bytes()).hexdigest() != diameter_hash:
            errors.append("destination collision modified the Diameter source")

    if errors:
        for error in errors:
            print(f"validate-ims-registration: {error}", file=sys.stderr)
        return 1
    print("ims-registration validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())