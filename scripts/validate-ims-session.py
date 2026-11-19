#!/usr/bin/env python3
"""Validate the standalone ims-session Domain Skill contract."""

from __future__ import annotations

import json
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "domain" / "ims-session"
SCRIPTS = SKILL / "scripts"
INPUTS = SKILL / "examples" / "inputs"
EXPECTED = SKILL / "examples" / "expected"
CLI = SCRIPTS / "analyze-ims-session.py"
SCHEMA = SKILL / "schemas" / "ims-session-analysis.schema.json"

sys.path.insert(0, str(SCRIPTS))
import ims_session_model  # noqa: E402

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/session-procedures.md",
    "references/evidence-model.md",
    "references/failure-cases.md",
    "references/privacy.md",
    "schemas/ims-session-analysis.schema.json",
    "scripts/analyze-ims-session.py",
    "scripts/ims_session_model.py",
    "tests/test_ims_session.py",
    "examples/inputs/session-cases-events.jsonl",
    "examples/inputs/session-cases-transactions.json",
    "examples/inputs/session-cases-dialogs.json",
    "examples/expected/session-analysis.json",
    "examples/expected/session-report.txt",
)
REQUIRED_TEST_TOKENS = tuple(
    f"test_{index:02d}_" for index in range(1, 37)
) + (
    "test_deterministic_replay_and_schema",
    "test_expected_output_and_report_match_committed_fixture",
)
PRIVATE_TOKENS = (
    "sip:caller@example.com",
    "sip:callee@example.com",
    "PRIVATE-CALLID",
    "PRIVATE-FTAG",
    "PRIVATE-TTAG",
    "nonce",
    "response=",
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _producer(directory: Path) -> tuple[Path, Path, subprocess.CompletedProcess]:
    output = directory / "analysis.json"
    report = directory / "report.txt"
    completed = run(
        [
            sys.executable,
            str(CLI),
            "--sip-events",
            str(INPUTS / "session-cases-events.jsonl"),
            "--sip-transactions",
            str(INPUTS / "session-cases-transactions.json"),
            "--sip-dialogs",
            str(INPUTS / "session-cases-dialogs.json"),
            "--output",
            str(output),
            "--report",
            str(report),
            "--force",
        ]
    )
    return output, report, completed


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
            print(f"validate-ims-session: {error}", file=sys.stderr)
        return 1

    try:
        import jsonschema
    except ImportError:
        print("validate-ims-session: jsonschema is required", file=sys.stderr)
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
        "session_attempt_count",
        "session_attempts",
        "unbound_observations",
        "in_dialog_observations",
        "completeness",
        "limitations",
        "not_confirmed",
    ):
        if required not in schema.get("required", []):
            errors.append(f"schema is missing required property: {required}")
    if schema["properties"]["analysis_version"].get("const") != ims_session_model.ANALYSIS_VERSION:
        errors.append("schema analysis_version diverges from the model constant")
    for definition in (
        "session_attempt",
        "stage_evidence",
        "branch",
        "branch_release",
        "ack_evidence",
        "cancel_evidence",
        "release_evidence",
        "unbound_observation",
        "in_dialog_observation",
        "completeness",
    ):
        if schema["$defs"][definition].get("additionalProperties") is not False:
            errors.append(f"schema definition {definition} is not strict")

    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for token in (
        "name: ims-session",
        "version: 0.1.0",
        "category: domain",
        "sip >=0.4.0",
    ):
        if token not in manifest:
            errors.append(f"manifest missing {token}")

    test_source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((SKILL / "tests").glob("test_*.py"))
    )
    for token in REQUIRED_TEST_TOKENS:
        if token not in test_source:
            errors.append(f"test suite is missing required coverage: {token}")

    events, transactions, dialogs, provenance = ims_session_model.load_inputs(
        INPUTS / "session-cases-events.jsonl",
        INPUTS / "session-cases-transactions.json",
        INPUTS / "session-cases-dialogs.json",
    )
    event_references = {event["source_reference"] for event in events}
    transaction_references = {
        item["transaction_reference"] for item in transactions["transactions"]
    }
    dialog_references = {item["dialog_reference"] for item in dialogs["dialogs"]}
    document = ims_session_model.build_analysis(
        events, transactions, dialogs, provenance=provenance
    )
    try:
        jsonschema.validate(document, schema)
        ims_session_model.validate_analysis(
            document,
            event_references=event_references,
            transaction_references=transaction_references,
            dialog_references=dialog_references,
        )
    except (jsonschema.ValidationError, ims_session_model.InputError) as exc:
        errors.append(f"in-process schema or semantic validation failed: {exc}")

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        output, report, completed = _producer(directory)
        if completed.returncode != 0:
            errors.append(f"producer failed: {completed.stderr.strip()}")
        else:
            for path, expected_name in (
                (output, "session-analysis.json"),
                (report, "session-report.txt"),
            ):
                if path.read_bytes() != (EXPECTED / expected_name).read_bytes():
                    errors.append(f"{expected_name} differs from the committed expectation")
            produced = load_json(output)
            try:
                jsonschema.validate(produced, schema)
                ims_session_model.validate_analysis(
                    produced,
                    event_references=event_references,
                    transaction_references=transaction_references,
                    dialog_references=dialog_references,
                )
            except (jsonschema.ValidationError, ims_session_model.InputError) as exc:
                errors.append(f"schema or semantic validation failed: {exc}")
            text = json.dumps(produced) + report.read_text(encoding="utf-8")
            for secret in PRIVATE_TOKENS:
                if secret in text:
                    errors.append(f"output leaked a sensitive value: {secret}")
            for field in ('"call_id"', '"from_tag"', '"to_tag"', '"request_uri"', '"sip_uri"'):
                if field in text:
                    errors.append(f"output publishes a raw identity field: {field}")
            completeness = produced["completeness"]
            if completeness["session_attempt_count"] != (
                len(produced["session_attempts"]) + completeness["attempts_omitted"]
            ):
                errors.append("session attempt count conservation failed")
            if completeness["branch_count"] != (
                sum(item["branch_count"] for item in produced["session_attempts"])
                + completeness["branches_omitted"]
            ):
                errors.append("branch count conservation failed")
            if completeness["unbound_observation_count"] != (
                len(produced["unbound_observations"])
                + completeness["unbound_observations_omitted"]
            ):
                errors.append("unbound observation count conservation failed")
            if completeness["in_dialog_observation_count"] != (
                len(produced["in_dialog_observations"])
                + completeness["in_dialog_observations_omitted"]
            ):
                errors.append("in-dialog observation count conservation failed")
            for attempt in produced["session_attempts"]:
                if attempt["cancel_evidence"]["invite_transaction_termination_established"]:
                    errors.append("an attempt claims INVITE transaction termination")
                if attempt["release_evidence"]["outcome"] not in (
                    ims_session_model.RELEASE_OUTCOMES
                ):
                    errors.append("an attempt has an invalid release outcome")
            for observation in produced["in_dialog_observations"]:
                if observation["conclusion"] != "NOT_INTERPRETED":
                    errors.append("session modification was interpreted")

            second = directory / "second-analysis.json"
            rerun = run(
                [
                    sys.executable,
                    str(CLI),
                    "--sip-events",
                    str(INPUTS / "session-cases-events.jsonl"),
                    "--sip-transactions",
                    str(INPUTS / "session-cases-transactions.json"),
                    "--sip-dialogs",
                    str(INPUTS / "session-cases-dialogs.json"),
                    "--output",
                    str(second),
                    "--force",
                ]
            )
            if rerun.returncode != 0:
                errors.append(f"deterministic rerun failed: {rerun.stderr.strip()}")
            elif second.read_bytes() != output.read_bytes():
                errors.append("analysis is not deterministic")

            missing = directory / "missing.json"
            missing.write_text('{"analysis_name": "other"}', encoding="utf-8")
            missing_output = directory / "missing-output.json"
            missing_run = run(
                [
                    sys.executable,
                    str(CLI),
                    "--sip-events",
                    str(INPUTS / "session-cases-events.jsonl"),
                    "--sip-transactions",
                    str(missing),
                    "--sip-dialogs",
                    str(INPUTS / "session-cases-dialogs.json"),
                    "--output",
                    str(missing_output),
                    "--force",
                ]
            )
            if missing_run.returncode == 0:
                errors.append("an invalid transaction artifact was accepted")

            collision = run(
                [
                    sys.executable,
                    str(CLI),
                    "--sip-events",
                    str(INPUTS / "session-cases-events.jsonl"),
                    "--sip-transactions",
                    str(INPUTS / "session-cases-transactions.json"),
                    "--sip-dialogs",
                    str(INPUTS / "session-cases-dialogs.json"),
                    "--output",
                    str(INPUTS / "session-cases-events.jsonl"),
                    "--force",
                ]
            )
            if collision.returncode == 0:
                errors.append("an output destination colliding with an input was accepted")

    if errors:
        for error in errors:
            print(f"validate-ims-session: {error}", file=sys.stderr)
        return 1
    print("ims-session validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())