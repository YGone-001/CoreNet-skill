#!/usr/bin/env python3
"""Validate the standalone sdp-rtp Protocol Skill contract."""

from __future__ import annotations

import json
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "protocol" / "sdp-rtp"
SCRIPTS = SKILL / "scripts"
INPUTS = SKILL / "examples" / "inputs" / "sdp-cases.jsonl"
EXPECTED = SKILL / "examples" / "expected"
CLI = SCRIPTS / "parse-sdp.py"
SCHEMA = SKILL / "schemas" / "sdp-events.schema.json"
sys.path.insert(0, str(SCRIPTS))
import sdp_model  # noqa: E402

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/field-reference.md",
    "references/failure-cases.md",
    "references/privacy.md",
    "schemas/sdp-events.schema.json",
    "scripts/parse-sdp.py",
    "scripts/sdp_model.py",
    "tests/test_sdp.py",
    "tests/sdp_fixture_builder.py",
    "tests/test_rtp_rtcp.py",
    "tests/rtp_rtcp_fixture_builder.py",
    "schemas/rtp-rtcp-events.schema.json",
    "scripts/rtp_rtcp_model.py",
    "scripts/extract-rtp-rtcp.py",
    "examples/inputs/sdp-cases.jsonl",
    "examples/inputs/rtp-rtcp-cases.jsonl",
    "examples/expected/sdp-analysis.json",
    "examples/expected/sdp-report.txt",
    "examples/expected/rtp-rtcp-analysis.json",
    "examples/expected/rtp-rtcp-report.txt",
)
REQUIRED_TESTS = tuple(f"test_{index:02d}_" for index in range(1, 25)) + tuple(
    f"test_{index:02d}_" for index in range(1, 52)
) + tuple(f"test_{index:02d}_" for index in range(52, 84))
PRIVATE_TOKENS = (
    "private-user",
    "private-ufrag-value",
    "private-password-value",
    "private-key-material",
    "AA:BB:CC:DD",
    "203.0.113.10",
    "10.0.0.1",
    "2001:db8::10",
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def main() -> int:
    errors: list[str] = []
    for relative in REQUIRED:
        if not (SKILL / relative).is_file():
            errors.append(f"missing required file: {relative}")
    with tempfile.TemporaryDirectory() as compile_dir:
        for script in SCRIPTS.glob("*.py"):
            try:
                py_compile.compile(
                    str(script),
                    cfile=str(Path(compile_dir) / f"{script.stem}.pyc"),
                    doraise=True,
                )
            except py_compile.PyCompileError as exc:
                errors.append(f"compile failure {script.name}: {exc}")
    if errors:
        for error in errors:
            print(f"validate-sdp-rtp: {error}", file=sys.stderr)
        return 1

    try:
        import jsonschema
    except ImportError:
        print("validate-sdp-rtp: jsonschema is required", file=sys.stderr)
        return 1

    schema = load_json(SCHEMA)
    if schema.get("additionalProperties") is not False:
        errors.append("schema must set additionalProperties: false")
    for required in (
        "analysis_name",
        "analysis_version",
        "event_schema_version",
        "capability",
        "input_provenance",
        "message_count",
        "messages",
        "completeness",
        "limitations",
        "not_confirmed",
    ):
        if required not in schema.get("required", []):
            errors.append(f"schema is missing required property: {required}")
    if schema["properties"]["analysis_version"].get("const") != sdp_model.ANALYSIS_VERSION:
        errors.append("schema analysis_version diverges from the model")
    for definition in ("input_provenance", "message", "session", "media", "completeness"):
        if schema["$defs"][definition].get("additionalProperties") is not False:
            errors.append(f"schema definition {definition} is not strict")

    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for token in (
        "name: sdp-rtp",
        "version: 0.3.0",
        "RTP version 2 packet evidence",
        "RFC 3550",
        "category: protocol",
        "RFC 8866",
    ):
        if token not in manifest:
            errors.append(f"manifest missing {token}")

    if "RTP packet extraction" in manifest:
        errors.append("manifest contradicts implemented RTP capability by excluding RTP packet extraction")

    test_source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((SKILL / "tests").glob("test_*.py"))
    )
    for token in REQUIRED_TESTS:
        if token not in test_source:
            errors.append(f"test suite is missing required coverage: {token}")

    records = sdp_model.load_messages(INPUTS)
    document = sdp_model.build_analysis(records, input_name=INPUTS.name)
    try:
        jsonschema.validate(document, schema)
        sdp_model.validate_analysis(document)
    except (jsonschema.ValidationError, sdp_model.InputError) as exc:
        errors.append(f"in-process schema or semantic validation failed: {exc}")

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        output = directory / "analysis.json"
        report = directory / "report.txt"
        completed = run(
            [
                sys.executable,
                str(CLI),
                "--input",
                str(INPUTS),
                "--output",
                str(output),
                "--report",
                str(report),
                "--force",
            ]
        )
        if completed.returncode != 0:
            errors.append(f"producer failed: {completed.stderr.strip()}")
        else:
            if output.read_bytes() != (EXPECTED / "sdp-analysis.json").read_bytes():
                errors.append("analysis output differs from the committed expectation")
            if report.read_bytes() != (EXPECTED / "sdp-report.txt").read_bytes():
                errors.append("text report differs from the committed expectation")
            produced = load_json(output)
            try:
                jsonschema.validate(produced, schema)
                sdp_model.validate_analysis(produced)
            except (jsonschema.ValidationError, sdp_model.InputError) as exc:
                errors.append(f"schema or semantic validation failed: {exc}")
            text = json.dumps(produced) + report.read_text(encoding="utf-8")
            for token in PRIVATE_TOKENS:
                if token in text:
                    errors.append(f"output leaked a private value: {token}")
            for field in ('"sdp_body"', '"raw_sdp"', '"call_id"', '"sip_uri"'):
                if field in text:
                    errors.append(f"output publishes a raw field: {field}")
            completeness = produced["completeness"]
            if completeness["supplied_message_count"] != (
                completeness["published_message_count"] + completeness["messages_omitted"]
            ):
                errors.append("message count conservation failed")
            if sum(
                completeness[key]
                for key in (
                    "observed_message_count",
                    "incomplete_message_count",
                    "ambiguous_message_count",
                    "unsupported_message_count",
                    "invalid_message_count",
                )
            ) != completeness["published_message_count"]:
                errors.append("message status counts do not sum to published messages")

            second = directory / "second.json"
            rerun = run(
                [
                    sys.executable,
                    str(CLI),
                    "--input",
                    str(INPUTS),
                    "--output",
                    str(second),
                    "--force",
                ]
            )
            if rerun.returncode != 0:
                errors.append(f"deterministic rerun failed: {rerun.stderr.strip()}")
            elif second.read_bytes() != output.read_bytes():
                errors.append("analysis is not deterministic")

            mismatch_records = records[:2]
            mismatch_records[1]["capture_file"] = "other.pcapng"
            mismatch_records[1]["source_reference"] = "sip-body:other.pcapng:2.1"
            mismatch_input = directory / "mismatch.jsonl"
            mismatch_input.write_text(
                "\n".join(json.dumps(record) for record in mismatch_records) + "\n",
                encoding="utf-8",
            )
            mismatch = run(
                [
                    sys.executable,
                    str(CLI),
                    "--input",
                    str(mismatch_input),
                    "--output",
                    str(directory / "mismatch-out.json"),
                    "--force",
                ]
            )
            if mismatch.returncode == 0:
                errors.append("a mixed-capture provenance input was accepted")

            collision = run(
                [
                    sys.executable,
                    str(CLI),
                    "--input",
                    str(INPUTS),
                    "--output",
                    str(INPUTS),
                    "--force",
                ]
            )
            if collision.returncode == 0:
                errors.append("an output destination colliding with the input was accepted")

    if errors:
        for error in errors:
            print(f"validate-sdp-rtp: {error}", file=sys.stderr)
        return 1
    print("sdp-rtp validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())