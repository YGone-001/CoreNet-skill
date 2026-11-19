#!/usr/bin/env python3
"""Validate the bounded RTP/RTCP extension of the sdp-rtp Protocol Skill."""

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
CLI = SCRIPTS / "extract-rtp-rtcp.py"
SCHEMA = SKILL / "schemas" / "rtp-rtcp-events.schema.json"
INPUTS = SKILL / "examples" / "inputs" / "rtp-rtcp-cases.jsonl"
EXPECTED = SKILL / "examples" / "expected"
sys.path.insert(0, str(SCRIPTS))
import rtp_rtcp_model  # noqa: E402

REQUIRED = (
    "references/field-reference.md",
    "references/privacy.md",
    "references/failure-cases.md",
    "schemas/rtp-rtcp-events.schema.json",
    "scripts/rtp_rtcp_model.py",
    "scripts/extract-rtp-rtcp.py",
    "tests/test_rtp_rtcp.py",
    "tests/rtp_rtcp_fixture_builder.py",
    "examples/inputs/rtp-rtcp-cases.jsonl",
    "examples/expected/rtp-rtcp-analysis.json",
    "examples/expected/rtp-rtcp-report.txt",
)
REQUIRED_TESTS = tuple(f"test_{index:02d}_" for index in range(1, 52))
PRIVATE_TOKENS = (
    "SECRET-PAYLOAD-BYTES",
    "SECRET-EXTENSION-DATA",
    "SECRET-APP-DATA",
    "secret-sdes-text",
    "secret-bye-reason",
    "udp.payload",
    "rtp.payload",
    "srtp.auth_tag",
    "srtp.mki",
)


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


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
            print(f"validate-rtp-rtcp: {error}", file=sys.stderr)
        return 1

    try:
        import jsonschema
    except ImportError:
        print("validate-rtp-rtcp: jsonschema is required", file=sys.stderr)
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
        "event_count",
        "events",
        "completeness",
        "limitations",
        "not_confirmed",
    ):
        if required not in schema.get("required", []):
            errors.append(f"schema missing required property: {required}")
    if schema["properties"]["analysis_version"].get("const") != rtp_rtcp_model.ANALYSIS_VERSION:
        errors.append("schema analysis_version diverges from the model")
    for definition in ("input_provenance", "rtp_event", "rtcp_event", "completeness"):
        if schema["$defs"][definition].get("additionalProperties") is not False:
            errors.append(f"schema definition {definition} is not strict")

    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for token in ("name: sdp-rtp", "version: 0.2.0", "category: protocol", "RFC 3550"):
        if token not in manifest:
            errors.append(f"manifest missing {token}")

    test_source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((SKILL / "tests").glob("test_*.py"))
    )
    for token in REQUIRED_TESTS:
        if token not in test_source:
            errors.append(f"test suite missing required coverage: {token}")

    records = rtp_rtcp_model.load_structured_messages(INPUTS)
    events, provenance = rtp_rtcp_model.extract_structured(INPUTS)
    document = rtp_rtcp_model.build_analysis(events, provenance)
    try:
        jsonschema.validate(document, schema)
        rtp_rtcp_model.validate_analysis(document)
    except (jsonschema.ValidationError, rtp_rtcp_model.InputError) as exc:
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
                "--input-format",
                "jsonl",
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
            if output.read_bytes() != (EXPECTED / "rtp-rtcp-analysis.json").read_bytes():
                errors.append("event output differs from the committed expectation")
            if report.read_bytes() != (EXPECTED / "rtp-rtcp-report.txt").read_bytes():
                errors.append("text report differs from the committed expectation")
            produced = load_json(output)
            try:
                jsonschema.validate(produced, schema)
                rtp_rtcp_model.validate_analysis(produced)
            except (jsonschema.ValidationError, rtp_rtcp_model.InputError) as exc:
                errors.append(f"schema or semantic validation failed: {exc}")
            text = json.dumps(produced) + report.read_text(encoding="utf-8")
            for token in PRIVATE_TOKENS:
                if token in text:
                    errors.append(f"output leaked protected data: {token}")
            completeness = produced["completeness"]
            if sum(
                completeness[key]
                for key in (
                    "observed_event_count",
                    "incomplete_event_count",
                    "ambiguous_event_count",
                    "unsupported_event_count",
                    "invalid_event_count",
                )
            ) != completeness["rtp_packet_count"] + completeness["rtcp_component_count"]:
                errors.append("event status count conservation failed")

            second = directory / "second.json"
            rerun = run(
                [
                    sys.executable,
                    str(CLI),
                    "--input",
                    str(INPUTS),
                    "--input-format",
                    "jsonl",
                    "--output",
                    str(second),
                    "--force",
                ]
            )
            if rerun.returncode != 0:
                errors.append(f"deterministic rerun failed: {rerun.stderr.strip()}")
            elif second.read_bytes() != output.read_bytes():
                errors.append("event output is not deterministic")

            mixed = records[:2]
            mixed[1]["capture_file"] = "other.pcapng"
            mixed[1]["source_reference"] = "rtp-packet:other.pcapng:2.1"
            mixed_input = directory / "mixed.jsonl"
            mixed_input.write_text(
                "\n".join(json.dumps(record) for record in mixed) + "\n", encoding="utf-8"
            )
            mixed_run = run(
                [
                    sys.executable,
                    str(CLI),
                    "--input",
                    str(mixed_input),
                    "--input-format",
                    "jsonl",
                    "--output",
                    str(directory / "mixed-out.json"),
                    "--force",
                ]
            )
            if mixed_run.returncode == 0:
                errors.append("mixed capture provenance was accepted")

            collision = run(
                [
                    sys.executable,
                    str(CLI),
                    "--input",
                    str(INPUTS),
                    "--input-format",
                    "jsonl",
                    "--output",
                    str(INPUTS),
                    "--force",
                ]
            )
            if collision.returncode == 0:
                errors.append("an output collision with the input was accepted")

    if errors:
        for error in errors:
            print(f"validate-rtp-rtcp: {error}", file=sys.stderr)
        return 1
    print("rtp-rtcp validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())