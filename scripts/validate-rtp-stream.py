#!/usr/bin/env python3
"""Validate the rtp-stream Protocol Skill contract and artifacts."""

from __future__ import annotations

import json
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "protocol" / "rtp-stream"
SCRIPTS = SKILL / "scripts"
CLI = SCRIPTS / "reconstruct-rtp-streams.py"
SCHEMA = SKILL / "schemas" / "rtp-stream-analysis.schema.json"
INPUT = SKILL / "examples" / "inputs" / "rtp-rtcp-analysis.json"
EXPECTED = SKILL / "examples" / "expected"
sys.path.insert(0, str(SCRIPTS))
import rtp_stream_model  # noqa: E402

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/stream-identity.md",
    "references/sequence-validation.md",
    "references/failure-cases.md",
    "references/privacy.md",
    "schemas/rtp-stream-analysis.schema.json",
    "scripts/rtp_stream_model.py",
    "scripts/reconstruct-rtp-streams.py",
    "tests/test_rtp_stream.py",
    "tests/rtp_stream_fixture_builder.py",
    "examples/inputs/rtp-rtcp-analysis.json",
    "examples/expected/rtp-stream-analysis.json",
    "examples/expected/rtp-stream-report.txt",
)
REQUIRED_TESTS = tuple(f"test_{index:02d}_" for index in range(1, 85))
PRIVATE_TOKENS = (
    "10.0.0.",
    "192.168.",
    "172.16.",
    "source_address",
    "destination_address",
    "source_port",
    "destination_port",
    "rtp.payload",
    "udp.payload",
    "hmac_key",
    "endpoint_key",
    "srtp.auth_tag",
    "call_id",
    "sip_uri",
    "imsi",
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
            print(f"validate-rtp-stream: {error}", file=sys.stderr)
        return 1

    try:
        import jsonschema
    except ImportError:
        print("validate-rtp-stream: jsonschema is required", file=sys.stderr)
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
        "source_stream_count",
        "source_streams",
        "unassigned_packet_count",
        "unassigned_packets",
        "rtcp_event_count",
        "rtcp_observation_status",
        "completeness",
        "limitations",
        "not_confirmed",
    ):
        if required not in schema.get("required", []):
            errors.append(f"schema missing required property: {required}")
    if schema["properties"]["analysis_name"].get("const") != rtp_stream_model.ANALYSIS_NAME:
        errors.append("schema analysis_name diverges from the model")
    if schema["properties"]["analysis_version"].get("const") != rtp_stream_model.ANALYSIS_VERSION:
        errors.append("schema analysis_version diverges from the model")
    if schema["properties"]["event_schema_version"].get("const") != rtp_stream_model.EVENT_SCHEMA_VERSION:
        errors.append("schema event_schema_version diverges from the model")
    for definition in (
        "input_provenance",
        "sequence_epoch",
        "sequence_gap",
        "restart_pattern",
        "source_stream",
        "unassigned_packet",
        "completeness",
    ):
        if schema["$defs"][definition].get("additionalProperties") is not False:
            errors.append(f"schema definition {definition} is not strict")

    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for token in (
        "name: rtp-stream",
        "version: 0.1.0",
        "category: protocol",
        "RFC 3550 Appendix A.1",
        "RTP_SEQ_MOD",
        "MIN_SEQUENTIAL",
        "MAX_DROPOUT",
        "MAX_MISORDER",
        "sdp-rtp >=0.4.0",
        "schemas/rtp-stream-analysis.schema.json",
        "scripts/reconstruct-rtp-streams.py",
    ):
        if token not in manifest:
            errors.append(f"manifest missing {token}")

    test_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((SKILL / "tests").glob("test_*.py"))
    )
    for token in REQUIRED_TESTS:
        if token not in test_source:
            errors.append(f"test suite missing required coverage: {token}")

    document, provenance, _ = rtp_stream_model.load_rtp_rtcp_analysis(INPUT)
    output = rtp_stream_model.build_analysis(document, provenance=provenance)
    try:
        jsonschema.validate(output, schema)
        rtp_stream_model.validate_analysis(output)
    except (jsonschema.ValidationError, rtp_stream_model.InputError) as exc:
        errors.append(f"in-process schema or semantic validation failed: {exc}")

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        produced = directory / "analysis.json"
        report = directory / "report.txt"
        completed = run(
            [
                sys.executable,
                str(CLI),
                "--rtp-rtcp-analysis",
                str(INPUT),
                "--output",
                str(produced),
                "--report",
                str(report),
                "--force",
            ]
        )
        if completed.returncode != 0:
            errors.append(f"producer failed: {completed.stderr.strip()}")
        else:
            if produced.read_bytes() != (EXPECTED / "rtp-stream-analysis.json").read_bytes():
                errors.append("analysis output differs from the committed expectation")
            if report.read_bytes() != (EXPECTED / "rtp-stream-report.txt").read_bytes():
                errors.append("text report differs from the committed expectation")
            published = load_json(produced)
            try:
                jsonschema.validate(published, schema)
                rtp_stream_model.validate_analysis(published)
            except (jsonschema.ValidationError, rtp_stream_model.InputError) as exc:
                errors.append(f"schema or semantic validation failed: {exc}")
            text = json.dumps(published) + report.read_text(encoding="utf-8")
            for token in PRIVATE_TOKENS:
                if token in text:
                    errors.append(f"output leaked protected data: {token}")
            completeness = published["completeness"]
            if (
                completeness["total_input_rtp_packet_count"]
                != completeness["assigned_rtp_packet_count"]
                + completeness["unassigned_rtp_packet_count"]
            ):
                errors.append("RTP input packet conservation failed")
            if (
                completeness["source_stream_count"]
                != completeness["sequence_validated_stream_count"]
                + completeness["probation_stream_count"]
                + completeness["ambiguous_stream_count"]
                + completeness["incomplete_stream_count"]
            ):
                errors.append("source-stream status conservation failed")
            if completeness["rtcp_event_count"] != published["rtcp_event_count"]:
                errors.append("RTCP event count conservation failed")
            if [path.name for path in directory.glob(".*.tmp")]:
                errors.append("temporary output file was not cleaned up")

            second = directory / "second.json"
            rerun = run(
                [
                    sys.executable,
                    str(CLI),
                    "--rtp-rtcp-analysis",
                    str(INPUT),
                    "--output",
                    str(second),
                    "--force",
                ]
            )
            if rerun.returncode != 0:
                errors.append(f"deterministic rerun failed: {rerun.stderr.strip()}")
            elif second.read_bytes() != produced.read_bytes():
                errors.append("analysis output is not deterministic")

            collision = run(
                [
                    sys.executable,
                    str(CLI),
                    "--rtp-rtcp-analysis",
                    str(INPUT),
                    "--output",
                    str(INPUT),
                    "--force",
                ]
            )
            if collision.returncode == 0:
                errors.append("an output collision with the input was accepted")

            malformed = directory / "malformed.json"
            malformed.write_text('{"analysis_name": ', encoding="utf-8")
            rejected = run(
                [
                    sys.executable,
                    str(CLI),
                    "--rtp-rtcp-analysis",
                    str(malformed),
                    "--output",
                    str(directory / "malformed-out.json"),
                ]
            )
            if rejected.returncode != 2:
                errors.append("malformed input did not return the documented exit code 2")

    if errors:
        for error in errors:
            print(f"validate-rtp-stream: {error}", file=sys.stderr)
        return 1
    print("rtp-stream validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())