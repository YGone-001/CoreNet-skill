#!/usr/bin/env python3
"""Validate the standalone ims-media-session Domain Skill contract."""

from __future__ import annotations

import json
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "domain" / "ims-media-session"
SCRIPTS = SKILL / "scripts"
INPUTS = SKILL / "examples" / "inputs"
EXPECTED = SKILL / "examples" / "expected"
CLI = SCRIPTS / "analyze-ims-media-session.py"
SCHEMA = SKILL / "schemas" / "ims-media-session-analysis.schema.json"
sys.path.insert(0, str(SCRIPTS))
import ims_media_session_model as model  # noqa: E402

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/evidence-model.md",
    "references/media-session-evidence.md",
    "references/failure-cases.md",
    "references/privacy.md",
    "schemas/ims-media-session-analysis.schema.json",
    "scripts/ims_media_session_model.py",
    "scripts/analyze-ims-media-session.py",
    "tests/test_ims_media_session.py",
    "tests/media_session_fixture_builder.py",
    "examples/inputs/ims-session.json",
    "examples/inputs/ims-media-signaling.json",
    "examples/inputs/sdp-analysis.json",
    "examples/inputs/transport-correlation.json",
    "examples/expected/ims-media-session-analysis.json",
    "examples/expected/ims-media-session-report.txt",
)
REQUIRED_TESTS = tuple(f"test_{index:02d}_" for index in range(1, 91))
PRIVATE_TOKENS = (
    "192.0.2.10",
    "192.0.2.21",
    "192.0.2.22",
    "2001:db8",
    "49170",
    "49200",
    "source_address",
    "destination_address",
    "source_port",
    "destination_port",
    "sip:caller",
    "sip:callee",
    "v=0",
    "m=audio",
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _cli(inputs: Path, output: Path, report: Path | None = None) -> subprocess.CompletedProcess:
    command = [
        sys.executable,
        str(CLI),
        "--ims-session-analysis",
        str(inputs / "ims-session.json"),
        "--ims-media-signaling-analysis",
        str(inputs / "ims-media-signaling.json"),
        "--sdp-analysis",
        str(inputs / "sdp-analysis.json"),
        "--transport-correlation",
        str(inputs / "transport-correlation.json"),
        "--output",
        str(output),
        "--force",
    ]
    if report is not None:
        command.extend(["--report", str(report)])
    return run(command)


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
            print(f"validate-ims-media-session: {error}", file=sys.stderr)
        return 1

    try:
        import jsonschema
    except ImportError:
        print("validate-ims-media-session: jsonschema is required", file=sys.stderr)
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
        "attempt_count",
        "attempts",
        "exchange_count",
        "exchanges",
        "transport_observation_count",
        "transport_observations",
        "unbound_signaling_observation_count",
        "unbound_signaling_observations",
        "unmatched_rtp_stream_count",
        "unmatched_rtp_streams",
        "completeness",
        "limitations",
        "not_confirmed",
    ):
        if required not in schema.get("required", []):
            errors.append(f"schema is missing required property: {required}")
    if schema["properties"]["analysis_version"].get("const") != model.ANALYSIS_VERSION:
        errors.append("schema analysis_version diverges from the model")
    provenance = schema["$defs"]["input_provenance"]["properties"]
    for key, expected in (
        ("ims_session_analysis_version", model.IMS_SESSION_ANALYSIS_VERSION),
        ("ims_media_signaling_analysis_version", model.IMS_MEDIA_SIGNALING_ANALYSIS_VERSION),
        ("sdp_analysis_version", model.SDP_ANALYSIS_VERSION),
        ("sdp_event_schema_version", model.SDP_EVENT_SCHEMA_VERSION),
        ("transport_correlation_analysis_version", model.TRANSPORT_CORRELATION_ANALYSIS_VERSION),
    ):
        if provenance[key].get("const") != expected:
            errors.append(f"schema {key} diverges from the accepted upstream version")
    for definition in (
        "input_provenance",
        "attempt",
        "branch",
        "exchange",
        "transport_observation",
        "sdp_binding",
        "unbound_signaling_observation",
        "unmatched_stream",
        "completeness",
    ):
        if schema["$defs"][definition].get("additionalProperties") is not False:
            errors.append(f"schema definition {definition} is not strict")

    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for token in (
        "name: ims-media-session",
        "version: 0.1.0",
        "category: domain",
        "ims-session >=0.1.0",
        "ims-media-signaling >=0.3.0",
        "sdp-rtp >=0.4.0",
        "sdp-rtp-transport >=0.1.0",
        "schemas/ims-media-session-analysis.schema.json",
        "scripts/analyze-ims-media-session.py",
    ):
        if token not in manifest:
            errors.append(f"manifest missing {token}")

    test_source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((SKILL / "tests").glob("test_*.py"))
    )
    for token in REQUIRED_TESTS:
        if token not in test_source:
            errors.append(f"test suite is missing required coverage: {token}")

    sdp_path = INPUTS / "sdp-analysis.json"
    session_path = INPUTS / "ims-session.json"
    media_path = INPUTS / "ims-media-signaling.json"
    correlation_path = INPUTS / "transport-correlation.json"
    sdp = model.load_sdp(sdp_path)
    session = model.load_session(session_path)
    media = model.load_media_signaling(
        media_path, {message["source_reference"] for message in sdp["messages"]}
    )
    correlation = model.load_correlation(correlation_path)
    provenance = model.verify_provenance(
        session,
        media,
        sdp,
        correlation,
        session_path=session_path,
        media_path=media_path,
        sdp_path=sdp_path,
        correlation_path=correlation_path,
    )
    document = model.build_analysis(
        session, media, sdp, correlation, provenance=provenance
    )
    try:
        jsonschema.validate(document, schema)
        model.validate_analysis(document)
    except (jsonschema.ValidationError, model.InputError) as exc:
        errors.append(f"in-process schema or semantic validation failed: {exc}")

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        output = directory / "analysis.json"
        report = directory / "report.txt"
        completed = _cli(INPUTS, output, report)
        if completed.returncode != 0:
            errors.append(f"producer failed: {completed.stderr.strip()}")
        else:
            if output.read_bytes() != (EXPECTED / "ims-media-session-analysis.json").read_bytes():
                errors.append("analysis output differs from the committed expectation")
            if report.read_bytes() != (EXPECTED / "ims-media-session-report.txt").read_bytes():
                errors.append("text report differs from the committed expectation")
            produced = load_json(output)
            try:
                jsonschema.validate(produced, schema)
                model.validate_analysis(produced)
            except (jsonschema.ValidationError, model.InputError) as exc:
                errors.append(f"schema or semantic validation failed: {exc}")
            text = json.dumps(produced) + report.read_text(encoding="utf-8")
            for token in PRIVATE_TOKENS:
                if token in text:
                    errors.append(f"output leaked a private value: {token}")
            for field in ('"call_id"', '"from_tag"', '"to_tag"', '"sdp_body"', '"hmac_key"'):
                if field in text:
                    errors.append(f"output publishes a raw field: {field}")
            completeness = produced["completeness"]
            if (
                completeness["attempt_bound_observation_count"]
                + completeness["branch_bound_observation_count"]
                + completeness["ambiguous_observation_count"]
                + completeness["unbound_observation_count"]
            ) != produced["transport_observation_count"]:
                errors.append("transport observation scope count conservation failed")
            if (
                completeness["established_exchange_count"]
                + completeness["non_established_exchange_count"]
            ) != completeness["signaling_exchange_count"]:
                errors.append("exchange count conservation failed")

            second = directory / "second.json"
            rerun = _cli(INPUTS, second)
            if rerun.returncode != 0:
                errors.append(f"deterministic rerun failed: {rerun.stderr.strip()}")
            elif second.read_bytes() != output.read_bytes():
                errors.append("analysis is not deterministic")

            bad_media = load_json(media_path)
            bad_media["analysis_version"] = "9.9.9"
            bad_media_path = directory / "bad-media.json"
            bad_media_path.write_text(json.dumps(bad_media), encoding="utf-8")
            invalid = run(
                [
                    sys.executable,
                    str(CLI),
                    "--ims-session-analysis",
                    str(session_path),
                    "--ims-media-signaling-analysis",
                    str(bad_media_path),
                    "--sdp-analysis",
                    str(sdp_path),
                    "--transport-correlation",
                    str(correlation_path),
                    "--output",
                    str(directory / "invalid-out.json"),
                    "--force",
                ]
            )
            if invalid.returncode == 0:
                errors.append("an invalid IMS Media Signaling artifact was accepted")

            collision = run(
                [
                    sys.executable,
                    str(CLI),
                    "--ims-session-analysis",
                    str(session_path),
                    "--ims-media-signaling-analysis",
                    str(media_path),
                    "--sdp-analysis",
                    str(sdp_path),
                    "--transport-correlation",
                    str(correlation_path),
                    "--output",
                    str(session_path),
                    "--force",
                ]
            )
            if collision.returncode == 0:
                errors.append("an output colliding with an input was accepted")

    if errors:
        for error in errors:
            print(f"validate-ims-media-session: {error}", file=sys.stderr)
        return 1
    print("ims-media-session validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())