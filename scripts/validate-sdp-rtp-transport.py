#!/usr/bin/env python3
"""Validate the standalone sdp-rtp-transport Correlation Skill contract."""

from __future__ import annotations

import json
import os
import py_compile
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "correlation" / "sdp-rtp-transport"
SCRIPTS = SKILL / "scripts"
INPUTS = SKILL / "examples" / "inputs"
EXPECTED = SKILL / "examples" / "expected"
CLI = SCRIPTS / "correlate-sdp-rtp-transport.py"
KEY_CLI = SCRIPTS / "create-endpoint-key.py"
SCHEMA = SKILL / "schemas" / "sdp-rtp-transport-correlation.schema.json"
SDP_SKILL = ROOT / "skills" / "protocol" / "sdp-rtp"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SDP_SKILL / "scripts"))
import rtp_rtcp_model  # noqa: E402
import sdp_model  # noqa: E402
import sdp_rtp_transport_model  # noqa: E402

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/endpoint-privacy.md",
    "references/correlation-model.md",
    "references/failure-cases.md",
    "schemas/sdp-rtp-transport-correlation.schema.json",
    "scripts/correlate-sdp-rtp-transport.py",
    "scripts/create-endpoint-key.py",
    "scripts/sdp_rtp_transport_model.py",
    "tests/test_sdp_rtp_transport.py",
    "tests/transport_fixture_builder.py",
    "examples/inputs/transport-sdp-analysis.json",
    "examples/inputs/transport-rtp-rtcp-analysis.json",
    "examples/expected/transport-correlation.json",
    "examples/expected/transport-correlation.txt",
)
REQUIRED_TESTS = tuple(f"test_{index:02d}_" for index in range(1, 35))
PRIVATE_TOKENS = (
    "192.0.2.10",
    "192.0.2.20",
    "192.0.2.30",
    "192.0.2.40",
    "192.0.2.60",
    "2001:db8::10",
    "source_address",
    "destination_address",
    "source_port",
    "destination_port",
    "hmac_key",
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
            print(f"validate-sdp-rtp-transport: {error}", file=sys.stderr)
        return 1

    try:
        import jsonschema
    except ImportError:
        print("validate-sdp-rtp-transport: jsonschema is required", file=sys.stderr)
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
        "correlation_count",
        "correlations",
        "unmatched_stream_count",
        "unmatched_streams",
        "completeness",
        "limitations",
        "not_confirmed",
    ):
        if required not in schema.get("required", []):
            errors.append(f"schema missing required property: {required}")
    if schema["properties"]["analysis_version"].get("const") != sdp_rtp_transport_model.ANALYSIS_VERSION:
        errors.append("schema analysis_version diverges from the model")
    provenance_schema = schema["$defs"]["input_provenance"]["properties"]
    if provenance_schema["sdp_analysis_version"].get("const") != sdp_model.ANALYSIS_VERSION:
        errors.append("schema SDP analysis version diverges from the Protocol Skill")
    if provenance_schema["sdp_event_schema_version"].get("const") != sdp_model.EVENT_SCHEMA_VERSION:
        errors.append("schema SDP event schema version diverges from the Protocol Skill")
    if provenance_schema["rtp_rtcp_analysis_version"].get("const") != rtp_rtcp_model.ANALYSIS_VERSION:
        errors.append("schema RTP analysis version diverges from the Protocol Skill")
    if provenance_schema["rtp_rtcp_event_schema_version"].get("const") != rtp_rtcp_model.EVENT_SCHEMA_VERSION:
        errors.append("schema RTP event schema version diverges from the Protocol Skill")
    for definition in ("input_provenance", "correlation", "media_section", "unmatched_stream", "completeness"):
        if schema["$defs"][definition].get("additionalProperties") is not False:
            errors.append(f"schema definition {definition} is not strict")

    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for token in (
        "name: sdp-rtp-transport",
        "version: 0.1.0",
        "category: correlation",
        "sdp-rtp >=0.4.0",
        "schemas/sdp-rtp-transport-correlation.schema.json",
        "scripts/correlate-sdp-rtp-transport.py",
        "scripts/create-endpoint-key.py",
    ):
        if token not in manifest:
            errors.append(f"manifest missing {token}")

    test_source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((SKILL / "tests").glob("test_*.py"))
    )
    for token in REQUIRED_TESTS:
        if token not in test_source:
            errors.append(f"test suite is missing required coverage: {token}")

    sdp_path = INPUTS / "transport-sdp-analysis.json"
    rtp_path = INPUTS / "transport-rtp-rtcp-analysis.json"
    sdp = sdp_rtp_transport_model.load_sdp_analysis(sdp_path)
    rtp = sdp_rtp_transport_model.load_rtp_analysis(rtp_path)
    provenance = sdp_rtp_transport_model.verify_provenance(
        sdp, rtp, sdp_path=sdp_path, rtp_path=rtp_path
    )
    document = sdp_rtp_transport_model.build_analysis(sdp, rtp, provenance=provenance)
    try:
        jsonschema.validate(document, schema)
        sdp_rtp_transport_model.validate_analysis(document)
    except (jsonschema.ValidationError, sdp_rtp_transport_model.InputError) as exc:
        errors.append(f"in-process schema or semantic validation failed: {exc}")

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        output = directory / "correlation.json"
        report = directory / "correlation.txt"
        completed = run(
            [
                sys.executable,
                str(CLI),
                "--sdp-analysis",
                str(sdp_path),
                "--rtp-rtcp-analysis",
                str(rtp_path),
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
            if output.read_bytes() != (EXPECTED / "transport-correlation.json").read_bytes():
                errors.append("correlation output differs from the committed expectation")
            if report.read_bytes() != (EXPECTED / "transport-correlation.txt").read_bytes():
                errors.append("correlation report differs from the committed expectation")
            produced = load_json(output)
            try:
                jsonschema.validate(produced, schema)
                sdp_rtp_transport_model.validate_analysis(produced)
            except (jsonschema.ValidationError, sdp_rtp_transport_model.InputError) as exc:
                errors.append(f"schema or semantic validation failed: {exc}")
            text = json.dumps(produced) + report.read_text(encoding="utf-8")
            for token in PRIVATE_TOKENS:
                if token in text:
                    errors.append(f"output leaked a private endpoint value: {token}")
            if "hmac_key" in text or "endpoint_key" in text:
                errors.append("output published key material metadata")
            completeness = produced["completeness"]
            if (
                completeness["matched_correlation_count"]
                + completeness["bundle_matched_correlation_count"]
                + completeness["ambiguous_correlation_count"]
                + completeness["insufficient_correlation_count"]
                + completeness["unmatched_correlation_count"]
                + completeness["out_of_scope_correlation_count"]
            ) != completeness["correlation_count"]:
                errors.append("correlation status count conservation failed")
            if (
                completeness["sdp_media_with_endpoint_count"]
                + completeness["sdp_media_without_endpoint_count"]
            ) != completeness["sdp_media_section_count"]:
                errors.append("SDP media endpoint count conservation failed")

            second = directory / "second.json"
            rerun = run(
                [
                    sys.executable,
                    str(CLI),
                    "--sdp-analysis",
                    str(sdp_path),
                    "--rtp-rtcp-analysis",
                    str(rtp_path),
                    "--output",
                    str(second),
                    "--force",
                ]
            )
            if rerun.returncode != 0:
                errors.append(f"deterministic rerun failed: {rerun.stderr.strip()}")
            elif second.read_bytes() != output.read_bytes():
                errors.append("correlation output is not deterministic")

            mismatch_rtp = copy_with_capture(rtp, "other-capture.pcapng")
            mismatch_path = directory / "mismatch-rtp.json"
            mismatch_path.write_text(
                json.dumps(mismatch_rtp, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            mismatch = run(
                [
                    sys.executable,
                    str(CLI),
                    "--sdp-analysis",
                    str(sdp_path),
                    "--rtp-rtcp-analysis",
                    str(mismatch_path),
                    "--output",
                    str(directory / "mismatch-out.json"),
                    "--force",
                ]
            )
            if mismatch.returncode == 0:
                errors.append("a cross-capture correlation was accepted")

            key_destination = directory / "endpoint.key"
            key_run = run(
                [sys.executable, str(KEY_CLI), "--output", str(key_destination)]
            )
            if key_run.returncode != 0:
                errors.append(f"endpoint key generation failed: {key_run.stderr.strip()}")
            else:
                material = key_destination.read_bytes()
                if len(material) != 32:
                    errors.append("generated endpoint key is not 32 bytes")
                if os.name == "posix" and stat.S_IMODE(key_destination.stat().st_mode) != 0o600:
                    errors.append("generated endpoint key is not owner-only")
                if material.hex() in key_run.stdout + key_run.stderr:
                    errors.append("endpoint key generator printed key material")
                overwrite = run(
                    [sys.executable, str(KEY_CLI), "--output", str(key_destination)]
                )
                if overwrite.returncode == 0:
                    errors.append("endpoint key generator overwrote an existing key")

            repository_key = ROOT / "forbidden-endpoint.key"
            if not repository_key.exists():
                rejected = run(
                    [sys.executable, str(KEY_CLI), "--output", str(repository_key)]
                )
                if rejected.returncode == 0:
                    errors.append("endpoint key generator accepted a repository path")

            collision = run(
                [
                    sys.executable,
                    str(CLI),
                    "--sdp-analysis",
                    str(sdp_path),
                    "--rtp-rtcp-analysis",
                    str(rtp_path),
                    "--output",
                    str(sdp_path),
                    "--force",
                ]
            )
            if collision.returncode == 0:
                errors.append("an output colliding with an input was accepted")

    if errors:
        for error in errors:
            print(f"validate-sdp-rtp-transport: {error}", file=sys.stderr)
        return 1
    print("sdp-rtp-transport validation passed.")
    return 0


def copy_with_capture(document: dict, capture: str) -> dict:
    import copy

    result = copy.deepcopy(document)
    result["input_provenance"]["capture_files"] = [capture]
    for event in result["events"]:
        event["capture_file"] = capture
    return result


if __name__ == "__main__":
    raise SystemExit(main())