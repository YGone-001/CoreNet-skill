#!/usr/bin/env python3
"""Validate the standalone sip Protocol Skill contract."""

from __future__ import annotations

import json
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "protocol" / "sip"
SCRIPTS = SKILL / "scripts"
EXAMPLES = SKILL / "examples"
EXPECTED = EXAMPLES / "expected"
CLI = SCRIPTS / "extract-sip.py"
SCHEMA = SKILL / "schemas" / "sip-events.schema.json"
TRACE_SCHEMA = SKILL / "schemas" / "trace-event.schema.json"

sys.path.insert(0, str(SCRIPTS))
import sip_model  # noqa: E402

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/protocol-model.md",
    "references/field-reference.md",
    "references/privacy.md",
    "references/failure-cases.md",
    "scripts/sip_model.py",
    "scripts/extract-sip.py",
    "schemas/sip-events.schema.json",
    "schemas/trace-event.schema.json",
    "filters/wireshark.txt",
    "tests/test_sip.py",
    "examples/pdml/base-udp.pdml",
    "examples/pdml/tcp-reassembled.pdml",
    "examples/pdml/no-sip.pdml",
    "examples/pdml/malformed-sip.pdml",
    "examples/pdml/truncated-sip.pdml",
    "examples/pdml/multi-message-frame.pdml",
    "examples/dissector/message-cases.jsonl",
    "examples/dissector/transport-cases.jsonl",
    "examples/dissector/negative-cases.jsonl",
    "examples/dissector/privacy-cases.jsonl",
    "examples/expected/base-udp-events.jsonl",
    "examples/expected/base-udp-trace.jsonl",
    "examples/expected/tcp-reassembled-events.jsonl",
    "examples/expected/malformed-events.jsonl",
    "examples/expected/truncated-events.jsonl",
    "examples/expected/multi-message-events.jsonl",
    "examples/expected/message-cases-events.jsonl",
    "examples/expected/transport-cases-events.jsonl",
    "examples/expected/negative-cases-events.jsonl",
    "examples/expected/privacy-cases-events.jsonl",
)

GOLDEN_CASES = (
    ("examples/pdml/base-udp.pdml", "base-udp-events.jsonl"),
    ("examples/pdml/tcp-reassembled.pdml", "tcp-reassembled-events.jsonl"),
    ("examples/pdml/malformed-sip.pdml", "malformed-events.jsonl"),
    ("examples/pdml/truncated-sip.pdml", "truncated-events.jsonl"),
    ("examples/pdml/multi-message-frame.pdml", "multi-message-events.jsonl"),
    ("examples/dissector/message-cases.jsonl", "message-cases-events.jsonl"),
    ("examples/dissector/transport-cases.jsonl", "transport-cases-events.jsonl"),
    ("examples/dissector/negative-cases.jsonl", "negative-cases-events.jsonl"),
    ("examples/dissector/privacy-cases.jsonl", "privacy-cases-events.jsonl"),
)

PRIVACY_SECRETS = (
    "PRIVATE-USER-001",
    "PRIVATE-CALL-ID-001",
    "PRIVATE-BRANCH-001",
    "PRIVATE-FROM-TAG-001",
    "PRIVATE-TO-TAG-001",
    "PRIVATE-REASON-001",
    "secretuser",
    "callidsecret12345",
    "fromtagsecret",
    "totagsecret",
    "noncesecret",
    "digestresponse",
    "secretbody",
)

FORBIDDEN_OUTPUT_TOKENS = (
    "registration_success",
    "registration_failure",
    "call_success",
    "call_failure",
    "ims_registered",
    "transaction_status",
    "transaction_matched",
    "dialog_id",
    "root_cause",
    "rtp_stream",
    "sdp_body",
)

REQUIRED_TEST_TOKENS = (
    "test_register_request",
    "test_401_unauthorized_response",
    "test_407_proxy_authentication_required_response",
    "test_invite_request",
    "test_ack_request",
    "test_bye_request",
    "test_cancel_request",
    "test_options_request",
    "test_unknown_extension_method",
    "test_tcp_segmentation_and_reassembly",
    "test_ipv6_udp",
    "test_tls_without_decryption_is_unavailable",
    "test_invalid_capture_is_rejected",
    "test_missing_tshark_is_tool_unavailable",
    "test_tshark_execution_failure_is_decoder_failure",
    "test_no_identity_or_uri_in_base_events",
    "test_no_message_body_or_sdp",
    "test_expected_events_validate",
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


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
            print(f"validate-sip: {error}", file=sys.stderr)
        return 1

    try:
        import jsonschema
    except ImportError:
        print("validate-sip: jsonschema is required", file=sys.stderr)
        return 1

    schema = load_json(SCHEMA)
    if schema.get("additionalProperties") is not False:
        errors.append("event schema must set additionalProperties: false")
    for required in (
        "event_schema_version",
        "protocol",
        "capture_file",
        "frame_number",
        "frame_time_epoch",
        "source_reference",
        "message_type",
        "method",
        "status_code",
        "headers",
        "transport",
        "integrity_findings",
        "message_completeness",
        "extraction_status",
        "limitations",
    ):
        if required not in schema.get("required", []):
            errors.append(f"event schema is missing required property: {required}")
    if schema["properties"]["event_schema_version"].get("const") != sip_model.EVENT_SCHEMA_VERSION:
        errors.append("event schema version diverges from the model constant")
    if schema["properties"]["protocol"].get("const") != "SIP":
        errors.append("event schema protocol identity is not SIP")
    for definition in ("headers", "transport", "tag", "count_only"):
        if schema["$defs"][definition].get("additionalProperties") is not False:
            errors.append(f"event schema definition {definition} is not strict")
    if schema["$defs"]["transport"]["properties"].get("encrypted", {}).get("const") is not False:
        errors.append("event schema must forbid encrypted plaintext SIP events")

    if load_json(TRACE_SCHEMA) != load_json(ROOT / "shared" / "schemas" / "trace-event.schema.json"):
        errors.append("trace-event schema diverges from the shared schema")

    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for token in ('name: "sip"', "category: protocol", "protocols:", "version:"):
        if token not in manifest:
            errors.append(f"manifest missing {token}")

    test_source = (SKILL / "tests" / "test_sip.py").read_text(encoding="utf-8")
    for token in REQUIRED_TEST_TOKENS:
        if token not in test_source:
            errors.append(f"test suite is missing required coverage: {token}")

    tracked = subprocess.run(
        ["git", "ls-files", "skills/protocol/sip"], capture_output=True, text=True, check=False
    ).stdout.splitlines()
    for name in tracked:
        if name.endswith((".pcap", ".pcapng", ".cap")):
            errors.append(f"binary capture is tracked in the repository: {name}")

    for relative, expected_name in GOLDEN_CASES:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = directory / "events.jsonl"
            completed = run([sys.executable, str(CLI), str(SKILL / relative), "--output", str(output)])
            if completed.returncode != 0:
                errors.append(f"{relative}: extraction failed: {completed.stderr.strip()}")
                continue
            if output.read_bytes() != (EXPECTED / expected_name).read_bytes():
                errors.append(f"{relative}: output differs from the committed expectation")
            rows = load_jsonl(output)
            for index, row in enumerate(rows, start=1):
                try:
                    jsonschema.validate(row, schema)
                except jsonschema.ValidationError as exc:
                    errors.append(f"{expected_name} row {index}: {exc.message}")
                    break
                if row["timestamp"] != sip_model._timestamp(row["frame_time_epoch"]):
                    errors.append(f"{expected_name} row {index}: timestamp was not derived from the source epoch")
                expected_reference = (
                    f"sip-event:{row['capture_file']}:{row['frame_number']}.{row['message_occurrence']}"
                )
                if row["source_reference"] != expected_reference:
                    errors.append(f"{expected_name} row {index}: source reference does not match its frame provenance")
                if row["frame_number"] < 1:
                    errors.append(f"{expected_name} row {index}: fabricated frame number")

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        base_trace = directory / "trace.jsonl"
        completed = run(
            [
                sys.executable,
                str(CLI),
                str(EXAMPLES / "pdml" / "base-udp.pdml"),
                "--output",
                str(directory / "events.jsonl"),
                "--trace-output",
                str(base_trace),
            ]
        )
        if completed.returncode != 0:
            errors.append(f"base trace extraction failed: {completed.stderr.strip()}")
        elif base_trace.read_bytes() != (EXPECTED / "base-udp-trace.jsonl").read_bytes():
            errors.append("base trace output differs from the committed expectation")
        else:
            trace_schema = load_json(TRACE_SCHEMA)
            for row in load_jsonl(base_trace):
                try:
                    jsonschema.validate(row, trace_schema)
                except jsonschema.ValidationError as exc:
                    errors.append(f"trace projection validation failed: {exc.message}")
                    break

    for name in EXPECTED.glob("*.jsonl"):
        text = name.read_text(encoding="utf-8")
        for secret in PRIVACY_SECRETS:
            if secret in text:
                errors.append(f"privacy leak detected in {name.name}: {secret}")
        for token in FORBIDDEN_OUTPUT_TOKENS:
            if token in text:
                errors.append(f"{name.name} publishes forbidden semantic token: {token}")

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        privacy_output = directory / "privacy.jsonl"
        completed = run(
            [
                sys.executable,
                str(CLI),
                str(EXAMPLES / "dissector" / "privacy-cases.jsonl"),
                "--output",
                str(privacy_output),
            ]
        )
        if completed.returncode != 0:
            errors.append(f"privacy fixture extraction failed: {completed.stderr.strip()}")
        combined = completed.stdout + completed.stderr + (
            privacy_output.read_text(encoding="utf-8") if privacy_output.is_file() else ""
        )
        for secret in PRIVACY_SECRETS:
            if secret in combined:
                errors.append(f"privacy fixture leaked a sensitive value: {secret}")
        for token in ("Digest ", "Authorization:", "WWW-Authenticate:", "<sip:", "tel:+"):
            if token in combined:
                errors.append(f"privacy fixture leaked a raw header or URI token: {token}")

        malformed = directory / "malformed.jsonl"
        malformed.write_text('{"frame_number": 1, "headers": {}', encoding="utf-8")
        completed = run([sys.executable, str(CLI), str(malformed), "--output", str(directory / "bad.jsonl")])
        if completed.returncode != 2:
            errors.append(f"malformed input did not return exit code 2: {completed.returncode}")

        empty = run(
            [
                sys.executable,
                str(CLI),
                str(EXAMPLES / "pdml" / "no-sip.pdml"),
                "--output",
                str(directory / "empty.jsonl"),
            ]
        )
        if empty.returncode != 3:
            errors.append(f"no-SIP input did not return exit code 3: {empty.returncode}")

        missing_directory = run(
            [
                sys.executable,
                str(CLI),
                str(EXAMPLES / "pdml" / "base-udp.pdml"),
                "--output",
                str(directory / "absent" / "events.jsonl"),
            ]
        )
        if missing_directory.returncode != 6:
            errors.append(f"missing output directory did not return exit code 6: {missing_directory.returncode}")

        existing = directory / "existing.jsonl"
        existing.write_text("existing", encoding="utf-8")
        refused = run(
            [
                sys.executable,
                str(CLI),
                str(EXAMPLES / "pdml" / "base-udp.pdml"),
                "--output",
                str(existing),
            ]
        )
        if refused.returncode != 6:
            errors.append(f"existing output without --force did not return exit code 6: {refused.returncode}")

        first = directory / "first.jsonl"
        second = directory / "second.jsonl"
        for destination in (first, second):
            result = run(
                [
                    sys.executable,
                    str(CLI),
                    str(EXAMPLES / "pdml" / "base-udp.pdml"),
                    "--output",
                    str(destination),
                ]
            )
            if result.returncode != 0:
                errors.append(f"deterministic rerun failed: {result.stderr.strip()}")
        if first.is_file() and second.is_file() and first.read_bytes() != second.read_bytes():
            errors.append("event extraction is not deterministic")

        invalid = {
            "event_schema_version": "1.0.0",
            "protocol": "SIP",
        }
        try:
            jsonschema.validate(invalid, schema)
        except jsonschema.ValidationError:
            pass
        else:
            errors.append("strict schema accepted a truncated event")

    if errors:
        for error in errors:
            print(f"validate-sip: {error}", file=sys.stderr)
        return 1
    print("sip validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())