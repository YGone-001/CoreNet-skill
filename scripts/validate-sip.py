#!/usr/bin/env python3
"""Validate the standalone sip Protocol Skill contract."""

from __future__ import annotations

import copy
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
TRANSACTION_SCHEMA = SKILL / "schemas" / "sip-transactions.schema.json"
DIALOG_SCHEMA = SKILL / "schemas" / "sip-dialogs.schema.json"
TRACE_SCHEMA = SKILL / "schemas" / "trace-event.schema.json"

sys.path.insert(0, str(SCRIPTS))
import sip_model  # noqa: E402
import sip_dialogs  # noqa: E402
import sip_transactions  # noqa: E402

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/protocol-model.md",
    "references/field-reference.md",
    "references/privacy.md",
    "references/failure-cases.md",
    "references/transactions.md",
    "references/dialogs.md",
    "scripts/sip_model.py",
    "scripts/sip_transactions.py",
    "scripts/sip_dialogs.py",
    "scripts/extract-sip.py",
    "schemas/sip-events.schema.json",
    "schemas/sip-transactions.schema.json",
    "schemas/sip-dialogs.schema.json",
    "schemas/trace-event.schema.json",
    "filters/wireshark.txt",
    "tests/test_sip.py",
    "tests/test_sip_dialogs.py",
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
    "examples/dissector/transaction-cases.jsonl",
    "examples/dissector/dialog-cases.jsonl",
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
    "examples/expected/transaction-cases-events.jsonl",
    "examples/expected/transaction-cases-transactions.json",
    "examples/expected/dialog-cases-events.jsonl",
    "examples/expected/dialog-cases-transactions.json",
    "examples/expected/dialog-cases-dialogs.json",
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
    "test_cancel_matching_invite",
    "test_ack_for_non_2xx_invite",
    "test_ack_for_2xx_invite_is_independent",
    "test_udp_invite_retransmission",
    "test_udp_response_retransmission",
    "test_repeated_tcp_message_is_not_sip_retransmission",
    "test_ambiguous_matching_remains_unresolved",
    "test_transaction_schema_validation",
    "test_invalid_transaction_reference_is_rejected",
    "test_duplicate_source_reference_is_rejected",
    "test_fixture_dialog_schema_validation",
    "test_forking_produces_two_independent_dialogs",
    "test_valid_2xx_ack_is_bound",
    "test_bye_reverse_direction",
    "test_mid_capture_bye_is_unbound",
    "test_same_frame_multiple_occurrences_are_distinct",
    "test_no_raw_identity_or_secret_is_published",
    "test_replay_is_deterministic",
    "test_capture_identity_isolation",
    "test_cross_capture_bye_is_rejected",
    "test_cross_capture_ack_is_rejected",
    "test_cross_capture_update_is_rejected",
    "test_reused_initial_transaction_is_not_collapsed",
    "test_cseq_gap_is_direction_specific",
    "test_cseq_cross_direction_values_do_not_form_a_gap",
    "test_reference_accounting_conserves_counts",
    "test_reference_accounting_marks_truncated_collections",
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


    transaction_schema = load_json(TRANSACTION_SCHEMA)
    if transaction_schema.get("additionalProperties") is not False:
        errors.append("transaction schema must set additionalProperties: false")
    for required in (
        "analysis_name",
        "analysis_version",
        "protocol",
        "capture_files",
        "transaction_count",
        "summary",
        "transactions",
        "limitations",
        "not_confirmed",
    ):
        if required not in transaction_schema.get("required", []):
            errors.append(f"transaction schema is missing required property: {required}")
    if "transaction_reference" not in schema.get("properties", {}):
        errors.append("event schema does not expose an optional transaction_reference")

    dialog_schema = load_json(DIALOG_SCHEMA)
    if dialog_schema.get("additionalProperties") is not False:
        errors.append("dialog schema must set additionalProperties: false")
    for required in (
        "analysis_name",
        "analysis_version",
        "protocol",
        "capture_provenance",
        "dialog_count",
        "dialog_summary",
        "dialogs",
        "unbound_observations",
        "ambiguous_observations",
        "limitations",
        "not_confirmed",
    ):
        if required not in dialog_schema.get("required", []):
            errors.append(f"dialog schema is missing required property: {required}")
    for definition in (
        "capture_provenance",
        "dialog",
        "unbound_observation",
        "ambiguous_observation",
        "cseq_observations",
        "reference_count",
        "dialog_reference_accounting",
        "unbound_reference_accounting",
        "ambiguous_reference_accounting",
    ):
        if dialog_schema["$defs"][definition].get("additionalProperties") is not False:
            errors.append(f"dialog schema definition {definition} is not strict")
    if dialog_schema["properties"]["analysis_version"].get("const") != sip_dialogs.DIALOG_SCHEMA_VERSION:
        errors.append("dialog schema version diverges from the dialog model constant")

    if load_json(TRACE_SCHEMA) != load_json(ROOT / "shared" / "schemas" / "trace-event.schema.json"):
        errors.append("trace-event schema diverges from the shared schema")

    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for token in ('name: "sip"', "category: protocol", "protocols:", "version:"):
        if token not in manifest:
            errors.append(f"manifest missing {token}")

    test_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((SKILL / "tests").glob("test_*.py"))
    )
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
        transaction_events = directory / "transaction-events.jsonl"
        transaction_output = directory / "transaction-output.json"
        completed = run(
            [
                sys.executable,
                str(CLI),
                str(EXAMPLES / "dissector" / "transaction-cases.jsonl"),
                "--output",
                str(transaction_events),
                "--transaction-output",
                str(transaction_output),
                "--force",
            ]
        )
        if completed.returncode != 0:
            errors.append(f"transaction correlation failed: {completed.stderr.strip()}")
        else:
            if transaction_events.read_bytes() != (EXPECTED / "transaction-cases-events.jsonl").read_bytes():
                errors.append("transaction event output differs from the committed expectation")
            if transaction_output.read_bytes() != (EXPECTED / "transaction-cases-transactions.json").read_bytes():
                errors.append("transaction output differs from the committed expectation")
            document = load_json(transaction_output)
            try:
                jsonschema.validate(document, transaction_schema)
            except jsonschema.ValidationError as exc:
                errors.append(f"transaction schema validation failed: {exc.message}")
            try:
                sip_transactions.validate_transaction_document(document)
            except sip_transactions.TransactionError as exc:
                errors.append(f"transaction document validation failed: {exc}")
            rows = load_jsonl(transaction_events)
            for row in rows:
                reference = row.get("transaction_reference")
                if not isinstance(reference, str) or not sip_transactions.TRANSACTION_REFERENCE_PATTERN.fullmatch(reference):
                    errors.append("a transaction-mode SIP event lacks a valid transaction reference")
                    break
                try:
                    jsonschema.validate(row, schema)
                except jsonschema.ValidationError as exc:
                    errors.append(f"transaction-mode event schema validation failed: {exc.message}")
                    break
            transaction_text = transaction_output.read_text(encoding="utf-8")
            for secret in PRIVACY_SECRETS:
                if secret in transaction_text:
                    errors.append(f"transaction output leaked a sensitive value: {secret}")
            for raw_key in ('"call_id"', '"via_branch"', '"from_tag"', '"to_tag"', '"request_uri"', '"authorization"'):
                if raw_key in transaction_text:
                    errors.append(f"transaction output publishes a raw matching field: {raw_key}")

            tampered = copy.deepcopy(document)
            tampered["transactions"][0]["transaction_reference"] = "invalid"
            try:
                sip_transactions.validate_transaction_document(tampered)
            except sip_transactions.TransactionError:
                pass
            else:
                errors.append("invalid transaction reference was not rejected")

            duplicated = copy.deepcopy(document)
            duplicated["transactions"][0]["request_event_references"].append(
                duplicated["transactions"][0]["request_event_references"][0]
            )
            try:
                sip_transactions.validate_transaction_document(duplicated)
            except sip_transactions.TransactionError:
                pass
            else:
                errors.append("duplicate source reference was not rejected")

            second_output = directory / "second-transactions.json"
            second_events = directory / "second-events.jsonl"
            rerun = run(
                [
                    sys.executable,
                    str(CLI),
                    str(EXAMPLES / "dissector" / "transaction-cases.jsonl"),
                    "--output",
                    str(second_events),
                    "--transaction-output",
                    str(second_output),
                    "--force",
                ]
            )
            if rerun.returncode != 0:
                errors.append(f"transaction deterministic rerun failed: {rerun.stderr.strip()}")
            elif (
                second_output.read_bytes() != transaction_output.read_bytes()
                or second_events.read_bytes() != transaction_events.read_bytes()
            ):
                errors.append("transaction correlation is not deterministic")

            transaction_only = directory / "transaction-only.json"
            only = run(
                [
                    sys.executable,
                    str(CLI),
                    str(EXAMPLES / "dissector" / "transaction-cases.jsonl"),
                    "--transaction-output",
                    str(transaction_only),
                ]
            )
            if only.returncode != 0:
                errors.append(f"transaction-only output failed: {only.stderr.strip()}")

            missing = run(
                [
                    sys.executable,
                    str(CLI),
                    str(EXAMPLES / "dissector" / "transaction-cases.jsonl"),
                    "--transaction-output",
                    str(directory / "absent" / "transactions.json"),
                ]
            )
            if missing.returncode != 6:
                errors.append(
                    f"missing transaction output directory did not return exit code 6: {missing.returncode}"
                )

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        dialog_events = directory / "dialog-events.jsonl"
        dialog_transactions = directory / "dialog-transactions.json"
        dialog_output = directory / "dialog-dialogs.json"
        dialog_input = EXAMPLES / "dissector" / "dialog-cases.jsonl"
        completed = run(
            [
                sys.executable,
                str(CLI),
                str(dialog_input),
                "--output",
                str(dialog_events),
                "--transaction-output",
                str(dialog_transactions),
                "--dialog-output",
                str(dialog_output),
                "--force",
            ]
        )
        if completed.returncode != 0:
            errors.append(f"dialog analysis failed: {completed.stderr.strip()}")
        else:
            for path, expected_name in (
                (dialog_events, "dialog-cases-events.jsonl"),
                (dialog_transactions, "dialog-cases-transactions.json"),
                (dialog_output, "dialog-cases-dialogs.json"),
            ):
                if path.read_bytes() != (EXPECTED / expected_name).read_bytes():
                    errors.append(f"{expected_name} differs from the committed expectation")
            transaction_document = load_json(dialog_transactions)
            dialog_document = load_json(dialog_output)
            messages, _ = sip_model.messages_for_input(dialog_input, "fields-jsonl")
            try:
                jsonschema.validate(transaction_document, transaction_schema)
                jsonschema.validate(dialog_document, dialog_schema)
            except jsonschema.ValidationError as exc:
                errors.append(f"dialog artifact schema validation failed: {exc.message}")
            try:
                sip_transactions.validate_transaction_document(transaction_document, messages)
                sip_dialogs.validate_dialog_document(
                    dialog_document, messages, transaction_document
                )
            except (sip_transactions.TransactionError, sip_dialogs.DialogError) as exc:
                errors.append(f"dialog semantic validation failed: {exc}")

            dialog_text = dialog_output.read_text(encoding="utf-8")
            for secret in PRIVACY_SECRETS:
                if secret in dialog_text:
                    errors.append(f"dialog output leaked a sensitive value: {secret}")
            for token in (
                "alice@",
                "bob@",
                "TAG-INIT",
                '"call_id"',
                '"from_tag"',
                '"to_tag"',
                '"request_uri"',
                '"from_uri"',
                '"to_uri"',
                '"via_branch"',
                '"dialog_id"',
            ):
                if token in dialog_text:
                    errors.append(f"dialog output publishes a raw identity field: {token}")

            tampered = copy.deepcopy(dialog_document)
            tampered["dialogs"][0]["dialog_reference"] = "invalid"
            try:
                sip_dialogs.validate_dialog_document(tampered, messages, transaction_document)
            except sip_dialogs.DialogError:
                pass
            else:
                errors.append("invalid dialog reference was not rejected")

            duplicated = copy.deepcopy(dialog_document)
            if len(duplicated["dialogs"]) > 1:
                duplicated["dialogs"][1]["dialog_reference"] = duplicated["dialogs"][0][
                    "dialog_reference"
                ]
                try:
                    sip_dialogs.validate_dialog_document(
                        duplicated, messages, transaction_document
                    )
                except sip_dialogs.DialogError:
                    pass
                else:
                    errors.append("duplicate dialog reference was not rejected")

            missing_transaction = copy.deepcopy(dialog_document)
            missing_transaction["dialogs"][0][
                "initiating_transaction_reference"
            ] = "sip-transaction:missing.pcapng:request:1.1"
            try:
                sip_dialogs.validate_dialog_document(
                    missing_transaction, messages, transaction_document
                )
            except sip_dialogs.DialogError:
                pass
            else:
                errors.append("unknown initiating transaction reference was not rejected")

            dialog_only = directory / "dialog-only.json"
            only_dialog = run(
                [
                    sys.executable,
                    str(CLI),
                    str(dialog_input),
                    "--dialog-output",
                    str(dialog_only),
                    "--force",
                ]
            )
            if only_dialog.returncode != 0 or not dialog_only.is_file():
                errors.append(f"dialog-only output failed: {only_dialog.stderr.strip()}")

            second_dialog = directory / "second-dialogs.json"
            second_transactions = directory / "second-transactions.json"
            second_events = directory / "second-events.jsonl"
            rerun = run(
                [
                    sys.executable,
                    str(CLI),
                    str(dialog_input),
                    "--output",
                    str(second_events),
                    "--transaction-output",
                    str(second_transactions),
                    "--dialog-output",
                    str(second_dialog),
                    "--force",
                ]
            )
            if rerun.returncode != 0:
                errors.append(f"dialog deterministic rerun failed: {rerun.stderr.strip()}")
            elif (
                second_dialog.read_bytes() != dialog_output.read_bytes()
                or second_transactions.read_bytes() != dialog_transactions.read_bytes()
                or second_events.read_bytes() != dialog_events.read_bytes()
            ):
                errors.append("dialog analysis is not deterministic")

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