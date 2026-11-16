#!/usr/bin/env python3
"""Validate the standalone diameter-core Protocol Skill contract."""

from __future__ import annotations

import json
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "protocol" / "diameter-core"
SCRIPTS = SKILL / "scripts"
EXAMPLES = SKILL / "examples"
EXPECTED = EXAMPLES / "expected"
EXTRACT = SCRIPTS / "extract-diameter-core.py"
CORRELATE = SCRIPTS / "correlate-diameter-core.py"

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/protocol-model.md",
    "references/field-reference.md",
    "references/correlation.md",
    "references/privacy.md",
    "references/failure-cases.md",
    "scripts/diameter_core_model.py",
    "scripts/extract-diameter-core.py",
    "scripts/correlate-diameter-core.py",
    "schemas/diameter-event.schema.json",
    "schemas/diameter-transaction.schema.json",
    "schemas/trace-event.schema.json",
    "filters/wireshark.txt",
    "tests/test_diameter_core.py",
    "examples/pdml/base-exchange.pdml",
    "examples/pdml/no-diameter.pdml",
    "examples/dissector/negative-cases.jsonl",
    "examples/dissector/privacy-cases.jsonl",
    "examples/dissector/association-reuse.jsonl",
    "examples/dissector/tcp-stream-reuse.jsonl",
    "examples/dissector/incomplete-association.jsonl",
    "examples/dissector/mid-capture-start.jsonl",
)

PRIVACY_SECRETS = ("001010000000001", "a1b2c3d4e5f6", "IMSI999")

FORBIDDEN_OUTPUT_TOKENS = (
    "procedure_family",
    "attach_success",
    "registration_success",
    "root_cause",
    "bearer_activated",
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def validate_schema(rows: list[dict], schema_file: Path, label: str, errors: list[str]) -> None:
    try:
        import jsonschema
    except ImportError:
        errors.append(f"{label}: jsonschema is required")
        return
    schema = load_json(schema_file)
    for index, row in enumerate(rows, start=1):
        try:
            jsonschema.validate(row, schema)
        except jsonschema.ValidationError as exc:
            errors.append(f"{label} row {index}: {exc.message}")
            return


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
            print(f"validate-diameter-core: {error}", file=sys.stderr)
        return 1

    if load_json(SKILL / "schemas/trace-event.schema.json") != load_json(
        ROOT / "shared/schemas/trace-event.schema.json"
    ):
        errors.append("trace-event schema diverges from the shared schema")

    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for required_token in ('name: "diameter-core"', "category: protocol", "protocols:"):
        if required_token not in manifest:
            errors.append(f"manifest missing {required_token}")

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        base_events = directory / "base-events.jsonl"
        base_trace = directory / "base-trace.jsonl"
        result = run(
            [
                sys.executable,
                str(EXTRACT),
                str(EXAMPLES / "pdml/base-exchange.pdml"),
                "--output",
                str(base_events),
                "--trace-output",
                str(base_trace),
            ]
        )
        if result.returncode != 0:
            errors.append(f"base extraction failed: {result.stderr.strip()}")
        else:
            if base_events.read_bytes() != (EXPECTED / "base-events.jsonl").read_bytes():
                errors.append("base event output differs from the committed expectation")
            if base_trace.read_bytes() != (EXPECTED / "base-trace.jsonl").read_bytes():
                errors.append("base trace output differs from the committed expectation")
            base_transactions = directory / "base-transactions.json"
            base_timeline = directory / "base-timeline.txt"
            result = run(
                [
                    sys.executable,
                    str(CORRELATE),
                    str(base_events),
                    "--output",
                    str(base_transactions),
                    "--timeline-output",
                    str(base_timeline),
                ]
            )
            if result.returncode != 0:
                errors.append(f"base correlation failed: {result.stderr.strip()}")
            else:
                if base_transactions.read_bytes() != (EXPECTED / "base-transactions.json").read_bytes():
                    errors.append("base transaction output differs from the committed expectation")
                if base_timeline.read_bytes() != (EXPECTED / "base-timeline.txt").read_bytes():
                    errors.append("base timeline output differs from the committed expectation")

        negative_events = directory / "negative-events.jsonl"
        negative_transactions = directory / "negative-transactions.json"
        result = run(
            [
                sys.executable,
                str(EXTRACT),
                str(EXAMPLES / "dissector/negative-cases.jsonl"),
                "--output",
                str(negative_events),
            ]
        )
        if result.returncode != 0:
            errors.append(f"negative extraction failed: {result.stderr.strip()}")
        else:
            if negative_events.read_bytes() != (EXPECTED / "negative-events.jsonl").read_bytes():
                errors.append("negative event output differs from the committed expectation")
            result = run(
                [
                    sys.executable,
                    str(CORRELATE),
                    str(negative_events),
                    "--output",
                    str(negative_transactions),
                ]
            )
            if result.returncode != 0:
                errors.append(f"negative correlation failed: {result.stderr.strip()}")
            elif negative_transactions.read_bytes() != (EXPECTED / "negative-transactions.json").read_bytes():
                errors.append("negative transaction output differs from the committed expectation")

        privacy_events = directory / "privacy-events.jsonl"
        result = run(
            [
                sys.executable,
                str(EXTRACT),
                str(EXAMPLES / "dissector/privacy-cases.jsonl"),
                "--output",
                str(privacy_events),
            ]
        )
        if result.returncode != 0:
            errors.append(f"privacy extraction failed: {result.stderr.strip()}")
        else:
            text = privacy_events.read_text(encoding="utf-8")
            for secret in PRIVACY_SECRETS:
                if secret in text:
                    errors.append(f"privacy leak detected: {secret}")
            if privacy_events.read_bytes() != (EXPECTED / "privacy-events.jsonl").read_bytes():
                errors.append("privacy event output differs from the committed expectation")
            try:
                privacy_rows = load_jsonl(privacy_events)
            except json.JSONDecodeError as exc:
                errors.append(f"privacy output is not valid JSONL: {exc}")
            else:
                for row in privacy_rows:
                    validate_schema(
                        [row], SKILL / "schemas/diameter-event.schema.json", "privacy event", errors
                    )
                    for avp in row.get("avps") or []:
                        if avp.get("sensitive") and avp.get("value") is not None:
                            errors.append(f"sensitive AVP published a value: code {avp.get('code')}")
                        if avp.get("value_kind") == "SENSITIVE_REDACTED" and avp.get("value") is not None:
                            errors.append(f"redacted AVP published a value: code {avp.get('code')}")

        if base_events.is_file():
            validate_schema(
                load_jsonl(base_events), SKILL / "schemas/diameter-event.schema.json", "base event", errors
            )
        if base_transactions.is_file():
            validate_schema(
                [load_json(base_transactions)],
                SKILL / "schemas/diameter-transaction.schema.json",
                "transaction",
                errors,
            )
        if base_trace.is_file():
            validate_schema(
                load_jsonl(base_trace), SKILL / "schemas/trace-event.schema.json", "trace", errors
            )

        second_events = directory / "second-events.jsonl"
        result = run(
            [
                sys.executable,
                str(EXTRACT),
                str(EXAMPLES / "pdml/base-exchange.pdml"),
                "--output",
                str(second_events),
            ]
        )
        if result.returncode != 0 or not base_events.is_file():
            errors.append("deterministic rerun extraction failed")
        elif second_events.read_bytes() != base_events.read_bytes():
            errors.append("event extraction is not deterministic")

        malformed = run(
            [
                sys.executable,
                str(EXTRACT),
                str(EXAMPLES / "dissector/malformed.jsonl"),
                "--output",
                str(directory / "bad.jsonl"),
            ]
        )
        if malformed.returncode != 2:
            errors.append(f"malformed input did not return exit code 2: {malformed.returncode}")
        empty = run(
            [
                sys.executable,
                str(EXTRACT),
                str(EXAMPLES / "pdml/no-diameter.pdml"),
                "--output",
                str(directory / "empty.jsonl"),
            ]
        )
        if empty.returncode != 3:
            errors.append(f"no-Diameter input did not return exit code 3: {empty.returncode}")

        for stem in (
            "association-reuse",
            "tcp-stream-reuse",
            "incomplete-association",
            "mid-capture-start",
        ):
            events_path = directory / f"{stem}-events.jsonl"
            transactions_path = directory / f"{stem}-transactions.json"
            result = run(
                [
                    sys.executable,
                    str(EXTRACT),
                    str(EXAMPLES / f"dissector/{stem}.jsonl"),
                    "--output",
                    str(events_path),
                ]
            )
            if result.returncode != 0:
                errors.append(f"{stem} extraction failed: {result.stderr.strip()}")
                continue
            if events_path.read_bytes() != (EXPECTED / f"{stem}-events.jsonl").read_bytes():
                errors.append(f"{stem} event output differs from the committed expectation")
            result = run(
                [
                    sys.executable,
                    str(CORRELATE),
                    str(events_path),
                    "--output",
                    str(transactions_path),
                ]
            )
            if result.returncode != 0:
                errors.append(f"{stem} correlation failed: {result.stderr.strip()}")
            elif transactions_path.read_bytes() != (EXPECTED / f"{stem}-transactions.json").read_bytes():
                errors.append(f"{stem} transaction output differs from the committed expectation")

        for name in (
            "base-transactions.json",
            "negative-transactions.json",
            "association-reuse-transactions.json",
            "tcp-stream-reuse-transactions.json",
            "incomplete-association-transactions.json",
            "mid-capture-start-transactions.json",
        ):
            document = load_json(EXPECTED / name)
            for transaction in document["transactions"]:
                status = transaction["correlation_status"]
                if status == "MATCHED":
                    if transaction["request"] is None or transaction["answer"] is None:
                        errors.append(f"{name}: MATCHED transaction lacks a request or answer")
                    if transaction["latency_seconds"] is None:
                        errors.append(f"{name}: MATCHED transaction lacks latency")
                else:
                    if transaction["latency_seconds"] is not None:
                        errors.append(f"{name}: non-MATCHED transaction publishes latency")
                    if status == "RESPONSE_ONLY" and transaction["request"] is not None:
                        errors.append(f"{name}: RESPONSE_ONLY transaction publishes a request")
                if status == "OPEN_REQUEST" and transaction["answer"] is not None:
                    errors.append(f"{name}: OPEN_REQUEST transaction publishes an answer")
                if status == "AMBIGUOUS" and transaction["request"] is not None:
                    errors.append(f"{name}: AMBIGUOUS transaction selects a request")

        for label, path in (
            ("base events", EXPECTED / "base-events.jsonl"),
            ("base transactions", EXPECTED / "base-transactions.json"),
            ("negative events", EXPECTED / "negative-events.jsonl"),
            ("negative transactions", EXPECTED / "negative-transactions.json"),
            ("privacy events", EXPECTED / "privacy-events.jsonl"),
            ("association events", EXPECTED / "association-reuse-events.jsonl"),
            ("association transactions", EXPECTED / "association-reuse-transactions.json"),
            ("tcp events", EXPECTED / "tcp-stream-reuse-events.jsonl"),
            ("tcp transactions", EXPECTED / "tcp-stream-reuse-transactions.json"),
            ("incomplete events", EXPECTED / "incomplete-association-events.jsonl"),
            ("incomplete transactions", EXPECTED / "incomplete-association-transactions.json"),
            ("mid-capture events", EXPECTED / "mid-capture-start-events.jsonl"),
            ("mid-capture transactions", EXPECTED / "mid-capture-start-transactions.json"),
        ):
            text = path.read_text(encoding="utf-8")
            for token in FORBIDDEN_OUTPUT_TOKENS:
                if token in text:
                    errors.append(f"{label} publishes forbidden verdict token: {token}")
            for secret in PRIVACY_SECRETS:
                if secret in text:
                    errors.append(f"{label} contains a sensitive value: {secret}")

    if errors:
        for error in errors:
            print(f"validate-diameter-core: {error}", file=sys.stderr)
        return 1
    print("diameter-core validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())