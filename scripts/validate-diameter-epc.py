#!/usr/bin/env python3
"""Validate the standalone diameter-epc Protocol Skill contract."""

from __future__ import annotations

import json
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "protocol" / "diameter-epc"
SCRIPTS = SKILL / "scripts"
EXAMPLES = SKILL / "examples"
EXPECTED = EXAMPLES / "expected"
CLI = SCRIPTS / "analyze-diameter-epc.py"

sys.path.insert(0, str(SCRIPTS))
import diameter_epc_model as model  # noqa: E402

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/standards.md",
    "references/application-model.md",
    "references/result-namespaces.md",
    "references/privacy.md",
    "references/evidence-model.md",
    "references/failure-cases.md",
    "scripts/diameter_epc_model.py",
    "scripts/analyze-diameter-epc.py",
    "schemas/diameter-epc-analysis.schema.json",
    "tests/test_diameter_epc.py",
    "examples/core/events.jsonl",
    "examples/core/transactions.json",
    "examples/expected/analysis.json",
    "examples/expected/timeline.txt",
)

PRIVACY_SECRETS = ("001010000000001", "mme.example", "RAND", "AUTN", "XRES", "KASME")
FORBIDDEN_TOKENS = ("attach_success", "ue_authenticated", "registration_success", "root_cause")


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


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
            print(f"validate-diameter-epc: {error}", file=sys.stderr)
        return 1

    try:
        import jsonschema
    except ImportError:
        print("validate-diameter-epc: jsonschema is required", file=sys.stderr)
        return 1
    schema = load_json(SKILL / "schemas" / "diameter-epc-analysis.schema.json")
    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for token in ('name: "diameter-epc"', "category: protocol", "diameter-core >=0.1.0"):
        if token not in manifest:
            errors.append(f"manifest missing {token}")

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        output = directory / "analysis.json"
        timeline = directory / "timeline.txt"
        result = run(
            [
                sys.executable,
                str(CLI),
                "--events",
                str(EXAMPLES / "core/events.jsonl"),
                "--transactions",
                str(EXAMPLES / "core/transactions.json"),
                "--output",
                str(output),
                "--timeline-output",
                str(timeline),
            ]
        )
        if result.returncode != 0:
            errors.append(f"example analysis failed: {result.stderr.strip()}")
        else:
            analysis_text = output.read_text(encoding="utf-8")
            timeline_text = timeline.read_text(encoding="utf-8")
            if output.read_bytes() != (EXPECTED / "analysis.json").read_bytes():
                errors.append("example analysis differs from the committed expectation")
            if timeline.read_bytes() != (EXPECTED / "timeline.txt").read_bytes():
                errors.append("example timeline differs from the committed expectation")
            try:
                analysis = json.loads(analysis_text)
                jsonschema.validate(analysis, schema)
            except (json.JSONDecodeError, jsonschema.ValidationError) as exc:
                errors.append(f"analysis schema validation failed: {exc}")
                analysis = {}
            for secret in PRIVACY_SECRETS:
                if secret in analysis_text or secret in timeline_text:
                    errors.append(f"privacy leak detected: {secret}")
            serialized = (analysis_text + timeline_text).lower()
            for token in FORBIDDEN_TOKENS:
                if token in serialized:
                    errors.append(f"forbidden application verdict token: {token}")
            completeness = analysis.get("completeness", {})
            if completeness.get("observation_count", 0) < 10:
                errors.append("example analysis did not publish the expected observation set")
            for observation in analysis.get("observations", []):
                if observation["transaction_status"] != "MATCHED" and observation["latency_seconds"] is not None:
                    errors.append("non-MATCHED observation publishes latency")
                if observation["transaction_status"] == "RESPONSE_ONLY" and observation["request"] is not None:
                    errors.append("RESPONSE_ONLY observation publishes a request")
                for presence in observation["request_avp_presence"] + observation["answer_avp_presence"]:
                    if presence["value_published"]:
                        errors.append("AVP presence publishes a value")

        second = directory / "analysis-2.json"
        result = run(
            [
                sys.executable,
                str(CLI),
                "--events",
                str(EXAMPLES / "core/events.jsonl"),
                "--transactions",
                str(EXAMPLES / "core/transactions.json"),
                "--output",
                str(second),
            ]
        )
        if result.returncode != 0 or not output.is_file():
            errors.append("deterministic rerun failed")
        elif second.read_bytes() != output.read_bytes():
            errors.append("analysis output is not deterministic")

        invalid = directory / "invalid.jsonl"
        invalid.write_text("{not-json}\n", encoding="utf-8")
        result = run(
            [
                sys.executable,
                str(CLI),
                "--events",
                str(invalid),
                "--transactions",
                str(EXAMPLES / "core/transactions.json"),
                "--output",
                str(directory / "invalid-out.json"),
            ]
        )
        if result.returncode != 2:
            errors.append("invalid JSON input did not return exit code 2")

        events = model.load_jsonl(EXAMPLES / "core/events.jsonl")
        transactions = model.load_json(EXAMPLES / "core/transactions.json")
        events[1]["capture_file"] = "other.pcapng"
        mismatch_events = directory / "mismatch-events.jsonl"
        mismatch_events.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
        result = run(
            [
                sys.executable,
                str(CLI),
                "--events",
                str(mismatch_events),
                "--transactions",
                str(EXAMPLES / "core/transactions.json"),
                "--output",
                str(directory / "mismatch-out.json"),
            ]
        )
        if result.returncode != 2:
            errors.append("capture mismatch did not return exit code 2")

        events = model.load_jsonl(EXAMPLES / "core/events.jsonl")
        transactions = model.load_json(EXAMPLES / "core/transactions.json")
        transactions["transactions"][0]["answer"]["frame_number"] = 999
        missing_ref = directory / "missing-ref.json"
        missing_ref.write_text(json.dumps(transactions), encoding="utf-8")
        result = run(
            [
                sys.executable,
                str(CLI),
                "--events",
                str(EXAMPLES / "core/events.jsonl"),
                "--transactions",
                str(missing_ref),
                "--output",
                str(directory / "missing-out.json"),
            ]
        )
        if result.returncode != 2:
            errors.append("unresolved transaction reference did not return exit code 2")

        no_s6a_events = [item for item in model.load_jsonl(EXAMPLES / "core/events.jsonl") if item["application_id"] != 16777251]
        no_s6a_doc = {
            "protocol": "Diameter",
            "capture_files": [no_s6a_events[0]["capture_file"]],
            "transactions": [],
        }
        no_s6a_events_path = directory / "no-s6a-events.jsonl"
        no_s6a_events_path.write_text("\n".join(json.dumps(item) for item in no_s6a_events) + "\n", encoding="utf-8")
        no_s6a_tx_path = directory / "no-s6a-tx.json"
        no_s6a_tx_path.write_text(json.dumps(no_s6a_doc), encoding="utf-8")
        result = run(
            [
                sys.executable,
                str(CLI),
                "--events",
                str(no_s6a_events_path),
                "--transactions",
                str(no_s6a_tx_path),
                "--output",
                str(directory / "no-s6a-out.json"),
            ]
        )
        if result.returncode != 3:
            errors.append("no-S6a input did not return exit code 3")

    checks = {
        "base_5001": model.classify_result(
            {"result": {"result_code": 5001, "result_code_name": "DIAMETER_AVP_UNSUPPORTED", "result_namespace": "BASE", "experimental_result_present": False}}
        ),
        "experimental_5001": model.classify_result(
            {"result": {"result_code": None, "result_namespace": "VENDOR_SPECIFIC", "experimental_result_present": True, "experimental_result_code": 5001, "experimental_vendor_id": 10415}}
        ),
        "unknown_vendor_5001": model.classify_result(
            {"result": {"result_code": None, "result_namespace": "VENDOR_SPECIFIC", "experimental_result_present": True, "experimental_result_code": 5001, "experimental_vendor_id": 9999}}
        ),
    }
    if checks["base_5001"]["base_result_code_name"] != "DIAMETER_AVP_UNSUPPORTED":
        errors.append("base 5001 namespace mapping is wrong")
    if checks["base_5001"]["base_result_code_name"] == "DIAMETER_ERROR_USER_UNKNOWN":
        errors.append("base 5001 was confused with the 3GPP User Unknown namespace")
    if checks["experimental_5001"]["experimental_result_code_name"] != "DIAMETER_ERROR_USER_UNKNOWN":
        errors.append("3GPP Experimental 5001 mapping is wrong")
    if checks["unknown_vendor_5001"]["experimental_result_code_name"] is not None:
        errors.append("unknown vendor received 3GPP semantics")

    if errors:
        for error in errors:
            print(f"validate-diameter-epc: {error}", file=sys.stderr)
        return 1
    print("diameter-epc validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())