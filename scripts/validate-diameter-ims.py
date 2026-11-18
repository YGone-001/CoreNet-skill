#!/usr/bin/env python3
"""Validate the standalone diameter-ims Protocol Skill contract, including the
TS 29.230 Release 19 result-code registry crosswalk."""

from __future__ import annotations

import json
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "protocol" / "diameter-ims"
SCRIPTS = SKILL / "scripts"
EXAMPLES = SKILL / "examples"
EXPECTED = EXAMPLES / "expected"
CLI = SCRIPTS / "analyze-diameter-ims.py"

sys.path.insert(0, str(SCRIPTS))
import diameter_ims_model as model  # noqa: E402

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/standards.md",
    "references/commands.md",
    "references/avp-reference.md",
    "references/evidence-model.md",
    "references/privacy.md",
    "references/failure-cases.md",
    "scripts/diameter_ims_model.py",
    "scripts/analyze-diameter-ims.py",
    "schemas/diameter-ims-analysis.schema.json",
    "tests/test_diameter_ims.py",
    "examples/core/events.jsonl",
    "examples/core/transactions.json",
    "examples/expected/analysis.json",
    "examples/expected/timeline.txt",
)

PRIVACY_SECRETS = (
    "client.example",
    "scscf.example",
    "scscf-scscf.example",
    "visited.example",
    "PRIVATE-IMPU",
    "PRIVATE-IMPI",
    "PRIVATE-USER",
    "Digest",
)
FORBIDDEN_TOKENS = (
    "ims_registered",
    "registration_success",
    "registration_failure",
    "hss_authorized",
    "authentication_success",
    "call_success",
    "media_delivered",
    "root_cause",
)


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def check_analysis(analysis: dict, errors: list[str]) -> None:
    capability = analysis.get("capability", {})
    if capability.get("application_id") != model.CX_APPLICATION_ID:
        errors.append("application_id is not the reviewed Cx/Dx Application-ID")
    if capability.get("application_name") != "Cx/Dx":
        errors.append("application_name is not Cx/Dx")
    if capability.get("interface_identity") != "UNPROVED":
        errors.append("interface_identity is not UNPROVED")
    if capability.get("interface_identity_basis"):
        errors.append("interface_identity_basis must stay empty without trusted metadata")
    expected_supported = [
        f"{code} {model.COMMANDS[code][1]}/{model.COMMANDS[code][2]}"
        for code in model.SUPPORTED_COMMAND_CODES
    ]
    if capability.get("supported_commands") != expected_supported:
        errors.append("supported_commands diverges from the reviewed command set")
    if model.ANALYSIS_VERSION != "1.1.0":
        errors.append("producer analysis version is not the corrected 1.1.0 contract")
    if analysis.get("analysis_version") != model.ANALYSIS_VERSION:
        errors.append("analysis_version does not match the producer version")

    observations = analysis.get("observations", [])
    completeness = analysis.get("completeness", {})
    if completeness.get("observation_count") != len(observations):
        errors.append("observation_count does not match the observation array")
    counted = {
        "unsupported_observations": sum(
            1 for item in observations if item["message_status"] == "KNOWN_UNSUPPORTED"
        ),
        "conflicting_observations": sum(
            1 for item in observations if item["message_status"] == "CONFLICTING"
        ),
        "truncated_observations": sum(
            1
            for item in observations
            if any(
                presence["status"] == "NOT_OBSERVED_IN_PUBLISHED_SUBSET"
                for presence in item["request_avp_presence"] + item["answer_avp_presence"]
            )
        ),
        "observations_with_unproven_grouping": sum(
            1
            for item in observations
            if any(
                presence["grouped"]
                and presence["status"] == "PRESENT_STRUCTURE_ONLY"
                and not presence["structure_proven"]
                for presence in item["request_avp_presence"] + item["answer_avp_presence"]
            )
        ),
    }
    for key, value in counted.items():
        if completeness.get(key) != value:
            errors.append(f"completeness {key} is inconsistent with the observation array")

    for observation in observations:
        if not model.TRANSACTION_REFERENCE_PATTERN.fullmatch(observation["transaction_reference"]):
            errors.append("observation publishes an invalid transaction reference")
        if observation["message_status"] not in ("OBSERVED", "KNOWN_UNSUPPORTED", "CONFLICTING"):
            errors.append("observation has an invalid message_status")
        if observation["transaction_status"] not in ("MATCHED", "OPEN_REQUEST", "RESPONSE_ONLY", "AMBIGUOUS"):
            errors.append("observation has an invalid transaction_status")
        if observation["application_result"] not in (
            "SUCCESS_REPORTED",
            "FAILURE_REPORTED",
            "UNRESOLVED",
            "NOT_APPLICABLE",
        ):
            errors.append("observation has an invalid application_result")
        if observation["transaction_status"] != "MATCHED" and observation["latency_seconds"] is not None:
            errors.append("non-MATCHED observation publishes latency")
        if observation["transaction_status"] == "OPEN_REQUEST" and observation["answer"] is not None:
            errors.append("OPEN_REQUEST observation publishes an answer")
        if observation["transaction_status"] == "RESPONSE_ONLY" and observation["request"] is not None:
            errors.append("RESPONSE_ONLY observation publishes a request")
        if observation["transaction_status"] == "AMBIGUOUS":
            if observation["request"] is not None:
                errors.append("AMBIGUOUS observation publishes a selected request")
            if not observation["response_candidates"]:
                errors.append("AMBIGUOUS observation does not retain candidates")
        if observation["message_status"] != "OBSERVED":
            if observation["request_avp_presence"] or observation["answer_avp_presence"]:
                errors.append("uninterpreted observation publishes AVP semantics")
            if observation["command_name"] is not None:
                errors.append("uninterpreted observation publishes a reviewed command name")
        for side in ("request", "answer", "response_candidates"):
            projection = observation[side]
            items = projection if isinstance(projection, list) else ([projection] if projection else [])
            for item in items:
                if item["command_code"] != observation["command_code"]:
                    errors.append("reference command code disagrees with its observation")
        for presence in observation["request_avp_presence"] + observation["answer_avp_presence"]:
            if presence.get("canonical_name") != model.canonical_avp_name(presence["code"]):
                errors.append(f"AVP {presence['code']} canonical name is not the reviewed TS 29.229 name")
            if presence["code"] in model.AVP_NAMES and presence["name"] != model.AVP_NAMES[presence["code"]]:
                errors.append(f"AVP {presence['code']} decoder name diverges from the reviewed alias")
            if presence["code"] in model.PROTECTED_CODES:
                if presence["value_published"] or presence["reviewed_values"]:
                    errors.append(f"protected AVP {presence['code']} publishes a value")
            if presence["value_published"] and presence["code"] not in model.REVIEWED_ENUMS:
                errors.append(f"AVP {presence['code']} publishes a value outside the reviewed enumerations")
            for child in presence["children"]:
                expected_child_name = model.canonical_avp_name(child["code"]) or child["name"]
                if child.get("canonical_name") != expected_child_name:
                    errors.append(f"child AVP {child['code']} canonical name is not the reviewed TS 29.229 name")
                if child["code"] in model.PROTECTED_CODES and child["value_published"]:
                    errors.append(f"protected child AVP {child['code']} publishes a value")
                if child["value_published"] and child["code"] not in model.REVIEWED_ENUMS:
                    errors.append(f"child AVP {child['code']} publishes a value outside the reviewed enumerations")


def _experimental(code: int, vendor) -> dict:
    return {
        "result": {
            "result_code": None,
            "result_namespace": "VENDOR_SPECIFIC" if code is not None else None,
            "experimental_result_present": True,
            "experimental_result_code": code,
            "experimental_vendor_id": vendor,
        }
    }


def namespace_checks() -> list[str]:
    errors: list[str] = []
    base = model.classify_result(
        {"result": {"result_code": 5001, "result_code_name": "DIAMETER_AVP_UNSUPPORTED", "result_namespace": "BASE", "experimental_result_present": False}}
    )
    experimental = model.classify_result(
        {"result": {"result_code": None, "result_namespace": "VENDOR_SPECIFIC", "experimental_result_present": True, "experimental_result_code": 5001, "experimental_vendor_id": model.THREEGPP_VENDOR_ID}}
    )
    unknown = model.classify_result(
        {"result": {"result_code": None, "result_namespace": "VENDOR_SPECIFIC", "experimental_result_present": True, "experimental_result_code": 5001, "experimental_vendor_id": 9999}}
    )
    if base.get("base_result_code_name") != "DIAMETER_AVP_UNSUPPORTED":
        errors.append("base 5001 namespace mapping is wrong")
    if base.get("base_result_code_name") == "DIAMETER_ERROR_USER_UNKNOWN":
        errors.append("base 5001 was confused with the 3GPP Cx result namespace")
    if experimental.get("experimental_result_code_name") != "DIAMETER_ERROR_USER_UNKNOWN":
        errors.append("3GPP Experimental 5001 mapping is wrong")
    if experimental.get("namespace_status") != "3GPP_TS_29_229_EXPERIMENTAL":
        errors.append("3GPP Experimental namespace is not TS 29.229")
    if unknown.get("experimental_result_code_name") is not None:
        errors.append("unknown vendor received 3GPP semantics")

    success = {
        2001: "DIAMETER_FIRST_REGISTRATION",
        2002: "DIAMETER_SUBSEQUENT_REGISTRATION",
        2003: "DIAMETER_UNREGISTERED_SERVICE",
        2004: "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED",
    }
    for code, name in success.items():
        classified = model.classify_result(_experimental(code, model.THREEGPP_VENDOR_ID))
        if classified.get("experimental_result_code_name") != name:
            errors.append(f"Cx success {code} mapping is wrong")
        if classified.get("application_result") != "SUCCESS_REPORTED":
            errors.append(f"Cx success {code} is not reported as SUCCESS_REPORTED")

    for code in (2001, 2002):
        classified = model.classify_result(
            {"result": {"result_code": code, "result_code_name": "DIAMETER_SUCCESS", "result_namespace": "BASE", "experimental_result_present": False}}
        )
        if classified.get("application_result") != "SUCCESS_REPORTED":
            errors.append(f"base success {code} is no longer classified as base success")
        if classified.get("namespace_status") != "BASE_RFC6733":
            errors.append(f"base success {code} lost its base namespace")

    missing_vendor = model.classify_result(_experimental(2001, None))
    wrong_vendor = model.classify_result(_experimental(2001, 9999))
    wrong_vendor_2002 = model.classify_result(_experimental(2002, 9999))
    for label, classified in (
        ("2001 missing Vendor-ID", missing_vendor),
        ("2001 wrong Vendor-ID", wrong_vendor),
        ("2002 wrong Vendor-ID", wrong_vendor_2002),
    ):
        if classified.get("application_result") != "UNRESOLVED":
            errors.append(f"{label} was not left unresolved")
        if classified.get("experimental_result_code_name") is not None:
            errors.append(f"{label} received a 3GPP Cx name")

    failures = {
        5001: "DIAMETER_ERROR_USER_UNKNOWN",
        5002: "DIAMETER_ERROR_IDENTITIES_DONT_MATCH",
        5003: "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED",
        5004: "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
        5005: "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED",
        5006: "DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED",
        5007: "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE",
        5008: "DIAMETER_ERROR_TOO_MUCH_DATA",
        5009: "DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA",
        5011: "DIAMETER_ERROR_FEATURE_UNSUPPORTED",
        5012: "DIAMETER_ERROR_SERVING_NODE_FEATURE_UNSUPPORTED",
    }
    for code, name in failures.items():
        classified = model.classify_result(_experimental(code, model.THREEGPP_VENDOR_ID))
        if classified.get("experimental_result_code_name") != name:
            errors.append(f"permanent failure {code} mapping is wrong")
        if classified.get("application_result") != "FAILURE_REPORTED":
            errors.append(f"permanent failure {code} is not reported as FAILURE_REPORTED")

    void_5010 = model.classify_result(_experimental(5010, model.THREEGPP_VENDOR_ID))
    if void_5010.get("application_result") != "UNRESOLVED":
        errors.append("5010 was not left unresolved")
    if void_5010.get("experimental_result_code_name") is not None:
        errors.append("5010 received an invented semantic name")
    if void_5010.get("experimental_result_code") != 5010:
        errors.append("5010 numeric identity was not preserved")
    if not any("6.2.2.10" in item for item in void_5010.get("limitations", [])):
        errors.append("5010 limitation does not record the TS 29.229 Void clause")
    void_5010_text = " ".join(void_5010.get("limitations", []))
    if "8.1.4" not in void_5010_text or "unassigned" not in void_5010_text:
        errors.append("5010 does not record the TS 29.230 unassigned classification")
    if 5010 in model.THREEGPP_CX_FAILURE_RESULT_NAMES or 5010 in model.THREEGPP_CX_RESULT_NAMES:
        errors.append("5010 is still present in the reviewed result-name maps")

    void_2005 = model.classify_result(_experimental(2005, model.THREEGPP_VENDOR_ID))
    if void_2005.get("application_result") != "UNRESOLVED" or void_2005.get("experimental_result_code_name") is not None:
        errors.append("2005 Void was not left unresolved without a name")
    void_2005_text = " ".join(void_2005.get("limitations", []))
    if "6.2.1.5" not in void_2005_text or "Deprecated" not in void_2005_text or "8.1.2" not in void_2005_text:
        errors.append("2005 does not reconcile TS 29.229 Void with TS 29.230 Deprecated terminology")

    for code in (2006, 2020):
        classified = model.classify_result(_experimental(code, model.THREEGPP_VENDOR_ID))
        text = " ".join(classified.get("limitations", []))
        if classified.get("application_result") != "UNRESOLVED":
            errors.append(f"reserved success result {code} was not left unresolved")
        if classified.get("experimental_result_code_name") is not None:
            errors.append(f"reserved success result {code} received a semantic name")
        if classified.get("experimental_result_code") != code:
            errors.append(f"reserved success result {code} lost numeric identity")
        if "8.1.2" not in text or "2006-2020" not in text:
            errors.append(f"reserved success result {code} lacks the TS 29.230 8.1.2 limitation")

    boundary_success = model.classify_result(_experimental(2021, model.THREEGPP_VENDOR_ID))
    if boundary_success.get("experimental_result_code_name") is not None:
        errors.append("result 2021 received Cx success semantics")
    if any("2006-2020" in item for item in boundary_success.get("limitations", [])):
        errors.append("result 2021 was incorrectly classified into the reserved success range")

    for code in (5013, 5020):
        classified = model.classify_result(_experimental(code, model.THREEGPP_VENDOR_ID))
        text = " ".join(classified.get("limitations", []))
        if classified.get("application_result") != "UNRESOLVED":
            errors.append(f"reserved permanent-failure result {code} was not left unresolved")
        if classified.get("experimental_result_code_name") is not None:
            errors.append(f"reserved permanent-failure result {code} received a semantic name")
        if classified.get("experimental_result_code") != code:
            errors.append(f"reserved permanent-failure result {code} lost numeric identity")
        if "8.1.4" not in text or "5013-5020" not in text:
            errors.append(f"reserved permanent-failure result {code} lacks the TS 29.230 8.1.4 limitation")

    for code in (5021, 5040):
        classified = model.classify_result(_experimental(code, model.THREEGPP_VENDOR_ID))
        text = " ".join(classified.get("limitations", []))
        if classified.get("experimental_result_code_name") is not None:
            errors.append(f"result {code} received Cx/Dx semantics outside the TS 29.229 range")
        if classified.get("application_result") != "UNRESOLVED":
            errors.append(f"result {code} was not left unresolved")
        if "TS 32.299" not in text:
            errors.append(f"result {code} does not record the TS 32.299 reserved ownership")
        if code in model.THREEGPP_CX_RESERVED_PERMANENT_FAILURE_RESULT_CODES:
            errors.append(f"result {code} was conflated with the Cx permanent-failure reserved range")

    if model.THREEGPP_CX_RESERVED_SUCCESS_RESULT_CODES != frozenset(range(2006, 2021)):
        errors.append("reserved success range is not 2006-2020")
    if model.THREEGPP_CX_RESERVED_PERMANENT_FAILURE_RESULT_CODES != frozenset(range(5013, 5021)):
        errors.append("reserved permanent-failure range is not 5013-5020")
    if model.THREEGPP_OTHER_SPEC_RESERVED_RESULT_CODES != frozenset(range(5021, 5041)):
        errors.append("other-specification reserved range is not 5021-5040")
    if set(model.THREEGPP_CX_RESERVED_SUCCESS_RESULT_CODES) & set(
        model.THREEGPP_CX_RESERVED_PERMANENT_FAILURE_RESULT_CODES
    ):
        errors.append("success and permanent-failure reserved ranges overlap")

    unreviewed = model.classify_result(_experimental(5999, model.THREEGPP_VENDOR_ID))
    if unreviewed.get("experimental_result_code_name") is not None:
        errors.append("unreviewed result 5999 received a semantic name")
    if unreviewed.get("experimental_result_code") != 5999:
        errors.append("unreviewed result 5999 lost numeric identity")

    if set(model.THREEGPP_CX_SUCCESS_RESULT_NAMES) & set(model.THREEGPP_CX_FAILURE_RESULT_NAMES):
        errors.append("Cx success and failure result maps overlap")
    return errors


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
            print(f"validate-diameter-ims: {error}", file=sys.stderr)
        return 1

    try:
        import jsonschema
    except ImportError:
        print("validate-diameter-ims: jsonschema is required", file=sys.stderr)
        return 1
    schema = load_json(SKILL / "schemas" / "diameter-ims-analysis.schema.json")
    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for token in ('name: "diameter-ims"', 'version: "0.1.1"', "category: protocol", "diameter-core >=0.1.0"):
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
            if analysis:
                check_analysis(analysis, errors)
                if analysis.get("completeness", {}).get("observation_count", 0) < 10:
                    errors.append("example analysis did not publish the expected observation set")

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

        malformed_events = model.load_jsonl(EXAMPLES / "core/events.jsonl")
        malformed_events[0]["result"] = []
        malformed_path = directory / "malformed-result-events.jsonl"
        malformed_path.write_text(
            "\n".join(json.dumps(item) for item in malformed_events) + "\n", encoding="utf-8"
        )
        result = run(
            [
                sys.executable,
                str(CLI),
                "--events",
                str(malformed_path),
                "--transactions",
                str(EXAMPLES / "core/transactions.json"),
                "--output",
                str(directory / "malformed-result-out.json"),
            ]
        )
        if result.returncode != 2:
            errors.append("malformed result structure did not return exit code 2")

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

        transactions = model.load_json(EXAMPLES / "core/transactions.json")
        transactions["transactions"][0]["transaction_reference"] = "invalid"
        invalid_ref = directory / "invalid-ref.json"
        invalid_ref.write_text(json.dumps(transactions), encoding="utf-8")
        result = run(
            [
                sys.executable,
                str(CLI),
                "--events",
                str(EXAMPLES / "core/events.jsonl"),
                "--transactions",
                str(invalid_ref),
                "--output",
                str(directory / "invalid-ref-out.json"),
            ]
        )
        if result.returncode != 2:
            errors.append("invalid transaction reference did not return exit code 2")

        events = model.load_jsonl(EXAMPLES / "core/events.jsonl")
        transactions = model.load_json(EXAMPLES / "core/transactions.json")
        events.append(dict(events[0]))
        duplicate_events = directory / "duplicate-events.jsonl"
        duplicate_events.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
        result = run(
            [
                sys.executable,
                str(CLI),
                "--events",
                str(duplicate_events),
                "--transactions",
                str(EXAMPLES / "core/transactions.json"),
                "--output",
                str(directory / "duplicate-out.json"),
            ]
        )
        if result.returncode != 2:
            errors.append("duplicate event identity did not return exit code 2")

        no_cx_events = [
            item
            for item in model.load_jsonl(EXAMPLES / "core/events.jsonl")
            if item["application_id"] != model.CX_APPLICATION_ID
        ]
        no_cx_transactions = {
            "protocol": "Diameter",
            "capture_files": [no_cx_events[0]["capture_file"]],
            "transactions": [
                item
                for item in model.load_json(EXAMPLES / "core/transactions.json")["transactions"]
                if item["application_id"] != model.CX_APPLICATION_ID
                and item["command_code"] not in model.SUPPORTED_COMMAND_CODES
            ],
        }
        no_cx_events_path = directory / "no-cx-events.jsonl"
        no_cx_events_path.write_text(
            "\n".join(json.dumps(item) for item in no_cx_events) + "\n", encoding="utf-8"
        )
        no_cx_tx_path = directory / "no-cx-tx.json"
        no_cx_tx_path.write_text(json.dumps(no_cx_transactions), encoding="utf-8")
        result = run(
            [
                sys.executable,
                str(CLI),
                "--events",
                str(no_cx_events_path),
                "--transactions",
                str(no_cx_tx_path),
                "--output",
                str(directory / "no-cx-out.json"),
            ]
        )
        if result.returncode != 3:
            errors.append("no-Cx input did not return exit code 3")

    errors.extend(namespace_checks())

    if errors:
        for error in errors:
            print(f"validate-diameter-ims: {error}", file=sys.stderr)
        return 1
    print("diameter-ims validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())