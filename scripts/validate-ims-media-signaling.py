#!/usr/bin/env python3
"""Validate the standalone ims-media-signaling Domain Skill contract."""

from __future__ import annotations

import json
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "domain" / "ims-media-signaling"
SCRIPTS = SKILL / "scripts"
INPUTS = SKILL / "examples" / "inputs"
EXPECTED = SKILL / "examples" / "expected"
CLI = SCRIPTS / "analyze-ims-media-signaling.py"
SCHEMA = SKILL / "schemas" / "ims-media-signaling-analysis.schema.json"

sys.path.insert(0, str(SCRIPTS))
import ims_media_signaling_model  # noqa: E402

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/offer-answer-procedures.md",
    "references/evidence-model.md",
    "references/failure-cases.md",
    "references/privacy.md",
    "schemas/ims-media-signaling-analysis.schema.json",
    "scripts/analyze-ims-media-signaling.py",
    "scripts/ims_media_signaling_model.py",
    "tests/test_ims_media_signaling.py",
    "examples/inputs/media-cases-events.jsonl",
    "examples/inputs/media-cases-ims-session.json",
    "examples/inputs/media-cases-sdp-analysis.json",
    "examples/expected/media-analysis.json",
    "examples/expected/media-report.txt",
)
REQUIRED_TEST_TOKENS = tuple(f"test_{index:02d}_" for index in range(1, 93))
PRIVATE_TOKENS = (
    "sip:caller@example.com",
    "sip:callee@example.com",
    "192.0.2.10",
    "192.0.2.20",
    "PRIVATE-CALLID",
    "PRIVATE-FTAG",
    "PRIVATE-TTAG",
    "v=0",
    "m=audio",
    "a=rtpmap",
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _producer(directory: Path) -> tuple[Path, Path, subprocess.CompletedProcess]:
    output = directory / "analysis.json"
    report = directory / "report.txt"
    completed = run(
        [
            sys.executable,
            str(CLI),
            "--sip-events",
            str(INPUTS / "media-cases-events.jsonl"),
            "--ims-session",
            str(INPUTS / "media-cases-ims-session.json"),
            "--sdp-analysis",
            str(INPUTS / "media-cases-sdp-analysis.json"),
            "--output",
            str(output),
            "--report",
            str(report),
            "--force",
        ]
    )
    return output, report, completed


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
            print(f"validate-ims-media-signaling: {error}", file=sys.stderr)
        return 1

    try:
        import jsonschema
    except ImportError:
        print("validate-ims-media-signaling: jsonschema is required", file=sys.stderr)
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
        "exchange_count",
        "exchanges",
        "unbound_observation_count",
        "unbound_observations",
        "completeness",
        "limitations",
        "not_confirmed",
    ):
        if required not in schema.get("required", []):
            errors.append(f"schema is missing required property: {required}")
    if schema["properties"]["analysis_version"].get("const") != ims_media_signaling_model.ANALYSIS_VERSION:
        errors.append("schema analysis_version diverges from the model constant")
    for definition in ("exchange", "observation", "completeness", "input_provenance"):
        if schema["$defs"][definition].get("additionalProperties") is not False:
            errors.append(f"schema definition {definition} is not strict")

    manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
    for token in (
        "name: ims-media-signaling",
        "version: 0.3.0",
        "category: domain",
        "sip >=0.4.0",
        "sdp-rtp >=0.3.0",
        "ims-session >=0.1.0",
    ):
        if token not in manifest:
            errors.append(f"manifest missing {token}")

    test_source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((SKILL / "tests").glob("test_*.py"))
    )
    for token in REQUIRED_TEST_TOKENS:
        if token not in test_source:
            errors.append(f"test suite is missing required coverage: {token}")

    events = ims_media_signaling_model.load_events(INPUTS / "media-cases-events.jsonl")
    event_references = {event["source_reference"] for event in events}
    session = ims_media_signaling_model.load_session_analysis(
        INPUTS / "media-cases-ims-session.json", event_references
    )
    sdp = ims_media_signaling_model.load_sdp_analysis(INPUTS / "media-cases-sdp-analysis.json")
    provenance = ims_media_signaling_model.verify_provenance(
        events,
        session,
        sdp,
        events_path=INPUTS / "media-cases-events.jsonl",
        session_path=INPUTS / "media-cases-ims-session.json",
        sdp_path=INPUTS / "media-cases-sdp-analysis.json",
    )
    document = ims_media_signaling_model.build_analysis(
        events, session, sdp, provenance=provenance
    )
    try:
        jsonschema.validate(document, schema)
        ims_media_signaling_model.validate_analysis(
            document,
            event_references=event_references,
            sdp_references={message["source_reference"] for message in sdp["messages"]},
        )
    except (jsonschema.ValidationError, ims_media_signaling_model.InputError) as exc:
        errors.append(f"in-process schema or semantic validation failed: {exc}")

    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        output, report, completed = _producer(directory)
        if completed.returncode != 0:
            errors.append(f"producer failed: {completed.stderr.strip()}")
        else:
            for path, expected_name in (
                (output, "media-analysis.json"),
                (report, "media-report.txt"),
            ):
                if path.read_bytes() != (EXPECTED / expected_name).read_bytes():
                    errors.append(f"{expected_name} differs from the committed expectation")
            produced = load_json(output)
            try:
                jsonschema.validate(produced, schema)
                ims_media_signaling_model.validate_analysis(
                    produced,
                    event_references=event_references,
                    sdp_references={message["source_reference"] for message in sdp["messages"]},
                )
            except (jsonschema.ValidationError, ims_media_signaling_model.InputError) as exc:
                errors.append(f"schema or semantic validation failed: {exc}")
            text = json.dumps(produced) + report.read_text(encoding="utf-8")
            for secret in PRIVATE_TOKENS:
                if secret in text:
                    errors.append(f"output leaked a sensitive value: {secret}")
            for field in ('"call_id"', '"from_tag"', '"to_tag"', '"request_uri"', '"sip_uri"'):
                if field in text:
                    errors.append(f"output publishes a raw identity field: {field}")
            for exchange in produced["exchanges"]:
                if exchange["negotiation_compatibility"] != "NOT_EVALUATED":
                    errors.append("negotiation compatibility was claimed")
                if exchange["evidence_class"] != "DERIVED":
                    errors.append("an exchange evidence class diverged")
                if (
                    exchange["association_status"] == "ESTABLISHED"
                    and exchange["exchange_type"]
                    in ("INITIAL_INVITE_OFFER_ANSWER", "LATE_OFFER_ANSWER")
                    and (
                        not exchange["answer_sdp_reference"]
                        or not exchange["branch_reference"]
                        or not exchange["dialog_reference"]
                        or exchange["branch_identity_status"] != "ESTABLISHED"
                    )
                ):
                    errors.append("an established branch-scoped exchange lacks identity or an answer")
                if (
                    exchange["exchange_type"] == "INITIAL_INVITE_WITHOUT_SDP"
                    and exchange["initial_sdp_state"] != "ABSENT"
                ):
                    errors.append("INITIAL_INVITE_WITHOUT_SDP was published without proven absence")
                if (
                    exchange["association_status"] != "ESTABLISHED"
                    and (exchange["offer_role"] or exchange["answer_role"])
                ):
                    errors.append("an unestablished exchange claimed an offer or answer role")
            completeness = produced["completeness"]
            if completeness["supplied_sdp_message_count"] != (
                completeness["matched_sip_event_count"]
                + completeness["unmatched_sdp_message_count"]
            ):
                errors.append("SDP message count conservation failed")
            if (
                completeness["established_exchange_count"]
                + completeness["incomplete_exchange_count"]
                + completeness["ambiguous_exchange_count"]
                + completeness["not_established_exchange_count"]
            ) != len(produced["exchanges"]):
                errors.append("exchange status count conservation failed")

            second = directory / "second-analysis.json"
            rerun = run(
                [
                    sys.executable,
                    str(CLI),
                    "--sip-events",
                    str(INPUTS / "media-cases-events.jsonl"),
                    "--ims-session",
                    str(INPUTS / "media-cases-ims-session.json"),
                    "--sdp-analysis",
                    str(INPUTS / "media-cases-sdp-analysis.json"),
                    "--output",
                    str(second),
                    "--force",
                ]
            )
            if rerun.returncode != 0:
                errors.append(f"deterministic rerun failed: {rerun.stderr.strip()}")
            elif second.read_bytes() != output.read_bytes():
                errors.append("analysis is not deterministic")

            missing = directory / "missing.json"
            missing.write_text('{"analysis_name": "other"}', encoding="utf-8")
            missing_output = directory / "missing-output.json"
            missing_run = run(
                [
                    sys.executable,
                    str(CLI),
                    "--sip-events",
                    str(INPUTS / "media-cases-events.jsonl"),
                    "--ims-session",
                    str(missing),
                    "--sdp-analysis",
                    str(INPUTS / "media-cases-sdp-analysis.json"),
                    "--output",
                    str(missing_output),
                    "--force",
                ]
            )
            if missing_run.returncode == 0:
                errors.append("an invalid IMS Session artifact was accepted")

            collision = run(
                [
                    sys.executable,
                    str(CLI),
                    "--sip-events",
                    str(INPUTS / "media-cases-events.jsonl"),
                    "--ims-session",
                    str(INPUTS / "media-cases-ims-session.json"),
                    "--sdp-analysis",
                    str(INPUTS / "media-cases-sdp-analysis.json"),
                    "--output",
                    str(INPUTS / "media-cases-events.jsonl"),
                    "--force",
                ]
            )
            if collision.returncode == 0:
                errors.append("an output destination colliding with an input was accepted")

    if errors:
        for error in errors:
            print(f"validate-ims-media-signaling: {error}", file=sys.stderr)
        return 1
    print("ims-media-signaling validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())