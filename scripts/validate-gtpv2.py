#!/usr/bin/env python3
"""Validate the standalone gtpv2 Protocol Skill contract."""

from __future__ import annotations

import argparse
import importlib.util
import json
import py_compile
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "protocol" / "gtpv2"

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/protocol-model.md",
    "references/procedure-map.md",
    "references/field-reference.md",
    "references/correlation.md",
    "references/failure-cases.md",
    "scripts/gtpv2_model.py",
    "scripts/extract-gtpv2.py",
    "scripts/correlate-gtpv2.py",
    "scripts/gtpv2_timeline.py",
    "schemas/gtpv2-event.schema.json",
    "schemas/gtpv2-transaction.schema.json",
    "schemas/trace-event.schema.json",
    "filters/wireshark.txt",
    "tests/test_gtpv2.py",
    "tests/test_gtpv2_dedicated_bearer.py",
    "examples/pdml/session-control.pdml",
    "examples/pdml/bearer-control.pdml",
)

EXTRACTION_FIXTURES = {
    "examples/pdml/session-control.pdml": "examples/expected/session-control-events.jsonl",
    "examples/pdml/multi-bearer-context.pdml": "examples/expected/multi-bearer-context-events.jsonl",
    "examples/pdml/bearer-control.pdml": "examples/expected/bearer-control-events.jsonl",
    "examples/extracted/session-control-fields.jsonl": "examples/expected/session-control-fields-events.jsonl",
    "examples/extracted/teid-states.jsonl": "examples/expected/teid-states-events.jsonl",
    "examples/extracted/unsupported-messages.jsonl": "examples/expected/unsupported-messages-events.jsonl",
}

CORRELATION_FIXTURES = {
    "examples/expected/session-control-events.jsonl": "examples/expected/session-control-transactions.json",
    "examples/expected/session-control-fields-events.jsonl": "examples/expected/session-control-fields-transactions.json",
    "examples/expected/teid-states-events.jsonl": "examples/expected/teid-states-transactions.json",
    "examples/expected/bearer-control-events.jsonl": "examples/expected/bearer-control-transactions.json",
    "examples/extracted/correlation-ambiguous-events.jsonl": "examples/expected/correlation-ambiguous-transactions.json",
    "examples/extracted/correlation-retransmission-events.jsonl": "examples/expected/correlation-retransmission-transactions.json",
    "examples/extracted/correlation-response-only-events.jsonl": "examples/expected/correlation-response-only-transactions.json",
    "examples/extracted/correlation-endpoints-events.jsonl": "examples/expected/correlation-endpoints-transactions.json",
}

ERROR_FIXTURES = (
    "examples/extracted/malformed.jsonl",
    "examples/extracted/missing-required.jsonl",
)

FORBIDDEN_EVENT_KEYS = {
    "imsi",
    "mei",
    "msisdn",
    "tmsi",
    "apn",
    "apn_name",
    "paa_address",
    "pdn_address",
    "raw_bytes",
    "payload",
    "ie_raw",
}

LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s*[0-9]+\b|\bmilestone\s*[a-z]?[0-9]+\b")
HEX_BLOB = re.compile(r"\b[0-9a-fA-F]{64,}\b")
LONG_DIGITS = re.compile(r"\d{14,}")
NON_ZERO_LONG_DIGITS = re.compile(r"(?<![0])\d{14,}")
PRIVATE_MARKERS = ("internet", "10.45.0.7")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def read_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path.name} line {number}: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"{path.name} line {number}: record is not an object")
        records.append(record)
    return records


def produced_events(model, path: Path) -> list[dict]:
    if path.suffix.lower() in {".pdml", ".xml"}:
        with path.open("rb") as handle:
            return list(model.pdml_events(handle, path.name))
    return [model.normalize_flat_record(record, path.name) for record in read_jsonl(path)]


def validate(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    skill = root / "skills" / "protocol" / "gtpv2"

    def fail(message: str) -> None:
        errors.append(message)

    if not skill.is_dir():
        return ["missing Skill directory: skills/protocol/gtpv2"]

    for relative in REQUIRED:
        if not (skill / relative).is_file():
            fail(f"missing required file: skills/protocol/gtpv2/{relative}")
    if errors:
        return errors

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    if not re.search(r"(?m)^name:\s*gtpv2\s*$", manifest):
        fail("manifest name must be gtpv2")
    if not re.search(r"(?m)^category:\s*protocol\s*$", manifest):
        fail("manifest category must be protocol")
    if not re.search(r"(?m)^version:\s*\d+\.\d+\.\d+\s*$", manifest):
        fail("manifest version must be a semantic version")

    for schema_name in (
        "schemas/gtpv2-event.schema.json",
        "schemas/gtpv2-transaction.schema.json",
        "schemas/trace-event.schema.json",
    ):
        try:
            schema = json.loads((skill / schema_name).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"invalid JSON schema {schema_name}: {exc}")
            continue
        if schema_name.endswith("gtpv2-event.schema.json"):
            required = set(schema.get("required", []))
            for field in (
                "frame_number",
                "message_type",
                "header",
                "message_cause",
                "bearer_contexts",
                "hierarchy_basis",
                "evidence",
            ):
                if field not in required:
                    fail(f"event schema does not require '{field}'")
            properties = schema.get("properties", {})
            if "apn" in properties or "imsi" in properties:
                fail("event schema must not expose subscriber identity or APN name properties")
        if schema_name.endswith("gtpv2-transaction.schema.json"):
            text = json.dumps(schema)
            for status in ("MATCHED", "OPEN_REQUEST", "RESPONSE_ONLY", "AMBIGUOUS"):
                if status not in text:
                    fail(f"transaction schema is missing the {status} classification")

    skill_md = (skill / "SKILL.md").read_text(encoding="utf-8")
    for section in ("## Scope", "## Non-Goals", "## Inputs", "## Outputs", "## Evidence", "## Failure Behavior"):
        if section not in skill_md:
            fail(f"SKILL.md is missing the '{section}' section")

    for path in sorted(skill.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
            fail(f"raw capture committed inside the Skill: {path.relative_to(root)}")
            continue
        if path.suffix.lower() not in {".md", ".py", ".yaml", ".json", ".jsonl", ".txt", ".pdml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if LIFECYCLE_MARKER.search(text):
            fail(f"lifecycle marker in {path.relative_to(root)}")

    for script in (skill / "scripts").glob("*.py"):
        try:
            py_compile.compile(str(script), doraise=True)
        except py_compile.PyCompileError as exc:
            fail(f"script does not compile: {script.name}: {exc}")

    for fixture in ERROR_FIXTURES:
        if not (skill / fixture).is_file():
            fail(f"missing error fixture: {fixture}")

    model = load_module("gtpv2_model_under_test", skill / "scripts" / "gtpv2_model.py")
    correlate = load_module("gtpv2_correlate_under_test", skill / "scripts" / "correlate-gtpv2.py")

    for code, expected_name in ((170, "Release Access Bearers Request"), (171, "Release Access Bearers Response")):
        if model.MESSAGE_TYPES.get(code) != expected_name:
            fail(f"message type {code} must be '{expected_name}'")
    if model.MESSAGE_TYPES.get(149) != "Detach Notification":
        fail("message type 149 must be 'Detach Notification'")
    if model.CAUSES.get(16) != "Request accepted":
        fail("cause 16 must be 'Request accepted'")
    if model.INTERFACE_TYPES.get(11) != "S11/S4 SGW GTP-C interface":
        fail("F-TEID interface type 11 must be 'S11/S4 SGW GTP-C interface'")

    for fixture, expected in EXTRACTION_FIXTURES.items():
        fixture_path = skill / fixture
        expected_path = skill / expected
        if not fixture_path.is_file() or not expected_path.is_file():
            fail(f"missing fixture or expected file: {fixture} -> {expected}")
            continue
        try:
            produced = produced_events(model, fixture_path)
            golden = read_jsonl(expected_path)
        except (ValueError, model.InputError) as exc:
            fail(f"{fixture}: {exc}")
            continue
        if produced != golden:
            fail(f"{fixture}: produced events do not match {expected}")
        for event in golden:
            forbidden = FORBIDDEN_EVENT_KEYS & set(event)
            if forbidden:
                fail(f"{expected}: publishes forbidden evidence field(s) {sorted(forbidden)}")
            serialized = json.dumps(event)
            if HEX_BLOB.search(serialized):
                fail(f"{expected}: publishes a long hex payload blob")
            for marker in PRIVATE_MARKERS:
                if marker in serialized:
                    fail(f"{expected}: publishes private value '{marker}'")

    for fixture, expected in CORRELATION_FIXTURES.items():
        fixture_path = skill / fixture
        expected_path = skill / expected
        if not fixture_path.is_file() or not expected_path.is_file():
            fail(f"missing correlation fixture or expected file: {fixture} -> {expected}")
            continue
        try:
            produced = correlate.correlate(read_jsonl(fixture_path))
            golden = json.loads(expected_path.read_text(encoding="utf-8"))
        except (ValueError, model.InputError) as exc:
            fail(f"{fixture}: {exc}")
            continue
        if produced != golden:
            fail(f"{fixture}: produced transactions do not match {expected}")

    ambiguous = json.loads(
        (skill / "examples/expected/correlation-ambiguous-transactions.json").read_text(encoding="utf-8")
    )
    if ambiguous["ambiguous_count"] < 1:
        fail("the ambiguous fixture must produce an AMBIGUOUS transaction")
    for item in ambiguous["transactions"]:
        if item["correlation_status"] == "AMBIGUOUS" and not item["response_candidates"]:
            fail("an AMBIGUOUS transaction must keep its response candidates")

    retransmission = json.loads(
        (skill / "examples/expected/correlation-retransmission-transactions.json").read_text(encoding="utf-8")
    )
    if retransmission["retransmission_count"] < 1:
        fail("the retransmission fixture must report a retransmission")

    response_only = json.loads(
        (skill / "examples/expected/correlation-response-only-transactions.json").read_text(encoding="utf-8")
    )
    if response_only["response_only_count"] < 1:
        fail("the response-only fixture must report RESPONSE_ONLY evidence")

    flat_events = read_jsonl(skill / "examples/expected/session-control-fields-events.jsonl")
    for event in flat_events:
        if event["bearer_contexts"]:
            fail("flat fields input must never publish a bearer context")
        if event["hierarchy_basis"] != "flat_fields":
            fail("flat fields input must record hierarchy_basis 'flat_fields'")
        for item in event["f_teids"]:
            if item["scope"] != "unbound":
                fail("flat fields input must publish F-TEID scope 'unbound'")

    pdml_events = read_jsonl(skill / "examples/expected/session-control-events.jsonl")
    bearer_causes = [
        context["cause"]
        for event in pdml_events
        for context in event["bearer_contexts"]
        if context.get("cause")
    ]
    if not bearer_causes:
        fail("PDML input must publish bearer-scope Cause evidence")
    for cause in bearer_causes:
        if cause["scope"] != "bearer":
            fail("a bearer-context Cause must keep scope 'bearer'")
    message_causes = [event["message_cause"] for event in pdml_events if event.get("message_cause")]
    if not message_causes:
        fail("PDML input must publish message-scope Cause evidence")
    for cause in message_causes:
        if cause["scope"] != "message":
            fail("a message Cause must keep scope 'message'")

    teid_states = {event["header"]["teid_state"] for event in read_jsonl(skill / "examples/expected/teid-states-events.jsonl")}
    if not {"ABSENT", "ZERO", "PRESENT"}.issubset(teid_states):
        fail("the header TEID states ABSENT, ZERO and PRESENT must all be exercised")

    unsupported = read_jsonl(skill / "examples/expected/unsupported-messages-events.jsonl")
    statuses = {event["support_status"] for event in unsupported}
    if "UNSUPPORTED" not in statuses or "UNKNOWN" not in statuses:
        fail("unsupported and unknown message codes must both be reported explicitly")

    bearer_events = read_jsonl(skill / "examples/expected/bearer-control-events.jsonl")
    expected_families = {
        95: "create-bearer",
        96: "create-bearer",
        97: "update-bearer",
        98: "update-bearer",
        99: "delete-bearer",
        100: "delete-bearer",
    }
    for code, family in expected_families.items():
        name, status, procedure, message_family = model.resolve_message(code)
        if name is None or status != "SUPPORTED" or procedure != family or message_family != family:
            fail(f"message type {code} must be SUPPORTED in family '{family}'")
    expected_pairs = [(95, 96), (97, 98), (99, 100)]
    bearer_transactions = json.loads(
        (skill / "examples/expected/bearer-control-transactions.json").read_text(encoding="utf-8")
    )
    actual_pairs = [
        (item["request"]["message_type_code"], item["response"]["message_type_code"])
        for item in bearer_transactions["transactions"]
        if item.get("request") and item.get("response")
    ]
    if actual_pairs != expected_pairs:
        fail("dedicated-bearer request/response pairs must be 95->96, 97->98 and 99->100")
    if bearer_transactions["matched_count"] != 3 or bearer_transactions["retransmission_count"] != 1:
        fail("dedicated-bearer transactions must match three pairs and group one retransmission")
    request_contexts = bearer_events[0]["bearer_contexts"]
    response_contexts = bearer_events[1]["bearer_contexts"]
    if [item["item_index"] for item in request_contexts] != [0, 1]:
        fail("grouped Bearer Context items must preserve item_index")
    if [item["ebi"] for item in request_contexts] != [5, 6]:
        fail("grouped Bearer Context items must preserve item-scoped EBI")
    if [item["cause"]["cause_code"] for item in response_contexts] != [16, 73]:
        fail("grouped Bearer Context items must preserve item-scoped Cause")
    if any(item["cause"]["scope"] != "bearer" for item in response_contexts):
        fail("bearer-level Cause must keep scope 'bearer'")
    if bearer_events[1]["message_cause"]["cause_code"] != 16:
        fail("message-level Cause must remain separate from bearer-level Cause")
    if not request_contexts[0].get("qos") or not request_contexts[0].get("tft"):
        fail("decoder-proven bearer QoS and TFT presence must be published")
    if any(
        item.get("other_ie_names") and "Bearer QoS" in item["other_ie_names"]
        for item in request_contexts
    ):
        fail("Bearer QoS must not be published only as an unmodelled IE name")
    for item in bearer_transactions["transactions"]:
        if "lifecycle" in json.dumps(item).lower():
            fail("a matched dedicated-bearer transaction must not publish lifecycle state")

    original_layer_event = model.layer_event
    try:
        def flattened(layer, frame, capture_file, occurrence):
            event = original_layer_event(layer, frame, capture_file, occurrence)
            if event.get("bearer_contexts"):
                event["bearer_contexts"] = [event["bearer_contexts"][0]]
            return event

        model.layer_event = flattened
        with (skill / "examples/pdml/bearer-control.pdml").open("rb") as handle:
            mutated_events = list(model.pdml_events(handle, "mutated.pdml"))
    finally:
        model.layer_event = original_layer_event
    if len(mutated_events[0]["bearer_contexts"]) != 1:
        fail("mutation check failed: flattening multiple Bearer Context items was not detected")
    with (skill / "examples/pdml/bearer-control.pdml").open("rb") as handle:
        restored_events = list(model.pdml_events(handle, "restored.pdml"))
    if len(restored_events[0]["bearer_contexts"]) != 2:
        fail("mutation restore failed: grouped Bearer Context items stayed flat")

    try:
        def promoted(layer, frame, capture_file, occurrence):
            event = original_layer_event(layer, frame, capture_file, occurrence)
            if event.get("message_type_code") == 96 and event.get("bearer_contexts"):
                cause = event["bearer_contexts"][1]["cause"]
                if cause is not None:
                    event["message_cause"] = dict(cause, scope="message")
            return event

        model.layer_event = promoted
        with (skill / "examples/pdml/bearer-control.pdml").open("rb") as handle:
            promoted_events = list(model.pdml_events(handle, "promoted.pdml"))
    finally:
        model.layer_event = original_layer_event
    if promoted_events[1]["message_cause"]["cause_code"] != 73:
        fail("mutation check failed: bearer Cause promotion was not detected")
    with (skill / "examples/pdml/bearer-control.pdml").open("rb") as handle:
        restored_promoted = list(model.pdml_events(handle, "restored-promoted.pdml"))
    if restored_promoted[1]["message_cause"]["cause_code"] != 16:
        fail("mutation restore failed: message Cause stayed promoted")

    original_request_codes = dict(correlate.REQUEST_CODES)
    try:
        correlate.REQUEST_CODES = {
            code: response for code, response in original_request_codes.items() if code != 95
        }
        mutated_transactions = correlate.correlate(bearer_events)
    finally:
        correlate.REQUEST_CODES = original_request_codes
    if any(
        item.get("procedure_family") == "create-bearer"
        and item.get("correlation_status") == "MATCHED"
        for item in mutated_transactions["transactions"]
    ):
        fail("mutation check failed: removing the 95->96 mapping was not detected")
    restored_transactions = correlate.correlate(bearer_events)
    if not any(
        item.get("procedure_family") == "create-bearer"
        and item.get("correlation_status") == "MATCHED"
        for item in restored_transactions["transactions"]
    ):
        fail("mutation restore failed: the 95->96 mapping stayed removed")

    for pdml_name in ("session-control.pdml", "bearer-control.pdml"):
        pdml_text = (skill / "examples/pdml" / pdml_name).read_text(encoding="utf-8")
        for marker in ("460020000000001", "919000001", "1122334455667788"):
            if marker in pdml_text:
                fail(f"{pdml_name} still contains a subscriber identity value")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("gtpv2 validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("gtpv2 validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
