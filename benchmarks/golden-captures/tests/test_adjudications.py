#!/usr/bin/env python3
"""Deterministic contract tests for the Domain deviation adjudication area.

Covers the adjudication schemas, the bounded status vocabulary, evidence anchors,
sanitization, summary aggregation, and every committed case adjudication when one
exists. No network access, no capture files, and no Skill runtime is imported.
"""

from __future__ import annotations

import copy
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_DIR = ROOT / "benchmarks" / "golden-captures"
ADJ_DIR = BENCHMARK_DIR / "adjudications"
ADJ_CASES_DIR = ADJ_DIR / "cases"
ADJ_SCHEMA_DIR = ADJ_DIR / "schemas"

DEVIATION_SCHEMA_NAME = "deviation-adjudication.schema.json"
CASE_SCHEMA_NAME = "case-adjudication.schema.json"

STATUSES = (
    "SUPPORTED_BY_PACKET_EVIDENCE",
    "VALID_CAPTURE_LIMITATION",
    "POTENTIALLY_SPURIOUS",
    "UNSUPPORTED_BY_PACKET_EVIDENCE",
    "INSUFFICIENT_EVIDENCE",
    "OUT_OF_IMPLEMENTED_SCOPE",
)
LAYERS = (
    "PROTOCOL_EXTRACTION",
    "CORRELATION",
    "DOMAIN_INSTANCE_FORMATION",
    "DOMAIN_STAGE_ACTIVATION",
    "DOMAIN_DEVIATION_EMISSION",
    "ORCHESTRATION_CANDIDATE_CONSTRUCTION",
    "ORCHESTRATION_ORDERING",
    "HUMAN_BASELINE",
    "CAPTURE_LIMITATION",
    "NONE_OBSERVED",
)
CAUSE_FIELD_PATTERN = re.compile(
    r"(?i)^(?:root_cause|root_cause_confidence|culprit|responsible_nf|implementation_"
    r"(?:bug|blame|defect)|vendor_fault|network_function_blame|cause|caused_by|attribution)$"
)
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|/(?:home|users)/|[a-z]:\\\\)")
SUBSCRIBER_VALUE = re.compile(r'(?i)"(?:imsi|supi|suci|msisdn|imei)"\s*:\s*"[^"\n]+"')
AUTH_VECTOR = re.compile(r'(?i)"(?:rand|autn|res\*?|hxres\*?|kausf|kseaf|kamf)"\s*:\s*"[^"\n]+"')
RAW_DUMP_NAMES = {"ngap-events.jsonl", "nas-5gs-events.jsonl", "pfcp-events.jsonl",
                  "gtpu-events.jsonl", "sbi-events.jsonl", "correlation-groups.jsonl"}

_TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def _type_ok(value, expected) -> bool:
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        python_type = _TYPE_MAP.get(name)
        if python_type is None:
            continue
        if name in ("integer", "number") and isinstance(value, bool):
            continue
        if isinstance(value, python_type):
            return True
    return False


def validate(instance, schema: dict, prefix: str = "", schemas: dict | None = None) -> list[str]:
    """Validate against the JSON Schema subset used by the adjudication contracts."""
    schemas = schemas if schemas is not None else load_schemas()
    errors: list[str] = []

    ref = schema.get("$ref")
    if ref is not None:
        target = schemas.get(str(ref).split("/")[-1])
        if target is None:
            return [f"{prefix}: unresolved $ref {ref}"]
        return validate(instance, target, prefix, schemas)

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{prefix}: expected const {schema['const']!r}, got {instance!r}")
    if "type" in schema and not _type_ok(instance, schema["type"]):
        return errors + [f"{prefix}: expected {schema['type']}, got {type(instance).__name__}"]

    if "if" in schema and not validate(instance, schema["if"], prefix, schemas):
        then = schema.get("then", {})
        errors.extend(validate(instance, {"required": then.get("required", [])}, prefix, schemas))
        for key, subschema in (then.get("properties") or {}).items():
            if key in instance:
                errors.extend(validate(instance[key], subschema, f"{prefix}.{key}", schemas))

    for combinator in ("allOf", "anyOf"):
        if combinator in schema:
            branches = [validate(instance, branch, prefix, schemas) for branch in schema[combinator]]
            if combinator == "allOf":
                errors.extend(error for branch in branches for error in branch)
            elif all(branch for branch in branches):
                errors.append(f"{prefix}: matches none of {combinator}")

    if isinstance(instance, dict):
        for required in schema.get("required", []):
            if required not in instance:
                errors.append(f"{prefix}: missing required property '{required}'")
        properties = schema.get("properties", {})
        allow_extra = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in properties:
                errors.extend(validate(value, properties[key], f"{prefix}.{key}", schemas))
            elif not allow_extra:
                errors.append(f"{prefix}.{key}: additional property '{key}' is not allowed")
    elif isinstance(instance, list):
        items = schema.get("items")
        if items:
            for index, item in enumerate(instance):
                errors.extend(validate(item, items, f"{prefix}[{index}]", schemas))
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{prefix}: fewer than minItems {schema['minItems']}")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{prefix}: more than maxItems {schema['maxItems']}")
    elif isinstance(instance, str):
        if "enum" in schema and instance not in schema["enum"]:
            errors.append(f"{prefix}: '{instance}' not in enum")
        if "pattern" in schema and not re.match(schema["pattern"], instance):
            errors.append(f"{prefix}: '{instance}' does not match pattern {schema['pattern']}")
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{prefix}: shorter than minLength")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{prefix}: longer than maxLength")
    elif isinstance(instance, int) and not isinstance(instance, bool):
        if "enum" in schema and instance not in schema["enum"]:
            errors.append(f"{prefix}: {instance} not in enum")
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{prefix}: {instance} below minimum {schema['minimum']}")
    return errors


def load(name: str) -> dict:
    return json.loads((ADJ_SCHEMA_DIR / name).read_text(encoding="utf-8"))


def load_schemas() -> dict:
    return {name: load(name) for name in (DEVIATION_SCHEMA_NAME, CASE_SCHEMA_NAME)}


def deviation_item(**overrides) -> dict:
    item = {
        "adjudication_id": "adj-01",
        "kind": "DOMAIN_DEVIATION",
        "source_domain": "5gc-registration-mobility",
        "source_instance_id": "5gc-reg:example.pcap:sctp-assoc-0:r1",
        "candidate_id": None,
        "deviation_type": "PROTECTED_INNER_MESSAGE_UNAVAILABLE",
        "stage_id": None,
        "status": "VALID_CAPTURE_LIMITATION",
        "finality": "FINAL",
        "evidence_level": "OBSERVED",
        "observation_ref": {
            "capture_file": "example.pcap",
            "frame_number": 13,
            "window_first_frame": None,
            "window_last_frame": None,
            "protocol": "NAS-5GS",
            "message_type": None,
        },
        "packet_evidence": [
            {
                "capture_file": "example.pcap",
                "frame_number": 13,
                "field": "nas_5gs.security_header_type",
                "observed_value": "4",
            }
        ],
        "equivalent_evidence_basis_ids": [],
        "proposed_owner_domain": "5gc-registration-mobility",
        "correction_ref": None,
        "rationale": "The frame carries a ciphered NAS envelope with no dissector message identity.",
        "uncertainty": None,
    }
    item.update(overrides)
    return item


def case_document(**overrides) -> dict:
    document = {
        "schema_name": "case-adjudication",
        "adjudication_revision": 1,
        "case_id": "public-5gc-example-case",
        "capture_file": "example.pcap",
        "capture_sha256": "0" * 64,
        "runtime_provenance": {
            "corenet_commit": "0" * 40,
            "source_commit": "0" * 40,
            "tshark_version": "TShark (Wireshark) 4.7.1",
            "domain_skill_versions": {
                "5gc-registration-mobility": "0.2.1",
                "5gc-pdu-session": "0.4.1",
                "5gc-handover-mobility": "0.1.1",
            },
        },
        "protocol_health": {"ngap": "SUCCESS_WITH_UNSUPPORTED_SEMANTICS", "nas-5gs": "SUCCESS"},
        "human_baseline_status": "NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED",
        "comparison_status": "NEEDS_ADJUDICATION",
        "first_differing_layer": "CAPTURE_LIMITATION",
        "status_counts": {status: 0 for status in STATUSES},
        "adjudications": [deviation_item()],
        "limitations": ["Adjudication is limited to packet evidence observable from this capture vantage point."],
    }
    document["status_counts"][deviation_item()["status"]] += 1
    document.update(overrides)
    return document


def committed_cases() -> list[tuple[Path, dict]]:
    if not ADJ_CASES_DIR.is_dir():
        return []
    return [(path, json.loads(path.read_text(encoding="utf-8"))) for path in sorted(ADJ_CASES_DIR.glob("*.json"))]


class AdjudicationAreaStructureTests(unittest.TestCase):
    def test_area_and_schemas_exist(self):
        self.assertTrue((ADJ_DIR / "README.md").is_file())
        for name in (DEVIATION_SCHEMA_NAME, CASE_SCHEMA_NAME):
            self.assertTrue((ADJ_SCHEMA_DIR / name).is_file(), name)

    def test_schemas_are_draft_2020_12_and_closed(self):
        for name in (DEVIATION_SCHEMA_NAME, CASE_SCHEMA_NAME):
            schema = load(name)
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema", name)
            self.assertIn("$id", schema, name)
            self.assertFalse(schema["additionalProperties"], name)

    def test_status_vocabulary_is_bounded_and_shared_with_schema(self):
        schema = load(DEVIATION_SCHEMA_NAME)
        self.assertEqual(sorted(schema["properties"]["status"]["enum"]), sorted(STATUSES))
        counts = load(CASE_SCHEMA_NAME)["properties"]["status_counts"]
        self.assertEqual(sorted(counts["properties"]), sorted(STATUSES))

    def test_layer_vocabulary_is_bounded(self):
        schema = load(CASE_SCHEMA_NAME)
        self.assertEqual(sorted(schema["properties"]["first_differing_layer"]["enum"]), sorted(LAYERS))

    def test_no_cause_attribution_field_is_declared_anywhere(self):
        text = "\n".join(path.read_text(encoding="utf-8")
                         for path in sorted(ADJ_DIR.rglob("*.json")))
        for key in re.findall(r'"([A-Za-z0-9_]+)"\s*:\s', text):
            self.assertFalse(CAUSE_FIELD_PATTERN.match(key), f"forbidden cause field declared: {key}")


class DeviationContractTests(unittest.TestCase):
    def setUp(self):
        self.schemas = load_schemas()

    def check(self, item):
        return validate(item, self.schemas[DEVIATION_SCHEMA_NAME], "item", self.schemas)

    def test_valid_item_passes(self):
        self.assertEqual(self.check(deviation_item()), [])

    def test_status_enum_is_bounded(self):
        item = deviation_item(status="DEFINITELY_SPURIOUS")
        self.assertTrue(any("not in enum" in error for error in self.check(item)))

    def test_evidence_level_enum_is_bounded(self):
        item = deviation_item(evidence_level="HYPOTHESIS")
        self.assertTrue(any("evidence_level" in error for error in self.check(item)))

    def test_source_domain_enum_is_bounded(self):
        item = deviation_item(source_domain="ngap")
        self.assertTrue(any("source_domain" in error for error in self.check(item)))

    def test_deviation_type_enum_is_bounded(self):
        item = deviation_item(deviation_type="INVENTED_DEVIATION")
        self.assertTrue(any("deviation_type" in error for error in self.check(item)))

    def test_frame_anchor_or_window_anchor_is_required(self):
        item = deviation_item(observation_ref={
            "capture_file": "example.pcap", "frame_number": None,
            "window_first_frame": None, "window_last_frame": None,
            "protocol": None, "message_type": None,
        })
        self.assertTrue(any("anyOf" in error for error in self.check(item)))

    def test_window_must_be_ordered_pair(self):
        item = deviation_item(observation_ref={
            "capture_file": "example.pcap", "frame_number": None,
            "window_first_frame": 20, "window_last_frame": None,
            "protocol": None, "message_type": None,
        })
        self.assertTrue(any("anyOf" in error for error in self.check(item)))

    def test_observed_level_requires_packet_evidence(self):
        item = deviation_item(packet_evidence=[])
        self.assertTrue(any("packet_evidence" in error for error in self.check(item)))

    def test_derived_absence_may_have_no_packet_evidence_rows(self):
        item = deviation_item(
            evidence_level="DERIVED",
            deviation_type="MISSING_EXPECTED_COUNTERPART",
            packet_evidence=[],
            observation_ref={
                "capture_file": "example.pcap", "frame_number": None,
                "window_first_frame": 9, "window_last_frame": 60,
                "protocol": None, "message_type": None,
            },
        )
        self.assertEqual(self.check(item), [])

    def test_potentially_spurious_must_stay_nonfinal(self):
        item = deviation_item(status="POTENTIALLY_SPURIOUS", finality="FINAL")
        self.assertTrue(any("finality" in error for error in self.check(item)))

    def test_candidate_kind_requires_candidate_id(self):
        item = deviation_item(kind="ORCHESTRATION_CANDIDATE", status="SUPPORTED_BY_PACKET_EVIDENCE")
        self.assertTrue(any("candidate_id" in error for error in self.check(item)))

    def test_deviation_kind_rejects_candidate_id(self):
        item = deviation_item(candidate_id="1-cand-1")
        self.assertTrue(any("candidate_id" in error for error in self.check(item)))

    def test_candidate_shape_round_trips(self):
        item = deviation_item(
            kind="ORCHESTRATION_CANDIDATE",
            candidate_id="1-cand-2",
            deviation_type="MISSING_EXPECTED_COUNTERPART",
            status="POTENTIALLY_SPURIOUS",
            finality="NONFINAL",
            evidence_level="DERIVED",
            packet_evidence=[],
            observation_ref={
                "capture_file": "example.pcap", "frame_number": None,
                "window_first_frame": 9, "window_last_frame": 15,
                "protocol": None, "message_type": None,
            },
        )
        self.assertEqual(self.check(item), [])

    def test_additional_properties_are_rejected(self):
        item = deviation_item(network_function_blame="amf")
        self.assertTrue(any("additional property" in error for error in self.check(item)))

    def test_capture_reference_must_be_a_bare_file_name(self):
        for bad in ("dir/example.pcap", "C:\\Users\\me\\example.pcap", "example.txt"):
            with self.subTest(capture=bad):
                item = copy.deepcopy(deviation_item())
                item["observation_ref"]["capture_file"] = bad
                self.assertTrue(any("capture_file" in error for error in self.check(item)))

    def test_packet_evidence_field_names_are_structured(self):
        item = copy.deepcopy(deviation_item())
        item["packet_evidence"][0]["field"] = "Info column"
        self.assertTrue(any("field" in error for error in self.check(item)))

    def test_frame_numbers_must_be_positive(self):
        item = copy.deepcopy(deviation_item())
        item["observation_ref"]["frame_number"] = 0
        self.assertTrue(any("frame_number" in error for error in self.check(item)))


class CaseContractTests(unittest.TestCase):
    def setUp(self):
        self.schemas = load_schemas()

    def check(self, document):
        return validate(document, self.schemas[CASE_SCHEMA_NAME], "case", self.schemas)

    def test_valid_case_passes(self):
        self.assertEqual(self.check(case_document()), [])

    def test_case_rejects_bad_nested_item(self):
        document = case_document(adjudications=[deviation_item(status="MAYBE")])
        self.assertTrue(any("not in enum" in error for error in self.check(document)))

    def test_case_requires_at_least_one_adjudication(self):
        document = case_document(adjudications=[])
        self.assertTrue(any("adjudications" in error for error in self.check(document)))

    def test_provenance_commits_are_full_shas(self):
        document = copy.deepcopy(case_document())
        document["runtime_provenance"]["corenet_commit"] = "abc123"
        self.assertTrue(any("corenet_commit" in error for error in self.check(document)))

    def test_first_differing_layer_is_bounded(self):
        document = case_document(first_differing_layer="DOMAIN_RUNTIME")
        self.assertTrue(any("first_differing_layer" in error for error in self.check(document)))


class AdjudicationConsistencyTests(unittest.TestCase):
    """Semantic rules that the schema subset cannot express on its own."""

    def test_duplicate_adjudication_ids_are_rejected(self):
        document = case_document(adjudications=[deviation_item(), deviation_item()])
        self.assertTrue(duplicate_ids(document))

    def test_unique_ids_pass(self):
        document = case_document(adjudications=[
            deviation_item(), deviation_item(adjudication_id="adj-02", evidence_level="DERIVED", packet_evidence=[]),
        ])
        self.assertFalse(duplicate_ids(document))

    def test_status_counts_must_match_items(self):
        document = case_document()
        document["status_counts"]["INSUFFICIENT_EVIDENCE"] = 1
        self.assertTrue(count_mismatch(document))

    def test_unanchored_session_instance_is_never_packet_supported(self):
        item = deviation_item(
            source_domain="5gc-pdu-session",
            source_instance_id="5gc-pdu-session:example.pcap:ran1-amf2:psi1",
            deviation_type="PARTIAL_CAPTURE",
            status="SUPPORTED_BY_PACKET_EVIDENCE",
            evidence_level="DERIVED",
            packet_evidence=[],
            observation_ref={
                "capture_file": "example.pcap", "frame_number": None,
                "window_first_frame": None, "window_last_frame": None,
                "protocol": None, "message_type": None,
            },
        )
        self.assertTrue(unanchored_session_claim(item))

    def test_protected_envelope_is_never_adjudicated_abnormal(self):
        item = deviation_item(deviation_type="PROTECTED_INNER_MESSAGE_UNAVAILABLE",
                              status="UNSUPPORTED_BY_PACKET_EVIDENCE")
        self.assertTrue(protected_envelope_mistreated(item))

    def test_recognized_protected_limitation_is_allowed(self):
        self.assertFalse(protected_envelope_mistreated(deviation_item()))


class CommittedRecordTests(unittest.TestCase):
    def setUp(self):
        self.schemas = load_schemas()
        self.cases = committed_cases()

    def test_committed_cases_conform_to_schema(self):
        for path, document in self.cases:
            with self.subTest(case=path.name):
                self.assertEqual(validate(document, self.schemas[CASE_SCHEMA_NAME], "case", self.schemas), [])

    def test_committed_case_ids_are_unique_and_known(self):
        seen = set()
        for path, document in self.cases:
            self.assertEqual(path.stem, document["case_id"], path.name)
            self.assertNotIn(document["case_id"], seen)
            seen.add(document["case_id"])
            self.assertTrue((BENCHMARK_DIR / "cases" / document["case_id"]).is_dir(), document["case_id"])

    def test_committed_capture_identity_matches_accepted_case_record(self):
        for _path, document in self.cases:
            accepted = json.loads((BENCHMARK_DIR / "cases" / document["case_id"] / "case.json").read_text(encoding="utf-8"))
            self.assertEqual(document["capture_sha256"], accepted["capture_sha256"], document["case_id"])
            self.assertEqual(document["capture_file"], Path(accepted["source_capture_path"]).name, document["case_id"])

    def test_committed_baseline_and_comparison_match_frozen_differential(self):
        for _path, document in self.cases:
            differential = json.loads((BENCHMARK_DIR / "cases" / document["case_id"] / "differential.json").read_text(encoding="utf-8"))
            self.assertEqual(document["comparison_status"], differential["comparison_status"], document["case_id"])

    def test_committed_ids_unique_and_counts_agree(self):
        for path, document in self.cases:
            with self.subTest(case=path.name):
                self.assertFalse(duplicate_ids(document))
                self.assertFalse(count_mismatch(document))

    def test_committed_items_are_cross_referenceable(self):
        for path, document in self.cases:
            ids = {item["adjudication_id"] for item in document["adjudications"]}
            for item in document["adjudications"]:
                for related in item.get("equivalent_evidence_basis_ids", []):
                    self.assertIn(related, ids, f"{path.name} -> {related}")

    def test_summary_totals_match_committed_cases(self):
        summary_path = ADJ_DIR / "summary.json"
        if not summary_path.is_file() or not self.cases:
            self.skipTest("no committed adjudication results yet")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        expected = {status: 0 for status in STATUSES}
        for _path, document in self.cases:
            for status in STATUSES:
                expected[status] += document["status_counts"][status]
        self.assertEqual(summary["status_totals"], expected)
        self.assertEqual([case["case_id"] for case in summary["cases"]],
                         sorted(document["case_id"] for _p, document in self.cases))
        self.assertEqual(summary["case_count"], len(self.cases))


class SanitizationTests(unittest.TestCase):
    def texts(self) -> list[Path]:
        return [path for path in sorted(ADJ_DIR.rglob("*")) if path.is_file() and path.suffix in (".json", ".md")]

    def test_no_private_workstation_paths(self):
        for path in self.texts():
            with self.subTest(file=path.name):
                self.assertIsNone(ABSOLUTE_PATH.search(path.read_text(encoding="utf-8")), path.name)

    def test_no_subscriber_identifiers_or_auth_vectors(self):
        for path in self.texts():
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(SUBSCRIBER_VALUE.search(text), path.name)
            self.assertIsNone(AUTH_VECTOR.search(text), path.name)

    def test_no_raw_protocol_event_or_capture_artifacts(self):
        for path in ADJ_DIR.rglob("*"):
            self.assertNotIn(path.name, RAW_DUMP_NAMES)
            self.assertNotIn(path.suffix, (".pcap", ".pcapng", ".cap"))

    def test_committed_text_stays_within_length_budget(self):
        for path in self.texts():
            if path.suffix == ".json":
                self.assertLess(path.stat().st_size, 60_000, path.name)

    def test_adjudication_area_never_touches_scored_records(self):
        for path in ADJ_DIR.rglob("*"):
            self.assertNotIn("differential.json", path.name)
            self.assertNotIn("human-baseline.json", path.name)
            self.assertNotIn("skill-result-summary.json", path.name)


def duplicate_ids(document: dict) -> bool:
    ids = [item["adjudication_id"] for item in document["adjudications"]]
    return len(ids) != len(set(ids))


def count_mismatch(document: dict) -> bool:
    expected = {status: 0 for status in STATUSES}
    for item in document["adjudications"]:
        expected[item["status"]] += 1
    return document["status_counts"] != expected


def unanchored_session_claim(item: dict) -> bool:
    ref = item["observation_ref"]
    anchored = ref["frame_number"] is not None or ref["window_first_frame"] is not None
    session = item["source_domain"] == "5gc-pdu-session"
    supported = item["status"] == "SUPPORTED_BY_PACKET_EVIDENCE"
    return session and supported and not anchored


def protected_envelope_mistreated(item: dict) -> bool:
    if item["deviation_type"] != "PROTECTED_INNER_MESSAGE_UNAVAILABLE":
        return False
    return item["status"] not in ("VALID_CAPTURE_LIMITATION", "POTENTIALLY_SPURIOUS", "INSUFFICIENT_EVIDENCE")


if __name__ == "__main__":
    unittest.main()
