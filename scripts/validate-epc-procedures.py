#!/usr/bin/env python3
"""Validate the standalone epc-procedures Domain Skill contract."""

from __future__ import annotations

import argparse
import importlib.util
import json
import py_compile
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/procedure-model.md",
    "references/stage-map.md",
    "references/evidence-rules.md",
    "references/limitations.md",
    "rules/epc-attach-model.json",
    "schemas/epc-attach-analysis.schema.json",
    "scripts/epc_attach_model.py",
    "scripts/analyze_epc_attach.py",
    "scripts/epc_attach_timeline.py",
    "tests/test_epc_procedures.py",
    "references/session-control.md",
    "rules/epc-session-model.json",
    "schemas/epc-session-analysis.schema.json",
    "scripts/epc_session_model.py",
    "scripts/analyze_epc_session.py",
    "scripts/epc_session_timeline.py",
    "tests/test_epc_session.py",
    "examples/gtpv2/events.jsonl",
    "examples/gtpv2/transactions.json",
    "examples/gtpv2/expected-session-analysis.json",
    "references/default-bearer.md",
    "references/identity-linking.md",
    "rules/epc-default-bearer-model.json",
    "schemas/epc-default-bearer-analysis.schema.json",
    "scripts/epc_default_bearer_model.py",
    "scripts/analyze_epc_default_bearer.py",
    "scripts/epc_default_bearer_timeline.py",
    "tests/test_epc_default_bearer.py",
    "examples/default-bearer/nas-eps-events.jsonl",
    "examples/default-bearer/s1ap-events.jsonl",
    "examples/default-bearer/gtpv2-events.jsonl",
    "examples/default-bearer/attach-analysis.json",
    "examples/default-bearer/session-analysis.json",
    "examples/default-bearer/expected-analysis.json",
    "references/s1u-observation.md",
    "rules/epc-s1u-model.json",
    "schemas/epc-s1u-observation.schema.json",
    "scripts/epc_s1u_model.py",
    "scripts/analyze_epc_s1u.py",
    "scripts/epc_s1u_timeline.py",
    "tests/test_epc_s1u.py",
    "references/session-identity-bridge.md",
    "references/release-binding.md",
    "rules/epc-session-identity-model.json",
    "schemas/epc-session-identity-analysis.schema.json",
    "scripts/epc_session_identity_model.py",
    "scripts/analyze_epc_session_identity.py",
    "scripts/epc_session_identity_report.py",
    "tests/test_epc_session_identity.py",
    "examples/s1u/gtpu-fields.jsonl",
    "examples/s1u/gtpu-events.jsonl",
    "examples/s1u/gtpu-streams.json",
    "examples/s1u/default-bearer.json",
    "examples/s1u/gtpv2-endpoints.jsonl",
    "examples/s1u/expected-observation.json",
    "references/bearer-lifecycle.md",
    "references/advertisement-family.md",
    "rules/epc-bearer-lifecycle-model.json",
    "schemas/epc-bearer-lifecycle-analysis.schema.json",
    "scripts/epc_bearer_lifecycle_model.py",
    "scripts/analyze_epc_bearer_lifecycle.py",
    "tests/test_epc_bearer_lifecycle.py",
    "examples/lifecycle/gtpv2-events.jsonl",
    "examples/lifecycle/gtpv2-transactions.json",
    "examples/lifecycle/s1u-observation.json",
    "examples/lifecycle/gtpu-events.jsonl",
    "examples/lifecycle/expected-analysis.json",
)

S1U_FORBIDDEN_KEYS = {
    "inner_packet", "inner_source_address", "inner_destination_address",
    "inner_source_port", "inner_destination_port", "payload", "raw_bytes",
}

SESSION_OUTCOMES = (
    "RESPONSE_ACCEPTED_OBSERVED",
    "RESPONSE_REJECTED_OBSERVED",
    "RESPONSE_OUTCOME_UNKNOWN",
    "OPEN_REQUEST",
    "RESPONSE_ONLY",
    "AMBIGUOUS_TRANSACTION",
)

SESSION_INTERFACES = ("S11", "S5/S8", "UNKNOWN_INTERFACE")

SESSION_FORBIDDEN_KEYS = {
    "imsi", "msisdn", "imei", "tmsi", "guti", "apn", "apn_name",
    "paa_address", "pdn_address", "raw_bytes", "payload",
}

CASES = (
    "attach-reject",
    "auth-failure",
    "smc-reject",
    "conflicting-ids",
    "protected-inner",
)

DEVIATION_FIELDS = (
    "deviation_type",
    "procedure_stage",
    "protocol",
    "message_type",
    "frame_number",
    "evidence_level",
    "evidence_refs",
    "observation_window",
    "explanation",
    "limitations",
)

FORBIDDEN_KEYS = {
    "imsi", "imei", "imeisv", "guti", "tmsi", "msisdn", "supi", "suci",
    "rand", "autn", "res", "xres", "kasme", "key", "nas_pdu", "esm_msg_cont",
}

FORBIDDEN_CLAIMS = (
    "bearer_active",
    "pdn_connectivity_success",
    "user_plane_ready",
    "service_success",
    "root cause is",
)

LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s*[0-9]+\b|\bmilestone\s*[a-z]?[0-9]+\b")
LONG_DIGITS = re.compile(r"\d{14,}")


def load_session_model(root: Path):
    path = root / "skills" / "domain" / "epc-procedures" / "scripts" / "epc_session_model.py"
    spec = importlib.util.spec_from_file_location("epc_session_model_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_model(root: Path):
    path = root / "skills" / "domain" / "epc-procedures" / "scripts" / "epc_attach_model.py"
    spec = importlib.util.spec_from_file_location("epc_attach_model_under_test", path)
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


def manifest_version(text):
    for line in text.splitlines():
        if line.startswith("version:"):
            return line.split(":", 1)[1].strip()
    return None


def validate(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    skill = root / "skills" / "domain" / "epc-procedures"

    def fail(message: str) -> None:
        errors.append(message)

    if not skill.is_dir():
        return ["missing Skill directory: skills/domain/epc-procedures"]

    for relative in REQUIRED:
        if not (skill / relative).is_file():
            fail(f"missing required file: skills/domain/epc-procedures/{relative}")
    if errors:
        return errors

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    if not re.search(r"(?m)^name:\s*epc-procedures\s*$", manifest):
        fail("manifest name must be epc-procedures")
    if not re.search(r"(?m)^category:\s*domain\s*$", manifest):
        fail("manifest category must be domain")
    if not re.search(r"(?m)^version:\s*\d+\.\d+\.\d+\s*$", manifest):
        fail("manifest version must be a semantic version")

    try:
        schema = json.loads((skill / "schemas" / "epc-attach-analysis.schema.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid analysis schema: {exc}")
        schema = {}
    for field in (
        "procedure_instances",
        "instance_count",
        "global_first_abnormal_boundary",
        "global_boundary_evaluation",
        "not_confirmed",
    ):
        if field not in schema.get("required", []):
            fail(f"analysis schema does not require '{field}'")

    try:
        rules = json.loads((skill / "rules" / "epc-attach-model.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid rules model: {exc}")
        rules = {}

    model = load_model(root)
    rule_stages = tuple(stage["stage_id"] for stage in rules.get("stages", []))
    if rule_stages != tuple(model.STAGE_ORDER):
        fail("rules stage vocabulary does not match the implemented stage order")
    if tuple(rules.get("deviations", ())) != tuple(model.DEVIATION_TYPES):
        fail("rules deviation catalogue does not match the implemented deviations")

    for path in sorted(skill.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".md", ".py", ".yaml", ".json", ".jsonl"}:
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

    for case in CASES:
        s1ap_path = skill / "examples" / "extracted" / f"{case}-s1ap.jsonl"
        nas_path = skill / "examples" / "extracted" / f"{case}-nas.jsonl"
        expected_path = skill / "examples" / "expected" / f"{case}-analysis.json"
        if not s1ap_path.is_file() or not nas_path.is_file() or not expected_path.is_file():
            fail(f"missing fixture or expected analysis for case '{case}'")
            continue
        try:
            s1ap_events = read_jsonl(s1ap_path)
            nas_events = read_jsonl(nas_path)
            produced = model.analyze(s1ap_events, nas_events, s1ap_path.name, nas_path.name)
            expected = json.loads(expected_path.read_text(encoding="utf-8"))
        except (ValueError, model.InputError) as exc:
            fail(f"{case}: {exc}")
            continue
        _check_analysis(expected, case, fail)
        if produced != expected:
            fail(f"{case}: produced analysis does not match the committed expected result")

    errors.extend(_validate_published_contracts(skill, root))
    errors.extend(_validate_session_control(skill, root))
    errors.extend(_validate_default_bearer(skill, root))
    errors.extend(_validate_s1u(skill, root))
    errors.extend(_validate_lifecycle(skill, root))
    errors.extend(_validate_session_identity(skill, root))

    malformed = skill / "examples" / "extracted" / "malformed-nas.jsonl"
    if not malformed.is_file():
        fail("missing malformed NAS fixture")
    else:
        try:
            model.validate_events(read_jsonl(malformed), "NAS-EPS")
            fail("malformed NAS fixture must be rejected")
        except model.InputError:
            pass

    return errors


def _validate_session_control(skill: Path, root: Path) -> list[str]:
    """Validate the bounded EPC session-control capability."""
    errors: list[str] = []

    def fail(message: str) -> None:
        errors.append(message)

    try:
        schema = json.loads(
            (skill / "schemas" / "epc-session-analysis.schema.json").read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        return [f"invalid session analysis schema: {exc}"]
    for field in (
        "domain",
        "analysis_scope",
        "input_provenance",
        "control_plane_subjects",
        "transaction_observations",
        "bearer_context_observations",
        "procedure_local_deviations",
        "unbound_evidence",
        "ambiguous_evidence",
        "evidence_limitations",
        "additional_evidence_needed",
        "not_confirmed",
    ):
        if field not in schema.get("required", []):
            fail(f"session schema does not require '{field}'")

    try:
        rules = json.loads((skill / "rules" / "epc-session-model.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"invalid session rules model: {exc}"]

    model = load_session_model(root)
    if set(rules.get("procedure_families", {})) != set(model.FAMILY_ORDER):
        fail("session rules families do not match the implemented families")
    if set(rules.get("outcome_vocabulary", ())) != set(model.OUTCOMES):
        fail("session rules outcome vocabulary does not match the implemented outcomes")
    if set(rules.get("accepting_causes", ())) != set(model.ACCEPTING_CAUSES):
        fail("session rules accepting causes do not match the implemented set")
    if tuple(rules.get("not_confirmed", ())) != tuple(model.NOT_CONFIRMED):
        fail("session rules not_confirmed list does not match the implemented list")
    if set(rules.get("interface_detection", {}).get("s11_control_interface_types", ())) != set(
        model.S11_CONTROL_TYPES
    ):
        fail("session rules S11 interface types do not match the implemented set")
    if set(rules.get("interface_detection", {}).get("s5s8_control_interface_types", ())) != set(
        model.S5S8_CONTROL_TYPES
    ):
        fail("session rules S5/S8 interface types do not match the implemented set")

    events_path = skill / "examples" / "gtpv2" / "events.jsonl"
    transactions_path = skill / "examples" / "gtpv2" / "transactions.json"
    expected_path = skill / "examples" / "gtpv2" / "expected-session-analysis.json"
    try:
        events = read_jsonl(events_path)
        document = json.loads(transactions_path.read_text(encoding="utf-8"))
        produced = model.analyze(events, document, events_path.name, transactions_path.name)
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
    except (ValueError, OSError, json.JSONDecodeError, model.InputError) as exc:
        return errors + [f"session-control fixture: {exc}"]

    if produced != expected:
        fail("session-control analysis does not reproduce the committed expected result")

    if expected.get("boundary_selection_status") != "NOT_EVALUATED":
        fail("session-control analysis must keep boundary selection NOT_EVALUATED")
    if expected.get("first_abnormal_boundary") is not None:
        fail("session-control analysis must never select a first abnormal boundary")
    if not expected.get("not_confirmed"):
        fail("session-control analysis must publish what it does not confirm")

    subjects = expected.get("control_plane_subjects") or []
    if not subjects:
        fail("session-control fixture must produce at least one subject")
    interfaces = set()
    for subject in subjects:
        interfaces.add(subject.get("interface"))
        if subject.get("cross_interface_association") != "NOT_ESTABLISHED":
            fail("a session-control subject must not claim a cross-interface association")
        if subject.get("attach_association") != "NOT_ESTABLISHED":
            fail("a session-control subject must not claim an Attach association")
        if subject.get("interface") not in SESSION_INTERFACES:
            fail(f"unexpected session-control interface: {subject.get('interface')}")
        forbidden = SESSION_FORBIDDEN_KEYS & set(subject)
        if forbidden:
            fail(f"session-control subject publishes forbidden field(s) {sorted(forbidden)}")
    if "S11" not in interfaces or "S5/S8" not in interfaces:
        fail("the accepted fixture must exercise both S11 and S5/S8 subjects")

    for observation in expected.get("transaction_observations") or []:
        if observation.get("outcome") not in SESSION_OUTCOMES:
            fail(f"unexpected transaction outcome: {observation.get('outcome')}")

    serialized = json.dumps(expected)
    for claim in FORBIDDEN_CLAIMS:
        if claim in serialized:
            fail(f"session-control analysis publishes forbidden claim '{claim}'")
    if LONG_DIGITS.search(serialized):
        fail("session-control analysis publishes a long digit run that may be an identifier")

    return errors


def _validate_published_contracts(skill: Path, root: Path) -> list[str]:
    """The published capability inventory must match the implemented one."""
    errors: list[str] = []

    def fail(message: str) -> None:
        errors.append(message)

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    version = manifest_version(manifest)
    if version is None:
        fail("manifest version must be a semantic version")

    skill_md = (skill / "SKILL.md").read_text(encoding="utf-8")
    readme = (skill / "README.md").read_text(encoding="utf-8")
    for name, text in (("SKILL.md", skill_md), ("README.md", readme)):
        if version is not None and version not in text:
            fail(f"{name} does not state the manifest version {version}")
        for script in (
            "analyze_epc_attach.py",
            "analyze_epc_session.py",
            "analyze_epc_default_bearer.py",
            "analyze_epc_s1u.py",
        ):
            if script not in text:
                fail(f"{name} does not document the {script} capability")
    if "four independently executable capabilities" not in skill_md:
        fail("SKILL.md must state that the package has four capabilities")
    if "two independently executable capabilities" in skill_md:
        fail("SKILL.md still describes only two capabilities")

    # The correction phase added no orchestration of default-bearer subjects.
    orchestration = root / "skills" / "orchestration" / "epc-failure-boundary" / "manifest.yaml"
    if orchestration.is_file():
        orchestration_text = orchestration.read_text(encoding="utf-8")
        if "EPS Attach procedure instance" not in orchestration_text:
            fail("the EPC orchestration manifest no longer states its supported subject families")
        if "default-bearer" not in orchestration_text:
            fail("the EPC orchestration manifest must declare the default-bearer subject family")
        if "S1-U" in orchestration_text or "s1u" in orchestration_text:
            fail("S1-U packet observation must not be advertised as an orchestration subject")

    return errors


def load_s1u_model(root: Path):
    path = root / "skills" / "domain" / "epc-procedures" / "scripts" / "epc_s1u_model.py"
    spec = importlib.util.spec_from_file_location("epc_s1u_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _validate_s1u(skill: Path, root: Path) -> list[str]:
    """Validate the bounded EPC S1-U GTP-U observation capability."""
    errors: list[str] = []

    def fail(message: str) -> None:
        errors.append(message)

    try:
        schema = json.loads(
            (skill / "schemas" / "epc-s1u-observation.schema.json").read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        return [f"invalid S1-U schema: {exc}"]
    for field in (
        "stream_observations",
        "supported_stream_count",
        "ambiguous_stream_count",
        "unbound_stream_count",
        "observed_g_pdu_packet_count",
        "observed_payload_byte_count",
        "procedure_local_deviations",
        "evidence_limitations",
        "not_confirmed",
    ):
        if field not in schema.get("required", []):
            fail(f"S1-U schema does not require '{field}'")

    try:
        rules = json.loads((skill / "rules" / "epc-s1u-model.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"invalid S1-U rules model: {exc}"]

    model = load_s1u_model(root)
    if list(rules.get("association_statuses", ())) != list(model.ASSOCIATION_STATUSES):
        fail("S1-U rules association statuses do not match the implemented set")
    if list(rules.get("outcome_vocabulary", ())) != list(model.OUTCOMES):
        fail("S1-U rules outcomes do not match the implemented set")
    if list(rules.get("deviation_vocabulary", ())) != list(model.DEVIATION_TYPES):
        fail("S1-U rules deviations do not match the implemented set")
    if tuple(rules.get("not_confirmed", ())) != tuple(model.NOT_CONFIRMED):
        fail("S1-U rules not_confirmed list does not match the implemented list")
    if rules.get("s1u_interface_type") != model.S1U_INTERFACE_TYPE:
        fail("S1-U rules interface type does not match the implemented value")
    required_equal = set((rules.get("matching_rule") or {}).get("required_equal") or ())
    if required_equal != {"outer_destination_address", "gtpu_header_teid"}:
        fail("S1-U matching rule must require destination address and header TEID equality")

    # TS 29.274 clause 8.22: interface type 1 identifies the SGW's S1-U GTP-U
    # endpoint and type 0 the eNodeB's. A role and an interface type are never
    # derived from each other, so the name table must cover exactly the reviewed
    # role mapping and must not invent a name.
    if set(model.INTERFACE_TYPE_NAMES) != set(model.INTERFACE_TYPE_ROLE):
        fail("S1-U interface type names must cover exactly the reviewed role mapping")
    if model.INTERFACE_TYPE_NAMES.get(1) != "S1-U SGW GTP-U interface":
        fail("interface type 1 must be named 'S1-U SGW GTP-U interface'")
    if model.INTERFACE_TYPE_NAMES.get(0) != "S1-U eNodeB GTP-U interface":
        fail("interface type 0 must be named 'S1-U eNodeB GTP-U interface'")
    if model.INTERFACE_TYPE_ROLE.get(1) != model.ROLE_SGW:
        fail("interface type 1 must map to the sgw_s1u receiving role")
    if model.INTERFACE_TYPE_ROLE.get(0) != model.ROLE_ENODEB:
        fail("interface type 0 must map to the enodeb_s1u receiving role")

    base = skill / "examples" / "s1u"
    try:
        gtpu_events = model.read_jsonl(base / "gtpu-events.jsonl")
        produced = model.analyze(
            gtpu_events,
            model.read_json(base / "gtpu-streams.json"),
            default_bearer=model.read_json(base / "default-bearer.json"),
            gtpv2_events=model.read_jsonl(base / "gtpv2-endpoints.jsonl"),
        )
        expected = json.loads((base / "expected-observation.json").read_text(encoding="utf-8"))
    except (ValueError, OSError, json.JSONDecodeError, model.InputError) as exc:
        return errors + [f"S1-U fixture: {exc}"]

    observed_types: dict[int, str] = {}
    for event in gtpu_events:
        if not isinstance(event, dict):
            continue
        frame = event.get("frame_number")
        header = event.get("header")
        if not isinstance(frame, int) or not isinstance(header, dict):
            continue
        message_type = header.get("message_type")
        if isinstance(message_type, str) and message_type:
            observed_types.setdefault(frame, message_type)

    produced.pop("input_provenance", None)
    expected_without = dict(expected)
    expected_without.pop("input_provenance", None)
    if produced != expected_without:
        fail("S1-U observation does not reproduce the committed expected result")

    if expected.get("boundary_selection_status") != "NOT_APPLICABLE":
        fail("S1-U observation must not claim a boundary selection")
    if expected.get("first_abnormal_boundary") is not None:
        fail("S1-U observation must never select a first abnormal boundary")
    if not expected.get("stream_observations"):
        fail("S1-U fixture must produce at least one stream observation")

    for stream in expected.get("stream_observations") or []:
        if stream.get("association_status") not in model.ASSOCIATION_STATUSES:
            fail(f"unexpected stream association status: {stream.get('association_status')}")
        if stream.get("direction") not in ("DOWNLINK", "UPLINK", "UNKNOWN"):
            fail(f"unexpected stream direction: {stream.get('direction')}")
        if stream.get("user_plane_interface") not in (model.INTERFACE_S1U, model.INTERFACE_UNKNOWN):
            fail(f"unexpected user-plane interface: {stream.get('user_plane_interface')}")
        forbidden = S1U_FORBIDDEN_KEYS & set(stream)
        if forbidden:
            fail(f"S1-U stream publishes forbidden field(s) {sorted(forbidden)}")
        for reference in stream.get("evidence_refs") or []:
            if not isinstance(reference, dict) or reference.get("protocol") != "GTP-U":
                continue
            frame = reference.get("frame_number")
            message_type = reference.get("message_type")
            actual = observed_types.get(frame)
            if actual is not None and message_type != actual:
                fail(
                    "an S1-U evidence reference does not name the message observed in its frame "
                    f"(frame {frame}: {message_type!r} vs {actual!r})"
                )
            if actual is None and message_type is not None:
                fail(
                    "an S1-U evidence reference names a message for a frame with no observed event "
                    f"(frame {frame}: {message_type!r})"
                )
        protocols = stream.get("matched_endpoint_source_protocols") or []
        interface_types = stream.get("matched_endpoint_interface_types") or []
        if not isinstance(protocols, list) or not isinstance(interface_types, list):
            fail("S1-U stream provenance fields must be lists")
            continue
        if not stream.get("association_status") == model.ASSOCIATION_SUPPORTED:
            if protocols or interface_types:
                fail("an unassociated S1-U stream must not publish matched-endpoint provenance")
            continue
        if not protocols:
            fail("a supported S1-U stream must name the protocol that advertised its endpoint")
        if set(protocols) == {"S1AP"} and interface_types:
            fail("an S1AP-only match must not publish a GTPv2-C interface type")
        for interface_type in interface_types:
            if interface_type not in model.INTERFACE_TYPE_NAMES:
                fail(f"unreviewed S1-U interface type published: {interface_type}")
        if interface_types:
            names = stream.get("matched_endpoint_interface_type_names") or []
            for interface_type in interface_types:
                if model.INTERFACE_TYPE_NAMES[interface_type] not in names:
                    fail(f"interface type {interface_type} is published without its reviewed name")

    serialized = json.dumps(expected)
    for claim in (
        "USER_RECEIVED_PACKET",
        "BEARER_DELIVERY_CONFIRMED",
        "PDN_CONNECTIVITY_SUCCESS_CONFIRMED",
        "S1U_FORWARDING_HEALTHY",
        "APPLICATION_REACHABLE",
    ):
        if claim in serialized:
            fail(f"S1-U observation publishes forbidden claim '{claim}'")
    for claim in FORBIDDEN_CLAIMS:
        if claim in serialized:
            fail(f"S1-U observation publishes forbidden claim '{claim}'")

    return errors


def load_default_bearer_model(root: Path):
    path = root / "skills" / "domain" / "epc-procedures" / "scripts" / "epc_default_bearer_model.py"
    spec = importlib.util.spec_from_file_location("epc_default_bearer_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _validate_default_bearer(skill: Path, root: Path) -> list[str]:
    """Validate the bounded EPS default-bearer capability."""
    errors: list[str] = []

    def fail(message: str) -> None:
        errors.append(message)

    try:
        schema = json.loads(
            (skill / "schemas" / "epc-default-bearer-analysis.schema.json").read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        return [f"invalid default-bearer schema: {exc}"]
    for field in (
        "analysis_scope",
        "default_bearer_instances",
        "esm_observations",
        "s1_erab_observations",
        "gtpv2_supporting_evidence",
        "established_links",
        "ambiguous_links",
        "unbound_evidence",
        "procedure_local_deviations",
        "evidence_limitations",
        "additional_evidence_needed",
        "not_confirmed",
    ):
        if field not in schema.get("required", []):
            fail(f"default-bearer schema does not require '{field}'")

    try:
        rules = json.loads((skill / "rules" / "epc-default-bearer-model.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"invalid default-bearer rules model: {exc}"]

    model = load_default_bearer_model(root)
    if set(rules.get("stages", {})) != set(model.STAGE_ORDER):
        fail("default-bearer rules stages do not match the implemented stages")
    if list(rules.get("stage_status_vocabulary", ())) != list(model.STAGE_STATUSES):
        fail("default-bearer rules stage statuses do not match the implemented set")
    if list(rules.get("outcome_vocabulary", ())) != list(model.OUTCOMES):
        fail("default-bearer rules outcomes do not match the implemented set")
    if list(rules.get("link_status_vocabulary", ())) != list(model.LINK_STATUSES):
        fail("default-bearer rules link statuses do not match the implemented set")
    if set(rules.get("negative_deviation_types", ())) != set(model.NEGATIVE_DEVIATIONS):
        fail("default-bearer rules negative deviations do not match the implemented set")
    if set(rules.get("limitation_deviation_types", ())) | set(model.NEGATIVE_DEVIATIONS) != set(
        model.DEVIATION_TYPES
    ):
        fail("default-bearer rules deviation vocabulary does not match the implemented set")
    if set(rules.get("identity_rules", {}).get("s1u_interface_types", ())) != set(
        model.S1U_INTERFACE_TYPES
    ):
        fail("default-bearer rules S1-U interface types do not match the implemented set")
    if tuple(rules.get("not_confirmed", ())) != tuple(model.NOT_CONFIRMED):
        fail("default-bearer rules not_confirmed list does not match the implemented list")
    if rules.get("identity_rules", {}).get("s11_to_s5s8_link") != "NOT_ESTABLISHED":
        fail("default-bearer rules must keep the S11 to S5/S8 link NOT_ESTABLISHED")

    # The supporting inventory admits every reviewed S1-U interface type, while
    # only the S1AP-derived role decides which one may match an endpoint.
    reviewed_types = set()
    for role_types in model.ROLE_INTERFACE_TYPES.values():
        reviewed_types |= set(role_types)
    if set(model.S1U_SUPPORTING_INTERFACE_TYPES) != reviewed_types:
        fail("the S1-U supporting inventory must cover exactly the reviewed role interface types")
    if set(model.S1U_INTERFACE_TYPE_NAMES) != reviewed_types:
        fail("the S1-U interface type names must cover exactly the reviewed role interface types")
    if model.S1U_INTERFACE_TYPE_NAMES.get(0) != "S1-U eNodeB GTP-U interface":
        fail("interface type 0 must be named 'S1-U eNodeB GTP-U interface'")
    if model.S1U_INTERFACE_TYPE_NAMES.get(1) != "S1-U SGW GTP-U interface":
        fail("interface type 1 must be named 'S1-U SGW GTP-U interface'")

    base = skill / "examples" / "default-bearer"
    try:
        produced = model.analyze(
            model.read_jsonl(base / "nas-eps-events.jsonl"),
            model.read_jsonl(base / "s1ap-events.jsonl"),
            attach_analysis=model.read_json(base / "attach-analysis.json"),
            session_analysis=model.read_json(base / "session-analysis.json"),
            gtpv2_events=model.read_jsonl(base / "gtpv2-events.jsonl"),
            gtpv2_transactions=model.read_json(base / "gtpv2-transactions.json"),
        )
        expected = json.loads((base / "expected-analysis.json").read_text(encoding="utf-8"))
    except (ValueError, OSError, json.JSONDecodeError, model.InputError) as exc:
        return errors + [f"default-bearer fixture: {exc}"]

    produced.pop("input_provenance", None)
    expected_without_provenance = dict(expected)
    expected_without_provenance.pop("input_provenance", None)
    if produced != expected_without_provenance:
        fail("default-bearer analysis does not reproduce the committed expected result")

    if expected.get("boundary_selection_status") != "NOT_EVALUATED":
        fail("default-bearer analysis must keep boundary selection NOT_EVALUATED")
    if expected.get("first_abnormal_boundary") is not None:
        fail("default-bearer analysis must never select a first abnormal boundary")
    if not expected.get("not_confirmed"):
        fail("default-bearer analysis must publish what it does not confirm")

    instances = expected.get("default_bearer_instances") or []
    if not instances:
        fail("default-bearer fixture must produce at least one instance")
    for instance in instances:
        if instance.get("association_strength") not in ("STRONG", "SUPPORTED", "AMBIGUOUS", "UNBOUND"):
            fail(f"unexpected association strength: {instance.get('association_strength')}")
        stages = {stage.get("stage_id"): stage for stage in instance.get("stages") or []}
        if set(stages) != set(model.STAGE_ORDER):
            fail("a default-bearer instance must publish every stage")
        for stage in stages.values():
            if stage.get("status") not in model.STAGE_STATUSES:
                fail(f"unexpected stage status: {stage.get('status')}")
        for outcome in instance.get("outcomes") or []:
            if outcome not in model.OUTCOMES:
                fail(f"unexpected outcome: {outcome}")
        forbidden = SESSION_FORBIDDEN_KEYS & set(instance)
        if forbidden:
            fail(f"default-bearer instance publishes forbidden field(s) {sorted(forbidden)}")
        bearer = instance.get("bearer_context") or {}
        if "apn_name" in bearer or "pdn_address" in bearer:
            fail("default-bearer instance publishes a subscriber-level value")

    inventory = expected.get("gtpv2_supporting_evidence") or []
    for entry in inventory:
        if entry.get("interface_type") not in model.S1U_SUPPORTING_INTERFACE_TYPES:
            fail(f"unrelated interface type in the supporting inventory: {entry.get('interface_type')}")
        if entry.get("interface_type_name") != model.S1U_INTERFACE_TYPE_NAMES.get(entry.get("interface_type")):
            fail("a supporting F-TEID entry publishes a name that does not match its interface type")

    all_links = (
        (expected.get("established_links") or [])
        + (expected.get("ambiguous_links") or [])
        + (expected.get("unbound_evidence") or [])
    )
    for link in all_links:
        if link.get("status") not in model.LINK_STATUSES:
            fail(f"unexpected link status: {link.get('status')}")
        if link.get("link_type") == "s1ap_erab_to_gtpv2_bearer" and link.get("status") == "ESTABLISHED":
            fail("an S1AP to GTPv2 tunnel link must never be published as ESTABLISHED")
        if "s11" in str(link.get("link_type", "")).lower():
            fail("an S11 to S5/S8 link must never be published")
        if link.get("link_type") != "s1ap_erab_to_gtpv2_bearer":
            continue
        published = [
            item.get("value")
            for item in link.get("supporting_identifiers") or []
            if item.get("identifier") == "f_teid_interface_type"
        ]
        observed = link.get("observed_interface_types")
        if not isinstance(observed, list):
            fail("a tunnel link must publish the observed interface types as a list")
            continue
        for interface_type in observed:
            if interface_type not in model.S1U_SUPPORTING_INTERFACE_TYPES:
                fail(f"a tunnel link publishes an unreviewed observed interface type: {interface_type}")
        if len(published) > 1:
            fail("a tunnel link must publish at most one f_teid_interface_type identifier")
        if not observed:
            if published:
                fail("a link without an observed F-TEID must not publish an interface type")
            if link.get("target_interface_type") is not None:
                fail("a link without an observed F-TEID must not select a target interface type")
            continue
        if not published:
            fail("a link with an observed F-TEID must publish its interface type")
            continue
        value = published[0]
        expected_value = observed[0] if len(observed) == 1 else observed
        if value != expected_value:
            fail(
                "the published interface type does not match the observed F-TEID "
                f"({value!r} vs {expected_value!r})"
            )
        if link.get("status") == "SUPPORTED":
            if link.get("target_interface_type") != observed[0]:
                fail("a supported link must publish the observed interface type as its target")
            frames = {
                (entry.get("frame_number"), entry.get("interface_type")) for entry in inventory
            }
            if (link.get("target_frame"), observed[0]) not in frames:
                fail("a supported link names a target F-TEID missing from the supporting inventory")
        else:
            if link.get("target_interface_type") is not None:
                fail("a link without a selected owner must not publish a target interface type")

    for deviation in expected.get("procedure_local_deviations") or []:
        if deviation.get("deviation_type") not in model.DEVIATION_TYPES:
            fail(f"unexpected deviation type: {deviation.get('deviation_type')}")
        if deviation.get("evidence_level") != "OBSERVED":
            fail("a default-bearer deviation must stay at the OBSERVED evidence level")
        if deviation.get("frame_number") is None:
            fail("a default-bearer deviation must carry an exact frame anchor")

    serialized = json.dumps(expected)
    for claim in FORBIDDEN_CLAIMS:
        if claim in serialized:
            fail(f"default-bearer analysis publishes forbidden claim '{claim}'")
    if LONG_DIGITS.search(serialized):
        fail("default-bearer analysis publishes a long digit run that may be an identifier")
    for forbidden in ("internet", "10.45.0."):
        if forbidden in serialized:
            fail(f"default-bearer analysis publishes forbidden value '{forbidden}'")

    return errors


def load_lifecycle_model(root: Path):
    path = root / "skills" / "domain" / "epc-procedures" / "scripts" / "epc_bearer_lifecycle_model.py"
    spec = importlib.util.spec_from_file_location("epc_bearer_lifecycle_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _validate_lifecycle(skill: Path, root: Path) -> list[str]:
    errors: list[str] = []

    def fail(message: str) -> None:
        errors.append(message)

    try:
        schema = json.loads(
            (skill / "schemas" / "epc-bearer-lifecycle-analysis.schema.json").read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        return [f"invalid lifecycle schema: {exc}"]

    for field in (
        "lifecycle_subjects",
        "advertisement_families",
        "generation_observations",
        "generation_boundary_evidence",
        "endpoint_reuse_observations",
        "generation_scoped_s1u_observations",
        "unresolved_packet_observations",
        "ambiguous_associations",
        "unbound_evidence",
        "procedure_local_deviations",
        "evidence_limitations",
        "additional_evidence_needed",
        "not_confirmed",
        "accounting",
    ):
        if field not in schema.get("required", []):
            fail(f"lifecycle schema does not require '{field}'")
    if schema.get("properties", {}).get("boundary_selection_status", {}).get("const") != "NOT_APPLICABLE":
        fail("a lifecycle analysis must not claim a boundary selection")

    try:
        rules = json.loads(
            (skill / "rules" / "epc-bearer-lifecycle-model.json").read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        return errors + [f"invalid lifecycle rules model: {exc}"]

    model = load_lifecycle_model(root)
    if list(rules.get("advertisement_family_classifications", ())) != list(model.FAMILY_CLASSIFICATIONS):
        fail("lifecycle rules family classifications do not match the implemented set")
    if list(rules.get("lifecycle_observations", ())) != list(model.OBSERVATIONS):
        fail("lifecycle rules observations do not match the implemented set")
    if list(rules.get("generation_states", ())) != list(model.GENERATION_STATES):
        fail("lifecycle rules generation states do not match the implemented set")
    if list(rules.get("association_statuses", ())) != list(model.ASSOCIATION_STATUSES):
        fail("lifecycle rules association statuses do not match the implemented set")
    if list(rules.get("deviation_vocabulary", ())) != list(model.DEVIATION_TYPES):
        fail("lifecycle rules deviations do not match the implemented set")
    if tuple(rules.get("not_confirmed", ())) != tuple(model.NOT_CONFIRMED):
        fail("lifecycle rules not_confirmed list does not match the implemented list")
    if rules.get("identity_rules", {}).get("s11_to_s5s8_link") != "NOT_ESTABLISHED":
        fail("lifecycle rules must keep the S11 to S5/S8 link NOT_ESTABLISHED")
    if list(rules.get("release_outcomes", ())) != list(model.RELEASE_OUTCOMES):
        fail("lifecycle rules release outcomes do not match the implemented set")
    if list(rules.get("reviewed_correlation_strengths", ())) != sorted(model.REVIEWED_STRENGTHS):
        fail("lifecycle rules reviewed correlation strengths do not match the implemented set")
    if list(rules.get("proof_correlation_strengths", ())) != sorted(model.PROOF_STRENGTHS):
        fail("lifecycle rules proof correlation strengths do not match the implemented set")
    if "NONE" in model.PROOF_STRENGTHS:
        fail("the NONE correlation strength must never carry a proof")
    for closure_rule in ("same_capture_provenance", "bound_control_plane_context"):
        if closure_rule not in (rules.get("identity_rules", {}).get("generation_closure_requires") or []):
            fail(f"lifecycle rules must require '{closure_rule}' before closing a generation")

    base = skill / "examples" / "lifecycle"
    try:
        produced = model.analyze(
            model.read_jsonl(base / "gtpv2-events.jsonl"),
            transactions=model.read_json(base / "gtpv2-transactions.json"),
            s1u_analysis=model.read_json(base / "s1u-observation.json"),
            gtpu_events=model.read_jsonl(base / "gtpu-events.jsonl"),
        )
        expected = json.loads((base / "expected-analysis.json").read_text(encoding="utf-8"))
    except (ValueError, OSError, json.JSONDecodeError, model.InputError) as exc:
        return errors + [f"lifecycle fixture: {exc}"]

    produced.pop("input_provenance", None)
    expected_without = dict(expected)
    expected_without.pop("input_provenance", None)
    if produced != expected_without:
        fail("lifecycle analysis does not reproduce the committed expected result")

    if expected.get("first_abnormal_boundary") is not None:
        fail("a lifecycle analysis must never select an abnormal boundary")
    if not expected.get("not_confirmed"):
        fail("a lifecycle analysis must publish what it does not confirm")

    accounting = expected.get("accounting") or {}
    if accounting.get("attributed_g_pdu_count", 0) + accounting.get("unresolved_g_pdu_count", 0) != accounting.get(
        "aggregate_g_pdu_count", -1
    ):
        fail("lifecycle G-PDU accounting does not conserve the aggregate count")
    if accounting.get("attributed_payload_octets", 0) + accounting.get(
        "unresolved_payload_octets", 0
    ) != accounting.get("aggregate_payload_octets", -1):
        fail("lifecycle payload-octet accounting does not conserve the aggregate count")
    if not accounting.get("conserved_g_pdu") or not accounting.get("conserved_payload_octets"):
        fail("lifecycle analysis must report conserved accounting")

    families = expected.get("advertisement_families") or []
    if not families:
        fail("lifecycle fixture must produce at least one advertisement family")
    generated = {ref for subject in expected.get("lifecycle_subjects") or [] for ref in subject.get("advertisement_family_references") or []}
    for family in families:
        classification = family.get("family_classification")
        if classification not in model.FAMILY_CLASSIFICATIONS:
            fail(f"unexpected advertisement family classification: {classification}")
        if family.get("receiving_endpoint_role") != model.INTERFACE_TYPE_ROLE.get(
            family.get("reviewed_interface_type")
        ):
            fail("an advertisement family publishes an endpoint role that does not match its interface type")
        if classification == model.FAMILY_SAME_TRANSACTION:
            if len(family.get("source_frames") or []) < 2:
                fail("a same-transaction family must retain every advertisement frame")
            if len(family.get("source_transaction_references") or []) != 1:
                fail("a same-transaction family must name exactly one accepted transaction")
            if family.get("correlation_status") != "MATCHED":
                fail("a same-transaction family requires a matched correlation")
        if classification in (model.FAMILY_COMPETING, model.FAMILY_INSUFFICIENT):
            if family.get("advertisement_family_reference") in generated:
                fail("an unproved advertisement family must not open a generation")
        if classification == model.FAMILY_SINGLE and len(family.get("source_frames") or []) != 1:
            fail("a single-advertisement family must name exactly one frame")

    for boundary in expected.get("generation_boundary_evidence") or []:
        if boundary.get("release_outcome") not in model.RELEASE_OUTCOMES:
            fail(f"unexpected release outcome: {boundary.get('release_outcome')}")
        if not boundary.get("capture_file"):
            fail("a release boundary must publish its capture provenance")
        if boundary.get("response_frame") is None and boundary.get("release_outcome") == "ACCEPTED":
            fail("an accepted release must publish the correlated response frame")
        if boundary.get("release_outcome") == "ACCEPTED" and boundary.get("correlation_status") != "MATCHED":
            fail("an accepted release requires a matched correlation")
        if boundary.get("correlation_strength") == "NONE":
            fail("a NONE correlation strength cannot establish a release outcome")

    for subject in expected.get("lifecycle_subjects") or []:
        if subject.get("generation_state") not in model.GENERATION_STATES:
            fail(f"unexpected generation state: {subject.get('generation_state')}")
        boundary = subject.get("generation_boundary")
        if isinstance(boundary, dict):
            if boundary.get("release_request_frame") is None:
                fail("a generation boundary must publish its release request frame")
            if boundary.get("release_confirmation_frame") is None:
                fail("a generation boundary must publish its release confirmation frame")
            if boundary.get("frame_number") != boundary.get("release_confirmation_frame"):
                fail("a generation boundary must anchor on the confirmation frame, not the request")
            if boundary.get("release_effective_frame_proven") is not False:
                fail("the exact release-effective frame must never be claimed as proven")
        if not subject.get("generation_reference", "").startswith("epc-bearer-generation-"):
            fail("a generation reference must use the scoped pseudonymous prefix")
        if subject.get("generation_state") == model.GENERATION_CLOSED and not subject.get("generation_boundary"):
            fail("a closed generation must publish its boundary")
        if subject.get("generation_state") == model.GENERATION_OPEN and subject.get("generation_boundary"):
            fail("an open generation must not publish a boundary")
        if model.OBS_RELEASE_UNRESOLVED in (subject.get("observations") or []) and subject.get(
            "generation_state"
        ) != model.GENERATION_OPEN:
            fail("an unresolved release must leave the generation open")
        for observation in subject.get("observations") or []:
            if observation not in model.OBSERVATIONS:
                fail(f"unexpected lifecycle observation: {observation}")

    scoped = expected.get("generation_scoped_s1u_observations") or []
    unresolved = expected.get("unresolved_packet_observations") or []
    per_stream: dict[str, int] = {}
    for item in scoped:
        per_stream[item.get("source_stream_reference")] = per_stream.get(item.get("source_stream_reference"), 0) + item.get(
            "observed_g_pdu_count", 0
        )
    for item in unresolved:
        per_stream[item.get("stream_reference")] = per_stream.get(item.get("stream_reference"), 0) + item.get(
            "observed_g_pdu_count", 0
        )
    for stream in (model.read_json(base / "s1u-observation.json").get("stream_observations") or []):
        reference = stream.get("stream_reference")
        if per_stream.get(reference, 0) != stream.get("observed_g_pdu_packet_count"):
            fail(f"lifecycle packet accounting does not conserve stream {reference}")

    # A proved closure never appears in the committed example, so the positive
    # boundary contract is exercised on a constructed scenario as well.
    errors.extend(_validate_lifecycle_boundary(model, fail))
    errors.extend(_validate_message_cause_contract(skill, root, model, fail))

    serialized = json.dumps(expected)
    for forbidden in (
        "PACKET_LOSS",
        "DELIVERY_CONFIRMED",
        "USER_RECEIVED_PACKET",
        "APPLICATION_REACHABLE",
        "TUNNEL_FAILED",
    ):
        if forbidden in serialized:
            fail(f"lifecycle analysis publishes forbidden claim '{forbidden}'")
    for forbidden in ("internet", "10.45.0."):
        if forbidden in serialized:
            fail(f"lifecycle analysis publishes forbidden value '{forbidden}'")
    if LONG_DIGITS.search(serialized):
        fail("lifecycle analysis publishes a long digit run that may be an identifier")

    return errors


def _validate_message_cause_contract(skill: Path, root: Path, model, fail) -> list[str]:
    """The release outcome must come from the accepted message_cause field."""
    problems: list[str] = []

    for name in ("epc_bearer_lifecycle_model.py", "epc_default_bearer_model.py"):
        path = skill / "scripts" / name
        text = path.read_text(encoding="utf-8")
        for forbidden in ('event.get("cause")', "event['cause']", 'context.get("cause") is None'):
            if forbidden in text:
                problems.append(f"{name} still reads a non-contract Cause field: {forbidden}")

    schema_path = root / "skills" / "protocol" / "gtpv2" / "schemas" / "gtpv2-event.schema.json"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return problems + [f"gtpv2 event schema unreadable: {exc}"]
    if "message_cause" not in (schema.get("properties") or {}):
        problems.append("the accepted gtpv2 event contract no longer publishes message_cause")
    if "cause" in (schema.get("properties") or {}):
        problems.append("the accepted gtpv2 event contract must not publish a 'cause' field")

    def cause(code: int, scope: str = "message") -> dict:
        return {
            "cause_code": code,
            "cause_name": "Request accepted" if code == 16 else "Context not found",
            "scope": scope,
        }

    def event(frame: int, message: str, family: str, *, capture: str = "contract.pcap",
              message_cause=None, contexts=None) -> dict:
        return {
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "frame_number": frame,
            "message_occurrence": 0,
            "capture_file": capture,
            "protocol": "GTPv2-C",
            "transport": "UDP",
            "message_type": message,
            "message_type_code": 0,
            "procedure_family": family,
            "message_family": family,
            "support_status": "SUPPORTED",
            "hierarchy_basis": "validation",
            "header": {"teid": 1, "sequence_number": 1, "teid_state": "PRESENT"},
            "message_cause": message_cause,
            "information_elements": [],
            "identity_ies": [],
            "f_teids": [],
            "bearer_contexts": contexts or [],
            "unbound_ie_metadata": [],
            "ie_summary": [],
            "extraction_limitations": [],
            "evidence": {},
            "derivations": {},
        }

    def reference(frame: int, message: str) -> dict:
        return {
            "frame_number": frame,
            "header_teid": 1,
            "header_teid_state": "PRESENT",
            "message_type": message,
            "message_type_code": 0,
            "sequence_number": 1,
        }

    def transaction(reference_id: str, family: str, request, response) -> dict:
        return {
            "transaction_reference": reference_id,
            "procedure_family": family,
            "message_family": family,
            "request": reference(*request),
            "response": reference(*response),
            "response_candidates": [reference(*response)],
            "correlation_status": "MATCHED",
            "correlation_strength": "STRONG",
            "correlation_basis": ["request/response message identity"],
            "corroboration": {"teid_echo": True},
            "retransmissions": [],
            "observation_window": {"start_frame": request[0], "end_frame": response[0]},
            "evidence_refs": [reference(*request), reference(*response)],
            "limitations": [],
        }

    def document(*transactions, captures=("contract.pcap",)) -> dict:
        return {
            "protocol": "gtpv2",
            "capture_files": list(captures),
            "transaction_count": len(transactions),
            "matched_count": len(transactions),
            "open_request_count": 0,
            "response_only_count": 0,
            "ambiguous_count": 0,
            "retransmission_count": 0,
            "transactions": list(transactions),
            "limitations": [],
        }

    endpoint = {"scope": "bearer", "interface_type": 1, "teid": 100, "ipv4": "198.51.100.2"}
    contexts = [
        {
            "item_index": 0,
            "ebi": 5,
            "cause": None,
            "f_teids": [endpoint],
            "charging_id_present": False,
            "binding_basis": "validation",
        }
    ]
    allocation_events = [
        event(100, "Create Session Request", "create-session", contexts=contexts),
        event(106, "Create Session Response", "create-session", contexts=contexts, message_cause=cause(16)),
    ]
    release_events = [
        event(300, "Delete Session Request", "delete-session", contexts=contexts),
        event(306, "Delete Session Response", "delete-session", message_cause=cause(16)),
    ]
    transactions = document(
        transaction("cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
        transaction("ds", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response")),
    )

    # Every constructed event must conform to the accepted field set.
    properties = set(schema.get("properties") or {})
    required = set(schema.get("required") or [])
    for item in allocation_events + release_events:
        if set(item) - properties:
            problems.append(f"constructed event carries unknown field(s) {sorted(set(item) - properties)}")
        missing = required - set(item)
        if missing:
            problems.append(f"constructed event is missing required field(s) {sorted(missing)}")

    analysis = model.analyze(allocation_events + release_events, transactions=transactions)
    boundary = (analysis.get("generation_boundary_evidence") or [{}])[0]
    if boundary.get("release_outcome") != "ACCEPTED":
        problems.append("an accepted message_cause must establish an accepted release outcome")

    # A legacy test-only Cause alias must never be honoured.
    legacy = [dict(item) for item in allocation_events + release_events]
    legacy[-1] = dict(legacy[-1])
    legacy[-1]["message_cause"] = None
    legacy[-1]["cause"] = cause(16)
    legacy_analysis = model.analyze(legacy, transactions=transactions)
    legacy_boundary = (legacy_analysis.get("generation_boundary_evidence") or [{}])[0]
    if legacy_boundary.get("release_outcome") == "ACCEPTED":
        problems.append("a test-only Cause alias must never establish an accepted release")

    # A document that names one capture must never bind another capture's event.
    foreign_events = [
        event(100, "Create Session Request", "create-session", capture="elsewhere.pcap", contexts=contexts),
        event(106, "Create Session Response", "create-session", capture="elsewhere.pcap",
              contexts=contexts, message_cause=cause(16)),
    ]
    foreign_analysis = model.analyze(
        foreign_events,
        transactions=document(
            transaction("cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response"))
        ),
    )
    if (foreign_analysis.get("advertisement_families") or [{}])[0].get("family_classification") != model.FAMILY_INSUFFICIENT:
        problems.append("a transaction document naming one capture must not bind another capture's event")

    # Two captures with colliding frame numbers must not transfer evidence.
    collision_events = [
        event(100, "Create Session Request", "create-session", capture="A.pcap", contexts=contexts),
        event(106, "Create Session Response", "create-session", capture="A.pcap", contexts=contexts, message_cause=cause(16)),
        event(300, "Delete Session Request", "delete-session", capture="A.pcap", contexts=contexts),
        event(306, "Delete Session Response", "delete-session", capture="A.pcap", message_cause=cause(72)),
        event(300, "Delete Session Request", "delete-session", capture="B.pcap", contexts=contexts),
        event(306, "Delete Session Response", "delete-session", capture="B.pcap", message_cause=cause(16)),
    ]
    collision_transactions = document(
        transaction("cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
        transaction("ds", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response")),
        captures=("A.pcap", "B.pcap"),
    )
    collision_analysis = model.analyze(collision_events, transactions=collision_transactions)
    for item in collision_analysis.get("generation_boundary_evidence") or []:
        if item.get("release_outcome") == "ACCEPTED":
            problems.append("a colliding frame number in another capture must never supply acceptance")
    for generation in collision_analysis.get("lifecycle_subjects") or []:
        if generation.get("generation_state") == model.GENERATION_CLOSED:
            problems.append("a colliding frame number must never close a generation")

    for problem in problems:
        fail(problem)
    return []


def _validate_lifecycle_boundary(model, fail) -> list[str]:
    """Exercise the proved-closure and cross-capture contracts directly."""

    def fteid(interface_type, teid, address):
        return {"scope": "bearer", "interface_type": interface_type, "teid": teid, "ipv4": address}

    def context(ebi, teids, cause=None):
        return {
            "ebi": ebi,
            "cause": {"cause_code": cause, "cause_name": "accepted", "scope": "bearer"}
            if cause is not None
            else None,
            "f_teids": teids,
        }

    def event(frame, message, family, contexts, cause=None, capture="boundary.pcap"):
        return {
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "frame_number": frame,
            "message_occurrence": 0,
            "capture_file": capture,
            "protocol": "GTPv2-C",
            "transport": "UDP",
            "message_type": message,
            "message_type_code": 0,
            "procedure_family": family,
            "message_family": family,
            "support_status": "SUPPORTED",
            "hierarchy_basis": "validation",
            "header": {"teid": 1, "sequence_number": 1, "teid_state": "PRESENT"},
            "message_cause": (
                {"cause_code": cause, "cause_name": "accepted", "scope": "message"}
                if cause is not None
                else None
            ),
            "information_elements": [],
            "identity_ies": [],
            "f_teids": [],
            "bearer_contexts": contexts,
            "unbound_ie_metadata": [],
            "ie_summary": [],
            "extraction_limitations": [],
            "evidence": {},
            "derivations": {},
        }

    def message(frame, name, teid=1, cause=None):
        # The transaction reference carries no Cause in the accepted contract.
        return {
            "frame_number": frame,
            "header_teid": teid,
            "header_teid_state": "PRESENT" if teid else "ZERO",
            "message_type": name,
            "message_type_code": 0,
            "sequence_number": 1,
        }

    def transaction(reference, family, request, response, *, session_teid=1, cause=16):
        return {
            "transaction_reference": reference,
            "procedure_family": family,
            "message_family": family,
            "request": message(request[0], request[1], session_teid),
            "response": message(response[0], response[1], session_teid),
            "response_candidates": [message(response[0], response[1], session_teid)],
            "correlation_status": "MATCHED",
            "correlation_strength": "STRONG",
            "correlation_basis": ["request/response message identity"],
            "corroboration": {"teid_echo": True},
            "retransmissions": [],
            "observation_window": {"start_frame": request[0], "end_frame": response[0]},
            "evidence_refs": [
                message(request[0], request[1], session_teid),
                message(response[0], response[1], session_teid, cause),
            ],
            "limitations": [],
        }

    def document(*transactions):
        return {
            "protocol": "gtpv2",
            "capture_files": ["boundary.pcap"],
            "transaction_count": len(transactions),
            "matched_count": len(transactions),
            "open_request_count": 0,
            "response_only_count": 0,
            "ambiguous_count": 0,
            "retransmission_count": 0,
            "transactions": list(transactions),
            "limitations": [],
        }

    events = [
        event(100, "Create Session Request", "create-session", [context(5, [fteid(1, 100, "198.51.100.2")])]),
        event(106, "Create Session Response", "create-session", [context(5, [fteid(1, 100, "198.51.100.2")], 16)], 16),
        event(300, "Delete Session Request", "delete-session", [context(5, [fteid(1, 100, "198.51.100.2")])]),
        event(306, "Delete Session Response", "delete-session", [], 16),
    ]
    transactions = document(
        transaction("cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
        transaction("ds", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response")),
    )
    analysis = model.analyze(events, transactions=transactions)
    generation = (analysis.get("lifecycle_subjects") or [{}])[0]
    boundary = generation.get("generation_boundary")
    if generation.get("generation_state") != model.GENERATION_CLOSED:
        return ["a bound accepted release must close its generation"]
    if not isinstance(boundary, dict):
        return ["a closed generation must publish its boundary"]
    problems: list[str] = []
    if boundary.get("release_request_frame") != 300:
        problems.append("the release request frame must stay initiation evidence")
    if boundary.get("release_confirmation_frame") != 306:
        problems.append("the accepted response frame must carry the confirmation")
    if boundary.get("frame_number") != 306:
        problems.append("the boundary must anchor on the confirmation frame")
    if boundary.get("release_effective_frame_proven") is not False:
        problems.append("the exact release-effective frame must never be claimed as proven")

    # The same release in another capture must not close this generation.
    cross_events = list(events)
    for item in cross_events[2:]:
        item["capture_file"] = "other.pcap"
    cross = model.analyze(cross_events, transactions=transactions)
    cross_generation = (cross.get("lifecycle_subjects") or [{}])[0]
    if cross_generation.get("generation_state") == model.GENERATION_CLOSED:
        problems.append("a release from another capture must never close a generation")

    # NONE correlation strength must never prove a family.
    weak = document(
        transaction(
            "cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response")
        )
    )
    weak["transactions"][0]["correlation_strength"] = "NONE"
    weak_analysis = model.analyze(events[:2], transactions=weak)
    if (weak_analysis.get("advertisement_families") or [{}])[0].get("family_classification") != model.FAMILY_INSUFFICIENT:
        problems.append("a NONE correlation strength must not establish an advertisement family")

    for problem in problems:
        fail(problem)
    return []


def _check_analysis(analysis: dict, case: str, fail) -> None:
    if analysis.get("global_first_abnormal_boundary") is not None:
        fail(f"{case}: a global first abnormal boundary must never be selected")
    if analysis.get("global_boundary_evaluation") != "NOT_EVALUATED":
        fail(f"{case}: global boundary evaluation must be NOT_EVALUATED")
    if not analysis.get("not_confirmed"):
        fail(f"{case}: analysis must state what it does not confirm")

    serialised = json.dumps(analysis).lower()
    for claim in FORBIDDEN_CLAIMS:
        if claim in serialised:
            fail(f"{case}: analysis contains a forbidden success or root-cause claim")
    if LONG_DIGITS.search(serialised):
        fail(f"{case}: analysis publishes a long digit run that may be an identifier")

    for instance in analysis.get("procedure_instances") or []:
        reference = instance.get("procedure_reference", "")
        if not re.fullmatch(r"epc-attach-[0-9a-f]{10}", reference):
            fail(f"{case}: procedure reference is not pseudonymous: {reference}")
        if FORBIDDEN_KEYS & set(instance):
            fail(f"{case}: instance publishes a forbidden evidence field")
        for deviation in instance.get("deviations") or []:
            missing = [field for field in DEVIATION_FIELDS if field not in deviation]
            if missing:
                fail(f"{case}: deviation {deviation.get('deviation_type')} misses {missing}")
            if deviation.get("deviation_type") == "PROTECTED_INNER_MESSAGE_UNAVAILABLE":
                if deviation.get("message_type") is not None:
                    fail(f"{case}: a protected inner message must not be given an identity")
            if deviation.get("evidence_level") == "OBSERVED" and not deviation.get("evidence_refs"):
                fail(f"{case}: observed deviation without an evidence reference")
        for stage in instance.get("stages") or []:
            if stage.get("status") not in ("OBSERVED", "INCOMPLETE", "NOT_OBSERVED", "UNAVAILABLE_PROTECTED"):
                fail(f"{case}: unexpected stage status {stage.get('status')}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("epc-procedures validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("epc-procedures validation passed.")
    return 0



def load_session_identity_model(root: Path):
    path = (
        root
        / "skills"
        / "domain"
        / "epc-procedures"
        / "scripts"
        / "epc_session_identity_model.py"
    )
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("epc_session_identity_model_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _session_identity_scenario(second_same_control_teid: bool = False, create_cause: int | None = 16):
    """One reviewed two-hop session; optionally a second one reusing TEID 14."""
    mme, sgw, pgw = "10.0.0.1", "10.0.0.2", "10.0.0.3"
    capture = "validator.pcap"

    def event(frame, message, family, *, src, dst, teid=0, seq=1, cause=None, fteids=None, contexts=None, unbound=None):
        return {
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "frame_number": frame,
            "message_occurrence": 0,
            "capture_file": capture,
            "protocol": "GTPv2-C",
            "transport": "UDP",
            "message_type": message,
            "message_type_code": 0,
            "procedure_family": family,
            "message_family": family,
            "support_status": "SUPPORTED",
            "hierarchy_basis": "validator",
            "header": {"teid": teid, "sequence_number": seq, "teid_state": "PRESENT" if teid else "ZERO"},
            "message_cause": (
                {"cause_code": cause, "cause_name": "Request accepted", "scope": "message"}
                if cause is not None
                else None
            ),
            "information_elements": [],
            "identity_ies": [],
            "f_teids": fteids or [],
            "bearer_contexts": contexts or [],
            "unbound_ie_metadata": unbound or [],
            "ie_summary": [],
            "extraction_limitations": [],
            "evidence": {},
            "derivations": {},
            "source": {"address": src, "port": 2123},
            "destination": {"address": dst, "port": 2123},
        }

    def fteid(interface_type, teid, address):
        return {"scope": "message", "interface_type": interface_type, "teid": teid, "ipv4": address}

    def bearer_fteid(interface_type, teid, address):
        return {"scope": "bearer", "interface_type": interface_type, "teid": teid, "ipv4": address}

    def context(ebi, teids):
        return {"ebi": ebi, "cause": None, "f_teids": teids}

    def tx_message(frame, message, teid, seq):
        return {
            "frame_number": frame,
            "header_teid": teid,
            "header_teid_state": "PRESENT" if teid else "ZERO",
            "message_type": message,
            "message_type_code": 0,
            "sequence_number": seq,
        }

    def transaction(reference, family, request, response):
        return {
            "transaction_reference": reference,
            "procedure_family": family,
            "message_family": family,
            "request": tx_message(*request),
            "response": tx_message(*response) if response else None,
            "response_candidates": [tx_message(*response)] if response else [],
            "correlation_status": "MATCHED",
            "correlation_strength": "STRONG",
            "correlation_basis": ["request/response message identity"],
            "corroboration": {"teid_echo": True},
            "retransmissions": [],
            "observation_window": {"start_frame": request[0], "end_frame": response[0] if response else request[0]},
            "evidence_refs": [tx_message(*request)] + ([tx_message(*response)] if response else []),
            "limitations": [],
        }

    events = [
        event(100, "Create Session Request", "create-session", src=mme, dst=sgw, teid=0, seq=1,
              fteids=[fteid(10, 1, mme), fteid(7, 0, pgw)]),
        event(101, "Create Session Request", "create-session", src=sgw, dst=pgw, teid=0, seq=2,
              fteids=[fteid(6, 14, sgw)], contexts=[context(5, [bearer_fteid(4, 55, sgw)])]),
        event(102, "Create Session Response", "create-session", src=pgw, dst=sgw, teid=14, seq=2, cause=create_cause,
              fteids=[fteid(7, 5, pgw)], contexts=[context(5, [bearer_fteid(5, 54, "10.0.0.30")])]),
        event(103, "Create Session Response", "create-session", src=sgw, dst=mme, teid=1, seq=1, cause=create_cause,
              fteids=[fteid(11, 14, sgw), fteid(7, 5, pgw)],
              contexts=[context(5, [bearer_fteid(1, 56, "10.0.0.20"), bearer_fteid(5, 54, "10.0.0.30")])]),
        event(110, "Modify Bearer Request", "modify-bearer", src=mme, dst=sgw, teid=14, seq=3,
              contexts=[context(5, [bearer_fteid(0, 16777736, "10.0.0.40")])]),
        event(111, "Modify Bearer Response", "modify-bearer", src=sgw, dst=mme, teid=1, seq=3, cause=16,
              contexts=[context(5, [bearer_fteid(0, 16777736, "10.0.0.40")])]),
        event(120, "Delete Session Request", "delete-session", src=mme, dst=sgw, teid=14, seq=4,
              unbound={"binding_basis": "validator", "ebi_values": [5], "limitations": []}),
        event(121, "Delete Session Response", "delete-session", src=sgw, dst=mme, teid=1, seq=4, cause=16),
        event(122, "Delete Session Request", "delete-session", src=sgw, dst=pgw, teid=5, seq=5,
              unbound={"binding_basis": "validator", "ebi_values": [5], "limitations": []}),
        event(123, "Delete Session Response", "delete-session", src=pgw, dst=sgw, teid=14, seq=5, cause=16),
    ]
    transactions = [
        transaction("s11-create-a", "create-session", (100, "Create Session Request", 0, 1), (103, "Create Session Response", 1, 1)),
        transaction("s5-create-a", "create-session", (101, "Create Session Request", 0, 2), (102, "Create Session Response", 14, 2)),
        transaction("modify-a", "modify-bearer", (110, "Modify Bearer Request", 14, 3), (111, "Modify Bearer Response", 1, 3)),
        transaction("s11-delete-a", "delete-session", (120, "Delete Session Request", 14, 4), (121, "Delete Session Response", 1, 4)),
        transaction("s5-delete-a", "delete-session", (122, "Delete Session Request", 5, 5), (123, "Delete Session Response", 14, 5)),
    ]
    if second_same_control_teid:
        events.extend([
            event(500, "Create Session Request", "create-session", src=mme, dst=sgw, teid=0, seq=11,
                  fteids=[fteid(10, 1, mme), fteid(7, 0, pgw)]),
            event(501, "Create Session Request", "create-session", src=sgw, dst=pgw, teid=0, seq=12,
                  fteids=[fteid(6, 15, sgw)], contexts=[context(5, [bearer_fteid(4, 65, sgw)])]),
            event(502, "Create Session Response", "create-session", src=pgw, dst=sgw, teid=15, seq=12, cause=16,
                  fteids=[fteid(7, 9, pgw)], contexts=[context(5, [bearer_fteid(5, 64, "10.0.0.30")])]),
            event(503, "Create Session Response", "create-session", src=sgw, dst=mme, teid=1, seq=11, cause=16,
                  fteids=[fteid(11, 14, sgw), fteid(7, 9, pgw)],
                  contexts=[context(5, [bearer_fteid(1, 58, "10.0.0.20"), bearer_fteid(5, 64, "10.0.0.30")])]),
        ])
        transactions.extend([
            transaction("s11-create-b", "create-session", (500, "Create Session Request", 0, 11), (503, "Create Session Response", 1, 11)),
            transaction("s5-create-b", "create-session", (501, "Create Session Request", 0, 12), (502, "Create Session Response", 15, 12)),
        ])
    document = {
        "protocol": "gtpv2",
        "capture_files": [capture],
        "transaction_count": len(transactions),
        "transactions": transactions,
    }
    return events, document


def _validate_session_identity(skill: Path, root: Path) -> list[str]:
    """Validate the bounded EPC session-identity bridge capability."""
    errors: list[str] = []

    def fail(message: str) -> None:
        errors.append(message)

    schema_path = skill / "schemas" / "epc-session-identity-analysis.schema.json"
    rules_path = skill / "rules" / "epc-session-identity-model.json"
    for relative in (
        "scripts/epc_session_identity_model.py",
        "scripts/analyze_epc_session_identity.py",
        "scripts/epc_session_identity_report.py",
        "references/session-identity-bridge.md",
        "references/release-binding.md",
    ):
        if not (skill / relative).is_file():
            fail(f"missing session-identity file: {relative}")
    if errors:
        return errors
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        rules = json.loads(rules_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid session-identity contract file: {exc}")
        return errors

    model = load_session_identity_model(root)
    if tuple(rules.get("relationship_types", ())) != tuple(model.RELATIONSHIP_TYPES):
        fail("session-identity rules relationship types do not match the implementation")
    if tuple(rules.get("association_statuses", ())) != tuple(model.ASSOCIATION_STATUSES):
        fail("session-identity rules association statuses do not match the implementation")

    events, document = _session_identity_scenario()
    try:
        analysis = model.analyze(events, transactions=document)
    except model.InputError as exc:
        fail(f"the reviewed session-identity scenario failed: {exc}")
        return errors

    for field in schema.get("required", []):
        if field not in analysis:
            fail(f"session-identity analysis does not publish required field '{field}'")

    contexts = analysis["hop_local_contexts"]
    if len(contexts) != 2 or any(
        context["association_status"] != "ESTABLISHED" for context in contexts
    ):
        fail("the reviewed two-hop scenario must establish both hop-local contexts")
    identities = analysis["session_identity_links"]
    if len(identities) != 1 or identities[0]["association_status"] != "ESTABLISHED":
        fail("the relayed control-plane F-TEID must establish the session identity")
    if identities and identities[0]["relationship_type"] != "CROSS_INTERFACE_SESSION_IDENTITY":
        fail("the relayed F-TEID bridge must be published as cross-interface session identity")
    correspondences = analysis["endpoint_correspondence_links"]
    if len(correspondences) != 1 or correspondences[0]["association_status"] != "SUPPORTED":
        fail("the equal bearer user-plane F-TEID must stay an endpoint correspondence")
    bindings = analysis["release_session_bindings"]
    established = [item for item in bindings if item["association_status"] == "ESTABLISHED"]
    if len(established) != 2:
        fail("both reviewed releases must bind to their session contexts")
    candidates = [
        item
        for item in analysis["generation_closure_candidates"]
        if item["association_status"] == "ESTABLISHED"
    ]
    if len(candidates) != 2:
        fail("the reviewed scenario must publish two established closure candidates")
    for binding in bindings:
        if binding["release_outcome_status"] != "ACCEPTED":
            fail("a reviewed accepted release must keep its accepted outcome beside the binding")

    # A shared control-plane TEID value never joins: the release must stay
    # ambiguous when two contexts claim the same receiver-side F-TEID.
    ambiguous_events, ambiguous_document = _session_identity_scenario(
        second_same_control_teid=True
    )
    ambiguous = model.analyze(ambiguous_events, transactions=ambiguous_document)
    binding = next(
        (
            item
            for item in ambiguous["release_session_bindings"]
            if item["source_subject_reference"] == "s11-delete-a"
        ),
        None,
    )
    if binding is None or binding["association_status"] != "AMBIGUOUS":
        fail("a release addressing a TEID value claimed by two contexts must stay ambiguous")

    # The relayed F-TEID of a foreign interface type is never a join key: the
    # S5/S8 release binds the S5/S8 context only.
    s5_binding = next(
        (
            item
            for item in analysis["release_session_bindings"]
            if item["source_subject_reference"] == "s5-delete-a"
        ),
        None,
    )
    if s5_binding is None or s5_binding["association_status"] != "ESTABLISHED":
        fail("the S5/S8 release must bind through receiver-scoped addressing")
    else:
        target = next(
            (
                context
                for context in contexts
                if context["session_context_reference"] == s5_binding["target_subject_reference"]
            ),
            None,
        )
        if target is None or target["interface_class"] != "S5/S8":
            fail("a release must never bind through a relayed foreign-interface F-TEID")

    # The lifecycle closes through the reviewed session-context path only with
    # an accepted identity analysis, and a weakened analysis closes nothing.
    lifecycle = load_lifecycle_model(root)
    index = lifecycle.transaction_index(document, events)
    boundaries = lifecycle.release_boundaries(events, index)
    records = lifecycle.endpoint_records(events)
    conflicts = lifecycle.transaction_endpoint_values(document, events, index)
    families = lifecycle.build_advertisement_families(records, index, conflicts, boundaries)
    without_identity, _ = lifecycle.build_generations(families, boundaries)
    if any(
        generation["generation_state"] == "CLOSED_BY_ACCEPTED_RELEASE"
        for generation in without_identity
    ):
        fail("without a session-identity analysis the reviewed releases must not close generations")
    with_identity, _ = lifecycle.build_generations(
        families,
        boundaries,
        lifecycle._session_identity_closure_index(analysis),
    )
    closed = [
        generation
        for generation in with_identity
        if generation["generation_state"] == "CLOSED_BY_ACCEPTED_RELEASE"
    ]
    if len(closed) != 2:
        fail("the reviewed session-context path must close both fixture generations")
    for generation in closed:
        if generation["generation_boundary"]["basis"] != (
            "accepted_release_response_bound_by_reviewed_session_context"
        ):
            fail("a session-context closure must publish the reviewed basis")
        if generation["generation_boundary"]["release_effective_frame_proven"]:
            fail("no closure may claim a proven release-effective instant")
    links_weakened = json.loads(json.dumps(analysis))
    for link in links_weakened["session_to_generation_links"]:
        link["association_status"] = "SUPPORTED"
    weakened_generations, _ = lifecycle.build_generations(
        families,
        boundaries,
        lifecycle._session_identity_closure_index(links_weakened),
    )
    if any(
        generation["generation_state"] == "CLOSED_BY_ACCEPTED_RELEASE"
        for generation in weakened_generations
    ):
        fail("a session-identity analysis with only supported links must not close generations")
    candidates_weakened = json.loads(json.dumps(analysis))
    for candidate in candidates_weakened["generation_closure_candidates"]:
        candidate["association_status"] = "SUPPORTED"
    weakened_generations, _ = lifecycle.build_generations(
        families,
        boundaries,
        lifecycle._session_identity_closure_index(candidates_weakened),
    )
    if any(
        generation["generation_state"] == "CLOSED_BY_ACCEPTED_RELEASE"
        for generation in weakened_generations
    ):
        fail("a session-identity analysis with unsupported closure candidates must not close")

    # The release outcome stays separate from the binding: a rejected release
    # keeps an established binding and closes nothing.
    rejected_events, rejected_document = _session_identity_scenario()
    for item in rejected_events:
        if item["frame_number"] == 121:
            item["message_cause"] = {
                "cause_code": 72,
                "cause_name": "No resources available",
                "scope": "message",
            }
    rejected = model.analyze(rejected_events, transactions=rejected_document)
    rejected_binding = next(
        (
            item
            for item in rejected["release_session_bindings"]
            if item["source_subject_reference"] == "s11-delete-a"
        ),
        None,
    )
    if rejected_binding is None or rejected_binding["association_status"] != "ESTABLISHED":
        fail("a rejected release keeps its session binding; identity is independent of outcome")
    if rejected_binding is not None and rejected_binding["release_outcome_status"] != (
        "REJECTED_OBSERVED"
    ):
        fail("a Cause 72 response must classify the release as rejected")
    if any(
        item["association_status"] == "ESTABLISHED"
        and item["release_transaction_reference"] == "s11-delete-a"
        for item in rejected["generation_closure_candidates"]
    ):
        fail("a rejected release must not produce an established closure candidate")


    # A rejected allocation (Cause 72) keeps its observations but establishes
    # nothing downstream, and the lifecycle closes nothing through it.
    rejected_events, rejected_document = _session_identity_scenario(create_cause=72)
    rejected_analysis = model.analyze(rejected_events, transactions=rejected_document)
    for context in rejected_analysis["hop_local_contexts"]:
        if context["association_status"] != "NOT_ESTABLISHED":
            fail("a rejected allocation must not establish its hop-local context")
        if context["allocation_outcome_status"] != "REJECTED_OBSERVED":
            fail("a rejected allocation must publish its rejected outcome beside the correlation")
    if any(
        item["association_status"] == "ESTABLISHED"
        for item in rejected_analysis["session_to_generation_links"]
    ):
        fail("a rejected allocation must not establish any session-to-generation link")
    if rejected_analysis["established_closure_candidate_count"]:
        fail("a rejected allocation must not produce established closure candidates")

    # A bearer-scope rejection blocks exactly its own endpoint's association.
    bearer_events, bearer_document = _session_identity_scenario()
    for item in bearer_events:
        if item["frame_number"] == 103:
            for bearer in item["bearer_contexts"]:
                if any(ft["interface_type"] == 1 for ft in bearer["f_teids"]):
                    bearer["cause"] = {
                        "cause_code": 72,
                        "cause_name": "No resources available",
                        "scope": "bearer",
                    }
    bearer_analysis = model.analyze(bearer_events, transactions=bearer_document)
    bearer_links = {
        item["bearer_endpoint"]["role"]: item
        for item in bearer_analysis["session_to_generation_links"]
    }
    if bearer_links.get("sgw_s1u", {}).get("association_status") != "NOT_ESTABLISHED":
        fail("a rejected bearer item must block its own endpoint's bearer association")
    if bearer_links.get("sgw_s1u", {}).get("association_basis") != "bearer_item_rejected_observed":
        fail("a rejected bearer item must publish the bearer-scope rejection basis")
    if bearer_links.get("enodeb_s1u", {}).get("association_status") != "ESTABLISHED":
        fail("a bearer-scope rejection must not leak to other receiving roles")

    # One endpoint carrying two distinct item-scoped bearer identities stays
    # ambiguous and cannot isolate a bearer generation.
    multi_events, multi_document = _session_identity_scenario()
    for item in multi_events:
        if item["frame_number"] == 103:
            item["bearer_contexts"] = [
                {
                    "ebi": 5,
                    "cause": None,
                    "f_teids": [
                        {"scope": "bearer", "interface_type": 1, "teid": 56, "ipv4": "10.0.0.20"}
                    ],
                },
                {
                    "ebi": 6,
                    "cause": None,
                    "f_teids": [
                        {"scope": "bearer", "interface_type": 1, "teid": 56, "ipv4": "10.0.0.20"}
                    ],
                },
            ]
    multi_analysis = model.analyze(multi_events, transactions=multi_document)
    multi_links = {
        item["bearer_endpoint"]["role"]: item
        for item in multi_analysis["session_to_generation_links"]
    }
    if multi_links.get("sgw_s1u", {}).get("association_status") != "AMBIGUOUS":
        fail("an endpoint advertising two bearer identities must stay ambiguous")

    # A truncated identity analysis (counts exceeding published records) proves
    # no candidate-set uniqueness: the lifecycle refuses session-context closure
    # and publishes SOURCE_CANDIDATES_TRUNCATED.
    truncated = json.loads(json.dumps(analysis))
    truncated["generation_closure_candidate_count"] = 257
    filler = json.loads(json.dumps(truncated["generation_closure_candidates"][0]))
    filler.pop("generation_closure_candidate_reference", None)
    truncated["generation_closure_candidates"] = truncated[
        "generation_closure_candidates"
    ] + [filler] * (256 - len(truncated["generation_closure_candidates"]))
    truncated_index = lifecycle._session_identity_closure_index(truncated)
    if truncated_index.get("complete"):
        fail("a truncated identity analysis must fail the completeness gate")
    truncated_generations, _ = lifecycle.build_generations(
        families,
        boundaries,
        truncated_index,
    )
    if any(
        generation["generation_state"] == "CLOSED_BY_ACCEPTED_RELEASE"
        for generation in truncated_generations
    ):
        fail("a truncated identity analysis must not close any generation")

    # C1: an endpoint advertised only at message scope, without any grouped
    # bearer-context item carrying a readable EBI, cannot establish a bearer
    # association or a closure candidate; the lifecycle closes nothing for it.
    scope_only_events, scope_only_document = _session_identity_scenario()
    for item in scope_only_events:
        if item["frame_number"] == 103:
            item["bearer_contexts"] = []
            item["f_teids"] = item["f_teids"] + [
                {"scope": "message", "interface_type": 1, "teid": 56, "ipv4": "10.0.0.20"}
            ]
    scope_only = model.analyze(scope_only_events, transactions=scope_only_document)
    scope_links = {
        item["bearer_endpoint"]["role"]: item
        for item in scope_only["session_to_generation_links"]
    }
    if scope_links.get("sgw_s1u", {}).get("association_status") != "NOT_ESTABLISHED":
        fail("a message-scope-only endpoint must not establish a bearer association")
    if scope_links.get("sgw_s1u", {}).get("association_basis") != (
        "grouped_bearer_item_identity_missing"
    ):
        fail("a missing grouped bearer-item identity must publish its fail-closed basis")
    if scope_links.get("enodeb_s1u", {}).get("association_status") != "ESTABLISHED":
        fail("a message-scope-only advertisement must not block other receiving roles")
    if scope_only["established_closure_candidate_count"] != 1:
        fail("only the grouped-evidence endpoint may keep an established closure candidate")
    scope_index = lifecycle.transaction_index(scope_only_document, scope_only_events)
    scope_boundaries = lifecycle.release_boundaries(scope_only_events, scope_index)
    scope_records = lifecycle.endpoint_records(scope_only_events)
    scope_conflicts = lifecycle.transaction_endpoint_values(
        scope_only_document, scope_only_events, scope_index
    )
    scope_families = lifecycle.build_advertisement_families(
        scope_records, scope_index, scope_conflicts, scope_boundaries
    )
    scope_generations, _ = lifecycle.build_generations(
        scope_families,
        scope_boundaries,
        lifecycle._session_identity_closure_index(scope_only),
    )
    if sum(
        1
        for generation in scope_generations
        if generation["generation_state"] == "CLOSED_BY_ACCEPTED_RELEASE"
    ) != 1:
        fail("the message-scope-only generation must stay open at the lifecycle")

    # C3: a readable EPS Bearer Identity value is not an assigned bearer
    # identity. Zero is the explicit "no EPS bearer identity assigned" code
    # (3GPP TS 24.007 sec 11.2.3.1.5, TS 24.301 sec 9.3.2, TS 29.274 sec 8.8)
    # and a value outside the 4-bit encoded domain is no identity at all, so
    # neither may establish a bearer association, a closure candidate or a
    # generation.
    def _unassigned_scenario(value):
        scenario_events, scenario_document = _session_identity_scenario()
        for scenario_item in scenario_events:
            if scenario_item["frame_number"] == 103:
                scenario_item["bearer_contexts"] = [
                    {
                        "ebi": value,
                        "cause": None,
                        "f_teids": [
                            {
                                "scope": "bearer",
                                "interface_type": 1,
                                "teid": 56,
                                "ipv4": "10.0.0.20",
                            }
                        ],
                    }
                ]
        return scenario_events, scenario_document

    for unassigned_value in (0, 16, 99, -1):
        identity_events, identity_document = _unassigned_scenario(unassigned_value)
        identity = model.analyze(identity_events, transactions=identity_document)
        identity_links = {
            item["bearer_endpoint"]["role"]: item
            for item in identity["session_to_generation_links"]
        }
        unassigned_link = identity_links.get("sgw_s1u", {})
        if unassigned_link.get("association_status") != "NOT_ESTABLISHED":
            fail(
                "an unassigned or out-of-domain grouped EBI "
                f"({unassigned_value}) must not establish a bearer association"
            )
        if unassigned_link.get("association_basis") != (
            "grouped_bearer_item_identity_unassigned_or_invalid"
        ):
            fail(
                "an unassigned or out-of-domain grouped EBI "
                f"({unassigned_value}) must publish its fail-closed basis"
            )
        if unassigned_link.get("bearer_endpoint", {}).get("eps_bearer_identities") != [
            unassigned_value
        ]:
            fail("an unassigned or out-of-domain EBI must stay published as diagnostic evidence")
        if identity_links.get("enodeb_s1u", {}).get("association_status") != "ESTABLISHED":
            fail("an unassigned or out-of-domain EBI must not block another receiving role")
        if identity["established_closure_candidate_count"] != 1:
            fail("only the assigned-EBI endpoint may keep an established closure candidate")
        unassigned_index = lifecycle.transaction_index(identity_document, identity_events)
        unassigned_boundaries = lifecycle.release_boundaries(identity_events, unassigned_index)
        unassigned_records = lifecycle.endpoint_records(identity_events)
        unassigned_conflicts = lifecycle.transaction_endpoint_values(
            identity_document, identity_events, unassigned_index
        )
        unassigned_families = lifecycle.build_advertisement_families(
            unassigned_records, unassigned_index, unassigned_conflicts, unassigned_boundaries
        )
        unassigned_generations, _ = lifecycle.build_generations(
            unassigned_families,
            unassigned_boundaries,
            lifecycle._session_identity_closure_index(identity),
        )
        if sum(
            1
            for generation in unassigned_generations
            if generation["generation_state"] == "CLOSED_BY_ACCEPTED_RELEASE"
        ) != 1:
            fail("the unassigned-identity generation must stay open at the lifecycle")

    # A published closure candidate is never trusted on its own status: a
    # doctored ESTABLISHED candidate whose endpoint carries only EBI zero must
    # still close nothing, because the lifecycle re-verifies the identity.
    zero_events, zero_document = _unassigned_scenario(0)
    zero_analysis = model.analyze(zero_events, transactions=zero_document)
    doctored = json.loads(json.dumps(zero_analysis))
    doctored_link = next(
        item
        for item in doctored["session_to_generation_links"]
        if item["bearer_endpoint"]["role"] == "sgw_s1u"
    )
    doctored_link["association_status"] = "ESTABLISHED"
    doctored_candidate = next(
        item
        for item in doctored["generation_closure_candidates"]
        if item["bearer_endpoint_reference"] == doctored_link["target_subject_reference"]
    )
    doctored_candidate["association_status"] = "ESTABLISHED"
    doctored_candidate["bearer_endpoint"] = json.loads(
        json.dumps(doctored_link["bearer_endpoint"])
    )
    doctored_candidate["bearer_endpoint"]["eps_bearer_identities"] = [0]
    if (
        doctored_candidate["session_context_reference"],
        doctored_candidate["release_transaction_reference"],
        doctored_candidate["bearer_endpoint_reference"],
    ) in lifecycle._session_identity_closure_index(doctored)["candidates"]:
        fail("a closure candidate carrying only EBI zero must never be indexed for closure")

    # C2: missing completeness metadata, underdeclared counts and nonzero
    # omitted counts fail closed with their own precise limitation token; only
    # positive truncation keeps SOURCE_CANDIDATES_TRUNCATED.
    missing_count = json.loads(json.dumps(analysis))
    missing_count.pop("generation_closure_candidate_count")
    missing_index = lifecycle._session_identity_closure_index(missing_count)
    if missing_index.get("complete"):
        fail("a missing candidate count must fail the completeness gate")
    if "SOURCE_CANDIDATES_METADATA_INVALID" not in str(missing_index.get("limitation")):
        fail("a missing candidate count must publish the metadata-invalid limitation")
    underdeclared = json.loads(json.dumps(analysis))
    underdeclared["generation_closure_candidate_count"] = 1
    under_index = lifecycle._session_identity_closure_index(underdeclared)
    if under_index.get("complete"):
        fail("an underdeclared candidate count must fail the completeness gate")
    if "SOURCE_CANDIDATES_METADATA_INVALID" not in str(under_index.get("limitation")):
        fail("an underdeclared candidate count must publish the metadata-invalid limitation")
    nonzero_omitted = json.loads(json.dumps(analysis))
    nonzero_omitted["generation_closure_candidates_omitted"] = 5
    omitted_index = lifecycle._session_identity_closure_index(nonzero_omitted)
    if omitted_index.get("complete"):
        fail("a nonzero omitted count must fail the completeness gate")
    if "SOURCE_CANDIDATES_METADATA_INVALID" not in str(omitted_index.get("limitation")):
        fail("a nonzero omitted count must publish the metadata-invalid limitation")

    return errors

if __name__ == "__main__":
    raise SystemExit(main())
