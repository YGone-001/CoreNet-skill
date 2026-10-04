#!/usr/bin/env python3
"""Validate the standalone 5GC PDU Session Domain Skill."""

from __future__ import annotations

import argparse
import hashlib
import json
import py_compile
import re
import sys
from pathlib import Path

SKILL = Path("skills/domain/5gc-pdu-session")
PROCEDURE_EVIDENCE_SCHEMA = Path("skills/domain/procedure-evidence/schemas/procedure-evidence.schema.json")

REQUIRED = (
    "SKILL.md", "README.md", "manifest.yaml",
    "references/procedure-model.md", "references/stage-model.md",
    "references/association-model.md", "references/deviation-model.md",
    "references/field-findings.md", "references/failure-cases.md",
    "scripts/pdu_session_model.py", "scripts/analyze_pdu_session.py", "scripts/pdu_session_timeline.py",
    "schemas/5gc-pdu-session-analysis.schema.json", "schemas/procedure-evidence.schema.json",
    "tests/test_5gc_pdu_session.py",
)

ESTABLISHMENT_SCENARIOS = {
    "normal-establishment", "establishment-reject", "create-sm-context-error",
    "pfcp-negative-cause", "ngap-failed-resource", "ngap-mixed-resources",
    "namf-pending-202", "namf-failure-notification", "no-gtpu-traffic",
    "multi-ue-same-psi", "sbi-ambiguity", "teid-reuse-different-endpoints",
    "address-and-qfi-conflict", "partial-capture",
}

MODIFICATION_SCENARIOS = {
    "ue-requested-modification",
    "network-requested-modification",
    "network-requested-no-ue-request",
    "two-sequential-modifications",
    "concurrent-distinct-pti-modifications",
    "ambiguous-concurrent-modifications",
    "same-pti-two-ues-modify",
    "update-sm-context-error",
    "pfcp-modification-accepted",
    "pfcp-modification-negative-cause",
    "pfcp-rule-create",
    "pfcp-rule-update",
    "pfcp-rule-remove",
    "ngap-resource-modify-success",
    "ngap-resource-modify-failed-item",
    "ngap-mixed-modify-items",
    "namf-modify-transfer-200",
    "namf-modify-pending-202",
    "namf-modify-failure-notification",
    "nas-modification-reject",
    "nas-command-reject",
    "fteid-unchanged-post-modification",
    "fteid-changed-matching-gtpu",
    "fteid-changed-no-gtpu",
    "same-teid-different-endpoints-modify",
    "qfi-updated-qer",
    "qfi-cross-plane-conflict",
    "duplicate-nas-modify-request",
    "duplicate-pfcp-modify-request",
    "late-capture-modification",
    "truncated-capture-modification",
    "tls-unavailable-sbi-modify",
    "protected-nas-inner-unavailable-modify",
    "release-events-after-modification",
    "network-only-modification-transactions",
    "release-ue-requested",
    "release-ue-requested-reject",
    "release-network-requested",
    "release-repeated-attempts",
    "release-same-pti-two-ues",
    "release-same-psi-two-ues",
    "release-command-retransmission",
    "release-request-retransmission",
    "release-protected-nas",
    "release-late-capture",
    "release-truncated-capture",
    "release-n11-update-context",
    "release-n11-release-smcontext-204",
    "release-n11-release-smcontext-error",
    "release-n11-release-smcontext-no-anchor",
    "release-pfcp-deletion-accepted",
    "release-pfcp-deletion-negative-cause",
    "release-pfcp-deletion-no-response",
    "release-pfcp-deletion-no-anchor",
    "release-ngap-resource-release",
    "release-ngap-multi-psi",
    "release-ngap-target-plus-unrelated",
    "release-namf-transfer-200",
    "release-namf-transfer-202",
    "release-namf-failure-notification",
    "release-end-marker-observed",
    "release-no-end-marker",
    "release-gtpu-after-complete",
    "release-no-gtpu-after-complete",
    "release-error-indication",
    "release-teid-reuse-endpoint",
    "release-teid-reuse-generation",
    "release-psi-reuse-after-complete",
    "release-psi-reuse-incomplete-boundary",
    "release-modification-before-release",
    "release-new-generation-modification",
    "release-interleaved-two-ues",
    "release-out-of-order-input",
    "release-partial-capture-multi-plane",
}

SCENARIOS = ESTABLISHMENT_SCENARIOS | MODIFICATION_SCENARIOS

CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
TEXT_SUFFIXES = {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
SUBSCRIBER_VALUE = re.compile(r'(?i)"(?:imsi|supi|suci|msisdn|imei)"\s*:\s*"[^"\n]+"')
AUTH_VECTOR = re.compile(r'(?i)"(?:rand|autn|res\*?|hxres\*?|kausf|kseaf|kamf)"\s*:\s*"[^"\n]+"')
IMPLEMENTATION_MAPPING = re.compile(r"(?is)(?:open5gs|free5gc|openairinterface|srsran|vendor).{0,120}(?:source|handler|function|path|mapping|module)")
RAW_DECODER = re.compile(r"(?i)def\s+(?:parse|decode)[a-z0-9_]*(?:nas|ngap|pfcp|gtp|packet|payload)|(?:raw_)?(?:nas|ngap|pfcp|gtpu)_payload\s*=")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s*[0-9]+\b|\bmilestone\s*[a-z]?[0-9]+\b")
FORBIDDEN_SCHEMA_FIELDS = re.compile(r"(?i)root_?cause|culprit|implementation|vendor|product_?bug")
TIMESTAMP_ONLY_JOIN = re.compile(r"(?i)\b(?:match|join|correlate)_by_timestamp_only\b")
GLOBAL_PTI_JOIN = re.compile(r"(?i)\b(?:global_pti|pti_only_join|join_by_pti_only)\b")
QFI_IDENTITY_JOIN = re.compile(r"(?i)\b(?:qfi_identity|join_by_qfi|qfi_only_join)\b")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_value(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def manifest_block_or_flow(text: str, key: str) -> list[str]:
    match = re.search(rf"(?m)^\s*{re.escape(key)}:\s*\[([^\]]*)\]", text)
    if match:
        return [item.strip() for item in match.group(1).split(",") if item.strip()]
    block = re.search(rf"(?m)^\s*{re.escape(key)}:\s*\n((?:\s+-\s+.+\n?)+)", text)
    if not block:
        return []
    return [line.strip().lstrip("-").strip() for line in block.group(1).splitlines() if line.strip()]


def check_structured_provenance(root: Path, errors: list[str]) -> None:
    """Every OBSERVED boundary-eligible deviation must carry a structured EVENT
    ref with frame provenance; every MISSING_EXPECTED_COUNTERPART must carry an
    OBSERVATION_WINDOW ref and no fabricated observed frame. Instances expose
    structured capture_file and observation_window."""
    expected_dir = root / "skills/domain/5gc-pdu-session/examples/expected"
    if not expected_dir.is_dir():
        return
    eligible = {
        "PROTOCOL_REJECT_OBSERVED", "PROTOCOL_NEGATIVE_OUTCOME_OBSERVED",
        "RESOURCE_FAILED_ITEM_OBSERVED", "DELIVERY_FAILURE_NOTIFICATION_OBSERVED",
        "MISSING_EXPECTED_COUNTERPART", "FIELD_CONFLICT",
    }
    for path in sorted(expected_dir.glob("*-analysis.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for inst in doc.get("instances", []):
            if inst.get("capture_file") is None:
                errors.append(f"{path.name}: instance {inst.get('instance_id')} lacks structured capture_file")
            all_devs = list(inst.get("deviations", []))
            for attempt in inst.get("modification_attempts", []) + inst.get("release_attempts", []):
                all_devs.extend(attempt.get("deviations", []))
            for deviation in all_devs:
                dtype = deviation.get("type")
                if dtype not in eligible:
                    continue
                refs = deviation.get("evidence_refs")
                if not isinstance(refs, list) or not refs:
                    errors.append(f"{path.name}: eligible deviation {dtype} lacks structured evidence_refs")
                    continue
                if dtype == "MISSING_EXPECTED_COUNTERPART":
                    if not any(r.get("kind") == "OBSERVATION_WINDOW" for r in refs):
                        errors.append(f"{path.name}: MISSING_EXPECTED_COUNTERPART lacks an OBSERVATION_WINDOW ref")
                    if any(r.get("kind") == "EVENT" and r.get("evidence_level") == "OBSERVED" and r.get("frame_number") is not None for r in refs):
                        errors.append(f"{path.name}: MISSING_EXPECTED_COUNTERPART must not carry a fabricated observed frame")
                else:
                    has_anchor = any(
                        (r.get("kind") == "EVENT" and r.get("evidence_level") == "OBSERVED" and r.get("frame_number") is not None)
                        or (r.get("kind") == "OBSERVATION_WINDOW")
                        for r in refs
                    )
                    if not has_anchor:
                        errors.append(f"{path.name}: OBSERVED deviation {dtype} lacks structured frame or window provenance")


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    skill = root / SKILL
    if not skill.is_dir():
        return [f"missing package directory: {SKILL}"]

    for relative in REQUIRED:
        if not (skill / relative).is_file():
            errors.append(f"missing required package file: {relative}")
    if errors:
        return errors

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    for key, expected in (("name", "5gc-pdu-session"), ("version", "0.4.0"), ("category", "domain")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"manifest {key} must be {expected}")

    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append("manifest required dependencies must be empty")
    if manifest_block_or_flow(manifest, "protocols") != []:
        errors.append("manifest protocols must remain empty")
    if manifest_block_or_flow(manifest, "network_functions") != []:
        errors.append("manifest network_functions must remain empty")
    if set(manifest_block_or_flow(manifest, "interfaces")) != {"N1", "N2", "N3", "N4", "N11"}:
        errors.append("manifest interfaces must be N1, N2, N3, N4, N11")

    # Release analysis lives inside 5gc-pdu-session; a separate Release Skill is forbidden.
    for forbidden_dir in ("pdu-session-release", "5gc-pdu-session-release", "pdu-session-release-domain"):
        if (root / "skills/domain" / forbidden_dir).is_dir():
            errors.append(f"separate Release Skill is forbidden; Release remains inside 5gc-pdu-session: {forbidden_dir}")

    # Release lifecycle contract consistency: the manifest must declare what
    # v0.3.0 implements and must not simultaneously exclude it.
    scope_includes = " ".join(manifest_block_or_flow(manifest, "includes")).lower()
    if "release attempt modeling" not in scope_includes or "release stages" not in scope_includes:
        errors.append("manifest scope.includes must declare bounded release attempt modeling and release stages")
    if "lifecycle generation" not in scope_includes:
        errors.append("manifest scope.includes must declare lifecycle generation handling")
    scope_excludes = manifest_block_or_flow(manifest, "excludes")
    for entry in scope_excludes:
        if re.search(r"(?i)pdu\s+session\s+release|release\s+lifecycle", entry):
            errors.append(
                "manifest scope.excludes must not exclude the implemented PDU Session Release lifecycle: "
                f"{entry}"
            )

    # Check that expected lower Skill dependencies are declared in optional dependencies
    optional_deps = " ".join(manifest_block_or_flow(manifest, "optional"))
    for exp_dep in ("nas-5gs", "ngap", "pfcp", "gtpu", "sbi-http2", "procedure-evidence"):
        if exp_dep not in optional_deps:
            errors.append(f"manifest optional dependencies should include {exp_dep}")

    local_evidence = skill / "schemas/procedure-evidence.schema.json"
    shared_evidence = root / PROCEDURE_EVIDENCE_SCHEMA
    if not shared_evidence.is_file() or digest(local_evidence) != digest(shared_evidence):
        errors.append("package-local procedure-evidence schema must match the generic framework bytes")

    try:
        schema = json.loads((skill / "schemas/5gc-pdu-session-analysis.schema.json").read_text(encoding="utf-8"))
        properties = schema.get("properties", {})
        for field in ("procedure_name", "procedure_version", "instances", "unbound_evidence", "limitations"):
            if field not in properties:
                errors.append(f"analysis schema must define {field}")
        instance = schema.get("$defs", {}).get("instanceAnalysis", {})
        instance_properties = instance.get("properties", {}) if isinstance(instance, dict) else {}
        for field in (
            "instance_id", "association_basis", "association_strength", "ue_context",
            "pdu_session_id", "stages", "terminal_observation", "deviations",
            "earliest_observed_deviation", "field_findings", "plane_bindings",
            "modification_attempts", "unbound_evidence", "limitations"
        ):
            if field not in instance_properties:
                errors.append(f"analysis schema must define instance {field}")

        # Check modification_attempts property is array
        mod_prop = instance_properties.get("modification_attempts", {})
        if mod_prop.get("type") != "array":
            errors.append("analysis schema modification_attempts property must be an array")

        # Check release_attempts property is array
        rel_prop = instance_properties.get("release_attempts", {})
        if rel_prop.get("type") != "array":
            errors.append("analysis schema release_attempts property must be an array")

        # Check releaseAttempt definition exists with required properties
        rel_def = schema.get("$defs", {}).get("releaseAttempt", {})
        if not rel_def:
            errors.append("analysis schema must define $defs/releaseAttempt")
        else:
            rel_props = rel_def.get("properties", {})
            for field in (
                "attempt_id", "trigger_type", "procedure_transaction_identity", "anchor_evidence",
                "association_basis", "association_strength", "association_details",
                "observation_window", "event_ownership", "stages",
                "terminal_observation", "deviations", "earliest_observed_deviation",
                "field_findings", "plane_bindings", "pre_release_context",
                "post_release_observations", "unbound_evidence", "limitations"
            ):
                if field not in rel_props:
                    errors.append(f"releaseAttempt definition must define {field}")
            rel_term = rel_props.get("terminal_observation", {}).get("properties", {}).get("observation", {})
            for vocab in ("RELEASE_COMPLETE_OBSERVED", "RELEASE_REJECT_OBSERVED", "NO_N1_RELEASE_TERMINAL_OBSERVATION"):
                if vocab not in rel_term.get("enum", []):
                    errors.append(f"releaseAttempt terminal vocabulary must include {vocab}")
            if "RELEASE_SUCCESS" in rel_term.get("enum", []) or "RELEASE_FAILURE" in rel_term.get("enum", []):
                errors.append("releaseAttempt terminal vocabulary must not include success/failure verdicts")

        forbidden = [field for field in properties if FORBIDDEN_SCHEMA_FIELDS.search(field)]
        if forbidden:
            errors.append(f"analysis schema must not include causal or implementation fields: {forbidden}")
    except json.JSONDecodeError as exc:
        errors.append(f"analysis schema is invalid JSON: {exc}")

    input_root = skill / "examples/inputs"
    actual_scenarios = {path.name for path in input_root.iterdir() if path.is_dir()} if input_root.is_dir() else set()
    if actual_scenarios != SCENARIOS:
        errors.append(f"synthetic input scenarios must cover all 88 bounded cases; found: {actual_scenarios}")

    for scenario in sorted(SCENARIOS):
        sdir = input_root / scenario
        found_any = any((sdir / f).is_file() for f in ("nas.jsonl", "ngap.jsonl", "pfcp.jsonl", "gtpu.jsonl", "sbi.jsonl"))
        if not found_any:
            errors.append(f"missing input files for scenario {scenario}")
        for suffix in ("analysis.json", "stages.jsonl"):
            if not (skill / "examples/expected" / f"{scenario}-{suffix}").is_file():
                errors.append(f"missing expected {suffix} fixture for {scenario}")

    # Explicit fixture existence checks required by contract
    required_fixtures = {
        "two-sequential-modifications": "sequential-attempt",
        "ue-requested-modification": "UE-requested",
        "network-requested-modification": "network-requested",
        "network-requested-no-ue-request": "branch-conditional",
        "same-pti-two-ues-modify": "PTI isolation",
        "pfcp-modification-accepted": "PFCP Modification",
        "ngap-resource-modify-success": "NGAP Modify",
        "update-sm-context-error": "SBI Update",
        "qfi-cross-plane-conflict": "QFI-conflict",
        "fteid-changed-matching-gtpu": "changed-F-TEID",
        "fteid-changed-no-gtpu": "no-GTPU neutral",
        "ambiguous-concurrent-modifications": "true concurrent cross-plane ambiguity",
        "network-only-modification-transactions": "network-only partial capture",
    }
    for fix_name, fix_desc in required_fixtures.items():
        if fix_name not in SCENARIOS:
            errors.append(f"missing required {fix_desc} fixture: {fix_name}")

    # Verify no-gtpu fixtures remain neutral and do not invent USER_PLANE_FAILED
    for no_gtpu_fix in ("no-gtpu-traffic", "fteid-changed-no-gtpu"):
        expected_path = skill / f"examples/expected/{no_gtpu_fix}-analysis.json"
        if expected_path.is_file():
            fix_text = expected_path.read_text(encoding="utf-8")
            if "USER_PLANE_FAILED" in fix_text:
                errors.append(f"{no_gtpu_fix} must remain neutral observation and not assert USER_PLANE_FAILED")

    # Post-modification GTP-U absence is conditional NOT_OBSERVED evidence, never
    # a missing required counterpart.
    no_gtpu_mod_expected = skill / "examples/expected/fteid-changed-no-gtpu-analysis.json"
    if no_gtpu_mod_expected.is_file():
        try:
            doc = json.loads(no_gtpu_mod_expected.read_text(encoding="utf-8"))
            for inst in doc.get("instances", []):
                for attempt in inst.get("modification_attempts", []):
                    pmo = next((s for s in attempt.get("stages", []) if s.get("stage_id") == "post_modification_observation"), None)
                    if pmo is not None:
                        if pmo.get("status") != "NOT_OBSERVED":
                            errors.append("fteid-changed-no-gtpu post_modification_observation must use NOT_OBSERVED status")
                        if pmo.get("missing_evidence"):
                            errors.append("fteid-changed-no-gtpu post_modification_observation must not emit missing_evidence for idle user plane")
            dev_types = {
                d.get("type")
                for inst in doc.get("instances", [])
                for attempt in inst.get("modification_attempts", [])
                for d in attempt.get("deviations", [])
                if d.get("stage_id") == "post_modification_observation"
            }
            if "MISSING_EXPECTED_COUNTERPART" in dev_types:
                errors.append("fteid-changed-no-gtpu must not emit a missing-counterpart deviation for idle user plane")
        except json.JSONDecodeError as exc:
            errors.append(f"fteid-changed-no-gtpu expected analysis is invalid JSON: {exc}")

    # The concurrent-ambiguity fixture must keep two distinct attempts and an
    # explicit CORRELATION_AMBIGUITY record with no forced attempt assignment.
    ambiguity_expected = skill / "examples/expected/ambiguous-concurrent-modifications-analysis.json"
    if ambiguity_expected.is_file():
        try:
            doc = json.loads(ambiguity_expected.read_text(encoding="utf-8"))
            inst = doc["instances"][0]
            if len(inst.get("modification_attempts", [])) != 2:
                errors.append("ambiguous-concurrent-modifications must keep two distinct modification attempts")
            ambiguous_records = [
                r for r in inst.get("unbound_evidence", [])
                if r.get("association_strength") == "AMBIGUOUS"
            ]
            if not ambiguous_records:
                errors.append("ambiguous-concurrent-modifications must retain an AMBIGUOUS unbound modification record")
            if not any(r.get("association_strength") == "AMBIGUOUS" and len(r.get("candidate_attempt_ids", [])) >= 2 for r in inst.get("unbound_evidence", [])):
                errors.append("ambiguous-concurrent-modifications ambiguous record must list both candidate attempts")
        except (json.JSONDecodeError, KeyError) as exc:
            errors.append(f"ambiguous-concurrent-modifications expected analysis is invalid: {exc}")

    # Release hard gates validated against committed fixture outputs.
    def _release_attempts(doc):
        for inst in doc.get("instances", []):
            for attempt in inst.get("release_attempts", []):
                yield inst, attempt

    def _expect_doc(rel_name, apply):
        path = skill / f"examples/expected/{rel_name}-analysis.json"
        if not path.is_file():
            return
        try:
            apply(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, KeyError, AssertionError) as exc:
            errors.append(f"{rel_name} expected analysis failed release contract check: {exc}")

    def _check_reject_not_boundary(doc):
        attempts = [a for _, a in _release_attempts(doc)]
        if not attempts or attempts[0]["terminal_observation"]["observation"] != "RELEASE_REJECT_OBSERVED":
            raise AssertionError("first release attempt must observe RELEASE_REJECT_OBSERVED")
        if len(doc["instances"]) != 1:
            raise AssertionError("release reject must not split the lifecycle generation")

    def _check_network_no_false_missing(doc):
        for _, attempt in _release_attempts(doc):
            init = next(s for s in attempt["stages"] if s["stage_id"] == "release_initiation")
            if attempt["trigger_type"] == "NETWORK_REQUESTED":
                if init["status"] != "OBSERVED":
                    raise AssertionError("network-requested release initiation must be OBSERVED")
                if any("ReleaseRequest" in m for m in init.get("missing_evidence", [])):
                    raise AssertionError("network-requested branch must not report a missing Release Request")

    def _check_bounded_success(doc, stage_id, needle):
        for _, attempt in _release_attempts(doc):
            stage = next(s for s in attempt["stages"] if s["stage_id"] == stage_id)
            text = json.dumps(stage)
            if needle not in text and stage.get("status") != "MISSING":
                raise AssertionError(f"{stage_id} must remain bounded evidence ({needle})")
            if "PDU_SESSION_RELEASE_SUCCESS" in text or "RELEASE_SUCCESS" in text:
                raise AssertionError(f"{stage_id} must not become a release success verdict")

    _expect_doc("release-ue-requested-reject", _check_reject_not_boundary)
    _expect_doc("release-network-requested", _check_network_no_false_missing)
    _expect_doc("release-pfcp-deletion-accepted", lambda doc: _check_bounded_success(doc, "user_plane_teardown_control", "PFCP_DELETION_ACCEPTED_OBSERVED"))
    _expect_doc("release-n11-release-smcontext-204", lambda doc: _check_bounded_success(doc, "sm_context_release_control", "bounded N11 response evidence"))
    _expect_doc("release-ngap-resource-release", lambda doc: _check_bounded_success(doc, "access_resource_release", "does not independently prove"))

    for no_end_marker_fix, expect_not_observed in (
        ("release-no-end-marker", True),
        ("release-no-gtpu-after-complete", True),
        ("release-gtpu-after-complete", False),
    ):
        path = skill / f"examples/expected/{no_end_marker_fix}-analysis.json"
        if path.is_file():
            doc = json.loads(path.read_text(encoding="utf-8"))
            for _, attempt in _release_attempts(doc):
                pro = next(s for s in attempt["stages"] if s["stage_id"] == "post_release_observation")
                expected_status = "NOT_OBSERVED" if expect_not_observed else "OBSERVED"
                if pro["status"] != expected_status:
                    errors.append(f"{no_end_marker_fix} post_release_observation must be {expected_status}")
                if "MISSING_EXPECTED_COUNTERPART" in [d["type"] for d in attempt["deviations"] if d.get("stage_id") == "post_release_observation"]:
                    errors.append(f"{no_end_marker_fix} must not emit a missing-counterpart deviation for post-release N3")

    # Lifecycle generation gates.
    reuse_path = skill / "examples/expected/release-psi-reuse-after-complete-analysis.json"
    if reuse_path.is_file():
        doc = json.loads(reuse_path.read_text(encoding="utf-8"))
        gens = sorted(i.get("session_generation") for i in doc.get("instances", []))
        if gens != [1, 2]:
            errors.append("release-psi-reuse-after-complete must produce two lifecycle generations")
        ids = [i["instance_id"] for i in doc.get("instances", [])]
        if len(set(ids)) != 2 or not all(i.endswith((":g1", ":g2")) for i in ids):
            errors.append("release-psi-reuse-after-complete must derive unique lifecycle instance ids")

    unsafe_path = skill / "examples/expected/release-psi-reuse-incomplete-boundary-analysis.json"
    if unsafe_path.is_file():
        doc = json.loads(unsafe_path.read_text(encoding="utf-8"))
        if len(doc.get("instances", [])) != 1:
            errors.append("release-psi-reuse-incomplete-boundary must not silently split the lifecycle")
        dev_types = {d["type"] for i in doc.get("instances", []) for d in i.get("deviations", [])}
        if "LIFECYCLE_AMBIGUITY" not in dev_types:
            errors.append("release-psi-reuse-incomplete-boundary must expose LIFECYCLE_AMBIGUITY")

    teid_path = skill / "examples/expected/release-teid-reuse-generation-analysis.json"
    if teid_path.is_file():
        doc = json.loads(teid_path.read_text(encoding="utf-8"))
        for inst in doc.get("instances", []):
            owned = [
                (r["protocol"], r["frame_number"])
                for att in inst.get("release_attempts", []) + inst.get("modification_attempts", [])
                for r in att["event_ownership"]["owned_event_refs"]
                if r["protocol"] == "GTP-U"
            ]
            if inst.get("session_generation") == 1 and any(f > 20 for _, f in owned):
                errors.append("release-teid-reuse-generation generation 1 must not own post-boundary GTP-U events")

    # Event ownership exclusivity across release attempts of committed fixtures.
    for scenario in ("release-repeated-attempts", "release-ue-requested", "release-interleaved-two-ues"):
        path = skill / f"examples/expected/{scenario}-analysis.json"
        if path.is_file():
            doc = json.loads(path.read_text(encoding="utf-8"))
            for inst in doc.get("instances", []):
                refs = [
                    (r["protocol"], r["capture_file"], r["frame_number"])
                    for att in inst.get("release_attempts", [])
                    for r in att["event_ownership"]["owned_event_refs"]
                ]
                if len(refs) != len(set(refs)):
                    errors.append(f"{scenario} release attempt event ownership must be exclusive")

    for path in skill.rglob("*"):
        if not path.is_file():
            continue
        name = path.relative_to(root)
        if path.suffix.lower() in CAPTURE_SUFFIXES:
            errors.append(f"binary capture fixture is not allowed: {name}")
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8")
        if "../../../" in text or "third_party/" in text:
            errors.append(f"repository-root runtime reference in {name}")
        if ABSOLUTE_PATH.search(text):
            errors.append(f"absolute workstation path in {name}")
        if LIFECYCLE_MARKER.search(text):
            errors.append(f"repository lifecycle marker in {name}")
        if SUBSCRIBER_VALUE.search(text):
            errors.append(f"subscriber identifier value in {name}")
        if AUTH_VECTOR.search(text):
            errors.append(f"authentication vector value in {name}")
        if path.parent.name != "tests" and path.suffix in {".py", ".json", ".jsonl"} and IMPLEMENTATION_MAPPING.search(text):
            errors.append(f"implementation or vendor source mapping in {name}")
        if path.suffix == ".py" and RAW_DECODER.search(text):
            errors.append(f"raw protocol decoding code in {name}")
        if path.parent.name != "tests" and path.suffix == ".py":
            if TIMESTAMP_ONLY_JOIN.search(text):
                errors.append(f"timestamp-only identity join antipattern in {name}")
            if GLOBAL_PTI_JOIN.search(text):
                errors.append(f"PTI-only global join antipattern in {name}")
            if QFI_IDENTITY_JOIN.search(text):
                errors.append(f"QFI-only identity join antipattern in {name}")

    for script_dir in (skill / "scripts", skill / "tests"):
        for script in script_dir.glob("*.py"):
            try:
                py_compile.compile(str(script), doraise=True)
            except py_compile.PyCompileError as exc:
                errors.append(f"script does not compile: {script.name}: {exc.msg}")

    check_structured_provenance(root, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("5gc-pdu-session validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("5gc-pdu-session validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
