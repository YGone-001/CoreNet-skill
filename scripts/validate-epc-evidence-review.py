#!/usr/bin/env python3
"""Behavior validation for the EPC Evidence Review Pack.

The gate builds real accepted-artifact documents, exercises the Review Pack
end-to-end, checks unresolved and ambiguous evidence behavior, verifies that
duplicate ownership stays local to actual claimants, verifies capture-scoped equal
textual references, checks replay failure semantics, and proves that a changed
review is detected. Three semantic mutations must each be detected and restored.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ARTIFACT_FILES = {
    "identity": ("epc-session-identity-analysis.json", "epc-session-identity"),
    "lifecycle": ("epc-bearer-lifecycle-analysis.json", "epc-bearer-lifecycle"),
    "narrative": ("epc-release-narrative-analysis.json", "epc-release-narrative"),
    "s1u": ("epc-s1u-observation.json", "epc-s1u-observation"),
}


def write_documents(directory: Path, documents: dict, audit: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for key, (filename, analysis_name) in ARTIFACT_FILES.items():
        payload = documents.get(key)
        if payload is None:
            continue
        payload = copy.deepcopy(payload)
        payload.setdefault("domain", "epc-procedures")
        payload.setdefault("analysis_name", analysis_name)
        payload.setdefault("analysis_version", "1.0.0")
        (directory / filename).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    (directory / "epc-evidence-audit-analysis.json").write_text(
        json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    gtpu = documents.get("gtpu")
    if gtpu is not None:
        (directory / "gtpu-events.jsonl").write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in gtpu),
            encoding="utf-8",
        )
    gtpv2 = documents.get("gtpv2")
    if gtpv2 is not None:
        (directory / "gtpv2-events.jsonl").write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in gtpv2),
            encoding="utf-8",
        )
    return directory


def audit_records(audit: dict, category: str, subject: str, capture: str | None = None):
    return [
        record
        for record in audit.get("audit_records") or []
        if record.get("audit_category") == category
        and (
            record.get("source_subject_reference") == subject
            or record.get("target_subject_reference") == subject
        )
        and (capture is None or record.get("capture_file") == capture)
    ]


def validate() -> list[str]:
    errors: list[str] = []

    def fail(message: str) -> None:
        errors.append(message)

    review = load_module(ROOT / "scripts" / "epc_evidence_review.py", "epc_evidence_review_gate")
    review_cli = ROOT / "scripts" / "epc-evidence-review.py"
    epc_validator = load_module(
        ROOT / "scripts" / "validate-epc-procedures.py", "epc_procedures_fixture_gate"
    )
    epc_scripts = str(ROOT / "skills" / "domain" / "epc-procedures" / "scripts")
    if epc_scripts not in sys.path:
        sys.path.insert(0, epc_scripts)
    audit_model = load_module(
        ROOT / "skills" / "domain" / "epc-procedures" / "scripts" / "epc_evidence_audit_model.py",
        "epc_audit_model_gate",
    )

    with tempfile.TemporaryDirectory(prefix="epc-review-validate-") as temporary:
        temporary_root = Path(temporary)

        positive = epc_validator._audit_scenario()
        positive_audit = epc_validator._audit_run(audit_model, positive)
        positive_source = write_documents(
            temporary_root / "positive", positive, positive_audit
        )
        artifacts, files = review.existing_artifact_pack(
            positive_source,
            gtpu_events=positive_source / "gtpu-events.jsonl",
            gtpv2_events=positive_source / "gtpv2-events.jsonl",
        )
        positive_pack = temporary_root / "positive-pack"
        review.write_pack(positive_pack, files, artifacts_dir=positive_source, force=True)
        for name in (
            "manifest.json",
            "evidence-review.json",
            "evidence-review.md",
            "evidence-index.json",
            "replay-verification.json",
        ):
            if not (positive_pack / name).is_file():
                fail(f"review pack is missing {name}")
        markdown = (positive_pack / "evidence-review.md").read_text(encoding="utf-8")
        for heading in (
            "## 1. Review Scope",
            "## 5. Release Outcome Summary",
            "## 18. Non-Goals and Safety Limitations",
        ):
            if heading not in markdown:
                fail(f"review markdown is missing section {heading}")
        positive_index = json.loads((positive_pack / "evidence-index.json").read_text())
        if positive_index.get("missing_reference_count") != 0:
            fail("complete positive evidence chain reported unresolved references")

        broken = copy.deepcopy(positive)
        broken["s1u"]["stream_observations"] = []
        broken["s1u"]["stream_count"] = 0
        broken_audit = epc_validator._audit_run(audit_model, broken)
        broken_source = write_documents(temporary_root / "broken", broken, broken_audit)
        broken_artifacts = review.load_artifacts(broken_source)
        broken_index = review.build_index(broken_artifacts["documents"])
        if not any(
            item.get("kind") == "S1U_STREAM"
            for item in broken_index.get("missing_references") or []
        ):
            fail("a broken S1U stream reference was not reported as unresolved")

        original_append_missing = review._append_missing
        try:
            review._append_missing = lambda *_args, **_kwargs: None
            mutated_index = review.build_index(broken_artifacts["documents"])
        finally:
            review._append_missing = original_append_missing
        if mutated_index.get("missing_references"):
            fail("mutation check failed: disabling missing-reference reporting was not detected")
        restored_index = review.build_index(broken_artifacts["documents"])
        if not restored_index.get("missing_references"):
            fail("mutation restore failed: missing-reference reporting stayed disabled")

        ambiguous = epc_validator._audit_two_generation_scenario()
        ambiguous["identity"]["generation_closure_candidates"].append(
            dict(
                ambiguous["identity"]["generation_closure_candidates"][1],
                generation_closure_candidate_reference=epc_validator.AUDIT_CANDIDATE_3,
            )
        )
        ambiguous["identity"]["generation_closure_candidate_count"] = 3
        ambiguous["identity"]["established_closure_candidate_count"] = 3
        ambiguous_audit = epc_validator._audit_run(audit_model, ambiguous)
        ambiguous_closures = audit_records(
            ambiguous_audit,
            "GENERATION_CLOSURE",
            epc_validator.AUDIT_GENERATION_2,
        )
        if not ambiguous_closures:
            fail("ambiguous generation produced no closure audit record")
        elif any(record.get("audit_status") == "VERIFIED_CONSISTENT" for record in ambiguous_closures):
            fail("ambiguous generation was promoted to verified")

        conflict = epc_validator._audit_conflict_scenario()
        conflict_audit = epc_validator._audit_run(audit_model, conflict)
        conflict_index = review.build_index(
            {
                review.ARTIFACT_SESSION_IDENTITY: conflict["identity"],
                review.ARTIFACT_BEARER_LIFECYCLE: conflict["lifecycle"],
                review.ARTIFACT_RELEASE_NARRATIVE: conflict["narrative"],
                review.ARTIFACT_S1U: conflict["s1u"],
                review.ARTIFACT_AUDIT: conflict_audit,
            }
        )
        review_document = review.build_review(
            {
                review.ARTIFACT_SESSION_IDENTITY: conflict["identity"],
                review.ARTIFACT_BEARER_LIFECYCLE: conflict["lifecycle"],
                review.ARTIFACT_RELEASE_NARRATIVE: conflict["narrative"],
                review.ARTIFACT_S1U: conflict["s1u"],
                review.ARTIFACT_AUDIT: conflict_audit,
            },
            conflict_index,
        )
        conflict_references = {
            item.get("temporal_observation_reference")
            for item in review_document["sections"]["conflicting_or_ambiguous_ownership"]
        }
        if not {
            epc_validator.AUDIT_TEMPORAL_1,
            epc_validator.AUDIT_TEMPORAL_2,
        }.issubset(conflict_references):
            fail("actual duplicate claimants were not disclosed")
        if epc_validator.AUDIT_TEMPORAL_3 in conflict_references:
            fail("an unrelated observation inherited a duplicate-ownership conflict")

        original_scope = audit_model._observation_conflict_scope
        try:
            audit_model._observation_conflict_scope = (
                lambda conflicts, _capture, _reference: bool(conflicts)
            )
            mutated_conflict = epc_validator._audit_run(audit_model, conflict)
        finally:
            audit_model._observation_conflict_scope = original_scope
        mutated_independent = audit_records(
            mutated_conflict, "TEMPORAL_FRAME_PARTITION", epc_validator.AUDIT_TEMPORAL_3
        )
        if not mutated_independent or mutated_independent[0].get("audit_status") != "INCONSISTENT":
            fail("mutation check failed: restoring global conflict propagation was not detected")
        restored_independent = audit_records(
            epc_validator._audit_run(audit_model, conflict),
            "TEMPORAL_FRAME_PARTITION",
            epc_validator.AUDIT_TEMPORAL_3,
        )
        if not restored_independent or restored_independent[0].get("audit_status") != "VERIFIED_CONSISTENT":
            fail("mutation restore failed: global conflict propagation stayed active")

        cross_capture = copy.deepcopy(conflict)
        stream_b = {
            "stream_reference": "stream-b2",
            "capture_file": epc_validator.AUDIT_CAPTURE_B,
            "outer_source": "10.0.0.20",
            "outer_destination": "10.0.0.40",
            "teid": 79,
            "first_frame": 400,
            "last_frame": 401,
            "observed_g_pdu_packet_count": 2,
            "observed_payload_byte_count": 200,
            "direction": "DOWNLINK",
            "association_status": "SUPPORTED",
            "matched_endpoint_role": "enodeb_s1u",
        }
        cross_capture["s1u"]["stream_observations"].append(stream_b)
        cross_capture["s1u"]["stream_count"] = 3
        cross_capture["s1u"]["observed_g_pdu_packet_count"] = 6
        cross_capture["s1u"]["observed_payload_byte_count"] = 600
        observation_capture_b = copy.deepcopy(cross_capture["narrative"]["temporal_observations"][0])
        observation_capture_b.update(
            {
                "temporal_observation_reference": epc_validator.AUDIT_TEMPORAL_1,
                "capture_file": stream_b["capture_file"],
                "stream_reference": "stream-b2",
                "first_observed_frame": 400,
                "last_observed_frame": 401,
                "release_request_frame": 402,
                "release_confirmation_frame": 403,
                "partitions": {
                    "before_release": {
                        "g_pdu_count": 2,
                        "payload_octets": 200,
                        "first_frame": 400,
                        "last_frame": 401,
                    },
                    "pending_release": {
                        "g_pdu_count": 0,
                        "payload_octets": 0,
                        "first_frame": None,
                        "last_frame": None,
                    },
                    "after_confirmation": {
                        "g_pdu_count": 0,
                        "payload_octets": 0,
                        "first_frame": None,
                        "last_frame": None,
                    },
                },
                "duplicate_frame_ownership": False,
            }
        )
        cross_capture["narrative"]["temporal_observations"].append(observation_capture_b)
        cross_capture["narrative"]["temporal_observation_count"] = 4
        release_capture_b = copy.deepcopy(cross_capture["narrative"]["release_narratives"][0])
        release_capture_b.update(
            {
                "release_narrative_reference": "rel-b",
                "capture_file": stream_b["capture_file"],
                "temporal_observation_references": [epc_validator.AUDIT_TEMPORAL_1],
            }
        )
        cross_capture["narrative"]["release_narratives"].append(release_capture_b)
        cross_capture["narrative"]["release_narrative_count"] = 4
        cross_capture["gtpu"] = list(cross_capture["gtpu"]) + [
            {
                "capture_file": stream_b["capture_file"],
                "frame_number": 400,
                "header": {"message_type": "G-PDU", "teid": 79, "message_length": 100},
                "outer": {"source_address": "10.0.0.20", "destination_address": "10.0.0.40"},
            },
            {
                "capture_file": stream_b["capture_file"],
                "frame_number": 401,
                "header": {"message_type": "G-PDU", "teid": 79, "message_length": 100},
                "outer": {"source_address": "10.0.0.20", "destination_address": "10.0.0.40"},
            },
        ]
        cross_capture_audit = epc_validator._audit_run(audit_model, cross_capture)
        cross_capture_index = review.build_index(
            {
                review.ARTIFACT_SESSION_IDENTITY: cross_capture["identity"],
                review.ARTIFACT_BEARER_LIFECYCLE: cross_capture["lifecycle"],
                review.ARTIFACT_RELEASE_NARRATIVE: cross_capture["narrative"],
                review.ARTIFACT_S1U: cross_capture["s1u"],
                review.ARTIFACT_AUDIT: cross_capture_audit,
            }
        )
        if not any(
            item.get("reference") == epc_validator.AUDIT_TEMPORAL_1
            for item in cross_capture_index.get("cross_capture_references") or []
        ):
            fail("equal textual observation references across captures were not disclosed")
        capture_b_records = audit_records(
            cross_capture_audit,
            "TEMPORAL_FRAME_PARTITION",
            epc_validator.AUDIT_TEMPORAL_1,
            stream_b["capture_file"],
        )
        if not capture_b_records or capture_b_records[0].get("audit_status") != "VERIFIED_CONSISTENT":
            fail("an equal textual observation reference inherited another capture's conflict")

        truncated = copy.deepcopy(positive)
        truncated["narrative"]["temporal_observations_omitted"] = 1
        truncated_audit = epc_validator._audit_run(audit_model, truncated)
        truncated_source = write_documents(temporary_root / "truncated", truncated, truncated_audit)
        truncated_artifacts = review.load_artifacts(truncated_source)
        truncated_manifest = review.build_manifest(
            truncated_artifacts,
            mode="EXISTING_ARTIFACTS",
            local_pcap_replayed=False,
            replay_status="NOT_EXECUTED",
        )
        if not truncated_manifest.get("audit_results_truncated"):
            fail("truncated source coverage was not disclosed")

        missing_capture = temporary_root / "missing.pcap"
        verification, replay_artifacts, _detail = review.run_local_replay(missing_capture)
        if verification.get("overall_status") != "FAILED" or replay_artifacts is not None:
            fail("a failed local replay was reported as usable evidence")
        failed_pack = temporary_root / "failed-pack"
        completed = subprocess.run(
            [
                sys.executable,
                str(review_cli),
                "--capture",
                str(missing_capture),
                "--output-dir",
                str(failed_pack),
                "--force",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 6:
            fail("failed replay CLI did not return the replay-failure exit code")
        failed_manifest = json.loads((failed_pack / "manifest.json").read_text())
        if failed_manifest.get("local_pcap_replayed") is not False:
            fail("failed replay manifest claimed a successful replay")

        pack_a = temporary_root / "pack-a"
        pack_b = temporary_root / "pack-b"
        review.write_pack(pack_a, files, artifacts_dir=positive_source, force=True)
        review.write_pack(pack_b, files, artifacts_dir=positive_source, force=True)
        identical = review.compare_runs(pack_a, pack_b)
        if identical.get("overall_status") != "IDENTICAL":
            fail("identical review packs were not compared as identical")
        changed_review = json.loads((pack_b / "evidence-review.json").read_text())
        changed_review["coverage"]["release_narrative_count"] = 99
        (pack_b / "evidence-review.json").write_text(
            json.dumps(changed_review, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        changed = review.compare_runs(pack_a, pack_b)
        if changed.get("overall_status") != "DIFFERENT":
            fail("changed review evidence was not detected")

        original_compare = review.compare_runs
        try:
            review.compare_runs = lambda *_args, **_kwargs: {"overall_status": "IDENTICAL"}
            mutated_compare = review.compare_runs(pack_a, pack_b)
        finally:
            review.compare_runs = original_compare
        if mutated_compare.get("overall_status") != "IDENTICAL":
            fail("mutation check failed: changed evidence did not compare as equal")
        restored_compare = review.compare_runs(pack_a, pack_b)
        if restored_compare.get("overall_status") != "DIFFERENT":
            fail("mutation restore failed: comparison remained weakened")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.parse_args()
    errors = validate()
    if errors:
        print("epc-evidence-review validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("epc-evidence-review validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())