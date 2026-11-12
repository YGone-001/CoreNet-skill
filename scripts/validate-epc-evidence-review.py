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
from unittest import mock

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
    review_cli_module = load_module(review_cli, "epc_evidence_review_cli_gate")
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

        replay_work = temporary_root / "replay-work"
        stale_run = replay_work / "epc" / "runs" / "ffffffffffffffff"
        stale_documents = copy.deepcopy(positive)
        stale_documents["identity"]["hop_local_contexts"][0]["association_basis"] = "stale"
        write_documents(
            stale_run,
            stale_documents,
            epc_validator._audit_run(audit_model, stale_documents),
        )
        capture_path = temporary_root / epc_validator.AUDIT_CAPTURE
        capture_path.write_bytes(b"validator-capture")

        def fake_replay_run(command, **_kwargs):
            invocation = Path(command[command.index("--work-dir") + 1])
            current = invocation / "epc" / "runs" / "0000000000000000"
            write_documents(current, positive, positive_audit)
            cli_output = Path(command[command.index("--output-dir") + 1])
            cli_output.mkdir(parents=True, exist_ok=True)
            (cli_output / "analysis.json").write_text(
                json.dumps({"overall_execution_status": "COMPLETED"}), encoding="utf-8"
            )
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(review.subprocess, "run", side_effect=fake_replay_run), mock.patch.object(
            review.shutil, "which", return_value="/bin/tshark"
        ):
            replay_verification, replay_artifacts, replay_detail = review.run_local_replay(
                capture_path, work_dir=replay_work
            )
        if (
            replay_verification.get("overall_status") != "COMPLETED"
            or replay_artifacts is None
        ):
            fail("current-invocation replay did not complete")
        if replay_detail.get("run_dir") != "0000000000000000":
            fail("replay selected a stale run directory")
        replay_manifest = review.build_manifest(
            replay_artifacts,
            mode="LOCAL_PCAP_REPLAY",
            local_pcap_replayed=True,
            replay_status="COMPLETED",
        )
        if replay_manifest.get("capture_identities") != [epc_validator.AUDIT_CAPTURE]:
            fail("replay consumed stale capture artifacts")
        current_run = next(
            replay_work.glob("epc-review-run-*/epc/runs/0000000000000000")
        )
        consumed = next(
            source["sha256"]
            for source in replay_manifest["source_artifacts"]
            if source["artifact_type"] == "session_identity"
        )
        if consumed != review.sha256_file(
            current_run / "epc-session-identity-analysis.json"
        ):
            fail("replay consumed an artifact outside the current invocation")
        if review.sha256_file(
            current_run / "epc-session-identity-analysis.json"
        ) == review.sha256_file(stale_run / "epc-session-identity-analysis.json"):
            fail("replay fixture did not distinguish current and stale artifacts")

        original_select = review._select_current_run
        try:
            review._select_current_run = (
                lambda candidates: sorted(candidates, key=lambda path: path.name)[-1]
                if candidates
                else None
            )
            mutated_selection = review._select_current_run([current_run, stale_run])
        finally:
            review._select_current_run = original_select
        if mutated_selection != stale_run:
            fail("mutation check failed: lexical stale-run selection was not detected")
        if review._select_current_run([current_run, stale_run]) is not None:
            fail("mutation restore failed: lexical stale-run selection stayed active")

        empty_work = temporary_root / "replay-empty"
        write_documents(empty_work / "epc" / "runs" / "ffffffffffffffff", positive, positive_audit)

        def no_current_run(command, **_kwargs):
            cli_output = Path(command[command.index("--output-dir") + 1])
            cli_output.mkdir(parents=True, exist_ok=True)
            (cli_output / "analysis.json").write_text(
                json.dumps({"overall_execution_status": "PARTIAL"}), encoding="utf-8"
            )
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(review.subprocess, "run", side_effect=no_current_run), mock.patch.object(
            review.shutil, "which", return_value="/bin/tshark"
        ):
            no_current_verification, no_current_artifacts, _detail = review.run_local_replay(
                capture_path, work_dir=empty_work
            )
        if (
            no_current_verification.get("overall_status") != "FAILED"
            or no_current_artifacts is not None
        ):
            fail("replay fell back to stale artifacts when no current run existed")

        def comparison_cli(first, second, label):
            output = temporary_root / f"compare-{label}"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(review_cli),
                    "--compare-a",
                    str(first),
                    "--compare-b",
                    str(second),
                    "--output-dir",
                    str(output),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            payload = (
                json.loads((output / "replay-verification.json").read_text())
                if (output / "replay-verification.json").is_file()
                else {}
            )
            return completed.returncode, payload.get("overall_status")

        pack_c = temporary_root / "pack-c"
        review.write_pack(pack_c, files, artifacts_dir=positive_source, force=True)
        for label, first, second, expected_code, expected_status in (
            ("identical", pack_a, pack_c, 0, "IDENTICAL"),
            ("different", pack_a, pack_b, 1, "DIFFERENT"),
            ("missing", pack_a, temporary_root / "absent-compare", 5, "MISSING_OUTPUT"),
        ):
            actual_code, actual_status = comparison_cli(first, second, label)
            if (actual_code, actual_status) != (expected_code, expected_status):
                fail(
                    f"comparison CLI returned {actual_code}/{actual_status} for {label}"
                )

        schema_pack = temporary_root / "schema-pack"
        review.write_pack(schema_pack, files, artifacts_dir=positive_source, force=True)
        schema_manifest = json.loads((schema_pack / "manifest.json").read_text())
        schema_manifest["schema_version"] = "9.0"
        (schema_pack / "manifest.json").write_text(
            json.dumps(schema_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        schema_code, schema_status = comparison_cli(pack_a, schema_pack, "schema")
        if (schema_code, schema_status) != (5, "SCHEMA_VERSION_MISMATCH"):
            fail("schema mismatch comparison did not return the intended nonzero status")

        capture_pack = temporary_root / "capture-pack"
        review.write_pack(capture_pack, files, artifacts_dir=positive_source, force=True)
        capture_manifest = json.loads((capture_pack / "manifest.json").read_text())
        capture_manifest["capture_identities"] = ["other.pcap"]
        (capture_pack / "manifest.json").write_text(
            json.dumps(capture_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        capture_code, capture_status = comparison_cli(pack_a, capture_pack, "capture")
        if (capture_code, capture_status) != (5, "INPUT_CAPTURE_MISMATCH"):
            fail("capture mismatch comparison did not return the intended nonzero status")

        original_exit = review_cli_module.review.comparison_exit_code
        try:
            review_cli_module.review.comparison_exit_code = (
                lambda status: 0 if status != "DIFFERENT" else 1
            )
            mutated_exit = review_cli_module._main(
                [
                    "--compare-a",
                    str(pack_a),
                    "--compare-b",
                    str(temporary_root / "absent-compare"),
                    "--output-dir",
                    str(temporary_root / "mutation-b"),
                    "--force",
                ]
            )
        finally:
            review_cli_module.review.comparison_exit_code = original_exit
        if mutated_exit != 0:
            fail(
                "mutation check failed: success exit for an incompatible comparison was not "
                "detected"
            )
        restored_exit = review_cli_module._main(
            [
                "--compare-a",
                str(pack_a),
                "--compare-b",
                str(temporary_root / "absent-compare"),
                "--output-dir",
                str(temporary_root / "mutation-b-restored"),
                "--force",
            ]
        )
        if restored_exit != 5:
            fail("mutation restore failed: incompatible comparison stayed successful")

        def ledger_audit(omitted, declared, record_count, exhaustive=True):
            audit = copy.deepcopy(positive_audit)
            audit["source_completeness"]["status"] = "COMPLETE"
            audit["source_completeness"]["exhaustive_coverage_proven"] = exhaustive
            for entry in audit["source_completeness"].get("collections", []):
                entry["status"] = "COMPLETE"
            base_records = audit["audit_records"]
            records = []
            for index in range(record_count):
                record = copy.deepcopy(base_records[index % len(base_records)])
                record["audit_record_reference"] = f"gate-record-{index:04d}"
                records.append(record)
            audit["audit_records"] = records
            audit["audit_record_count"] = declared
            audit["audit_records_omitted"] = omitted
            return audit

        omitted_audit = ledger_audit(44, 300, 256)
        omitted_source = write_documents(
            temporary_root / "ledger-truncated", positive, omitted_audit
        )
        omitted_artifacts = review.load_artifacts(omitted_source)
        omitted_manifest = review.build_manifest(
            omitted_artifacts,
            mode="EXISTING_ARTIFACTS",
            local_pcap_replayed=False,
            replay_status="NOT_EXECUTED",
        )
        omitted_review = review.build_review(
            omitted_artifacts["documents"],
            review.build_index(omitted_artifacts["documents"]),
        )
        if (
            not omitted_manifest.get("audit_results_truncated")
            or not omitted_manifest.get("source_collections_complete")
            or omitted_manifest.get("audit_ledger_complete")
        ):
            fail("omitted audit records were not disclosed while sources stayed complete")
        if omitted_manifest.get("audit_records_omitted") != 44:
            fail("omitted audit-record count was not published")
        if not any(
            item.get("collection") == "audit_records"
            for item in omitted_review["sections"]["source_completeness_limitations"]
        ):
            fail("audit ledger truncation was not published in the review view")
        if not any(
            item.get("status") == "DISPLAY_TRUNCATED"
            for item in omitted_review["sections"]["source_completeness_limitations"]
        ):
            fail("review display truncation was not independently disclosed")

        false_exhaustive = ledger_audit(0, 256, 256, exhaustive=False)
        false_source = write_documents(
            temporary_root / "exhaustive-false", positive, false_exhaustive
        )
        false_manifest = review.build_manifest(
            review.load_artifacts(false_source),
            mode="EXISTING_ARTIFACTS",
            local_pcap_replayed=False,
            replay_status="NOT_EXECUTED",
        )
        if false_manifest.get("source_collections_complete"):
            fail("false exhaustive-coverage flag appeared complete")

        original_completeness = review._audit_completeness

        def weakened_completeness(audit):
            data = dict(original_completeness(audit))
            data["audit_records_omitted"] = 0
            data["audit_ledger_complete"] = True
            data["audit_results_truncated"] = not data["source_collections_complete"]
            return data

        try:
            review._audit_completeness = weakened_completeness
            mutated_manifest = review.build_manifest(
                omitted_artifacts,
                mode="EXISTING_ARTIFACTS",
                local_pcap_replayed=False,
                replay_status="NOT_EXECUTED",
            )
        finally:
            review._audit_completeness = original_completeness
        if (
            mutated_manifest.get("audit_results_truncated")
            or not mutated_manifest.get("audit_ledger_complete")
        ):
            fail(
                "mutation check failed: ignoring audit_records_omitted was not detected"
            )
        restored_manifest = review.build_manifest(
            omitted_artifacts,
            mode="EXISTING_ARTIFACTS",
            local_pcap_replayed=False,
            replay_status="NOT_EXECUTED",
        )
        if not restored_manifest.get("audit_results_truncated"):
            fail("mutation restore failed: omitted audit records stayed ignored")

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