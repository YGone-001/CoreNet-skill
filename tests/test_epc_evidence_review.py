#!/usr/bin/env python3
"""Behavior tests for the EPC Evidence Review Pack and local replay workflow."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
REVIEW_PATH = ROOT / "scripts" / "epc_evidence_review.py"
CLI_PATH = ROOT / "scripts" / "epc-evidence-review.py"
FIXTURES_PATH = ROOT / "skills" / "domain" / "epc-procedures" / "tests" / "test_epc_evidence_audit.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


REVIEW = load_module(REVIEW_PATH, "epc_evidence_review_under_test")
EPC = load_module(FIXTURES_PATH, "epc_evidence_review_fixtures")

ARTIFACT_FILES = {
    "identity": "epc-session-identity-analysis.json",
    "lifecycle": "epc-bearer-lifecycle-analysis.json",
    "narrative": "epc-release-narrative-analysis.json",
    "s1u": "epc-s1u-observation.json",
}


def write_documents(
    directory: Path,
    documents: dict,
    *,
    audit: dict | None = None,
    include_audit: bool = True,
    detailed: bool = False,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for key, filename in ARTIFACT_FILES.items():
        payload = documents.get(key)
        if payload is None:
            continue
        (directory / filename).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    if include_audit:
        audit_document = audit if audit is not None else EPC.audit(documents)
        (directory / "epc-evidence-audit-analysis.json").write_text(
            json.dumps(audit_document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if detailed and documents.get("gtpv2") is not None:
        (directory / "gtpv2-events.jsonl").write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in documents["gtpv2"]),
            encoding="utf-8",
        )
    if detailed and documents.get("gtpu") is not None:
        (directory / "gtpu-events.jsonl").write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in documents["gtpu"]),
            encoding="utf-8",
        )
    return directory


def record_for(result: dict, category: str, subject: str) -> dict:
    matches = [
        record
        for record in result.get("audit_records") or []
        if record.get("audit_category") == category
        and record.get("source_subject_reference") == subject
    ]
    assert matches, (category, subject)
    return matches[0]


class EpcEvidenceReviewTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def source(self, name: str = "artifacts", documents: dict | None = None, **kwargs) -> Path:
        documents = EPC.scenario() if documents is None else copy.deepcopy(documents)
        directory = self.root / name
        return write_documents(
            directory,
            documents,
            audit=kwargs.get("audit"),
            include_audit=kwargs.get("include_audit", True),
            detailed=kwargs.get("detailed", True),
        )

    def pack(self, source: Path, name: str = "pack") -> tuple[Path, dict, dict]:
        artifacts, files = REVIEW.existing_artifact_pack(
            source,
            gtpv2_events=source / "gtpv2-events.jsonl"
            if (source / "gtpv2-events.jsonl").is_file()
            else None,
            gtpu_events=source / "gtpu-events.jsonl"
            if (source / "gtpu-events.jsonl").is_file()
            else None,
        )
        output = self.root / name
        REVIEW.write_pack(output, files, artifacts_dir=source, force=True)
        return output, artifacts, files

    def read(self, output: Path, name: str) -> dict:
        return json.loads((output / name).read_text(encoding="utf-8"))

    def audit_status(self, artifacts: dict, category: str, subject: str) -> str:
        return record_for(artifacts["documents"]["evidence_audit"], category, subject)[
            "audit_status"
        ]

    def test_existing_artifact_review_pack_generation(self) -> None:
        output, artifacts, _files = self.pack(self.source())
        for name in (
            "manifest.json",
            "evidence-review.json",
            "evidence-review.md",
            "evidence-index.json",
            "replay-verification.json",
        ):
            self.assertTrue((output / name).is_file(), name)
        manifest = self.read(output, "manifest.json")
        self.assertEqual(manifest["mode"], "EXISTING_ARTIFACTS")
        self.assertEqual(manifest["capture_identities"], ["capture-a.pcap"])
        self.assertFalse(manifest["local_pcap_replayed"])
        markdown = (output / "evidence-review.md").read_text(encoding="utf-8")
        for heading in (
            "## 1. Review Scope",
            "## 9. Temporal Placement Summary",
            "## 18. Non-Goals and Safety Limitations",
        ):
            self.assertIn(heading, markdown)

    def test_local_replay_invocation_with_controlled_fixture(self) -> None:
        documents = EPC.scenario()
        commands: list[list[str]] = []

        def fake_run(command, **kwargs):
            commands.append(command)
            work = Path(command[command.index("--work-dir") + 1])
            run_dir = work / "epc" / "runs" / "replay1"
            write_documents(run_dir, documents, detailed=True)
            return subprocess.CompletedProcess(command, 0, "ok", "")

        capture = self.root / "controlled.pcap"
        capture.write_bytes(b"synthetic")
        with mock.patch.object(REVIEW.subprocess, "run", side_effect=fake_run), mock.patch.object(
            REVIEW.shutil, "which", return_value="/bin/tshark"
        ):
            verification, artifacts, _detail = REVIEW.run_local_replay(capture)
        self.assertEqual(verification["overall_status"], "COMPLETED")
        self.assertTrue(verification["replayed"])
        self.assertIsNotNone(artifacts)
        self.assertTrue(any("corenet-analyze.py" in value for value in commands[0]))
        self.assertIn("epc", commands[0])

    def test_missing_required_source_artifact(self) -> None:
        source = self.source()
        (source / ARTIFACT_FILES["identity"]).unlink()
        with self.assertRaises(REVIEW.ReviewInputError) as raised:
            REVIEW.load_artifacts(source)
        self.assertEqual(raised.exception.code, "MISSING_SOURCE_ARTIFACT")

    def test_invalid_source_json(self) -> None:
        source = self.source()
        (source / ARTIFACT_FILES["narrative"]).write_text("{", encoding="utf-8")
        with self.assertRaises(REVIEW.ReviewInputError) as raised:
            REVIEW.load_artifacts(source)
        self.assertEqual(raised.exception.code, "INVALID_SOURCE_JSON")

    def test_unsupported_schema_version(self) -> None:
        documents = EPC.scenario()
        documents["identity"]["analysis_version"] = "2.0.0"
        source = self.source(documents=documents)
        with self.assertRaises(REVIEW.ReviewInputError) as raised:
            REVIEW.load_artifacts(source)
        self.assertEqual(raised.exception.code, "UNSUPPORTED_SCHEMA_VERSION")

    def test_truncated_audit_records_are_disclosed(self) -> None:
        documents = EPC.scenario()
        documents["narrative"]["temporal_observations_omitted"] = 2
        output, _artifacts, _files = self.pack(self.source(documents=documents))
        manifest = self.read(output, "manifest.json")
        review = self.read(output, "evidence-review.json")
        self.assertTrue(manifest["audit_results_truncated"])
        self.assertFalse(manifest["source_collections_complete"])
        self.assertTrue(
            any(
                item.get("collection") == "temporal_observations"
                for item in review["sections"]["source_completeness_limitations"]
            )
        )

    def test_missing_reference_remains_unresolved(self) -> None:
        documents = EPC.scenario()
        documents["s1u"]["stream_observations"] = []
        documents["s1u"]["stream_count"] = 0
        output, _artifacts, _files = self.pack(self.source(documents=documents))
        index = self.read(output, "evidence-index.json")
        self.assertTrue(
            any(item.get("kind") == "S1U_STREAM" for item in index["missing_references"])
        )

    def test_ambiguous_reference_is_not_selected(self) -> None:
        documents = EPC.scenario()
        duplicate = copy.deepcopy(documents["narrative"]["temporal_observations"][0])
        documents["narrative"]["temporal_observations"].append(duplicate)
        documents["narrative"]["temporal_observation_count"] = 2
        output, _artifacts, _files = self.pack(self.source(documents=documents))
        index = self.read(output, "evidence-index.json")
        self.assertTrue(
            any(
                item.get("kind") == "temporal_observation"
                for item in index["ambiguous_references"]
            )
        )

    def test_equal_teids_across_captures_do_not_merge(self) -> None:
        documents = EPC.two_capture_documents()
        output, _artifacts, _files = self.pack(self.source(documents=documents))
        index = self.read(output, "evidence-index.json")
        self.assertEqual(sorted(item["capture"] for item in index["captures"]), ["capture-a.pcap", "capture-b.pcap"])
        self.assertEqual(index["reference_counts"]["s1u_stream"], 2)
        for capture in index["captures"]:
            self.assertEqual(len(capture["s1u_streams"]), 1)
            self.assertEqual(capture["s1u_streams"][0]["teid"], 77)

    def test_equal_frame_numbers_across_captures_remain_separate(self) -> None:
        documents = EPC.duplicate_ownership_documents()
        stream_b = documents["s1u"]["stream_observations"][1]
        stream_b.update({"capture_file": EPC.CAPTURE_B, "first_frame": 100, "last_frame": 101})
        observation_b = documents["narrative"]["temporal_observations"][2]
        observation_b.update(
            {
                "capture_file": EPC.CAPTURE_B,
                "first_observed_frame": 100,
                "last_observed_frame": 101,
                "release_request_frame": 102,
                "release_confirmation_frame": 103,
                "partitions": EPC.temporal_conflict_partitions(2, 200, 100, 101),
            }
        )
        documents["gtpu"] = [
            EPC.gtpu_event(100),
            EPC.gtpu_event(101),
            EPC.gtpu_event(100, capture=EPC.CAPTURE_B, teid=78),
            EPC.gtpu_event(101, capture=EPC.CAPTURE_B, teid=78),
        ]
        output, artifacts, _files = self.pack(self.source(documents=documents))
        self.assertEqual(
            self.audit_status(artifacts, "TEMPORAL_FRAME_PARTITION", "obs-b1"),
            "VERIFIED_CONSISTENT",
        )
        review = self.read(output, "evidence-review.json")
        conflicting = {
            item.get("temporal_observation_reference")
            for item in review["sections"]["conflicting_or_ambiguous_ownership"]
        }
        self.assertNotIn("obs-b1", conflicting)

    def test_equal_observation_reference_across_captures_stays_isolated(self) -> None:
        documents = EPC.duplicate_ownership_documents()
        stream_b = EPC.s1u_stream(capture=EPC.CAPTURE_B, stream_reference="stream-b2")
        stream_b.update(
            {
                "teid": 79,
                "first_frame": 400,
                "last_frame": 401,
                "observed_g_pdu_packet_count": 2,
                "observed_payload_byte_count": 200,
            }
        )
        documents["s1u"]["stream_observations"].append(stream_b)
        documents["s1u"]["stream_count"] = 3
        documents["s1u"]["observed_g_pdu_packet_count"] = 6
        documents["s1u"]["observed_payload_byte_count"] = 600
        documents["narrative"]["temporal_observations"].append(
            EPC.temporal_conflict_observation(
                "obs-a1",
                "stream-b2",
                (400, 401),
                capture=EPC.CAPTURE_B,
            )
        )
        documents["narrative"]["temporal_observation_count"] = 4
        documents["narrative"]["release_narratives"].append(
            EPC.temporal_conflict_release("rel-b", "tx-b", "obs-a1")
        )
        documents["narrative"]["release_narrative_count"] = 4
        documents["gtpu"] += [
            EPC.gtpu_event(400, capture=EPC.CAPTURE_B, teid=79),
            EPC.gtpu_event(401, capture=EPC.CAPTURE_B, teid=79),
        ]
        output, artifacts, _files = self.pack(self.source(documents=documents))
        index = self.read(output, "evidence-index.json")
        self.assertTrue(
            any(
                item.get("reference") == "obs-a1"
                for item in index["cross_capture_references"]
            )
        )
        capture_b_capture = next(
            item for item in index["captures"] if item["capture"] == EPC.CAPTURE_B
        )
        capture_b_observation = capture_b_capture["temporal_observations"][0]
        self.assertEqual(capture_b_observation["temporal_observation_reference"], "obs-a1")
        capture_b_records = [
            record
            for record in artifacts["documents"]["evidence_audit"]["audit_records"]
            if record.get("audit_category") == "TEMPORAL_FRAME_PARTITION"
            and record.get("source_subject_reference") == "obs-a1"
            and record.get("capture_file") == EPC.CAPTURE_B
        ]
        self.assertTrue(capture_b_records)
        self.assertEqual(capture_b_records[0]["audit_status"], "VERIFIED_CONSISTENT")

    def test_one_release_with_two_proved_generations(self) -> None:
        documents = EPC.closure_documents(
            [
                {"generation_reference": EPC.GENERATION},
                {
                    "direction": "UPLINK",
                    "generation_reference": EPC.UP_GENERATION,
                    "candidate_reference": EPC.UP_CANDIDATE,
                },
            ]
        )
        output, _artifacts, _files = self.pack(self.source(documents=documents))
        review = self.read(output, "evidence-review.json")
        releases = review["sections"]["release_outcome_summary"]
        self.assertEqual(len(releases), 1)
        self.assertEqual(releases[0]["proved_generation_count"], 2)
        self.assertEqual(len(review["sections"]["bearer_generation_closure_summary"]), 2)

    def test_valid_observed_subset_is_conservative(self) -> None:
        output, artifacts, _files = self.pack(
            self.source(documents=EPC.observed_subset_documents())
        )
        review = self.read(output, "evidence-review.json")
        placement = review["sections"]["temporal_placement_summary"][0]
        self.assertEqual(placement["temporal_placement_status"], "TEMPORAL_PLACEMENT_NOT_ESTABLISHED")
        self.assertTrue(
            any(
                item.get("status") == "TEMPORAL_PLACEMENT_NOT_ESTABLISHED"
                for item in review["sections"]["not_established_or_not_verifiable"]
            )
        )
        temporal_records = [
            record
            for record in artifacts["documents"]["evidence_audit"]["audit_records"]
            if record.get("audit_category") == "TEMPORAL_FRAME_PARTITION"
        ]
        self.assertTrue(all(record["audit_status"] == "VERIFIED_CONSISTENT" for record in temporal_records))

    def test_conflicted_temporal_observations_are_visible(self) -> None:
        output, _artifacts, _files = self.pack(
            self.source(documents=EPC.duplicate_ownership_documents())
        )
        review = self.read(output, "evidence-review.json")
        references = {
            item.get("temporal_observation_reference")
            for item in review["sections"]["conflicting_or_ambiguous_ownership"]
        }
        self.assertEqual(references, {"obs-a1", "obs-a2"})

    def test_independent_observation_beside_conflict_remains_verified(self) -> None:
        output, artifacts, _files = self.pack(
            self.source(documents=EPC.duplicate_ownership_documents())
        )
        self.assertEqual(
            self.audit_status(artifacts, "TEMPORAL_FRAME_PARTITION", "obs-b1"),
            "VERIFIED_CONSISTENT",
        )
        review = self.read(output, "evidence-review.json")
        temporal_references = {
            item.get("temporal_observation_reference")
            for item in review["sections"]["temporal_placement_summary"]
        }
        self.assertIn("obs-b1", temporal_references)

    def test_incomplete_candidate_collection_is_disclosed(self) -> None:
        documents = EPC.scenario()
        documents["identity"]["generation_closure_candidates_omitted"] = 2
        output, _artifacts, _files = self.pack(self.source(documents=documents))
        manifest = self.read(output, "manifest.json")
        review = self.read(output, "evidence-review.json")
        self.assertTrue(manifest["audit_results_truncated"])
        self.assertTrue(review["sections"]["source_completeness_limitations"])

    def test_missing_optional_gtpu_evidence_stays_not_verifiable(self) -> None:
        documents = EPC.scenario()
        documents["gtpu"] = None
        source = self.source(documents=documents)
        (source / "gtpu-events.jsonl").unlink(missing_ok=True)
        output, artifacts, _files = self.pack(source)
        manifest = self.read(output, "manifest.json")
        self.assertFalse(manifest["detailed_gtpu_supplied"])
        records = [
            record
            for record in artifacts["documents"]["evidence_audit"]["audit_records"]
            if record.get("audit_category") == "TEMPORAL_FRAME_PARTITION"
        ]
        self.assertTrue(
            any(record["audit_status"] == "NOT_INDEPENDENTLY_VERIFIABLE" for record in records)
        )

    def test_unestablished_session_generation_link_is_a_finding(self) -> None:
        documents = EPC.scenario()
        documents["identity"]["session_to_generation_links"][0]["association_status"] = "NOT_ESTABLISHED"
        output, _artifacts, _files = self.pack(self.source(documents=documents))
        review = self.read(output, "evidence-review.json")
        statuses = {
            item.get("audit_status")
            for item in review["sections"]["evidence_audit_findings"]
        }
        self.assertIn("INCONSISTENT", statuses)

    def test_incorrect_input_capture_hash_comparison(self) -> None:
        first, _artifacts, _files = self.pack(self.source("artifacts-a"), "pack-a")
        second, _artifacts2, _files2 = self.pack(self.source("artifacts-b"), "pack-b")
        replay = self.read(second, "replay-verification.json")
        replay["capture_sha256"] = "0" * 64
        (second / "replay-verification.json").write_text(
            json.dumps(replay, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        comparison = REVIEW.compare_runs(first, second)
        self.assertEqual(comparison["overall_status"], "INPUT_CAPTURE_MISMATCH")

    def test_identical_replay_comparison(self) -> None:
        first, _artifacts, _files = self.pack(self.source("artifacts-a"), "pack-a")
        second, _artifacts2, _files2 = self.pack(self.source("artifacts-b"), "pack-b")
        comparison = REVIEW.compare_runs(first, second)
        self.assertEqual(comparison["overall_status"], "IDENTICAL")
        self.assertEqual(comparison["differences"], [])

    def test_different_replay_comparison(self) -> None:
        first, _artifacts, _files = self.pack(self.source("artifacts-a"), "pack-a")
        second, _artifacts2, _files2 = self.pack(self.source("artifacts-b"), "pack-b")
        review = self.read(second, "evidence-review.json")
        review["coverage"]["release_narrative_count"] = 99
        (second / "evidence-review.json").write_text(
            json.dumps(review, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        comparison = REVIEW.compare_runs(first, second)
        self.assertEqual(comparison["overall_status"], "DIFFERENT")
        self.assertTrue(comparison["differences"])

    def test_reordered_source_records_keep_equivalent_evidence(self) -> None:
        documents = EPC.duplicate_ownership_documents()
        first = self.source("artifacts-a", documents=documents)
        reordered = copy.deepcopy(documents)
        reordered["narrative"]["temporal_observations"] = list(
            reversed(reordered["narrative"]["temporal_observations"])
        )
        reordered["narrative"]["release_narratives"] = list(
            reversed(reordered["narrative"]["release_narratives"])
        )
        reordered["s1u"]["stream_observations"] = list(
            reversed(reordered["s1u"]["stream_observations"])
        )
        reordered["gtpu"] = list(reversed(reordered["gtpu"]))
        second = self.source("artifacts-b", documents=reordered)
        first_pack, _a, _f = self.pack(first, "pack-a")
        second_pack, _b, _f2 = self.pack(second, "pack-b")
        comparison = REVIEW.compare_runs(first_pack, second_pack)
        self.assertEqual(comparison["overall_status"], "IDENTICAL")

    def test_privacy_redaction_of_untrusted_limitation_text(self) -> None:
        documents = EPC.scenario()
        audit = EPC.audit(documents)
        audit["audit_records"][0]["limitations"].append("imsi 001010000000001")
        source = self.source(documents=documents, audit=audit)
        output, _artifacts, _files = self.pack(source)
        for name in (
            "manifest.json",
            "evidence-review.json",
            "evidence-review.md",
            "evidence-index.json",
        ):
            self.assertNotIn("001010000000001", (output / name).read_text(encoding="utf-8"))

    def test_unsafe_output_path_aliasing_is_rejected(self) -> None:
        source = self.source()
        _artifacts, files = REVIEW.existing_artifact_pack(source)
        with self.assertRaises(REVIEW.ReviewInputError) as raised:
            REVIEW.write_pack(source / "nested", files, artifacts_dir=source, force=True)
        self.assertEqual(raised.exception.code, "UNSAFE_OUTPUT_PATH")
        real = self.root / "real-output"
        real.mkdir()
        link = self.root / "linked-output"
        try:
            link.symlink_to(real)
        except OSError:
            self.skipTest("symlinks are unavailable")
        with self.assertRaises(REVIEW.ReviewInputError) as symlink_error:
            REVIEW.write_pack(link, files, artifacts_dir=source, force=True)
        self.assertEqual(symlink_error.exception.code, "UNSAFE_OUTPUT_PATH")

    def test_deterministic_markdown_output(self) -> None:
        first, _artifacts, _files = self.pack(self.source("artifacts-a"), "pack-a")
        second, _artifacts2, _files2 = self.pack(self.source("artifacts-b"), "pack-b")
        self.assertEqual(
            (first / "evidence-review.md").read_bytes(),
            (second / "evidence-review.md").read_bytes(),
        )

    def test_deterministic_json_output(self) -> None:
        first, _artifacts, _files = self.pack(self.source("artifacts-a"), "pack-a")
        second, _artifacts2, _files2 = self.pack(self.source("artifacts-b"), "pack-b")
        for name in ("manifest.json", "evidence-review.json", "evidence-index.json"):
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())

    def test_summary_metrics_ignore_unrelated_limitation_text(self) -> None:
        documents = EPC.duplicate_ownership_documents()
        before = EPC.audit(documents)["temporal_integrity_summary"]
        documents["narrative"]["temporal_observations"][0]["limitations"] = [
            "an unrelated human-readable limitation"
        ]
        after = EPC.audit(documents)["temporal_integrity_summary"]
        self.assertEqual(before["partition_duplicate_assignment_count"], 2)
        self.assertEqual(before["conflicted_partition_count"], 2)
        self.assertEqual(before["partition_duplicate_assignment_count"], after["partition_duplicate_assignment_count"])
        self.assertEqual(before["conflicted_partition_count"], after["conflicted_partition_count"])

    def test_standalone_cli_end_to_end(self) -> None:
        source = self.source()
        output = self.root / "cli-pack"
        completed = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "--artifacts-dir",
                str(source),
                "--output-dir",
                str(output),
                "--force",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            sorted(path.name for path in output.iterdir()),
            [
                "evidence-index.json",
                "evidence-review.json",
                "evidence-review.md",
                "manifest.json",
                "replay-verification.json",
            ],
        )

    def test_local_replay_failure_is_not_reported_as_success(self) -> None:
        missing = self.root / "missing.pcap"
        output = self.root / "failed-pack"
        completed = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "--capture",
                str(missing),
                "--output-dir",
                str(output),
                "--force",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 6)
        verification = self.read(output, "replay-verification.json")
        manifest = self.read(output, "manifest.json")
        self.assertEqual(verification["overall_status"], "FAILED")
        self.assertFalse(manifest["local_pcap_replayed"])
        self.assertFalse(manifest["replay_status"] == "COMPLETED")

    def test_k1_k6_regression(self) -> None:
        k6 = EPC.audit(EPC.duplicate_ownership_documents())
        self.assertEqual(record_for(k6, "TEMPORAL_FRAME_PARTITION", "obs-a1")["audit_status"], "INCONSISTENT")
        self.assertEqual(record_for(k6, "TEMPORAL_FRAME_PARTITION", "obs-a2")["audit_status"], "INCONSISTENT")
        self.assertEqual(record_for(k6, "TEMPORAL_FRAME_PARTITION", "obs-b1")["audit_status"], "VERIFIED_CONSISTENT")
        k1 = EPC.audit(
            EPC.closure_documents(
                [
                    {"generation_reference": EPC.GENERATION},
                    {
                        "direction": "UPLINK",
                        "generation_reference": EPC.UP_GENERATION,
                        "candidate_reference": EPC.UP_CANDIDATE,
                    },
                ]
            )
        )
        closures = [
            record
            for record in k1["audit_records"]
            if record.get("audit_category") == "GENERATION_CLOSURE"
        ]
        self.assertTrue(closures)
        self.assertTrue(all(record["audit_status"] == "VERIFIED_CONSISTENT" for record in closures))


if __name__ == "__main__":
    unittest.main()