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
CLI = load_module(CLI_PATH, "epc_evidence_review_cli_under_test")
EPC = load_module(FIXTURES_PATH, "epc_evidence_review_fixtures")


def normalize_capture(value, capture: str):
    if isinstance(value, dict):
        return {key: normalize_capture(item, capture) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_capture(item, capture) for item in value]
    if isinstance(value, str) and value.endswith(".pcap"):
        return capture
    return value

ARTIFACT_FILES = {
    "identity": "epc-session-identity-analysis.json",
    "lifecycle": "epc-bearer-lifecycle-analysis.json",
    "narrative": "epc-release-narrative-analysis.json",
    "s1u": "epc-s1u-observation.json",
    "dedicated": "epc-dedicated-bearer-control-analysis.json",
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
            run_dir = work / "epc" / "runs" / "0000000000000000"
            write_documents(
                run_dir,
                normalize_capture(copy.deepcopy(documents), "controlled.pcap"),
                detailed=True,
            )
            cli_output = Path(command[command.index("--output-dir") + 1])
            cli_output.mkdir(parents=True, exist_ok=True)
            (cli_output / "analysis.json").write_text(
                json.dumps({"overall_execution_status": "COMPLETED"}), encoding="utf-8"
            )
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


class EpcReplayProvenanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def replay(
        self,
        work: Path,
        capture_name: str = "capture-a.pcap",
        documents: dict | None = None,
        *,
        exit_code: int = 0,
        cli_status: str = "COMPLETED",
        current_count: int = 1,
        omit: tuple[str, ...] = (),
        provenance_capture: str | None = None,
    ):
        capture = self.root / capture_name
        capture.write_bytes(b"capture:" + capture_name.encode())
        docs = normalize_capture(copy.deepcopy(documents or EPC.scenario()), capture_name)
        if provenance_capture is not None:
            docs = normalize_capture(docs, provenance_capture)

        def fake_run(command, **kwargs):
            invocation_work = Path(command[command.index("--work-dir") + 1])
            for index in range(current_count):
                run = invocation_work / "epc" / "runs" / f"{index:016d}"
                write_documents(run, docs)
                for name in omit:
                    (run / name).unlink(missing_ok=True)
            cli_output = Path(command[command.index("--output-dir") + 1])
            cli_output.mkdir(parents=True, exist_ok=True)
            (cli_output / "analysis.json").write_text(
                json.dumps({"overall_execution_status": cli_status}), encoding="utf-8"
            )
            return subprocess.CompletedProcess(command, exit_code, "", "")

        with mock.patch.object(REVIEW.subprocess, "run", side_effect=fake_run), mock.patch.object(
            REVIEW.shutil, "which", return_value="/bin/tshark"
        ):
            verification, artifacts, detail = REVIEW.run_local_replay(capture, work_dir=work)
        return capture, verification, artifacts, detail

    def stale(self, work: Path, name: str = "ffffffffffffffff", capture: str = "old.pcap") -> Path:
        run = work / "epc" / "runs" / name
        write_documents(run, normalize_capture(EPC.scenario(), capture))
        return run

    def current_run(self, work: Path, run_name: str) -> Path:
        invocation = next(work.glob("epc-review-run-*"))
        return invocation / "scratch" / "epc" / "runs" / run_name

    def manifest(self, artifacts: dict, verification: dict) -> dict:
        return REVIEW.build_manifest(
            artifacts,
            mode="LOCAL_PCAP_REPLAY",
            local_pcap_replayed=verification.get("replayed", False),
            replay_status=verification["overall_status"],
        )

    def test_l1_01_fresh_isolated_replay_succeeds(self) -> None:
        work = self.root / "work"
        _capture, verification, artifacts, detail = self.replay(work)
        self.assertEqual(verification["overall_status"], "COMPLETED")
        self.assertEqual(detail["run_dir"], "0000000000000000")
        self.assertEqual(self.manifest(artifacts, verification)["capture_identities"], ["capture-a.pcap"])

    def test_l1_02_stale_lexicographically_larger_uuid_ignored(self) -> None:
        work = self.root / "work"
        stale = self.stale(work)
        _capture, verification, artifacts, detail = self.replay(work)
        self.assertEqual(detail["run_dir"], "0000000000000000")
        self.assertEqual(self.manifest(artifacts, verification)["capture_identities"], ["capture-a.pcap"])
        self.assertNotEqual(
            REVIEW.sha256_file(stale / "epc-session-identity-analysis.json"),
            REVIEW.sha256_file(
                self.current_run(work, detail["run_dir"]) / "epc-session-identity-analysis.json"
            ),
        )

    def test_l1_03_current_lexicographically_smaller_uuid_selected(self) -> None:
        work = self.root / "work"
        self.stale(work, name="ffffffffffffffff")
        _capture, _verification, _artifacts, detail = self.replay(work)
        self.assertEqual(detail["run_dir"], "0000000000000000")

    def test_l1_04_multiple_stale_runs_ignored(self) -> None:
        work = self.root / "work"
        self.stale(work, name="aaaaaaaaaaaaaaaa", capture="old-a.pcap")
        self.stale(work, name="ffffffffffffffff", capture="old-b.pcap")
        _capture, verification, artifacts, detail = self.replay(work)
        self.assertEqual(detail["run_dir"], "0000000000000000")
        self.assertEqual(self.manifest(artifacts, verification)["capture_identities"], ["capture-a.pcap"])

    def test_l1_05_two_sequential_replays_same_root(self) -> None:
        work = self.root / "work"
        self.replay(work, capture_name="capture-a.pcap", documents=EPC.scenario())
        _capture, verification, artifacts, detail = self.replay(
            work,
            capture_name="capture-b.pcap",
            documents=EPC.scenario(capture="capture-b.pcap"),
        )
        self.assertEqual(detail["run_dir"], "0000000000000000")
        self.assertEqual(self.manifest(artifacts, verification)["capture_identities"], ["capture-b.pcap"])

    def test_l1_06_two_captures_same_root(self) -> None:
        work = self.root / "work"
        self.replay(work, capture_name="capture-a.pcap")
        _capture, _verification, _artifacts, second = self.replay(
            work, capture_name="capture-b.pcap", documents=EPC.scenario(capture="capture-b.pcap")
        )
        self.assertEqual(second["run_dir"], "0000000000000000")
        self.assertEqual(self.manifest(_artifacts, _verification)["capture_identities"], ["capture-b.pcap"])

    def test_l1_07_competing_current_runs_fail_closed(self) -> None:
        work = self.root / "work"
        self.stale(work)
        _capture, verification, artifacts, _detail = self.replay(work, current_count=2)
        self.assertEqual(verification["overall_status"], "FAILED")
        self.assertIsNone(artifacts)

    def test_l1_08_no_current_run_fails_closed(self) -> None:
        work = self.root / "work"
        self.stale(work)
        _capture, verification, artifacts, _detail = self.replay(work, current_count=0)
        self.assertEqual(verification["overall_status"], "FAILED")
        self.assertIsNone(artifacts)

    def test_l1_09_multiple_ambiguous_current_runs_fail_closed(self) -> None:
        work = self.root / "work"
        _capture, verification, artifacts, _detail = self.replay(work, current_count=3)
        self.assertEqual(verification["overall_status"], "FAILED")
        self.assertIsNone(artifacts)

    def test_l1_10_missing_required_current_artifact_fails(self) -> None:
        work = self.root / "work"
        _capture, verification, artifacts, _detail = self.replay(
            work, omit=("epc-session-identity-analysis.json",)
        )
        self.assertEqual(verification["overall_status"], "FAILED")
        self.assertIsNone(artifacts)

    def test_l1_11_current_artifact_differs_from_older(self) -> None:
        work = self.root / "work"
        stale = self.stale(work)
        _capture, verification, artifacts, detail = self.replay(work)
        current = self.current_run(work, detail["run_dir"])
        self.assertNotEqual(
            REVIEW.sha256_file(stale / "epc-session-identity-analysis.json"),
            REVIEW.sha256_file(current / "epc-session-identity-analysis.json"),
        )
        manifest = self.manifest(artifacts, verification)
        consumed = next(
            source["sha256"]
            for source in manifest["source_artifacts"]
            if source["artifact_type"] == "session_identity"
        )
        self.assertEqual(
            consumed, REVIEW.sha256_file(current / "epc-session-identity-analysis.json")
        )

    def test_l1_12_subprocess_zero_with_valid_current_completes(self) -> None:
        work = self.root / "work"
        _capture, verification, artifacts, _detail = self.replay(work, exit_code=0, cli_status="COMPLETED")
        self.assertEqual(verification["overall_status"], "COMPLETED")
        self.assertTrue(verification["replayed"])
        self.assertIsNotNone(artifacts)

    def test_l1_13_subprocess_failure_with_stale_artifacts_fails(self) -> None:
        work = self.root / "work"
        self.stale(work)
        _capture, verification, artifacts, _detail = self.replay(work, exit_code=4, current_count=0)
        self.assertEqual(verification["overall_status"], "FAILED")
        self.assertIsNone(artifacts)

    def test_l1_14_partial_completion_remains_partial(self) -> None:
        work = self.root / "work"
        _capture, verification, artifacts, _detail = self.replay(
            work, exit_code=0, cli_status="PARTIAL"
        )
        self.assertEqual(verification["overall_status"], "PARTIAL")
        self.assertFalse(verification["replayed"])
        self.assertIsNotNone(artifacts)
        verification_partial = REVIEW.build_replay_verification(
            mode="LOCAL_PCAP_REPLAY", status="PARTIAL"
        )
        output = self.root / "partial-cli"
        with mock.patch.object(
            CLI.review, "run_local_replay", return_value=(verification_partial, artifacts, {})
        ):
            code = CLI._main(
                [
                    "--capture",
                    str(self.root / "capture-a.pcap"),
                    "--output-dir",
                    str(output),
                    "--force",
                ]
            )
        self.assertEqual(code, 6)

    def test_l1_15_mismatched_capture_provenance_fails(self) -> None:
        work = self.root / "work"
        _capture, verification, artifacts, _detail = self.replay(
            work, provenance_capture="other.pcap"
        )
        self.assertEqual(verification["overall_status"], "FAILED")
        self.assertIsNone(artifacts)

    def test_l1_16_deterministic_pack_from_same_capture(self) -> None:
        work_a = self.root / "work-a"
        work_b = self.root / "work-b"
        _c, _v, artifacts_a, _d = self.replay(work_a)
        _c2, _v2, artifacts_b, _d2 = self.replay(work_b)
        first_files = REVIEW.build_review_pack(
            artifacts_a,
            mode="LOCAL_PCAP_REPLAY",
            replay_verification=REVIEW.build_replay_verification(
                mode="LOCAL_PCAP_REPLAY", status="COMPLETED"
            ),
        )
        second_files = REVIEW.build_review_pack(
            artifacts_b,
            mode="LOCAL_PCAP_REPLAY",
            replay_verification=REVIEW.build_replay_verification(
                mode="LOCAL_PCAP_REPLAY", status="COMPLETED"
            ),
        )
        for name in ("evidence-index.json", "evidence-review.json", "evidence-review.md"):
            self.assertEqual(first_files[name], second_files[name])


class EpcComparisonExitTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def pack(self, name: str, documents: dict, *, suffix: str = "pack") -> Path:
        source = self.root / f"{name}-artifacts"
        write_documents(source, copy.deepcopy(documents))
        _artifacts, files = REVIEW.existing_artifact_pack(source)
        output = self.root / f"{name}-{suffix}"
        REVIEW.write_pack(output, files, artifacts_dir=source, force=True)
        return output

    def compare(self, a: Path, b: Path, label: str, *, force: bool = False) -> dict:
        output = self.root / f"comparison-{label}"
        command = [
            sys.executable,
            str(CLI_PATH),
            "--compare-a",
            str(a),
            "--compare-b",
            str(b),
            "--output-dir",
            str(output),
        ]
        if force:
            command.append("--force")
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        path = output / "replay-verification.json"
        payload = json.loads(path.read_text()) if path.is_file() else {}
        return {"exit_code": completed.returncode, "status": payload.get("overall_status")}

    def test_l2_01_identical_returns_success(self) -> None:
        base = self.pack("base", EPC.scenario())
        result = self.compare(base, base, "identical")
        self.assertEqual((result["status"], result["exit_code"]), ("IDENTICAL", 0))

    def test_l2_02_changed_returns_different_nonzero(self) -> None:
        base = self.pack("base", EPC.scenario())
        changed = self.pack("changed", EPC.scenario())
        payload = json.loads((changed / "evidence-review.json").read_text())
        payload["coverage"]["release_narrative_count"] = 99
        (changed / "evidence-review.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        result = self.compare(base, changed, "different")
        self.assertEqual((result["status"], result["exit_code"]), ("DIFFERENT", 1))

    def test_l2_03_missing_input_directory_returns_nonzero(self) -> None:
        base = self.pack("base", EPC.scenario())
        result = self.compare(base, self.root / "absent", "missing-dir")
        self.assertEqual(result["status"], "MISSING_OUTPUT")
        self.assertEqual(result["exit_code"], 5)

    def test_l2_04_missing_required_file_returns_nonzero(self) -> None:
        base = self.pack("base", EPC.scenario())
        missing = self.pack("missing", EPC.scenario())
        (missing / "evidence-index.json").unlink()
        result = self.compare(base, missing, "missing-file")
        self.assertEqual(result["status"], "MISSING_OUTPUT")
        self.assertEqual(result["exit_code"], 5)

    def test_l2_05_unsupported_schema_returns_nonzero(self) -> None:
        base = self.pack("base", EPC.scenario())
        unsupported = self.pack("unsupported", EPC.scenario())
        manifest = json.loads((unsupported / "manifest.json").read_text())
        manifest.pop("schema_version")
        (unsupported / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        result = self.compare(base, unsupported, "unsupported")
        self.assertEqual(result["status"], "UNSUPPORTED_COMPARISON")
        self.assertEqual(result["exit_code"], 5)

    def test_l2_06_schema_mismatch_returns_nonzero(self) -> None:
        base = self.pack("base", EPC.scenario())
        schema = self.pack("schema", EPC.scenario())
        manifest = json.loads((schema / "manifest.json").read_text())
        manifest["schema_version"] = "9.0"
        (schema / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        result = self.compare(base, schema, "schema-mismatch")
        self.assertEqual(result["status"], "SCHEMA_VERSION_MISMATCH")
        self.assertEqual(result["exit_code"], 5)

    def test_l2_07_different_captures_return_nonzero(self) -> None:
        base = self.pack("base", EPC.scenario())
        other = self.pack("other", EPC.scenario(capture="other.pcap"))
        result = self.compare(base, other, "captures")
        self.assertEqual(result["status"], "INPUT_CAPTURE_MISMATCH")
        self.assertEqual(result["exit_code"], 5)

    def test_l2_08_different_capture_hashes_return_nonzero(self) -> None:
        base = self.pack("base", EPC.scenario())
        hashes = self.pack("hashes", EPC.scenario())
        replay = json.loads((hashes / "replay-verification.json").read_text())
        replay["capture_sha256"] = "f" * 64
        (hashes / "replay-verification.json").write_text(
            json.dumps(replay, indent=2, sort_keys=True) + "\n"
        )
        result = self.compare(base, hashes, "hashes")
        self.assertEqual(result["status"], "INPUT_CAPTURE_MISMATCH")
        self.assertEqual(result["exit_code"], 5)

    def test_l2_09_output_collision_returns_output_failure(self) -> None:
        base = self.pack("base", EPC.scenario())
        result = self.compare(base, base, "collision", force=False)
        second = self.compare(base, base, "collision")
        self.assertEqual(second["exit_code"], 7)

    def test_l2_10_output_write_failure_returns_output_failure(self) -> None:
        base = self.pack("base", EPC.scenario())
        blocked = self.root / "blocked"
        blocked.write_text("not a directory")
        completed = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "--compare-a",
                str(base),
                "--compare-b",
                str(base),
                "--output-dir",
                str(blocked / "sub"),
                "--force",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 7)

    def test_l2_11_repeated_identical_and_reordered_equivalent_are_success(self) -> None:
        documents = EPC.duplicate_ownership_documents()
        base = self.pack("base", documents)
        reordered = copy.deepcopy(documents)
        reordered["narrative"]["temporal_observations"] = list(
            reversed(reordered["narrative"]["temporal_observations"])
        )
        reordered["narrative"]["release_narratives"] = list(
            reversed(reordered["narrative"]["release_narratives"])
        )
        equivalent = self.pack("equivalent", reordered)
        first = self.compare(base, base, "repeat-1")
        second = self.compare(base, base, "repeat-2")
        reordered_result = self.compare(base, equivalent, "reordered")
        self.assertEqual((first["status"], first["exit_code"]), ("IDENTICAL", 0))
        self.assertEqual((second["status"], second["exit_code"]), ("IDENTICAL", 0))
        self.assertEqual((reordered_result["status"], reordered_result["exit_code"]), ("IDENTICAL", 0))


class EpcAuditTruncationTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def audit_documents(
        self,
        *,
        records: int = 5,
        declared: int | None = None,
        omitted: int | None = 0,
        exhaustive=True,
        status: str = "COMPLETE",
        collection_status: str = "COMPLETE",
        omit_exhaustive: bool = False,
        omit_omitted: bool = False,
        omitted_value=None,
    ) -> dict:
        documents = EPC.scenario()
        audit = EPC.audit(documents)
        base_records = audit["audit_records"]
        selected = []
        for index in range(records):
            record = copy.deepcopy(base_records[index % len(base_records)])
            record["audit_record_reference"] = f"truncation-record-{index:04d}"
            selected.append(record)
        audit["audit_records"] = selected
        if declared is None:
            declared = records + (omitted or 0)
        audit["audit_record_count"] = declared
        if omit_omitted:
            audit.pop("audit_records_omitted", None)
        elif omitted_value is not None:
            audit["audit_records_omitted"] = omitted_value
        else:
            audit["audit_records_omitted"] = omitted
        completeness = audit["source_completeness"]
        completeness["status"] = status
        if omit_exhaustive:
            completeness.pop("exhaustive_coverage_proven", None)
        else:
            completeness["exhaustive_coverage_proven"] = exhaustive
        for entry in completeness.get("collections", []):
            entry["status"] = collection_status
        return documents, audit

    def pack(self, audit: dict, name: str) -> tuple[dict, dict, str]:
        source = self.root / f"{name}-artifacts"
        write_documents(source, EPC.scenario(), audit=audit)
        _artifacts, files = REVIEW.existing_artifact_pack(source)
        output = self.root / f"{name}-pack"
        REVIEW.write_pack(output, files, artifacts_dir=source, force=True)
        manifest = json.loads((output / "manifest.json").read_text())
        review = json.loads((output / "evidence-review.json").read_text())
        markdown = (output / "evidence-review.md").read_text()
        return manifest, review, markdown

    def test_l3_01_complete_sources_and_complete_ledger(self) -> None:
        _documents, audit = self.audit_documents(records=5, declared=5, omitted=0)
        manifest, review, _markdown = self.pack(audit, "complete")
        self.assertFalse(manifest["audit_results_truncated"])
        self.assertTrue(manifest["source_collections_complete"])
        self.assertTrue(manifest["audit_ledger_complete"])
        self.assertTrue(manifest["review_display_complete"])

    def test_l3_02_complete_sources_and_truncated_ledger(self) -> None:
        _documents, audit = self.audit_documents(records=256, declared=300, omitted=44)
        manifest, review, _markdown = self.pack(audit, "ledger-truncated")
        self.assertTrue(manifest["audit_results_truncated"])
        self.assertTrue(manifest["source_collections_complete"])
        self.assertFalse(manifest["audit_ledger_complete"])
        self.assertEqual(manifest["audit_records_omitted"], 44)
        self.assertTrue(
            any(item.get("collection") == "audit_records" for item in review["sections"]["source_completeness_limitations"])
        )

    def test_l3_03_truncated_sources_and_complete_visible_ledger(self) -> None:
        _documents, audit = self.audit_documents(
            records=5, declared=5, omitted=0, collection_status="SOURCE_TRUNCATED"
        )
        manifest, _review, _markdown = self.pack(audit, "source-truncated")
        self.assertTrue(manifest["audit_results_truncated"])
        self.assertFalse(manifest["source_collections_complete"])
        self.assertTrue(manifest["audit_ledger_complete"])

    def test_l3_04_both_source_and_ledger_truncated(self) -> None:
        _documents, audit = self.audit_documents(
            records=256,
            declared=300,
            omitted=44,
            collection_status="SOURCE_TRUNCATED",
        )
        manifest, _review, _markdown = self.pack(audit, "both-truncated")
        self.assertFalse(manifest["source_collections_complete"])
        self.assertFalse(manifest["audit_ledger_complete"])
        self.assertTrue(manifest["audit_results_truncated"])

    def test_l3_05_false_exhaustive_flag_is_not_complete(self) -> None:
        _documents, audit = self.audit_documents(records=5, declared=5, omitted=0, exhaustive=False)
        manifest, review, _markdown = self.pack(audit, "exhaustive-false")
        self.assertFalse(manifest["source_collections_complete"])
        self.assertTrue(manifest["source_metadata_valid"] if "source_metadata_valid" in manifest else True)
        self.assertTrue(
            any(item.get("status") == "NOT_EXHAUSTIVE" for item in review["sections"]["source_completeness_limitations"])
        )

    def test_l3_06_missing_exhaustive_boolean_is_invalid(self) -> None:
        _documents, audit = self.audit_documents(records=5, declared=5, omitted=0, omit_exhaustive=True)
        manifest, review, _markdown = self.pack(audit, "exhaustive-missing")
        self.assertTrue(manifest["audit_results_truncated"])
        self.assertFalse(manifest["source_collections_complete"])
        self.assertTrue(
            any(item.get("status") == "INVALID_METADATA" for item in review["sections"]["source_completeness_limitations"])
        )

    def test_l3_07_missing_omitted_count_is_invalid(self) -> None:
        _documents, audit = self.audit_documents(records=5, declared=5, omit_omitted=True)
        manifest, _review, _markdown = self.pack(audit, "omitted-missing")
        self.assertFalse(manifest["audit_ledger_metadata_valid"])
        self.assertTrue(manifest["audit_results_truncated"])

    def test_l3_08_invalid_omitted_count_type_is_invalid(self) -> None:
        _documents, audit = self.audit_documents(records=5, declared=5, omitted_value="44")
        manifest, _review, _markdown = self.pack(audit, "omitted-type")
        self.assertFalse(manifest["audit_ledger_metadata_valid"])
        self.assertTrue(manifest["audit_results_truncated"])

    def test_l3_09_underdeclared_audit_record_count_is_invalid(self) -> None:
        _documents, audit = self.audit_documents(records=5, declared=4, omitted=0)
        manifest, _review, _markdown = self.pack(audit, "underdeclared")
        self.assertFalse(manifest["audit_ledger_metadata_valid"])

    def test_l3_10_inconsistent_count_metadata_is_invalid(self) -> None:
        _documents, audit = self.audit_documents(records=5, declared=99, omitted=2)
        manifest, _review, _markdown = self.pack(audit, "inconsistent")
        self.assertFalse(manifest["audit_ledger_metadata_valid"])

    def test_l3_11_review_display_truncation_is_independent(self) -> None:
        _documents, audit = self.audit_documents(records=256, declared=256, omitted=0)
        manifest, review, markdown = self.pack(audit, "display-only")
        self.assertTrue(manifest["audit_ledger_complete"])
        self.assertFalse(manifest["audit_results_truncated"])
        self.assertFalse(manifest["review_display_complete"])
        self.assertEqual(manifest["review_audit_records_omitted"], 208)
        self.assertEqual(review["coverage"]["review_audit_records_published"], 48)
        self.assertIn("DISPLAY_TRUNCATED", markdown)

    def test_l3_12_maximum_boundary_audit_record_count(self) -> None:
        _documents, audit = self.audit_documents(records=48, declared=48, omitted=0)
        manifest, _review, _markdown = self.pack(audit, "max-boundary")
        self.assertTrue(manifest["review_display_complete"])
        self.assertEqual(manifest["review_audit_records_omitted"], 0)

    def test_l3_13_manifest_reports_independent_dimensions(self) -> None:
        _documents, audit = self.audit_documents(records=256, declared=300, omitted=44)
        manifest, _review, _markdown = self.pack(audit, "dimensions")
        self.assertTrue(manifest["source_collections_complete"])
        self.assertFalse(manifest["audit_ledger_complete"])
        self.assertFalse(manifest["review_display_complete"])
        self.assertTrue(manifest["audit_results_truncated"])

    def test_l3_14_markdown_discloses_truncation(self) -> None:
        _documents, audit = self.audit_documents(records=256, declared=300, omitted=44)
        _manifest, _review, markdown = self.pack(audit, "markdown")
        self.assertIn("audit records: supplied 256, declared 300, omitted 44", markdown)
        self.assertIn("audit ledger complete: False", markdown)

    def test_l3_15_deterministic_repeated_output(self) -> None:
        _documents, audit = self.audit_documents(records=256, declared=300, omitted=44)
        first = self.pack(audit, "deterministic-a")
        second = self.pack(audit, "deterministic-b")
        self.assertEqual(first[0], second[0])
        self.assertEqual(first[1], second[1])
        self.assertEqual(first[2], second[2])


class EpcReplayPathIsolationTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_replay_paths_are_non_overlapping_siblings(self) -> None:
        scratch, output = REVIEW._replay_paths(Path("/tmp/invocation"))
        self.assertEqual(scratch.parent, output.parent)
        self.assertNotEqual(scratch, output)
        self.assertNotIn(scratch, output.parents)
        self.assertNotIn(output, scratch.parents)

    def test_replay_command_uses_scratch_and_sibling_output(self) -> None:
        work = self.root / "work"
        capture = self.root / "capture-a.pcap"
        capture.write_bytes(b"capture")
        commands: list[list[str]] = []

        def fake_run(command, **kwargs):
            commands.append(command)
            scratch = Path(command[command.index("--work-dir") + 1])
            run = scratch / "epc" / "runs" / "0000000000000000"
            write_documents(
                run,
                normalize_capture(copy.deepcopy(EPC.scenario()), "capture-a.pcap"),
            )
            output = Path(command[command.index("--output-dir") + 1])
            output.mkdir(parents=True, exist_ok=True)
            (output / "analysis.json").write_text(
                json.dumps({"overall_execution_status": "COMPLETED"}), encoding="utf-8"
            )
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(REVIEW.subprocess, "run", side_effect=fake_run), mock.patch.object(
            REVIEW.shutil, "which", return_value="/bin/tshark"
        ):
            verification, artifacts, detail = REVIEW.run_local_replay(
                capture, work_dir=work
            )
        self.assertEqual(verification["overall_status"], "COMPLETED")
        self.assertIsNotNone(artifacts)
        work_path = Path(commands[0][commands[0].index("--work-dir") + 1])
        output_path = Path(commands[0][commands[0].index("--output-dir") + 1])
        self.assertEqual(work_path.name, "scratch")
        self.assertEqual(output_path.name, "cli-output")
        self.assertNotIn(work_path, output_path.parents)
        self.assertNotIn(output_path, work_path.parents)
        self.assertEqual(detail["run_dir"], "0000000000000000")


    def test_unified_cli_rejects_nested_work_output_paths(self) -> None:
        work = self.root / "work"
        capture = self.root / "x.pcap"
        capture.write_bytes(b"not-a-real-capture")
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "corenet-analyze.py"),
                "--capture",
                str(capture),
                "--domains",
                "epc",
                "--work-dir",
                str(work),
                "--output-dir",
                str(work / "out"),
                "--force",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 4)
        self.assertIn("UNSAFE_PATH_OVERLAP", completed.stderr)


def dedicated_document(
    *,
    capture: str = "capture-a.pcap",
    create: int = 2,
    update: int = 1,
    delete: int = 1,
    completeness: str = "COMPLETE",
) -> dict:
    transactions = []
    items = []
    associations = []
    index = 0
    for family, count in (
        ("create-bearer", create),
        ("update-bearer", update),
        ("delete-bearer", delete),
    ):
        for occurrence in range(count):
            reference = f"epc-db-tx:{capture}:{family}-{index}"
            transactions.append(
                {
                    "capture": capture,
                    "correlation_status": "MATCHED",
                    "correlation_strength": "STRONG",
                    "procedure_family": family,
                    "transaction_reference": reference,
                    "protocol_transaction_reference": f"gtpv2-{family}-{index}",
                    "message_outcome": {
                        "status": "MESSAGE_ACCEPTED_OBSERVED",
                        "cause": {
                            "cause_code": 16,
                            "cause_name": "Request accepted",
                            "scope": "message",
                        },
                        "limitations": [],
                    },
                    "transaction_outcome": "CONTROL_ACCEPTED_OBSERVED",
                    "evidence_limitations": [],
                    "source_completeness_status": completeness,
                }
            )
            request_reference = f"epc-db-item:{reference}:request:{index}:0:0"
            item_reference = f"epc-db-item:{reference}:response:{index}:0:0"
            items.append(
                {
                    "capture": capture,
                    "ebi": 7,
                    "ebi_status": "VALID",
                    "ebi_valid": True,
                    "item_reference": request_reference,
                    "item_outcome": "ITEM_REQUEST_EVIDENCE_ONLY",
                    "procedure_family": family,
                    "side": "REQUEST",
                    "transaction_reference": reference,
                    "evidence_limitations": [],
                    "source_completeness_status": completeness,
                }
            )
            items.append(
                {
                    "capture": capture,
                    "ebi": 7,
                    "ebi_status": "VALID",
                    "ebi_valid": True,
                    "item_reference": item_reference,
                    "item_outcome": "ITEM_CONTROL_ACCEPTED_OBSERVED",
                    "procedure_family": family,
                    "side": "RESPONSE",
                    "transaction_reference": reference,
                    "evidence_limitations": [],
                    "source_completeness_status": completeness,
                }
            )
            associations.append(
                {
                    "association_reference": f"epc-db-assoc:{reference}:{index}",
                    "capture": capture,
                    "ebi": 7,
                    "status": "ITEM_ASSOCIATION_ESTABLISHED",
                    "transaction_reference": reference,
                    "request_item_reference": request_reference,
                    "response_item_reference": item_reference,
                    "limitations": [],
                }
            )
            index += 1
    return {
        "analysis_name": "epc-dedicated-bearer-control",
        "analysis_version": "1.0.0",
        "domain": "epc-procedures",
        "control_transaction_count": len(transactions),
        "control_transactions": transactions,
        "control_transactions_omitted": 0,
        "bearer_item_observation_count": len(items),
        "bearer_item_observations": items,
        "bearer_item_observations_omitted": 0,
        "item_association_count": len(associations),
        "item_associations": associations,
        "item_associations_omitted": 0,
        "source_completeness": {
            "status": completeness,
            "exhaustive_coverage_proven": completeness == "COMPLETE",
            "limitations": [] if completeness == "COMPLETE" else ["truncated source"],
        },
        "evidence_limitations": [
            "a correlated Create/Update/Delete Bearer transaction proves an observed signaling exchange only",
        ],
        "not_confirmed": [
            "no dedicated-bearer activation, modification or effective removal is proven",
        ],
    }


class EpcDedicatedBearerReviewTests(unittest.TestCase):
    """The optional dedicated-bearer artifact is loaded, bounded and navigable."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def source(self, documents: dict, name: str = "artifacts") -> Path:
        directory = self.root / name
        return write_documents(directory, documents, detailed=True)

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

    def documents(self, **kwargs) -> dict:
        documents = EPC.scenario()
        documents["dedicated"] = dedicated_document(**kwargs)
        return documents

    def test_supplied_artifact_is_loaded_hashed_and_provenanced(self) -> None:
        source = self.source(self.documents())
        output, _artifacts, _files = self.pack(source)
        manifest = self.read(output, "manifest.json")
        expected = REVIEW.sha256_file(
            source / "epc-dedicated-bearer-control-analysis.json"
        )
        entry = [
            item
            for item in manifest["source_artifacts"]
            if item["artifact_type"] == "dedicated_bearer_control"
        ][0]
        self.assertTrue(entry["supplied"])
        self.assertEqual(entry["sha256"], expected)
        self.assertEqual(entry["analysis_name"], "epc-dedicated-bearer-control")
        self.assertEqual(
            manifest["provenance"]["dedicated_bearer_control"],
            "epc-dedicated-bearer-control-analysis.json",
        )
        review = self.read(output, "evidence-review.json")
        self.assertTrue(review["coverage"]["dedicated_source_supplied"])
        self.assertEqual(review["coverage"]["dedicated_status"], "EXECUTED")
        self.assertEqual(review["coverage"]["dedicated_control_transaction_count"], 4)
        self.assertEqual(review["coverage"]["dedicated_bearer_item_count"], 8)
        self.assertEqual(review["coverage"]["dedicated_item_association_count"], 4)
        summary = review["sections"]["dedicated_bearer_control_summary"][0]
        self.assertEqual(
            summary["transaction_family_counts"],
            {"create-bearer": 2, "update-bearer": 1, "delete-bearer": 1},
        )
        self.assertEqual(summary["message_outcome_counts"], {"MESSAGE_ACCEPTED_OBSERVED": 4})
        self.assertEqual(
            summary["item_outcome_counts"],
            {
                "ITEM_CONTROL_ACCEPTED_OBSERVED": 4,
                "ITEM_REQUEST_EVIDENCE_ONLY": 4,
            },
        )

    def test_markdown_renders_bounded_summary_and_disclaimer(self) -> None:
        source = self.source(self.documents())
        output, _artifacts, _files = self.pack(source)
        markdown = (output / "evidence-review.md").read_text(encoding="utf-8")
        self.assertIn("## 9A. Dedicated Bearer Control Evidence", markdown)
        self.assertIn("status=EXECUTED", markdown)
        self.assertIn('"create-bearer": 2', markdown)
        self.assertIn(
            "do not prove end-to-end dedicated-bearer activation", markdown
        )

    def test_navigation_resolves_dedicated_source_references(self) -> None:
        source = self.source(self.documents())
        output, artifacts, _files = self.pack(source)
        index = self.read(output, "evidence-index.json")
        self.assertEqual(index["missing_references"], [])
        review = self.read(output, "evidence-review.json")
        transactions = review["sections"]["dedicated_bearer_control_transactions"]
        items = review["sections"]["dedicated_bearer_control_items"]
        associations = review["sections"]["dedicated_bearer_control_associations"]
        self.assertEqual(len(transactions), 4)
        self.assertEqual(len(items), 8)
        self.assertEqual(len(associations), 4)
        for entry in transactions:
            self.assertTrue(entry["source_references"])
            self.assertIn(entry["transaction_reference"], entry["source_references"])
        for entry in items:
            self.assertTrue(entry["source_references"])
        self.assertTrue(
            all(
                entry["status"] == "ITEM_ASSOCIATION_ESTABLISHED"
                for entry in associations
            )
        )
        self.assertTrue(
            artifacts["documents"]["dedicated_bearer_control"]["control_transactions"]
        )

    def test_missing_optional_artifact_keeps_older_pack_valid(self) -> None:
        documents = EPC.scenario()
        source = self.source(documents)
        self.assertFalse(
            (source / "epc-dedicated-bearer-control-analysis.json").exists()
        )
        output, _artifacts, _files = self.pack(source)
        manifest = self.read(output, "manifest.json")
        self.assertIsNone(manifest["provenance"]["dedicated_bearer_control"])
        review = self.read(output, "evidence-review.json")
        self.assertFalse(review["coverage"]["dedicated_source_supplied"])
        self.assertEqual(review["coverage"]["dedicated_status"], "NOT_SUPPLIED")
        summary = review["sections"]["dedicated_bearer_control_summary"][0]
        self.assertEqual(summary["status"], "NOT_SUPPLIED")
        self.assertIsNone(summary["source_artifact"])
        markdown = (output / "evidence-review.md").read_text(encoding="utf-8")
        self.assertIn("no Dedicated Bearer Control source was supplied", markdown)
        self.assertNotIn("source=epc-dedicated-bearer-control-analysis.json", markdown)

    def test_corrupt_optional_artifact_is_rejected(self) -> None:
        source = self.source(self.documents())
        path = source / "epc-dedicated-bearer-control-analysis.json"
        path.write_text("{", encoding="utf-8")
        with self.assertRaises(REVIEW.ReviewInputError) as raised:
            REVIEW.load_artifacts(source)
        self.assertEqual(raised.exception.code, "INVALID_SOURCE_JSON")

    def test_incompatible_optional_artifact_is_rejected(self) -> None:
        documents = self.documents()
        documents["dedicated"]["analysis_name"] = "epc-session-identity"
        source = self.source(documents)
        with self.assertRaises(REVIEW.ReviewInputError) as raised:
            REVIEW.load_artifacts(source)
        self.assertEqual(raised.exception.code, "INVALID_SOURCE_ARTIFACT")

        documents = self.documents()
        documents["dedicated"]["analysis_version"] = "2.0.0"
        source = self.source(documents, name="artifacts-v2")
        with self.assertRaises(REVIEW.ReviewInputError) as raised:
            REVIEW.load_artifacts(source)
        self.assertEqual(raised.exception.code, "UNSUPPORTED_SCHEMA_VERSION")

    def test_truncated_artifact_keeps_limits_visible(self) -> None:
        documents = self.documents(completeness="TRUNCATED")
        source = self.source(documents)
        output, _artifacts, _files = self.pack(source)
        review = self.read(output, "evidence-review.json")
        summary = review["sections"]["dedicated_bearer_control_summary"][0]
        self.assertEqual(summary["source_completeness_status"], "TRUNCATED")
        markdown = (output / "evidence-review.md").read_text(encoding="utf-8")
        self.assertIn("source completeness=TRUNCATED", markdown)


if __name__ == "__main__":
    unittest.main()