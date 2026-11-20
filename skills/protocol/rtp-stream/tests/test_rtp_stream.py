#!/usr/bin/env python3
"""Deterministic tests for the rtp-stream Protocol Skill.

The suite follows the required input/provenance, stream-identity, sequence,
capture-boundary, evidence/privacy and output-integrity matrix. Every fixture is
synthetic and sanitized; no capture, raw address, raw port, payload or key is
produced.
"""

from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
CLI = SCRIPTS / "reconstruct-rtp-streams.py"
SCHEMA = SKILL / "schemas" / "rtp-stream-analysis.schema.json"
INPUT = SKILL / "examples" / "inputs" / "rtp-rtcp-analysis.json"
EXPECTED_JSON = SKILL / "examples" / "expected" / "rtp-stream-analysis.json"
EXPECTED_REPORT = SKILL / "examples" / "expected" / "rtp-stream-report.txt"

for path in (SCRIPTS, SKILL / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import rtp_stream_fixture_builder as fb  # noqa: E402
import rtp_stream_model as model  # noqa: E402


def run_cli(arguments: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CLI), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )


def build(events, **kwargs):
    document = fb.analysis(events, **kwargs)
    provenance = model.load_source_provenance(
        document,
        source_name="fixture-rtp-rtcp-analysis.json",
        source_sha256="d" * 64,
        schema_validation="JSON_SCHEMA",
    )
    output = model.build_analysis(document, provenance=provenance)
    model.validate_analysis(output)
    return output


def build_document(document):
    provenance = model.load_source_provenance(
        document,
        source_name="fixture-rtp-rtcp-analysis.json",
        source_sha256="d" * 64,
        schema_validation="JSON_SCHEMA",
    )
    output = model.build_analysis(document, provenance=provenance)
    model.validate_analysis(output)
    return output


def load_from_file(document, *, expected: str | None = None):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "fixture-rtp-rtcp-analysis.json"
        fb.write_json(document, path)
        return model.load_rtp_rtcp_analysis(path, expected_source_sha256=expected)


def only_stream(output):
    return output["source_streams"][0]


def stream_status(output, index=0):
    return output["source_streams"][index]["sequence_validation_status"]


def stream_by_udp(output, udp_stream):
    for stream in output["source_streams"]:
        if stream["udp_stream"] == udp_stream:
            return stream
    raise AssertionError(f"no stream for udp_stream {udp_stream}")


def gap_for(output, index=0):
    return output["source_streams"][index]["sequence_gaps"][0]


class RtpStreamTests(unittest.TestCase):
    # ---------------------------------------------------------------- A. input
    def test_01_valid_rtp_rtcp_analysis_input(self):
        document, provenance, actual_sha = model.load_rtp_rtcp_analysis(INPUT)
        self.assertEqual(provenance["source_analysis_sha256"], actual_sha)
        self.assertEqual(provenance["capture_files"], ["rtp-stream-example.pcapng"])
        self.assertEqual(provenance["input_status"], "VERIFIED")
        output = model.build_analysis(document, provenance=provenance)
        model.validate_analysis(output)
        self.assertEqual(output["analysis_name"], "rtp-stream")
        self.assertEqual(output["completeness"]["total_input_rtp_packet_count"], 26)

    def test_02_invalid_analysis_version_is_rejected(self):
        document = fb.analysis(fb.stream([100, 101]))
        document["analysis_version"] = "0.3.0"
        with self.assertRaises(model.InputError):
            load_from_file(document)

    def test_03_invalid_event_schema_version_is_rejected(self):
        document = fb.analysis(fb.stream([100, 101]))
        document["event_schema_version"] = "1.1.0"
        with self.assertRaises(model.InputError):
            load_from_file(document)

    def test_04_wrong_capture_sha_is_rejected(self):
        events = fb.stream([100, 101])
        events[1]["capture_sha256"] = "b" * 64
        document = fb.analysis(events)
        with self.assertRaises(model.InputError):
            load_from_file(document)

    def test_05_wrong_actual_input_artifact_sha_is_rejected(self):
        document = fb.analysis(fb.stream([100, 101]))
        with self.assertRaises(model.InputError):
            load_from_file(document, expected="0" * 64)

    def test_06_mixed_capture_identities_are_rejected(self):
        events = fb.stream([100, 101])
        events[1]["capture_file"] = "other-capture.pcapng"
        events[1]["capture_sha256"] = "b" * 64
        document = fb.analysis(events)
        with self.assertRaises(model.InputError):
            load_from_file(document)

    def test_07_duplicate_event_references_are_rejected(self):
        events = fb.stream([100, 101])
        events[1]["event_reference"] = events[0]["event_reference"]
        document = fb.analysis(events)
        with self.assertRaises(model.InputError):
            load_from_file(document)

    def test_08_invalid_frame_identity_is_rejected(self):
        events = fb.stream([100, 101])
        events[1]["frame_reference"] = "frame:999"
        document = fb.analysis(events)
        with self.assertRaises(model.InputError):
            load_from_file(document)

    def test_09_invalid_udp_stream_id_is_rejected(self):
        event = fb.rtp_event(udp_stream=-1)
        document = fb.analysis([event])
        with self.assertRaises(model.InputError):
            load_from_file(document)

    def test_10_invalid_ssrc_reference_type_is_rejected(self):
        event = fb.rtp_event(ssrc_reference=17, ssrc=0x11112222)
        document = fb.analysis([event])
        with self.assertRaises(model.InputError):
            load_from_file(document)

    def test_11_missing_endpoint_context_is_rejected(self):
        event = fb.rtp_event(
            endpoint_status="ESTABLISHED",
            source_endpoint=fb.SOURCE_ENDPOINT,
            destination_endpoint=fb.DESTINATION_ENDPOINT,
        )
        document = fb.analysis([event], endpoint_context=None)
        with self.assertRaises(model.InputError):
            load_from_file(document)

    def test_12_malformed_endpoint_context_is_rejected(self):
        event = fb.rtp_event(
            endpoint_status="ESTABLISHED",
            source_endpoint=fb.SOURCE_ENDPOINT,
            destination_endpoint=fb.DESTINATION_ENDPOINT,
        )
        document = fb.analysis([event], endpoint_context="endpoint-context-bad")
        with self.assertRaises(model.InputError):
            load_from_file(document)

    def test_13_event_count_mismatch_is_rejected(self):
        document = fb.analysis(fb.stream([100, 101]))
        document["event_count"] = 3
        with self.assertRaises(model.InputError):
            load_from_file(document)

    def test_14_rtp_rtcp_completeness_mismatch_is_rejected(self):
        document = fb.analysis(fb.stream([100, 101]))
        document["completeness"]["rtp_packet_count"] = 1
        with self.assertRaises(model.InputError):
            load_from_file(document)

    # ---------------------------------------------------------- B. identity
    def test_15_one_udp_stream_and_one_ssrc(self):
        output = build(fb.stream([100, 101, 102]))
        self.assertEqual(output["source_stream_count"], 1)
        stream = only_stream(output)
        self.assertEqual(stream["udp_stream"], 1)
        self.assertTrue(stream["ssrc_reference"].startswith("rtp-ssrc:"))
        self.assertEqual(stream["rtp_packet_count"], 3)

    def test_16_one_udp_stream_and_multiple_ssrcs(self):
        events = fb.stream([100, 101]) + fb.stream(
            [200, 201], ssrc=0x33334444, start_frame=10
        )
        output = build(events)
        self.assertEqual(output["source_stream_count"], 2)
        self.assertEqual({stream["udp_stream"] for stream in output["source_streams"]}, {1})

    def test_17_same_ssrc_across_different_udp_streams(self):
        events = fb.stream([100, 101], udp_stream=1) + fb.stream(
            [100, 101], udp_stream=2, start_frame=10
        )
        output = build(events)
        self.assertEqual(output["source_stream_count"], 2)
        self.assertEqual(
            {stream["udp_stream"] for stream in output["source_streams"]}, {1, 2}
        )
        self.assertEqual(
            {stream["ssrc_reference"] for stream in output["source_streams"]},
            {"rtp-ssrc:synthetic-rtp.pcapng:11112222"},
        )

    def test_18_multiple_payload_types_retain_one_stream(self):
        events = fb.stream(
            [100, 101, 102], payload_types=[0, 8, 0]
        )
        output = build(events)
        self.assertEqual(output["source_stream_count"], 1)
        self.assertEqual(only_stream(output)["observed_payload_types"], [0, 8])

    def test_19_missing_udp_stream_is_unassigned(self):
        event = fb.rtp_event(udp_stream=None)
        output = build([event])
        self.assertEqual(output["source_stream_count"], 0)
        self.assertEqual(output["unassigned_packet_count"], 1)
        self.assertIn("UDP_STREAM_UNAVAILABLE", output["unassigned_packets"][0]["reason_codes"])

    def test_20_missing_ssrc_reference_is_unassigned(self):
        event = fb.rtp_event(ssrc_reference=None, ssrc=0x11112222)
        output = build([event])
        self.assertEqual(output["unassigned_packet_count"], 1)
        self.assertIn(
            "SSRC_REFERENCE_UNAVAILABLE",
            output["unassigned_packets"][0]["reason_codes"],
        )

    def test_21_missing_sequence_number_is_incomplete_but_assigned(self):
        events = [
            fb.rtp_event(frame=1, sequence=100),
            fb.rtp_event(frame=2, sequence=None),
        ]
        output = build(events)
        stream = only_stream(output)
        self.assertEqual(stream["rtp_packet_count"], 2)
        self.assertEqual(stream["sequence_eligible_packet_count"], 1)
        self.assertEqual(stream["incomplete_packet_count"], 1)
        self.assertEqual(stream["sequence_validation_status"], "PROBATION")
        self.assertEqual(output["unassigned_packet_count"], 0)

    def test_22_multiple_source_endpoint_references_are_ambiguous(self):
        first = fb.rtp_event(
            frame=1,
            sequence=100,
            endpoint_status="ESTABLISHED",
            source_endpoint=fb.SOURCE_ENDPOINT,
            destination_endpoint=fb.DESTINATION_ENDPOINT,
        )
        second = fb.rtp_event(
            frame=2,
            sequence=101,
            endpoint_status="ESTABLISHED",
            source_endpoint=fb.SOURCE_ENDPOINT_SECOND,
            destination_endpoint=fb.DESTINATION_ENDPOINT,
        )
        output = build([first, second])
        stream = only_stream(output)
        self.assertEqual(stream["source_endpoint_identity_status"], "AMBIGUOUS")
        self.assertIn("MULTIPLE_SOURCE_ENDPOINT_REFERENCES", stream["conflict_findings"])
        self.assertEqual(len(stream["source_endpoint_references"]), 2)

    def test_23_stable_source_endpoint_reference_is_established(self):
        events = []
        for frame, sequence in ((1, 100), (2, 101)):
            events.append(
                fb.rtp_event(
                    frame=frame,
                    sequence=sequence,
                    endpoint_status="ESTABLISHED",
                    source_endpoint=fb.SOURCE_ENDPOINT,
                    destination_endpoint=fb.DESTINATION_ENDPOINT,
                )
            )
        output = build(events)
        stream = only_stream(output)
        self.assertEqual(stream["source_endpoint_identity_status"], "ESTABLISHED")
        self.assertEqual(stream["source_endpoint_references"], [fb.SOURCE_ENDPOINT])
        self.assertEqual(stream["destination_endpoint_references"], [fb.DESTINATION_ENDPOINT])

    def test_24_missing_endpoint_references_do_not_block_reconstruction(self):
        output = build(fb.stream([100, 101]))
        stream = only_stream(output)
        self.assertEqual(stream["source_endpoint_identity_status"], "UNAVAILABLE")
        self.assertEqual(stream["endpoint_evidence_status"], "UNAVAILABLE")
        self.assertEqual(stream["sequence_validation_status"], "VALIDATED")

    def test_25_different_capture_hashes_never_merge(self):
        events = fb.stream([100, 101])
        second = fb.stream([100, 101], start_frame=10)[0]
        second["capture_sha256"] = "b" * 64
        second["event_reference"] = "rtp-packet:synthetic-rtp.pcapng:10.1"
        events.append(second)
        document = fb.analysis(events)
        with self.assertRaises(model.InputError):
            load_from_file(document)

    def test_26_source_stream_references_are_deterministic(self):
        events = fb.stream([100, 101])
        first = build(events)
        second = build(events)
        self.assertEqual(
            [stream["source_stream_reference"] for stream in first["source_streams"]],
            [stream["source_stream_reference"] for stream in second["source_streams"]],
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )

    # ---------------------------------------------------------- C. sequence
    def test_27_initial_probation(self):
        output = build(fb.stream([100]))
        stream = only_stream(output)
        self.assertEqual(stream["sequence_validation_status"], "PROBATION")
        self.assertEqual(stream["sequence_epochs"][0]["sequence_validation_status"], "PROBATION")
        self.assertIn("SEQUENTIAL_VALIDATION_INCOMPLETE", stream["missing_evidence"])

    def test_28_two_sequential_packets_validate(self):
        output = build(fb.stream([100, 101]))
        self.assertEqual(stream_status(output), "VALIDATED")
        epoch = only_stream(output)["sequence_epochs"][0]
        self.assertEqual(epoch["probation_observation_count"], 1)
        self.assertEqual(epoch["accepted_observation_count"], 1)

    def test_29_three_or_more_sequential_packets_validate(self):
        output = build(fb.stream([100, 101, 102]))
        stream = only_stream(output)
        self.assertEqual(stream["sequence_validation_status"], "VALIDATED")
        epoch = stream["sequence_epochs"][0]
        self.assertEqual(epoch["unique_sequence_count"], 2)
        self.assertEqual(stream["unobserved_sequence_number_slot_count"], 0)

    def test_30_65535_to_0_sequence_wrap(self):
        output = build(fb.stream([65534, 65535, 0, 1]))
        stream = only_stream(output)
        self.assertEqual(stream["sequence_wrap_count"], 1)
        self.assertEqual(stream["out_of_order_packet_count"], 0)
        self.assertEqual(stream["observed_sequence_gap_count"], 0)

    def test_31_multiple_sequence_wraps(self):
        original = (
            model.RTP_SEQ_MOD,
            model.MAX_DROPOUT,
            model.MAX_MISORDER,
            model.MIN_SEQUENTIAL,
        )
        try:
            model.RTP_SEQ_MOD = 8
            model.MAX_DROPOUT = 4
            model.MAX_MISORDER = 2
            model.MIN_SEQUENTIAL = 2
            output = build(fb.stream([6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1]))
        finally:
            (
                model.RTP_SEQ_MOD,
                model.MAX_DROPOUT,
                model.MAX_MISORDER,
                model.MIN_SEQUENTIAL,
            ) = original
        stream = only_stream(output)
        self.assertEqual(stream["sequence_wrap_count"], 2)
        self.assertEqual(stream["out_of_order_packet_count"], 0)

    def test_32_one_duplicated_sequence_number(self):
        output = build(fb.stream([100, 101, 102, 102]))
        stream = only_stream(output)
        self.assertEqual(stream["duplicate_sequence_observation_count"], 1)
        self.assertEqual(stream["out_of_order_packet_count"], 0)

    def test_33_multiple_duplicate_observations(self):
        output = build(fb.stream([100, 101, 102, 102, 101, 102]))
        stream = only_stream(output)
        self.assertEqual(stream["duplicate_sequence_observation_count"], 3)

    def test_34_one_out_of_order_packet(self):
        output = build(fb.stream([100, 101, 103, 102]))
        stream = only_stream(output)
        self.assertEqual(stream["out_of_order_packet_count"], 1)
        self.assertEqual(stream["observed_sequence_gap_count"], 1)
        self.assertTrue(gap_for(output)["filled_by_later_observation"])

    def test_35_multiple_out_of_order_packets(self):
        output = build(fb.stream([100, 101, 105, 103, 102, 104]))
        stream = only_stream(output)
        self.assertEqual(stream["out_of_order_packet_count"], 3)

    def test_36_gap_between_two_validated_positions(self):
        output = build(fb.stream([100, 101, 105]))
        stream = only_stream(output)
        self.assertEqual(stream["observed_sequence_gap_count"], 1)
        self.assertEqual(stream["unobserved_sequence_number_slot_count"], 3)
        gap = gap_for(output)
        self.assertEqual(gap["unobserved_sequence_numbers"], [102, 103, 104])
        self.assertFalse(gap["filled_by_later_observation"])
        self.assertEqual(gap["missing_evidence"], ["UNOBSERVED_SEQUENCE_NUMBERS"])

    def test_37_previously_observed_gap_filled_by_reordered_packet(self):
        output = build(fb.stream([100, 101, 105, 104, 103, 102]))
        stream = only_stream(output)
        self.assertEqual(stream["observed_sequence_gap_count"], 1)
        self.assertEqual(stream["unobserved_sequence_number_slot_count"], 0)
        gap = gap_for(output)
        self.assertTrue(gap["filled_by_later_observation"])
        self.assertEqual(gap["filled_sequence_numbers"], [102, 103, 104])

    def test_38_multiple_independent_gaps(self):
        output = build(fb.stream([100, 101, 105, 110]))
        stream = only_stream(output)
        self.assertEqual(stream["observed_sequence_gap_count"], 2)
        self.assertEqual(stream["unobserved_sequence_number_slot_count"], 7)

    def test_39_large_sequence_jump_is_a_restart_candidate_not_a_gap(self):
        output = build(fb.stream([100, 101, 5000]))
        stream = only_stream(output)
        self.assertEqual(stream["observed_sequence_gap_count"], 0)
        self.assertEqual(stream["restart_pattern_count"], 1)
        self.assertEqual(stream["sequence_validation_status"], "AMBIGUOUS")

    def test_40_restart_candidate_is_preserved(self):
        output = build(fb.stream([100, 101, 5000]))
        pattern = only_stream(output)["restart_patterns"][0]
        self.assertEqual(pattern["restart_confirmation"], "UNCONFIRMED")
        self.assertEqual(pattern["candidate_sequence_number"], 5000)
        self.assertIsNone(pattern["new_epoch_index"])

    def test_41_confirmed_restart_pattern(self):
        output = build(fb.stream([100, 101, 102, 5000, 5001, 5002]))
        stream = only_stream(output)
        self.assertEqual(stream["restart_pattern_count"], 1)
        pattern = stream["restart_patterns"][0]
        self.assertEqual(pattern["restart_confirmation"], "CONFIRMED")
        self.assertEqual(pattern["candidate_sequence_number"], 5000)
        self.assertEqual(pattern["confirmation_sequence_number"], 5001)
        self.assertEqual(stream["sequence_validation_status"], "VALIDATED")

    def test_42_independent_sequence_epochs(self):
        output = build(fb.stream([100, 101, 102, 5000, 5001, 5002]))
        stream = only_stream(output)
        self.assertEqual(stream["sequence_epoch_count"], 2)
        self.assertEqual([epoch["epoch_index"] for epoch in stream["sequence_epochs"]], [0, 1])
        self.assertEqual(stream["sequence_epochs"][1]["extended_sequence_start"], 5001)

    def test_43_max_dropout_boundary(self):
        gap = build(fb.stream([100, 101, 3100]))
        self.assertEqual(only_stream(gap)["observed_sequence_gap_count"], 1)
        candidate = build(fb.stream([100, 101, 3101]))
        stream = only_stream(candidate)
        self.assertEqual(stream["observed_sequence_gap_count"], 0)
        self.assertEqual(stream["restart_pattern_count"], 1)

    def test_44_max_misorder_boundary(self):
        candidate = build(fb.stream([100, 101, 103, 3]))
        self.assertEqual(only_stream(candidate)["restart_pattern_count"], 1)
        reordered = build(fb.stream([100, 101, 103, 4]))
        stream = only_stream(reordered)
        self.assertEqual(stream["restart_pattern_count"], 0)
        self.assertEqual(stream["out_of_order_packet_count"], 1)
        self.assertEqual(stream["sequence_validation_status"], "VALIDATED")

    def test_45_16_bit_sequence_boundaries(self):
        output = build(fb.stream([0, 1, 2]))
        self.assertEqual(only_stream(output)["sequence_validation_status"], "VALIDATED")
        wrapped = build(fb.stream([65533, 65534, 65535, 0, 1]))
        stream = only_stream(wrapped)
        self.assertEqual(stream["sequence_wrap_count"], 1)
        self.assertEqual(stream["unobserved_sequence_number_slot_count"], 0)

    def test_46_invalid_sequence_values_are_excluded(self):
        events = [
            fb.rtp_event(frame=1, sequence=100),
            fb.rtp_event(frame=2, sequence=70000),
        ]
        output = build(events)
        stream = only_stream(output)
        self.assertEqual(stream["invalid_or_excluded_packet_count"], 1)
        self.assertEqual(stream["sequence_eligible_packet_count"], 1)

    def test_47_same_frame_multiple_occurrences_are_ordered(self):
        events = [
            fb.rtp_event(frame=1, sequence=100, occurrence=1),
            fb.rtp_event(frame=2, sequence=101, occurrence=1),
            fb.rtp_event(frame=3, sequence=103, occurrence=1),
            fb.rtp_event(frame=3, sequence=102, occurrence=2),
        ]
        output = build(events)
        stream = only_stream(output)
        self.assertEqual(stream["out_of_order_packet_count"], 1)
        self.assertTrue(gap_for(output)["filled_by_later_observation"])
        references = stream["event_references"]
        self.assertLess(references.index(events[2]["event_reference"]), references.index(events[3]["event_reference"]))

    def test_48_frame_order_versus_sequence_order(self):
        output = build(fb.stream([100, 101, 103, 102]))
        stream = only_stream(output)
        self.assertEqual(stream["out_of_order_packet_count"], 1)
        self.assertEqual(
            stream["event_references"],
            [
                "rtp-packet:synthetic-rtp.pcapng:1.1",
                "rtp-packet:synthetic-rtp.pcapng:2.1",
                "rtp-packet:synthetic-rtp.pcapng:3.1",
                "rtp-packet:synthetic-rtp.pcapng:4.1",
            ],
        )

    def test_49_deterministic_replay(self):
        events = fb.stream([100, 101, 105, 103, 102, 104])
        first = build(events)
        second = build(events)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))

    # ------------------------------------------------- D. capture boundaries
    def test_50_capture_starts_mid_stream(self):
        output = build(fb.stream([5000, 5001, 5002]))
        stream = only_stream(output)
        self.assertEqual(stream["sequence_validation_status"], "VALIDATED")
        self.assertEqual(stream["observed_sequence_gap_count"], 0)

    def test_51_capture_ends_mid_stream(self):
        output = build(fb.stream([100, 101, 102]))
        stream = only_stream(output)
        self.assertEqual(stream["unobserved_sequence_number_slot_count"], 0)
        self.assertNotIn("STREAM_TERMINATED", stream["conflict_findings"])

    def test_52_no_leading_gap_inference(self):
        output = build(fb.stream([5000, 5001]))
        stream = only_stream(output)
        self.assertEqual(stream["observed_sequence_gap_count"], 0)
        self.assertEqual(stream["sequence_epochs"][0]["extended_sequence_start"], 5001)

    def test_53_no_trailing_gap_inference(self):
        output = build(fb.stream([100, 101, 102]))
        stream = only_stream(output)
        self.assertEqual(stream["unobserved_sequence_number_slot_count"], 0)
        self.assertIn("CAPTURE_BOUNDARY_COMPLETENESS_UNKNOWN", stream["missing_evidence"])

    def test_54_no_stream_termination_inference(self):
        events = fb.stream([100, 101, 102]) + [fb.rtcp_bye_event(frame=50)]
        output = build(events)
        self.assertEqual(output["source_stream_count"], 1)
        self.assertIn("RTP_TEARDOWN_FROM_RTCP_BYE", output["not_confirmed"])
        self.assertNotIn("STREAM_TERMINATED", json.dumps(output))
        self.assertNotIn('"termination_status"', json.dumps(output))

    def test_55_partial_capture_preserves_unknown_completeness(self):
        output = build(fb.stream([700, 701]))
        self.assertIn(
            "CAPTURE_BOUNDARY_COMPLETENESS_UNKNOWN",
            only_stream(output)["missing_evidence"],
        )

    # ----------------------------------------------------- E. evidence/privacy
    def test_56_incomplete_event_with_usable_sequence_evidence(self):
        events = fb.stream([100, 101], statuses=["INCOMPLETE", "INCOMPLETE"])
        output = build(events)
        stream = only_stream(output)
        self.assertEqual(stream["sequence_eligible_packet_count"], 2)
        self.assertEqual(stream["incomplete_packet_count"], 0)
        self.assertEqual(stream["sequence_validation_status"], "VALIDATED")

    def test_57_invalid_event_is_excluded(self):
        events = [fb.rtp_event(frame=1, sequence=100, status="INVALID")]
        output = build(events)
        stream = only_stream(output)
        self.assertEqual(stream["invalid_or_excluded_packet_count"], 1)
        self.assertEqual(stream["sequence_eligible_packet_count"], 0)
        self.assertEqual(stream["sequence_validation_status"], "INSUFFICIENT_EVIDENCE")

    def test_58_unsupported_rtp_version_is_excluded(self):
        events = [
            fb.rtp_event(frame=1, sequence=100),
            fb.rtp_event(frame=2, sequence=101, version=1, status="UNSUPPORTED"),
        ]
        output = build(events)
        stream = only_stream(output)
        self.assertEqual(stream["invalid_or_excluded_packet_count"], 1)
        self.assertEqual(stream["sequence_eligible_packet_count"], 1)

    def test_59_ambiguous_event_is_excluded(self):
        events = [fb.rtp_event(frame=1, sequence=100, status="AMBIGUOUS")]
        output = build(events)
        self.assertEqual(only_stream(output)["invalid_or_excluded_packet_count"], 1)

    def test_60_missing_endpoint_key_does_not_block_reconstruction(self):
        output = build(fb.stream([100, 101, 102]))
        self.assertIsNone(output["input_provenance"]["endpoint_context_reference"])
        self.assertEqual(stream_status(output), "VALIDATED")

    def test_61_no_raw_ip_leakage(self):
        text = json.dumps(build(fb.stream([100, 101])))
        self.assertIsNone(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))

    def test_62_no_udp_port_leakage(self):
        text = json.dumps(build(fb.stream([100, 101])))
        for token in ('"source_port"', '"destination_port"', '"port"'):
            self.assertNotIn(token, text)

    def test_63_no_raw_endpoint_tuple_leakage(self):
        text = json.dumps(build(fb.stream([100, 101])))
        for token in ("source_address", "destination_address", "source_transport_endpoint"):
            self.assertNotIn(token, text)

    def test_64_no_rtp_payload_leakage(self):
        output = build(fb.stream([100, 101]))
        self.assertNotIn('"payload"', json.dumps(output))
        self.assertNotIn('"rtp_payload"', json.dumps(output))

    def test_65_no_key_material_leakage(self):
        text = json.dumps(build(fb.stream([100, 101])))
        for token in ("hmac_key", "endpoint_key", "srtp_key"):
            self.assertNotIn(token, text)

    def test_66_no_subscriber_identity_inference(self):
        output = build(fb.stream([100, 101]))
        self.assertIn("SUBSCRIBER_IDENTITY", output["not_confirmed"])
        self.assertNotIn("imsi", json.dumps(output).lower())

    def test_67_no_ims_identity_inference(self):
        output = build(fb.stream([100, 101]))
        self.assertIn("IMS_IDENTITY", output["not_confirmed"])
        self.assertIn("IMS_MEDIA_SESSION_IDENTITY", output["not_confirmed"])

    def test_68_no_network_packet_loss_verdict(self):
        output = build(fb.stream([100, 101, 105]))
        gap = gap_for(output)
        self.assertEqual(gap["missing_evidence"], ["UNOBSERVED_SEQUENCE_NUMBERS"])
        self.assertNotIn("PACKET_LOSS", json.dumps(gap))
        self.assertIn("NETWORK_PACKET_LOSS", output["not_confirmed"])

    def test_69_no_jitter_or_mos_calculation(self):
        output = build(fb.stream([100, 101]))
        text = json.dumps(output)
        self.assertNotIn('"jitter"', text)
        self.assertNotIn('"mos"', text)
        self.assertIn("LOCAL_JITTER", output["not_confirmed"])
        self.assertIn("MOS", output["not_confirmed"])

    def test_70_no_rtp_delivery_verdict(self):
        output = build(fb.stream([100, 101]))
        self.assertIn("RTP_DELIVERY", output["not_confirmed"])
        self.assertNotIn("DELIVERED", json.dumps(output))

    def test_71_no_two_way_audio_verdict(self):
        output = build(fb.stream([100, 101]))
        self.assertIn("TWO_WAY_AUDIO", output["not_confirmed"])

    def test_72_no_rtcp_to_rtp_stream_association(self):
        events = fb.stream([100, 101]) + [fb.rtcp_sr_event()]
        output = build(events)
        self.assertEqual(output["rtcp_event_count"], 1)
        self.assertEqual(
            output["rtcp_observation_status"],
            "NOT_INTERPRETED_FOR_RTP_STREAM_ASSOCIATION",
        )
        self.assertEqual(output["source_stream_count"], 1)
        self.assertEqual(only_stream(output)["rtp_packet_count"], 2)
        self.assertNotIn("rtcp-component", json.dumps(output["source_streams"]))

    def test_73_no_bye_teardown_inference(self):
        events = fb.stream([100, 101, 102]) + [fb.rtcp_bye_event()]
        output = build(events)
        self.assertEqual(stream_status(output), "VALIDATED")
        self.assertEqual(output["rtcp_event_count"], 1)
        self.assertIn("RTP_TEARDOWN_FROM_RTCP_BYE", output["not_confirmed"])

    # --------------------------------------------------- F. output integrity
    def test_74_strict_json_schema_validation(self):
        import jsonschema

        document = json.loads(EXPECTED_JSON.read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        jsonschema.validate(document, schema)
        jsonschema.validate(build(fb.stream([100, 101])), schema)

    def test_75_cross_field_consistency(self):
        document = build(fb.stream([100, 101]))
        document = copy.deepcopy(document)
        document["completeness"]["sequence_validated_stream_count"] = 0
        with self.assertRaises(model.InputError):
            model.validate_analysis(document)

    def test_76_event_reference_uniqueness(self):
        document = build(fb.stream([100, 101]) + [fb.rtp_event(frame=10, udp_stream=None)])
        document = copy.deepcopy(document)
        document["unassigned_packets"][0]["event_reference"] = document[
            "source_streams"
        ][0]["event_references"][0]
        with self.assertRaises(model.InputError):
            model.validate_analysis(document)

    def test_77_count_conservation(self):
        document = build(fb.stream([100, 101]) + [fb.rtp_event(frame=10, udp_stream=None)])
        document = copy.deepcopy(document)
        document["completeness"]["total_input_rtp_packet_count"] += 1
        with self.assertRaises(model.InputError):
            model.validate_analysis(document)

    def test_78_unassigned_packet_preservation(self):
        events = [
            fb.rtp_event(frame=1, sequence=100),
            fb.rtp_event(frame=2, sequence=101),
            fb.rtp_event(frame=3, udp_stream=None, status="INCOMPLETE"),
            fb.rtp_event(frame=4, ssrc_reference=None, ssrc=0x99999999),
        ]
        output = build(events)
        self.assertEqual(output["source_stream_count"], 1)
        self.assertEqual(output["unassigned_packet_count"], 2)
        self.assertEqual(
            [packet["original_evidence_status"] for packet in output["unassigned_packets"]],
            ["INCOMPLETE", "OBSERVED"],
        )
        stream_refs = set(only_stream(output)["event_references"])
        for packet in output["unassigned_packets"]:
            self.assertNotIn(packet["event_reference"], stream_refs)
        self.assertEqual(
            output["completeness"]["assigned_rtp_packet_count"]
            + output["completeness"]["unassigned_rtp_packet_count"],
            output["completeness"]["total_input_rtp_packet_count"],
        )

    def test_79_output_truncation_accounting(self):
        events = (
            fb.stream([100, 101, 102], udp_stream=1)
            + fb.stream([200, 201, 202], udp_stream=2, ssrc=0x33334444, start_frame=10)
            + fb.stream([300, 301, 302], udp_stream=3, ssrc=0x55556666, start_frame=20)
            + [
                fb.rtp_event(frame=30, udp_stream=None),
                fb.rtp_event(frame=31, ssrc_reference=None, ssrc=0x77778888),
            ]
        )
        original = (
            model.MAX_SOURCE_STREAMS,
            model.MAX_UNASSIGNED_PACKETS,
            model.MAX_STREAM_EVENT_REFERENCES,
        )
        try:
            model.MAX_SOURCE_STREAMS = 1
            model.MAX_UNASSIGNED_PACKETS = 1
            model.MAX_STREAM_EVENT_REFERENCES = 1
            output = build(events)
        finally:
            (
                model.MAX_SOURCE_STREAMS,
                model.MAX_UNASSIGNED_PACKETS,
                model.MAX_STREAM_EVENT_REFERENCES,
            ) = original
        self.assertEqual(output["source_stream_count"], 3)
        self.assertEqual(len(output["source_streams"]), 1)
        self.assertEqual(output["source_streams_omitted"], 2)
        self.assertEqual(output["unassigned_packet_count"], 2)
        self.assertEqual(len(output["unassigned_packets"]), 1)
        self.assertEqual(output["unassigned_packets_omitted"], 1)
        completeness = output["completeness"]
        self.assertEqual(completeness["event_references_omitted"], 8)
        self.assertEqual(completeness["omitted_record_count"], 11)
        self.assertEqual(
            len(output["source_streams"][0]["event_references"]), 1
        )

    def test_80_atomic_output_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "analysis.json"
            report = Path(directory) / "report.txt"
            completed = run_cli(
                [
                    "--rtp-rtcp-analysis",
                    str(INPUT),
                    "--output",
                    str(output),
                    "--report",
                    str(report),
                ]
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(output.is_file())
            self.assertTrue(report.is_file())
            self.assertEqual(
                [path.name for path in Path(directory).glob(".*.tmp")], []
            )
            invalid = Path(directory) / "invalid.json"
            invalid.write_text('{"analysis_name": ', encoding="utf-8")
            rejected = Path(directory) / "rejected.json"
            failed = run_cli(
                [
                    "--rtp-rtcp-analysis",
                    str(invalid),
                    "--output",
                    str(rejected),
                ]
            )
            self.assertEqual(failed.returncode, 2)
            self.assertFalse(rejected.exists())

    def test_81_output_collision_protection(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "input.json"
            copied.write_bytes(INPUT.read_bytes())
            collision = run_cli(
                [
                    "--rtp-rtcp-analysis",
                    str(copied),
                    "--output",
                    str(copied),
                    "--force",
                ]
            )
            self.assertEqual(collision.returncode, 6)
            existing = Path(directory) / "existing.json"
            existing.write_text("{}", encoding="utf-8")
            blocked = run_cli(
                [
                    "--rtp-rtcp-analysis",
                    str(INPUT),
                    "--output",
                    str(existing),
                ]
            )
            self.assertEqual(blocked.returncode, 6)

    def test_82_report_and_json_consistency(self):
        document = json.loads(EXPECTED_JSON.read_text(encoding="utf-8"))
        report = EXPECTED_REPORT.read_text(encoding="utf-8")
        completeness = document["completeness"]
        self.assertIn(
            f"input_rtp_events: {completeness['total_input_rtp_packet_count']}", report
        )
        self.assertIn(
            f"streams: {document['source_stream_count']}", report
        )
        self.assertIn(
            "duplicate_observations: {}".format(
                completeness["duplicate_observation_count"]
            ),
            report,
        )
        self.assertIn(
            "out_of_order_observations: {}".format(
                completeness["out_of_order_observation_count"]
            ),
            report,
        )
        self.assertIn(
            "restart_patterns: {}".format(completeness["restart_pattern_count"]), report
        )
        self.assertIn(document["rtcp_observation_status"], report)
        for stream in document["source_streams"]:
            self.assertIn(stream["source_stream_reference"], report)

    def test_83_existing_upstream_fixture_compatibility(self):
        upstream = ROOT / "skills" / "protocol" / "sdp-rtp" / "examples" / "expected" / "rtp-rtcp-analysis.json"
        document, provenance, _ = model.load_rtp_rtcp_analysis(upstream)
        output = model.build_analysis(document, provenance=provenance)
        model.validate_analysis(output)
        self.assertEqual(
            output["completeness"]["total_input_rtp_packet_count"],
            document["completeness"]["rtp_packet_count"],
        )
        self.assertEqual(output["rtcp_event_count"], document["completeness"]["rtcp_component_count"])
        self.assertEqual(
            output["input_provenance"]["capture_sha256"],
            document["input_provenance"]["capture_sha256"],
        )

    def test_85_malformed_ssrc_reference_string_is_unassigned(self):
        event = fb.rtp_event(
            ssrc_reference="rtp-ssrc:synthetic-rtp.pcapng:ZZZZZZZZ",
            ssrc=0x11112222,
        )
        output = build([event])
        self.assertEqual(output["source_stream_count"], 0)
        self.assertEqual(output["unassigned_packet_count"], 1)
        self.assertIn(
            "SSRC_REFERENCE_INVALID",
            output["unassigned_packets"][0]["reason_codes"],
        )

    def test_86_expected_source_artifact_sha_succeeds(self):
        import hashlib

        document = fb.analysis(fb.stream([100, 101]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture-rtp-rtcp-analysis.json"
            payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
            path.write_bytes(payload)
            expected = hashlib.sha256(payload).hexdigest()
            _, provenance, actual = model.load_rtp_rtcp_analysis(
                path, expected_source_sha256=expected
            )
        self.assertEqual(actual, expected)
        self.assertEqual(provenance["source_analysis_sha256"], expected)

    def test_84_existing_upstream_regression_compatibility(self):
        sys.path.insert(0, str(ROOT / "skills" / "protocol" / "sdp-rtp" / "scripts"))
        import rtp_rtcp_model

        inputs = ROOT / "skills" / "protocol" / "sdp-rtp" / "examples" / "inputs" / "rtp-rtcp-cases.jsonl"
        expected = ROOT / "skills" / "protocol" / "sdp-rtp" / "examples" / "expected" / "rtp-rtcp-analysis.json"
        events, provenance = rtp_rtcp_model.extract_structured(inputs)
        document = rtp_rtcp_model.build_analysis(events, provenance)
        self.assertEqual(
            (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            expected.read_bytes(),
        )


if __name__ == "__main__":
    unittest.main()