#!/usr/bin/env python3
"""Deterministic tests for branch-scoped IMS media transport evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:
    jsonschema = None

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
CLI = SCRIPTS / "analyze-ims-media-session.py"
SCHEMA = SKILL / "schemas" / "ims-media-session-analysis.schema.json"
INPUTS = SKILL / "examples" / "inputs"
EXPECTED = SKILL / "examples" / "expected"
TEST_DIR = Path(__file__).resolve().parent
for path in (SCRIPTS, TEST_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import ims_media_session_model as model  # noqa: E402
import media_session_fixture_builder as builder  # noqa: E402
import media_fixture_builder as upstream  # noqa: E402

_FIXTURES: dict[str, dict] = {}

BUNDLE_ANSWER = (
    "v=0\r\n"
    "o=- 3000 1 IN IP4 192.0.2.30\r\n"
    "s=bundle-answer\r\n"
    "c=IN IP4 192.0.2.30\r\n"
    "t=0 0\r\n"
    "a=group:BUNDLE 0 1\r\n"
    "m=audio 49300 RTP/AVP 0\r\n"
    "a=mid:0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "m=video 49300 RTP/AVP 96\r\n"
    "a=mid:1\r\n"
    "a=rtpmap:96 H264/90000\r\n"
)
UNRELATED_ANSWER = (
    "v=0\r\n"
    "o=- 3001 1 IN IP4 192.0.2.31\r\n"
    "s=unrelated-answer\r\n"
    "c=IN IP4 192.0.2.31\r\n"
    "t=0 0\r\n"
    "m=audio 49302 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "m=video 49302 RTP/AVP 96\r\n"
    "a=rtpmap:96 H264/90000\r\n"
)
DISABLED_ANSWER = (
    "v=0\r\n"
    "o=- 3002 1 IN IP4 192.0.2.32\r\n"
    "s=disabled-answer\r\n"
    "c=IN IP4 192.0.2.32\r\n"
    "t=0 0\r\n"
    "m=audio 0 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
)
SAME_ENDPOINT_ANSWER = (
    "v=0\r\n"
    "o=- 3003 1 IN IP4 192.0.2.10\r\n"
    "s=same-endpoint-answer\r\n"
    "c=IN IP4 192.0.2.10\r\n"
    "t=0 0\r\n"
    "m=audio 49170 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
)


def _rtp(frame, stream, source, destination, source_port, destination_port, ssrc):
    return builder._rtp_record(
        frame,
        stream=stream,
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        ssrc=ssrc,
        sequence=1,
    )


def bundle_rtp_records():
    return [
        _rtp(1, 0, "192.0.2.99", "192.0.2.30", 6000, 49300, 0x44444444)
    ]


def unrelated_rtp_records():
    return [
        _rtp(1, 0, "192.0.2.99", "192.0.2.31", 6000, 49302, 0x55555555)
    ]


def _bundle(records=None, rtp=None, *, key=builder.KEY):
    directory = Path(tempfile.mkdtemp())
    return builder.build_bundle(
        directory,
        records if records is not None else builder.fork_terminated_records(),
        rtp if rtp is not None else builder.fork_rtp_records(),
        prefix="domain-",
        key=key,
    )


def fixture(name: str) -> dict:
    if name in _FIXTURES:
        return _FIXTURES[name]
    if name == "base":
        bundle = _bundle()
    elif name == "late":
        bundle = _bundle(builder.late_offer_records(), builder.late_rtp_records())
    elif name == "offer":
        bundle = _bundle(builder.offer_only_records(), builder.offer_only_rtp_records())
    elif name == "no_key":
        bundle = _bundle(upstream.build_records(), builder.late_rtp_records(), key=None)
    elif name == "bundle":
        records = [
            upstream.rec(1, method="INVITE", sdp_body=upstream.AUDIO_OFFER),
            upstream.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=BUNDLE_ANSWER),
            upstream.rec(3, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        bundle = _bundle(records, bundle_rtp_records())
    elif name == "unrelated":
        records = [
            upstream.rec(1, method="INVITE", sdp_body=upstream.AUDIO_OFFER),
            upstream.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=UNRELATED_ANSWER),
            upstream.rec(3, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        bundle = _bundle(records, unrelated_rtp_records())
    elif name == "rejected":
        records = [
            upstream.rec(1, method="INVITE", sdp_body=upstream.AUDIO_OFFER),
            upstream.rec(2, status=180, cseq_method="INVITE", to_tag="TT-1"),
            upstream.rec(3, status=180, cseq_method="INVITE", to_tag="TT-2"),
            upstream.rec(4, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.ANSWER_ONE),
            upstream.rec(5, status=486, cseq_method="INVITE", to_tag="TT-2"),
            upstream.rec(6, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        bundle = _bundle(records, builder.fork_rtp_records())
    elif name == "provisional":
        records = [
            upstream.rec(1, method="INVITE", sdp_body=upstream.AUDIO_OFFER),
            upstream.rec(2, status=183, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.ANSWER_ONE),
            upstream.rec(3, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.ANSWER_ONE),
            upstream.rec(4, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        bundle = _bundle(records, builder.offer_only_rtp_records())
    elif name == "unusable":
        bad_offer = "v=0\r\nm=audio 49170 RTP/AVP 0\r\n"
        records = [
            upstream.rec(1, method="INVITE", sdp_body=bad_offer),
            upstream.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.ANSWER_ONE),
            upstream.rec(3, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        bundle = _bundle(records, builder.fork_rtp_records())
    elif name == "two_attempts":
        records = [
            upstream.rec(1, method="INVITE", sdp_body=upstream.AUDIO_OFFER, call_id="CALL-1", branch="z9hG4bK-A"),
            upstream.rec(2, method="INVITE", sdp_body=upstream.AUDIO_OFFER, call_id="CALL-2", branch="z9hG4bK-B"),
        ]
        bundle = _bundle(records, builder.offer_only_rtp_records())
    elif name == "shared_answer":
        records = [
            upstream.rec(1, method="INVITE", sdp_body=upstream.AUDIO_OFFER),
            upstream.rec(2, status=180, cseq_method="INVITE", to_tag="TT-1"),
            upstream.rec(3, status=180, cseq_method="INVITE", to_tag="TT-2"),
            upstream.rec(4, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.ANSWER_ONE),
            upstream.rec(5, status=200, cseq_method="INVITE", to_tag="TT-2", sdp_body=builder.ANSWER_ONE),
            upstream.rec(6, method="ACK", cseq=1, to_tag="TT-1"),
            upstream.rec(7, method="ACK", cseq=1, to_tag="TT-2"),
        ]
        bundle = _bundle(records, builder.fork_rtp_records())
    elif name == "unmatched_media":
        bundle = _bundle(upstream.build_records(), builder.offer_only_rtp_records())
    elif name == "out_of_scope":
        records = [
            upstream.rec(1, method="INVITE", sdp_body=upstream.AUDIO_OFFER),
            upstream.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=DISABLED_ANSWER),
            upstream.rec(3, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        bundle = _bundle(records, builder.offer_only_rtp_records())
    elif name == "same_endpoint":
        records = [
            upstream.rec(1, method="INVITE", sdp_body=upstream.AUDIO_OFFER),
            upstream.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=SAME_ENDPOINT_ANSWER),
            upstream.rec(3, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        bundle = _bundle(records, builder.offer_only_rtp_records())
    elif name == "no_correlation":
        bundle = _bundle()
        correlation = copy.deepcopy(bundle["correlation_document"])
        correlation["correlations"] = []
        correlation["correlation_count"] = 0
        correlation["unmatched_streams"] = []
        correlation["unmatched_stream_count"] = 0
        completeness = correlation["completeness"]
        for key in (
            "rtp_packet_count",
            "correlatable_rtp_packet_count",
            "non_observed_rtp_packet_count",
            "ungrouped_rtp_packet_count",
            "rtp_stream_count",
            "rtp_stream_with_endpoint_count",
            "rtp_stream_without_endpoint_count",
            "correlation_count",
            "correlations_omitted",
            "matched_correlation_count",
            "bundle_matched_correlation_count",
            "ambiguous_correlation_count",
            "insufficient_correlation_count",
            "unmatched_correlation_count",
            "out_of_scope_correlation_count",
            "unmatched_stream_count",
        ):
            completeness[key] = 0
        bundle["correlation_document"] = correlation
    else:
        raise AssertionError(f"unknown fixture {name}")
    _FIXTURES[name] = bundle
    return bundle


def docs(name: str) -> tuple[dict, dict, dict, dict]:
    bundle = fixture(name)
    return (
        copy.deepcopy(bundle["session_document"]),
        copy.deepcopy(bundle["media_document"]),
        copy.deepcopy(bundle["sdp_document"]),
        copy.deepcopy(bundle["correlation_document"]),
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyze_docs(
    session: dict,
    media: dict,
    sdp: dict,
    correlation: dict,
    *,
    patch_hashes: bool = True,
) -> dict:
    directory = Path(tempfile.mkdtemp())
    session_path = directory / "ims-session.json"
    media_path = directory / "ims-media-signaling.json"
    sdp_path = directory / "sdp-analysis.json"
    correlation_path = directory / "transport-correlation.json"
    for path, document in (
        (session_path, session),
        (media_path, media),
        (sdp_path, sdp),
        (correlation_path, correlation),
    ):
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if patch_hashes:
        media["input_provenance"]["ims_session_sha256"] = _sha(session_path)
        media["input_provenance"]["sdp_analysis_sha256"] = _sha(sdp_path)
        correlation["input_provenance"]["sdp_analysis_sha256"] = _sha(sdp_path)
        for path, document in (
            (media_path, media),
            (correlation_path, correlation),
        ):
            path.write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    loaded_session = model.load_session(session_path)
    loaded_sdp = model.load_sdp(sdp_path)
    references = {
        message["source_reference"] for message in loaded_sdp["messages"]
    }
    loaded_media = model.load_media_signaling(media_path, references)
    loaded_correlation = model.load_correlation(correlation_path)
    provenance = model.verify_provenance(
        loaded_session,
        loaded_media,
        loaded_sdp,
        loaded_correlation,
        session_path=session_path,
        media_path=media_path,
        sdp_path=sdp_path,
        correlation_path=correlation_path,
    )
    document = model.build_analysis(
        loaded_session,
        loaded_media,
        loaded_sdp,
        loaded_correlation,
        provenance=provenance,
    )
    model.validate_analysis(document)
    return document


def analyze_fixture(name: str) -> dict:
    return analyze_docs(*docs(name))


def find_observation(document: dict, message_reference: str) -> dict:
    for observation in document["transport_observations"]:
        if any(
            binding["message_reference"] == message_reference
            for binding in observation["sdp_message_bindings"]
        ):
            return observation
    raise AssertionError(f"no observation for {message_reference}")


def find_branch(document: dict, state: str) -> dict:
    for attempt in document["attempts"]:
        for branch in attempt["branches"]:
            if branch["dialog_state"] == state:
                return branch
    raise AssertionError(f"no branch in state {state}")


def run_cli(
    sdp_path: Path,
    media_path: Path,
    session_path: Path,
    correlation_path: Path,
    output: Path,
    report: Path | None = None,
) -> subprocess.CompletedProcess:
    command = [
        sys.executable,
        str(CLI),
        "--ims-session-analysis",
        str(session_path),
        "--ims-media-signaling-analysis",
        str(media_path),
        "--sdp-analysis",
        str(sdp_path),
        "--transport-correlation",
        str(correlation_path),
        "--output",
        str(output),
        "--force",
    ]
    if report is not None:
        command.extend(["--report", str(report)])
    return subprocess.run(command, capture_output=True, text=True, check=False)


def example_cli(output: Path, report: Path | None = None):
    return run_cli(
        INPUTS / "sdp-analysis.json",
        INPUTS / "ims-media-signaling.json",
        INPUTS / "ims-session.json",
        INPUTS / "transport-correlation.json",
        output,
        report,
    )


class ProvenanceIntegrityTests(unittest.TestCase):
    def test_01_valid_four_artifact_input(self) -> None:
        document = analyze_fixture("base")
        self.assertEqual(document["attempt_count"], 1)
        self.assertEqual(document["transport_observation_count"], 3)

    def test_02_wrong_ims_session_hash(self) -> None:
        session, media, sdp, correlation = docs("base")
        media["input_provenance"]["ims_session_sha256"] = "0" * 64
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation, patch_hashes=False)

    def test_03_wrong_media_signaling_provenance_hash(self) -> None:
        session, media, sdp, correlation = docs("base")
        media["input_provenance"]["sdp_analysis_sha256"] = "1" * 64
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation, patch_hashes=False)

    def test_04_wrong_sdp_analysis_hash(self) -> None:
        session, media, sdp, correlation = docs("base")
        correlation["input_provenance"]["sdp_analysis_sha256"] = "2" * 64
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation, patch_hashes=False)

    def test_05_wrong_correlation_sdp_hash(self) -> None:
        session, media, sdp, correlation = docs("base")
        correlation["input_provenance"]["sdp_analysis_sha256"] = "3" * 64
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation, patch_hashes=False)

    def test_06_capture_basename_mismatch(self) -> None:
        session, media, sdp, correlation = docs("base")
        correlation["input_provenance"]["capture_files"] = ["other-capture.pcapng"]
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_07_capture_sha_mismatch(self) -> None:
        session, media, sdp, correlation = docs("base")
        correlation["input_provenance"]["capture_sha256"] = "4" * 64
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_08_endpoint_context_mismatch(self) -> None:
        session, media, sdp, correlation = docs("base")
        correlation["input_provenance"]["endpoint_context_reference"] = (
            "endpoint-context-hmac-sha256:v1:" + "5" * 64
        )
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_09_missing_endpoint_context_on_both_sides(self) -> None:
        document = analyze_fixture("no_key")
        self.assertIsNone(document["input_provenance"]["endpoint_context_reference"])
        self.assertTrue(document["transport_observations"])
        self.assertTrue(
            all(
                item["original_association_status"] != "MATCHED_ENDPOINT"
                for item in document["transport_observations"]
            )
        )

    def test_10_unsupported_analysis_version(self) -> None:
        session, media, sdp, correlation = docs("base")
        media["analysis_version"] = "9.9.9"
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_11_unsupported_schema_version(self) -> None:
        session, media, sdp, correlation = docs("base")
        sdp["event_schema_version"] = "9.9.9"
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_12_duplicate_attempt_reference(self) -> None:
        session, media, sdp, correlation = docs("base")
        session["session_attempts"].append(copy.deepcopy(session["session_attempts"][0]))
        session["session_attempt_count"] = 2
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_13_duplicate_dialog_branch_reference(self) -> None:
        session, media, sdp, correlation = docs("base")
        session["session_attempts"][0]["branches"][1]["branch_reference"] = session[
            "session_attempts"
        ][0]["branches"][0]["branch_reference"]
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_14_duplicate_exchange_reference(self) -> None:
        session, media, sdp, correlation = docs("base")
        media["exchanges"][1]["exchange_reference"] = media["exchanges"][0][
            "exchange_reference"
        ]
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_15_duplicate_transport_correlation_reference(self) -> None:
        session, media, sdp, correlation = docs("base")
        correlation["correlations"][1]["correlation_reference"] = correlation[
            "correlations"
        ][0]["correlation_reference"]
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_16_invalid_media_section_index(self) -> None:
        session, media, sdp, correlation = docs("base")
        correlation["correlations"][0]["sdp_media_sections"][0]["media_index"] = 99
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_17_invalid_sdp_source_reference(self) -> None:
        session, media, sdp, correlation = docs("base")
        sdp["messages"][0]["source_reference"] = "not-a-reference"
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_18_invalid_correlation_stream_reference(self) -> None:
        session, media, sdp, correlation = docs("base")
        correlation["correlations"][0]["rtp_udp_stream_references"] = ["bad-stream"]
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)


class BranchOwnershipTests(unittest.TestCase):
    def test_19_one_accepted_dialog_branch(self) -> None:
        document = analyze_fixture("late")
        branches = document["attempts"][0]["branches"]
        self.assertEqual(len(branches), 1)
        self.assertEqual(branches[0]["identity_status"], "ESTABLISHED")

    def test_20_two_independent_forked_branches(self) -> None:
        document = analyze_fixture("base")
        branches = document["attempts"][0]["branches"]
        self.assertEqual(len({item["branch_reference"] for item in branches}), 2)
        self.assertEqual(len({item["dialog_reference"] for item in branches}), 2)

    def test_21_confirmed_and_rejected_branch(self) -> None:
        document = analyze_fixture("rejected")
        states = [item["dialog_state"] for item in document["attempts"][0]["branches"]]
        self.assertIn("CONFIRMED", states)
        self.assertIn("EARLY", states)
        self.assertEqual(document["exchanges"][0]["association_status"], "ESTABLISHED")

    def test_22_branch_identity_not_established(self) -> None:
        session, media, sdp, correlation = docs("base")
        media["exchanges"][0]["branch_identity_status"] = "INSUFFICIENT_EVIDENCE"
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_23_dialog_identity_ambiguous(self) -> None:
        session, media, sdp, correlation = docs("base")
        session["session_attempts"][0]["branches"][0]["identity_status"] = "AMBIGUOUS"
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_24_missing_dialog_reference(self) -> None:
        session, media, sdp, correlation = docs("base")
        media["exchanges"][0]["dialog_reference"] = None
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_25_attempt_reference_mismatch(self) -> None:
        session, media, sdp, correlation = docs("base")
        media["exchanges"][0]["attempt_reference"] = "ims-session:other:9.9"
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_26_transaction_reference_mismatch(self) -> None:
        session, media, sdp, correlation = docs("base")
        media["exchanges"][0]["initial_invite_transaction_reference"] = (
            "sip-transaction:other:request:9.9"
        )
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_27_branch_reference_mismatch(self) -> None:
        session, media, sdp, correlation = docs("base")
        media["exchanges"][0]["branch_reference"] = "sip-dialog:other:9.9"
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_28_dialog_reference_mismatch(self) -> None:
        session, media, sdp, correlation = docs("base")
        media["exchanges"][0]["dialog_reference"] = "sip-dialog:other:9.9"
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_29_historical_dialog_termination(self) -> None:
        document = analyze_fixture("base")
        branch = find_branch(document, "TERMINATED")
        self.assertEqual(branch["release_outcome"], "SIP_TERMINATION_SIGNALING_SUPPORTED")
        self.assertTrue(branch["branch_transport_observation_references"])

    def test_30_missing_termination_evidence_is_preserved(self) -> None:
        document = analyze_fixture("base")
        branch = find_branch(document, "CONFIRMED")
        self.assertEqual(branch["release_outcome"], "NO_BYE_OBSERVED")

    def test_31_initial_offer_without_a_branch(self) -> None:
        document = analyze_fixture("offer")
        observation = document["transport_observations"][0]
        self.assertEqual(observation["binding_scope"], "ATTEMPT")
        self.assertIsNone(observation["branch_reference"])
        self.assertEqual(document["exchanges"][0]["exchange_type"], "INITIAL_INVITE_SDP_OFFER")

    def test_32_initial_invite_without_sdp(self) -> None:
        document = analyze_fixture("late")
        types = [item["exchange_type"] for item in document["exchanges"]]
        self.assertIn("INITIAL_INVITE_WITHOUT_SDP", types)

    def test_33_unusable_initial_sdp(self) -> None:
        document = analyze_fixture("unusable")
        types = [item["exchange_type"] for item in document["exchanges"]]
        self.assertIn("INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE", types)

    def test_34_provisional_sdp(self) -> None:
        document = analyze_fixture("provisional")
        types = [
            item["observation_type"]
            for item in document["unbound_signaling_observations"]
        ]
        self.assertIn("PROVISIONAL_SDP_UNINTERPRETED", types)

    def test_35_unsupported_in_dialog_sdp(self) -> None:
        records = [
            upstream.rec(1, method="INVITE", sdp_body=upstream.AUDIO_OFFER),
            upstream.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=builder.ANSWER_ONE),
            upstream.rec(3, method="ACK", cseq=1, to_tag="TT-1"),
            upstream.rec(4, method="UPDATE", cseq=2, to_tag="TT-1", sdp_body=builder.ANSWER_ONE),
        ]
        bundle = _bundle(records, builder.offer_only_rtp_records())
        document = analyze_docs(*(
            copy.deepcopy(bundle["session_document"]),
            copy.deepcopy(bundle["media_document"]),
            copy.deepcopy(bundle["sdp_document"]),
            copy.deepcopy(bundle["correlation_document"]),
        ))
        types = [
            item["observation_type"]
            for item in document["unbound_signaling_observations"]
        ]
        self.assertIn("UNSUPPORTED_SDP_OBSERVATION", types)


class OfferAnswerTests(unittest.TestCase):
    def test_36_initial_invite_offer_answer(self) -> None:
        document = analyze_fixture("base")
        self.assertTrue(
            all(item["exchange_type"] == "INITIAL_INVITE_OFFER_ANSWER" for item in document["exchanges"])
        )

    def test_37_shared_initial_offer_across_forks(self) -> None:
        document = analyze_fixture("base")
        shared = document["attempts"][0]["shared_initial_offer_observation_references"]
        self.assertEqual(len(shared), 1)
        for branch in document["attempts"][0]["branches"]:
            self.assertEqual(branch["shared_initial_offer_observation_references"], shared)

    def test_38_different_answer_per_fork(self) -> None:
        document = analyze_fixture("base")
        answers = {
            item["answer_sdp_reference"] for item in document["exchanges"]
        }
        self.assertEqual(len(answers), 2)

    def test_39_late_offer_and_ack_answer(self) -> None:
        document = analyze_fixture("late")
        late = [item for item in document["exchanges"] if item["exchange_type"] == "LATE_OFFER_ANSWER"]
        self.assertEqual(len(late), 1)
        observation = find_observation(document, late[0]["answer_sdp_reference"])
        self.assertEqual(observation["binding_scope"], "BRANCH")

    def test_40_missing_ack_answer(self) -> None:
        records = [
            upstream.rec(1, method="INVITE"),
            upstream.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=upstream.AUDIO_OFFER),
        ]
        bundle = _bundle(records, builder.offer_only_rtp_records())
        document = analyze_docs(*(
            copy.deepcopy(bundle["session_document"]),
            copy.deepcopy(bundle["media_document"]),
            copy.deepcopy(bundle["sdp_document"]),
            copy.deepcopy(bundle["correlation_document"]),
        ))
        late = [item for item in document["exchanges"] if item["exchange_type"] == "LATE_OFFER_ANSWER"]
        self.assertTrue(late)
        self.assertNotEqual(late[0]["association_status"], "ESTABLISHED")

    def test_41_multiple_competing_answers(self) -> None:
        document = analyze_fixture("shared_answer")
        observation = find_observation(document, document["exchanges"][0]["answer_sdp_reference"])
        self.assertEqual(observation["binding_scope"], "AMBIGUOUS")
        self.assertEqual(observation["binding_status"], "AMBIGUOUS")

    def test_42_ambiguous_offer_answer_exchange(self) -> None:
        session, media, sdp, correlation = docs("base")
        media["exchanges"][0]["association_status"] = "AMBIGUOUS"
        media["exchanges"][0]["offer_role"] = None
        media["exchanges"][0]["answer_role"] = None
        media["completeness"]["established_exchange_count"] -= 1
        media["completeness"]["ambiguous_exchange_count"] += 1
        document = analyze_docs(session, media, sdp, correlation)
        observation = find_observation(document, media["exchanges"][0]["answer_sdp_reference"])
        self.assertEqual(observation["binding_scope"], "UNBOUND")
        self.assertEqual(observation["binding_status"], "INSUFFICIENT_EVIDENCE")

    def test_43_unestablished_signaling_exchange(self) -> None:
        document = analyze_fixture("unusable")
        self.assertFalse(
            any(item["association_status"] == "ESTABLISHED" for item in document["exchanges"] if item["exchange_type"] == "INITIAL_INVITE_SDP_EVIDENCE_UNUSABLE")
        )

    def test_44_one_exchange_with_missing_transport_correlation(self) -> None:
        document = analyze_fixture("no_correlation")
        self.assertEqual(document["transport_observation_count"], 0)
        self.assertTrue(
            all(
                "TRANSPORT_CORRELATION_NOT_OBSERVED" in item["missing_evidence"]
                for item in document["exchanges"]
                if item["association_status"] == "ESTABLISHED"
            )
        )


class TransportAssociationTests(unittest.TestCase):
    def test_45_unique_matched_endpoint(self) -> None:
        document = analyze_fixture("base")
        observation = find_observation(document, document["exchanges"][0]["answer_sdp_reference"])
        self.assertEqual(observation["original_association_status"], "MATCHED_ENDPOINT")
        self.assertEqual(observation["binding_scope"], "BRANCH")

    def test_46_unique_bundle_transport(self) -> None:
        document = analyze_fixture("bundle")
        observations = [
            item
            for item in document["transport_observations"]
            if item["original_association_status"] == "BUNDLE_TRANSPORT_MATCHED"
        ]
        self.assertEqual(len(observations), 1)
        self.assertEqual(len(observations[0]["sdp_message_bindings"]), 2)
        self.assertEqual(observations[0]["binding_scope"], "BRANCH")

    def test_47_original_ambiguous_preserved(self) -> None:
        document = analyze_fixture("unrelated")
        ambiguous = [
            item
            for item in document["transport_observations"]
            if item["original_association_status"] == "AMBIGUOUS"
        ]
        self.assertTrue(ambiguous)
        self.assertEqual(ambiguous[0]["binding_scope"], "BRANCH")

    def test_48_original_insufficient_preserved(self) -> None:
        document = analyze_fixture("no_key")
        statuses = {
            item["original_association_status"]
            for item in document["transport_observations"]
        }
        self.assertIn("INSUFFICIENT_EVIDENCE", statuses)
        self.assertNotIn("MATCHED_ENDPOINT", statuses)

    def test_49_original_unmatched_preserved(self) -> None:
        document = analyze_fixture("unmatched_media")
        statuses = {
            item["original_association_status"]
            for item in document["transport_observations"]
        }
        self.assertIn("UNMATCHED", statuses)

    def test_50_original_out_of_scope_preserved(self) -> None:
        document = analyze_fixture("out_of_scope")
        statuses = {
            item["original_association_status"]
            for item in document["transport_observations"]
        }
        self.assertIn("OUT_OF_SCOPE", statuses)

    def test_51_source_endpoint_direction_preserved(self) -> None:
        document = analyze_fixture("base")
        directions = {
            direction
            for item in document["transport_observations"]
            for direction in item["match_directions"]
        }
        self.assertIn("RTP_SOURCE_ENDPOINT_MATCH", directions)

    def test_52_destination_endpoint_direction_preserved(self) -> None:
        document = analyze_fixture("base")
        directions = {
            direction
            for item in document["transport_observations"]
            for direction in item["match_directions"]
        }
        self.assertIn("RTP_DESTINATION_ENDPOINT_MATCH", directions)

    def test_53_multiple_media_sections_one_correlation(self) -> None:
        document = analyze_fixture("bundle")
        bundle = [
            item for item in document["transport_observations"]
            if item["correlation_type"] == "BUNDLE_MEDIA"
        ][0]
        self.assertEqual(len(bundle["sdp_message_bindings"]), 2)

    def test_54_multiple_sdp_messages_one_correlation(self) -> None:
        document = analyze_fixture("shared_answer")
        observation = [
            item for item in document["transport_observations"]
            if len(item["sdp_message_bindings"]) > 1
        ][0]
        self.assertEqual(len({b["message_reference"] for b in observation["sdp_message_bindings"]}), 2)

    def test_55_multiple_exchange_owners(self) -> None:
        document = analyze_fixture("shared_answer")
        ambiguous = [
            item for item in document["transport_observations"]
            if item["binding_scope"] == "AMBIGUOUS"
        ][0]
        self.assertEqual(len(ambiguous["exchange_references"]), 2)

    def test_56_correlation_spanning_multiple_branches(self) -> None:
        document = analyze_fixture("shared_answer")
        ambiguous = [
            item for item in document["transport_observations"]
            if item["binding_scope"] == "AMBIGUOUS"
        ][0]
        self.assertEqual(len(ambiguous["candidate_branch_references"]), 2)

    def test_57_correlation_spanning_multiple_attempts(self) -> None:
        document = analyze_fixture("two_attempts")
        ambiguous = [
            item for item in document["transport_observations"]
            if item["binding_scope"] == "AMBIGUOUS"
        ][0]
        self.assertEqual(len(ambiguous["candidate_attempt_references"]), 2)
        self.assertIsNone(ambiguous["attempt_reference"])

    def test_58_same_endpoint_reused_across_forks(self) -> None:
        document = analyze_fixture("shared_answer")
        ambiguous = [
            item for item in document["transport_observations"]
            if item["binding_scope"] == "AMBIGUOUS"
        ][0]
        self.assertEqual(len(ambiguous["endpoint_references"]), 1)

    def test_59_correlation_with_offer_and_answer_references(self) -> None:
        document = analyze_fixture("same_endpoint")
        observation = document["transport_observations"][0]
        roles = {
            role
            for binding in observation["sdp_message_bindings"]
            for role in binding["roles"]
        }
        self.assertIn("OFFER", roles)
        self.assertIn("ANSWER", roles)
        self.assertEqual(observation["binding_scope"], "BRANCH")

    def test_60_shared_bundle_transport(self) -> None:
        document = analyze_fixture("bundle")
        observation = [
            item for item in document["transport_observations"]
            if item["original_association_status"] == "BUNDLE_TRANSPORT_MATCHED"
        ][0]
        self.assertEqual(len(observation["rtp_udp_stream_references"]), 1)
        self.assertEqual(len(observation["sdp_message_bindings"]), 2)

    def test_61_unresolved_bundle(self) -> None:
        unresolved = BUNDLE_ANSWER.replace("a=group:BUNDLE 0 1", "a=group:BUNDLE 0 9")
        records = [
            upstream.rec(1, method="INVITE", sdp_body=upstream.AUDIO_OFFER),
            upstream.rec(2, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=unresolved),
            upstream.rec(3, method="ACK", cseq=1, to_tag="TT-1"),
        ]
        bundle = _bundle(records, bundle_rtp_records())
        document = analyze_docs(*(
            copy.deepcopy(bundle["session_document"]),
            copy.deepcopy(bundle["media_document"]),
            copy.deepcopy(bundle["sdp_document"]),
            copy.deepcopy(bundle["correlation_document"]),
        ))
        self.assertFalse(
            any(
                item["original_association_status"] == "BUNDLE_TRANSPORT_MATCHED"
                for item in document["transport_observations"]
            )
        )

    def test_62_missing_correlation_record(self) -> None:
        document = analyze_fixture("no_correlation")
        self.assertEqual(document["transport_observation_count"], 0)
        self.assertEqual(document["completeness"]["transport_correlation_count"], 0)

    def test_63_correlation_truncation(self) -> None:
        old = model.MAX_OBSERVATIONS
        model.MAX_OBSERVATIONS = 1
        try:
            document = analyze_fixture("base")
        finally:
            model.MAX_OBSERVATIONS = old
        self.assertEqual(document["transport_observation_count"], 1)
        self.assertEqual(document["completeness"]["transport_correlations_omitted"], 2)

    def test_64_unmatched_rtp_stream_preservation(self) -> None:
        document = analyze_fixture("base")
        self.assertEqual(document["unmatched_rtp_stream_count"], 1)
        self.assertIn(
            "rtp-udp-stream:synthetic-ims-media.pcapng:9",
            [item["rtp_udp_stream_reference"] for item in document["unmatched_rtp_streams"]],
        )

    def test_65_no_arbitrary_stream_selection(self) -> None:
        document = analyze_fixture("shared_answer")
        ambiguous = [
            item for item in document["transport_observations"]
            if item["binding_scope"] == "AMBIGUOUS"
        ][0]
        self.assertIsNone(ambiguous["branch_reference"])
        self.assertTrue(ambiguous["candidate_branch_references"])


class PrivacyTemporalTests(unittest.TestCase):
    def test_66_no_raw_ip_leakage(self) -> None:
        text = json.dumps(analyze_fixture("base"))
        for token in ("192.0.2.10", "192.0.2.21", "192.0.2.22", "2001:db8"):
            self.assertNotIn(token, text)

    def test_67_no_raw_udp_port_leakage(self) -> None:
        text = json.dumps(analyze_fixture("base"))
        for token in ('"source_port"', '"destination_port"', ":49170", ":49200", ":6000", ":7000"):
            self.assertNotIn(token, text)

    def test_68_no_raw_endpoint_tuple_leakage(self) -> None:
        text = json.dumps(analyze_fixture("base"))
        for token in ("source_address", "destination_address", "source_port", "destination_port"):
            self.assertNotIn(token, text)

    def test_69_no_hmac_key_leakage(self) -> None:
        text = json.dumps(analyze_fixture("base"))
        self.assertNotIn(builder.KEY.hex(), text)
        self.assertNotIn("hmac_key", text)
        self.assertNotIn("endpoint_key", text)

    def test_70_no_raw_sip_or_sdp_body_leakage(self) -> None:
        text = json.dumps(analyze_fixture("base"))
        for token in ("v=0", "m=audio", "a=rtpmap", "sdp_body", "call_id", "from_tag", "to_tag"):
            self.assertNotIn(token, text)

    def test_71_no_subscriber_identity_leakage(self) -> None:
        text = json.dumps(analyze_fixture("base"))
        for token in ("sip:caller", "sip:callee", "203.0.113"):
            self.assertNotIn(token, text)

    def test_72_capture_wide_match_does_not_imply_temporal_association(self) -> None:
        document = analyze_fixture("base")
        self.assertEqual(document["temporal_association_status"], "NOT_EVALUATED")
        self.assertEqual(
            document["association_scope"],
            "CAPTURE_WIDE_ENDPOINT_CORRESPONDENCE_ONLY",
        )
        for observation in document["transport_observations"]:
            self.assertEqual(observation["temporal_association_status"], "NOT_EVALUATED")
            self.assertEqual(observation["association_scope"], "CAPTURE_WIDE_ENDPOINT_CORRESPONDENCE_ONLY")

    def test_73_no_timestamp_proximity_selection(self) -> None:
        document = analyze_fixture("base")
        self.assertNotIn("timestamp", json.dumps(document["transport_observations"]))
        self.assertNotIn("TIME_WINDOW", json.dumps(document))

    def test_74_no_rtp_delivery_verdict(self) -> None:
        document = analyze_fixture("base")
        self.assertIn("MEDIA_DELIVERY", document["not_confirmed"])
        self.assertNotIn("media_delivery", json.dumps(document).lower().replace('"media_delivery"', ""))

    def test_75_no_two_way_audio_verdict(self) -> None:
        self.assertIn("TWO_WAY_AUDIO", analyze_fixture("base")["not_confirmed"])

    def test_76_no_media_teardown_inference_after_bye(self) -> None:
        document = analyze_fixture("base")
        self.assertIn("RTP_TEARDOWN_AFTER_BYE", document["not_confirmed"])
        self.assertEqual(find_branch(document, "TERMINATED")["release_outcome"], "SIP_TERMINATION_SIGNALING_SUPPORTED")

    def test_77_no_codec_compatibility_verdict(self) -> None:
        self.assertIn("CODEC_COMPATIBILITY", analyze_fixture("base")["not_confirmed"])

    def test_78_no_qos_or_mos_verdict(self) -> None:
        not_confirmed = analyze_fixture("base")["not_confirmed"]
        self.assertIn("MEDIA_QOS", not_confirmed)
        self.assertIn("MOS", not_confirmed)

    def test_79_no_early_media_promotion_from_provisional_sdp(self) -> None:
        document = analyze_fixture("provisional")
        provisional = [
            item
            for item in document["unbound_signaling_observations"]
            if item["observation_type"] == "PROVISIONAL_SDP_UNINTERPRETED"
        ][0]
        self.assertEqual(provisional["association_status"], "OUT_OF_SCOPE")

    def test_80_no_rtp_mid_demultiplexing(self) -> None:
        document = analyze_fixture("bundle")
        observation = [
            item for item in document["transport_observations"]
            if item["correlation_type"] == "BUNDLE_MEDIA"
        ][0]
        self.assertEqual(len(observation["rtp_udp_stream_references"]), 1)
        self.assertEqual(len(observation["sdp_message_bindings"]), 2)
        self.assertTrue(observation["bundle_references"])


class OutputIntegrityTests(unittest.TestCase):
    def test_81_strict_json_schema_validation(self) -> None:
        if jsonschema is None:
            self.skipTest("jsonschema is unavailable")
        document = analyze_fixture("base")
        jsonschema.validate(document, json.loads(SCHEMA.read_text(encoding="utf-8")))

    def test_82_cross_field_consistency(self) -> None:
        document = analyze_fixture("base")
        for observation in document["transport_observations"]:
            if observation["binding_scope"] == "ATTEMPT":
                self.assertIsNone(observation["branch_reference"])
                self.assertEqual(observation["binding_status"], "ESTABLISHED")
            if observation["binding_scope"] == "BRANCH":
                self.assertIsNotNone(observation["branch_reference"])
                self.assertIsNotNone(observation["dialog_reference"])

    def test_83_count_conservation(self) -> None:
        document = analyze_fixture("base")
        completeness = document["completeness"]
        self.assertEqual(
            completeness["attempt_bound_observation_count"]
            + completeness["branch_bound_observation_count"]
            + completeness["ambiguous_observation_count"]
            + completeness["unbound_observation_count"],
            document["transport_observation_count"],
        )
        self.assertEqual(
            completeness["ims_session_attempt_count"],
            completeness["published_attempt_count"] + completeness["attempts_omitted"],
        )

    def test_84_duplicate_output_reference_rejection(self) -> None:
        session, media, sdp, correlation = docs("base")
        correlation["correlations"].append(copy.deepcopy(correlation["correlations"][0]))
        correlation["correlation_count"] = len(correlation["correlations"])
        with self.assertRaises(model.InputError):
            analyze_docs(session, media, sdp, correlation)

    def test_85_deterministic_replay(self) -> None:
        first = analyze_fixture("base")
        second = analyze_fixture("base")
        self.assertEqual(first, second)

    def test_86_invalid_input_produces_no_partial_output(self) -> None:
        directory = Path(tempfile.mkdtemp())
        session_path = directory / "session.json"
        media_path = directory / "media.json"
        sdp_path = directory / "sdp.json"
        correlation_path = directory / "corr.json"
        session, media, sdp, correlation = docs("base")
        media["analysis_version"] = "9.9.9"
        for path, document in (
            (session_path, session),
            (media_path, media),
            (sdp_path, sdp),
            (correlation_path, correlation),
        ):
            path.write_text(json.dumps(document), encoding="utf-8")
        output = directory / "out.json"
        completed = run_cli(sdp_path, media_path, session_path, correlation_path, output)
        self.assertEqual(completed.returncode, 2)
        self.assertFalse(output.exists())

    def test_87_output_collision_rejection(self) -> None:
        directory = Path(tempfile.mkdtemp())
        output = directory / "same.json"
        completed = example_cli(INPUTS / "ims-session.json")
        self.assertNotEqual(completed.returncode, 0)

    def test_88_report_and_json_consistency(self) -> None:
        directory = Path(tempfile.mkdtemp())
        output = directory / "out.json"
        report = directory / "report.txt"
        completed = example_cli(output, report)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document = json.loads(output.read_text(encoding="utf-8"))
        text = report.read_text(encoding="utf-8")
        self.assertIn(f"attempts: {document['attempt_count']}", text)
        self.assertIn(f"transport_observations: {document['transport_observation_count']}", text)

    def test_89_existing_upstream_fixtures_unchanged(self) -> None:
        media_expected = (
            SKILL.parents[1]
            / "domain"
            / "ims-media-signaling"
            / "examples"
            / "expected"
            / "media-analysis.json"
        )
        self.assertTrue(media_expected.is_file())
        document = json.loads(media_expected.read_text(encoding="utf-8"))
        self.assertEqual(document["analysis_version"], "0.3.0")

    def test_90_full_example_expected_output(self) -> None:
        directory = Path(tempfile.mkdtemp())
        output = directory / "analysis.json"
        report = directory / "report.txt"
        completed = example_cli(output, report)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            output.read_bytes(),
            (EXPECTED / "ims-media-session-analysis.json").read_bytes(),
        )
        self.assertEqual(
            report.read_bytes(),
            (EXPECTED / "ims-media-session-report.txt").read_bytes(),
        )
        document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(document["attempt_count"], 1)
        self.assertEqual(document["unmatched_rtp_stream_count"], 1)