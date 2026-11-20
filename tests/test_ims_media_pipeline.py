#!/usr/bin/env python3
"""Tests for the application-level offline IMS media pipeline."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ims_media_pipeline as pipeline  # noqa: E402


def _load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


sdp_adapter = _load_script("extract_sdp_bodies", ROOT / "scripts" / "extract-sdp-bodies.py")
corenet = _load_script("corenet_analyze", ROOT / "scripts" / "corenet-analyze.py")


class _Completed:
    def __init__(self, returncode: int, stderr: str = "", stdout: str = "") -> None:
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout


def _success_runner(command, **kwargs):
    output = command[command.index("--output") + 1]
    Path(output).write_text("{}\n", encoding="utf-8")
    return _Completed(0)


class MediaStatusTests(unittest.TestCase):
    def test_success_requires_answer_and_association(self) -> None:
        stages = {name: "SUCCESS" for name in (
            "sdp_extraction", "ims_media_signaling", "rtp_extraction",
            "rtp_stream", "sdp_rtp_transport", "ims_media_session",
        )}
        status, _ = pipeline._media_status(
            stages,
            {"analysis_status": "COMPLETED"},
            {"analysis_status": "COMPLETED", "rtp_packet_count": 10},
            {"matched_correlation_count": 2},
            {"established_exchange_count": 2, "attempt_bound_observation_count": 1, "branch_bound_observation_count": 1},
            {"observed_offer_count": 2, "observed_answer_count": 1},
        )
        self.assertEqual(status, "SUCCESS")

    def test_missing_answer_is_partial(self) -> None:
        stages = {name: "SUCCESS" for name in (
            "sdp_extraction", "ims_media_signaling", "rtp_extraction",
            "rtp_stream", "sdp_rtp_transport", "ims_media_session",
        )}
        status, basis = pipeline._media_status(
            stages,
            {"analysis_status": "COMPLETED"},
            {"analysis_status": "COMPLETED", "rtp_packet_count": 10},
            {"matched_correlation_count": 2},
            {"established_exchange_count": 0, "attempt_bound_observation_count": 1},
            {"observed_offer_count": 2, "observed_answer_count": 0},
        )
        self.assertEqual(status, "PARTIAL")
        self.assertIn("SDP_ANSWER_NOT_OBSERVED", basis)

    def test_no_sdp_or_rtp_is_insufficient(self) -> None:
        status, _ = pipeline._media_status(
            {"sdp_extraction": "NOT_OBSERVED_IN_CAPTURE"},
            {"analysis_status": "INSUFFICIENT_EVIDENCE"},
            {"analysis_status": "INSUFFICIENT_EVIDENCE"},
            {},
            {},
            {},
        )
        self.assertEqual(status, "INSUFFICIENT_EVIDENCE")

    def test_failed_stage_without_evidence_is_failed(self) -> None:
        status, _ = pipeline._media_status(
            {"sdp_extraction": "FAILED"},
            {"analysis_status": "NOT_OBSERVED_IN_CAPTURE"},
            {"analysis_status": "NOT_OBSERVED_IN_CAPTURE"},
            {},
            {},
            {},
        )
        self.assertEqual(status, "FAILED")


class EndpointKeyTests(unittest.TestCase):
    def test_key_creation_reuse_and_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            old = os.environ.get("CORENET_ENDPOINT_KEY_DIR")
            os.environ["CORENET_ENDPOINT_KEY_DIR"] = directory
            try:
                path, status = pipeline._resolve_key("a" * 64, None)
                self.assertEqual(status, "CREATED")
                self.assertEqual(len(path.read_bytes()), 32)
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                reused, status = pipeline._resolve_key("a" * 64, None)
                self.assertEqual(status, "REUSED")
                self.assertEqual(reused, path)
                os.chmod(path, 0o644)
                with self.assertRaises(pipeline.MediaError):
                    pipeline._resolve_key("a" * 64, None)
                path.write_bytes(b"x" * 31)
                os.chmod(path, 0o600)
                with self.assertRaises(pipeline.MediaError):
                    pipeline._resolve_key("a" * 64, None)
            finally:
                if old is None:
                    os.environ.pop("CORENET_ENDPOINT_KEY_DIR", None)
                else:
                    os.environ["CORENET_ENDPOINT_KEY_DIR"] = old

    def test_key_inside_repository_is_rejected(self) -> None:
        with self.assertRaises(pipeline.MediaError):
            pipeline._resolve_key("a" * 64, ROOT / "forbidden.key")


class StageRunnerTests(unittest.TestCase):
    def test_exit_code_mapping(self) -> None:
        self.assertEqual(pipeline._run(["x"], lambda *a, **k: _Completed(0), "stage"), ("SUCCESS", None))
        status, detail = pipeline._run(["x"], lambda *a, **k: _Completed(3, stderr="none"), "stage")
        self.assertEqual(status, "NOT_OBSERVED_IN_CAPTURE")
        self.assertIn("none", detail)
        status, _ = pipeline._run(["x"], lambda *a, **k: _Completed(4, stderr="/secret/path failed"), "stage")
        self.assertEqual(status, "FAILED")

    def test_pipeline_runs_offline_and_publishes_no_raw_body(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "synthetic.pcapng"
            capture.write_bytes(b"not-a-real-capture")
            sip_events = root / "sip-events.jsonl"
            sip_events.write_text('{"frame_number": 1, "source_reference": "sip-event:cap:1.1"}\n', encoding="utf-8")
            ims_session = root / "ims-session.json"
            ims_session.write_text("{}\n", encoding="utf-8")
            run_dir = root / "run"
            run_dir.mkdir()
            old = os.environ.get("CORENET_ENDPOINT_KEY_DIR")
            os.environ["CORENET_ENDPOINT_KEY_DIR"] = str(root / "keys")
            try:
                media = pipeline.execute_media_pipeline(
                    capture=capture,
                    run_dir=run_dir,
                    sip_events=sip_events,
                    ims_session=ims_session,
                    capture_sha256="b" * 64,
                    offline=True,
                    runner=_success_runner,
                )
            finally:
                if old is None:
                    os.environ.pop("CORENET_ENDPOINT_KEY_DIR", None)
                else:
                    os.environ["CORENET_ENDPOINT_KEY_DIR"] = old
            self.assertTrue(media["requested"])
            self.assertTrue(media["offline"])
            self.assertFalse(media["network_required"])
            self.assertEqual(media["media_status"], "INSUFFICIENT_EVIDENCE")
            self.assertEqual(media["endpoint_key_status"], "CREATED")
            text = json.dumps(media)
            for token in ("sdp_body", "raw_sdp", "hmac_key", "endpoint_key_file", "payload"):
                self.assertNotIn(token, text)
            self.assertNotIn(str(root / "keys"), text)
            for artifact in media["artifacts"]:
                self.assertTrue((run_dir / "media" / artifact["file_name"]).is_file())
                self.assertEqual(len(artifact["sha256"]), 64)
            self.assertFalse(list((run_dir / "media").glob("*.key")))

    def test_failed_sdp_stage_preserves_other_stage_attempts(self) -> None:
        def runner(command, **kwargs):
            if str(ROOT / "scripts" / "extract-sdp-bodies.py") in command:
                return _Completed(4, stderr="adapter failed")
            output = command[command.index("--output") + 1]
            Path(output).write_text("{}\n", encoding="utf-8")
            return _Completed(0)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "synthetic.pcapng"
            capture.write_bytes(b"not-a-real-capture")
            sip_events = root / "sip-events.jsonl"
            sip_events.write_text('{"frame_number": 1, "source_reference": "sip-event:cap:1.1"}\n', encoding="utf-8")
            ims_session = root / "ims-session.json"
            ims_session.write_text("{}\n", encoding="utf-8")
            run_dir = root / "run"
            run_dir.mkdir()
            old = os.environ.get("CORENET_ENDPOINT_KEY_DIR")
            os.environ["CORENET_ENDPOINT_KEY_DIR"] = str(root / "keys")
            try:
                media = pipeline.execute_media_pipeline(
                    capture=capture,
                    run_dir=run_dir,
                    sip_events=sip_events,
                    ims_session=ims_session,
                    capture_sha256="b" * 64,
                    offline=True,
                    runner=runner,
                )
            finally:
                if old is None:
                    os.environ.pop("CORENET_ENDPOINT_KEY_DIR", None)
                else:
                    os.environ["CORENET_ENDPOINT_KEY_DIR"] = old
            self.assertEqual(media["stage_statuses"]["sdp_extraction"], "FAILED")
            self.assertEqual(media["stage_statuses"]["ims_media_signaling"], "SKIPPED")
            self.assertEqual(media["media_status"], "FAILED")


class AdapterBodyTests(unittest.TestCase):
    def test_hex_decoder_accepts_pdml_bytes(self) -> None:
        text, data, error = sdp_adapter._decode_body("763d30", 3)
        self.assertIsNone(error)
        self.assertEqual(text, "v=0")
        self.assertEqual(data, b"v=0")

    def test_hex_decoder_rejects_length_mismatch(self) -> None:
        _, _, error = sdp_adapter._decode_body("763d30", 4)
        self.assertEqual(error, "SDP_BODY_LENGTH_MISMATCH")

    def test_hex_decoder_rejects_non_sdp(self) -> None:
        _, _, error = sdp_adapter._decode_body("48656c6c6f", 5)
        self.assertEqual(error, "SDP_BODY_NOT_SDP")

    def test_plain_text_body_is_accepted(self) -> None:
        text, data, error = sdp_adapter._decode_body("v=0\r\n", 5)
        self.assertIsNone(error)
        self.assertEqual(text, "v=0\r\n")
        self.assertEqual(len(data), 5)


class RepositoryHygieneTests(unittest.TestCase):
    def test_no_raw_capture_or_key_file_is_tracked(self) -> None:
        tracked = __import__("subprocess").run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=False
        ).stdout.splitlines()
        forbidden = [
            name
            for name in tracked
            if name.lower().endswith((".pcap", ".pcapng", ".cap", ".key"))
        ]
        self.assertEqual(forbidden, [])
        self.assertFalse(any(name.startswith("reports/") for name in tracked))


class UnifiedCliFlagTests(unittest.TestCase):
    def test_media_flags_are_available(self) -> None:
        parser = corenet.build_parser()
        args = parser.parse_args(
            [
                "--capture", "capture.pcapng",
                "--work-dir", "work",
                "--output-dir", "output",
                "--with-media",
                "--offline",
                "--endpoint-key-file", "key.bin",
                "--expected-capture-sha256", "a" * 64,
            ]
        )
        self.assertTrue(args.with_media)
        self.assertTrue(args.offline)
        self.assertEqual(args.endpoint_key_file, Path("key.bin"))
        self.assertEqual(args.expected_capture_sha256, "a" * 64)

    def test_media_report_rendering_has_no_raw_sdp(self) -> None:
        media = {
            "requested": True,
            "offline": True,
            "network_required": False,
            "media_status": "SUCCESS",
            "endpoint_key_status": "REUSED",
            "sdp": {"analysis_status": "COMPLETED", "message_count": 2, "media_section_count": 2},
            "media_signaling": {"analysis_status": "COMPLETED", "observed_offer_count": 1, "observed_answer_count": 1, "established_exchange_count": 1},
            "rtp_rtcp": {"analysis_status": "COMPLETED", "rtp_packet_count": 10, "rtcp_component_count": 0, "sequence": {"source_stream_count": 1}},
            "transport_correlation": {"matched_correlation_count": 1, "correlation_count": 1},
            "ims_media_session": {"attempt_count": 1, "exchange_count": 1, "established_exchange_count": 1, "transport_observation_count": 1},
            "diagnostics": {"observed": ["SDP observed"], "missing": [], "ambiguous": [], "unsupported": [], "last_supported_evidence": {"stage": "SDP", "reference": "sip-event:cap:1.1", "frame_number": 1}},
        }
        lines: list[str] = []
        corenet._render_ims_media(lines, media)
        text = "\n".join(lines)
        self.assertIn("Media pipeline", text)
        self.assertIn("SDP/RTP match", text)
        self.assertNotIn("v=0", text)
        self.assertNotIn("sdp_body", text)


if __name__ == "__main__":
    unittest.main()