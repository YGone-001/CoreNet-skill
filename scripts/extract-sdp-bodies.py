#!/usr/bin/env python3
"""Extract SDP bodies from locally decoded SIP messages into SDP Analysis.

This is an application-level adapter, not a Protocol Skill. It reuses the
accepted SIP decoder and the accepted SDP parser. Raw SIP bodies are retained
only in memory; the published SDP Analysis contains structural evidence and
never the raw SDP body. No temporary plaintext body file is created.

The adapter binds every SDP message to the exact accepted SIP Event source
reference, capture identity, frame number and message occurrence. Ambiguous,
incomplete or non-SDP messages are not promoted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for relative in ("skills/protocol/sip/scripts", "skills/protocol/sdp-rtp/scripts"):
    path = ROOT / relative
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import sdp_model  # noqa: E402
import sip_model  # noqa: E402
from endpoint_reference import (  # noqa: E402
    EndpointKeyError,
    load_endpoint_key,
)

EXIT_OK = 0
EXIT_MALFORMED_INPUT = 2
EXIT_NO_SDP = 3
EXIT_DECODER_FAILURE = 4
EXIT_OUTPUT_FAILURE = 6

MAX_MESSAGES = 4096
SDP_MEDIA_TYPE = "application/sdp"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--capture", type=Path, required=True)
    result.add_argument("--sip-events", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--report", type=Path)
    result.add_argument("--endpoint-key-file", type=Path)
    result.add_argument("--force", action="store_true")
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_sip_events(path: Path) -> dict[str, dict]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise sdp_model.InputError(f"SIP event input could not be read: {exc}") from None
    events: dict[str, dict] = {}
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise sdp_model.InputError(
                f"SIP event line {line_number} is not valid JSON: {exc}"
            ) from None
        if not isinstance(event, dict):
            raise sdp_model.InputError(f"SIP event line {line_number} is not an object")
        reference = event.get("source_reference")
        if not isinstance(reference, str) or not reference:
            raise sdp_model.InputError(
                f"SIP event line {line_number} has no source reference"
            )
        if reference in events:
            raise sdp_model.InputError("SIP event references are not unique")
        events[reference] = event
    if not events:
        raise sdp_model.InputError("SIP event input contains no messages")
    return events


def _media_type(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value.split(";", 1)[0].strip().lower() or None


def _decode_body(raw: str, declared_length: object) -> tuple[str | None, bytes | None, str | None]:
    """Decode a decoder body value without publishing it.

    TShark PDML exposes byte fields as hexadecimal text; a caller-supplied
    plain SDP string is also accepted. The returned bytes are only compared to
    the declared length and are discarded after parsing.
    """
    compact = re.sub(r"[:\s]", "", raw)
    data: bytes | None = None
    text: str | None = None
    if compact and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
        try:
            data = bytes.fromhex(compact)
            text = data.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None, None, "SDP_BODY_NOT_UTF8"
    else:
        text = raw
        data = raw.encode("utf-8", errors="surrogatepass")
    if isinstance(declared_length, int) and declared_length > 0 and len(data) != declared_length:
        return None, data, "SDP_BODY_LENGTH_MISMATCH"
    if not text.startswith("v="):
        return None, data, "SDP_BODY_NOT_SDP"
    return text, data, None


def _output_collision(source: Path, destination: Path, force: bool) -> None:
    if destination.exists() and destination.resolve() == source.resolve():
        raise OSError("output must not replace the input artifact")
    if destination.exists() and not force:
        raise OSError(f"output already exists: {destination}; use --force to replace it")
    if not destination.parent.is_dir():
        raise OSError(f"output directory does not exist: {destination.parent}")


def _write_atomic(path: Path, payload: str) -> None:
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            newline="\n",
        ) as handle:
            temporary = handle.name
            handle.write(payload)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        temporary = None
    finally:
        if temporary:
            Path(temporary).unlink(missing_ok=True)


def _report(summary: dict) -> str:
    lines = [
        "SIP-to-SDP private extraction adapter",
        f"capture: {summary['capture_file']}",
        f"capture_sha256: {summary['capture_sha256']}",
        f"sip_messages_decoded: {summary['decoded_messages']}",
        f"sdp_bodies_accepted: {summary['accepted_sdp']}",
        f"sdp_messages_published: {summary['published_sdp']}",
        "rejected_reasons:",
    ]
    if summary["rejected_reasons"]:
        lines.extend(
            f"- {reason}: {count}"
            for reason, count in sorted(summary["rejected_reasons"].items())
        )
    else:
        lines.append("- none")
    lines.append("limits:")
    lines.append("- Raw SIP and SDP bodies are never published by this adapter")
    lines.append("- Only Content-Type application/sdp messages are promoted")
    lines.append("- Incomplete or ambiguous SIP messages are not promoted")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if not args.capture.is_file() or args.capture.stat().st_size == 0:
            raise sdp_model.InputError("capture is missing or empty")
        _output_collision(args.capture, args.output, args.force)
        if args.report is not None and args.report.resolve() == args.output.resolve():
            raise OSError("JSON and report destinations must differ")
        sip_events = _load_sip_events(args.sip_events)
        capture_sha256 = _sha256(args.capture)
        capture_file = args.capture.name
        decoder_messages, decoder = sip_model.messages_for_input(
            args.capture, "capture", include_body=True
        )
        if len(decoder_messages) > MAX_MESSAGES:
            raise sdp_model.InputError("decoded SIP message count exceeds the bounded limit")
        records: list[dict] = []
        seen: set[str] = set()
        rejected: dict[str, int] = {}
        decoded_with_body = 0

        def reject(reason: str) -> None:
            rejected[reason] = rejected.get(reason, 0) + 1

        for message in decoder_messages:
            event = message.get("event") or {}
            private = message.get("_private_body") or {}
            body = private.get("body")
            if not body:
                continue
            decoded_with_body += 1
            media_type = _media_type(private.get("content_type"))
            if media_type is None:
                reject("CONTENT_TYPE_UNAVAILABLE")
                continue
            if media_type.startswith("multipart/"):
                reject("UNSUPPORTED_MULTIPART_BODY")
                continue
            if media_type != SDP_MEDIA_TYPE:
                reject("NON_SDP_BODY")
                continue
            if private.get("message_completeness") != "COMPLETE":
                reject("SIP_MESSAGE_COMPLETE")
                continue
            if private.get("extraction_status") != "OBSERVED":
                reject("SIP_EXTRACTION_NOT_OBSERVED")
                continue
            reference = event.get("source_reference")
            sip_event = sip_events.get(reference) if isinstance(reference, str) else None
            if sip_event is None:
                reject("SIP_EVENT_REFERENCE_NOT_PUBLISHED")
                continue
            if (
                sip_event.get("capture_file") != capture_file
                or sip_event.get("frame_number") != event.get("frame_number")
                or sip_event.get("message_occurrence") != event.get("message_occurrence")
            ):
                reject("SIP_EVENT_IDENTITY_MISMATCH")
                continue
            if sip_event.get("body_present") is not True or _media_type(
                (sip_event.get("headers") or {}).get("content_type")
            ) != SDP_MEDIA_TYPE:
                reject("SIP_EVENT_BODY_EVIDENCE_MISMATCH")
                continue
            decoded_body, _body_bytes, body_error = _decode_body(
                body, private.get("declared_length")
            )
            if body_error is not None:
                reject(body_error)
                continue
            assert decoded_body is not None
            if reference in seen:
                reject("DUPLICATE_SDP_REFERENCE")
                continue
            seen.add(reference)
            records.append(
                {
                    "source_reference": reference,
                    "capture_file": capture_file,
                    "capture_sha256": capture_sha256,
                    "frame_number": event["frame_number"],
                    "frame_reference": f"frame:{event['frame_number']}",
                    "message_occurrence": event["message_occurrence"],
                    "sdp_body": decoded_body,
                }
            )

        if not records:
            if args.report is not None:
                _write_atomic(
                    args.report,
                    _report(
                        {
                            "capture_file": capture_file,
                            "capture_sha256": capture_sha256,
                            "decoded_messages": len(decoder_messages),
                            "accepted_sdp": decoded_with_body,
                            "published_sdp": 0,
                            "rejected_reasons": rejected,
                        }
                    ),
                )
            print("no accepted SDP body was available for extraction", file=sys.stderr)
            return EXIT_NO_SDP
        endpoint_key = (
            load_endpoint_key(args.endpoint_key_file)
            if args.endpoint_key_file is not None
            else None
        )
        document = sdp_model.build_analysis(
            records, input_name="sip-sdp-adapter", endpoint_key=endpoint_key
        )
        sdp_model.validate_analysis(document)
        _write_atomic(
            args.output, json.dumps(document, indent=2, sort_keys=True) + "\n"
        )
        if args.report is not None:
            _write_atomic(
                args.report,
                _report(
                    {
                        "capture_file": capture_file,
                        "capture_sha256": capture_sha256,
                        "decoded_messages": len(decoder_messages),
                        "accepted_sdp": decoded_with_body,
                        "published_sdp": document["message_count"],
                        "rejected_reasons": rejected,
                    }
                ),
            )
        print(
            "extracted {} SDP message(s) from {} decoded SIP message(s) "
            "using {}".format(document["message_count"], len(decoder_messages), decoder or "local decoder")
        )
        return EXIT_OK
    except (sip_model.ToolUnavailable, sip_model.TsharkError) as exc:
        print(f"extract-sdp-bodies: {exc}", file=sys.stderr)
        return EXIT_DECODER_FAILURE
    except EndpointKeyError as exc:
        print(f"extract-sdp-bodies: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except sdp_model.InputError as exc:
        print(f"extract-sdp-bodies: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"extract-sdp-bodies: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())