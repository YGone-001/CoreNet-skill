#!/usr/bin/env python3
"""Protocol-local GTP-U directed stream summary.

Groups observed GTP-U events into directed tunnel contexts scoped by
capture, outer source endpoint, outer destination endpoint and TEID. A TEID
alone never identifies a global tunnel, and opposite directions are always
separate contexts.

This is an observation summary, not PDU Session state and not a delivery or
success verdict. Packet and byte counts count what was observed at the
capture point. Sequence gaps produce at most a non-conclusive
discontinuity candidate; they never produce a packet-loss conclusion.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gtpu_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    directed_path_key,
    optional_int,
)

BYTE_COUNT_DEFINITION = "sum of the GTP-U Length field (payload octets following the mandatory header part)"

G_PDU_CODE = 255
END_MARKER_CODE = 254
ERROR_INDICATION_CODE = 26


def read_events(path: Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON at line {line_number}: {exc.msg}") from exc
            if not isinstance(event, dict):
                raise InputError(f"event at line {line_number} is not an object")
            if "frame_number" not in event or "capture_file" not in event:
                raise InputError(f"event at line {line_number} lacks frame provenance")
            events.append(event)
    if not events:
        raise InputError("no detailed GTP-U events found")
    return events


def _header(event: dict[str, object]) -> dict[str, object]:
    header = event.get("header")
    return header if isinstance(header, dict) else {}


def _has_directed_context(event: dict[str, object]) -> bool:
    outer = event.get("outer")
    if not isinstance(outer, dict):
        return False
    return outer.get("source_address") is not None and outer.get("destination_address") is not None


def _sequence_discontinuity(sequences: list[int]) -> bool | None:
    """Non-conclusive candidate flag over observed sequence numbers."""
    if len(sequences) < 2:
        return None
    ordered = sorted(set(sequences))
    for index in range(1, len(ordered)):
        if ordered[index] != ordered[index - 1] + 1:
            return True
    return False


def summarize(events: list[dict[str, object]]) -> dict[str, object]:
    """Group events into directed observed user-plane contexts."""
    capture_file: str | None = None
    streams: dict[str, dict[str, object]] = {}
    unbound_events: list[dict[str, object]] = []

    ordered = sorted(events, key=lambda item: (str(item.get("timestamp")), item.get("frame_number") or 0))

    for event in ordered:
        if capture_file is None and event.get("capture_file") is not None:
            capture_file = str(event["capture_file"])
        header = _header(event)
        code = optional_int(header.get("message_type_code"))
        if code is None or not _has_directed_context(event):
            unbound_events.append({
                "frame_number": event.get("frame_number"),
                "timestamp": event.get("timestamp"),
                "message_type": header.get("message_type"),
                "support_status": event.get("support_status"),
                "limitation": "no outer endpoint evidence; no directed tunnel context could be built",
            })
            continue
        key = directed_path_key(event)
        outer = event.get("outer") if isinstance(event.get("outer"), dict) else {}
        stream = streams.setdefault(key, {
            "stream_key": key,
            "capture_file": event.get("capture_file"),
            "outer_source": outer.get("source_address"),
            "outer_destination": outer.get("destination_address"),
            "udp_source_port": outer.get("source_port"),
            "udp_destination_port": outer.get("destination_port"),
            "teid": optional_int(header.get("teid")),
            "frames": [],
            "timestamps": [],
            "g_pdu_frames": [],
            "g_pdu_bytes": 0,
            "qfi_values": [],
            "sequence_numbers": [],
            "sequence_frames": {},
            "end_marker_frames": [],
            "error_indication_refs": [],
            "limitations": [],
        })
        frame = event.get("frame_number")
        stream["frames"].append(frame)
        stream["timestamps"].append(event.get("timestamp"))

        if code == G_PDU_CODE:
            stream["g_pdu_frames"].append(frame)
            length = optional_int(header.get("message_length"))
            stream["g_pdu_bytes"] += length if length is not None else 0
            container = event.get("pdu_session_container")
            if isinstance(container, dict) and container.get("qfi") is not None:
                qfi = int(container["qfi"])
                if qfi not in stream["qfi_values"]:
                    stream["qfi_values"].append(qfi)
            if header.get("s_flag") is True and header.get("sequence_number") is not None:
                sequence = int(header["sequence_number"])
                stream["sequence_numbers"].append(sequence)
                stream["sequence_frames"].setdefault(sequence, []).append(frame)
        elif code == END_MARKER_CODE:
            stream["end_marker_frames"].append(frame)
        elif code == ERROR_INDICATION_CODE:
            stream["error_indication_refs"].append(frame)

    rendered: list[dict[str, object]] = []
    limitations: list[str] = []
    for key in sorted(streams):
        stream = streams[key]
        frames = [frame for frame in stream["frames"] if frame is not None]
        timestamps = sorted(str(value) for value in stream["timestamps"] if value)
        sequences = sorted(stream["sequence_numbers"])
        duplicates = sorted(
            frame for sequence, frames_for_sequence in stream["sequence_frames"].items() if len(frames_for_sequence) > 1
            for frame in frames_for_sequence[1:]
        )
        if duplicates:
            stream["limitations"].append("identical sequence numbers observed more than once; duplicate-observation candidate only, every frame preserved")
        if sequences:
            stream["limitations"].append("sequence numbers are optional in GTP-U; gaps are not a packet-loss conclusion")
        if not stream["g_pdu_frames"]:
            stream["limitations"].append("no G-PDU observed in this directed context inside the capture window")
        rendered.append({
            "stream_key": key,
            "capture_file": stream["capture_file"],
            "outer_source": stream["outer_source"],
            "outer_destination": stream["outer_destination"],
            "udp_source_port": stream["udp_source_port"],
            "udp_destination_port": stream["udp_destination_port"],
            "teid": stream["teid"],
            "first_frame": min(frames) if frames else None,
            "last_frame": max(frames) if frames else None,
            "first_timestamp": timestamps[0] if timestamps else None,
            "last_timestamp": timestamps[-1] if timestamps else None,
            "observed_g_pdu_packet_count": len(stream["g_pdu_frames"]),
            "observed_payload_byte_count": stream["g_pdu_bytes"],
            "byte_count_definition": BYTE_COUNT_DEFINITION,
            "qfi_values": sorted(stream["qfi_values"]),
            "sequence_numbers": sequences,
            "sequence_discontinuity_candidate": _sequence_discontinuity(sequences),
            "end_marker_frames": sorted(frame for frame in stream["end_marker_frames"] if frame is not None),
            "error_indication_refs": sorted(frame for frame in stream["error_indication_refs"] if frame is not None),
            "duplicate_observation_candidates": duplicates,
            "limitations": stream["limitations"],
        })

    if unbound_events:
        limitations.append("some events carried no outer endpoint evidence and were left unbound")
    limitations.append("counts describe packets observed at this capture point only; they are not end-to-end delivery counts")
    return {
        "capture_file": capture_file,
        "streams": rendered,
        "unbound_events": unbound_events,
        "limitations": limitations,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="detailed GTP-U event JSONL")
    result.add_argument("--output", type=Path, required=True, help="stream summary JSON destination")
    result.add_argument("--force", action="store_true", help="explicitly replace an existing output file")
    return result


def write_summary(input_path: Path, output: Path, force: bool) -> int:
    if input_path.resolve() == output.resolve():
        raise OSError("output must not replace the input artifact")
    if output.exists() and not force:
        raise OSError(f"output already exists: {output}; use --force to replace it")
    if not output.parent.is_dir():
        raise OSError(f"output directory does not exist: {output.parent}")
    summary = summarize(read_events(input_path))
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=output.parent, prefix=f".{output.name}.", suffix=".tmp") as temporary:
            temporary_name = temporary.name
            temporary.write(json.dumps(summary, sort_keys=True, indent=2) + "\n")
        os.replace(temporary_name, output)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)
    return len(summary["streams"])


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        stream_count = write_summary(args.input, args.output, args.force)
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_NO_EVENTS if "no detailed GTP-U events" in str(exc) else EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    print(f"summarized {stream_count} directed stream(s) -> {args.output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
