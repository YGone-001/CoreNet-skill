#!/usr/bin/env python3
"""Render a bounded mobility timeline from a 5gc-handover-mobility analysis.

The timeline shows capture, frame, association, UE IDs, attempt family and
identifier, side role, message identity, HandoverType, PDU Session resource
roles, Cause, supporting N11/N4/N3 evidence, and deviation markers. It never
renders end-to-end mobility success, path-switch success, or root cause.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mobility_model import EXIT_MALFORMED_INPUT, EXIT_NO_EVENTS, EXIT_OUTPUT_FAILURE, InputError


def read_analysis(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise InputError(f"input file does not exist: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in {path.name}: {exc.msg}") from exc
    if not isinstance(document, dict) or "handover_attempts" not in document:
        raise InputError(f"{path.name} is not a 5gc-handover-mobility analysis summary")
    return document


def _value(value: object) -> str:
    return str(value) if value is not None else "-"


def _cause(cause: object) -> str:
    if not isinstance(cause, dict):
        return "-"
    category = cause.get("category")
    value = cause.get("value")
    if value is None:
        return _value(category)
    return f"{category}:{value}"


def timeline_entries(document: dict[str, object]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for family, key in (("handover", "handover_attempts"), ("path-switch", "path_switch_attempts")):
        for attempt in document.get(key, []):
            deviations = [
                deviation["type"] for deviation in attempt.get("deviations", [])
                if isinstance(deviation, dict)
            ]
            for event in attempt.get("events", []):
                supporting = []
                bindings = attempt.get("plane_bindings") or {}
                for plane in ("n11", "n4", "n3"):
                    for item in bindings.get(plane, []) or []:
                        if isinstance(item, dict) and item.get("frame_number") == event.get("frame_number"):
                            supporting.append(plane)
                entries.append({
                    "attempt_family": family,
                    "attempt_id": attempt.get("attempt_id"),
                    "side_role": event.get("role"),
                    "capture_file": event.get("capture_file"),
                    "frame_number": event.get("frame_number"),
                    "timestamp": event.get("timestamp"),
                    "association": event.get("association"),
                    "ran_ue_ngap_id": event.get("ran_ue_ngap_id"),
                    "amf_ue_ngap_id": event.get("amf_ue_ngap_id"),
                    "message_type": event.get("message_type"),
                    "handover_type": event.get("handover_type"),
                    "pdu_session_resources": event.get("resource_roles", []),
                    "cause": event.get("cause"),
                    "supporting_planes": supporting,
                    "deviation_markers": sorted(set(deviations)),
                })
            for plane, prefix in (("n11", "N11"), ("n4", "N4"), ("n3", "N3")):
                for item in (attempt.get("plane_bindings") or {}).get(plane, []) or []:
                    if isinstance(item, dict) and any(
                        entry["attempt_id"] == attempt.get("attempt_id") and entry["frame_number"] == item.get("frame_number")
                        for entry in entries
                    ):
                        continue
                    entries.append({
                        "attempt_family": family,
                        "attempt_id": attempt.get("attempt_id"),
                        "side_role": prefix.lower(),
                        "capture_file": item.get("capture_file"),
                        "frame_number": item.get("frame_number"),
                        "timestamp": item.get("timestamp"),
                        "association": None,
                        "ran_ue_ngap_id": None,
                        "amf_ue_ngap_id": None,
                        "message_type": item.get("message_type") or item.get("operation"),
                        "handover_type": None,
                        "pdu_session_resources": [],
                        "cause": item.get("cause"),
                        "supporting_planes": [plane],
                        "deviation_markers": [],
                    })
    for event in document.get("unbound_mobility_evidence", []):
        entries.append({
            "attempt_family": "unbound",
            "attempt_id": None,
            "side_role": None,
            "capture_file": event.get("capture_file"),
            "frame_number": event.get("frame_number"),
            "timestamp": event.get("timestamp"),
            "association": None,
            "ran_ue_ngap_id": None,
            "amf_ue_ngap_id": None,
            "message_type": event.get("message_type"),
            "handover_type": None,
            "pdu_session_resources": [],
            "cause": None,
            "supporting_planes": [],
            "deviation_markers": [],
        })
    entries.sort(key=lambda entry: (
        str(entry.get("timestamp") or ""), int(entry.get("frame_number") or 0),
    ))
    return entries


def render_text(document: dict[str, object]) -> str:
    lines = []
    for entry in timeline_entries(document):
        resources = ",".join(
            f"{item.get('pdu_session_id')}:{item.get('role')}"
            for item in entry["pdu_session_resources"] if isinstance(item, dict)
        )
        line = (
            f"frame={_value(entry['frame_number'])} {entry['timestamp'] or '-'} "
            f"assoc={_value(entry['association'])} "
            f"ran={_value(entry['ran_ue_ngap_id'])} amf={_value(entry['amf_ue_ngap_id'])} "
            f"[{entry['attempt_family'] or 'unbound'}:{_value(entry['attempt_id'])}] "
            f"role={_value(entry['side_role'])} {entry['message_type'] or '-'}"
        )
        if entry.get("handover_type"):
            line += f" ho-type={entry['handover_type']}"
        if resources:
            line += f" resources={resources}"
        line += f" cause={_cause(entry.get('cause'))}"
        if entry["supporting_planes"]:
            line += f" supporting={','.join(entry['supporting_planes'])}"
        if entry["deviation_markers"]:
            line += f" deviations={','.join(entry['deviation_markers'])}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def render_json(document: dict[str, object]) -> str:
    return json.dumps({"events": timeline_entries(document)}, sort_keys=True, indent=2) + "\n"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="5gc-handover-mobility analysis summary JSON")
    result.add_argument("--format", choices=("text", "json"), default="text")
    result.add_argument("--output", type=Path, help="write instead of stdout; existing files are refused without --force")
    result.add_argument("--force", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        document = read_analysis(args.input)
        rendered = render_text(document) if args.format == "text" else render_json(document)
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            if args.input.resolve() == args.output.resolve():
                raise OSError("timeline output must not replace the input artifact")
            if args.output.exists() and not args.force:
                raise OSError(f"output already exists: {args.output}; use --force to replace it")
            if not args.output.parent.is_dir():
                raise OSError(f"output directory does not exist: {args.output.parent}")
            temporary_name: str | None = None
            try:
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=args.output.parent, prefix=f".{args.output.name}.", suffix=".tmp") as temporary:
                    temporary_name = temporary.name
                    temporary.write(rendered)
                os.replace(temporary_name, args.output)
                temporary_name = None
            finally:
                if temporary_name:
                    Path(temporary_name).unlink(missing_ok=True)
            print(f"wrote timeline for {len(timeline_entries(document))} entry(ies) to {args.output.name}")
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_NO_EVENTS if "does not exist" in str(exc) else EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
