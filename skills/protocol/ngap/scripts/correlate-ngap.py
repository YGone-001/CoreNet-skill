#!/usr/bin/env python3
"""Protocol-local UE-context correlation for detailed NGAP events.

Two deterministic passes over detailed events:

1. Per capture/SCTP association, derive RAN-UE-NGAP-ID <-> AMF-UE-NGAP-ID
   bindings only from frames where both identifiers are observed together.
   A UE may bind AMF-UE-NGAP-ID A to RAN-UE-NGAP-ID R; several distinct UE
   contexts may share one association. A both-ID frame that contradicts an
   already-derived binding is recorded as a conflict (first binding is
   retained; the conflicting observation is preserved, never overwritten).

2. Assign every UE-ID-bearing event to a context and label correlation
   strength: STRONG (both IDs observed in that frame), MEDIUM (one observed
   ID plus an already-derived binding in the same association), SINGLE-ID
   (one ID observed, no binding yet).

Contexts are scoped by capture and SCTP association. Numeric identifier
matches across captures or associations never merge contexts. A context
binding is always DERIVED evidence tied to the frame that established it;
earlier single-ID frames stay in the context but are never claimed to have
observed the bound identifier.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ngap_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    association_key,
    context_key,
    optional_int,
)


class Correlator:
    """Deterministic UE-context binding model, one association at a time."""

    def __init__(self) -> None:
        self._events: list[tuple[dict[str, object], tuple[str, str]]] = []
        # association -> {"ran_to_amf": {ran: amf}, "amf_to_ran": {amf: ran}, "bound_frames": {(ran, amf): frame}}
        self._bindings: dict[tuple[str, str], dict[str, object]] = {}
        self._conflicts: list[dict[str, object]] = []

    def add(self, event: dict[str, object]) -> None:
        ran = optional_int(event.get("ran_ue_ngap_id"))
        amf = optional_int(event.get("amf_ue_ngap_id"))
        if ran is None and amf is None:
            return
        self._events.append((event, association_key(event)))

    def _state(self, association: tuple[str, str]) -> dict[str, object]:
        return self._bindings.setdefault(
            association, {"ran_to_amf": {}, "amf_to_ran": {}, "bound_frames": {}}
        )

    def _establish_bindings(self) -> None:
        for event, association in self._events:
            ran = optional_int(event.get("ran_ue_ngap_id"))
            amf = optional_int(event.get("amf_ue_ngap_id"))
            if ran is None or amf is None:
                continue
            state = self._state(association)
            ran_to_amf: dict[int, int] = state["ran_to_amf"]
            amf_to_ran: dict[int, int] = state["amf_to_ran"]
            bound_frame = state["bound_frames"].get((ran, amf))
            known_amf = ran_to_amf.get(ran)
            known_ran = amf_to_ran.get(amf)
            if known_amf == amf and known_ran == ran:
                continue
            if known_amf is not None and known_amf != amf:
                self._conflicts.append({
                    "context_key": context_key(association[0], association[1], ran, known_amf),
                    "frame_number": event.get("frame_number"),
                    "observed": {"ran_ue_ngap_id": ran, "amf_ue_ngap_id": amf},
                    "existing_binding": {"ran_ue_ngap_id": ran, "amf_ue_ngap_id": known_amf},
                    "resolution": "first-binding-retained",
                    "evidence_level": "DERIVED",
                    "source": f"correlation:{association[0]}#frame={event.get('frame_number')}",
                })
                continue
            if known_ran is not None and known_ran != ran:
                self._conflicts.append({
                    "context_key": context_key(association[0], association[1], known_ran, amf),
                    "frame_number": event.get("frame_number"),
                    "observed": {"ran_ue_ngap_id": ran, "amf_ue_ngap_id": amf},
                    "existing_binding": {"ran_ue_ngap_id": known_ran, "amf_ue_ngap_id": amf},
                    "resolution": "first-binding-retained",
                    "evidence_level": "DERIVED",
                    "source": f"correlation:{association[0]}#frame={event.get('frame_number')}",
                })
                continue
            ran_to_amf[ran] = amf
            amf_to_ran[amf] = ran
            state["bound_frames"][(ran, amf)] = event.get("frame_number")

    def summary(self, non_ue_associated: list[dict[str, object]]) -> dict[str, object]:
        self._establish_bindings()
        contexts: dict[str, dict[str, object]] = {}

        def context_for(association: tuple[str, str], ran: int | None, amf: int | None) -> dict[str, object]:
            capture, assoc = association
            state = self._bindings.get(association)
            bound_amf = state["ran_to_amf"].get(ran) if state is not None and ran is not None else None
            bound_ran = state["amf_to_ran"].get(amf) if state is not None and amf is not None else None
            if bound_amf is not None:
                key_ran, key_amf = ran, bound_amf
            elif bound_ran is not None:
                key_ran, key_amf = bound_ran, amf
            else:
                key_ran, key_amf = ran, amf
            key = context_key(capture, assoc, key_ran, key_amf)
            if key not in contexts:
                contexts[key] = {
                    "context_key": key,
                    "capture_file": capture,
                    "association": assoc,
                    "binding": None,
                    "observed_ran_ue_ngap_ids": [],
                    "observed_amf_ue_ngap_ids": [],
                    "conflicts": [],
                    "events": [],
                }
            context = contexts[key]
            if state is not None and context["binding"] is None:
                pair_frame = state["bound_frames"].get((key_ran, key_amf))
                if pair_frame is not None:
                    context["binding"] = {
                        "ran_ue_ngap_id": key_ran,
                        "amf_ue_ngap_id": key_amf,
                        "bound_frame": pair_frame,
                        "evidence_level": "DERIVED",
                        "basis": "both UE NGAP IDs observed in one frame",
                    }
            if key_ran is not None and key_ran not in context["observed_ran_ue_ngap_ids"]:
                context["observed_ran_ue_ngap_ids"].append(key_ran)
            if key_amf is not None and key_amf not in context["observed_amf_ue_ngap_ids"]:
                context["observed_amf_ue_ngap_ids"].append(key_amf)
            return context

        conflict_frames = {(conflict["context_key"], conflict["frame_number"]) for conflict in self._conflicts}
        for event, association in self._events:
            ran = optional_int(event.get("ran_ue_ngap_id"))
            amf = optional_int(event.get("amf_ue_ngap_id"))
            state = self._bindings.get(association)
            bound_amf = state["ran_to_amf"].get(ran) if state is not None and ran is not None else None
            bound_ran = state["amf_to_ran"].get(amf) if state is not None and amf is not None else None
            context = context_for(association, ran, amf)
            observed: dict[str, object] = {"ran_ue_ngap_id": ran, "amf_ue_ngap_id": amf}
            if ran is not None and amf is not None:
                strength = "STRONG"
            elif bound_amf is not None:
                strength = "MEDIUM"
                observed["derived_amf_ue_ngap_id"] = bound_amf
            elif bound_ran is not None:
                strength = "MEDIUM"
                observed["derived_ran_ue_ngap_id"] = bound_ran
            else:
                strength = "SINGLE-ID"
            entry = {
                "frame_number": event.get("frame_number"),
                "timestamp": event.get("timestamp"),
                "procedure_name": event.get("procedure_name"),
                "message_type": event.get("message_type"),
                "pdu_type": event.get("pdu_type"),
                "observed": observed,
                "correlation_strength": strength,
            }
            if (context["context_key"], event.get("frame_number")) in conflict_frames:
                entry["binding_conflict"] = True
            context["events"].append(entry)

        conflicts_by_context: dict[str, list[dict[str, object]]] = {}
        for conflict in self._conflicts:
            conflicts_by_context.setdefault(str(conflict["context_key"]), []).append(conflict)
        for key, context_conflicts in conflicts_by_context.items():
            if key in contexts:
                contexts[key]["conflicts"] = context_conflicts

        ordered = sorted(contexts.values(), key=lambda context: str(context["context_key"]))
        for context in ordered:
            context["observed_ran_ue_ngap_ids"].sort()
            context["observed_amf_ue_ngap_ids"].sort()
            context["event_count"] = len(context["events"])
            frames = [event["frame_number"] for event in context["events"] if event["frame_number"] is not None]
            context["frame_numbers"] = sorted(frames)
            timestamps = sorted(str(event["timestamp"]) for event in context["events"] if event["timestamp"])
            context["first_timestamp"] = timestamps[0] if timestamps else None
            context["last_timestamp"] = timestamps[-1] if timestamps else None
        return {
            "contexts": ordered,
            "conflicts": sorted(self._conflicts, key=lambda item: (str(item["context_key"]), str(item["frame_number"]))),
            "non_ue_associated_events": non_ue_associated,
        }


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
        raise InputError("no detailed NGAP events found")
    return events


def correlate(events: list[dict[str, object]]) -> dict[str, object]:
    correlator = Correlator()
    non_ue_associated: list[dict[str, object]] = []
    for event in events:
        if optional_int(event.get("ran_ue_ngap_id")) is None and optional_int(event.get("amf_ue_ngap_id")) is None:
            non_ue_associated.append({
                "frame_number": event.get("frame_number"),
                "timestamp": event.get("timestamp"),
                "procedure_name": event.get("procedure_name"),
                "message_type": event.get("message_type"),
                "support_status": event.get("support_status"),
                "note": "no UE NGAP ID observed; not merged into any UE context",
            })
        else:
            correlator.add(event)
    return correlator.summary(non_ue_associated)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="detailed NGAP event JSONL")
    result.add_argument("--output", type=Path, required=True, help="correlation summary JSON destination")
    result.add_argument("--force", action="store_true", help="explicitly replace an existing output file")
    return result


def write_summary(input_path: Path, output: Path, force: bool) -> int:
    if input_path.resolve() == output.resolve():
        raise OSError("output must not replace the input artifact")
    if output.exists() and not force:
        raise OSError(f"output already exists: {output}; use --force to replace it")
    if not output.parent.is_dir():
        raise OSError(f"output directory does not exist: {output.parent}")
    summary = correlate(read_events(input_path))
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
    return len(summary["contexts"])


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        context_count = write_summary(args.input, args.output, args.force)
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_NO_EVENTS if "no detailed NGAP events" in str(exc) else EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    print(f"correlated into {context_count} UE context(s) -> {args.output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
