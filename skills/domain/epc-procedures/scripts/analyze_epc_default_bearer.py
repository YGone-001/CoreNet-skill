#!/usr/bin/env python3
"""Analyze bounded EPS default-bearer evidence from accepted lower-layer output.

Consumes the detailed NAS-EPS events (including decoded ESM messages), the
detailed S1AP events (including item-scoped E-RAB evidence), the accepted EPS
Attach analysis, the accepted EPC session-control analysis, and optionally the
GTPv2-C events for exact S1-U endpoint identity only.

It never decodes a capture, never reads subscriber identity, and never claims
bearer, PDN-connection or user-plane success.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_default_bearer_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_INSTANCES,
    EXIT_OUTPUT_FAILURE,
    InputError,
    analyze,
    read_json,
    read_jsonl,
    safe_name,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--nas", type=Path, required=True, help="detailed NAS-EPS event JSONL with ESM evidence")
    result.add_argument("--s1ap", type=Path, help="detailed S1AP event JSONL with E-RAB evidence")
    result.add_argument("--attach", type=Path, help="accepted EPS Attach analysis JSON")
    result.add_argument("--session", type=Path, help="accepted EPC session-control analysis JSON")
    result.add_argument(
        "--gtpv2",
        type=Path,
        help="detailed GTPv2-C event JSONL, used only for exact S1-U tunnel endpoint identity",
    )
    result.add_argument("--output", type=Path, required=True, help="default-bearer analysis JSON destination")
    result.add_argument("--timeline-output", type=Path, help="optional procedure timeline JSONL destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing outputs")
    return result


def _check(sources: list[Path], destination: Path, force: bool) -> None:
    resolved = destination.resolve()
    for source in sources:
        if source.resolve() == resolved:
            raise OSError("output must not replace an input artifact")
    if destination.exists() and not force:
        raise OSError(f"output already exists: {destination}; use --force to replace it")
    if not destination.parent.is_dir():
        raise OSError(f"output directory does not exist: {destination.parent}")


def _write(path: Path, text: str) -> None:
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", newline="\n",
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(text)
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def _provenance(args: argparse.Namespace, nas: list, s1ap: list, gtpv2: list) -> dict[str, object]:
    provenance: dict[str, object] = {
        "nas_eps_events": safe_name(args.nas),
        "nas_eps_event_count": len(nas),
        "esm_message_count": sum(len(event.get("esm_messages") or []) for event in nas),
    }
    provenance["s1ap_events"] = safe_name(args.s1ap) if args.s1ap is not None else None
    provenance["s1ap_event_count"] = len(s1ap) if args.s1ap is not None else 0
    provenance["erab_item_count"] = sum(len(event.get("erab_items") or []) for event in s1ap)
    provenance["attach_analysis"] = safe_name(args.attach) if args.attach is not None else None
    provenance["session_analysis"] = safe_name(args.session) if args.session is not None else None
    provenance["gtpv2_events"] = safe_name(args.gtpv2) if args.gtpv2 is not None else None
    provenance["gtpv2_event_count"] = len(gtpv2) if args.gtpv2 is not None else 0
    return provenance


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    sources = [path for path in (args.nas, args.s1ap, args.attach, args.session, args.gtpv2) if path is not None]
    try:
        nas = read_jsonl(args.nas)
        s1ap = read_jsonl(args.s1ap) if args.s1ap is not None else []
        gtpv2 = read_jsonl(args.gtpv2) if args.gtpv2 is not None else []
        attach = read_json(args.attach) if args.attach is not None else None
        session = read_json(args.session) if args.session is not None else None
        analysis = analyze(
            nas,
            s1ap,
            attach_analysis=attach,
            session_analysis=session,
            gtpv2_events=gtpv2,
            provenance=_provenance(args, nas, s1ap, gtpv2),
        )
        _check(sources, args.output, args.force)
        if args.timeline_output is not None:
            _check(sources, args.timeline_output, args.force)
        _write(args.output, json.dumps(analysis, indent=2, sort_keys=True) + "\n")
        if args.timeline_output is not None:
            rows = timeline_rows(analysis)
            _write(
                args.timeline_output,
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            )
            print(f"wrote {len(rows)} procedure timeline record(s) to {args.timeline_output.name}")
        print(
            f"wrote EPS default-bearer analysis for {analysis['instance_count']} instance(s), "
            f"{analysis['esm_observation_count']} ESM observation(s) and "
            f"{len(analysis['established_links'])} established link(s) to {args.output.name}"
        )
        return 0 if analysis["instance_count"] else EXIT_NO_INSTANCES
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE


def timeline_rows(analysis: dict[str, object]) -> list[dict[str, object]]:
    """Deterministic per-instance stage rows, ordered by observation window."""
    rows: list[dict[str, object]] = []
    for instance in analysis.get("default_bearer_instances") or []:
        if not isinstance(instance, dict):
            continue
        for stage in instance.get("stages") or []:
            if not isinstance(stage, dict):
                continue
            rows.append(
                {
                    "instance_reference": instance.get("instance_reference"),
                    "association_strength": instance.get("association_strength"),
                    "stage_id": stage.get("stage_id"),
                    "status": stage.get("status"),
                    "conditional": stage.get("conditional"),
                    "first_frame": stage.get("first_frame"),
                    "last_frame": stage.get("last_frame"),
                    "message_count": stage.get("message_count"),
                }
            )
    rows.sort(
        key=lambda row: (
            row["first_frame"] if isinstance(row["first_frame"], int) else 1 << 30,
            str(row["instance_reference"]),
            str(row["stage_id"]),
        )
    )
    return rows


if __name__ == "__main__":
    raise SystemExit(main())
