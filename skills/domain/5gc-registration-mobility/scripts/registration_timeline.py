#!/usr/bin/env python3
"""Render per-instance registration timelines from an analysis summary.

The timeline lists observed signaling per procedure instance with stages,
causes, and missing-evidence markers. It never renders NETWORK OK, AMF
FAILURE, or any other verdict.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from procedure_model import EXIT_MALFORMED_INPUT, EXIT_NO_EVENTS, EXIT_OUTPUT_FAILURE, InputError


def load_analysis(path: Path) -> dict[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid analysis JSON in {path.name}: {exc.msg}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("analyses"), list):
        raise InputError(f"{path.name} is not an analysis summary")
    return document


def _cause_text(event: dict[str, object]) -> str:
    cause = event.get("cause")
    if not isinstance(cause, dict):
        return "-"
    if cause.get("name") is not None:
        return f"{cause['name']}({cause.get('code')})"
    if cause.get("code") is not None:
        return f"cause={cause.get('code')}"
    if cause.get("category") is not None:
        return f"{cause.get('category')}:{cause.get('value')}" if cause.get("value") is not None else str(cause.get("category"))
    return "-"


def render_text(analysis: dict[str, object]) -> str:
    lines: list[str] = []
    for instance in analysis["analyses"]:
        context = instance.get("context", {})
        ngap_context = context.get("ngap_context", {})
        lines.append(
            f"instance={instance['instance_id']} ran={ngap_context.get('ran_ue_ngap_id')} "
            f"amf={ngap_context.get('amf_ue_ngap_id')} confidence={instance['confidence']} "
            f"terminal={instance['terminal']['observation']}"
        )
        for event in instance["events"]:
            lines.append(
                f"  [{event.get('timestamp')}] frame {event.get('frame_number')} "
                f"{event.get('protocol')} {event.get('message_type')} cause={_cause_text(event)}"
            )
        for deviation in instance["deviations"]:
            lines.append(f"  deviation: {deviation['type']} - {deviation['description']}")
        for record in instance.get("stage_records", []):
            for item in record["missing_evidence"]:
                lines.append(f"  missing evidence ({record['stage']['stage_id']}): {item}")
        for limitation in instance.get("observation_window", {}) and [] or []:
            lines.append(f"  limitation: {limitation}")
    for unbound in analysis.get("unbound_records", []):
        lines.append(f"unbound: {unbound['observed_evidence'][0]}")
    return "\n".join(lines) + "\n"


def render_json(analysis: dict[str, object]) -> str:
    timeline = []
    for instance in analysis["analyses"]:
        timeline.append({
            "instance_id": instance["instance_id"],
            "confidence": instance["confidence"],
            "terminal": instance["terminal"],
            "observation_window": instance["observation_window"],
            "events": instance["events"],
            "deviations": instance["deviations"],
            "stage_records": instance["stage_records"],
            "context": instance["context"],
        })
    return json.dumps({
        "timeline": timeline,
        "unbound_records": analysis.get("unbound_records", []),
        "correlation_conflicts": analysis.get("correlation_conflicts", []),
    }, sort_keys=True, indent=2) + "\n"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="analysis summary JSON from analyze-registration.py")
    result.add_argument("--format", choices=("text", "json"), default="text")
    result.add_argument("--output", type=Path, help="write instead of stdout; existing files are refused without --force")
    result.add_argument("--force", action="store_true", help="explicitly replace an existing output file")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        analysis = load_analysis(args.input)
        rendered = render_text(analysis) if args.format == "text" else render_json(analysis)
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
            print(f"wrote timeline for {len(analysis['analyses'])} instance(s) to {args.output.name}")
    except InputError as exc:
        message = str(exc)
        print(f"input error: {message}", file=sys.stderr)
        return EXIT_NO_EVENTS if "not an analysis summary" in message else EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
