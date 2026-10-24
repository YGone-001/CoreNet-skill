#!/usr/bin/env python3
"""Render a bounded EPS Attach procedure timeline from a Domain analysis JSON.

Shows procedure instances, observed stages, procedure-local deviations and their
exact frame anchors. It never adds a root cause, a bearer verdict or a global
failure boundary.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_attach_model import EXIT_MALFORMED_INPUT, EXIT_NO_INSTANCES, InputError


def read_analysis(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError(f"analysis file cannot be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"analysis file is not valid JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise InputError("analysis file is not an object")
    if "procedure_instances" not in payload:
        raise InputError("analysis file is not an EPC Attach analysis record")
    return payload


def _cause(deviation: dict) -> str:
    explanation = str(deviation.get("explanation") or "")
    return explanation


def render_text(analysis: dict) -> str:
    lines: list[str] = []
    lines.append(f"EPC Attach procedure analysis ({analysis.get('domain_version')})")
    lines.append("=" * 60)
    lines.append(f"Input S1AP events   : {analysis['input_provenance']['s1ap_events']['event_count']}")
    lines.append(f"Input NAS-EPS events: {analysis['input_provenance']['nas_eps_events']['event_count']}")
    lines.append(f"Procedure instances : {analysis.get('instance_count')}")
    lines.append(f"Global boundary     : {analysis.get('global_boundary_evaluation')}")
    for instance in analysis.get("procedure_instances") or []:
        lines.append("")
        lines.append(
            f"Instance {instance['procedure_reference']} (attempt {instance['attempt_index']}, "
            f"association {instance['association']['strength']})"
        )
        lines.append(
            f"  frames {instance.get('first_frame')}-{instance.get('last_frame')}"
        )
        for stage in instance.get("stages") or []:
            marker = "conditional" if stage.get("conditional") else "required"
            frames = (
                f"frames {stage['first_frame']}-{stage['last_frame']}"
                if stage.get("first_frame") is not None
                else "no frame"
            )
            messages = ", ".join(stage.get("messages") or []) or "-"
            lines.append(
                f"  stage {stage['stage_id']:<20} {stage['status']:<12} ({marker}, {frames}) {messages}"
            )
        for observation in instance.get("observations") or []:
            lines.append(
                f"  observed {observation['observation_type']:<36} frame {observation['frame_number']}"
            )
        for deviation in instance.get("deviations") or []:
            lines.append(
                f"  deviation {deviation['deviation_type']:<36} frame {deviation['frame_number']}"
            )
            lines.append(f"    {_cause(deviation)}")
        for limitation in instance.get("evidence_limitations") or []:
            lines.append(f"  limitation: {limitation}")
    for limitation in analysis.get("limitations") or []:
        lines.append(f"limitation: {limitation}")
    lines.append("")
    lines.append("Not confirmed:")
    for item in analysis.get("not_confirmed") or []:
        lines.append(f"  - {item}")
    return "\n".join(lines) + "\n"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("analysis", type=Path, help="EPC Attach analysis JSON")
    result.add_argument("--format", choices=("text", "json"), default="text")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        analysis = read_analysis(args.analysis)
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    if args.format == "json":
        sys.stdout.write(json.dumps(analysis, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_text(analysis))
    return 0 if analysis.get("instance_count") else EXIT_NO_INSTANCES


if __name__ == "__main__":
    raise SystemExit(main())
