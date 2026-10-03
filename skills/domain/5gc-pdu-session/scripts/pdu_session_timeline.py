#!/usr/bin/env python3
"""Render per-instance PDU session timelines from an analysis summary.

Renders observed signaling stages, protocol causes, deviations, and missing-evidence
markers without emitting success, failure, or root-cause verdicts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pdu_session_model import EXIT_MALFORMED_INPUT, EXIT_OUTPUT_FAILURE, InputError


def load_analysis(path: Path) -> dict[str, object]:
    try:
        content = path.read_text(encoding="utf-8")
        doc = json.loads(content)
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in {path.name}: {exc.msg}") from exc
    except OSError as exc:
        raise InputError(f"cannot read analysis file {path}: {exc}") from exc

    if not isinstance(doc, dict) or not isinstance(doc.get("instances"), list):
        raise InputError(f"{path.name} is not a valid 5gc-pdu-session analysis summary")
    return doc


def render_text(analysis: dict[str, object]) -> str:
    lines: list[str] = []
    lines.append(f"Procedure: {analysis.get('procedure_name')} (v{analysis.get('procedure_version')})")
    for inst in analysis.get("instances", []):
        ctx = inst.get("ue_context", {})
        term = inst.get("terminal_observation", {})
        lines.append(
            f"Instance: {inst.get('instance_id')} [PSI={inst.get('pdu_session_id')}, "
            f"RAN={ctx.get('ran_ue_ngap_id')}, AMF={ctx.get('amf_ue_ngap_id')}, "
            f"Assoc={inst.get('association_strength')}] -> Terminal: {term.get('observation')}"
        )
        lines.append("  Stages:")
        for stage in inst.get("stages", []):
            st_line = f"    - {stage.get('stage_id')} [{stage.get('status')}]: "
            if stage.get("observed_evidence"):
                st_line += "; ".join(stage["observed_evidence"])
            elif stage.get("missing_evidence"):
                st_line += "; ".join(stage["missing_evidence"])
            else:
                st_line += "no evidence recorded"
            lines.append(st_line)
        if inst.get("deviations"):
            lines.append("  Deviations:")
            for dev in inst["deviations"]:
                lines.append(f"    * {dev.get('type')} ({dev.get('stage_id')}): {dev.get('description')}")
        if inst.get("field_findings"):
            lines.append("  Field Findings:")
            for f in inst["field_findings"]:
                lines.append(f"    * [{f.get('plane')}] {f.get('field_name')} = {f.get('observed_value')}: {f.get('interpretation')}")

    unbound = analysis.get("unbound_evidence", {})
    if isinstance(unbound, dict):
        amb = unbound.get("ambiguous_events", [])
        if amb:
            lines.append("Ambiguous Evidence:")
            for item in amb:
                lines.append(f"  * Frame {item.get('frame_number')} {item.get('capture_file')}: {item.get('ambiguity_reason')}")

    return "\n".join(lines) + "\n"


def render_json(analysis: dict[str, object]) -> str:
    timeline_instances = []
    for inst in analysis.get("instances", []):
        timeline_instances.append({
            "instance_id": inst.get("instance_id"),
            "pdu_session_id": inst.get("pdu_session_id"),
            "ue_context": inst.get("ue_context"),
            "association_strength": inst.get("association_strength"),
            "terminal_observation": inst.get("terminal_observation"),
            "stages": inst.get("stages"),
            "deviations": inst.get("deviations"),
            "earliest_observed_deviation": inst.get("earliest_observed_deviation"),
            "plane_bindings": inst.get("plane_bindings"),
        })

    return json.dumps({
        "procedure_name": analysis.get("procedure_name"),
        "procedure_version": analysis.get("procedure_version"),
        "timeline_instances": timeline_instances,
        "unbound_evidence": analysis.get("unbound_evidence"),
    }, indent=2, sort_keys=True) + "\n"


def parser() -> argparse.ArgumentParser:
    res = argparse.ArgumentParser(description=__doc__)
    res.add_argument("input", type=Path, help="analysis summary JSON from analyze_pdu_session.py")
    res.add_argument("--format", choices=("text", "json"), default="text")
    res.add_argument("--output", type=Path, help="write output to path instead of stdout")
    res.add_argument("--force", action="store_true", help="explicitly replace existing output file")
    return res


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        doc = load_analysis(args.input)
        payload = render_json(doc) if args.format == "json" else render_text(doc)

        if args.output:
            if args.output.exists() and not args.force:
                raise OSError(f"output file already exists: {args.output}; use --force to overwrite")
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=args.output.parent, prefix=f".{args.output.name}.", suffix=".tmp") as tmp:
                tmp_name = tmp.name
                tmp.write(payload)
            os.replace(tmp_name, args.output)
        else:
            sys.stdout.write(payload)

    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"I/O error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE

    return 0


if __name__ == "__main__":
    sys.exit(main())
