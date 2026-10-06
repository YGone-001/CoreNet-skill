#!/usr/bin/env python3
"""Render a concise text investigation report from a failure-boundary analysis.

Evidence-safe wording only: "First abnormal evidence boundary observed at ..."
never "the root cause is ..."; downstream observations are never described as
caused by the selected boundary.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from failure_boundary_model import EXIT_MALFORMED_INPUT, EXIT_OUTPUT_FAILURE, InputError


def load_analysis(path: Path) -> dict[str, object]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in {path.name}: {exc.msg}") from exc
    except OSError as exc:
        raise InputError(f"cannot read analysis file {path}: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("diagnostic_groups"), list):
        raise InputError(f"{path.name} is not a valid 5gc-failure-boundary analysis summary")
    return doc


def _candidate_line(candidate: dict[str, object]) -> str:
    anchor = candidate.get("boundary_anchor", {}) if isinstance(candidate.get("boundary_anchor"), dict) else {}
    frame = anchor.get("frame_number")
    frame_text = f"frame {frame}" if frame is not None else "no exact frame provenance"
    family = candidate.get("procedure_family")
    family_text = f"{candidate.get('source_domain')} / {family}" if family else candidate.get("source_domain")
    return (
        f"[{candidate.get('deviation_type')}] {family_text} "
        f"{candidate.get('source_instance_id')} stage={candidate.get('procedure_stage')} "
        f"({frame_text}): {candidate.get('description')}"
    )


def render_text(analysis: dict[str, object]) -> str:
    lines: list[str] = []
    lines.append(f"5GC Failure Boundary Orchestration (v{analysis.get('analysis_version')})")
    lines.append("")
    for group in analysis.get("diagnostic_groups", []):
        if not isinstance(group, dict):
            continue
        lines.append("Diagnostic subject:")
        instances = group.get("source_domain_instances", []) or []
        for instance in instances:
            if isinstance(instance, dict):
                identity = ""
                for key in ("pdu_session_id", "session_generation", "reuse_status"):
                    if instance.get(key) is not None:
                        identity += f" {key}={instance.get(key)}"
                lines.append(f"  {instance.get('source_domain')} {instance.get('source_instance_id')}{identity}")
        link = group.get("subject_link", {}) if isinstance(group.get("subject_link"), dict) else {}
        lines.append(f"  subject link: {link.get('strength')} ({link.get('basis')})")
        for bridge in link.get("context_bridges", []) or []:
            if isinstance(bridge, dict):
                lines.append(
                    f"  context bridge: {bridge.get('bridge_type')} "
                    f"({bridge.get('bridge_strength')}) via {bridge.get('source_domain')} "
                    f"{bridge.get('source_instance_id')}"
                )
        lines.append("")

        status = group.get("selection_status")
        lines.append(f"Selection status: {status}")
        selected = group.get("selected_boundary")
        if isinstance(selected, dict) and isinstance(selected.get("boundary_ref"), dict):
            ref = selected["boundary_ref"]
            anchor = ref.get("boundary_anchor", {}) if isinstance(ref.get("boundary_anchor"), dict) else {}
            frame = anchor.get("frame_number")
            where = f"frame {frame} in {anchor.get('capture_file')}" if frame is not None else "a bounded observation window"
            lines.append("")
            lines.append(f"First abnormal evidence boundary observed at {where}:")
            lines.append(f"  {_candidate_line(ref)}")
            lines.append(f"  evidence level: {ref.get('evidence_level')}")
            lines.append(f"  boundary confidence: {group.get('boundary_confidence')} (selection confidence, not causal confidence)")
        elif status == "NO_ABNORMAL_BOUNDARY_OBSERVED":
            lines.append("")
            lines.append("No selectable abnormal Domain deviation was observed in the supplied evidence.")
            lines.append("This is not a statement of network, procedure, or session success.")
        elif status == "AMBIGUOUS_FIRST_BOUNDARY":
            lines.append("")
            lines.append("Two or more candidate abnormalities exist but the evidence cannot safely determine which occurred first.")
        elif status == "INSUFFICIENT_COMPARABLE_EVIDENCE":
            lines.append("")
            lines.append("Candidate abnormalities exist but their provenance cannot be safely placed in one comparable ordered diagnostic path.")

        earlier = group.get("earlier_context", []) or []
        if earlier:
            lines.append("")
            lines.append("Earlier relevant evidence:")
            for entry in earlier:
                if isinstance(entry, dict):
                    lines.append(f"  [{entry.get('relation')}] {entry.get('description') or entry.get('deviation_type')}")
        downstream = group.get("downstream_observations", []) or []
        if downstream:
            lines.append("")
            lines.append("Downstream observations:")
            for entry in downstream:
                if isinstance(entry, dict):
                    lines.append(f"  [{entry.get('relation')}] {entry.get('description') or entry.get('deviation_type')}")
            lines.append("  (downstream observations are not caused by the selected boundary)")
        limitations = group.get("evidence_limitations", []) or []
        if limitations:
            lines.append("")
            lines.append("Evidence limitations:")
            for entry in limitations:
                if isinstance(entry, dict):
                    lines.append(f"  [{entry.get('type')}] {entry.get('description')}")
        additional = group.get("additional_evidence_needed", []) or []
        if additional:
            lines.append("")
            lines.append("Additional evidence needed:")
            for entry in additional:
                if isinstance(entry, dict):
                    lines.append(f"  {entry.get('requirement')} ({entry.get('reason')})")
        not_confirmed = group.get("not_confirmed", []) or []
        if not_confirmed:
            lines.append("")
            lines.append("Not confirmed:")
            for statement in not_confirmed:
                lines.append(f"  {statement}")
        lines.append("")
        lines.append("-" * 60)
        lines.append("")
    return "\n".join(lines) + "\n"


def parser() -> argparse.ArgumentParser:
    res = argparse.ArgumentParser(description=__doc__)
    res.add_argument("input", type=Path, help="failure-boundary analysis summary JSON")
    res.add_argument("--output", type=Path, help="write report to path instead of stdout")
    res.add_argument("--force", action="store_true", help="explicitly replace existing output file")
    return res


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        doc = load_analysis(args.input)
        payload = render_text(doc)
        if args.output:
            if args.output.exists() and not args.force:
                raise OSError(f"output file already exists: {args.output}; use --force to overwrite")
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=args.output.parent,
                                             prefix=f".{args.output.name}.", suffix=".tmp") as tmp:
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
