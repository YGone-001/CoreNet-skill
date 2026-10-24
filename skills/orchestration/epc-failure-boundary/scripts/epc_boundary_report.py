#!/usr/bin/env python3
"""Render a bounded EPC failure-boundary report from an analysis summary.

Wording is evidence-safe: "first abnormal evidence boundary observed at ...",
never "the root cause is ...", and downstream observations are never described
as caused by the selected boundary.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_boundary_model import (
    ANALYSIS_NAME,
    EXIT_MALFORMED_INPUT,
    EXIT_OUTPUT_FAILURE,
    InputError,
)


def load_analysis(path: Path) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in {path.name}: {exc.msg}") from exc
    except OSError as exc:
        raise InputError(f"cannot read analysis file {path}: {exc}") from exc
    if not isinstance(document, dict) or document.get("analysis_name") != ANALYSIS_NAME:
        raise InputError(f"{path.name} is not an {ANALYSIS_NAME} analysis")
    if not isinstance(document.get("diagnostic_groups"), list):
        raise InputError(f"{path.name} carries no diagnostic_groups list")
    return document


def _boundary_line(boundary: dict) -> str:
    frame = boundary.get("frame_number")
    where = f"frame {frame}" if frame is not None else "no exact frame"
    return (
        f"[{boundary.get('deviation_type')}] {boundary.get('protocol')} "
        f"{boundary.get('message_type')} ({where})"
    )


def _candidate_line(candidate: dict) -> str:
    frame = candidate.get("frame_number")
    where = f"frame {frame}" if frame is not None else "no exact frame"
    eligibility = candidate.get("selection_eligibility")
    return (
        f"[{candidate.get('deviation_type')}] {candidate.get('protocol')} "
        f"{candidate.get('message_type')} ({where}) {eligibility}"
    )


def render_text(analysis: dict) -> str:
    lines: list[str] = []
    lines.append(f"EPC Failure Boundary Orchestration (v{analysis.get('analysis_version')})")
    lines.append("")
    groups = analysis.get("diagnostic_groups") or []
    lines.append(f"Diagnostic subjects: {len(groups)}")
    lines.append("")
    for group in groups:
        if not isinstance(group, dict):
            continue
        lines.append("Diagnostic subject:")
        lines.append(
            f"  {group.get('subject_type')} {group.get('diagnostic_group_reference')}"
        )
        for instance in group.get("source_domain_instances") or []:
            if isinstance(instance, dict):
                interface = instance.get("interface")
                suffix = f" interface={interface}" if interface else ""
                lines.append(
                    f"  source: {instance.get('source_domain')} "
                    f"{instance.get('source_instance_id')} ({instance.get('source_file')}){suffix}"
                )
        link = group.get("subject_link") or {}
        lines.append(
            f"  subject link: {link.get('strength')} ({link.get('basis')}); "
            f"cross-subject link {link.get('cross_subject_link')}"
        )
        window = group.get("observation_window") or {}
        if window:
            lines.append(f"  observation window: frames {window.get('start_frame')}-{window.get('end_frame')}")
        lines.append("")

        status = group.get("boundary_selection_status")
        lines.append(f"Selection status: {status}")
        boundary = group.get("first_abnormal_boundary")
        if isinstance(boundary, dict):
            lines.append("")
            lines.append(f"First abnormal evidence boundary observed at {_boundary_line(boundary)}:")
            lines.append(f"  evidence level: {boundary.get('evidence_level')}")
            lines.append(
                f"  boundary confidence: {group.get('boundary_confidence')} "
                "(selection confidence, not causal confidence)"
            )
            if boundary.get("cause_code") is not None:
                lines.append(
                    f"  cause: {boundary.get('cause_code')} (scope {boundary.get('cause_scope')})"
                )
            if boundary.get("bearer_item_index") is not None:
                lines.append(f"  bearer item: {boundary.get('bearer_item_index')}")
            if boundary.get("transaction_reference"):
                lines.append(f"  transaction: {boundary.get('transaction_reference')}")
            refs = boundary.get("evidence_refs") or []
            for reference in refs:
                lines.append(
                    f"  evidence: frame {reference.get('frame_number')} "
                    f"{reference.get('protocol')} {reference.get('message_type')}"
                )
        elif status == "NO_ABNORMAL_BOUNDARY_OBSERVED":
            lines.append("")
            lines.append("No selectable abnormal Domain deviation was observed in this subject.")
            lines.append("This is not a statement of procedure, session or service success.")
        elif status == "AMBIGUOUS_FIRST_BOUNDARY":
            lines.append("")
            lines.append("Two or more eligible candidates share the earliest frame and the evidence cannot select one.")
        elif status == "INSUFFICIENT_COMPARABLE_EVIDENCE":
            lines.append("")
            lines.append("The candidate universe is incomplete or not comparable, so no earliest boundary is selected.")

        candidates = group.get("boundary_candidates") or []
        if candidates:
            lines.append("")
            lines.append(f"Candidates ({len(candidates)} shown, {group.get('boundary_candidates_omitted', 0)} omitted):")
            for candidate in candidates:
                lines.append(f"  {_candidate_line(candidate)}")

        downstream = group.get("downstream_observations") or []
        if downstream:
            lines.append("")
            lines.append("Downstream observations:")
            for entry in downstream:
                lines.append(
                    f"  [{entry.get('relation')}] frame {entry.get('frame_number')} "
                    f"{entry.get('deviation_type')}"
                )
            lines.append("  (ordering is not causation; these observations are not attributed to the boundary)")

        limitations = group.get("evidence_limitations") or []
        if limitations:
            lines.append("")
            lines.append("Evidence limitations:")
            for entry in limitations:
                if isinstance(entry, dict):
                    lines.append(f"  [{entry.get('type')}] {entry.get('description')}")

        additional = group.get("additional_evidence_needed") or []
        if additional:
            lines.append("")
            lines.append("Additional evidence needed:")
            for entry in additional:
                if isinstance(entry, dict):
                    lines.append(f"  {entry.get('requirement')} ({entry.get('reason')})")

        lines.append("")
        lines.append("-" * 60)
        lines.append("")

    if analysis.get("limitations"):
        lines.append("Analysis limitations:")
        for item in analysis["limitations"]:
            lines.append(f"  {item}")
        lines.append("")
    if analysis.get("not_confirmed"):
        lines.append("Not confirmed:")
        for item in analysis["not_confirmed"]:
            lines.append(f"  {item}")
        lines.append("")
    return "\n".join(lines)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="EPC failure-boundary analysis JSON")
    result.add_argument("--output", type=Path, help="write the report to a path instead of stdout")
    result.add_argument("--force", action="store_true", help="explicitly replace an existing report")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        analysis = load_analysis(args.input)
        payload = render_text(analysis)
        if args.output is None:
            sys.stdout.write(payload)
            return 0
        if args.output.exists() and not args.force:
            raise OSError(f"output already exists: {args.output}; use --force to replace it")
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", delete=False, dir=args.output.parent,
                prefix=f".{args.output.name}.", suffix=".tmp", newline="\n",
            ) as handle:
                temporary = handle.name
                handle.write(payload)
            os.replace(temporary, args.output)
            temporary = None
        finally:
            if temporary:
                Path(temporary).unlink(missing_ok=True)
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"I/O error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
