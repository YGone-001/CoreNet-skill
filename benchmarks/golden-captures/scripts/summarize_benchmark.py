#!/usr/bin/env python3
"""Aggregate differential results into a structured benchmark summary.

Calculates metrics, match rates, coverage gap counts, frame deltas, and adjudication
flags across all committed or executed golden capture cases.
"""

from __future__ import annotations

import argparse
import datetime
import json
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_DIR = ROOT / "benchmarks" / "golden-captures"


def calculate_metrics(cases_diffs: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    case_count = len(cases_diffs)
    executed_case_count = 0
    blocked_case_count = 0

    exact_match_count = 0
    procedure_match_count = 0
    stage_match_count = 0

    false_positive_count = 0
    false_negative_count = 0
    unsafe_correlation_count = 0

    protocol_coverage_gap_count = 0
    correlation_gap_count = 0
    domain_model_gap_count = 0
    orchestration_gap_count = 0

    capture_limitation_count = 0
    out_of_scope_count = 0
    human_baseline_unsupported_count = 0
    needs_adjudication_count = 0

    exact_frame_match_count = 0
    within_1_frame_count = 0
    within_3_frames_count = 0
    frame_deltas: list[int] = []

    case_summaries: list[dict[str, Any]] = []

    for diff in cases_diffs:
        case_id = diff["case_id"]
        status = diff.get("comparison_status", "UNKNOWN")
        layer = diff.get("layer_attribution", "UNKNOWN")
        adjudication = bool(diff.get("adjudication_required", False))
        baseline_supp = bool(diff.get("baseline_supported", True))
        action = diff.get("recommended_next_action", "NO_CHANGE")

        h_boundary = diff.get("human_boundary") or {}
        s_boundary = diff.get("skill_boundary") or {}

        h_status = h_boundary.get("analysis_status")
        s_status = s_boundary.get("selection_status")
        h_frame = h_boundary.get("frame_number")
        s_frame = s_boundary.get("boundary_frame")
        delta = diff.get("frame_delta")

        if delta is not None:
            frame_deltas.append(delta)
            if delta == 0:
                exact_frame_match_count += 1
            if delta <= 1:
                within_1_frame_count += 1
            if delta <= 3:
                within_3_frames_count += 1

        executed_case_count += 1

        if status == "EXACT_MATCH":
            exact_match_count += 1
            procedure_match_count += 1
            stage_match_count += 1
        elif status == "BOUNDARY_FRAME_DIFFERENCE":
            procedure_match_count += 1
            stage_match_count += 1
        elif status == "PROCEDURE_MATCH_STAGE_DIFFERENCE":
            procedure_match_count += 1
        elif status == "FALSE_POSITIVE":
            false_positive_count += 1
        elif status == "FALSE_NEGATIVE":
            false_negative_count += 1
        elif status == "UNSAFE_CORRELATION":
            unsafe_correlation_count += 1
        elif status == "PROTOCOL_COVERAGE_GAP":
            protocol_coverage_gap_count += 1
        elif status == "CORRELATION_GAP":
            correlation_gap_count += 1
        elif status == "DOMAIN_MODEL_GAP":
            domain_model_gap_count += 1
        elif status == "ORCHESTRATION_GAP":
            orchestration_gap_count += 1
        elif status == "CAPTURE_LIMITATION":
            capture_limitation_count += 1
        elif status == "OUT_OF_SCOPE":
            out_of_scope_count += 1
        elif status == "HUMAN_BASELINE_UNSUPPORTED":
            human_baseline_unsupported_count += 1

        if adjudication or status == "NEEDS_ADJUDICATION":
            needs_adjudication_count += 1

        case_summaries.append({
            "case_id": case_id,
            "comparison_status": status,
            "layer_attribution": layer,
            "human_status": h_status,
            "skill_status": s_status,
            "human_boundary_frame": h_frame,
            "skill_boundary_frame": s_frame,
            "frame_delta": delta,
            "baseline_supported": baseline_supp,
            "adjudication_required": adjudication,
            "recommended_next_action": action,
        })

    # Denominator rule: exclude OUT_OF_SCOPE, CAPTURE_LIMITATION, and HUMAN_BASELINE_UNSUPPORTED
    denom = executed_case_count - (out_of_scope_count + capture_limitation_count + human_baseline_unsupported_count)
    exact_match_rate = round(exact_match_count / denom, 4) if denom > 0 else None
    procedure_match_rate = round(procedure_match_count / denom, 4) if denom > 0 else None
    stage_match_rate = round(stage_match_count / denom, 4) if denom > 0 else None
    median_delta = statistics.median(frame_deltas) if frame_deltas else None

    metrics = {
        "case_count": case_count,
        "executed_case_count": executed_case_count,
        "blocked_case_count": blocked_case_count,
        "exact_match_count": exact_match_count,
        "procedure_match_count": procedure_match_count,
        "stage_match_count": stage_match_count,
        "false_positive_count": false_positive_count,
        "false_negative_count": false_negative_count,
        "unsafe_correlation_count": unsafe_correlation_count,
        "protocol_coverage_gap_count": protocol_coverage_gap_count,
        "correlation_gap_count": correlation_gap_count,
        "domain_model_gap_count": domain_model_gap_count,
        "orchestration_gap_count": orchestration_gap_count,
        "capture_limitation_count": capture_limitation_count,
        "out_of_scope_count": out_of_scope_count,
        "human_baseline_unsupported_count": human_baseline_unsupported_count,
        "needs_adjudication_count": needs_adjudication_count,
        "exact_match_rate": exact_match_rate,
        "procedure_match_rate": procedure_match_rate,
        "stage_match_rate": stage_match_rate,
        "denominator_definition": "evaluated_in_scope = executed_case_count - (out_of_scope_count + capture_limitation_count + human_baseline_unsupported_count)",
        "exact_frame_match_count": exact_frame_match_count,
        "within_1_frame_count": within_1_frame_count,
        "within_3_frames_count": within_3_frames_count,
        "median_absolute_frame_delta": float(median_delta) if median_delta is not None else None,
    }

    return metrics, case_summaries


def generate_benchmark_summary(
    cases_dir: Path,
    output_path: Path,
    corenet_commit: str,
    external_source_commit: str,
    tshark_version: str,
    skill_versions: dict[str, str],
) -> dict[str, Any]:
    diffs = []
    # Deterministic alphabetical ordering by case directory name
    for case_folder in sorted(cases_dir.iterdir()):
        if case_folder.is_dir():
            diff_file = case_folder / "differential.json"
            if diff_file.is_file():
                diffs.append(json.loads(diff_file.read_text(encoding="utf-8")))

    metrics, case_summaries = calculate_metrics(diffs)

    summary: dict[str, Any] = {
        "benchmark_id": "public-5gc-golden-captures",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "corenet_commit": corenet_commit,
        "external_source_commit": external_source_commit,
        "tshark_version": tshark_version,
        "python_version": sys.version.split()[0],
        "skill_versions": skill_versions,
        "metrics": metrics,
        "cases": case_summaries,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases-dir", type=Path, default=BENCHMARK_DIR / "cases", help="Directory containing case subdirectories")
    parser.add_argument("--output", type=Path, default=BENCHMARK_DIR / "benchmark-summary.json", help="Destination path for benchmark-summary.json")
    parser.add_argument("--corenet-commit", type=str, default="unknown", help="Current CoreNet commit SHA")
    parser.add_argument("--source-commit", type=str, default="unknown", help="External public source commit SHA")
    parser.add_argument("--tshark-version", type=str, default="unknown", help="TShark version string")
    args = parser.parse_args(argv)

    generate_benchmark_summary(
        args.cases_dir,
        args.output,
        args.corenet_commit,
        args.source_commit,
        args.tshark_version,
        {},
    )
    print(f"Benchmark summary generated at {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
