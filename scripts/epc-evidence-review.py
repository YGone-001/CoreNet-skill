#!/usr/bin/env python3
"""Build a deterministic EPC Evidence Review Pack.

Two input modes:

  --artifacts-dir DIR   consume already-published accepted EPC artifacts
  --capture PCAP        replay the accepted unified EPC pipeline locally

Outputs manifest.json, evidence-review.json, evidence-review.md,
evidence-index.json and replay-verification.json in the requested directory.
The tool never decodes packets itself and never rewrites producer evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import epc_evidence_review as review  # noqa: E402

EXIT_OK = 0
EXIT_DIFFERENT = 1
EXIT_INPUT = 5
EXIT_REPLAY_FAILED = 6
EXIT_REPLAY_PARTIAL = 6
EXIT_OUTPUT = 7


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--artifacts-dir",
        type=Path,
        help="directory containing accepted EPC analysis artifacts",
    )
    mode.add_argument("--capture", type=Path, help="explicitly supplied local PCAP")
    mode.add_argument("--compare-a", type=Path, help="first Review Pack directory")
    parser.add_argument("--compare-b", type=Path, help="second Review Pack directory")
    parser.add_argument("--work-dir", type=Path, help="optional replay scratch directory")
    parser.add_argument("--gtpv2-events", type=Path, help="optional detailed GTPv2-C JSONL")
    parser.add_argument("--gtpu-events", type=Path, help="optional detailed GTP-U JSONL")
    parser.add_argument("--output-dir", type=Path, required=True, help="Review Pack destination")
    parser.add_argument(
        "--force",
        action="store_true",
        help="explicitly replace existing Review Pack outputs",
    )
    return parser


def _failure_pack(
    replay_verification: dict,
    *,
    message: str,
) -> dict[str, str]:
    manifest = {
        "schema_version": review.REVIEW_SCHEMA_VERSION,
        "review_name": review.REVIEW_NAME,
        "review_version": review.REVIEW_VERSION,
        "mode": "LOCAL_PCAP_REPLAY",
        "capture_identities": [],
        "source_artifacts": [],
        "detailed_gtpv2_supplied": False,
        "detailed_gtpu_supplied": False,
        "local_pcap_replayed": False,
        "replay_status": replay_verification.get("overall_status"),
        "source_completeness_status": "UNKNOWN",
        "exhaustive_coverage_proven": None,
        "source_collections_complete": False,
        "audit_ledger_metadata_valid": False,
        "audit_ledger_complete": False,
        "audit_record_count_declared": None,
        "audit_records_supplied": 0,
        "audit_records_omitted": None,
        "review_audit_records_published": 0,
        "review_audit_records_omitted": 0,
        "review_display_complete": True,
        "audit_results_truncated": True,
        "evidence_limitations": [review._text(message) or "replay failed"],
        "review_artifact_hashes": {},
    }
    index = {
        "schema_version": review.REVIEW_SCHEMA_VERSION,
        "index_name": review.REVIEW_NAME,
        "captures": [],
        "missing_references": [],
        "missing_reference_count": 0,
        "ambiguous_references": [],
        "ambiguous_reference_count": 0,
        "cross_capture_references": [],
        "cross_capture_reference_count": 0,
        "reference_counts": {},
        "bounded_limits": {},
    }
    review_document = {
        "schema_version": review.REVIEW_SCHEMA_VERSION,
        "review_name": review.REVIEW_NAME,
        "review_version": review.REVIEW_VERSION,
        "review_scope": {"mode": "LOCAL_PCAP_REPLAY", "capture_identities": []},
        "coverage": {},
        "sections": {
            "replay_failure": [
                {
                    "classification": review.CLASSIFICATION_UNSUPPORTED,
                    "status": replay_verification.get("overall_status"),
                    "detail": review._text(message),
                    "source_references": [],
                }
            ]
        },
        "section_counts": {"replay_failure": 1},
        "not_confirmed": ["a failed replay is not reported as a successful execution"],
        "non_goals": ["no evidence is invented when replay fails"],
    }
    markdown = review.render_markdown(manifest, index, review_document)
    return {
        "manifest.json": json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        "evidence-review.json": json.dumps(review_document, indent=2, sort_keys=True) + "\n",
        "evidence-review.md": markdown,
        "evidence-index.json": json.dumps(index, indent=2, sort_keys=True) + "\n",
        "replay-verification.json": json.dumps(replay_verification, indent=2, sort_keys=True) + "\n",
    }


def _main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.compare_a is not None or args.compare_b is not None:
        if args.compare_a is None or args.compare_b is None:
            print("input error: --compare-a and --compare-b are both required", file=sys.stderr)
            return EXIT_INPUT
        comparison = review.compare_runs(args.compare_a, args.compare_b)
        content = json.dumps(comparison, indent=2, sort_keys=True) + "\n"
        try:
            review.write_pack(
                args.output_dir,
                {"replay-verification.json": content},
                force=args.force,
            )
        except (review.ReviewInputError, OSError) as exc:
            print(f"output error: {getattr(exc, 'message', str(exc))}", file=sys.stderr)
            return EXIT_OUTPUT
        print(f"comparison: {comparison['overall_status']} -> {args.output_dir.name}")
        return review.comparison_exit_code(comparison["overall_status"])

    if args.capture is not None:
        replay_verification, artifacts, _detail = review.run_local_replay(
            args.capture,
            work_dir=args.work_dir,
        )
        if artifacts is None:
            files = _failure_pack(replay_verification, message="local replay did not produce usable artifacts")
            try:
                review.write_pack(args.output_dir, files, force=args.force)
            except (review.ReviewInputError, OSError) as exc:
                print(f"output error: {getattr(exc, 'message', str(exc))}", file=sys.stderr)
                return EXIT_OUTPUT
            print(
                f"replay: {replay_verification.get('overall_status')} -> {args.output_dir.name}",
                file=sys.stderr,
            )
            return EXIT_REPLAY_FAILED
        files = review.build_review_pack(
            artifacts,
            mode="LOCAL_PCAP_REPLAY",
            replay_verification=replay_verification,
        )
        try:
            review.write_pack(args.output_dir, files, force=args.force)
        except (review.ReviewInputError, OSError) as exc:
            print(f"output error: {getattr(exc, 'message', str(exc))}", file=sys.stderr)
            return EXIT_OUTPUT
        print(
            f"review pack: {replay_verification.get('overall_status')} -> {args.output_dir.name}"
        )
        return (
            EXIT_OK
            if replay_verification.get("overall_status") == review.REPLAY_COMPLETED
            else EXIT_REPLAY_PARTIAL
        )

    assert args.artifacts_dir is not None
    try:
        artifacts, files = review.existing_artifact_pack(
            args.artifacts_dir,
            gtpv2_events=args.gtpv2_events,
            gtpu_events=args.gtpu_events,
        )
        review.write_pack(
            args.output_dir,
            files,
            artifacts_dir=args.artifacts_dir,
            force=args.force,
        )
    except (review.ReviewInputError, OSError) as exc:
        code = getattr(exc, "code", "OUTPUT_ERROR")
        message = getattr(exc, "message", str(exc))
        print(f"input error: {code}: {message}", file=sys.stderr)
        return EXIT_OUTPUT if code in ("OUTPUT_EXISTS", "UNSAFE_OUTPUT_PATH", "OUTPUT_ERROR") else EXIT_INPUT
    print(f"review pack: EXISTING_ARTIFACTS -> {args.output_dir.name}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(_main())