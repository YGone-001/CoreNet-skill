#!/usr/bin/env python3
"""Compose branch-scoped IMS media transport evidence from accepted artifacts."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from ims_media_session_model import (  # noqa: E402
    InputError,
    build_analysis,
    load_correlation,
    load_media_signaling,
    load_sdp,
    load_session,
    validate_analysis,
    verify_provenance,
)

EXIT_MALFORMED_INPUT = 2
EXIT_OUTPUT_FAILURE = 6


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--ims-session-analysis", type=Path, required=True)
    result.add_argument("--ims-media-signaling-analysis", type=Path, required=True)
    result.add_argument("--sdp-analysis", type=Path, required=True)
    result.add_argument("--transport-correlation", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--report", type=Path)
    result.add_argument("--force", action="store_true")
    return result


def _same(left: Path, right: Path) -> bool:
    try:
        if left.resolve() == right.resolve():
            return True
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return False


def _preflight(args: argparse.Namespace) -> None:
    inputs = [
        args.ims_session_analysis,
        args.ims_media_signaling_analysis,
        args.sdp_analysis,
        args.transport_correlation,
    ]
    outputs = [args.output] + ([args.report] if args.report else [])
    for output in outputs:
        if any(_same(output, item) for item in inputs):
            raise OSError("output destination collides with an input")
        if output.exists() and not args.force:
            raise OSError("output already exists; use --force to replace it")
        if not output.parent.is_dir():
            raise OSError("output directory does not exist")
    if args.report is not None and _same(args.output, args.report):
        raise OSError("JSON and report destinations must differ")


def _write_atomic(path: Path, payload: str) -> None:
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as handle:
            temporary = handle.name
            handle.write(payload)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary:
            Path(temporary).unlink(missing_ok=True)


def _report(document: dict) -> str:
    completeness = document["completeness"]
    lines = [
        "IMS media transport evidence",
        f"analysis_version: {document['analysis_version']}",
        f"capture: {document['input_provenance']['capture_files'][0]}",
        f"endpoint_context: {document['input_provenance'].get('endpoint_context_reference') or '-'}",
        f"attempts: {document['attempt_count']}",
        f"exchanges: {document['exchange_count']} "
        f"(established={completeness['established_exchange_count']})",
        f"transport_observations: {document['transport_observation_count']} "
        f"(attempt={completeness['attempt_bound_observation_count']}, "
        f"branch={completeness['branch_bound_observation_count']}, "
        f"ambiguous={completeness['ambiguous_observation_count']}, "
        f"unbound={completeness['unbound_observation_count']})",
        f"unbound_signaling_observations: {document['unbound_signaling_observation_count']}",
        f"unmatched_rtp_streams: {document['unmatched_rtp_stream_count']}",
    ]
    for attempt in document["attempts"]:
        lines.append(
            f"attempt: {attempt['attempt_reference']} / "
            f"{attempt['invite_outcome']} / branches={attempt['branch_count']} / "
            f"shared_offer_observations={len(attempt['shared_initial_offer_observation_references'])}"
        )
        for branch in attempt["branches"]:
            lines.append(
                f"  branch: {branch['branch_reference']} / "
                f"dialog={branch['dialog_reference'] or '-'} / "
                f"identity={branch['identity_status'] or '-'} / "
                f"state={branch['dialog_state']} / release={branch['release_outcome']} / "
                f"observations={len(branch['branch_transport_observation_references'])}"
            )
    for observation in document["transport_observations"]:
        lines.append(
            f"observation: {observation['observation_reference']} / "
            f"{observation['binding_scope']} / {observation['binding_status']} / "
            f"correlation={observation['original_association_status']} / "
            f"temporal={observation['temporal_association_status']}"
        )
        for binding in observation["sdp_message_bindings"]:
            lines.append(
                f"  sdp: {binding['message_reference']}#{binding['media_index']} / "
                f"mid={binding['mid'] or '-'} / roles={','.join(binding['roles'])}"
            )
    for stream in document["unmatched_rtp_streams"]:
        lines.append(
            f"unmatched_stream: {stream['rtp_udp_stream_reference']} / "
            f"{stream['endpoint_evidence_status']} / packets={stream['packet_count']}"
        )
    lines.append("limits:")
    lines.extend(f"- {item}" for item in document["limitations"])
    lines.append("not_confirmed:")
    lines.extend(f"- {item}" for item in document["not_confirmed"])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        _preflight(args)
        sdp = load_sdp(args.sdp_analysis)
        sdp_references = {
            message["source_reference"] for message in sdp.get("messages") or []
        }
        session = load_session(args.ims_session_analysis)
        media = load_media_signaling(
            args.ims_media_signaling_analysis, sdp_references
        )
        correlation = load_correlation(args.transport_correlation)
        provenance = verify_provenance(
            session,
            media,
            sdp,
            correlation,
            session_path=args.ims_session_analysis,
            media_path=args.ims_media_signaling_analysis,
            sdp_path=args.sdp_analysis,
            correlation_path=args.transport_correlation,
        )
        document = build_analysis(
            session, media, sdp, correlation, provenance=provenance
        )
        validate_analysis(document)
    except OSError as exc:
        print(f"analyze-ims-media-session: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    except InputError as exc:
        print(f"analyze-ims-media-session: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    _write_atomic(args.output, json.dumps(document, indent=2, sort_keys=True) + "\n")
    if args.report is not None:
        _write_atomic(args.report, _report(document))
        print(f"wrote report to {args.report}")
    print(
        f"composed {document['attempt_count']} IMS attempt(s), "
        f"{document['exchange_count']} exchange(s) and "
        f"{document['transport_observation_count']} transport observation(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())