#!/usr/bin/env python3
"""Analyze bounded IMS SDP Offer/Answer signaling evidence.

Consumes accepted SIP Event JSONL, IMS Session Analysis JSON and SDP Analysis
JSON. Performs no packet decoding, SIP transaction or dialog reconstruction and
no SDP body parsing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKILLS = HERE.parents[2]
for path in (
    HERE,
    SKILLS / "protocol" / "sip" / "scripts",
    SKILLS / "protocol" / "sdp-rtp" / "scripts",
    SKILLS / "domain" / "ims-session" / "scripts",
):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from ims_media_signaling_model import (  # noqa: E402
    InputError,
    build_analysis,
    load_events,
    load_sdp_analysis,
    load_session_analysis,
    validate_analysis,
    verify_provenance,
)

EXIT_INPUT = 2


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--sip-events", type=Path, required=True, help="SIP Event JSONL input")
    result.add_argument(
        "--ims-session", type=Path, required=True, help="IMS Session Analysis JSON input"
    )
    result.add_argument(
        "--sdp-analysis", type=Path, required=True, help="SDP Analysis JSON input from parse-sdp.py"
    )
    result.add_argument("--output", type=Path, required=True, help="analysis JSON destination")
    result.add_argument("--report", type=Path, help="optional text report destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing outputs")
    return result


def _same_artifact(left: Path, right: Path) -> bool:
    try:
        if left.resolve() == right.resolve():
            return True
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return False


def _preflight(args: argparse.Namespace) -> None:
    inputs = [args.sip_events, args.ims_session, args.sdp_analysis]
    outputs = [args.output]
    if args.report is not None:
        outputs.append(args.report)
    for output in outputs:
        for source in inputs:
            if _same_artifact(output, source):
                raise OSError("output destination collides with an input artifact")
    if len(outputs) == 2 and _same_artifact(outputs[0], outputs[1]):
        raise OSError("JSON output and text report destinations must be distinct")
    for output in outputs:
        if output.exists() and not args.force:
            raise OSError("output already exists; use --force to replace it")
        if not output.parent.is_dir():
            raise OSError("output directory does not exist")


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
    provenance = document["input_provenance"]
    completeness = document["completeness"]
    lines = [
        "IMS SDP offer/answer signaling evidence",
        f"analysis_version: {document['analysis_version']}",
        f"capture: {provenance['capture_files'][0]}",
        f"sdp_capture_sha256: {provenance['sdp_capture_sha256']}",
        f"supplied_sdp_messages: {completeness['supplied_sdp_message_count']}",
        f"matched_sip_events: {completeness['matched_sip_event_count']}",
        f"unmatched_sdp_messages: {completeness['unmatched_sdp_message_count']}",
        f"observed_offers: {completeness['observed_offer_count']}",
        f"observed_answers: {completeness['observed_answer_count']}",
        f"established_exchanges: {completeness['established_exchange_count']}",
        f"incomplete_exchanges: {completeness['incomplete_exchange_count']}",
        f"ambiguous_exchanges: {completeness['ambiguous_exchange_count']}",
        f"out_of_scope_observations: {completeness['out_of_scope_observation_count']}",
        f"omitted_observations: {completeness['omitted_observation_count']}",
    ]
    for exchange in document["exchanges"]:
        lines.append(
            "exchange: "
            f"{exchange['exchange_reference']} / "
            f"{exchange['exchange_type']} / "
            f"{exchange['association_status']} / "
            f"initial_sdp={exchange['initial_sdp_state']} / "
            f"branch_identity={exchange['branch_identity_status'] or '-'} / "
            f"branch={exchange['branch_reference'] or '-'} / "
            f"offer={exchange['offer_sdp_reference'] or '-'} / "
            f"answer={exchange['answer_sdp_reference'] or '-'} / "
            f"negotiation={exchange['negotiation_compatibility']}"
        )
    for observation in document["unbound_observations"]:
        lines.append(
            "unbound: "
            f"{observation['observation_reference']} / "
            f"{observation['observation_type']} / "
            f"{observation['association_status']} / "
            f"{observation['reason_code']}"
        )
    lines.append("not_confirmed:")
    lines.extend(f"- {item}" for item in document["not_confirmed"])
    lines.append("limitations:")
    lines.extend(f"- {item}" for item in document["limitations"])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        _preflight(args)
        events = load_events(args.sip_events)
        event_references = {event["source_reference"] for event in events}
        session = load_session_analysis(args.ims_session, event_references)
        sdp = load_sdp_analysis(args.sdp_analysis)
        provenance = verify_provenance(
            events,
            session,
            sdp,
            events_path=args.sip_events,
            session_path=args.ims_session,
            sdp_path=args.sdp_analysis,
        )
        document = build_analysis(events, session, sdp, provenance=provenance)
        validate_analysis(
            document,
            event_references=event_references,
            sdp_references={message["source_reference"] for message in sdp["messages"]},
        )
    except InputError as exc:
        print(f"analyze-ims-media-signaling: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except OSError:
        print("analyze-ims-media-signaling: an input or output path is unavailable", file=sys.stderr)
        return EXIT_INPUT

    payload = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    try:
        _write_atomic(args.output, payload)
        if args.report is not None:
            _write_atomic(args.report, _report(document))
    except OSError:
        print("analyze-ims-media-signaling: an output artifact could not be written", file=sys.stderr)
        return EXIT_INPUT
    if args.report is not None:
        print(f"wrote report to {args.report.name}")
    print(
        f"analyzed {len(events)} SIP event(s), "
        f"{len(sdp['messages'])} SDP message(s), "
        f"{len(session['session_attempts'])} session attempt(s), "
        f"{len(document['exchanges'])} exchange(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())