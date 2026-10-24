#!/usr/bin/env python3
"""Correlate GTPv2-C request/response transactions from detailed event JSONL.

Correlation is protocol-local: it uses capture provenance, message family,
request/response identity, the reversed endpoint tuple, the sequence number and
whatever TEID evidence the messages themselves carry. A shared sequence number
alone never links two messages, and no session, PDN-connection or bearer
lifecycle verdict is produced.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gtpv2_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    MAX_EVIDENCE_REFERENCES,
    REQUEST_CODES,
    RESPONSE_CODES,
    InputError,
)

MATCHED = "MATCHED"
OPEN_REQUEST = "OPEN_REQUEST"
RESPONSE_ONLY = "RESPONSE_ONLY"
AMBIGUOUS = "AMBIGUOUS"

STRONG = "STRONG"
SUPPORTED = "SUPPORTED"
NONE = "NONE"


def read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputError(f"invalid JSON at line {number}: {exc.msg}") from exc
        if not isinstance(event, dict):
            raise InputError(f"event at line {number} is not an object")
        for field in ("frame_number", "timestamp", "message_type_code", "header"):
            if field not in event:
                raise InputError(f"event at line {number} lacks {field}")
        events.append(event)
    if not events:
        raise InputError("no detailed GTPv2-C events found")
    return events


def endpoint_key(event: dict[str, Any], role: str) -> str:
    endpoint = event.get(role) or {}
    return f"{endpoint.get('address')}:{endpoint.get('port')}"


def reference(event: dict[str, Any]) -> dict[str, Any]:
    header = event.get("header") or {}
    return {
        "frame_number": event.get("frame_number"),
        "message_type": event.get("message_type"),
        "message_type_code": event.get("message_type_code"),
        "sequence_number": header.get("sequence_number"),
        "header_teid": header.get("teid"),
        "header_teid_state": header.get("teid_state"),
    }


def teid_relation(request: dict[str, Any], response: dict[str, Any] | None) -> str:
    request_header = request.get("header") or {}
    request_state = request_header.get("teid_state")
    if request_state == "ZERO":
        return "initial_zero_teid_request"
    if request_state == "ABSENT":
        return "teid_absent_request"
    if response is not None:
        response_state = (response.get("header") or {}).get("teid_state")
        if request_state == "PRESENT" and response_state == "PRESENT":
            return "established_context_request"
    return "unavailable"


def teid_echo(request: dict[str, Any], response: dict[str, Any] | None) -> bool | None:
    """True when the response header TEID matches a message-scope F-TEID of the request.

    Only message-scope F-TEID evidence is used: a bearer-scope or unbound F-TEID
    cannot establish which TEID the peer would address in its response.
    """
    if response is None:
        return None
    response_teid = (response.get("header") or {}).get("teid")
    if response_teid is None:
        return None
    advertised = {
        item.get("teid")
        for item in request.get("f_teids") or []
        if isinstance(item, dict) and item.get("scope") == "message" and item.get("teid") is not None
    }
    if not advertised:
        return None
    return response_teid in advertised


def decoder_link(response: dict[str, Any] | None) -> int | None:
    if response is None:
        return None
    link = response.get("decoder_link") or {}
    value = link.get("response_to_frame")
    return value if isinstance(value, int) else None


def transaction_id(event: dict[str, Any]) -> str:
    family = event.get("procedure_family") or "unknown"
    sequence = (event.get("header") or {}).get("sequence_number")
    return f"gtpv2-{family}-{event.get('frame_number')}-{sequence}"


def correlate(events: list[dict[str, Any]]) -> dict[str, Any]:
    requests = [event for event in events if event.get("message_type_code") in REQUEST_CODES]
    responses = [event for event in events if event.get("message_type_code") in RESPONSE_CODES]

    # Requests with an identical identity inside one capture cannot be separated
    # by protocol evidence; the later copies are reported as retransmissions.
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    order: list[tuple[Any, ...]] = []
    for request in sorted(requests, key=lambda item: item["frame_number"]):
        key = (
            request.get("capture_file"),
            request.get("message_type_code"),
            (request.get("header") or {}).get("sequence_number"),
            endpoint_key(request, "source"),
            endpoint_key(request, "destination"),
        )
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(request)

    used_responses: set[int] = set()
    transactions: list[dict[str, Any]] = []
    retransmission_count = 0

    for key in order:
        group = groups[key]
        request = group[0]
        duplicates = group[1:]
        retransmission_count += len(duplicates)
        expected = REQUEST_CODES.get(request.get("message_type_code"))
        sequence = (request.get("header") or {}).get("sequence_number")
        request_pair = (endpoint_key(request, "source"), endpoint_key(request, "destination"))

        candidates: list[dict[str, Any]] = []
        for response in responses:
            if response.get("message_type_code") != expected:
                continue
            if response.get("capture_file") != request.get("capture_file"):
                continue
            if (endpoint_key(response, "source"), endpoint_key(response, "destination")) != (
                request_pair[1],
                request_pair[0],
            ):
                continue
            if (response.get("header") or {}).get("sequence_number") != sequence:
                continue
            candidates.append(response)

        basis = [
            "same capture provenance",
            "request/response message identity",
            "reversed endpoint tuple",
            "equal sequence number",
        ]

        chosen: dict[str, Any] | None = None
        status = OPEN_REQUEST
        strength = NONE
        if len(candidates) == 1:
            chosen = candidates[0]
            status = MATCHED
        elif len(candidates) > 1:
            linked = [item for item in candidates if decoder_link(item) == request.get("frame_number")]
            if len(linked) == 1:
                chosen = linked[0]
                status = MATCHED
                basis.append("decoder transaction link to the request frame")
            else:
                status = AMBIGUOUS
        # Candidate responses belong to this transaction even when the pairing
        # stays ambiguous; they are not response-only evidence.
        used_responses.update(id(item) for item in candidates)

        if chosen is not None:
            used_responses.add(id(chosen))
            echo = teid_echo(request, chosen)
            link = decoder_link(chosen)
            corroborated = echo is True or link == request.get("frame_number")
            if corroborated:
                basis.append("TEID or decoder link corroboration")
            if len(group) > 1:
                strength = SUPPORTED
                basis.append("duplicate request identity limits attribution to the earliest frame")
            elif corroborated:
                strength = STRONG
            else:
                strength = SUPPORTED

        window_frames = [request["frame_number"]]
        window_frames.extend(item["frame_number"] for item in duplicates)
        if chosen is not None:
            window_frames.append(chosen["frame_number"])

        limitations: list[str] = []
        if status == OPEN_REQUEST:
            limitations.append(
                "an unmatched request is an open transaction inside this capture, not a proven timeout"
            )
        if status == AMBIGUOUS:
            limitations.append("several responses share the correlation keys; no response is selected")
        if duplicates:
            limitations.append(
                "identical request identity inside one capture is reported as a retransmission and cannot be "
                "resolved further by protocol evidence"
            )
        if (request.get("header") or {}).get("teid_state") == "ZERO":
            limitations.append("the request carried header TEID 0; the TEID alone cannot identify the session")

        transactions.append(
            {
                "transaction_reference": transaction_id(request),
                "procedure_family": request.get("procedure_family"),
                "message_family": request.get("message_family"),
                "request": reference(request),
                "response": reference(chosen) if chosen is not None else None,
                "response_candidates": [
                    reference(item) for item in candidates[:MAX_EVIDENCE_REFERENCES]
                ],
                "correlation_status": status,
                "correlation_strength": strength,
                "correlation_basis": basis,
                "corroboration": {
                    "decoder_link_frame": decoder_link(chosen),
                    "teid_echo": teid_echo(request, chosen),
                    "teid_relation": teid_relation(request, chosen),
                },
                "retransmissions": [reference(item) for item in duplicates[:MAX_EVIDENCE_REFERENCES]],
                "observation_window": {
                    "start_frame": min(window_frames),
                    "end_frame": max(window_frames),
                },
                "evidence_refs": [reference(request)]
                + ([reference(chosen)] if chosen is not None else [])
                + [reference(item) for item in duplicates[:MAX_EVIDENCE_REFERENCES]],
                "limitations": limitations,
            }
        )

    # Responses that no request in this capture accounts for stay explicit.
    for response in sorted(responses, key=lambda item: item["frame_number"]):
        if id(response) in used_responses:
            continue
        transactions.append(
            {
                "transaction_reference": f"gtpv2-response-only-{response['frame_number']}",
                "procedure_family": response.get("procedure_family"),
                "message_family": response.get("message_family"),
                "request": None,
                "response": reference(response),
                "response_candidates": [],
                "correlation_status": RESPONSE_ONLY,
                "correlation_strength": NONE,
                "correlation_basis": ["response present without a request in this capture"],
                "corroboration": {
                    "decoder_link_frame": decoder_link(response),
                    "teid_echo": None,
                    "teid_relation": "unavailable",
                },
                "retransmissions": [],
                "observation_window": {
                    "start_frame": response["frame_number"],
                    "end_frame": response["frame_number"],
                },
                "evidence_refs": [reference(response)],
                "limitations": [
                    "the request was not captured; no transaction relationship is asserted"
                ],
            }
        )

    transactions.sort(
        key=lambda item: (
            (item["request"] or item["response"])["frame_number"],
            item["transaction_reference"],
        )
    )

    capture_files = sorted({str(event.get("capture_file")) for event in events})
    return {
        "protocol": "GTPv2-C",
        "capture_files": capture_files,
        "transaction_count": len(transactions),
        "matched_count": sum(1 for item in transactions if item["correlation_status"] == MATCHED),
        "open_request_count": sum(1 for item in transactions if item["correlation_status"] == OPEN_REQUEST),
        "response_only_count": sum(1 for item in transactions if item["correlation_status"] == RESPONSE_ONLY),
        "ambiguous_count": sum(1 for item in transactions if item["correlation_status"] == AMBIGUOUS),
        "retransmission_count": retransmission_count,
        "transactions": transactions,
        "limitations": [
            "correlation is protocol-local and never asserts session, PDN-connection or bearer success",
            "a response is only paired with a request captured in the same file",
            "sequence numbers and TEIDs are not globally unique; endpoint scoping is mandatory",
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="detailed GTPv2-C event JSONL")
    parser.add_argument("--output", type=Path, help="transaction correlation JSON destination")
    parser.add_argument("--force", action="store_true", help="explicitly replace an existing output file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = correlate(read_events(args.input))
        payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output is None:
            sys.stdout.write(payload)
            return 0
        if args.input.resolve() == args.output.resolve():
            raise OSError("output must not replace the input artifact")
        if args.output.exists() and not args.force:
            raise OSError(f"output already exists: {args.output}; use --force to replace it")
        if not args.output.parent.is_dir():
            raise OSError(f"output directory does not exist: {args.output.parent}")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                delete=False,
                dir=args.output.parent,
                prefix=f".{args.output.name}.",
                suffix=".tmp",
                newline="\n",
            ) as handle:
                temporary = handle.name
                handle.write(payload)
            os.replace(temporary, args.output)
            temporary = None
        finally:
            if temporary:
                Path(temporary).unlink(missing_ok=True)
        print(f"wrote {result['transaction_count']} transaction(s) to {args.output.name}")
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_NO_EVENTS if "no detailed GTPv2-C events" in str(exc) else EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
