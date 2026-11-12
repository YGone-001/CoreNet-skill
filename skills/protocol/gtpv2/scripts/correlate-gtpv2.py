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

BEARER_FAMILIES = frozenset({"create-bearer", "update-bearer", "delete-bearer"})


def bearer_identity(event: dict[str, Any]) -> tuple[int, ...] | None:
    """Item-scoped EBI discriminator for dedicated-bearer request families.

    Existing families keep their previous grouping key. Dedicated-bearer requests
    that reuse a sequence number and endpoint pair for different bearer items are
    separate operations, while exact duplicate requests remain retransmissions.
    """
    if event.get("procedure_family") not in BEARER_FAMILIES:
        return None
    values: set[int] = set()
    for context in event.get("bearer_contexts") or []:
        if not isinstance(context, dict):
            continue
        ebi = context.get("ebi")
        if isinstance(ebi, int):
            values.add(ebi)
        for value in context.get("ebi_values") or []:
            if isinstance(value, int):
                values.add(value)
    metadata = event.get("unbound_ie_metadata")
    entries = metadata if isinstance(metadata, list) else [metadata]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for value in entry.get("ebi_values") or []:
            if isinstance(value, int):
                values.add(value)
    return tuple(sorted(values))


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


def observation_id(event: dict[str, Any]) -> tuple[str, int, int]:
    try:
        frame = int(event.get("frame_number"))
    except (TypeError, ValueError):
        frame = -1
    try:
        occurrence = int(event.get("message_occurrence") or 0)
    except (TypeError, ValueError):
        occurrence = 0
    return (str(event.get("capture_file")), frame, occurrence)


def reference(event: dict[str, Any]) -> dict[str, Any]:
    header = event.get("header") or {}
    payload = {
        "frame_number": event.get("frame_number"),
        "message_type": event.get("message_type"),
        "message_type_code": event.get("message_type_code"),
        "sequence_number": header.get("sequence_number"),
        "header_teid": header.get("teid"),
        "header_teid_state": header.get("teid_state"),
    }
    occurrence = int(event.get("message_occurrence") or 0)
    if occurrence:
        payload["message_occurrence"] = occurrence
    return payload


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


def unique_response_ownership(
    owners: dict[tuple[str, int, int], set[int]],
    response: dict[str, Any],
    group_index: int | None = None,
    selected_by_response: dict[tuple[str, int, int], list[int]] | None = None,
) -> bool:
    response_id = observation_id(response)
    if len(owners.get(response_id, set())) != 1:
        return False
    if selected_by_response is None:
        return True
    return len(selected_by_response.get(response_id, [])) == 1


def transaction_id(event: dict[str, Any]) -> str:
    family = event.get("procedure_family") or "unknown"
    sequence = (event.get("header") or {}).get("sequence_number")
    base = f"gtpv2-{family}-{event.get('frame_number')}-{sequence}"
    identity = bearer_identity(event)
    if identity is None:
        return base
    suffix = "-".join(str(value) for value in identity) or "none"
    return f"{base}-ebi-{suffix}"


def _eligible_candidates(
    request: dict[str, Any],
    expected: int | None,
    responses: list[dict[str, Any]],
    groups_by_link: dict[tuple[Any, ...], list[int]],
    group_index: int,
    group_frames: set[int],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    sequence = (request.get("header") or {}).get("sequence_number")
    request_pair = (endpoint_key(request, "source"), endpoint_key(request, "destination"))
    capture = request.get("capture_file")
    candidates: list[dict[str, Any]] = []
    linked: list[dict[str, Any]] = []
    ambiguous_link = False
    for response in responses:
        if response.get("message_type_code") != expected:
            continue
        if response.get("capture_file") != capture:
            continue
        if (endpoint_key(response, "source"), endpoint_key(response, "destination")) != (
            request_pair[1],
            request_pair[0],
        ):
            continue
        if (response.get("header") or {}).get("sequence_number") != sequence:
            continue
        link = decoder_link(response)
        if link is not None and link not in group_frames:
            # The decoder points at a frame outside this request group; this
            # response is not evidence for the current group.
            continue
        candidates.append(response)
        if link in group_frames:
            eligible_groups = groups_by_link.get((capture, link, expected), [])
            if len(eligible_groups) == 1 and eligible_groups[0] == group_index:
                linked.append(response)
            else:
                ambiguous_link = True
    return candidates, linked, ambiguous_link


def correlate(events: list[dict[str, Any]]) -> dict[str, Any]:
    requests = [event for event in events if event.get("message_type_code") in REQUEST_CODES]
    responses = [event for event in events if event.get("message_type_code") in RESPONSE_CODES]

    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for request in sorted(
        requests,
        key=lambda item: (
            str(item.get("capture_file")),
            item.get("frame_number"),
            item.get("message_occurrence") or 0,
            item.get("message_type_code"),
            (item.get("header") or {}).get("sequence_number") or 0,
            endpoint_key(item, "source"),
            endpoint_key(item, "destination"),
        ),
    ):
        key = (
            request.get("capture_file"),
            request.get("message_type_code"),
            (request.get("header") or {}).get("sequence_number"),
            endpoint_key(request, "source"),
            endpoint_key(request, "destination"),
            bearer_identity(request),
        )
        groups.setdefault(key, []).append(request)

    ordered_groups = [
        {"key": key, "requests": group, "request": group[0]}
        for key, group in groups.items()
    ]
    ordered_groups.sort(
        key=lambda group: (
            str(group["request"].get("capture_file")),
            group["request"].get("frame_number"),
            group["request"].get("message_occurrence") or 0,
            group["request"].get("message_type_code"),
            (group["request"].get("header") or {}).get("sequence_number") or 0,
            endpoint_key(group["request"], "source"),
            endpoint_key(group["request"], "destination"),
            bearer_identity(group["request"]) or (),
        )
    )

    groups_by_link: dict[tuple[Any, ...], list[int]] = {}
    for index, group in enumerate(ordered_groups):
        request = group["request"]
        expected = REQUEST_CODES.get(request.get("message_type_code"))
        for frame in {item.get("frame_number") for item in group["requests"]}:
            groups_by_link.setdefault(
                (request.get("capture_file"), frame, expected),
                [],
            ).append(index)

    retransmission_count = sum(len(group["requests"]) - 1 for group in ordered_groups)
    candidates_by_group: list[list[dict[str, Any]]] = []
    linked_by_group: list[list[dict[str, Any]]] = []
    ambiguous_link_by_group: list[bool] = []
    owners: dict[tuple[str, int, int], set[int]] = {}
    for index, group in enumerate(ordered_groups):
        request = group["request"]
        expected = REQUEST_CODES.get(request.get("message_type_code"))
        candidates, linked, ambiguous_link = _eligible_candidates(
            request,
            expected,
            responses,
            groups_by_link,
            index,
            {item.get("frame_number") for item in group["requests"]},
        )
        candidates_by_group.append(candidates)
        linked_by_group.append(linked)
        ambiguous_link_by_group.append(ambiguous_link)
        for candidate in candidates:
            owners.setdefault(observation_id(candidate), set()).add(index)

    selected: dict[int, dict[str, Any]] = {}
    statuses: dict[int, str] = {}
    basis_by_group: list[list[str]] = []
    for index, group in enumerate(ordered_groups):
        candidates = candidates_by_group[index]
        linked = linked_by_group[index]
        basis = [
            "same capture provenance",
            "request/response message identity",
            "reversed endpoint tuple",
            "equal sequence number",
        ]
        if not candidates:
            statuses[index] = OPEN_REQUEST
        elif len(linked) == 1:
            selected[index] = linked[0]
            statuses[index] = MATCHED
            if len(candidates) > 1:
                basis.append("decoder transaction link to the request frame")
        elif len(linked) > 1:
            statuses[index] = AMBIGUOUS
            basis.append("conflicting decoder transaction links do not select one response")
        elif (
            len(candidates) == 1
            and not ambiguous_link_by_group[index]
            and unique_response_ownership(owners, candidates[0])
        ):
            selected[index] = candidates[0]
            statuses[index] = MATCHED
        else:
            statuses[index] = AMBIGUOUS
            if ambiguous_link_by_group[index]:
                basis.append(
                    "the decoder transaction link does not uniquely identify one request occurrence"
                )
            if any(
                len(owners[observation_id(candidate)]) > 1 for candidate in candidates
            ):
                basis.append(
                    "the same response candidate is eligible for more than one request group"
                )
        basis_by_group.append(basis)

    selected_owners: dict[tuple[str, int, int], list[int]] = {}
    for index, response in selected.items():
        selected_owners.setdefault(observation_id(response), []).append(index)
    for response_id, indexes in selected_owners.items():
        response = selected.get(indexes[0])
        if response is None:
            continue
        if unique_response_ownership(owners, response, indexes[0], selected_owners):
            continue
        # Defense in depth: never publish one response as the completed response
        # of more than one transaction, even if a future rule change slips through.
        for index in indexes:
            selected.pop(index, None)
            statuses[index] = AMBIGUOUS
            basis_by_group[index].append(
                "response ownership conflict; the same observation was selected by multiple requests"
            )

    accounted: set[tuple[str, int, int]] = set()
    for candidates in candidates_by_group:
        accounted.update(observation_id(item) for item in candidates)
    accounted.update(observation_id(item) for item in selected.values())

    transactions: list[dict[str, Any]] = []
    for index, group in enumerate(ordered_groups):
        request = group["request"]
        duplicates = group["requests"][1:]
        chosen = selected.get(index)
        status = statuses[index]
        candidates = candidates_by_group[index]
        basis = basis_by_group[index]
        strength = NONE
        if chosen is not None:
            echo = teid_echo(request, chosen)
            link = decoder_link(chosen)
            group_frames = {item.get("frame_number") for item in group["requests"]}
            corroborated = echo is True or (
                link in group_frames
                and len(groups_by_link.get((request.get("capture_file"), link, REQUEST_CODES.get(request.get("message_type_code"))), [])) == 1
            )
            if corroborated:
                basis.append("TEID or decoder link corroboration")
            if len(group["requests"]) > 1:
                strength = SUPPORTED
                basis.append("duplicate request identity limits attribution to the earliest frame")
            elif corroborated:
                strength = STRONG
            else:
                strength = SUPPORTED

        window_frames = [item["frame_number"] for item in group["requests"]]
        if chosen is not None:
            window_frames.append(chosen["frame_number"])

        limitations: list[str] = []
        if status == OPEN_REQUEST:
            limitations.append(
                "an unmatched request is an open transaction inside this capture, not a proven timeout"
            )
        if status == AMBIGUOUS:
            limitations.append("several responses share the correlation keys; no response is selected")
            if any(len(owners[observation_id(candidate)]) > 1 for candidate in candidates):
                limitations.append(
                    "the same response candidate is eligible for more than one request group; response ownership is not unique"
                )
            if ambiguous_link_by_group[index] and not linked_by_group[index]:
                limitations.append(
                    "the decoder transaction link is ambiguous across multiple request occurrences; it is not used to select a response"
                )
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

    for response in sorted(
        responses,
        key=lambda item: (
            str(item.get("capture_file")),
            item.get("frame_number"),
            item.get("message_occurrence") or 0,
            item.get("message_type_code"),
        ),
    ):
        if observation_id(response) in accounted:
            continue
        occurrence = int(response.get("message_occurrence") or 0)
        reference_id = f"gtpv2-response-only-{response['frame_number']}"
        if occurrence:
            reference_id += f"-occurrence-{occurrence}"
        transactions.append(
            {
                "transaction_reference": reference_id,
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
