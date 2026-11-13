#!/usr/bin/env python3
"""Analyze EPC dedicated-bearer control-plane outcomes.

Consumes the accepted GTPv2-C detailed events and transaction artifact, plus an
optional accepted EPC session-identity artifact. It never rebuilds correlation and
never promotes an observed control outcome into dedicated-bearer activation,
bearer lifecycle, QoS admission, TFT installation or user-plane delivery.

Exit codes:
  0  analysis document written with at least one dedicated-bearer transaction
  5  malformed or missing input
  6  analysis document written but no dedicated-bearer transaction was found
  7  output failure, including a refused overwrite or path alias
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_dedicated_bearer_control_model import (  # noqa: E402
    ANALYSIS_VERSION,
    EXIT_MALFORMED_INPUT,
    EXIT_NO_SUBJECTS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    analyze,
    build_timeline,
    read_json,
    read_jsonl,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--gtpv2", type=Path, required=True, help="detailed GTPv2-C event JSONL")
    result.add_argument(
        "--transactions",
        type=Path,
        required=True,
        help="accepted GTPv2-C transaction correlation JSON",
    )
    result.add_argument(
        "--session-identity",
        type=Path,
        help="optional accepted EPC session-identity analysis JSON",
    )
    result.add_argument("--output", type=Path, required=True, help="analysis JSON destination")
    result.add_argument(
        "--timeline-output",
        type=Path,
        help="optional dedicated-bearer control timeline JSONL destination",
    )
    result.add_argument("--force", action="store_true", help="explicitly replace existing outputs")
    return result


def _check_outputs(inputs: list[Path], outputs: list[Path], force: bool) -> None:
    input_paths = {path.resolve() for path in inputs}
    for output in outputs:
        resolved = output.resolve()
        if resolved in input_paths:
            raise OSError("an output path must not replace an input artifact")
        if output.exists() and not force:
            raise OSError(f"output already exists: {output}; use --force to replace it")
        if not output.parent.is_dir():
            raise OSError(f"output directory does not exist: {output.parent}")


def _write(path: Path, text: str) -> None:
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            newline="\n",
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(text)
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    inputs = [
        path
        for path in (args.gtpv2, args.transactions, args.session_identity)
        if path is not None
    ]
    outputs = [path for path in (args.output, args.timeline_output) if path is not None]
    try:
        _check_outputs(inputs, outputs, args.force)
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE

    try:
        events = read_jsonl(args.gtpv2)
        transaction_document = read_json(args.transactions)
        session_identity = (
            read_json(args.session_identity) if args.session_identity is not None else None
        )
        analysis = analyze(
            events,
            transaction_document,
            session_identity=session_identity,
            provenance={
                "gtpv2_events": args.gtpv2.name,
                "transaction_artifact": args.transactions.name,
                "session_identity": args.session_identity.name
                if args.session_identity is not None
                else None,
            },
        )
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except (OSError, ValueError) as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT

    try:
        _write(args.output, json.dumps(analysis, indent=2, sort_keys=True) + "\n")
        if args.timeline_output is not None:
            rows = build_timeline(analysis)
            _write(
                args.timeline_output,
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            )
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE

    print(
        f"EPC dedicated-bearer control: {analysis['control_transaction_count']} transaction(s), "
        f"{analysis['bearer_item_observation_count']} item observation(s), "
        f"{analysis['item_association_count']} association(s)"
    )
    if analysis["control_transaction_count"] == 0:
        return EXIT_NO_SUBJECTS
    return 0


if __name__ == "__main__":
    raise SystemExit(main())