#!/usr/bin/env python3
"""CLI driver for 5GC PDU Session procedure analysis.

Composes lower-layer evidence across N1, N2, N3, N4, and N11:
- NAS-5GS detailed events
- NGAP detailed events
- PFCP detailed events
- GTP-U detailed events
- SBI-HTTP2 detailed events
- cross-protocol-evidence correlation groups (optional)

Outputs:
- --output: bounded analysis summary JSON
- --stages-output / --stage-output: generic procedure-evidence stage JSONL
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pdu_session_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    analyze,
    load_correlation_events,
    load_gtpu_events,
    load_nas_events,
    load_ngap_events,
    load_pfcp_events,
    load_sbi_events,
)


def parser() -> argparse.ArgumentParser:
    res = argparse.ArgumentParser(description=__doc__)
    res.add_argument("--nas", type=Path, action="append", default=[], help="NAS-5GS event JSONL; repeatable")
    res.add_argument("--ngap", type=Path, action="append", default=[], help="NGAP event JSONL; repeatable")
    res.add_argument("--pfcp", type=Path, action="append", default=[], help="PFCP event JSONL; repeatable")
    res.add_argument("--gtpu", type=Path, action="append", default=[], help="GTP-U event JSONL; repeatable")
    res.add_argument("--sbi", type=Path, action="append", default=[], help="SBI-HTTP2 event JSONL; repeatable")
    res.add_argument("--correlation", type=Path, action="append", default=[], help="cross-protocol-evidence JSONL; repeatable")
    res.add_argument("--input-dir", type=Path, help="directory containing protocol event jsonl files")
    res.add_argument("--output", type=Path, required=True, help="analysis summary JSON destination")
    res.add_argument("--stages-output", "--stage-output", type=Path, dest="stages_output", help="generic procedure-evidence stage JSONL destination")
    res.add_argument("--force", action="store_true", help="explicitly replace existing output files")
    return res


def _write_atomic(path: Path, payload: str) -> None:
    if not path.parent.is_dir():
        raise OSError(f"output directory does not exist: {path.parent}")
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=path.parent, prefix=f".{path.name}.", suffix=".tmp") as tmp:
            temp_name = tmp.name
            tmp.write(payload)
        os.replace(temp_name, path)
        temp_name = None
    finally:
        if temp_name:
            Path(temp_name).unlink(missing_ok=True)


def _refuse_replacement(path: Path, force: bool) -> None:
    if path.exists() and not force:
        raise OSError(f"output already exists: {path}; use --force to replace it")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)

    nas_paths: list[Path] = list(args.nas)
    ngap_paths: list[Path] = list(args.ngap)
    pfcp_paths: list[Path] = list(args.pfcp)
    gtpu_paths: list[Path] = list(args.gtpu)
    sbi_paths: list[Path] = list(args.sbi)
    corr_paths: list[Path] = list(args.correlation)

    if args.input_dir:
        idir = args.input_dir
        if not idir.is_dir():
            print(f"input-dir does not exist: {idir}", file=sys.stderr)
            return EXIT_MALFORMED_INPUT
        for p in idir.glob("*.jsonl"):
            name = p.name.lower()
            if "nas" in name:
                nas_paths.append(p)
            elif "ngap" in name:
                ngap_paths.append(p)
            elif "pfcp" in name:
                pfcp_paths.append(p)
            elif "gtp" in name:
                gtpu_paths.append(p)
            elif "sbi" in name:
                sbi_paths.append(p)
            elif "corr" in name:
                corr_paths.append(p)

    if not any((nas_paths, ngap_paths, pfcp_paths, gtpu_paths, sbi_paths)):
        print("no input events requested; pass at least one protocol file or --input-dir", file=sys.stderr)
        return EXIT_NO_EVENTS

    try:
        _refuse_replacement(args.output, args.force)
        if args.stages_output is not None:
            _refuse_replacement(args.stages_output, args.force)
            if args.stages_output.resolve() == args.output.resolve():
                raise OSError("stage output path must differ from analysis output path")

        nas_events = []
        for p in nas_paths:
            nas_events.extend(load_nas_events(p))

        ngap_events = []
        for p in ngap_paths:
            ngap_events.extend(load_ngap_events(p))

        pfcp_events = []
        for p in pfcp_paths:
            pfcp_events.extend(load_pfcp_events(p))

        gtpu_events = []
        for p in gtpu_paths:
            gtpu_events.extend(load_gtpu_events(p))

        sbi_events = []
        for p in sbi_paths:
            sbi_events.extend(load_sbi_events(p))

        corr_groups = []
        for p in corr_paths:
            corr_groups.extend(load_correlation_events(p))

        if not any((nas_events, ngap_events, pfcp_events, gtpu_events, sbi_events)):
            raise InputError("no valid input events found across provided sources")

        summary, generic_stages = analyze(
            nas_events=nas_events,
            ngap_events=ngap_events,
            pfcp_events=pfcp_events,
            gtpu_events=gtpu_events,
            sbi_events=sbi_events,
            correlation_groups=corr_groups,
        )

        _write_atomic(args.output, json.dumps(summary, indent=2, sort_keys=True) + "\n")

        if args.stages_output is not None:
            lines = [json.dumps(stage_rec, sort_keys=True) for stage_rec in generic_stages]
            _write_atomic(args.stages_output, "\n".join(lines) + ("\n" if lines else ""))

    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"I/O error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    except Exception as exc:
        print(f"unexpected analysis failure: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE

    return 0


if __name__ == "__main__":
    sys.exit(main())
