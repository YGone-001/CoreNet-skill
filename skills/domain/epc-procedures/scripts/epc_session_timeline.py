#!/usr/bin/env python3
"""Render an EPC session-control timeline from an accepted analysis result."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_session_model import procedure_rows


def load(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"input error: {path.name}: {exc.msg}", file=sys.stderr)
        raise SystemExit(5)
    if not isinstance(payload, dict) or payload.get("analysis_scope") != "epc-session-control":
        print(f"input error: {path.name} is not an EPC session-control analysis", file=sys.stderr)
        raise SystemExit(5)
    return payload


def render_text(analysis: dict) -> str:
    rows = procedure_rows(analysis)
    lines = [
        "EPC session-control timeline",
        f"subjects: {analysis.get('control_plane_subject_count', 0)}",
        f"transactions: {analysis.get('input_provenance', {}).get('transaction_count', 0)}",
        "scope: protocol-control observations only; no bearer or user-plane verdict is implied",
        "",
    ]
    if not rows:
        lines.append("no session-control transaction was reconstructed")
        return "\n".join(lines) + "\n"
    for row in rows:
        cause = row.get("message_cause")
        lines.append(
            "  ".join(
                [
                    f"frame {row.get('start_frame')}-{row.get('end_frame')}",
                    str(row.get("interface")),
                    str(row.get("procedure_family")),
                    str(row.get("outcome")),
                    f"request={row.get('request_frame')}",
                    f"response={row.get('response_frame')}",
                    f"cause={cause}",
                    str(row.get("subject_reference")),
                ]
            )
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis", type=Path, help="EPC session-control analysis JSON")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    analysis = load(args.analysis)
    if args.format == "json":
        payload = {
            "analysis_scope": analysis.get("analysis_scope"),
            "control_plane_subject_count": analysis.get("control_plane_subject_count", 0),
            "procedure_rows": procedure_rows(analysis),
        }
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_text(analysis))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
