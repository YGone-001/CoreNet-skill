#!/usr/bin/env python3
"""Render a concise protocol-local timeline from detailed PFCP events.

The timeline shows observed message identity, transaction sequence number,
header SEID, CP/UP F-SEID, PFCP Cause, bounded rule operations, and
unambiguous TEID/QFI summaries. It never prints a PDU session, user-plane,
or network-function verdict.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pfcp_model import EXIT_MALFORMED_INPUT, EXIT_NO_EVENTS, EXIT_OUTPUT_FAILURE, InputError


def read_events(path: Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON at line {line_number}: {exc.msg}") from exc
            if not isinstance(event, dict):
                raise InputError(f"event at line {line_number} is not an object")
            if "frame_number" not in event or "timestamp" not in event:
                raise InputError(f"event at line {line_number} lacks frame and timestamp provenance")
            events.append(event)
    if not events:
        raise InputError("no detailed PFCP events found")
    return events


def _show(value: object) -> str:
    return str(value) if value not in (None, "") else "-"


def _f_seid(value: object) -> str:
    if not isinstance(value, dict):
        return "-"
    parts = []
    if value.get("seid") is not None:
        parts.append(str(value["seid"]))
    for key in ("ipv4", "ipv6"):
        if value.get(key):
            parts.append(str(value[key]))
    return "/".join(parts) if parts else "-"


def _cause(value: object) -> str:
    if not isinstance(value, dict):
        return "-"
    code = value.get("code")
    if code is None:
        return "-"
    name = value.get("name")
    return f"{name}({code})" if name else str(code)


def _rule_summary(event: dict[str, object]) -> str:
    rules = event.get("rule_operations")
    if not isinstance(rules, dict):
        return "-"
    parts = []
    for label, key in (("PDR", "pdrs"), ("FAR", "fars"), ("QER", "qers"), ("URR", "urrs")):
        items = rules.get(key)
        if not isinstance(items, list) or not items:
            continue
        rendered = []
        for item in items:
            if not isinstance(item, dict):
                continue
            operation = item.get("operation")
            rendered.append(f"{item.get('id')}{':' + str(operation) if operation else ''}")
        if rendered:
            parts.append(f"{label}[{','.join(rendered)}]")
    return " ".join(parts) if parts else "-"


def _teid_qfi_summary(event: dict[str, object]) -> str:
    rules = event.get("rule_operations")
    teids: list[int] = []
    qfis: list[int] = []
    if isinstance(rules, dict):
        for item in rules.get("pdrs", []) or []:
            if isinstance(item, dict):
                f_teid = item.get("f_teid")
                if isinstance(f_teid, dict) and f_teid.get("teid") is not None:
                    teids.append(int(f_teid["teid"]))
                if isinstance(item.get("qfi_values"), list):
                    qfis.extend(int(value) for value in item["qfi_values"])
        for item in rules.get("fars", []) or []:
            if isinstance(item, dict):
                outer = item.get("outer_header_creation")
                if isinstance(outer, dict) and outer.get("teid") is not None:
                    teids.append(int(outer["teid"]))
        for item in rules.get("qers", []) or []:
            if isinstance(item, dict) and item.get("qfi") is not None:
                qfis.append(int(item["qfi"]))
    unbound = event.get("unbound_ie_metadata")
    if isinstance(unbound, dict):
        teids.extend(int(value) for value in unbound.get("teids", []) or [])
        qfis.extend(int(value) for value in unbound.get("qfis", []) or [])
    distinct_teids = sorted(set(teids))
    distinct_qfis = sorted(set(qfis))
    teid_text = str(distinct_teids[0]) if len(distinct_teids) == 1 else ("ambiguous" if distinct_teids else "-")
    qfi_text = str(distinct_qfis[0]) if len(distinct_qfis) == 1 else ("ambiguous" if distinct_qfis else "-")
    return f"teid={teid_text} qfi={qfi_text}"


def timeline_entry(event: dict[str, object]) -> dict[str, object]:
    header = event.get("header") if isinstance(event.get("header"), dict) else {}
    session = event.get("session") if isinstance(event.get("session"), dict) else {}
    node = event.get("node") if isinstance(event.get("node"), dict) else {}
    return {
        "timestamp": event.get("timestamp"),
        "frame_number": event.get("frame_number"),
        "source": event.get("source"),
        "destination": event.get("destination"),
        "message_type": header.get("message_type"),
        "support_status": event.get("support_status"),
        "sequence_number": header.get("sequence_number"),
        "header_seid": header.get("seid"),
        "cp_f_seid": session.get("cp_f_seid"),
        "up_f_seid": session.get("up_f_seid"),
        "cause": event.get("cause"),
        "direction": event.get("direction"),
        "node_id": node.get("node_id"),
        "rule_operations": event.get("rule_operations"),
        "unbound_ie_metadata": event.get("unbound_ie_metadata"),
    }


def render_text(events: list[dict[str, object]]) -> str:
    lines = []
    for event in events:
        entry = timeline_entry(event)
        source = entry["source"] if isinstance(entry["source"], dict) else {}
        destination = entry["destination"] if isinstance(entry["destination"], dict) else {}
        label = entry["message_type"] or f"{entry['support_status']}()"
        lines.append(
            f"frame={_show(entry['frame_number'])} {entry['timestamp']} "
            f"{_show(source.get('address'))}:{_show(source.get('port'))} -> {_show(destination.get('address'))}:{_show(destination.get('port'))} "
            f"{label} seq={_show(entry['sequence_number'])} seid={_show(entry['header_seid'])} "
            f"cp={_f_seid(entry['cp_f_seid'])} up={_f_seid(entry['up_f_seid'])} "
            f"cause={_cause(entry['cause'])} rules={_rule_summary(event)} {_teid_qfi_summary(event)}"
        )
    return "\n".join(lines) + "\n"


def render_json(events: list[dict[str, object]]) -> str:
    return json.dumps({"events": [timeline_entry(event) for event in events]}, sort_keys=True, indent=2) + "\n"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="detailed PFCP event JSONL")
    result.add_argument("--format", choices=("text", "json"), default="text")
    result.add_argument("--output", type=Path, help="write instead of stdout; existing files are refused without --force")
    result.add_argument("--force", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        events = read_events(args.input)
        rendered = render_text(events) if args.format == "text" else render_json(events)
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            if args.input.resolve() == args.output.resolve():
                raise OSError("timeline output must not replace the input artifact")
            if args.output.exists() and not args.force:
                raise OSError(f"output already exists: {args.output}; use --force to replace it")
            if not args.output.parent.is_dir():
                raise OSError(f"output directory does not exist: {args.output.parent}")
            temporary_name: str | None = None
            try:
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=args.output.parent, prefix=f".{args.output.name}.", suffix=".tmp") as temporary:
                    temporary_name = temporary.name
                    temporary.write(rendered)
                os.replace(temporary_name, args.output)
                temporary_name = None
            finally:
                if temporary_name:
                    Path(temporary_name).unlink(missing_ok=True)
            print(f"wrote timeline for {len(events)} event(s) to {args.output.name}")
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_NO_EVENTS if "no detailed PFCP events" in str(exc) else EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
