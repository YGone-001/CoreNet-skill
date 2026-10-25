#!/usr/bin/env python3
"""Render a bounded EPS default-bearer analysis as a procedure timeline.

Reads the analysis JSON produced by `analyze_epc_default_bearer.py`; it never
re-runs the analysis and never reads a capture.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_default_bearer_model import EXIT_MALFORMED_INPUT, EXIT_OUTPUT_FAILURE, InputError, read_json


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("analysis", type=Path, help="default-bearer analysis JSON")
    result.add_argument("--format", choices=("text", "json"), default="text", help="output format")
    return result


def rows(analysis: dict) -> list[dict]:
    """Deterministic stage rows ordered by observation window."""
    collected: list[dict] = []
    for instance in analysis.get("default_bearer_instances") or []:
        if not isinstance(instance, dict):
            continue
        for stage in instance.get("stages") or []:
            if not isinstance(stage, dict):
                continue
            collected.append(
                {
                    "instance_reference": instance.get("instance_reference"),
                    "association_strength": instance.get("association_strength"),
                    "stage_id": stage.get("stage_id"),
                    "status": stage.get("status"),
                    "conditional": stage.get("conditional"),
                    "first_frame": stage.get("first_frame"),
                    "last_frame": stage.get("last_frame"),
                    "message_count": stage.get("message_count"),
                }
            )
    collected.sort(
        key=lambda row: (
            row["first_frame"] if isinstance(row["first_frame"], int) else 1 << 30,
            str(row["instance_reference"]),
            str(row["stage_id"]),
        )
    )
    return collected


def render_text(analysis: dict) -> str:
    lines = [
        "EPS default-bearer evidence",
        f"  instances: {analysis.get('instance_count', 0)}",
        f"  ESM observations: {analysis.get('esm_observation_count', 0)}",
        f"  E-RAB observations: {analysis.get('s1_erab_observation_count', 0)}",
        f"  established links: {len(analysis.get('established_links') or [])}",
        f"  boundary selection: {analysis.get('boundary_selection_status')}",
        "",
    ]
    for instance in analysis.get("default_bearer_instances") or []:
        if not isinstance(instance, dict):
            continue
        context = instance.get("ue_context") or {}
        lines.append(
            f"{instance.get('instance_reference')} "
            f"[{instance.get('association_strength')}] "
            f"eNB={context.get('enb_ue_s1ap_id')} MME={context.get('mme_ue_s1ap_id')}"
        )
        for outcome in instance.get("outcomes") or []:
            lines.append(f"  outcome: {outcome}")
        bearer = instance.get("bearer_context") or {}
        if bearer.get("eps_bearer_identity") is not None:
            lines.append(
                f"  bearer: EBI {bearer.get('eps_bearer_identity')}, "
                f"PDN {bearer.get('pdn_type')}, "
                f"APN present={bearer.get('apn_present')} length={bearer.get('apn_length')}, "
                f"address family={bearer.get('pdn_address_family')}"
            )
        for stage in instance.get("stages") or []:
            if not isinstance(stage, dict):
                continue
            window = ""
            if stage.get("first_frame") is not None:
                window = f" frames {stage.get('first_frame')}-{stage.get('last_frame')}"
            lines.append(f"  {stage.get('stage_id')}: {stage.get('status')}{window}")
        for link in instance.get("tunnel_links") or []:
            if not isinstance(link, dict):
                continue
            lines.append(
                f"  tunnel link: {link.get('status')} "
                f"S1-U {link.get('s1u_transport_layer_address')}:{link.get('s1u_gtp_teid')}"
                + (
                    f" -> frame {link.get('target_frame')} ({link.get('target_message_type')})"
                    if link.get("target_frame") is not None
                    else ""
                )
            )
        lines.append("")
    for deviation in analysis.get("procedure_local_deviations") or []:
        if not isinstance(deviation, dict):
            continue
        lines.append(
            f"deviation: {deviation.get('deviation_type')} frame {deviation.get('frame_number')} "
            f"{deviation.get('protocol')} {deviation.get('message_type')} "
            f"cause={deviation.get('esm_cause_code')}"
        )
    for limitation in analysis.get("evidence_limitations") or []:
        lines.append(f"limitation: {limitation}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        analysis = read_json(args.analysis)
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    if args.format == "json":
        for row in rows(analysis):
            print(json.dumps(row, sort_keys=True))
    else:
        sys.stdout.write(render_text(analysis))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
