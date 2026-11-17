#!/usr/bin/env python3
"""Render the bounded EPS Attach and S6a/S6d joint evidence report."""

from __future__ import annotations

from typing import Any


def _result_text(result: dict[str, Any]) -> str:
    if result.get("base_result_code") is not None:
        return f"base:{result['base_result_code']}({result.get('base_result_code_name') or 'UNNAMED'})"
    if result.get("experimental_result_code") is not None:
        return f"experimental:{result['experimental_result_code']}(vendor {result.get('experimental_vendor_id') or 'unknown'})"
    return "unresolved"


def render_report(document: dict[str, Any]) -> str:
    lines = ["EPC Attach and S6a/S6d Joint Evidence", "=" * 38]
    provenance = document["input_provenance"]
    lines.extend(
        [
            f"Attach artifact: {provenance['attach_artifact']['file']} "
            f"sha256={provenance['attach_artifact']['sha256']}",
            f"Diameter artifact: {provenance['diameter_artifact']['file']} "
            f"sha256={provenance['diameter_artifact']['sha256']}",
            f"Capture: {provenance['capture']['file'] or 'unavailable'} "
            f"sha256={provenance['capture']['sha256'] or 'unverified'}",
            f"Common capture provenance: {provenance['common_capture']['status']}",
            "",
            "EPS Attach inventory",
            "--------------------",
        ]
    )
    if not document["attach_inventory"]:
        lines.append("- no EPS Attach procedure instance observed")
    for instance in document["attach_inventory"]:
        lines.append(
            f"- {instance['procedure_reference']} attempt={instance['attempt_index']} "
            f"frames={instance['first_frame']}..{instance['last_frame']} status={instance['status']} "
            f"observed_stages={instance['observed_stage_count']} incomplete_stages={instance['incomplete_stage_count']} "
            f"deviations={instance['deviation_count']}"
        )
    if document["attach_instances_omitted"]:
        lines.append(f"- omitted Attach instances: {document['attach_instances_omitted']}")

    lines.extend(["", "Diameter S6a/S6d inventory", "--------------------------"])
    if not document["diameter_inventory"]:
        lines.append("- no S6a/S6d application observation observed")
    for observation in document["diameter_inventory"]:
        request = observation.get("request")
        answer = observation.get("answer")
        frames = []
        if request:
            frames.append(f"req {request['frame_number']}.{request['message_occurrence']}")
        if answer:
            frames.append(f"ans {answer['frame_number']}.{answer['message_occurrence']}")
        latency = observation.get("latency_seconds")
        lines.append(
            f"- {observation['procedure']} {observation['transaction_status']} "
            f"{' -> '.join(frames) or 'no frame'} result={_result_text(observation['result'])} "
            f"auth={observation['authentication_information']} "
            f"latency={latency + 's' if latency else 'not established'}"
        )
    if document["diameter_observations_omitted"]:
        lines.append(f"- omitted Diameter observations: {document['diameter_observations_omitted']}")

    lines.extend(["", "Frame-anchored timeline", "-----------------------"])
    lines.append(f"ordering: {document['timeline_ordering']} (ordering only; not causation)")
    for row in document["timeline"]:
        occurrence = "" if row["message_occurrence"] is None else f".{row['message_occurrence']}"
        lines.append(
            f"{row['frame_number']}{occurrence} {row['family']} {row['protocol']} "
            f"{row['event_type']} status={row['status']}"
        )
    if document["timeline_rows_omitted"]:
        lines.append(f"- omitted timeline rows: {document['timeline_rows_omitted']}")

    association = document["identity_association"]
    lines.extend(
        [
            "",
            "Attach/S6a identity association",
            "-------------------------------",
            f"status: {association['status']}",
            f"established pairs: {association['established_pair_count']}",
            f"ambiguous pairs: {association['ambiguous_pair_count']}",
            "basis: none",
        ]
    )
    for limitation in association["limitations"]:
        lines.append(f"- limitation: {limitation}")
    for evidence in association["required_evidence"]:
        lines.append(f"- required evidence: {evidence}")

    diagnostics = document["diagnostics"]
    lines.extend(
        [
            "",
            "Diagnostics",
            "-----------",
            f"Attach instances: {diagnostics['attach_instance_count']} "
            f"(incomplete {diagnostics['attach_incomplete_instance_count']})",
            f"Attach deviations: {diagnostics['attach_deviation_count']}",
            f"Diameter observations: {diagnostics['diameter_observation_count']} "
            f"(matched {diagnostics['diameter_matched_count']})",
            f"Reported Diameter failures: {diagnostics['diameter_failure_reported_count']}",
            f"Open/ambiguous Diameter transactions: {diagnostics['diameter_open_or_ambiguous_count']}",
            f"Earliest Attach deviation frame: {diagnostics['earliest_attach_deviation_frame']}",
            f"Earliest Diameter abnormal frame: {diagnostics['earliest_diameter_abnormal_frame']}",
            f"Cross-protocol attribution established: {diagnostics['cross_protocol_attribution_established']}",
            f"Root cause inferred: {diagnostics['root_cause_inferred']}",
        ]
    )
    lines.extend(["", "Limitations"])
    for limitation in document["limitations"]:
        lines.append(f"- {limitation}")
    lines.extend(["", "Not confirmed"])
    for item in document["not_confirmed"]:
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"