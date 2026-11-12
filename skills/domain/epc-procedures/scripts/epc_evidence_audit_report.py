"""Deterministic text report for the EPC evidence-audit ledger.

The report mirrors the published JSON document. It never adds a fact that the
JSON does not carry, never strengthens an audit status and never restates a
source claim as if the audit had established it.
"""

from __future__ import annotations

from typing import Any

MAX_LIST_ITEMS = 32


def _value(value: Any) -> str:
    return "not available" if value is None else str(value)


def _lines(text: list[str]) -> str:
    return "".join(f"  {item}\n" for item in text)


def _record_line(record: dict[str, Any]) -> str:
    target = record.get("target_subject_reference")
    suffix = f" -> {target}" if target else ""
    capture = record.get("capture_file")
    capture_suffix = f" [{capture}]" if capture else ""
    return (
        f"{record.get('audit_record_reference')} {record.get('audit_category')} "
        f"{record.get('audit_status')}{capture_suffix} "
        f"{_value(record.get('source_subject_reference'))}{suffix}"
    )


def render_report(analysis: dict[str, Any]) -> str:
    out: list[str] = []
    out.append("EPC Cross-Artifact Evidence Chain Audit Ledger")
    out.append("=============================================")
    out.append("")
    scope = analysis.get("analysis_scope") or {}
    out.append(f"capability: {scope.get('capability')}")
    summary = analysis.get("audit_summary") or {}
    out.append(
        f"overall audit status: {_value(summary.get('overall_status'))} "
        f"({_value(summary.get('record_count'))} record(s))"
    )
    for status, count in (summary.get("status_counts") or {}).items():
        if not count:
            continue
        out.append(f"  {status}: {count}")
    completeness = analysis.get("source_completeness") or {}
    out.append(
        f"source completeness: {_value(completeness.get('status'))} "
        f"(exhaustive coverage proven: {_value(completeness.get('exhaustive_coverage_proven'))})"
    )
    for entry in completeness.get("collections") or []:
        out.append(
            f"  {entry.get('document')} {entry.get('collection')}: declared "
            f"{_value(entry.get('declared_count'))}, published "
            f"{_value(entry.get('published_count'))}, omitted "
            f"{_value(entry.get('omitted_count'))} "
            f"({_value(entry.get('condition'))}) -> {entry.get('status')}"
        )
    out.append("")
    out.append(f"source artifacts: {analysis.get('source_artifact_count')}")
    for artifact in (analysis.get("source_artifacts") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {artifact.get('artifact')}: supplied "
            f"{_value(artifact.get('supplied'))}, records "
            f"{_value(artifact.get('record_count'))}, completeness "
            f"{_value(artifact.get('completeness_status'))}"
        )
    out.append("")
    references = analysis.get("reference_integrity_summary") or {}
    out.append(
        f"reference integrity: {_value(references.get('references_checked'))} checked, "
        f"{_value(references.get('references_resolved'))} resolved, "
        f"{_value(references.get('references_missing'))} missing, "
        f"{_value(references.get('references_ambiguous'))} ambiguous, "
        f"{_value(references.get('references_contradictory'))} contradictory, "
        f"{_value(references.get('references_not_independently_verifiable'))} not independently "
        "verifiable"
    )
    captures = analysis.get("capture_scope_summary") or {}
    out.append(
        f"capture scope: {_value(captures.get('capture_count'))} capture(s); "
        f"cross-capture rejections {_value(captures.get('cross_capture_rejections'))}; "
        f"value collisions kept separate "
        f"{_value(captures.get('cross_capture_value_collisions'))}"
    )
    temporal = analysis.get("temporal_integrity_summary") or {}
    out.append(
        f"temporal: {_value(temporal.get('temporal_observation_count'))} observation(s), "
        f"{_value(temporal.get('established_placement_count'))} established, "
        f"{_value(temporal.get('not_established_placement_count'))} not established, "
        f"{_value(temporal.get('conflicted_partition_count'))} conflicted, frame-level evidence "
        f"{_value(temporal.get('frame_level_evidence_supplied'))}"
    )
    accounting = analysis.get("accounting_integrity_summary") or {}
    lifecycle_counts = accounting.get("producer_lifecycle") or {}
    audit_counts = accounting.get("audit_derived") or {}
    out.append(
        f"accounting (producer): {_value(lifecycle_counts.get('attributed_g_pdu_count'))} "
        f"attributed + {_value(lifecycle_counts.get('unresolved_g_pdu_count'))} unresolved = "
        f"{_value(lifecycle_counts.get('aggregate_g_pdu_count'))} G-PDU; "
        f"{_value(lifecycle_counts.get('attributed_payload_octets'))} + "
        f"{_value(lifecycle_counts.get('unresolved_payload_octets'))} = "
        f"{_value(lifecycle_counts.get('aggregate_payload_octets'))} payload octets"
    )
    out.append(
        f"accounting (audit-derived): {_value(audit_counts.get('gtpu_event_g_pdu_count'))} G-PDU, "
        f"{_value(audit_counts.get('gtpu_event_payload_octets'))} payload octets; producer counts "
        f"unchanged {_value(audit_counts.get('source_counts_unchanged'))}"
    )
    out.append("")
    out.append(
        f"audit records: {analysis.get('audit_record_count')} "
        f"(omitted {analysis.get('audit_records_omitted')})"
    )
    for record in (analysis.get("audit_records") or [])[:MAX_LIST_ITEMS]:
        out.append(f"  {_record_line(record)}")
        for check in record.get("consistency_checks") or []:
            out.append(f"    check {check.get('check')}: {check.get('result')}")
        out.append(
            f"    candidate completeness "
            f"{_value(record.get('candidate_completeness_status'))}; proof sufficiency "
            f"{_value(record.get('proof_sufficiency_status'))}"
        )
        for limitation in record.get("limitations") or []:
            out.append(f"    limitation: {limitation}")
    out.append("")
    out.append(
        f"unresolved audit findings: {analysis.get('unresolved_audit_finding_count')} "
        f"(published {len(analysis.get('unresolved_audit_findings') or [])})"
    )
    for finding in (analysis.get("unresolved_audit_findings") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {finding.get('audit_status')} {finding.get('audit_category')} "
            f"{finding.get('audit_record_reference')}"
        )
    limitations = analysis.get("evidence_limitations") or []
    if limitations:
        out.append("")
        out.append("limitations:")
        out.append(_lines([str(item) for item in limitations[:MAX_LIST_ITEMS]]))
    additional = analysis.get("additional_evidence_needed") or []
    if additional:
        out.append("additional evidence needed:")
        out.append(_lines([str(item) for item in additional[:MAX_LIST_ITEMS]]))
    out.append("")
    out.append(
        f"boundary selection: {_value(analysis.get('boundary_selection_status'))} "
        "(an audit finding is not an abnormal failure boundary)"
    )
    out.append("")
    out.append("not confirmed:")
    out.append(_lines([str(item) for item in analysis.get("not_confirmed") or []]))
    return "".join(f"{line}\n" for line in out)