"""Deterministic text report for the EPC release narrative analysis.

The report mirrors the published JSON document; it never adds a fact that the
JSON does not carry and never restates a stage in stronger language than the
stage's own evidence status.
"""

from __future__ import annotations

from typing import Any

MAX_LIST_ITEMS = 32


def _value(value: Any) -> str:
    return "not available" if value is None else str(value)


def _lines(text: list[str]) -> str:
    return "".join(f"  {item}\n" for item in text)


def _stage_line(stage: dict[str, Any]) -> str:
    anchor = stage.get("frame_number")
    suffix = f" frame {anchor}" if anchor is not None else " no frame anchor"
    transaction = stage.get("transaction_reference")
    if transaction:
        suffix += f" transaction {transaction}"
    return (
        f"{stage.get('stage')}: {stage.get('evidence_status')}"
        f" [{stage.get('source_analysis')}]{suffix}"
    )


def render_report(analysis: dict[str, Any]) -> str:
    out: list[str] = []
    out.append("EPC Release Narrative and Temporal Evidence")
    out.append("==========================================")
    out.append("")
    scope = analysis.get("analysis_scope") or {}
    out.append(f"capability: {scope.get('capability')}")
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
            f"{_value(entry.get('omitted_count'))} -> {entry.get('status')}"
        )
    out.append("")
    out.append(
        f"narrative subjects: {analysis.get('narrative_subject_count')} "
        f"(omitted {analysis.get('narrative_subjects_omitted')})"
    )
    for subject in (analysis.get("narrative_subjects") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {subject.get('narrative_subject_reference')} "
            f"[{_value(subject.get('interface_class'))}] "
            f"{_value(subject.get('session_context_reference'))} "
            f"{_value(subject.get('session_context_status'))}"
        )
        out.append(
            f"    group {_value(subject.get('narrative_group_reference'))} "
            f"({_value(subject.get('narrative_group_basis'))}); members "
            f"{len(subject.get('narrative_group_members') or [])}; "
            f"bearer endpoints {len(subject.get('bearer_endpoints') or [])}; "
            f"releases {len(subject.get('release_narrative_references') or [])}"
        )
    out.append("")
    out.append(
        f"release narratives: {analysis.get('release_narrative_count')} "
        f"(omitted {analysis.get('release_narratives_omitted')})"
    )
    for narrative in (analysis.get("release_narratives") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {narrative.get('release_narrative_reference')} "
            f"transaction {_value(narrative.get('release_transaction_reference'))} "
            f"frames {_value(narrative.get('release_request_frame'))}->"
            f"{_value(narrative.get('release_confirmation_frame'))}"
        )
        out.append(
            f"    outcome {_value(narrative.get('release_outcome_status'))}; "
            f"binding {_value(narrative.get('release_session_binding_status'))}; "
            f"generation closure {_value(narrative.get('generation_closure_status'))}; "
            f"effective instant proved {_value(narrative.get('release_effective_frame_proven'))}"
        )
        for stage in narrative.get("stages") or []:
            out.append(f"    {_stage_line(stage)}")
        for generation in narrative.get("proved_generations") or []:
            out.append(
                f"    proved generation {generation.get('generation_reference')} "
                f"[{_value(generation.get('receiving_endpoint_role'))} "
                f"teid {_value(generation.get('receiving_endpoint_teid'))}] "
                f"{_value(generation.get('generation_state'))}"
            )
        for limitation in narrative.get("limitations") or []:
            out.append(f"    limitation: {limitation}")
    out.append("")
    accounting = analysis.get("temporal_accounting") or {}
    out.append(
        f"temporal observations: {analysis.get('temporal_observation_count')} "
        f"(omitted {analysis.get('temporal_observations_omitted')})"
    )
    out.append(
        f"  frame-level evidence supplied: {_value(accounting.get('frame_level_evidence_supplied'))}; "
        f"observed G-PDU events {_value(accounting.get('observed_g_pdu_event_count'))}; "
        f"assigned {_value(accounting.get('assigned_to_release_window_count'))}; "
        f"unassigned {_value(accounting.get('unassigned_g_pdu_event_count'))}; "
        f"duplicate assignments {_value(accounting.get('duplicate_assignment_count'))}; "
        f"conserved {_value(accounting.get('conserved'))}"
    )
    for observation in (analysis.get("temporal_observations") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {observation.get('temporal_observation_reference')} "
            f"stream {_value(observation.get('stream_reference'))} "
            f"[{_value(observation.get('receiving_endpoint_role'))} "
            f"{_value(observation.get('direction'))}] "
            f"{_value(observation.get('temporal_placement_status'))}"
        )
        out.append(
            f"    observed {_value(observation.get('observed_g_pdu_count'))} G-PDU / "
            f"{_value(observation.get('observed_payload_octets'))} payload octets; "
            f"frames {_value(observation.get('first_observed_frame'))}-"
            f"{_value(observation.get('last_observed_frame'))}"
        )
        partitions = observation.get("partitions") or {}
        for name in ("before_release", "pending_release", "after_confirmation"):
            part = partitions.get(name)
            if not isinstance(part, dict):
                continue
            out.append(
                f"    {name}: {part.get('g_pdu_count')} G-PDU / "
                f"{part.get('payload_octets')} payload octets, frames "
                f"{_value(part.get('first_frame'))}-{_value(part.get('last_frame'))}"
            )
    out.append("")
    out.append(f"ambiguous associations: {analysis.get('ambiguous_association_count')}")
    for record in (analysis.get("ambiguous_associations") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {record.get('source_analysis')} {record.get('relationship_type')} "
            f"{record.get('association_basis')} competitors "
            f"{record.get('competing_candidates')}"
        )
    out.append("")
    out.append(f"unbound evidence: {analysis.get('unbound_evidence_count')}")
    for record in (analysis.get("unbound_evidence") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {record.get('kind')} {_value(record.get('capture_file'))} "
            f"{_value(record.get('transaction_reference'))}"
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
        "(a release narrative is not an abnormal failure boundary)"
    )
    out.append("")
    out.append("not confirmed:")
    out.append(_lines([str(item) for item in analysis.get("not_confirmed") or []]))
    return "".join(f"{line}\n" for line in out)
