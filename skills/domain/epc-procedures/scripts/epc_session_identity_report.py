"""Deterministic text report for the EPC session-identity analysis.

The report mirrors the published JSON document; it never adds facts that the
JSON does not carry.
"""

from __future__ import annotations

from typing import Any

MAX_LIST_ITEMS = 32


def _lines(text: list[str]) -> str:
    return "".join(f"  {item}\n" for item in text)


def render_report(analysis: dict[str, Any]) -> str:
    out: list[str] = []
    out.append("EPC Session-Identity Bridge Evidence")
    out.append("===================================")
    out.append("")
    scope = analysis.get("analysis_scope") or {}
    out.append(f"capability: {scope.get('capability')}")
    out.append("")
    out.append(
        f"hop-local contexts: {analysis.get('hop_local_context_count')} "
        f"(established {analysis.get('established_hop_local_context_count')})"
    )
    for context in (analysis.get("hop_local_contexts") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {context.get('session_context_reference')} [{context.get('interface_class')}] "
            f"{context.get('association_status')} via {context.get('association_basis')}; "
            f"members {len(context.get('member_transaction_references') or [])}; "
            f"window {context.get('observation_window')}"
        )
    out.append("")
    out.append(
        f"endpoint correspondence links: {analysis.get('endpoint_correspondence_count')}"
    )
    for link in (analysis.get("endpoint_correspondence_links") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {link.get('reference')} {link.get('association_status')} "
            f"{link.get('association_basis')}"
        )
    out.append("")
    out.append(f"cross-interface session identity links: {analysis.get('session_identity_count')}")
    for link in (analysis.get("session_identity_links") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {link.get('reference')} {link.get('association_status')} "
            f"{link.get('association_basis')}; frames {link.get('source_frames')}"
        )
    out.append("")
    out.append(
        f"release-to-session bindings: {analysis.get('release_session_binding_count')}"
    )
    for binding in (analysis.get("release_session_bindings") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {binding.get('source_subject_reference')} -> "
            f"{binding.get('target_subject_reference')} {binding.get('association_status')} "
            f"(release outcome {binding.get('release_outcome_status')})"
        )
    out.append("")
    out.append(
        f"session-to-generation links: {analysis.get('session_to_generation_count')}"
    )
    for link in (analysis.get("session_to_generation_links") or [])[:MAX_LIST_ITEMS]:
        endpoint = link.get("bearer_endpoint") or {}
        generations = endpoint.get("generation_references") or []
        out.append(
            f"  {link.get('source_subject_reference')} -> {link.get('target_subject_reference')} "
            f"[{endpoint.get('role')} teid {endpoint.get('teid')}] "
            f"{link.get('association_status')}"
            + (f" generation {generations[0]}" if generations else "")
        )
    out.append("")
    out.append(
        f"generation closure candidates: {analysis.get('generation_closure_candidate_count')} "
        f"(established {analysis.get('established_closure_candidate_count')})"
    )
    for candidate in (analysis.get("generation_closure_candidates") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {candidate.get('generation_closure_candidate_reference', '(not established)')} "
            f"{candidate.get('association_status')} {candidate.get('association_basis')}"
        )
    out.append("")
    out.append(f"ambiguous associations: {analysis.get('ambiguous_association_count')}")
    for record in (analysis.get("ambiguous_associations") or [])[:MAX_LIST_ITEMS]:
        out.append(
            f"  {record.get('relationship_type')} {record.get('association_basis')} "
            f"competitors {record.get('competing_candidates')}"
        )
    out.append("")
    out.append(f"unbound evidence: {analysis.get('unbound_evidence_count')}")
    for record in (analysis.get("unbound_evidence") or [])[:MAX_LIST_ITEMS]:
        out.append(f"  {record.get('kind')} {record.get('transaction_reference', '')}")
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
    out.append("not confirmed:")
    out.append(_lines([str(item) for item in analysis.get("not_confirmed") or []]))
    return "".join(f"{line}\n" for line in out)
