#!/usr/bin/env python3
"""Non-vacuous validation of the unified EPC dedicated-bearer integration.

The validator exercises the Unified EPC projection and the optional Evidence
Review Pack artifact, then re-runs each gate against at least four semantic
mutations. A mutation must be detected; if it is not, the validator fails.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ANALYZE = load_module(ROOT / "scripts" / "corenet-analyze.py", "corenet_analyze_validator")
REVIEW = load_module(ROOT / "scripts" / "epc_evidence_review.py", "epc_review_validator")

CAPTURE = "synthetic-dedicated.pcap"
FORBIDDEN = (
    "bearer activation confirmed",
    "dedicated bearer success",
    "user_plane_ready",
    "bearer_active",
)


def render_review(artifacts: dict[str, Any], index: dict[str, Any], review: dict[str, Any]) -> str:
    manifest = REVIEW.build_manifest(
        artifacts,
        mode="EXISTING_ARTIFACTS",
        local_pcap_replayed=False,
        replay_status="NOT_REPLAYED",
    )
    return REVIEW.render_markdown(manifest, index, review)


def _reference(frame: int, code: int) -> dict[str, Any]:
    return {
        "frame_number": frame,
        "message_type": "Create Bearer Request",
        "message_type_code": code,
        "sequence_number": 1,
        "header_teid": 0,
        "header_teid_state": "PRESENT",
        "message_occurrence": 1,
    }


def _transaction(reference: str, family: str, index: int, partial: bool) -> dict[str, Any]:
    return {
        "transaction_reference": reference,
        "protocol_transaction_reference": f"gtpv2-{family}-{index}",
        "capture": CAPTURE,
        "procedure_family": family,
        "correlation_status": "MATCHED",
        "correlation_strength": "STRONG",
        "correlation_basis": ["sequence_number"],
        "request": _reference(10 + index, 95),
        "response": _reference(11 + index, 96),
        "retransmissions": [],
        "frame_anchors": {"request_frame": 10 + index, "response_frame": 11 + index},
        "message_outcome": {
            "status": (
                "MESSAGE_PARTIALLY_ACCEPTED_OBSERVED"
                if partial
                else "MESSAGE_ACCEPTED_OBSERVED"
            ),
            "cause": {
                "cause_code": 17 if partial else 16,
                "cause_name": "Request accepted",
                "scope": "message",
            },
            "source_reference": _reference(11 + index, 96),
            "limitations": [],
        },
        "transaction_outcome": (
            "CONTROL_PARTIAL_OR_MIXED" if partial else "CONTROL_ACCEPTED_OBSERVED"
        ),
        "transaction_outcome_basis": ["message and item evidence summarized"],
        "request_bearer_item_references": [f"epc-db-item:{reference}:request:{index}:0:0"],
        "response_bearer_item_references": [f"epc-db-item:{reference}:response:{index}:0:0"],
        "request_top_level_ebi_references": [],
        "source_completeness_status": "COMPLETE",
        "evidence_limitations": [],
    }


def _item(
    reference: str,
    family: str,
    index: int,
    side: str,
    outcome: str,
    partial: bool,
) -> dict[str, Any]:
    return {
        "item_reference": f"epc-db-item:{reference}:{side.lower()}:{index}:0:0",
        "capture": CAPTURE,
        "transaction_reference": reference,
        "procedure_family": family,
        "side": side,
        "frame_number": 11 + index,
        "message_occurrence": 1,
        "item_index": 0,
        "ebi": 7,
        "ebi_valid": True,
        "ebi_status": "VALID",
        "cause": {
            "cause_code": 17 if partial else 16,
            "cause_name": "Request accepted",
            "scope": "bearer",
        },
        "item_outcome": outcome,
        "f_teids": [],
        "qos": {"present": True},
        "tft": {"present": True},
        "source_completeness_status": "COMPLETE",
        "evidence_limitations": [],
    }


def dedicated_artifact() -> dict[str, Any]:
    transactions: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    associations: list[dict[str, Any]] = []
    index = 0
    for family, count in (("create-bearer", 2), ("update-bearer", 1), ("delete-bearer", 1)):
        for occurrence in range(count):
            reference = f"epc-db-tx:{CAPTURE}:{family}-{index}"
            partial = occurrence == 1
            transactions.append(_transaction(reference, family, index, partial))
            request_reference = f"epc-db-item:{reference}:request:{index}:0:0"
            response_reference = f"epc-db-item:{reference}:response:{index}:0:0"
            items.extend(
                [
                    _item(
                        reference,
                        family,
                        index,
                        "REQUEST",
                        "ITEM_REQUEST_EVIDENCE_ONLY",
                        partial,
                    ),
                    _item(
                        reference,
                        family,
                        index,
                        "RESPONSE",
                        (
                            "ITEM_CONTROL_PARTIALLY_ACCEPTED_OBSERVED"
                            if partial
                            else "ITEM_CONTROL_ACCEPTED_OBSERVED"
                        ),
                        partial,
                    ),
                ]
            )
            associations.append(
                {
                    "association_reference": f"epc-db-assoc:{reference}:{index}",
                    "capture": CAPTURE,
                    "transaction_reference": reference,
                    "request_item_reference": request_reference,
                    "response_item_reference": response_reference,
                    "request_top_level_ebi_reference": None,
                    "ebi": 7,
                    "status": "ITEM_ASSOCIATION_ESTABLISHED",
                    "basis": ["ebi"],
                    "limitations": [],
                }
            )
            index += 1
    transaction_outcomes: dict[str, int] = {}
    message_outcomes: dict[str, int] = {}
    for transaction in transactions:
        key = transaction["transaction_outcome"]
        transaction_outcomes[key] = transaction_outcomes.get(key, 0) + 1
        key = transaction["message_outcome"]["status"]
        message_outcomes[key] = message_outcomes.get(key, 0) + 1
    item_outcomes: dict[str, int] = {}
    for item in items:
        key = item["item_outcome"]
        item_outcomes[key] = item_outcomes.get(key, 0) + 1
    association_statuses: dict[str, int] = {}
    for item in associations:
        key = item["status"]
        association_statuses[key] = association_statuses.get(key, 0) + 1
    return {
        "domain": "epc-procedures",
        "analysis_name": "epc-dedicated-bearer-control",
        "analysis_version": "1.0.0",
        "input_provenance": {
            "gtpv2_events": "gtpv2-events.jsonl",
            "transaction_artifact": "gtpv2-transactions.json",
            "session_identity": "epc-session-identity-analysis.json",
            "event_count": len(transactions) * 2,
            "protocol_transaction_count": len(transactions),
            "control_transaction_input_count": len(transactions),
        },
        "analysis_scope": {
            "procedures": ["create-bearer", "update-bearer", "delete-bearer"],
            "message_types": [95, 96, 97, 98, 99, 100],
            "transaction_correlation_source": "accepted GTPv2-C transaction artifact",
            "not_inferred": ["no dedicated-bearer activation is proven"],
        },
        "source_completeness": {
            "status": "COMPLETE",
            "exhaustive_coverage_proven": False,
            "reference_complete": True,
            "missing_references": [],
            "missing_reference_count": 0,
            "limitations": ["bounded publication is not exhaustive coverage"],
        },
        "control_transactions": transactions,
        "control_transaction_count": len(transactions),
        "control_transactions_omitted": 0,
        "bearer_item_observations": items,
        "bearer_item_observation_count": len(items),
        "bearer_item_observations_omitted": 0,
        "item_associations": associations,
        "item_association_count": len(associations),
        "item_associations_omitted": 0,
        "session_identity_context": {
            "status": "NOT_ESTABLISHED",
            "artifact": "epc-session-identity-analysis.json",
            "captures": [CAPTURE],
            "associated_transaction_references": [],
            "limitations": ["no join attempted"],
        },
        "outcome_summary": {
            "transaction_classification_counts": dict(sorted(transaction_outcomes.items())),
            "message_outcome_counts": dict(sorted(message_outcomes.items())),
            "item_outcome_counts": dict(sorted(item_outcomes.items())),
            "item_association_status_counts": dict(sorted(association_statuses.items())),
        },
        "unresolved_findings": [],
        "unresolved_finding_count": 0,
        "evidence_limitations": [
            "a correlated Create/Update/Delete Bearer transaction proves an observed signaling exchange only",
        ],
        "not_confirmed": [
            "no dedicated-bearer activation, modification or effective removal is proven",
        ],
        "bounded": True,
        "limits": {
            "control_transactions": 128,
            "bearer_items": 256,
            "item_associations": 256,
            "unresolved_findings": 64,
        },
    }


def bounded_dedicated_artifact() -> dict[str, Any]:
    """129 declared / 128 published / 1 source-omitted for every collection family."""
    artifact = dedicated_artifact()
    declared = {
        "control_transactions": 129,
        "bearer_items": 257,
        "item_associations": 257,
    }
    published = {
        "control_transactions": 128,
        "bearer_items": 256,
        "item_associations": 256,
    }
    generated = {}
    for key in ("control_transactions", "bearer_item_observations", "item_associations"):
        generated[key] = list(artifact[key])
    while len(generated["control_transactions"]) < published["control_transactions"]:
        index = len(generated["control_transactions"])
        generated["control_transactions"].append(
            _transaction(
                f"epc-db-tx:{CAPTURE}:create-bearer-{index}",
                "create-bearer",
                index,
                False,
            )
        )
    while len(generated["bearer_item_observations"]) < published["bearer_items"]:
        index = len(generated["bearer_item_observations"])
        generated["bearer_item_observations"].append(
            _item(
                f"epc-db-tx:{CAPTURE}:create-bearer-{index}",
                "create-bearer",
                index,
                "RESPONSE",
                "ITEM_CONTROL_ACCEPTED_OBSERVED",
                False,
            )
        )
    while len(generated["item_associations"]) < published["item_associations"]:
        index = len(generated["item_associations"])
        generated["item_associations"].append(
            {
                "association_reference": f"epc-db-assoc:{CAPTURE}:{index}",
                "capture": CAPTURE,
                "transaction_reference": f"epc-db-tx:{CAPTURE}:create-bearer-{index}",
                "request_item_reference": None,
                "response_item_reference": None,
                "request_top_level_ebi_reference": None,
                "ebi": 0,
                "status": "ITEM_ASSOCIATION_NOT_ESTABLISHED",
                "basis": ["no item pair"],
                "limitations": ["top-level EBI is not a grouped Bearer Context item"],
            }
        )
    artifact["control_transactions"] = generated["control_transactions"]
    artifact["control_transaction_count"] = declared["control_transactions"]
    artifact["control_transactions_omitted"] = (
        declared["control_transactions"] - published["control_transactions"]
    )
    artifact["bearer_item_observations"] = generated["bearer_item_observations"]
    artifact["bearer_item_observation_count"] = declared["bearer_items"]
    artifact["bearer_item_observations_omitted"] = (
        declared["bearer_items"] - published["bearer_items"]
    )
    artifact["item_associations"] = generated["item_associations"]
    artifact["item_association_count"] = declared["item_associations"]
    artifact["item_associations_omitted"] = (
        declared["item_associations"] - published["item_associations"]
    )
    artifact["source_completeness"]["status"] = "TRUNCATED"
    artifact["source_completeness"]["reference_complete"] = False
    artifact["outcome_summary"]["transaction_classification_counts"] = {
        "CONTROL_ACCEPTED_OBSERVED": declared["control_transactions"]
    }
    artifact["outcome_summary"]["message_outcome_counts"] = {
        "MESSAGE_ACCEPTED_OBSERVED": declared["control_transactions"]
    }
    artifact["outcome_summary"]["item_outcome_counts"] = {
        "ITEM_CONTROL_ACCEPTED_OBSERVED": published["bearer_items"] // 2,
        "ITEM_REQUEST_EVIDENCE_ONLY": declared["bearer_items"] - published["bearer_items"] // 2,
    }
    artifact["outcome_summary"]["item_association_status_counts"] = {
        "ITEM_ASSOCIATION_ESTABLISHED": declared["item_associations"],
    }
    return artifact


def relevant_counts(artifact: dict[str, Any]) -> dict[str, int]:
    counts = {family: 0 for family in ANALYZE.DEDICATED_BEARER_FAMILIES}
    for transaction in artifact["control_transactions"]:
        counts[transaction["procedure_family"]] += 1
    return counts


def gate_producer_trigger(counts: dict[str, int], summary: dict[str, Any]) -> str | None:
    if ANALYZE._dedicated_bearer_requested(counts) and summary["execution_status"] != "EXECUTED":
        return "relevant dedicated-bearer transactions did not trigger a published producer result"
    return None


def gate_no_subject(counts: dict[str, int], summary: dict[str, Any], error: Any) -> str | None:
    if not ANALYZE._dedicated_bearer_requested(counts):
        if error:
            return "absence of dedicated-bearer evidence was treated as a producer failure"
        if summary["execution_status"] != ANALYZE.DEDICATED_BEARER_NOT_OBSERVED:
            return "absence of dedicated-bearer evidence did not publish NOT_OBSERVED_IN_CAPTURE"
    return None


def gate_failure_propagation(
    epc_status: str, summary: dict[str, Any], error: Any
) -> str | None:
    if error:
        if epc_status == ANALYZE.STATUS_COMPLETED:
            return "producer failure was swallowed and reported COMPLETED"
        if summary["execution_status"] != "FAILED":
            return "producer failure is not visible in the dedicated-bearer summary"
        if summary.get("failure_code") != ANALYZE.DEDICATED_BEARER_FAILURE_CODE:
            return "producer failure code is missing"
    return None


def gate_outcome_separation(artifact: dict[str, Any], summary: dict[str, Any]) -> str | None:
    message_statuses = {
        item["message_outcome"]["status"] for item in artifact["control_transactions"]
    }
    item_outcomes = {item["item_outcome"] for item in artifact["bearer_item_observations"]}
    if not item_outcomes - message_statuses:
        return "item outcomes were collapsed into message outcomes"
    if summary["message_outcome_counts"] == summary["item_outcome_counts"]:
        return "message and item outcome counts were conflated"
    if summary["item_association_status_counts"].get("ITEM_ASSOCIATION_ESTABLISHED", 0) != 4:
        return "established item-association counts were not preserved"
    return None


def gate_no_activation(summary: dict[str, Any]) -> str | None:
    serialized = json.dumps(summary, sort_keys=True).lower()
    for claim in FORBIDDEN:
        if claim in serialized:
            return f"forbidden activation verdict published: {claim}"
    return None


def gate_review_supplied() -> str | None:
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary) / "artifacts"
        source.mkdir()
        (source / "epc-session-identity-analysis.json").write_text(
            json.dumps({"analysis_name": "epc-session-identity", "analysis_version": "1.0.0"}),
            encoding="utf-8",
        )
        (source / "epc-bearer-lifecycle-analysis.json").write_text(
            json.dumps({"analysis_name": "epc-bearer-lifecycle", "analysis_version": "1.0.0"}),
            encoding="utf-8",
        )
        (source / "epc-release-narrative-analysis.json").write_text(
            json.dumps({"analysis_name": "epc-release-narrative", "analysis_version": "1.0.0"}),
            encoding="utf-8",
        )
        artifact_path = source / "epc-dedicated-bearer-control-analysis.json"
        artifact_path.write_text(json.dumps(dedicated_artifact()), encoding="utf-8")
        artifacts = REVIEW.load_artifacts(source)
        entry = [
            item
            for item in artifacts["sources"]
            if item["artifact_type"] == REVIEW.ARTIFACT_DEDICATED_BEARER
        ][0]
        if not entry["supplied"]:
            return "Review Pack did not recognize the optional dedicated-bearer artifact"
        if entry["analysis_name"] != "epc-dedicated-bearer-control":
            return "Review Pack recorded the wrong dedicated-bearer analysis name"
        if entry["sha256"] != REVIEW.sha256_file(artifact_path):
            return "Review Pack did not record the dedicated-bearer source hash"
        index = REVIEW.build_index(artifacts["documents"])
        if index["missing_references"]:
            return "Review Pack index left dedicated-bearer references unresolved"
        review = REVIEW.build_review(artifacts["documents"], index)
        summary = review["sections"]["dedicated_bearer_control_summary"][0]
        if summary["status"] != "EXECUTED":
            return "Review Pack projected the wrong dedicated-bearer status"
        if summary["control_transaction_count"] != 4:
            return "Review Pack did not publish the accepted transaction count"
        markdown = render_review(artifacts, index, review)
        if "## 9A. Dedicated Bearer Control Evidence" not in markdown:
            return "Review Pack Markdown did not render the dedicated-bearer section"
        if "do not prove end-to-end dedicated-bearer activation" not in markdown:
            return "Review Pack Markdown dropped the activation disclaimer"
        return None


def gate_review_backward_compatible() -> str | None:
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary) / "artifacts"
        source.mkdir()
        (source / "epc-session-identity-analysis.json").write_text(
            json.dumps({"analysis_name": "epc-session-identity", "analysis_version": "1.0.0"}),
            encoding="utf-8",
        )
        (source / "epc-bearer-lifecycle-analysis.json").write_text(
            json.dumps({"analysis_name": "epc-bearer-lifecycle", "analysis_version": "1.0.0"}),
            encoding="utf-8",
        )
        (source / "epc-release-narrative-analysis.json").write_text(
            json.dumps({"analysis_name": "epc-release-narrative", "analysis_version": "1.0.0"}),
            encoding="utf-8",
        )
        artifacts = REVIEW.load_artifacts(source)
        index = REVIEW.build_index(artifacts["documents"])
        review = REVIEW.build_review(artifacts["documents"], index)
        summary = review["sections"]["dedicated_bearer_control_summary"][0]
        if summary["status"] != "NOT_SUPPLIED":
            return "an older pack without the optional artifact no longer defaults to NOT_SUPPLIED"
        if summary["source_artifact"] is not None:
            return "a missing optional artifact was presented as a supplied source"
        if review["coverage"]["dedicated_source_supplied"]:
            return "missing optional artifact was reported as supplied"
        markdown = render_review(artifacts, index, review)
        if "no Dedicated Bearer Control source was supplied" not in markdown:
            return "Markdown did not state that the optional source was absent"
        return None


def gate_declared_total_preserved() -> str | None:
    summary = REVIEW._dedicated_summary(bounded_dedicated_artifact())
    expected = {
        "control_transaction_count": 129,
        "bearer_item_observation_count": 257,
        "item_association_count": 257,
    }
    for key, value in expected.items():
        if summary.get(key) != value:
            return f"Review Pack reported {summary.get(key)} instead of the Producer-declared {value} for {key}"
    expected_published = {
        "control_transactions": 128,
        "bearer_items": 256,
        "item_associations": 256,
    }
    if summary.get("producer_published_counts") != expected_published:
        return "Review Pack did not publish the Producer-published collection counts"
    if summary.get("transaction_outcome_counts") != {"CONTROL_ACCEPTED_OBSERVED": 129}:
        return "Review Pack recomputed outcome counts from the visible subset instead of the source-declared aggregate"
    return None


def gate_source_display_separation() -> str | None:
    summary = REVIEW._dedicated_summary(bounded_dedicated_artifact())
    expected_omitted = {
        "control_transactions": 1,
        "bearer_items": 1,
        "item_associations": 1,
    }
    if summary.get("producer_omitted_counts") != expected_omitted:
        return "Review Pack did not preserve the Producer source-omission metadata"
    if summary.get("omitted_counts") != expected_omitted:
        return "Review Pack omitted-count view does not reflect source omission"
    expected_display = {
        "control_transactions": 32,
        "bearer_items": 64,
        "item_associations": 64,
    }
    if summary.get("review_published_counts") != expected_display:
        return "Review Pack did not disclose its bounded display subset"
    expected_display_omitted = {
        "control_transactions": 96,
        "bearer_items": 192,
        "item_associations": 192,
    }
    if summary.get("review_display_omitted_counts") != expected_display_omitted:
        return "Review Pack conflated source omission with display omission"
    for label, declared in (
        ("control_transactions", 129),
        ("bearer_items", 257),
        ("item_associations", 257),
    ):
        if (
            summary.get("producer_declared_counts", {}).get(label)
            != summary.get("producer_published_counts", {}).get(label, 0)
            + summary.get("producer_omitted_counts", {}).get(label, 0)
        ):
            return f"declared/published/omitted accounting is inconsistent for {label}"
        if declared != (
            summary.get("producer_published_counts", {}).get(label, 0)
            + summary.get("producer_omitted_counts", {}).get(label, 0)
        ):
            return f"declared total was not preserved for {label}"
    basis = summary.get("outcome_counts_basis", {})
    if basis.get("transaction_family_counts") != "VISIBLE_SUBSET_ONLY":
        return "a visible-only breakdown was not labelled as visible-subset-only"
    if "transaction_family_counts" not in summary.get("visible_subset_only_breakdowns", []):
        return "the visible-subset-only breakdown list is incomplete"
    return None


def gate_contract_rejects_minimal() -> str | None:
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        events = base / "gtpv2-events.jsonl"
        transactions = base / "gtpv2-transactions.json"
        events.write_text("{}\n", encoding="utf-8")
        transactions.write_text('{"transactions": []}', encoding="utf-8")
        output = base / "epc-dedicated-bearer-control-analysis.json"
        minimal = {"analysis_name": "epc-dedicated-bearer-control", "control_transaction_count": 10}
        original = ANALYZE._run_component
        ANALYZE._run_component = lambda command, label: output.write_text(
            json.dumps(minimal), encoding="utf-8"
        )
        try:
            analysis, error = ANALYZE._run_dedicated_bearer_stage(events, transactions, output)
        finally:
            ANALYZE._run_component = original
        if analysis is not None or not error:
            return "a minimal name-plus-positive-count artifact was accepted as successful analysis"
        if error.get("code") != ANALYZE.DEDICATED_BEARER_FAILURE_CODE:
            return "the malformed artifact did not publish the stable component failure code"
    return None


def gate_review_rejects_invalid_optional() -> str | None:
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary) / "artifacts"
        source.mkdir()
        for name in (
            "epc-session-identity-analysis.json",
            "epc-bearer-lifecycle-analysis.json",
            "epc-release-narrative-analysis.json",
        ):
            analysis_name = name.replace("-analysis.json", "")
            (source / name).write_text(
                json.dumps({"analysis_name": analysis_name, "analysis_version": "1.0.0"}),
                encoding="utf-8",
            )
        (source / "epc-dedicated-bearer-control-analysis.json").write_text(
            json.dumps(
                {
                    "domain": "epc-procedures",
                    "analysis_name": "epc-dedicated-bearer-control",
                    "analysis_version": "1.0.0",
                    "control_transaction_count": 10,
                }
            ),
            encoding="utf-8",
        )
        try:
            REVIEW.load_artifacts(source)
        except REVIEW.ReviewInputError as exc:
            if exc.code == REVIEW.SUPPLIED_ARTIFACT_INVALID:
                return None
            return f"Review Pack rejected the invalid optional artifact with an unexpected code: {exc.code}"
        return "Review Pack accepted an invalid supplied optional Dedicated Bearer artifact"
    return None


def run_gates(
    *,
    summary: dict[str, Any],
    counts: dict[str, int],
    error: Any,
    epc_status: str,
    artifact: dict[str, Any],
    review_supplied: Callable[[], str | None] = gate_review_supplied,
    review_absent: Callable[[], str | None] = gate_review_backward_compatible,
) -> list[str]:
    errors: list[str] = []
    for check in (
        gate_producer_trigger(counts, summary),
        gate_no_subject(counts, summary, error),
        gate_failure_propagation(epc_status, summary, error),
        gate_outcome_separation(artifact, summary),
        gate_no_activation(summary),
        review_supplied(),
        review_absent(),
    ):
        if check:
            errors.append(check)
    return errors


def main() -> int:
    artifact = dedicated_artifact()
    counts = relevant_counts(artifact)
    summary = ANALYZE._project_dedicated_bearer_control(copy.deepcopy(artifact), None)
    failure_summary = ANALYZE._project_dedicated_bearer_control(
        None, {"code": ANALYZE.DEDICATED_BEARER_FAILURE_CODE, "message": "synthetic failure"}
    )

    baseline = run_gates(
        summary=summary,
        counts=counts,
        error=None,
        epc_status=ANALYZE.STATUS_COMPLETED,
        artifact=artifact,
    )
    for check in (
        gate_declared_total_preserved(),
        gate_source_display_separation(),
        gate_contract_rejects_minimal(),
        gate_review_rejects_invalid_optional(),
    ):
        if check:
            baseline.append(check)

    mutations: list[tuple[str, list[str], bool]] = []

    disabled = copy.deepcopy(summary)
    disabled["execution_status"] = ANALYZE.DEDICATED_BEARER_NOT_OBSERVED
    disabled["control_transaction_count"] = 0
    mutations.append(
        (
            "A: disable execution despite relevant transactions",
            run_gates(
                summary=disabled,
                counts=counts,
                error=None,
                epc_status=ANALYZE.STATUS_COMPLETED,
                artifact=artifact,
            ),
            bool(gate_producer_trigger(counts, disabled)),
        )
    )

    no_subject = copy.deepcopy(failure_summary)
    mutations.append(
        (
            "B: treat no subject as a component failure",
            run_gates(
                summary=no_subject,
                counts={family: 0 for family in ANALYZE.DEDICATED_BEARER_FAMILIES},
                error={"code": ANALYZE.DEDICATED_BEARER_FAILURE_CODE, "message": "none"},
                epc_status=ANALYZE.STATUS_FAILED,
                artifact=artifact,
            ),
            bool(
                gate_no_subject(
                    {family: 0 for family in ANALYZE.DEDICATED_BEARER_FAMILIES},
                    no_subject,
                    {"code": ANALYZE.DEDICATED_BEARER_FAILURE_CODE},
                )
            ),
        )
    )

    mutations.append(
        (
            "C: swallow producer failure and publish COMPLETED",
            run_gates(
                summary=failure_summary,
                counts=counts,
                error={"code": ANALYZE.DEDICATED_BEARER_FAILURE_CODE, "message": "failure"},
                epc_status=ANALYZE.STATUS_COMPLETED,
                artifact=artifact,
            ),
            bool(gate_failure_propagation(ANALYZE.STATUS_COMPLETED, failure_summary, {"code": "x"})),
        )
    )

    collapsed_artifact = copy.deepcopy(artifact)
    collapsed_message = collapsed_artifact["control_transactions"][0]["message_outcome"]["status"]
    for item in collapsed_artifact["bearer_item_observations"]:
        item["item_outcome"] = collapsed_message
    collapsed_summary = ANALYZE._project_dedicated_bearer_control(
        copy.deepcopy(collapsed_artifact), None
    )
    mutations.append(
        (
            "D: copy message outcome into every bearer item",
            run_gates(
                summary=collapsed_summary,
                counts=counts,
                error=None,
                epc_status=ANALYZE.STATUS_COMPLETED,
                artifact=collapsed_artifact,
            ),
            bool(gate_outcome_separation(collapsed_artifact, collapsed_summary)),
        )
    )

    original_summary = REVIEW._dedicated_summary

    def replace_declared_with_published(dedicated: dict[str, Any]) -> dict[str, Any]:
        result = original_summary(dedicated)
        published = result.get("producer_published_counts", {})
        result["control_transaction_count"] = published.get("control_transactions", 0)
        result["bearer_item_observation_count"] = published.get("bearer_items", 0)
        result["item_association_count"] = published.get("item_associations", 0)
        return result

    REVIEW._dedicated_summary = replace_declared_with_published
    try:
        mutation_e = gate_declared_total_preserved()
    finally:
        REVIEW._dedicated_summary = original_summary
    mutations.append(
        (
            "E: replace the declared Producer count with len(published_collection)",
            [mutation_e] if mutation_e else [],
            bool(mutation_e),
        )
    )

    def ignore_omission_metadata(dedicated: dict[str, Any]) -> dict[str, Any]:
        result = original_summary(dedicated)
        result["producer_omitted_counts"] = {}
        result["omitted_counts"] = {}
        result["review_display_omitted_counts"] = {}
        return result

    REVIEW._dedicated_summary = ignore_omission_metadata
    try:
        mutation_f = gate_source_display_separation()
    finally:
        REVIEW._dedicated_summary = original_summary
    mutations.append(
        (
            "F: ignore Producer omission metadata",
            [mutation_f] if mutation_f else [],
            bool(mutation_f),
        )
    )

    original_contract_check = ANALYZE._validate_dedicated_bearer_artifact
    ANALYZE._validate_dedicated_bearer_artifact = lambda analysis: None
    try:
        mutation_g = gate_contract_rejects_minimal()
    finally:
        ANALYZE._validate_dedicated_bearer_artifact = original_contract_check
    mutations.append(
        (
            "G: restore name-plus-positive-count-only artifact acceptance",
            [mutation_g] if mutation_g else [],
            bool(mutation_g),
        )
    )

    original_review_check = REVIEW._validate_dedicated_bearer_source
    REVIEW._validate_dedicated_bearer_source = lambda document: None
    try:
        mutation_h = gate_review_rejects_invalid_optional()
    finally:
        REVIEW._validate_dedicated_bearer_source = original_review_check
    mutations.append(
        (
            "H: bypass supplied optional Artifact validation in Review",
            [mutation_h] if mutation_h else [],
            bool(mutation_h),
        )
    )

    errors = list(baseline)
    for label, mutation_errors, detected in mutations:
        if not detected:
            errors.append(f"mutation was not detected: {label}")
        elif not mutation_errors:
            errors.append(f"mutation produced no gate failure: {label}")

    if errors:
        for error in errors:
            print(f"validate-epc-dedicated-bearer-integration: {error}", file=sys.stderr)
        return 1
    print(
        "validate-epc-dedicated-bearer-integration: OK "
        f"({len(mutations)} semantic mutations detected)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())