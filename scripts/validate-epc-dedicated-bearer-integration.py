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


def dedicated_artifact() -> dict[str, Any]:
    transactions: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []
    associations: list[dict[str, Any]] = []
    index = 0
    for family, count in (("create-bearer", 2), ("update-bearer", 1), ("delete-bearer", 1)):
        for occurrence in range(count):
            reference = f"epc-db-tx:{CAPTURE}:{family}-{index}"
            partial = occurrence == 1
            transactions.append(
                {
                    "capture": CAPTURE,
                    "correlation_status": "MATCHED",
                    "correlation_strength": "STRONG",
                    "procedure_family": family,
                    "transaction_reference": reference,
                    "protocol_transaction_reference": f"gtpv2-{family}-{index}",
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
                        "limitations": [],
                    },
                    "transaction_outcome": (
                        "CONTROL_PARTIALLY_ACCEPTED_OBSERVED"
                        if partial
                        else "CONTROL_ACCEPTED_OBSERVED"
                    ),
                    "transaction_outcome_basis": ["message and item evidence summarized"],
                    "evidence_limitations": [],
                    "source_completeness_status": "COMPLETE",
                }
            )
            request_reference = f"epc-db-item:{reference}:request:{index}:0:0"
            response_reference = f"epc-db-item:{reference}:response:{index}:0:0"
            items.extend(
                [
                    {
                        "capture": CAPTURE,
                        "ebi": 7,
                        "ebi_status": "VALID",
                        "ebi_valid": True,
                        "item_reference": request_reference,
                        "item_outcome": "ITEM_REQUEST_EVIDENCE_ONLY",
                        "procedure_family": family,
                        "side": "REQUEST",
                        "transaction_reference": reference,
                        "evidence_limitations": [],
                        "source_completeness_status": "COMPLETE",
                    },
                    {
                        "capture": CAPTURE,
                        "ebi": 7,
                        "ebi_status": "VALID",
                        "ebi_valid": True,
                        "item_reference": response_reference,
                        "item_outcome": (
                            "ITEM_CONTROL_PARTIALLY_ACCEPTED_OBSERVED"
                            if partial
                            else "ITEM_CONTROL_ACCEPTED_OBSERVED"
                        ),
                        "procedure_family": family,
                        "side": "RESPONSE",
                        "transaction_reference": reference,
                        "evidence_limitations": [],
                        "source_completeness_status": "COMPLETE",
                    },
                ]
            )
            associations.append(
                {
                    "association_reference": f"epc-db-assoc:{reference}:{index}",
                    "capture": CAPTURE,
                    "ebi": 7,
                    "status": "ITEM_ASSOCIATION_ESTABLISHED",
                    "transaction_reference": reference,
                    "request_item_reference": request_reference,
                    "response_item_reference": response_reference,
                    "limitations": [],
                }
            )
            index += 1
    return {
        "analysis_name": "epc-dedicated-bearer-control",
        "analysis_version": "1.0.0",
        "domain": "epc-procedures",
        "control_transaction_count": len(transactions),
        "control_transactions": transactions,
        "control_transactions_omitted": 0,
        "bearer_item_observation_count": len(items),
        "bearer_item_observations": items,
        "bearer_item_observations_omitted": 0,
        "item_association_count": len(associations),
        "item_associations": associations,
        "item_associations_omitted": 0,
        "source_completeness": {
            "status": "COMPLETE",
            "exhaustive_coverage_proven": True,
            "limitations": [],
        },
        "evidence_limitations": [
            "a correlated Create/Update/Delete Bearer transaction proves an observed signaling exchange only",
        ],
        "not_confirmed": [
            "no dedicated-bearer activation, modification or effective removal is proven",
        ],
    }


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