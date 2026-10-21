#!/usr/bin/env python3
"""Evidence-type-aware deviation classification for Golden Capture summaries.

The benchmark must distinguish candidate-eligible abnormal-boundary evidence from
non-candidate evidence limitations, non-candidate supporting anomalies, and
unknown deviation types. Candidate eligibility is *not* redefined here: the three
authoritative Orchestration sets are imported directly from the accepted
Orchestration model, so the two contracts cannot drift apart. The import
direction is benchmark -> Skill; no Skill package imports this module, so the
frozen Skill architecture gains no reverse dependency.

Category semantics (disjoint and exhaustive over every deviation type string):

- ``candidate_eligible``: in ``ELIGIBLE_DEVIATION_TYPES``; may become an
  abnormal-boundary candidate. Eligibility never implies that Orchestration
  actually selected the deviation as a boundary.
- ``evidence_limitation``: in ``EVIDENCE_LIMITATION_TYPES``; a capture or
  association limitation that invents no observation and is never a candidate.
- ``supporting_anomaly``: in ``SUPPORTING_ANOMALY_TYPES``; a non-candidate
  supporting observation retained as evidence.
- ``unclassified``: everything else. An unknown deviation type is never silently
  treated as benign and never silently folded into the limitation category.

New sanitized summary fields hold bounded categorical metadata and counts only:
deviation type names and integers, never raw Domain or Orchestration documents.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Iterable

_ROOT = Path(__file__).resolve().parents[3]
_MODEL_DIR = _ROOT / "skills" / "orchestration" / "5gc-failure-boundary" / "scripts"
if str(_MODEL_DIR) not in sys.path:
    sys.path.insert(0, str(_MODEL_DIR))

from failure_boundary_model import (  # noqa: E402
    ELIGIBLE_DEVIATION_TYPES,
    EVIDENCE_LIMITATION_TYPES,
    SUPPORTING_ANOMALY_TYPES,
)

CATEGORY_CANDIDATE_ELIGIBLE = "candidate_eligible"
CATEGORY_EVIDENCE_LIMITATION = "evidence_limitation"
CATEGORY_SUPPORTING_ANOMALY = "supporting_anomaly"
CATEGORY_UNCLASSIFIED = "unclassified"

# Stable evaluation order used for deterministic serialization and for the
# required count invariant: total = sum of these four categories.
CATEGORIES = (
    CATEGORY_CANDIDATE_ELIGIBLE,
    CATEGORY_EVIDENCE_LIMITATION,
    CATEGORY_SUPPORTING_ANOMALY,
    CATEGORY_UNCLASSIFIED,
)

# Bucket key used for deviations that carry no usable type identity at all. A
# missing type is contract-violating input, so it lands in the unclassified
# category and can never be read as a benign limitation.
MISSING_TYPE_KEY = "<missing-type>"


class ClassificationError(ValueError):
    """Raised when deviation classification evidence violates its own contract.

    The sanitizer must fail loudly rather than publish counts that do not add up,
    because a silently inconsistent summary would let a comparator treat unknown
    evidence as proven non-candidate evidence.
    """


def classify_deviation_type(deviation_type: Any) -> str:
    """Return the category key for one Domain deviation type value.

    A missing or non-string type is classified as unclassified, never as an
    evidence limitation, so unknown evidence always forces review.
    """
    if not isinstance(deviation_type, str) or not deviation_type.strip():
        return CATEGORY_UNCLASSIFIED
    if deviation_type in ELIGIBLE_DEVIATION_TYPES:
        return CATEGORY_CANDIDATE_ELIGIBLE
    if deviation_type in EVIDENCE_LIMITATION_TYPES:
        return CATEGORY_EVIDENCE_LIMITATION
    if deviation_type in SUPPORTING_ANOMALY_TYPES:
        return CATEGORY_SUPPORTING_ANOMALY
    return CATEGORY_UNCLASSIFIED


def _type_key(deviation_type: Any) -> str:
    if not isinstance(deviation_type, str) or not deviation_type.strip():
        return MISSING_TYPE_KEY
    return deviation_type


def build_classification_block(deviation_types: Iterable[Any]) -> dict[str, Any]:
    """Build the bounded per-Domain deviation classification block.

    The block always satisfies the required count invariant::

        total_count
          = candidate_eligible_count
          + evidence_limitation_count
          + supporting_anomaly_count
          + unclassified_count

    and every category count equals the sum of its per-type map. Per-type maps
    contain only the types that were actually observed. The block is rejected
    rather than repaired when the input cannot produce a consistent total.
    """
    per_category: dict[str, dict[str, int]] = {category: {} for category in CATEGORIES}
    total = 0
    for raw_type in deviation_types:
        category = classify_deviation_type(raw_type)
        key = _type_key(raw_type)
        bucket = per_category[category]
        bucket[key] = bucket.get(key, 0) + 1
        total += 1

    block: dict[str, Any] = {
        "total_count": total,
        "candidate_eligible_count": 0,
        "evidence_limitation_count": 0,
        "supporting_anomaly_count": 0,
        "unclassified_count": 0,
    }
    for category in CATEGORIES:
        bucket = per_category[category]
        count = sum(bucket.values())
        block[f"{category}_count"] = count
        # Deterministic ordering: only observed types are recorded, sorted by name.
        block[f"{category}_types"] = {key: bucket[key] for key in sorted(bucket)}

    errors = validate_classification_block(block, expected_total=total)
    if errors:
        raise ClassificationError("; ".join(errors))
    return block


def validate_classification_block(
    block: Any,
    expected_total: int | None = None,
) -> list[str]:
    """Return contract violations for a classification block (empty when valid).

    Checks the required fields, non-negative integer counts, the required count
    invariant, per-type map consistency, and optionally the agreement with a
    separately reported total deviation count. Callers treat any returned error
    as an explicit, conservative failure; nothing is silently repaired.
    """
    errors: list[str] = []
    if not isinstance(block, dict):
        return ["deviation_classification is missing or not an object"]

    required = ["total_count"] + [f"{category}_count" for category in CATEGORIES]
    required += [f"{category}_types" for category in CATEGORIES]
    for field in required:
        if field not in block:
            errors.append(f"deviation_classification is missing required field {field}")
    if errors:
        return errors

    counts: dict[str, int] = {}
    for field in ("total_count",) + tuple(f"{category}_count" for category in CATEGORIES):
        value = block[field]
        if isinstance(value, bool) or not isinstance(value, int):
            errors.append(f"deviation_classification.{field} must be an integer")
            continue
        if value < 0:
            errors.append(f"deviation_classification.{field} must not be negative")
            continue
        counts[field] = value

    type_sums: dict[str, int] = {}
    for category in CATEGORIES:
        bucket = block[f"{category}_types"]
        if not isinstance(bucket, dict):
            errors.append(f"deviation_classification.{category}_types must be an object")
            continue
        bucket_sum = 0
        for key, value in bucket.items():
            if not isinstance(key, str) or not key:
                errors.append(f"deviation_classification.{category}_types has a non-string key")
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                errors.append(
                    f"deviation_classification.{category}_types[{key!r}] must be a non-negative integer"
                )
                continue
            bucket_sum += value
        type_sums[category] = bucket_sum

    if len(counts) == 1 + len(CATEGORIES):
        category_total = sum(counts[f"{category}_count"] for category in CATEGORIES)
        if counts["total_count"] != category_total:
            errors.append(
                "deviation_classification count invariant violated: "
                f"total_count {counts['total_count']} != sum of category counts {category_total}"
            )
        for category in CATEGORIES:
            if category in type_sums and counts[f"{category}_count"] != type_sums[category]:
                errors.append(
                    f"deviation_classification.{category}_count "
                    f"{counts[f'{category}_count']} != sum of {category}_types {type_sums[category]}"
                )

    if expected_total is not None and "total_count" in counts:
        if counts["total_count"] != expected_total:
            errors.append(
                "deviation_classification.total_count "
                f"{counts['total_count']} != reported deviation_count {expected_total}"
            )

    return errors


def summarize_classification(blocks: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate classification blocks from several relevant Domain records.

    The aggregate is only ``available`` when every supplied block exists and is
    internally consistent. A partial or inconsistent aggregate is reported as
    unavailable or inconsistent instead of being read as zero candidate
    deviations, because absent evidence must never become proven non-candidate
    evidence.
    """
    materialized = list(blocks)
    if not materialized:
        return {
            "available": False,
            "consistent": False,
            "reasons": ["no per-Domain deviation classification was reported"],
        }

    aggregate = {
        "total_count": 0,
        "candidate_eligible_count": 0,
        "evidence_limitation_count": 0,
        "supporting_anomaly_count": 0,
        "unclassified_count": 0,
    }
    type_maps: dict[str, dict[str, int]] = {category: {} for category in CATEGORIES}
    reasons: list[str] = []
    consistent = True

    for index, block in enumerate(materialized):
        errors = validate_classification_block(block)
        if errors:
            consistent = False
            reasons.extend(f"Domain record {index}: {error}" for error in errors)
            continue
        aggregate["total_count"] += block["total_count"]
        for category in CATEGORIES:
            aggregate[f"{category}_count"] += block[f"{category}_count"]
            bucket = type_maps[category]
            for key, value in block[f"{category}_types"].items():
                bucket[key] = bucket.get(key, 0) + value

    for category in CATEGORIES:
        bucket = type_maps[category]
        aggregate[f"{category}_types"] = {key: bucket[key] for key in sorted(bucket)}

    errors = validate_classification_block(aggregate)
    if errors:
        consistent = False
        reasons.extend(errors)

    return {
        "available": True,
        "consistent": consistent,
        "reasons": reasons,
        **aggregate,
    }
