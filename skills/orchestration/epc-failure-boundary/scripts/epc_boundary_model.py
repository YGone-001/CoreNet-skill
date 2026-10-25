#!/usr/bin/env python3
"""Bounded EPC failure-boundary orchestration over accepted Domain evidence.

The model consumes the accepted EPC Domain analyses only:

* `epc-procedures` EPS Attach analysis (`procedure_instances`).
* `epc-procedures` EPC session-control analysis (`control_plane_subjects`).

It never reads a capture, never decodes a protocol, and never parses a
human-readable explanation to recover a cause or an event frame. Every
selectable boundary candidate is built from a machine-readable Domain deviation
that already carries an exact frame anchor.

Scope rules:

* One diagnostic subject is one unit of boundary selection. An EPS Attach
  instance, an S11 session-control subject and an S5/S8 session-control subject
  stay independent; no cross-subject identity bridge is authorized.
* Only explicit negative protocol outcomes are selectable. Evidence-quality
  deviations stay non-selectable and can only constrain the selection.
* A truncated candidate list blocks any claim that a visible candidate is the
  earliest, because omitted candidates could precede it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ANALYSIS_NAME = "epc-failure-boundary"
ANALYSIS_VERSION = "0.2.0"

EXIT_MALFORMED_INPUT = 5
EXIT_NO_INPUT = 6
EXIT_OUTPUT_FAILURE = 7

DOMAIN = "epc-procedures"
ATTACH_PROCEDURE = "eps-attach"
SESSION_SCOPE = "epc-session-control"
DEFAULT_BEARER_PROCEDURE = "eps-default-bearer"

ATTACH_VERSION_FLOOR = (0, 1, 0)
SESSION_VERSION_FLOOR = (0, 2, 0)
DEFAULT_BEARER_VERSION_FLOOR = (0, 3, 0)

SUBJECT_ATTACH = "EPS_ATTACH"
SUBJECT_SESSION = "EPC_SESSION_CONTROL"
SUBJECT_DEFAULT_BEARER = "EPS_DEFAULT_BEARER"

# ESM message identities that are explicit rejections in TS 24.301 §9.3. The
# Domain emits ESM_REJECTION_OBSERVED only for these, and the candidate guard
# below re-checks the message identity so a cause-bearing non-reject can never
# become a selectable negative outcome.
ESM_REJECT_MESSAGE_TYPES = (
    "activate dedicated eps bearer context reject",
    "activate default eps bearer context reject",
    "modify eps bearer context reject",
    "pdn connectivity reject",
    "pdn disconnect reject",
    "bearer resource allocation reject",
    "bearer resource modification reject",
)

# Explicit negative protocol outcomes that may become a selected boundary.
ELIGIBLE_ATTACH = frozenset({
    "ATTACH_REJECT_OBSERVED",
    "AUTHENTICATION_FAILURE_OBSERVED",
    "AUTHENTICATION_REJECT_OBSERVED",
    "SECURITY_MODE_REJECT_OBSERVED",
    "S1_CONTEXT_SETUP_FAILURE_OBSERVED",
})
ELIGIBLE_SESSION = frozenset({
    "CREATE_SESSION_REJECTED_OBSERVED",
    "MODIFY_BEARER_REJECTED_OBSERVED",
    "DELETE_SESSION_REJECTED_OBSERVED",
    "BEARER_CONTEXT_REJECTED_OBSERVED",
})
# Reviewed ESM negative outcomes. PDN connectivity and default-bearer activation
# rejection are the primary selectable outcomes; a generic ESM rejection is
# selectable only when its message identity is a reviewed reject type.
ELIGIBLE_DEFAULT_BEARER = frozenset({
    "PDN_CONNECTIVITY_REJECT_OBSERVED",
    "DEFAULT_BEARER_ACTIVATION_REJECT_OBSERVED",
    "ESM_REJECTION_OBSERVED",
})

# Evidence-quality deviations. They never become a negative network outcome,
# but they can block or weaken a selection.
NONSELECTABLE = frozenset({
    "OPEN_REQUEST_OBSERVED",
    "RESPONSE_ONLY_OBSERVED",
    "AMBIGUOUS_TRANSACTION_OBSERVED",
    "INTERFACE_EVIDENCE_UNAVAILABLE",
    "INTERFACE_EVIDENCE_CONFLICT",
    "CONTEXT_REUSE_AFTER_DELETION",
    "BEARER_CONTEXT_BINDING_UNAVAILABLE",
    "PROTECTED_INNER_MESSAGE_UNAVAILABLE",
    "INSUFFICIENT_TERMINAL_EVIDENCE",
    # Default-bearer evidence-quality deviations.
    "PROTECTED_ESM_UNAVAILABLE",
    "ERAB_ITEM_EVIDENCE_UNAVAILABLE",
    "TUNNEL_ENDPOINT_LINK_AMBIGUOUS",
    "ESM_EVIDENCE_UNBOUND",
})

STATUS_SELECTED = "SELECTED"
STATUS_NONE = "NO_ABNORMAL_BOUNDARY_OBSERVED"
STATUS_AMBIGUOUS = "AMBIGUOUS_FIRST_BOUNDARY"
STATUS_INSUFFICIENT = "INSUFFICIENT_COMPARABLE_EVIDENCE"

SELECTION_STATUSES = (STATUS_SELECTED, STATUS_NONE, STATUS_AMBIGUOUS, STATUS_INSUFFICIENT)

CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"

RELATION_AFTER = "OBSERVED_AFTER_BOUNDARY"

ELIGIBILITY_ELIGIBLE = "ELIGIBLE"
ELIGIBILITY_INELIGIBLE = "INELIGIBLE"

STRONG_LINK_STRENGTHS = frozenset({"STRONG", "SUPPORTED"})

NOT_CONFIRMED = (
    "the selected boundary is a first observed abnormality, not a root cause",
    "no network function is identified as responsible",
    "downstream observations are ordered after the boundary and are not attributed to it",
    "procedure or service success is not established by the absence of a boundary",
    "user-plane forwarding is not established by any control-plane boundary",
    "subscriber, subscription or implementation behaviour is not assessed",
)

ANALYSIS_LIMITATIONS = (
    "Boundary selection is per diagnostic subject; the analysis never merges independent "
    "EPS Attach, S11 and S5/S8 subjects into one EPC failure point.",
    "Selection ordering uses exact frame provenance only; severity, cause magnitude, message "
    "labels and list order never order candidates.",
    "A selected boundary is the earliest supported abnormal observation, not a causal claim.",
)

FORBIDDEN_OUTPUT_PATTERN = re.compile(
    r"(?i)\b(root cause is|root-cause chain|caused by the boundary|downstream failure caused by|"
    r"network function is responsible)\b"
)

MAX_CANDIDATES = 40
MAX_EVIDENCE_REFERENCES = 10
MAX_LIST_ITEMS = 20


class InputError(ValueError):
    """Raised when a supplied Domain artifact is unusable."""


def safe_name(path: Path) -> str:
    return path.name


def sanitize_output(document: Any) -> Any:
    """Reject accidental causal wording anywhere in the produced document."""
    if isinstance(document, str):
        if FORBIDDEN_OUTPUT_PATTERN.search(document):
            raise InputError("analysis output would contain a causal claim")
        return document
    if isinstance(document, dict):
        return {key: sanitize_output(value) for key, value in document.items()}
    if isinstance(document, list):
        return [sanitize_output(item) for item in document]
    return document


def _require_mapping(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{what} is not a JSON object")
    return value


def _require_list(value: Any, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise InputError(f"{what} is not a JSON array")
    return value


def _parse_version(value: Any) -> tuple[int, int, int] | None:
    if not isinstance(value, str):
        return None
    parts = value.strip().split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def _enforce_version(document: dict[str, Any], floor: tuple[int, int, int], what: str) -> str:
    version = document.get("domain_version")
    parsed = _parse_version(version)
    if parsed is None:
        raise InputError(f"{what} carries no usable domain_version")
    if parsed < floor:
        raise InputError(
            f"{what} domain_version {version} is below the supported floor "
            f"{'.'.join(str(part) for part in floor)}"
        )
    return str(version)


def _load_json(path: Path, what: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"invalid JSON in {path.name}: {exc.msg}") from exc
    except OSError as exc:
        raise InputError(f"cannot read {what} {path}: {exc}") from exc
    return _require_mapping(payload, what)


def _frame_of(reference: Any) -> int | None:
    if not isinstance(reference, dict):
        return None
    value = reference.get("frame_number")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _window_of(value: Any) -> tuple[int, int] | None:
    if not isinstance(value, dict):
        return None
    start = value.get("start_frame")
    end = value.get("end_frame")
    if isinstance(start, bool) or not isinstance(start, int):
        return None
    if isinstance(end, bool) or not isinstance(end, int):
        return None
    if end < start:
        return None
    return start, end


@dataclass
class Subject:
    subject_type: str
    reference: str
    capture_file: str | None
    association_strength: str
    association_basis: str
    deviations: list[dict[str, Any]] = field(default_factory=list)
    deviations_omitted: int = 0
    limitations: list[dict[str, Any]] = field(default_factory=list)
    additional_evidence: list[dict[str, Any]] = field(default_factory=list)
    window: tuple[int, int] | None = None
    source_file: str = ""
    source_domain: str = DOMAIN
    detail: dict[str, Any] = field(default_factory=dict)


def _limitation_entry(entry_type: str, description: str) -> dict[str, Any]:
    return {"type": entry_type, "description": description}


def load_attach_subjects(document: dict[str, Any], file_name: str) -> list[Subject]:
    if document.get("domain") != DOMAIN:
        raise InputError(f"{file_name} is not an {DOMAIN} analysis")
    if document.get("procedure") != ATTACH_PROCEDURE:
        raise InputError(f"{file_name} is not an EPS Attach analysis")
    _enforce_version(document, ATTACH_VERSION_FLOOR, file_name)
    subjects: list[Subject] = []
    for index, instance in enumerate(_require_list(document.get("procedure_instances"), f"{file_name} procedure_instances")):
        instance = _require_mapping(instance, f"{file_name} procedure_instances[{index}]")
        reference = instance.get("procedure_reference")
        if not isinstance(reference, str) or not reference:
            raise InputError(f"{file_name} procedure instance {index} lacks procedure_reference")
        association = instance.get("association") if isinstance(instance.get("association"), dict) else {}
        limitations = [
            _limitation_entry("DOMAIN_LIMITATION", str(text))
            for text in instance.get("evidence_limitations") or []
            if isinstance(text, str) and text
        ]
        additional = [
            {"requirement": str(text), "reason": "reported by the accepted EPS Attach Domain"}
            for text in instance.get("additional_evidence_needed") or []
            if isinstance(text, str) and text
        ]
        window = None
        first, last = instance.get("first_frame"), instance.get("last_frame")
        if isinstance(first, int) and isinstance(last, int) and not isinstance(first, bool) and not isinstance(last, bool):
            window = (first, last) if last >= first else None
        subjects.append(
            Subject(
                subject_type=SUBJECT_ATTACH,
                reference=reference,
                capture_file=association.get("capture_file") if isinstance(association.get("capture_file"), str) else None,
                association_strength=str(association.get("strength") or "UNBOUND"),
                association_basis=str(association.get("basis") or "procedure_instance"),
                deviations=[item for item in instance.get("deviations") or [] if isinstance(item, dict)],
                deviations_omitted=0,
                limitations=limitations,
                additional_evidence=additional,
                window=window,
                source_file=file_name,
                detail={
                    "attempt_index": instance.get("attempt_index"),
                    "stage_count": len(instance.get("stages") or []),
                    "stages": [
                        {
                            "stage_id": stage.get("stage_id"),
                            "status": stage.get("status"),
                            "first_frame": stage.get("first_frame"),
                            "last_frame": stage.get("last_frame"),
                        }
                        for stage in instance.get("stages") or []
                        if isinstance(stage, dict)
                    ],
                },
            )
        )
    return subjects


def load_session_subjects(document: dict[str, Any], file_name: str) -> list[Subject]:
    if document.get("domain") != DOMAIN:
        raise InputError(f"{file_name} is not an {DOMAIN} analysis")
    if document.get("analysis_scope") != SESSION_SCOPE:
        raise InputError(f"{file_name} is not an EPC session-control analysis")
    _enforce_version(document, SESSION_VERSION_FLOOR, file_name)
    subjects: list[Subject] = []
    for index, subject in enumerate(_require_list(document.get("control_plane_subjects"), f"{file_name} control_plane_subjects")):
        subject = _require_mapping(subject, f"{file_name} control_plane_subjects[{index}]")
        reference = subject.get("subject_reference")
        if not isinstance(reference, str) or not reference:
            raise InputError(f"{file_name} session subject {index} lacks subject_reference")
        deviations = [item for item in subject.get("procedure_local_deviations") or [] if isinstance(item, dict)]
        declared = subject.get("procedure_local_deviation_count")
        declared = declared if isinstance(declared, int) and not isinstance(declared, bool) else len(deviations)
        omitted = subject.get("procedure_local_deviations_omitted")
        if isinstance(omitted, int) and not isinstance(omitted, bool):
            omitted_count = max(0, omitted)
        else:
            omitted_count = max(0, declared - len(deviations))
        limitations = [
            _limitation_entry("DOMAIN_LIMITATION", str(text))
            for text in subject.get("limitations") or []
            if isinstance(text, str) and text
        ]
        window = _window_of(subject.get("observation_window"))
        interface = subject.get("interface")
        subjects.append(
            Subject(
                subject_type=SUBJECT_SESSION,
                reference=reference,
                capture_file=subject.get("capture_file") if isinstance(subject.get("capture_file"), str) else None,
                association_strength=str(subject.get("association_strength") or "UNBOUND"),
                association_basis=str((subject.get("interface_evidence") or {}).get("basis") or "unavailable"),
                deviations=deviations,
                deviations_omitted=omitted_count,
                limitations=limitations,
                additional_evidence=[],
                window=window,
                source_file=file_name,
                detail={
                    "interface": interface if isinstance(interface, str) else None,
                    "transaction_references": [
                        item for item in subject.get("transaction_references") or [] if isinstance(item, str)
                    ],
                },
            )
        )
    return subjects


def load_default_bearer_subjects(document: dict[str, Any], file_name: str) -> list[Subject]:
    """Load EPS default-bearer instances as independent diagnostic subjects.

    Each instance stays independently addressable. An instance that publishes an
    established Attach link keeps that reference as related evidence; it is never
    merged into the Attach group.
    """
    if document.get("domain") != DOMAIN:
        raise InputError(f"{file_name} is not an {DOMAIN} analysis")
    if document.get("procedure") != DEFAULT_BEARER_PROCEDURE:
        raise InputError(f"{file_name} is not an EPS default-bearer analysis")
    _enforce_version(document, DEFAULT_BEARER_VERSION_FLOOR, file_name)

    # Only a top-level omission count is published. When it is non-zero the
    # missing records cannot be attributed to one instance, so every instance is
    # treated as potentially incomplete.
    global_omitted = document.get("procedure_local_deviations_omitted")
    global_omitted = (
        max(0, global_omitted) if isinstance(global_omitted, int) and not isinstance(global_omitted, bool) else 0
    )

    subjects: list[Subject] = []
    for index, instance in enumerate(
        _require_list(document.get("default_bearer_instances"), f"{file_name} default_bearer_instances")
    ):
        instance = _require_mapping(instance, f"{file_name} default_bearer_instances[{index}]")
        reference = instance.get("instance_reference")
        if not isinstance(reference, str) or not reference:
            raise InputError(f"{file_name} default-bearer instance {index} lacks instance_reference")
        deviations = [item for item in instance.get("deviations") or [] if isinstance(item, dict)]
        limitations = [
            _limitation_entry("DOMAIN_LIMITATION", str(text))
            for text in instance.get("limitations") or []
            if isinstance(text, str) and text
        ]
        additional = [
            {"requirement": str(text), "reason": "reported by the EPS default-bearer analysis"}
            for text in instance.get("additional_evidence_needed") or []
            if isinstance(text, str) and text
        ]
        attach_link = instance.get("attach_link") if isinstance(instance.get("attach_link"), dict) else {}
        related_attach = (
            attach_link.get("target_subject_reference")
            if attach_link.get("status") == "ESTABLISHED"
            and isinstance(attach_link.get("target_subject_reference"), str)
            else None
        )
        context = instance.get("ue_context") if isinstance(instance.get("ue_context"), dict) else {}
        subjects.append(
            Subject(
                subject_type=SUBJECT_DEFAULT_BEARER,
                reference=reference,
                capture_file=context.get("capture_file") if isinstance(context.get("capture_file"), str) else None,
                association_strength=str(instance.get("association_strength") or "UNBOUND"),
                association_basis=str(instance.get("association_basis") or "unavailable"),
                deviations=deviations,
                deviations_omitted=global_omitted,
                limitations=limitations,
                additional_evidence=additional,
                window=_window_of(instance.get("observation_window")),
                source_file=file_name,
                detail={
                    "related_attach_reference": related_attach,
                    "interface": "N1/S1-MME",
                    "stages": [
                        {
                            "stage_id": stage.get("stage_id"),
                            "first_frame": stage.get("first_frame"),
                        }
                        for stage in instance.get("stages") or []
                        if isinstance(stage, dict)
                    ],
                },
            )
        )
    return subjects


# ---------------------------------------------------------------------------
# Candidate construction
# ---------------------------------------------------------------------------


_ELIGIBLE_BY_SUBJECT = {
    SUBJECT_ATTACH: ELIGIBLE_ATTACH,
    SUBJECT_SESSION: ELIGIBLE_SESSION,
    SUBJECT_DEFAULT_BEARER: ELIGIBLE_DEFAULT_BEARER,
}


def _eligible_types(subject_type: str) -> frozenset[str]:
    return _ELIGIBLE_BY_SUBJECT.get(subject_type, frozenset())


def candidate_reference(subject: Subject, deviation: dict[str, Any], ordinal: int) -> str:
    seed = "|".join(
        [
            subject.reference,
            str(deviation.get("deviation_type")),
            str(deviation.get("frame_number")),
            str(deviation.get("transaction_reference") or ""),
            str(deviation.get("bearer_item_index") or ""),
            str(ordinal),
        ]
    )
    return f"epc-boundary-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:10]}"


def _eligibility(
    subject: Subject,
    deviation: dict[str, Any],
    frame: int | None,
    window: tuple[int, int] | None,
    refs: list[dict[str, Any]],
) -> tuple[str, list[str], str | None]:
    deviation_type = deviation.get("deviation_type")
    reasons: list[str] = []
    limitation: str | None = None

    if deviation_type in _eligible_types(subject.subject_type):
        if deviation_type == "ESM_REJECTION_OBSERVED":
            message_type = deviation.get("message_type")
            if not isinstance(message_type, str) or message_type.strip().lower() not in ESM_REJECT_MESSAGE_TYPES:
                return (
                    ELIGIBILITY_INELIGIBLE,
                    ["the ESM message identity is not a reviewed rejection"],
                    "UNSUPPORTED_ESM_REJECTION_IDENTITY",
                )
    elif deviation_type in NONSELECTABLE:
        return ELIGIBILITY_INELIGIBLE, ["deviation_type is an evidence-quality observation, not a negative network outcome"], None
    else:
        return (
            ELIGIBILITY_INELIGIBLE,
            ["deviation_type is not a reviewed selectable outcome"],
            "UNKNOWN_DEVIATION_TYPE",
        )

    if frame is None:
        reasons.append("no exact frame anchor")
    else:
        ref_frames = [_frame_of(reference) for reference in refs]
        if frame not in [item for item in ref_frames if item is not None]:
            reasons.append("frame anchor is absent from the source evidence references")
    if window is None:
        reasons.append("no bounded observation window")
    elif frame is not None and not (window[0] <= frame <= window[1]):
        reasons.append("frame anchor lies outside the source observation window")
    if not isinstance(deviation.get("protocol"), str) or not deviation.get("protocol"):
        reasons.append("no protocol identity")
    if not isinstance(deviation.get("message_type"), str) or not deviation.get("message_type"):
        reasons.append("no message identity")
    if subject.subject_type == SUBJECT_SESSION and not isinstance(deviation.get("transaction_reference"), str):
        reasons.append("no source transaction reference")
    level = deviation.get("evidence_level")
    if level in ("INFERRED", "HYPOTHESIS"):
        reasons.append("evidence level does not support a selected boundary")
    if level not in ("OBSERVED", "DERIVED"):
        reasons.append("evidence level is not published")

    if reasons:
        return ELIGIBILITY_INELIGIBLE, reasons, limitation
    return ELIGIBILITY_ELIGIBLE, [], limitation


def build_candidate(subject: Subject, deviation: dict[str, Any], ordinal: int) -> dict[str, Any]:
    refs = [reference for reference in deviation.get("evidence_refs") or [] if isinstance(reference, dict)]
    bounded_refs, refs_omitted = _bounded_refs(refs)
    frame = deviation.get("frame_number") if isinstance(deviation.get("frame_number"), int) else None
    window = _window_of(deviation.get("observation_window"))
    eligibility, reasons, limitation = _eligibility(subject, deviation, frame, window, refs)
    candidate: dict[str, Any] = {
        "candidate_reference": candidate_reference(subject, deviation, ordinal),
        "source_domain": subject.source_domain,
        "source_subject_reference": subject.reference,
        "deviation_type": deviation.get("deviation_type"),
        "procedure_family_or_stage": deviation.get("procedure_family") or deviation.get("procedure_stage"),
        "protocol": deviation.get("protocol"),
        "message_type": deviation.get("message_type"),
        "frame_number": frame,
        "evidence_level": deviation.get("evidence_level"),
        "evidence_refs": bounded_refs,
        "observation_window": (
            {"start_frame": window[0], "end_frame": window[1]} if window else None
        ),
        "selection_eligibility": eligibility,
        "eligibility_reasons": reasons,
        "limitations": [
            str(item) for item in deviation.get("limitations") or [] if isinstance(item, str)
        ][:MAX_LIST_ITEMS],
    }
    if refs_omitted:
        candidate["evidence_refs_omitted"] = refs_omitted
    for field_name in (
        "transaction_reference",
        "cause_code",
        "cause_scope",
        "bearer_item_index",
        "esm_cause_code",
        "esm_cause_name",
        "eps_bearer_identity",
    ):
        value = deviation.get(field_name)
        if value is not None:
            candidate[field_name] = value
    if limitation:
        candidate["limitation_type"] = limitation
    return candidate


def _bounded_refs(refs: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    projected = [
        {
            "frame_number": reference.get("frame_number"),
            "protocol": reference.get("protocol"),
            "message_type": reference.get("message_type"),
            "evidence_level": reference.get("evidence_level"),
        }
        for reference in refs
    ]
    omitted = max(0, len(projected) - MAX_EVIDENCE_REFERENCES)
    return projected[:MAX_EVIDENCE_REFERENCES], omitted


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def _dedupe(candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Collapse exact duplicates and record the basis."""
    seen: dict[tuple[Any, ...], dict[str, Any]] = {}
    order: list[tuple[Any, ...]] = []
    duplicates: list[str] = []
    for candidate in candidates:
        key = (
            candidate.get("deviation_type"),
            candidate.get("frame_number"),
            candidate.get("transaction_reference"),
            candidate.get("cause_scope"),
            candidate.get("bearer_item_index"),
            candidate.get("message_type"),
        )
        if key in seen:
            duplicates.append(candidate["candidate_reference"])
            continue
        seen[key] = candidate
        order.append(key)
    return [seen[key] for key in order], duplicates


def _confidence(subject: Subject, selected: dict[str, Any], complete: bool) -> str:
    if not complete:
        return CONFIDENCE_LOW
    if selected.get("evidence_level") != "OBSERVED":
        return CONFIDENCE_LOW
    if subject.association_strength in STRONG_LINK_STRENGTHS:
        return CONFIDENCE_HIGH
    return CONFIDENCE_MEDIUM


def analyze_subject(subject: Subject, index: int) -> dict[str, Any]:
    candidates = [build_candidate(subject, deviation, ordinal) for ordinal, deviation in enumerate(subject.deviations)]
    candidates, duplicates = _dedupe(candidates)
    candidates.sort(
        key=lambda item: (
            item.get("frame_number") if isinstance(item.get("frame_number"), int) else 10**9,
            str(item.get("deviation_type")),
            item["candidate_reference"],
        )
    )
    visible = candidates[:MAX_CANDIDATES]
    omitted = subject.deviations_omitted + max(0, len(candidates) - MAX_CANDIDATES)
    complete = omitted == 0

    eligible = [item for item in visible if item["selection_eligibility"] == ELIGIBILITY_ELIGIBLE]
    limitations: list[dict[str, Any]] = list(subject.limitations)
    if subject.deviations_omitted:
        limitations.append(
            _limitation_entry(
                "TRUNCATED_SOURCE_DEVIATIONS",
                f"{subject.deviations_omitted} source deviation(s) were not published by the Domain; "
                "the visible candidate list cannot establish the earliest abnormal observation",
            )
        )
    if duplicates:
        limitations.append(
            _limitation_entry(
                "DUPLICATE_CANDIDATES_DEDUPLICATED",
                f"{len(duplicates)} candidate(s) shared identical provenance and were deduplicated",
            )
        )
    unknown = [item for item in visible if item.get("limitation_type") == "UNKNOWN_DEVIATION_TYPE"]
    if unknown:
        limitations.append(
            _limitation_entry(
                "UNKNOWN_DEVIATION_TYPE",
                "at least one Domain deviation type is not reviewed and was not made selectable",
            )
        )
    if any(item["deviation_type"] == "PROTECTED_INNER_MESSAGE_UNAVAILABLE" for item in visible):
        limitations.append(
            _limitation_entry(
                "PROTECTED_INNER_MESSAGE_UNAVAILABLE",
                "a protected NAS payload limits what the underlying procedure evidence can show",
            )
        )

    # An ambiguous transaction is not a negative outcome, but it can hide one:
    # if it sits at or before the earliest eligible candidate, the evidence
    # cannot establish that candidate as the first abnormal observation.
    uncertainty_frames = [
        item["frame_number"]
        for item in visible
        if item.get("deviation_type") == "AMBIGUOUS_TRANSACTION_OBSERVED"
        and isinstance(item.get("frame_number"), int)
    ]

    status = STATUS_NONE
    selected: dict[str, Any] | None = None
    confidence: str | None = None
    ordering_basis = None

    if not complete:
        status = STATUS_INSUFFICIENT
        limitations.append(
            _limitation_entry(
                "INCOMPLETE_CANDIDATE_UNIVERSE",
                "the candidate universe is incomplete, so no earliest boundary is selected",
            )
        )
    elif not eligible:
        if uncertainty_frames:
            status = STATUS_INSUFFICIENT
            limitations.append(
                _limitation_entry(
                    "AMBIGUOUS_TRANSACTION_PRECEDES_SELECTION",
                    "an ambiguous transaction could conceal a negative response, so the absence of a "
                    "selectable candidate cannot be stated as complete",
                )
            )
        else:
            status = STATUS_NONE
    else:
        earliest_frame = min(item["frame_number"] for item in eligible)
        earliest = [item for item in eligible if item["frame_number"] == earliest_frame]
        if any(frame <= earliest_frame for frame in uncertainty_frames):
            status = STATUS_INSUFFICIENT
            limitations.append(
                _limitation_entry(
                    "AMBIGUOUS_TRANSACTION_PRECEDES_SELECTION",
                    "an ambiguous transaction at or before the earliest eligible candidate could "
                    "conceal an earlier negative response",
                )
            )
        elif len(earliest) > 1:
            status = STATUS_AMBIGUOUS
            limitations.append(
                _limitation_entry(
                    "SAME_FRAME_CANDIDATES",
                    f"{len(earliest)} eligible candidates share frame {earliest_frame} with different "
                    "provenance; the evidence cannot select one",
                )
            )
        else:
            status = STATUS_SELECTED
            selected = earliest[0]
            confidence = _confidence(subject, selected, complete)
            ordering_basis = "exact_frame_number"

    boundary = None
    if selected is not None:
        boundary = {
            "boundary_reference": selected["candidate_reference"],
            "deviation_type": selected["deviation_type"],
            "protocol": selected["protocol"],
            "message_type": selected["message_type"],
            "frame_number": selected["frame_number"],
            "evidence_level": selected["evidence_level"],
            "evidence_refs": selected["evidence_refs"],
            "observation_window": selected["observation_window"],
            "ordering_basis": ordering_basis,
        }
        for field_name in (
            "transaction_reference",
            "cause_code",
            "cause_scope",
            "bearer_item_index",
            "procedure_family_or_stage",
            "esm_cause_code",
            "esm_cause_name",
            "eps_bearer_identity",
        ):
            if selected.get(field_name) is not None:
                boundary[field_name] = selected[field_name]
        if selected.get("evidence_refs_omitted"):
            boundary["evidence_refs_omitted"] = selected["evidence_refs_omitted"]

    downstream = []
    if boundary is not None:
        boundary_frame = boundary["frame_number"]
        for candidate in visible:
            if candidate is selected:
                continue
            frame = candidate.get("frame_number")
            if isinstance(frame, int) and frame > boundary_frame:
                downstream.append(
                    {
                        "relation": RELATION_AFTER,
                        "deviation_type": candidate["deviation_type"],
                        "protocol": candidate["protocol"],
                        "message_type": candidate["message_type"],
                        "frame_number": frame,
                        "candidate_reference": candidate["candidate_reference"],
                        "description": (
                            f"observed at frame {frame} after the selected boundary; "
                            "ordering is not causation"
                        ),
                    }
                )
        for stage in subject.detail.get("stages") or []:
            first_frame = stage.get("first_frame")
            if isinstance(first_frame, int) and first_frame > boundary_frame:
                downstream.append(
                    {
                        "relation": RELATION_AFTER,
                        "deviation_type": "PROCEDURE_STAGE_OBSERVED",
                        "protocol": None,
                        "message_type": stage.get("stage_id"),
                        "frame_number": first_frame,
                        "candidate_reference": None,
                        "description": (
                            f"procedure stage {stage.get('stage_id')} was observed at frame "
                            f"{first_frame} after the selected boundary; ordering is not causation"
                        ),
                    }
                )
        downstream.sort(key=lambda item: (item.get("frame_number") or 0, str(item.get("deviation_type"))))

    additional = list(subject.additional_evidence)
    if status == STATUS_INSUFFICIENT:
        additional.append(
            {
                "requirement": "a complete Domain deviation list for this subject",
                "reason": "omitted deviations could precede every visible candidate",
            }
        )
    if status == STATUS_AMBIGUOUS:
        additional.append(
            {
                "requirement": "evidence that separates the same-frame candidates",
                "reason": "two eligible candidates share one frame with different provenance",
            }
        )
    if status == STATUS_NONE:
        additional.append(
            {
                "requirement": "a complete capture of the procedure under analysis",
                "reason": "absence of a supported boundary is not evidence of success",
            }
        )

    group: dict[str, Any] = {
        "diagnostic_group_reference": subject.reference,
        "subject_type": subject.subject_type,
        "source_instance_reference": subject.reference,
        "related_attach_reference": subject.detail.get("related_attach_reference"),
        "source_domain_instances": [
            {
                "source_domain": subject.source_domain,
                "source_file": subject.source_file,
                "source_instance_id": subject.reference,
                "capture_file": subject.capture_file,
                "subject_type": subject.subject_type,
                "interface": subject.detail.get("interface"),
                "transaction_references": subject.detail.get("transaction_references") or [],
                "attempt_index": subject.detail.get("attempt_index"),
            }
        ],
        "subject_link": {
            "strength": subject.association_strength,
            "basis": subject.association_basis,
            "cross_subject_link": "NOT_ESTABLISHED",
        },
        "observation_window": (
            {"start_frame": subject.window[0], "end_frame": subject.window[1]} if subject.window else None
        ),
        "boundary_candidates": visible,
        "boundary_candidate_count": len(candidates),
        "boundary_candidates_omitted": omitted,
        "boundary_selection_status": status,
        "first_abnormal_boundary": boundary,
        "boundary_confidence": confidence,
        "downstream_observations": downstream[:MAX_LIST_ITEMS],
        "evidence_limitations": limitations[:MAX_LIST_ITEMS],
        "additional_evidence_needed": additional[:MAX_LIST_ITEMS],
        "not_confirmed": list(NOT_CONFIRMED),
        "group_index": index,
    }
    return group


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def analyze(
    attach_paths: list[Path],
    session_paths: list[Path],
    default_bearer_paths: list[Path] | None = None,
) -> dict[str, Any]:
    """Run bounded per-subject EPC failure-boundary orchestration."""
    default_bearer_paths = default_bearer_paths or []
    if not attach_paths and not session_paths and not default_bearer_paths:
        raise InputError("no EPC Domain analysis input supplied")

    subjects: list[Subject] = []
    provenance: list[dict[str, Any]] = []
    versions: set[str] = set()

    for path in attach_paths:
        document = _load_json(path, "EPS Attach analysis")
        loaded = load_attach_subjects(document, safe_name(path))
        versions.add(str(document.get("domain_version")))
        provenance.append(
            {
                "source_domain": DOMAIN,
                "analysis_kind": ATTACH_PROCEDURE,
                "source_file": safe_name(path),
                "subject_count": len(loaded),
                "domain_version": document.get("domain_version"),
            }
        )
        subjects.extend(loaded)

    for path in session_paths:
        document = _load_json(path, "EPC session-control analysis")
        loaded = load_session_subjects(document, safe_name(path))
        versions.add(str(document.get("domain_version")))
        provenance.append(
            {
                "source_domain": DOMAIN,
                "analysis_kind": SESSION_SCOPE,
                "source_file": safe_name(path),
                "subject_count": len(loaded),
                "domain_version": document.get("domain_version"),
            }
        )
        subjects.extend(loaded)

    for path in default_bearer_paths:
        document = _load_json(path, "EPS default-bearer analysis")
        loaded = load_default_bearer_subjects(document, safe_name(path))
        versions.add(str(document.get("domain_version")))
        provenance.append(
            {
                "source_domain": DOMAIN,
                "analysis_kind": DEFAULT_BEARER_PROCEDURE,
                "source_file": safe_name(path),
                "subject_count": len(loaded),
                "domain_version": document.get("domain_version"),
            }
        )
        subjects.extend(loaded)

    if not subjects:
        raise InputError("the supplied Domain analyses contain no diagnostic subject")

    groups = [analyze_subject(subject, index) for index, subject in enumerate(subjects, start=1)]

    unbound = [
        {
            "source_domain": subject.source_domain,
            "source_instance_id": subject.reference,
            "subject_type": subject.subject_type,
            "reason": "no evidence-safe cross-subject link is authorized; the subject is analyzed independently",
        }
        for subject in subjects
        if subject.association_strength not in STRONG_LINK_STRENGTHS
    ]

    ambiguities = [
        {
            "diagnostic_group_reference": group["diagnostic_group_reference"],
            "type": "AMBIGUOUS_FIRST_BOUNDARY",
            "description": "several eligible candidates share the earliest frame",
        }
        for group in groups
        if group["boundary_selection_status"] == STATUS_AMBIGUOUS
    ]

    limitations = list(ANALYSIS_LIMITATIONS)
    if any(group["boundary_candidates_omitted"] for group in groups):
        limitations.append(
            "At least one diagnostic group reports omitted Domain deviations; those groups cannot "
            "establish an earliest boundary."
        )
    if len({group["subject_type"] for group in groups}) > 1:
        limitations.append(
            "EPS Attach, EPC session-control and EPS default-bearer subjects are reported as "
            "independent diagnostic groups; no Attach-to-session, Attach-to-bearer or "
            "session-to-bearer association is asserted."
        )

    summary = {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "input_provenance": provenance,
        "source_domain_versions": sorted(versions),
        "diagnostic_groups": groups,
        "unbound_domain_analyses": unbound,
        "ambiguities": ambiguities,
        "limitations": limitations,
        "additional_evidence_needed": [
            {
                "requirement": "a reviewed identity bridge between Attach and GTPv2-C evidence",
                "reason": "the accepted Domains publish attach_association as NOT_ESTABLISHED",
            },
            {
                "requirement": "a reviewed SGW-C identity observation for S11 to S5/S8 association",
                "reason": "the accepted Session-Control Domain publishes cross_interface_association as NOT_ESTABLISHED",
            },
        ],
        "not_confirmed": list(NOT_CONFIRMED),
    }
    return sanitize_output(summary)


def group_summary(analysis: dict[str, Any]) -> dict[str, Any]:
    """Compact status summary used by unified-report projections."""
    statuses: dict[str, int] = {}
    for group in analysis.get("diagnostic_groups") or []:
        status = str(group.get("boundary_selection_status"))
        statuses[status] = statuses.get(status, 0) + 1
    return {
        "group_count": len(analysis.get("diagnostic_groups") or []),
        "status_counts": statuses,
        "selected_count": statuses.get(STATUS_SELECTED, 0),
        "ambiguous_count": statuses.get(STATUS_AMBIGUOUS, 0),
        "insufficient_count": statuses.get(STATUS_INSUFFICIENT, 0),
        "no_abnormal_count": statuses.get(STATUS_NONE, 0),
    }
