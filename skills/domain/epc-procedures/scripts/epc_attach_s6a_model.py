#!/usr/bin/env python3
"""Bounded EPS Attach and Diameter S6a/S6d joint evidence model.

Consumes accepted producer outputs only. It never decodes packets, re-correlates
Diameter transactions, alters Attach verdicts, or invents a per-UE identity.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

try:
    import jsonschema
except ImportError:  # pragma: no cover - the strict schema gate is optional locally
    jsonschema = None

ANALYSIS_NAME = "epc-attach-s6a"
ANALYSIS_VERSION = "1.0.0"
DOMAIN = "epc-procedures"

SCHEMA_DIRECTORY = Path(__file__).resolve().parents[1] / "schemas"
PROTOCOL_SKILLS_DIRECTORY = Path(__file__).resolve().parents[3] / "protocol"
ATTACH_SCHEMA_PATH = SCHEMA_DIRECTORY / "epc-attach-analysis.schema.json"
DIAMETER_EPC_SCHEMA_PATH = (
    PROTOCOL_SKILLS_DIRECTORY / "diameter-epc" / "schemas" / "diameter-epc-analysis.schema.json"
)

MANIFEST_NAME = "epc-attach-s6a-coordinated-run"
MANIFEST_SCHEMA_VERSION = "1.0.0"
MANIFEST_PRODUCER_ROLES = ("attach", "diameter_core", "diameter_epc")

MAX_ATTACH_INSTANCES = 128
MAX_DIAMETER_OBSERVATIONS = 256
MAX_TIMELINE_ROWS = 512

DIAMETER_STATUSES = {"MATCHED", "OPEN_REQUEST", "RESPONSE_ONLY", "AMBIGUOUS"}
ATTACH_INCOMPLETE_STAGES = {"INCOMPLETE", "UNAVAILABLE_PROTECTED"}
_SHA256_LENGTH = 64
_SCHEMA_CACHE: dict[Path, dict[str, Any]] = {}


class InputError(Exception):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError(f"{path.name} could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise InputError(f"{path.name} is not a JSON object")
    return value


def _require(container: dict[str, Any], fields: tuple[str, ...], label: str) -> None:
    for field in fields:
        if field not in container:
            raise InputError(f"{label} is missing required field: {field}")


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def strict_schema_available() -> bool:
    """Report whether the accepted source schemas can be enforced in this runtime."""
    return jsonschema is not None and hasattr(jsonschema, "Draft202012Validator")


def _validate_source_schema(document: dict[str, Any], schema_path: Path, label: str) -> None:
    """Reject an artifact that violates the schema it declares, when the gate is available."""
    if not strict_schema_available():
        return
    schema = _SCHEMA_CACHE.get(schema_path)
    if schema is None:
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise InputError(f"{label} schema could not be read: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise InputError(f"{label} schema is not valid JSON: {exc}") from exc
        _SCHEMA_CACHE[schema_path] = schema
    try:
        jsonschema.Draft202012Validator(schema).validate(document)
    except jsonschema.ValidationError as exc:
        location = "/".join(str(item) for item in exc.absolute_path) or "<root>"
        raise InputError(f"{label} violates its accepted schema at {location}: {exc.message}") from exc


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _frame(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def validate_attach(analysis: dict[str, Any]) -> None:
    _validate_source_schema(analysis, ATTACH_SCHEMA_PATH, "attach analysis")
    _require(
        analysis,
        ("domain", "domain_version", "model_version", "procedure_instances", "instance_count", "input_provenance"),
        "attach analysis",
    )
    if not isinstance(analysis["procedure_instances"], list):
        raise InputError("attach procedure_instances must be an array")
    if analysis["instance_count"] != len(analysis["procedure_instances"]):
        raise InputError("attach instance_count disagrees with procedure_instances")
    for instance in analysis["procedure_instances"]:
        if not isinstance(instance, dict):
            raise InputError("attach procedure instance must be an object")
        _require(
            instance,
            ("procedure_reference", "attempt_index", "first_frame", "last_frame", "stages", "observations", "deviations"),
            "attach instance",
        )
        if not isinstance(instance["stages"], list) or not isinstance(instance["observations"], list) or not isinstance(instance["deviations"], list):
            raise InputError("attach instance stage/observation/deviation collections must be arrays")
        for stage in instance["stages"]:
            if not isinstance(stage, dict) or not isinstance(stage.get("stage_id"), str):
                raise InputError("attach stage is malformed")
            if stage.get("status") not in {"OBSERVED", "INCOMPLETE", "NOT_OBSERVED", "UNAVAILABLE_PROTECTED"}:
                raise InputError("attach stage status is unsupported")
        for observation in instance["observations"]:
            if not isinstance(observation, dict) or not isinstance(observation.get("protocol"), str):
                raise InputError("attach observation is malformed")


def validate_diameter(analysis: dict[str, Any]) -> None:
    _validate_source_schema(analysis, DIAMETER_EPC_SCHEMA_PATH, "diameter EPC analysis")
    _require(
        analysis,
        ("analysis_name", "analysis_version", "domain", "input_provenance", "observations", "completeness"),
        "diameter EPC analysis",
    )
    if analysis["analysis_name"] != "diameter-epc":
        raise InputError("diameter EPC analysis_name is not diameter-epc")
    if not isinstance(analysis["observations"], list):
        raise InputError("diameter EPC observations must be an array")
    seen: set[str] = set()
    transactions: set[str] = set()
    for observation in analysis["observations"]:
        if not isinstance(observation, dict):
            raise InputError("diameter EPC observation must be an object")
        _require(
            observation,
            (
                "observation_reference",
                "procedure",
                "command_code",
                "message_status",
                "transaction_status",
                "application_result",
                "authentication_information",
                "request",
                "answer",
                "transaction_reference",
                "result",
            ),
            "diameter observation",
        )
        reference = observation["observation_reference"]
        if reference in seen:
            raise InputError("duplicate diameter observation reference")
        seen.add(reference)
        transaction = observation["transaction_reference"]
        if not isinstance(transaction, str) or not transaction.startswith("diameter-tx:"):
            raise InputError("diameter observation lacks an accepted Core transaction reference")
        if transaction in transactions:
            raise InputError("duplicate diameter transaction reference in application output")
        transactions.add(transaction)
        status = observation["transaction_status"]
        if status not in DIAMETER_STATUSES:
            raise InputError("diameter observation transaction_status is unsupported")
        request = observation["request"]
        answer = observation["answer"]
        if status == "MATCHED":
            if not isinstance(request, dict) or not isinstance(answer, dict):
                raise InputError("MATCHED diameter observation lacks request or answer")
        elif status == "OPEN_REQUEST":
            if not isinstance(request, dict) or answer is not None:
                raise InputError("OPEN_REQUEST diameter observation has invalid references")
        elif status == "RESPONSE_ONLY":
            if request is not None or not isinstance(answer, dict):
                raise InputError("RESPONSE_ONLY diameter observation has invalid references")
        elif status == "AMBIGUOUS":
            if request is not None or not isinstance(answer, dict) or not _list(observation.get("response_candidates")):
                raise InputError("AMBIGUOUS diameter observation lacks candidates")
        for item in (request, answer):
            if item is None:
                continue
            if not isinstance(item, dict) or not isinstance(item.get("event_reference"), str):
                raise InputError("diameter source reference is malformed")
            if not str(item["event_reference"]).startswith("diameter-event:"):
                raise InputError("diameter source reference is not an accepted Core event reference")
            if _frame(item.get("frame_number")) is None:
                raise InputError("diameter source reference has no valid frame number")
            occurrence = item.get("message_occurrence")
            if not isinstance(occurrence, int) or isinstance(occurrence, bool) or occurrence < 1:
                raise InputError("diameter source reference has no valid message occurrence")


def _stage_summary(instance: dict[str, Any]) -> tuple[dict[str, int], int, int, str]:
    counts = {"OBSERVED": 0, "INCOMPLETE": 0, "NOT_OBSERVED": 0, "UNAVAILABLE_PROTECTED": 0}
    for stage in instance.get("stages") or []:
        counts[stage["status"]] += 1
    observed = counts["OBSERVED"]
    incomplete = counts["INCOMPLETE"] + counts["UNAVAILABLE_PROTECTED"]
    if observed and not incomplete:
        status = "OBSERVED"
    elif observed or incomplete:
        status = "INCOMPLETE"
    else:
        status = "INCOMPLETE"
    return counts, observed, incomplete, status


def _attach_inventory(analysis: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    for instance in analysis["procedure_instances"]:
        counts, observed, incomplete, status = _stage_summary(instance)
        records.append(
            {
                "procedure_reference": instance["procedure_reference"],
                "attempt_index": instance["attempt_index"],
                "first_frame": _frame(instance.get("first_frame")),
                "last_frame": _frame(instance.get("last_frame")),
                "association": _dict(instance.get("association")),
                "stage_summary": counts,
                "observed_stage_count": observed,
                "incomplete_stage_count": incomplete,
                "deviation_count": len(instance.get("deviations") or []),
                "status": status,
                "evidence_limitations": _list(instance.get("evidence_limitations")),
                "source_reference": f"attach:{instance['procedure_reference']}",
            }
        )
    omitted = max(0, len(records) - MAX_ATTACH_INSTANCES)
    return records[:MAX_ATTACH_INSTANCES], omitted


def _diameter_inventory(analysis: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    for observation in analysis["observations"]:
        result = _dict(observation.get("result"))
        message = observation.get("request") or observation.get("answer") or {}
        records.append(
            {
                "observation_reference": observation["observation_reference"],
                "procedure": observation["procedure"],
                "command_code": observation["command_code"],
                "application_id": message.get("application_id"),
                "message_status": observation["message_status"],
                "transaction_status": observation["transaction_status"],
                "transaction_reference": observation["transaction_reference"],
                "request": observation["request"],
                "answer": observation["answer"],
                "response_candidates": _list(observation.get("response_candidates")),
                "result": {
                    "core_result_status": result.get("core_result_status"),
                    "namespace_status": result.get("namespace_status"),
                    "application_result": observation["application_result"],
                    "base_result_code": result.get("base_result_code"),
                    "base_result_code_name": result.get("base_result_code_name"),
                    "experimental_result_code": result.get("experimental_result_code"),
                    "experimental_result_code_name": result.get("experimental_result_code_name"),
                    "experimental_vendor_id": result.get("experimental_vendor_id"),
                },
                "authentication_information": observation["authentication_information"],
                "latency_seconds": observation.get("latency_seconds") if observation["transaction_status"] == "MATCHED" else None,
                "limitations": _list(observation.get("limitations")),
                "privacy_status": "REDACTED_PRESENCE_ONLY",
            }
        )
    omitted = max(0, len(records) - MAX_DIAMETER_OBSERVATIONS)
    return records[:MAX_DIAMETER_OBSERVATIONS], omitted


def _timeline(
    attach: dict[str, Any],
    diameter_records: list[dict[str, Any]],
    *,
    verified_capture: bool,
) -> tuple[list[dict[str, Any]], int, str]:
    rows: list[dict[str, Any]] = []
    for instance in attach["procedure_instances"]:
        for observation in instance.get("observations") or []:
            frame = _frame(observation.get("frame_number"))
            if frame is None:
                continue
            rows.append(
                {
                    "family": "EPS_ATTACH",
                    "protocol": observation["protocol"],
                    "frame_number": frame,
                    "message_occurrence": None,
                    "event_type": observation.get("message_type"),
                    "procedure": instance["procedure_reference"],
                    "source_reference": f"attach-observation:{instance['procedure_reference']}:{frame}",
                    "transaction_reference": None,
                    "result": None,
                    "status": observation.get("procedure_stage"),
                }
            )
    for record in diameter_records:
        for side in ("request", "answer"):
            reference = record.get(side)
            if not isinstance(reference, dict):
                continue
            rows.append(
                {
                    "family": "DIAMETER_S6A",
                    "protocol": "Diameter",
                    "frame_number": reference["frame_number"],
                    "message_occurrence": reference["message_occurrence"],
                    "event_type": f"{record['procedure']} {side.upper()}",
                    "procedure": record["observation_reference"],
                    "source_reference": reference["event_reference"],
                    "transaction_reference": record["transaction_reference"],
                    "result": {
                        "namespace_status": record["result"].get("namespace_status"),
                        "base_result_code": record["result"].get("base_result_code"),
                        "experimental_result_code": record["result"].get("experimental_result_code"),
                    },
                    "status": record["transaction_status"],
                }
            )
    dedup: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        key = (
            row["family"],
            row["frame_number"],
            row["message_occurrence"],
            row["source_reference"],
            row["event_type"],
        )
        dedup[key] = row
    ordered = list(dedup.values())
    if verified_capture:
        ordered.sort(
            key=lambda item: (
                item["frame_number"],
                item["message_occurrence"] or 0,
                item["family"],
                item["source_reference"],
            )
        )
        ordering = "VERIFIED_COMMON_CAPTURE"
    else:
        ordered.sort(key=lambda item: (item["family"], item["frame_number"], item["source_reference"]))
        ordering = "SOURCE_LOCAL_ONLY"
    omitted = max(0, len(ordered) - MAX_TIMELINE_ROWS)
    return ordered[:MAX_TIMELINE_ROWS], omitted, ordering


def _association_status(attach_count: int, diameter_count: int) -> dict[str, Any]:
    if not attach_count or not diameter_count:
        status = "NOT_APPLICABLE"
    else:
        status = "INSUFFICIENT_EVIDENCE"
    return {
        "scope": "ATTACH_TO_DIAMETER",
        "status": status,
        "basis": [],
        "established_pair_count": 0,
        "ambiguous_pair_count": 0,
        "candidate_pairs": [],
        "candidates_omitted": 0,
        "limitations": [
            "observation of EPS Attach and S6a/S6d in one capture does not prove that they belong to the same subscriber or Attach attempt",
            "privacy-safe Diameter projections publish no IMSI, User-Name, Session-Id value or authentication vector that could bridge identity",
            "no timestamp, endpoint, node-name, message-count or ordering relationship is promoted to identity evidence",
        ],
        "required_evidence": [
            "an independently reviewed identity bridge binding one Attach S1AP UE context to one S6a/S6d subscriber context",
            "authorization for the exact identity evidence class, separate from privacy-safe Diameter projections",
        ],
    }


def _diagnostics(
    attach: dict[str, Any], diameter_records: list[dict[str, Any]]
) -> dict[str, Any]:
    failures = [
        record for record in diameter_records
        if record["result"]["application_result"] == "FAILURE_REPORTED"
    ]
    open_ambiguous = [
        record for record in diameter_records
        if record["transaction_status"] in {"OPEN_REQUEST", "AMBIGUOUS"}
    ]
    latencies = [
        record["latency_seconds"] for record in diameter_records
        if record["transaction_status"] == "MATCHED" and record["latency_seconds"] is not None
    ]
    attach_deviation_frames = sorted(
        {
            observation.get("frame_number")
            for instance in attach["procedure_instances"]
            for deviation in (instance.get("deviations") or [])
            for observation in [deviation]
            if _frame(observation.get("frame_number")) is not None
        }
    )
    diameter_abnormal_frames = sorted(
        {
            (record.get("answer") or record.get("request") or {}).get("frame_number")
            for record in failures + open_ambiguous
            if _frame((record.get("answer") or record.get("request") or {}).get("frame_number")) is not None
        }
    )
    return {
        "attach_instance_count": attach["instance_count"],
        "attach_incomplete_instance_count": sum(
            1 for instance in attach["procedure_instances"] if _stage_summary(instance)[3] == "INCOMPLETE"
        ),
        "attach_deviation_count": sum(len(instance.get("deviations") or []) for instance in attach["procedure_instances"]),
        "diameter_observation_count": len(diameter_records),
        "diameter_matched_count": sum(1 for record in diameter_records if record["transaction_status"] == "MATCHED"),
        "diameter_failure_reported_count": len(failures),
        "diameter_open_or_ambiguous_count": len(open_ambiguous),
        "diameter_returned_latency_count": len(latencies),
        "earliest_attach_deviation_frame": attach_deviation_frames[0] if attach_deviation_frames else None,
        "earliest_diameter_abnormal_frame": diameter_abnormal_frames[0] if diameter_abnormal_frames else None,
        "cross_protocol_attribution_established": False,
        "root_cause_inferred": False,
    }


def _load_and_validate_manifest(manifest: dict[str, Any]) -> set[str]:
    """Validate a coordinated-run manifest and return the producers it declares executed."""
    _require(
        manifest,
        (
            "manifest_name",
            "manifest_schema_version",
            "coordinated_run_id",
            "capture",
            "artifacts",
            "producers",
            "executed_invocations",
        ),
        "coordinated run manifest",
    )
    if manifest["manifest_name"] != MANIFEST_NAME:
        raise InputError("coordinated run manifest_name is not accepted")
    if manifest["manifest_schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise InputError("coordinated run manifest_schema_version is not accepted")
    run_id = manifest["coordinated_run_id"]
    if not isinstance(run_id, str) or not run_id.strip():
        raise InputError("coordinated run manifest has no run identifier")
    capture = manifest["capture"]
    if not isinstance(capture, dict):
        raise InputError("coordinated run manifest capture is malformed")
    _require(capture, ("file", "sha256"), "coordinated run manifest capture")
    if not isinstance(capture["file"], str) or not capture["file"]:
        raise InputError("coordinated run manifest capture has no file identity")
    if not _is_sha256(capture["sha256"]):
        raise InputError("coordinated run manifest capture digest is malformed")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict):
        raise InputError("coordinated run manifest artifacts are malformed")
    for role in ("attach", "diameter_epc"):
        artifact = artifacts.get(role)
        if not isinstance(artifact, dict):
            raise InputError(f"coordinated run manifest has no {role} artifact entry")
        _require(artifact, ("file", "sha256", "producer"), f"manifest {role} artifact")
        if not isinstance(artifact["file"], str) or not artifact["file"]:
            raise InputError(f"manifest {role} artifact has no file identity")
        if not _is_sha256(artifact["sha256"]):
            raise InputError(f"manifest {role} artifact digest is malformed")
        if not isinstance(artifact["producer"], str) or not artifact["producer"]:
            raise InputError(f"manifest {role} artifact has no producer identity")
    producers = manifest["producers"]
    if not isinstance(producers, dict):
        raise InputError("coordinated run manifest producers are malformed")
    for role in MANIFEST_PRODUCER_ROLES:
        identity = producers.get(role)
        if not isinstance(identity, str) or not identity:
            raise InputError(f"coordinated run manifest has no {role} producer identity")
    invocations = manifest["executed_invocations"]
    if not isinstance(invocations, list) or not invocations:
        raise InputError("coordinated run manifest lists no executed producer invocation")
    executed: set[str] = set()
    for invocation in invocations:
        if not isinstance(invocation, dict):
            raise InputError("coordinated run manifest invocation is malformed")
        _require(invocation, ("producer", "capture_sha256"), "manifest invocation")
        producer = invocation["producer"]
        if not isinstance(producer, str) or not producer:
            raise InputError("coordinated run manifest invocation has no producer")
        if invocation["capture_sha256"] != capture["sha256"]:
            raise InputError(
                "coordinated run manifest invocation capture digest disagrees with the run capture"
            )
        executed.add(producer)
    return executed


def _provenance(
    attach_path: Path,
    diameter_path: Path,
    attach: dict[str, Any],
    diameter: dict[str, Any],
    capture: Path | None,
    manifest: dict[str, Any] | None,
    manifest_path: Path | None,
) -> dict[str, Any]:
    attach_digest = sha256_file(attach_path)
    diameter_digest = sha256_file(diameter_path)
    diameter_captures = _dict(diameter.get("input_provenance")).get("capture_files") or []
    attach_captures = {
        _dict(instance.get("association")).get("capture_file")
        for instance in attach.get("procedure_instances") or []
        if isinstance(_dict(instance.get("association")).get("capture_file"), str)
    }
    diameter_capture = (
        Path(diameter_captures[0]).name
        if len(diameter_captures) == 1 and isinstance(diameter_captures[0], str)
        else None
    )
    if diameter_capture is not None and attach_captures and diameter_capture not in attach_captures:
        raise InputError(
            "Attach source capture identity contradicts the Diameter EPC capture identity"
        )
    if capture is not None and diameter_capture is not None and capture.name != diameter_capture:
        raise InputError("supplied capture filename contradicts the Diameter EPC capture identity")
    if capture is not None and attach_captures and capture.name not in attach_captures:
        raise InputError("supplied capture filename contradicts the Attach source capture identity")

    filename_match = bool(diameter_capture) and diameter_capture in attach_captures
    capture_digest = sha256_file(capture) if capture is not None else None
    coordinated_run: dict[str, Any] | None = None

    if manifest is not None:
        executed = _load_and_validate_manifest(manifest)
        declared_producers = {
            manifest["producers"][role] for role in MANIFEST_PRODUCER_ROLES
        }
        verified_producers = sorted(executed & declared_producers)
        verified = False
        if capture is None:
            status = "DECLARED_PROVENANCE_UNVERIFIED"
            basis = ["run_manifest_declared", "capture_digest_not_observed"]
        else:
            if capture_digest != manifest["capture"]["sha256"]:
                raise InputError(
                    "coordinated run manifest capture digest contradicts the supplied capture"
                )
            if attach_digest != manifest["artifacts"]["attach"]["sha256"]:
                raise InputError(
                    "coordinated run manifest Attach artifact digest does not match the supplied artifact"
                )
            if diameter_digest != manifest["artifacts"]["diameter_epc"]["sha256"]:
                raise InputError(
                    "coordinated run manifest Diameter EPC artifact digest does not match the supplied artifact"
                )
            missing = sorted(declared_producers - executed)
            if missing:
                status = "DECLARED_PROVENANCE_UNVERIFIED"
                basis = [
                    "coordinated_run_manifest",
                    "manifest_capture_digest_match",
                    "declared_producer_invocation_missing",
                ]
            else:
                verified = True
                status = "VERIFIED_COORDINATED_CAPTURE_CONTEXT"
                basis = [
                    "coordinated_run_manifest",
                    "manifest_capture_digest_match",
                    "manifest_artifact_digest_match",
                    "controlled_producer_invocations",
                ]
        coordinated_run = {
            "run_id": manifest["coordinated_run_id"],
            "manifest_file": manifest_path.name if manifest_path is not None else None,
            "manifest_sha256": sha256_file(manifest_path) if manifest_path is not None else None,
            "producer_identities": {
                role: manifest["producers"][role] for role in MANIFEST_PRODUCER_ROLES
            },
            "verified_producers": verified_producers,
            "verification_basis": "DIGEST_BOUND_RUN_MANIFEST" if verified else "DECLARED_ONLY",
        }
        capture_observed = capture is not None
        artifacts_bound = verified
        capture_file = (
            capture.name
            if capture is not None
            else Path(manifest["capture"]["file"]).name
        )
    else:
        capture_observed = capture is not None
        artifacts_bound = False
        capture_file = diameter_capture
        if capture is None and filename_match:
            status = "FILENAME_MATCH_ONLY"
            basis = ["filename_equality"]
        elif capture is None:
            status = "UNVERIFIED"
            basis = []
        else:
            status = "CAPTURE_HASH_OBSERVED_UNBOUND"
            basis = ["supplied_capture_sha256", "artifacts_not_bound_to_capture"]
            if filename_match:
                basis.insert(1, "single_capture_filename_match")

    return {
        "capture": {"file": capture_file, "sha256": capture_digest},
        "attach_artifact": {
            "file": attach_path.name,
            "sha256": attach_digest,
            "domain": attach.get("domain"),
            "domain_version": attach.get("domain_version"),
            "model_version": attach.get("model_version"),
            "instance_count": attach.get("instance_count"),
        },
        "diameter_artifact": {
            "file": diameter_path.name,
            "sha256": diameter_digest,
            "analysis_name": diameter.get("analysis_name"),
            "analysis_version": diameter.get("analysis_version"),
            "observation_count": len(diameter.get("observations") or []),
            "capture_files": diameter_captures,
        },
        "common_capture": {
            "status": status,
            "basis": basis,
            "capture_digest_observed": capture_observed,
            "artifacts_bound_to_capture": artifacts_bound,
            "coordinated_run": coordinated_run,
        },
    }


def analyze(
    attach: dict[str, Any],
    diameter: dict[str, Any],
    *,
    attach_path: Path,
    diameter_path: Path,
    capture: Path | None,
    run_manifest: dict[str, Any] | None = None,
    run_manifest_path: Path | None = None,
) -> dict[str, Any]:
    validate_attach(attach)
    validate_diameter(diameter)
    provenance = _provenance(
        attach_path, diameter_path, attach, diameter, capture, run_manifest, run_manifest_path
    )
    attach_records, attach_omitted = _attach_inventory(attach)
    diameter_records, diameter_omitted = _diameter_inventory(diameter)
    verified = provenance["common_capture"]["status"] == "VERIFIED_COORDINATED_CAPTURE_CONTEXT"
    timeline, timeline_omitted, ordering = _timeline(attach, diameter_records, verified_capture=verified)
    association = _association_status(len(attach_records), len(diameter_records))
    diagnostics = _diagnostics(attach, diameter_records)
    limitations = [
        "the joint analysis does not re-decode, re-correlate or re-verdict either source",
        "a shared timeline is ordering evidence only, not proof of causation or shared UE identity",
        "a matched Diameter transaction and an EPS Attach instance remain independent unless reviewed identity evidence establishes a bridge",
        "a slow Diameter exchange is not automatically the first causal failure boundary",
    ]
    if not verified:
        limitations.append(
            "a capture digest identifies the supplied capture only; it does not prove that the "
            "supplied analysis artifacts were generated from those capture bytes"
        )
    if not strict_schema_available():
        limitations.append(
            "source artifacts were checked against structural contracts only because the JSON "
            "Schema validation dependency is unavailable in this runtime"
        )
    return {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "domain": DOMAIN,
        "analysis_scope": "bounded EPS Attach and Diameter S6a/S6d joint evidence",
        "input_provenance": provenance,
        "attach_inventory": attach_records,
        "attach_instances_omitted": attach_omitted,
        "diameter_inventory": diameter_records,
        "diameter_observations_omitted": diameter_omitted,
        "timeline": timeline,
        "timeline_rows_omitted": timeline_omitted,
        "timeline_ordering": ordering,
        "identity_association": association,
        "diagnostics": diagnostics,
        "limitations": limitations,
        "not_confirmed": [
            "per-UE association between any Attach instance and any S6a/S6d transaction is not established",
            "AIA success does not prove EPS-AKA completion or EPS Attach success",
            "ULA completion does not prove Attach completion or subscriber authorization",
            "no root cause is inferred from ordering or latency",
        ],
    }