#!/usr/bin/env python3
"""Validate the standalone sbi-http2 Protocol Skill contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import py_compile
import re
import sys
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from implementation_policy import IMPLEMENTATION_TOKEN_PATTERN

SKILL = Path("skills/protocol/sbi-http2")
REQUIRED = (
    "SKILL.md",
    "README.md",
    "manifest.yaml",
    "references/protocol-model.md",
    "references/http2-model.md",
    "references/sbi-model.md",
    "references/nsmf-pdusession.md",
    "references/namf-communication.md",
    "references/field-reference.md",
    "references/multipart-model.md",
    "references/privacy.md",
    "references/correlation.md",
    "references/failure-cases.md",
    "scripts/sbi_model.py",
    "scripts/extract-sbi-http2.py",
    "scripts/correlate-sbi-http2.py",
    "scripts/sbi_timeline.py",
    "schemas/sbi-http2-event.schema.json",
    "schemas/sbi-http2-correlation.schema.json",
    "schemas/trace-event.schema.json",
    "filters/wireshark.txt",
    "examples/extracted/create-sm-context.jsonl",
    "examples/extracted/update-sm-context.jsonl",
    "examples/extracted/release-sm-context.jsonl",
    "examples/extracted/namf-transfer.jsonl",
    "examples/extracted/namf-failure-notification.jsonl",
    "examples/extracted/namf-multipart-ambiguity.jsonl",
    "examples/extracted/namf-error-handling.jsonl",
    "examples/extracted/multipart-binding.jsonl",
    "examples/extracted/stream-isolation.jsonl",
    "examples/extracted/transactions.jsonl",
    "examples/extracted/error-handling.jsonl",
    "examples/extracted/recognition.jsonl",
    "examples/extracted/privacy.jsonl",
    "examples/extracted/malformed.jsonl",
    "examples/expected/create-sm-context-events.jsonl",
    "examples/expected/update-sm-context-events.jsonl",
    "examples/expected/release-sm-context-events.jsonl",
    "examples/expected/namf-transfer-events.jsonl",
    "examples/expected/namf-transfer-correlation.json",
    "examples/expected/namf-failure-notification-events.jsonl",
    "examples/expected/namf-failure-notification-correlation.json",
    "examples/expected/namf-multipart-ambiguity-events.jsonl",
    "examples/expected/namf-error-handling-events.jsonl",
    "examples/expected/multipart-binding-events.jsonl",
    "examples/expected/stream-isolation-events.jsonl",
    "examples/expected/stream-isolation-correlation.json",
    "examples/expected/transactions-events.jsonl",
    "examples/expected/transactions-correlation.json",
    "examples/expected/error-handling-events.jsonl",
    "examples/expected/recognition-events.jsonl",
    "examples/expected/privacy-events.jsonl",
    "tests/test_sbi_http2.py",
)
EXPECTED_EVENTS = (
    "examples/expected/create-sm-context-events.jsonl",
    "examples/expected/update-sm-context-events.jsonl",
    "examples/expected/release-sm-context-events.jsonl",
    "examples/expected/namf-transfer-events.jsonl",
    "examples/expected/namf-failure-notification-events.jsonl",
    "examples/expected/namf-multipart-ambiguity-events.jsonl",
    "examples/expected/namf-error-handling-events.jsonl",
    "examples/expected/multipart-binding-events.jsonl",
    "examples/expected/stream-isolation-events.jsonl",
    "examples/expected/transactions-events.jsonl",
    "examples/expected/error-handling-events.jsonl",
    "examples/expected/recognition-events.jsonl",
    "examples/expected/privacy-events.jsonl",
)
ABSOLUTE_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]+users[\\/]|(?:^|[\s\"'])/(?:home|users)/)")
IMPLEMENTATION_ASSET = re.compile(
    IMPLEMENTATION_TOKEN_PATTERN +
    r"|openairinterface|srsran|ueransim|nokia|ericsson|huawei|zte|(?:upf|gnb|smf|amf)\.(?:c|cc|cpp|h|go|py)\b"
)
SUBSCRIBER_FIELD = re.compile(r"(?i)[\"']?(?:imsi|msisdn|suci|supi|gpsi|pei)[\"']?\s*[:=]")
SECRET_FIELD = re.compile(r"(?i)[\"']?(?:password|passwd|secret|api[_-]?key|private[_-]?key|token)[\"']?\s*[:=]\s*[\"'][^\"']{6,}")
LIFECYCLE_MARKER = re.compile(r"(?i)\bphase\s+[0-9]+\b|\bmilestone\s+b?[0-9]+\b")

# Protocol and architecture boundary anti-patterns in scripts
RAW_FRAME_PARSER = re.compile(r"(?i)struct\.unpack|int\.from_bytes|bytes\.fromhex|memoryview\(|def\s+parse_http2_frame")
HPACK_DECODER = re.compile(r"(?i)\bhpack\.HpackDecoder\b|def\s+(?:decode_hpack|hpack_decode)\b|\bhpack\.decode\b")
TLS_DECRYPTION = re.compile(r"(?i)ssl\.create_default_context|tls_decrypt|decrypt_tls|sslkeylog|def\s+decrypt_ssl")
NAS_DECODER = re.compile(r"(?i)\b(?:decode_nas|nas_decoder|dissect_nas|decode_n1_sm)\b")
NGAP_DECODER = re.compile(r"(?i)\b(?:decode_ngap|ngap_decoder|dissect_ngap|decode_n2_sm)\b")
PFCP_OR_GTPU_JOIN = re.compile(r"(?i)\b(?:f_teid_join|match_pfcp|match_gtpu|pfcp_f_teid|gtpu_teid|teid_forwarding)\b")
DOMAIN_VERDICT = re.compile(r"(?i)\b(?:pdu_session_success|smf_failure|session_established|session_released)\b")
RAW_BODY_PERSISTENCE = re.compile(r"(?i)[\x22\x27]?(?:raw_body|raw_payload|payload_bytes|binary_bytes)[\x22\x27]?\]?\s*[:=]\s*[^=]")
TOKEN_PERSISTENCE = re.compile(r"(?i)[\x22\x27]?(?:authorization_token|bearer_token|access_token)[\x22\x27]?\]?\s*[:=]\s*[\x22\x27][^=]")
MULTIPART_ZIP = re.compile(r"(?i)\bzip\(\s*(?:parts|n1|n2|content_id)")

IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
DOC_IPV4_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
TEXT_SUFFIXES = {".md", ".py", ".yaml", ".json", ".jsonl", ".txt"}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_value(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else None


def manifest_list(text: str, key: str) -> list[str]:
    inline = re.search(rf"(?m)^{re.escape(key)}:\s*\[([^\]]*)\]", text)
    if inline is not None:
        return [item.strip() for item in inline.group(1).split(",") if item.strip()]
    lines: list[str] = []
    in_section = False
    for line in text.splitlines():
        if re.match(rf"^{re.escape(key)}:\s*$", line):
            in_section = True
            continue
        if in_section:
            match = re.match(r"^\s*-\s*(.+?)\s*$", line)
            if match:
                lines.append(match.group(1).strip())
            elif line and not line.startswith(" "):
                break
    return lines


def jsonl_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    skill = root / SKILL
    if not skill.is_dir():
        return [f"missing Skill directory: {SKILL}"]
    for relative in REQUIRED:
        if not (skill / relative).is_file():
            errors.append(f"missing required package file: {relative}")
    if errors:
        return errors

    manifest = (skill / "manifest.yaml").read_text(encoding="utf-8")
    for key, expected in (("name", "sbi-http2"), ("version", "0.2.1"), ("category", "protocol")):
        if manifest_value(manifest, key) != expected:
            errors.append(f"manifest {key} must be {expected}")
    if not re.search(r"(?m)^\s*required:\s*\[\]\s*$", manifest):
        errors.append("manifest must not require another CoreNet Skill")
    protocols = manifest_list(manifest, "protocols")
    if "HTTP/2" not in protocols or "3GPP-SBI" not in protocols:
        errors.append("manifest protocols must include HTTP/2 and 3GPP-SBI")
    interfaces = manifest_list(manifest, "interfaces")
    if interfaces != ["N11"]:
        errors.append("manifest interface ownership must be N11 only")
    if manifest_value(manifest, "network_functions") not in (None, "[]"):
        errors.append("manifest network_functions must stay empty for a Protocol Skill")

    model_text = (skill / "scripts" / "sbi_model.py").read_text(encoding="utf-8")
    if "FieldSpec" not in model_text:
        errors.append("sbi_model.py must implement FieldSpec compatibility model")
    if "resolve_field_specs" not in model_text:
        errors.append("sbi_model.py must provide resolve_field_specs")

    local_trace = skill / "schemas" / "trace-event.schema.json"
    shared_trace = root / "shared" / "schemas" / "trace-event.schema.json"
    if not shared_trace.is_file() or digest(local_trace) != digest(shared_trace):
        errors.append("package-local trace schema must match the authoritative shared schema bytes")

    try:
        event_schema = json.loads((skill / "schemas" / "sbi-http2-event.schema.json").read_text(encoding="utf-8"))
        required = event_schema.get("required", [])
        expected_fields = (
            "timestamp",
            "frame_number",
            "capture_file",
            "connection",
            "http2",
            "sbi",
            "session_management",
            "privacy",
            "multipart_parts",
            "problem_details",
            "transport_error",
            "support_status",
            "result",
            "evidence",
            "derivations",
            "limitations",
        )
        for key in expected_fields:
            if key not in required:
                errors.append(f"sbi-http2-event schema must require {key}")
        properties = event_schema.get("properties", {})
        if properties.get("evidence", {}).get("properties", {}).get("level", {}).get("const") != "OBSERVED":
            errors.append("sbi-http2-event schema evidence.level must stay OBSERVED")
    except json.JSONDecodeError as exc:
        errors.append(f"sbi-http2-event schema is invalid JSON: {exc}")

    try:
        correlation_schema = json.loads(
            (skill / "schemas" / "sbi-http2-correlation.schema.json").read_text(encoding="utf-8")
        )
        corr_required = correlation_schema.get("required", [])
        for key in ("capture_file", "transactions", "open_transactions", "unbound_events", "limitations"):
            if key not in corr_required:
                errors.append(f"sbi-http2-correlation schema must require {key}")
    except json.JSONDecodeError as exc:
        errors.append(f"sbi-http2-correlation schema is invalid JSON: {exc}")

    create_present = False
    update_present = False
    release_present = False
    namf_transfer_present = False
    namf_failure_present = False
    n1n2_transfer_ref_present = False
    n1n2_accepted_pending_present = False
    problem_details_present = False
    multipart_present = False
    stream_isolation_present = False
    transport_error_present = False
    tls_unavailable_present = False
    privacy_redaction_present = False

    observed_stream_contexts: dict[int, set[str]] = {}

    for relative in EXPECTED_EVENTS:
        try:
            events = jsonl_records(skill / relative)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"expected fixture is invalid: {relative}: {exc}")
            continue

        for event in events:
            # Output events must NEVER contain raw subscriber identifiers
            for id_field in ("supi", "gpsi", "pei", "imsi", "msisdn"):
                if id_field in event or id_field in (event.get("session_management") or {}):
                    errors.append(f"unredacted subscriber field {id_field} in expected fixture {relative}")

            sbi = event.get("sbi") or {}
            op = sbi.get("operation")
            if op == "CreateSMContext":
                create_present = True
            elif op == "UpdateSMContext":
                update_present = True
            elif op == "ReleaseSMContext":
                release_present = True
            elif op == "N1N2MessageTransfer":
                namf_transfer_present = True
            elif op == "N1N2TransferFailureNotification":
                namf_failure_present = True

            if sbi.get("n1n2_transfer_ref") is not None:
                n1n2_transfer_ref_present = True

            if event.get("result") == "N1N2_TRANSFER_ACCEPTED_PENDING":
                n1n2_accepted_pending_present = True

            if event.get("problem_details") is not None:
                problem_details_present = True

            mp_parts = event.get("multipart_parts")
            if isinstance(mp_parts, list) and len(mp_parts) > 0:
                multipart_present = True

            h2 = event.get("http2") or {}
            stream_id = h2.get("stream_id")
            conn = event.get("connection") or {}
            ctx_key = conn.get("connection_id") or conn.get("tcp_stream")
            if stream_id is not None and ctx_key is not None:
                observed_stream_contexts.setdefault(stream_id, set()).add(str(ctx_key))

            path_str = str(h2.get("path") or "")
            res_str = str(sbi.get("resource") or "")
            loc_str = str((sbi.get("selected_headers") or {}).get("location") or "")
            for raw_leak in re.finditer(r"/ue-contexts/(?!\{ueContextId\})(?!ctx-)[^/]+", f"{path_str} {res_str} {loc_str}"):
                errors.append(f"unredacted subscriber identity in path/resource in {relative}: {raw_leak.group(0)}")

            trans = event.get("transport_error") or {}
            if trans.get("type") in ("RST_STREAM", "GOAWAY"):
                transport_error_present = True

            if event.get("result") == "PAYLOAD_UNAVAILABLE":
                tls_unavailable_present = True

            priv = event.get("privacy") or {}
            if priv.get("subscriber_identity_present") is True:
                privacy_redaction_present = True

    for stream_id, ctxs in observed_stream_contexts.items():
        if len(ctxs) >= 2:
            stream_isolation_present = True

    for flag, message in (
        (create_present, "at least one expected fixture must contain CreateSMContext"),
        (update_present, "at least one expected fixture must contain UpdateSMContext"),
        (release_present, "at least one expected fixture must contain ReleaseSMContext"),
        (namf_transfer_present, "at least one expected fixture must contain N1N2MessageTransfer"),
        (namf_failure_present, "at least one expected fixture must contain N1N2TransferFailureNotification"),
        (n1n2_transfer_ref_present, "at least one expected fixture must contain n1n2_transfer_ref"),
        (n1n2_accepted_pending_present, "at least one expected fixture must contain N1N2_TRANSFER_ACCEPTED_PENDING result"),
        (problem_details_present, "at least one expected fixture must contain ProblemDetails"),
        (multipart_present, "at least one expected fixture must contain multipart evidence"),
        (stream_isolation_present, "at least one expected fixture must contain stream isolation across connections"),
        (transport_error_present, "at least one expected fixture must contain HTTP/2 transport errors"),
        (tls_unavailable_present, "at least one expected fixture must contain TLS unavailable limitation"),
        (privacy_redaction_present, "at least one expected fixture must contain redacted subscriber identity"),
    ):
        if not flag:
            errors.append(message)

    for path in skill.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if path.suffix.lower() in CAPTURE_SUFFIXES:
            errors.append(f"binary capture fixture is not allowed: {relative}")
        if path.suffix in TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8")
            if "../../../" in text or "third_party/" in text:
                errors.append(f"repository-root runtime reference in {relative}")
            if ABSOLUTE_PATH.search(text):
                errors.append(f"absolute workstation path in {relative}")
            if IMPLEMENTATION_ASSET.search(text):
                errors.append(f"implementation mapping asset or reference in {relative}")
            if LIFECYCLE_MARKER.search(text):
                errors.append(f"lifecycle marker must stay in task coordination, not the repository: {relative}")
            if path.parent.name == "scripts":
                if RAW_FRAME_PARSER.search(text):
                    errors.append(f"a manual HTTP/2 binary frame parser must not appear in {relative}")
                if HPACK_DECODER.search(text):
                    errors.append(f"an HPACK decoder implementation must not appear in {relative}")
                if TLS_DECRYPTION.search(text):
                    errors.append(f"TLS decryption or key handling must not appear in {relative}")
                if NAS_DECODER.search(text):
                    errors.append(f"NAS decoding logic must not appear in {relative}")
                if NGAP_DECODER.search(text):
                    errors.append(f"NGAP decoding logic must not appear in {relative}")
                if PFCP_OR_GTPU_JOIN.search(text):
                    errors.append(f"PFCP or GTP-U join logic must not appear in {relative}")
                if DOMAIN_VERDICT.search(text):
                    errors.append(f"complete PDU Session domain verdicts must not appear in {relative}")
                if RAW_BODY_PERSISTENCE.search(text):
                    errors.append(f"raw JSON body or binary persistence must not appear in {relative}")
                if TOKEN_PERSISTENCE.search(text):
                    errors.append(f"Authorization token persistence must not appear in {relative}")
                if MULTIPART_ZIP.search(text):
                    errors.append(f"multipart positional zip must not appear in {relative}")
            if path.name == "sbi_model.py":
                if "sbi-tx:" not in text or "conn_ctx" not in text:
                    errors.append("transaction key must scope stream ID by connection context")
            if path.parent.name in {"extracted", "expected"}:
                if SECRET_FIELD.search(text):
                    errors.append(f"credential-like material in fixture {relative}")
                for match in IPV4.finditer(text):
                    if not match.group(0).startswith(DOC_IPV4_PREFIXES):
                        errors.append(f"non-documentation IP address {match.group(0)} in fixture {relative}")
                        break
            if path.parent.name == "extracted" and path.name != "privacy.jsonl":
                if SUBSCRIBER_FIELD.search(text):
                    errors.append(f"subscriber identity field in non-privacy fixture {relative}")

    for directory, label in ((skill / "scripts", "script"), (skill / "tests", "test")):
        for script in directory.glob("*.py"):
            try:
                py_compile.compile(str(script), doraise=True)
            except py_compile.PyCompileError as exc:
                errors.append(f"{label} does not compile: {script.name}: {exc.msg}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate(args.root.resolve())
    if errors:
        print("sbi-http2 validation failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print("sbi-http2 validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
