#!/usr/bin/env python3
"""Standalone tests for the bounded EPC session-identity bridge capability.

Covers the mandatory structured cases: hop-local identity (A), cross-interface
bridges (B), Delete Session binding (C), identity and completeness (D) and the
unified invariance cases that are expressible against this capability (E), plus
the lifecycle session-context closure integration.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
CLI = SCRIPTS / "analyze_epc_session_identity.py"
LIFECYCLE_CLI = SCRIPTS / "analyze_epc_bearer_lifecycle.py"

sys.path.insert(0, str(SCRIPTS))
import epc_session_identity_model as model  # noqa: E402
import epc_bearer_lifecycle_model as lifecycle_model  # noqa: E402

CAPTURE_A = "capture-a.pcap"
CAPTURE_B = "capture-b.pcap"

MME = "10.0.0.1"
SGW = "10.0.0.2"
PGW = "10.0.0.3"
SGW_S1U = "10.0.0.20"
ENB_S1U = "10.0.0.40"
PGW_U = "10.0.0.30"

ESTABLISHED = "ESTABLISHED"
SUPPORTED = "SUPPORTED"
AMBIGUOUS = "AMBIGUOUS"
NOT_ESTABLISHED = "NOT_ESTABLISHED"


def fteid(interface_type: int, teid: int, address: str) -> dict:
    return {"scope": "message", "interface_type": interface_type, "teid": teid, "ipv4": address}


def bearer_fteid(interface_type: int, teid: int, address: str) -> dict:
    return {"scope": "bearer", "interface_type": interface_type, "teid": teid, "ipv4": address}


def bearer_context(ebi: int, teids: list[dict], cause: int | None = None) -> dict:
    return {
        "ebi": ebi,
        "cause": {"cause_code": cause, "cause_name": "Request accepted", "scope": "bearer"}
        if cause is not None
        else None,
        "f_teids": teids,
    }


def event(
    frame: int,
    message: str,
    family: str,
    *,
    src: str,
    dst: str,
    teid: int = 0,
    seq: int = 1,
    cause: int | None = None,
    fteids: list[dict] | None = None,
    contexts: list[dict] | None = None,
    capture: str = CAPTURE_A,
    occurrence: int = 0,
    unbound_ebi: list[int] | None = None,
) -> dict:
    return {
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "frame_number": frame,
        "message_occurrence": occurrence,
        "capture_file": capture,
        "protocol": "GTPv2-C",
        "transport": "UDP",
        "message_type": message,
        "message_type_code": 0,
        "procedure_family": family,
        "message_family": family,
        "support_status": "SUPPORTED",
        "hierarchy_basis": "test",
        "header": {
            "teid": teid,
            "sequence_number": seq,
            "teid_state": "PRESENT" if teid else "ZERO",
        },
        "message_cause": (
            {"cause_code": cause, "cause_name": "Request accepted", "scope": "message"}
            if cause is not None
            else None
        ),
        "information_elements": [],
        "identity_ies": [],
        "f_teids": fteids or [],
        "bearer_contexts": contexts or [],
        "unbound_ie_metadata": (
            {"binding_basis": "test", "ebi_values": unbound_ebi, "limitations": []}
            if unbound_ebi is not None
            else []
        ),
        "ie_summary": [],
        "extraction_limitations": [],
        "evidence": {},
        "derivations": {},
        "source": {"address": src, "port": 2123},
        "destination": {"address": dst, "port": 2123},
    }


def tx_message(frame: int, message: str, *, teid: int, seq: int) -> dict:
    return {
        "frame_number": frame,
        "header_teid": teid,
        "header_teid_state": "PRESENT" if teid else "ZERO",
        "message_type": message,
        "message_type_code": 0,
        "sequence_number": seq,
    }


def transaction(
    reference: str,
    family: str,
    request: tuple[int, str, int, int],
    response: tuple[int, str, int, int] | None,
    *,
    status: str = "MATCHED",
    strength: str = "STRONG",
    retransmissions: list[tuple[int, str, int, int]] | None = None,
) -> dict:
    response_message = (
        tx_message(response[0], response[1], teid=response[2], seq=response[3])
        if response
        else None
    )
    return {
        "transaction_reference": reference,
        "procedure_family": family,
        "message_family": family,
        "request": tx_message(request[0], request[1], teid=request[2], seq=request[3]),
        "response": response_message,
        "response_candidates": [response_message] if response_message else [],
        "correlation_status": status,
        "correlation_strength": strength,
        "correlation_basis": ["request/response message identity"],
        "corroboration": {"teid_echo": True},
        "retransmissions": [
            tx_message(item[0], item[1], teid=item[2], seq=item[3])
            for item in retransmissions or []
        ],
        "observation_window": {
            "start_frame": request[0],
            "end_frame": response[0] if response else request[0],
        },
        "evidence_refs": [
            tx_message(request[0], request[1], teid=request[2], seq=request[3])
        ]
        + ([response_message] if response_message else []),
        "limitations": [],
    }


def tx_document(*transactions: dict, captures: tuple[str, ...] = (CAPTURE_A,)) -> dict:
    return {
        "protocol": "gtpv2",
        "capture_files": list(captures),
        "transaction_count": len(transactions),
        "matched_count": sum(1 for item in transactions if item["correlation_status"] == "MATCHED"),
        "open_request_count": sum(
            1 for item in transactions if item["correlation_status"] == "OPEN_REQUEST"
        ),
        "response_only_count": sum(
            1 for item in transactions if item["correlation_status"] == "RESPONSE_ONLY"
        ),
        "ambiguous_count": sum(
            1 for item in transactions if item["correlation_status"] == "AMBIGUOUS"
        ),
        "transactions": list(transactions),
    }


def build_session(
    sink_events: list[dict],
    sink_transactions: dict,
    sid: str,
    *,
    capture: str = CAPTURE_A,
    frame: int = 100,
    seq: int = 1,
    sgw_cteid: int = 14,
    pgw_cteid: int = 5,
    mme: str = MME,
    sgw: str = SGW,
    pgw: str = PGW,
    sgw_s1u_address: str = SGW_S1U,
    enb_s1u_address: str = ENB_S1U,
    pgw_user_address: str = PGW_U,
    pgw_user_teid: int = 54,
    gen_sgw_teid: int = 56,
    gen_enb_teid: int = 16777736,
    relay_interface: int = 7,
    s5_relay_interface: int | None = 7,
    s11_relay: bool = True,
    ebi: int = 5,
    create_cause: int | None = 16,
    delete_cause: int | None = 16,
    modify: bool = True,
    deletes: bool = True,
    delete_header_teid: int | None = None,
    modify_enb_teid: int | None = None,
) -> dict:
    """One complete session: S11/S5 create, optional modify, optional deletes.

    ``sink_transactions`` is a transaction document; new transactions are
    appended to its ``transactions`` list and the capture is registered.
    """
    if capture not in sink_transactions["capture_files"]:
        sink_transactions["capture_files"].append(capture)
        sink_transactions["capture_files"].sort()
    modify_enb_teid = gen_enb_teid if modify_enb_teid is None else modify_enb_teid
    delete_teid = sgw_cteid if delete_header_teid is None else delete_header_teid

    def ev(frame_, message_, family_, **kwargs):
        kwargs.setdefault("capture", capture)
        return event(frame_, message_, family_, **kwargs)

    sink_events.append(
        ev(
            frame,
            "Create Session Request",
            "create-session",
            src=mme,
            dst=sgw,
            teid=0,
            seq=seq,
            fteids=[fteid(10, 1, mme), fteid(relay_interface, 0, pgw)],
        )
    )
    sink_events.append(
        ev(
            frame + 1,
            "Create Session Request",
            "create-session",
            src=sgw,
            dst=pgw,
            teid=0,
            seq=seq + 1,
            fteids=[fteid(6, sgw_cteid, sgw)],
            contexts=[bearer_context(ebi, [bearer_fteid(4, 55, sgw)])],
        )
    )
    sink_events.append(
        ev(
            frame + 2,
            "Create Session Response",
            "create-session",
            src=pgw,
            dst=sgw,
            teid=sgw_cteid,
            seq=seq + 1,
            cause=create_cause,
            fteids=(
                [fteid(s5_relay_interface, pgw_cteid, pgw)]
                if s5_relay_interface is not None
                else []
            ),
            contexts=[bearer_context(ebi, [bearer_fteid(5, pgw_user_teid, pgw_user_address)])],
        )
    )
    sink_events.append(
        ev(
            frame + 3,
            "Create Session Response",
            "create-session",
            src=sgw,
            dst=mme,
            teid=1,
            seq=seq,
            cause=create_cause,
            fteids=(
                [
                    fteid(11, sgw_cteid, sgw),
                    fteid(relay_interface, pgw_cteid, pgw),
                ]
                if s11_relay
                else [fteid(11, sgw_cteid, sgw)]
            ),
            contexts=[
                bearer_context(
                    ebi,
                    [
                        bearer_fteid(1, gen_sgw_teid, sgw_s1u_address),
                        bearer_fteid(5, pgw_user_teid, pgw_user_address),
                    ],
                )
            ],
        )
    )
    if modify:
        sink_events.append(
            ev(
                frame + 10,
                "Modify Bearer Request",
                "modify-bearer",
                src=mme,
                dst=sgw,
                teid=sgw_cteid,
                seq=seq + 2,
                contexts=[bearer_context(ebi, [bearer_fteid(0, gen_enb_teid, enb_s1u_address)])],
            )
        )
        sink_events.append(
            ev(
                frame + 11,
                "Modify Bearer Response",
                "modify-bearer",
                src=sgw,
                dst=mme,
                teid=1,
                seq=seq + 2,
                cause=create_cause,
                contexts=[bearer_context(ebi, [bearer_fteid(0, gen_enb_teid, enb_s1u_address)])],
            )
        )
    if deletes:
        sink_events.append(
            ev(
                frame + 20,
                "Delete Session Request",
                "delete-session",
                src=mme,
                dst=sgw,
                teid=delete_teid,
                seq=seq + 3,
                unbound_ebi=[ebi],
            )
        )
        sink_events.append(
            ev(
                frame + 21,
                "Delete Session Response",
                "delete-session",
                src=sgw,
                dst=mme,
                teid=1,
                seq=seq + 3,
                cause=delete_cause,
            )
        )
        sink_events.append(
            ev(
                frame + 22,
                "Delete Session Request",
                "delete-session",
                src=sgw,
                dst=pgw,
                teid=pgw_cteid,
                seq=seq + 4,
                unbound_ebi=[ebi],
            )
        )
        sink_events.append(
            ev(
                frame + 23,
                "Delete Session Response",
                "delete-session",
                src=pgw,
                dst=sgw,
                teid=sgw_cteid,
                seq=seq + 4,
                cause=delete_cause,
            )
        )
    sink_transactions["transactions"].append(
        transaction(
            f"s11-create-{sid}",
            "create-session",
            (frame, "Create Session Request", 0, seq),
            (frame + 3, "Create Session Response", 1, seq),
        )
    )
    sink_transactions["transactions"].append(
        transaction(
            f"s5-create-{sid}",
            "create-session",
            (frame + 1, "Create Session Request", 0, seq + 1),
            (frame + 2, "Create Session Response", sgw_cteid, seq + 1),
        )
    )
    if modify:
        sink_transactions["transactions"].append(
            transaction(
                f"modify-{sid}",
                "modify-bearer",
                (frame + 10, "Modify Bearer Request", sgw_cteid, seq + 2),
                (frame + 11, "Modify Bearer Response", 1, seq + 2),
            )
        )
    if deletes:
        sink_transactions["transactions"].append(
            transaction(
                f"s11-delete-{sid}",
                "delete-session",
                (frame + 20, "Delete Session Request", delete_teid, seq + 3),
                (frame + 21, "Delete Session Response", 1, seq + 3),
            )
        )
        sink_transactions["transactions"].append(
            transaction(
                f"s5-delete-{sid}",
                "delete-session",
                (frame + 22, "Delete Session Request", pgw_cteid, seq + 4),
                (frame + 23, "Delete Session Response", sgw_cteid, seq + 4),
            )
        )
    return {
        "s11_context_members": [f"s11-create-{sid}", f"modify-{sid}", f"s11-delete-{sid}"],
        "s5_context_members": [f"s5-create-{sid}", f"s5-delete-{sid}"],
        "s11_delete_reference": f"s11-delete-{sid}",
        "s5_delete_reference": f"s5-delete-{sid}",
    }


def base_document() -> tuple[list[dict], dict]:
    events: list[dict] = []
    transactions = tx_document()
    build_session(events, transactions, "a", frame=100, seq=1, sgw_cteid=14, pgw_cteid=5)
    return events, transactions


def analyze_events(events: list[dict], transactions: dict, **kwargs) -> dict:
    return model.analyze(events, transactions=transactions, **kwargs)


class SessionIdentityTestCase(unittest.TestCase):
    def analyze(self, events: list[dict], transactions: dict, **kwargs) -> dict:
        return analyze_events(events, transactions, **kwargs)

    def base(self) -> tuple[list[dict], dict]:
        return base_document()

    def write_inputs(self, tmp: Path, events: list[dict], transactions: dict) -> tuple[Path, Path]:
        events_path = tmp / "events.jsonl"
        transactions_path = tmp / "transactions.json"
        events_path.write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in events),
            encoding="utf-8",
        )
        transactions_path.write_text(
            json.dumps(transactions, sort_keys=True), encoding="utf-8"
        )
        return events_path, transactions_path

    def run_identity(self, tmp: Path, events_path: Path, transactions_path: Path) -> Path:
        identity_output = tmp / "identity.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(CLI),
                "--gtpv2",
                str(events_path),
                "--transactions",
                str(transactions_path),
                "--output",
                str(identity_output),
                "--force",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return identity_output

    def run_lifecycle(
        self, tmp: Path, events_path: Path, transactions_path: Path, identity_path: Path | None
    ) -> tuple[int, dict | None]:
        output = tmp / "lifecycle.json"
        command = [
            sys.executable,
            str(LIFECYCLE_CLI),
            "--gtpv2",
            str(events_path),
            "--transactions",
            str(transactions_path),
            "--output",
            str(output),
            "--force",
        ]
        if identity_path is not None:
            command.extend(["--session-identity", str(identity_path)])
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        analysis = json.loads(output.read_text(encoding="utf-8")) if output.exists() else None
        return completed.returncode, analysis

# ---------------------------------------------------------------------------
# A — hop-local identity
# ---------------------------------------------------------------------------
class HopLocalIdentityTests(SessionIdentityTestCase):
    def a01_s11_context(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        s11 = [c for c in result["hop_local_contexts"] if c["interface_class"] == "S11"]
        self.assertEqual(len(s11), 1)
        self.assertEqual(s11[0]["association_status"], ESTABLISHED)
        self.assertEqual(
            s11[0]["association_basis"],
            "proved_allocation_transaction_with_unique_hop_local_control_plane_fteids",
        )
        self.assertEqual(
            s11[0]["member_transaction_references"],
            ["s11-create-a", "modify-a", "s11-delete-a"],
        )

    def test_a01_s11_context_with_unique_control_plane_evidence_is_supported(self) -> None:
        self.a01_s11_context()

    def test_a02_s5s8_context_with_unique_control_plane_evidence_is_supported(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        s5 = [c for c in result["hop_local_contexts"] if c["interface_class"] == "S5/S8"]
        self.assertEqual(len(s5), 1)
        self.assertEqual(s5[0]["association_status"], ESTABLISHED)
        self.assertEqual(s5[0]["member_transaction_references"], ["s5-create-a", "s5-delete-a"])

    def test_a03_same_numeric_header_teid_on_different_receiving_endpoints_does_not_join(self) -> None:
        events, transactions = self.base()
        # A second session whose PGW S5-C F-TEID reuses the value 14: the S11
        # delete addresses (14, SGW) and must never join that S5/S8 context.
        build_session(
            events,
            transactions,
            "b",
            frame=500,
            seq=11,
            sgw_cteid=15,
            pgw_cteid=14,
        )
        result = self.analyze(events, transactions)
        bindings = {
            item["source_subject_reference"]: item
            for item in result["release_session_bindings"]
        }
        self.assertEqual(bindings["s11-delete-a"]["association_status"], ESTABLISHED)
        self.assertEqual(bindings["s5-delete-b"]["association_status"], ESTABLISHED)
        s11_contexts = {
            c["session_context_reference"]
            for c in result["hop_local_contexts"]
            if c["interface_class"] == "S11"
        }
        self.assertIn(bindings["s11-delete-a"]["target_subject_reference"], s11_contexts)

    def test_a04_same_header_teid_across_captures_does_not_join(self) -> None:
        events, transactions = self.base()
        # Another capture reuses every TEID value; the contexts stay
        # capture-scoped and no binding crosses the capture boundary.
        build_session(
            events,
            transactions,
            "b",
            capture=CAPTURE_B,
            frame=700,
            seq=11,
            sgw_cteid=14,
            pgw_cteid=9,
        )
        result = self.analyze(events, transactions)
        contexts_by_capture: dict[str, int] = {}
        for context in result["hop_local_contexts"]:
            contexts_by_capture[context["capture_file"]] = (
                contexts_by_capture.get(context["capture_file"], 0) + 1
            )
        self.assertEqual(contexts_by_capture, {CAPTURE_A: 2, CAPTURE_B: 2})
        for binding in result["release_session_bindings"]:
            self.assertEqual(binding["association_status"], ESTABLISHED)
            context = next(
                item
                for item in result["hop_local_contexts"]
                if item["session_context_reference"] == binding["target_subject_reference"]
            )
            self.assertEqual(context["capture_file"], binding["capture_file"])

    def test_a05_same_header_teid_in_two_competing_contexts_remains_ambiguous(self) -> None:
        events, transactions = self.base()
        # A second S11 allocation claiming exactly the same control-plane
        # F-TEID (same TEID, same addresses): the delete joins neither.
        build_session(
            events, transactions, "b", frame=500, seq=11, sgw_cteid=14, pgw_cteid=9
        )
        result = self.analyze(events, transactions)
        binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s11-delete-a"
        )
        self.assertEqual(binding["association_status"], AMBIGUOUS)
        self.assertEqual(len(binding["competing_candidates"]), 2)
        self.assertIsNone(binding["target_subject_reference"])
        self.assertGreaterEqual(result["ambiguous_association_count"], 1)

    def test_a06_missing_interface_resolution_prevents_a_proved_hop_local_association(self) -> None:
        events, transactions = self.base()
        # An allocation whose events carry no control-plane F-TEID at all.
        events.append(
            event(
                900,
                "Create Session Request",
                "create-session",
                src=MME,
                dst=SGW,
                teid=0,
                seq=50,
            )
        )
        transactions["transactions"].append(
            transaction(
                "s11-create-orphan",
                "create-session",
                (900, "Create Session Request", 0, 50),
                None,
                status="OPEN_REQUEST",
            )
        )
        result = self.analyze(events, transactions)
        self.assertTrue(
            any(
                item["kind"] == "transaction_insufficient_hop_evidence"
                for item in result["unbound_evidence"]
            )
        )
        self.assertFalse(
            any(
                context["allocation_transaction_reference"] == "s11-create-orphan"
                for context in result["hop_local_contexts"]
            )
        )

    def test_a07_control_plane_fteid_interface_types_are_checked(self) -> None:
        events, transactions = self.base()
        # The S11 context relays the PGW F-TEID (7, 5, PGW); the S5 delete
        # addresses that F-TEID but must join only the S5/S8 context, never the
        # S11 context through the relayed foreign-interface record.
        result = self.analyze(events, transactions)
        binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s5-delete-a"
        )
        self.assertEqual(binding["association_status"], ESTABLISHED)
        context = next(
            item
            for item in result["hop_local_contexts"]
            if item["session_context_reference"] == binding["target_subject_reference"]
        )
        self.assertEqual(context["interface_class"], "S5/S8")

    def test_a08_request_response_direction_remains_correct(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        # The responses all carry header TEID 1 addressed to the MME; they are
        # never treated as requests, so no ambiguity arises from the shared MME
        # F-TEID even though every context publishes it.
        self.assertEqual(result["ambiguous_association_count"], 0)
        for context in result["hop_local_contexts"]:
            for member in context["member_transactions"]:
                self.assertIn(member["join_basis"], (
                    "member_of_the_context_through_its_allocation_transaction",
                    "member_of_the_context_through_receiver_scoped_addressing",
                ))

    def test_a09_repeated_transaction_advertisement_does_not_create_a_second_context(self) -> None:
        events, transactions = self.base()
        events.append(
            event(
                104,
                "Create Session Request",
                "create-session",
                src=MME,
                dst=SGW,
                teid=0,
                seq=1,
                fteids=[fteid(10, 1, MME), fteid(7, 0, PGW)],
                occurrence=1,
            )
        )
        for item in transactions["transactions"]:
            if item["transaction_reference"] == "s11-create-a":
                item["retransmissions"].append(
                    tx_message(104, "Create Session Request", teid=0, seq=1)
                )
        result = self.analyze(events, transactions)
        self.assertEqual(result["hop_local_context_count"], 2)
        s11 = [c for c in result["hop_local_contexts"] if c["interface_class"] == "S11"]
        self.assertEqual(len(s11), 1)
        self.assertEqual(len(s11[0]["member_transactions"]), 3)

    def test_a10_reused_teid_after_a_proved_context_release_does_not_merge(self) -> None:
        events, transactions = self.base()
        # A later allocation reusing the released control TEID value stays a
        # separate context; the earlier release can no longer uniquely address
        # its own context, so the binding fails closed instead of merging.
        build_session(
            events, transactions, "b", frame=500, seq=11, sgw_cteid=14, pgw_cteid=9
        )
        result = self.analyze(events, transactions)
        s11 = [c for c in result["hop_local_contexts"] if c["interface_class"] == "S11"]
        self.assertEqual(len(s11), 2)
        self.assertNotEqual(
            s11[0]["session_context_reference"], s11[1]["session_context_reference"]
        )
        binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s11-delete-a"
        )
        self.assertEqual(binding["association_status"], AMBIGUOUS)
        self.assertEqual(len(binding["competing_candidates"]), 2)


# ---------------------------------------------------------------------------
# B — cross-interface bridge
# ---------------------------------------------------------------------------
class CrossInterfaceBridgeTests(SessionIdentityTestCase):
    def test_b01_unique_relayed_fteid_establishes_the_bridge(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        identities = result["session_identity_links"]
        self.assertEqual(len(identities), 1)
        self.assertEqual(identities[0]["association_status"], ESTABLISHED)
        self.assertEqual(
            identities[0]["association_basis"],
            "relayed_pgw_s5s8_control_plane_fteid_equal_and_unique_on_both_hops",
        )
        self.assertEqual(
            identities[0]["reviewed_identifiers"],
            [
                {
                    "kind": "relayed_control_plane_fteid",
                    "interface_type": 7,
                    "teid": 5,
                    "address": PGW,
                    "scope": "message",
                }
            ],
        )
        self.assertEqual(
            sorted(identities[0]["source_transaction_references"]),
            ["s11-create-a", "s5-create-a"],
        )

    def test_b02_shared_ebi_alone_cannot_establish_a_bridge(self) -> None:
        events, transactions = self.base()
        # Both sessions carry EBI 5; their relayed F-TEIDs differ, so no
        # cross-interface session identity may be published between them.
        build_session(
            events, transactions, "b", frame=500, seq=11, sgw_cteid=15, pgw_cteid=6
        )
        result = self.analyze(events, transactions)
        self.assertEqual(result["session_identity_count"], 2)
        contexts = {
            item["session_context_reference"]: item for item in result["hop_local_contexts"]
        }
        for identity in result["session_identity_links"]:
            self.assertEqual(identity["association_status"], ESTABLISHED)
            self.assertEqual(
                contexts[identity["source_subject_reference"]]["interface_class"], "S11"
            )
            self.assertEqual(
                contexts[identity["target_subject_reference"]]["interface_class"], "S5/S8"
            )
            self.assertEqual(
                contexts[identity["source_subject_reference"]][
                    "allocation_transaction_reference"
                ].rsplit("-", 1)[-1],
                contexts[identity["target_subject_reference"]][
                    "allocation_transaction_reference"
                ].rsplit("-", 1)[-1],
            )

    def test_b03_shared_control_plane_teid_alone_cannot_establish_a_bridge(self) -> None:
        events, transactions = self.base()
        # The S5/S8 SGW GTP-C F-TEID reuses the S11 value 14, but the relayed
        # PGW F-TEIDs differ, so the shared control TEID bridges nothing.
        build_session(
            events, transactions, "b", frame=500, seq=11, sgw_cteid=14, pgw_cteid=6
        )
        result = self.analyze(events, transactions)
        # The shared SGW control TEID value 14 bridges nothing: each session's
        # identity link rests only on its own relayed PGW F-TEID and pairs
        # same-session contexts.
        self.assertEqual(result["session_identity_count"], 2)
        contexts = {
            item["session_context_reference"]: item for item in result["hop_local_contexts"]
        }
        for identity in result["session_identity_links"]:
            self.assertEqual(identity["association_status"], ESTABLISHED)
            self.assertEqual(
                contexts[identity["source_subject_reference"]]["interface_class"], "S11"
            )
            self.assertEqual(
                contexts[identity["target_subject_reference"]]["interface_class"], "S5/S8"
            )
            self.assertEqual(
                contexts[identity["source_subject_reference"]][
                    "allocation_transaction_reference"
                ].rsplit("-", 1)[-1],
                contexts[identity["target_subject_reference"]][
                    "allocation_transaction_reference"
                ].rsplit("-", 1)[-1],
            )
        triple = result["session_identity_links"][0]["reviewed_identifiers"][0]
        self.assertEqual((triple["interface_type"], triple["teid"], triple["address"]), (7, 5, PGW))

    def test_b04_shared_s1u_endpoint_alone_cannot_establish_session_identity(self) -> None:
        events, transactions = self.base()
        # The bearer user-plane F-TEID is equal on both hops, but the S11
        # response carries no relayed control-plane F-TEID, so the only
        # cross-interface evidence is the endpoint correspondence.
        for item in events:
            if item["frame_number"] == 103:
                item["f_teids"] = [fteid(11, 14, SGW)]
        result = self.analyze(events, transactions)
        correspondences = result["endpoint_correspondence_links"]
        self.assertEqual(len(correspondences), 1)
        self.assertEqual(correspondences[0]["association_status"], SUPPORTED)
        self.assertEqual(
            sum(
                1
                for item in result["session_identity_links"]
                if item["association_status"] == ESTABLISHED
            ),
            0,
        )
        self.assertEqual(result["session_identity_count"], 0)

    def test_b05_shared_cause_16_cannot_establish_a_bridge(self) -> None:
        events, transactions = self.base()
        build_session(
            events, transactions, "b", frame=500, seq=11, sgw_cteid=15, pgw_cteid=6
        )
        result = self.analyze(events, transactions)
        # Every message carries Cause 16, yet only the relayed F-TEID equality
        # pairs the hops: exactly one identity link per session, never more.
        self.assertEqual(result["session_identity_count"], 2)

    def test_b06_timestamp_proximity_cannot_establish_a_bridge(self) -> None:
        events, transactions = self.base()
        # All events share one timestamp; the only pairing evidence is the
        # relayed F-TEID, not the clock.
        for item in events:
            item["timestamp"] = "2026-01-01T00:00:00.000000Z"
        result = self.analyze(events, transactions)
        self.assertEqual(
            sum(
                1
                for item in result["session_identity_links"]
                if item["association_status"] == ESTABLISHED
            ),
            1,
        )

    def test_b07_two_competing_s5s8_candidates_remain_ambiguous(self) -> None:
        events, transactions = self.base()
        # Two S5/S8 allocations publish the same PGW F-TEID; the S11 relay
        # cannot choose between them.
        build_session(events, transactions, "b", frame=500, seq=11, sgw_cteid=15, pgw_cteid=5)
        result = self.analyze(events, transactions)
        identities = result["session_identity_links"]
        self.assertTrue(identities)
        self.assertTrue(
            all(item["association_status"] == AMBIGUOUS for item in identities)
        )
        for identity in identities:
            self.assertEqual(len(identity["competing_candidates"]), 4)

    def test_b08_conflicting_fteid_roles_prevent_a_bridge(self) -> None:
        events, transactions = self.base()
        # The S5/S8 response publishes its control F-TEID with the SGW's
        # interface type instead of the PGW's, so the relay equality fails.
        for item in events:
            if item["frame_number"] == 102:
                item["f_teids"] = [fteid(6, 5, PGW)]
        result = self.analyze(events, transactions)
        self.assertEqual(result["session_identity_count"], 0)
        self.assertEqual(
            sum(
                1
                for item in result["cross_interface_candidates"]
                if item["association_status"] == ESTABLISHED
            ),
            0,
        )

    def test_b09_cross_capture_association_fails_closed(self) -> None:
        events, transactions = self.base()
        # The same relayed F-TEID appears in another capture's S5/S8 context;
        # bridge evaluation is capture-scoped, so no link crosses captures.
        build_session(
            events,
            transactions,
            "b",
            capture=CAPTURE_B,
            frame=700,
            seq=11,
            sgw_cteid=15,
            pgw_cteid=5,
        )
        result = self.analyze(events, transactions)
        self.assertEqual(result["session_identity_count"], 2)
        for identity in result["session_identity_links"]:
            self.assertEqual(identity["association_status"], ESTABLISHED)
            source = next(
                item
                for item in result["hop_local_contexts"]
                if item["session_context_reference"]
                == identity["source_subject_reference"]
            )
            target = next(
                item
                for item in result["hop_local_contexts"]
                if item["session_context_reference"]
                == identity["target_subject_reference"]
            )
            self.assertEqual(source["capture_file"], target["capture_file"])

    def test_b10_truncated_candidate_lists_cannot_establish_false_uniqueness(self) -> None:
        events, transactions = self.base()
        # A second S5/S8 create whose request frame was never captured: the
        # transaction cannot be bound, so it can never silently complete a
        # candidate set.
        transactions["transactions"].append(
            transaction(
                "s5-create-open",
                "create-session",
                (601, "Create Session Request", 0, 40),
                None,
                status="OPEN_REQUEST",
            )
        )
        result = self.analyze(events, transactions)
        self.assertTrue(
            any(
                "could not be bound" in item for item in result["evidence_limitations"]
            )
        )
        self.assertTrue(
            any(
                item["transaction_reference"] == "s5-create-open"
                for item in result["unbound_evidence"]
            )
        )
        binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s5-delete-a"
        )
        self.assertEqual(binding["association_status"], ESTABLISHED)

    def test_b11_endpoint_correspondence_and_session_identity_remain_separate(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        self.assertEqual(result["endpoint_correspondence_count"], 1)
        self.assertEqual(
            result["endpoint_correspondence_links"][0]["relationship_type"],
            "CROSS_INTERFACE_ENDPOINT_CORRESPONDENCE",
        )
        self.assertEqual(
            result["endpoint_correspondence_links"][0]["association_status"], SUPPORTED
        )
        self.assertEqual(result["session_identity_links"][0]["relationship_type"],
                         "CROSS_INTERFACE_SESSION_IDENTITY")
        self.assertEqual(result["session_identity_links"][0]["association_status"], ESTABLISHED)

    def test_b12_no_circular_or_unsupported_transitive_proof_is_accepted(self) -> None:
        events, transactions = self.base()
        build_session(
            events, transactions, "b", frame=500, seq=11, sgw_cteid=15, pgw_cteid=6
        )
        result = self.analyze(events, transactions)
        contexts = {
            item["session_context_reference"]: item for item in result["hop_local_contexts"]
        }
        for identity in result["session_identity_links"]:
            references = set(identity["source_transaction_references"])
            self.assertEqual(len(references), 2)
            for reference in references:
                self.assertIn(reference, contexts[identity["source_subject_reference"]][
                    "member_transaction_references"
                ] + contexts[identity["target_subject_reference"]][
                    "member_transaction_references"
                ])
        # No identity link spans two different sessions.
        sessions_per_link = [
            len({reference.rsplit("-", 1)[-1] for reference in identity["source_transaction_references"]})
            for identity in result["session_identity_links"]
        ]
        self.assertTrue(all(count == 1 for count in sessions_per_link))


# ---------------------------------------------------------------------------
# C — Delete Session binding
# ---------------------------------------------------------------------------
class DeleteSessionBindingTests(SessionIdentityTestCase):
    def test_c01_matched_strong_response_with_cause_16_retains_accepted(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s11-delete-a"
        )
        self.assertEqual(binding["release_outcome_status"], "ACCEPTED")
        self.assertEqual(binding["release_outcome_basis"], "accepted_cause_in_correlated_response")
        self.assertEqual(binding["association_status"], ESTABLISHED)

    def test_c02_cause_72_is_not_an_accepted_release(self) -> None:
        events, transactions = self.base()
        for item in events:
            if item["frame_number"] == 121:
                item["message_cause"] = {
                    "cause_code": 72,
                    "cause_name": "No resources available",
                    "scope": "message",
                }
        result = self.analyze(events, transactions)
        binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s11-delete-a"
        )
        self.assertEqual(binding["release_outcome_status"], "REJECTED_OBSERVED")
        self.assertEqual(binding["association_status"], ESTABLISHED)
        candidate = next(
            item
            for item in result["generation_closure_candidates"]
            if item["release_transaction_reference"] == "s11-delete-a"
        )
        self.assertEqual(candidate["association_status"], NOT_ESTABLISHED)
        self.assertEqual(candidate["association_basis"], "release_outcome_rejected_observed")

    def test_c03_missing_message_level_cause_leaves_the_outcome_unresolved(self) -> None:
        events, transactions = self.base()
        for item in events:
            if item["frame_number"] == 121:
                item["message_cause"] = None
        result = self.analyze(events, transactions)
        binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s11-delete-a"
        )
        self.assertEqual(binding["release_outcome_status"], "UNRESOLVED")
        candidate = next(
            item
            for item in result["generation_closure_candidates"]
            if item["release_transaction_reference"] == "s11-delete-a"
        )
        self.assertEqual(candidate["association_status"], NOT_ESTABLISHED)
        self.assertEqual(candidate["association_basis"], "release_outcome_unresolved")

    def test_c04_an_accepted_release_can_remain_unbound_to_any_generation(self) -> None:
        events, transactions = self.base()
        # A release whose request addresses a TEID no context publishes.
        for item in events:
            if item["frame_number"] == 120:
                item["header"]["teid"] = 99
        for item in transactions["transactions"]:
            if item["transaction_reference"] == "s11-delete-a":
                item["request"]["header_teid"] = 99
        result = self.analyze(events, transactions)
        binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s11-delete-a"
        )
        self.assertEqual(binding["association_status"], NOT_ESTABLISHED)
        self.assertIsNone(binding["target_subject_reference"])
        self.assertEqual(binding["release_outcome_status"], "ACCEPTED")
        self.assertEqual(result["generation_closure_candidate_count"], 0)

    def test_c05_unique_same_hop_context_evidence_permits_session_level_binding(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        established = [
            item
            for item in result["release_session_bindings"]
            if item["association_status"] == ESTABLISHED
        ]
        self.assertEqual(len(established), 2)
        for binding in established:
            self.assertEqual(
                binding["association_basis"],
                "request_addresses_one_hop_local_control_plane_fteid_with_its_path_peer",
            )
            self.assertEqual(len(binding["competing_candidates"]), 0)

    def test_c06_header_teid_1_reused_by_competing_contexts_cannot_identify_a_release_owner(self) -> None:
        events, transactions = self.base()
        build_session(
            events, transactions, "b", frame=500, seq=11, sgw_cteid=15, pgw_cteid=9
        )
        build_session(
            events, transactions, "c", frame=900, seq=21, sgw_cteid=16, pgw_cteid=10
        )
        # A release request addressed to the shared MME F-TEID (header TEID 1)
        # matches every S11 context and therefore identifies no owner.
        for item in events:
            if item["frame_number"] == 120:
                item["header"]["teid"] = 1
                item["source"], item["destination"] = (
                    {"address": SGW, "port": 2123},
                    {"address": MME, "port": 2123},
                )
        for item in transactions["transactions"]:
            if item["transaction_reference"] == "s11-delete-a":
                item["request"]["header_teid"] = 1
        result = self.analyze(events, transactions)
        binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s11-delete-a"
        )
        self.assertEqual(binding["association_status"], AMBIGUOUS)
        self.assertEqual(len(binding["competing_candidates"]), 3)

    def test_c07_a_release_from_another_capture_cannot_close_the_local_context(self) -> None:
        events, transactions = self.base()
        build_session(
            events,
            transactions,
            "b",
            capture=CAPTURE_B,
            frame=700,
            seq=11,
            sgw_cteid=14,
            pgw_cteid=5,
        )
        result = self.analyze(events, transactions)
        bindings_a = [
            item
            for item in result["release_session_bindings"]
            if item["capture_file"] == CAPTURE_A
        ]
        self.assertEqual(len(bindings_a), 2)
        for binding in bindings_a:
            self.assertEqual(binding["association_status"], ESTABLISHED)
            context = next(
                item
                for item in result["hop_local_contexts"]
                if item["session_context_reference"] == binding["target_subject_reference"]
            )
            self.assertEqual(context["capture_file"], CAPTURE_A)

    def test_c08_a_release_from_another_interface_cannot_close_the_local_context(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        contexts = {
            item["session_context_reference"]: item for item in result["hop_local_contexts"]
        }
        s11_binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s11-delete-a"
        )
        s5_binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s5-delete-a"
        )
        self.assertEqual(contexts[s11_binding["target_subject_reference"]]["interface_class"], "S11")
        self.assertEqual(contexts[s5_binding["target_subject_reference"]]["interface_class"], "S5/S8")

    def test_c09_uniquely_proved_session_to_generation_association_supports_closure(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        candidates = [
            item
            for item in result["generation_closure_candidates"]
            if item["association_status"] == ESTABLISHED
        ]
        self.assertEqual(len(candidates), 2)
        roles = {item["bearer_endpoint"]["role"] for item in candidates}
        self.assertEqual(roles, {"sgw_s1u", "enodeb_s1u"})
        for candidate in candidates:
            self.assertEqual(
                candidate["release_transaction_reference"], "s11-delete-a"
            )
            self.assertEqual(
                candidate["item_identities"]["release_bearer_identities"], [5]
            )
            self.assertEqual(
                candidate["item_identities"]["endpoint_bearer_identities"], [5]
            )

    def test_c10_one_session_release_cannot_blindly_close_multiple_generations(self) -> None:
        events, transactions = self.base()
        # A second enodeb-side advertisement whose modify transaction cannot be
        # bound (its request frame was never captured): the endpoint stays
        # unbound, no second generation is invented for it, and only the
        # context-owned endpoint can ever close.
        events.append(
            event(
                130,
                "Modify Bearer Request",
                "modify-bearer",
                src=MME,
                dst=SGW,
                teid=14,
                seq=9,
                contexts=[bearer_context(5, [bearer_fteid(0, 999, ENB_S1U)])],
            )
        )
        transactions["transactions"].append(
            transaction(
                "modify-a-second",
                "modify-bearer",
                (140, "Modify Bearer Request", 14, 9),
                None,
                status="OPEN_REQUEST",
            )
        )
        result = self.analyze(events, transactions)
        enodeb_links = [
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "enodeb_s1u"
        ]
        self.assertEqual(len(enodeb_links), 1)
        self.assertEqual(enodeb_links[0]["association_status"], ESTABLISHED)
        # The unbound modify's endpoint never becomes a link, so no second
        # generation is invented for it.
        self.assertTrue(
            any(
                item["kind"] == "endpoint_advertisement_without_accepted_transaction"
                for item in result["unbound_evidence"]
            )
        )
        self.assertFalse(
            any(
                item["bearer_endpoint"]["teid"] == 999
                for item in result["session_to_generation_links"]
            )
        )

    def test_c10b_two_context_owned_endpoints_of_one_role_stay_ambiguous(self) -> None:
        events, transactions = self.base()
        # Both modifies join the same context, so two enodeb endpoints of one
        # role compete and neither may close.
        events.append(
            event(
                130,
                "Modify Bearer Request",
                "modify-bearer",
                src=MME,
                dst=SGW,
                teid=14,
                seq=9,
                contexts=[bearer_context(5, [bearer_fteid(0, 999, ENB_S1U)])],
            )
        )
        events.append(
            event(
                131,
                "Modify Bearer Response",
                "modify-bearer",
                src=SGW,
                dst=MME,
                teid=1,
                seq=9,
                cause=16,
                contexts=[bearer_context(5, [bearer_fteid(0, 999, ENB_S1U)])],
            )
        )
        transactions["transactions"].append(
            transaction(
                "modify-a-second",
                "modify-bearer",
                (130, "Modify Bearer Request", 14, 9),
                (131, "Modify Bearer Response", 1, 9),
            )
        )
        result = self.analyze(events, transactions)
        enodeb_links = [
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "enodeb_s1u"
        ]
        self.assertEqual(len(enodeb_links), 2)
        self.assertTrue(
            all(item["association_status"] == AMBIGUOUS for item in enodeb_links)
        )
        established_candidates = [
            item
            for item in result["generation_closure_candidates"]
            if item["association_status"] == ESTABLISHED
                and item["bearer_endpoint"]["role"] == "enodeb_s1u"
        ]
        self.assertEqual(established_candidates, [])

    def test_c11_request_frame_and_confirmation_frame_remain_distinct(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        for candidate in result["generation_closure_candidates"]:
            if candidate["association_status"] == ESTABLISHED:
                self.assertEqual(candidate["release_request_frame"], 120)
                self.assertEqual(candidate["release_confirmation_frame"], 121)
                self.assertNotEqual(
                    candidate["release_request_frame"],
                    candidate["release_confirmation_frame"],
                )

    def test_c12_release_effective_instant_remains_unproved(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        serialized = json.dumps(result)
        self.assertNotIn("release_effective_frame", serialized)
        self.assertNotIn("forwarding_stopped", serialized)

    def test_c13_no_packet_in_a_pending_release_interval_is_reassigned(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        # The session-identity capability publishes no packet attribution at
        # all; packets inside a pending-release interval are nobody's claim.
        self.assertNotIn("packet", json.dumps(result).lower())
        self.assertNotIn("attributed", json.dumps(result).lower())


# ---------------------------------------------------------------------------
# D — identity and completeness
# ---------------------------------------------------------------------------
class IdentityCompletenessTests(SessionIdentityTestCase):
    def test_d01_ebi_is_scoped_not_globally_unique(self) -> None:
        events, transactions = self.base()
        build_session(
            events, transactions, "b", frame=500, seq=11, sgw_cteid=15, pgw_cteid=6
        )
        result = self.analyze(events, transactions)
        contexts = result["hop_local_contexts"]
        self.assertEqual(len(contexts), 4)
        for context in contexts:
            for record in context["control_plane_fteids"]:
                self.assertNotIn("eps_bearer_identity", record)
        self.assertEqual(result["session_identity_count"], 2)

    def test_d02_s1u_teid_is_scoped_to_the_receiver(self) -> None:
        events, transactions = self.base()
        # A second session reuses the S1-U TEID value 56 at another address.
        build_session(
            events,
            transactions,
            "b",
            frame=500,
            seq=11,
            sgw_cteid=15,
            pgw_cteid=6,
            gen_sgw_teid=56,
            sgw_s1u_address="10.0.0.99",
        )
        result = self.analyze(events, transactions)
        links = [
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["teid"] == 56
        ]
        self.assertEqual(len(links), 2)
        self.assertEqual(
            {item["bearer_endpoint"]["address"] for item in links},
            {SGW_S1U, "10.0.0.99"},
        )

    def test_d03_control_plane_teid_is_scoped_to_hop_and_receiving_endpoint(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        s11 = next(
            item
            for item in result["hop_local_contexts"]
            if item["interface_class"] == "S11"
        )
        s5 = next(
            item
            for item in result["hop_local_contexts"]
            if item["interface_class"] == "S5/S8"
        )
        s11_pairs = {
            (item["interface_type"], item["teid"], item["address"])
            for item in s11["control_plane_fteids"]
            if item["join_capable"]
        }
        s5_pairs = {
            (item["interface_type"], item["teid"], item["address"])
            for item in s5["control_plane_fteids"]
            if item["join_capable"]
        }
        # (11, 14, SGW) and (6, 14, SGW) are different tunnels.
        self.assertIn((11, 14, SGW), s11_pairs)
        self.assertIn((6, 14, SGW), s5_pairs)
        self.assertNotIn((6, 14, SGW), s11_pairs)

    def test_d04_multiple_message_occurrences_in_one_frame_remain_distinct(self) -> None:
        events, transactions = self.base()
        events.append(
            event(
                104,
                "Create Session Request",
                "create-session",
                src=MME,
                dst=SGW,
                teid=0,
                seq=1,
                fteids=[fteid(10, 1, MME), fteid(7, 0, PGW)],
                occurrence=1,
            )
        )
        for item in transactions["transactions"]:
            if item["transaction_reference"] == "s11-create-a":
                item["retransmissions"].append(
                    tx_message(104, "Create Session Request", teid=0, seq=1)
                )
        result = self.analyze(events, transactions)
        self.assertEqual(result["hop_local_context_count"], 2)
        self.assertEqual(result["ambiguous_association_count"], 0)

    def test_d05_different_captures_with_identical_frame_numbers_never_exchange_evidence(self) -> None:
        events, transactions = self.base()
        # Same frame numbers, same TEID values, different captures: evidence
        # identity stays (capture, frame, occurrence) everywhere.
        build_session(
            events,
            transactions,
            "b",
            capture=CAPTURE_B,
            frame=100,
            seq=1,
            sgw_cteid=15,
            pgw_cteid=9,
        )
        result = self.analyze(events, transactions)
        # Two captures carrying identical frame numbers cannot be told apart,
        # so the accepted fail-closed contract binds no transaction at all and
        # nothing joins across the capture boundary.
        self.assertEqual(result["hop_local_context_count"], 0)
        self.assertTrue(
            any(
                "could not be bound" in item for item in result["evidence_limitations"]
            )
        )

    def test_d06_an_ambiguous_transaction_cannot_establish_identity(self) -> None:
        events, transactions = self.base()
        events.append(
            event(
                900,
                "Create Session Request",
                "create-session",
                src=MME,
                dst=SGW,
                teid=0,
                seq=77,
                fteids=[fteid(10, 1, MME)],
            )
        )
        events.append(
            event(
                901,
                "Create Session Response",
                "create-session",
                src=SGW,
                dst=MME,
                teid=1,
                seq=77,
                cause=16,
                fteids=[fteid(11, 88, SGW)],
            )
        )
        transactions["transactions"].append(
            transaction(
                "s11-create-ambiguous",
                "create-session",
                (900, "Create Session Request", 0, 77),
                (901, "Create Session Response", 1, 77),
                status="AMBIGUOUS",
            )
        )
        result = self.analyze(events, transactions)
        contexts = {
            item["allocation_transaction_reference"]: item
            for item in result["hop_local_contexts"]
        }
        self.assertEqual(
            contexts["s11-create-ambiguous"]["association_status"], NOT_ESTABLISHED
        )
        self.assertFalse(
            any(
                identity["association_status"] == ESTABLISHED
                and "s11-create-ambiguous"
                in identity["source_transaction_references"]
                for identity in result["session_identity_links"]
            )
        )

    def test_d07_none_correlation_strength_cannot_establish_an_accepted_bridge(self) -> None:
        events, transactions = self.base()
        for item in transactions["transactions"]:
            if item["transaction_reference"] in ("s11-create-a", "s5-create-a"):
                item["correlation_strength"] = "NONE"
        result = self.analyze(events, transactions)
        contexts = {
            item["allocation_transaction_reference"]: item
            for item in result["hop_local_contexts"]
        }
        self.assertEqual(contexts["s11-create-a"]["association_status"], NOT_ESTABLISHED)
        self.assertEqual(contexts["s5-create-a"]["association_status"], NOT_ESTABLISHED)
        self.assertEqual(
            sum(
                1
                for item in result["session_identity_links"]
                if item["association_status"] == ESTABLISHED
            ),
            0,
        )

    def test_d08_source_truncation_remains_explicit(self) -> None:
        events, transactions = self.base()
        transactions["transactions"].append(
            transaction(
                "s11-create-open",
                "create-session",
                (900, "Create Session Request", 0, 77),
                None,
                status="OPEN_REQUEST",
            )
        )
        result = self.analyze(events, transactions)
        self.assertTrue(
            any(
                "could not be bound" in item for item in result["evidence_limitations"]
            )
        )

    def test_d09_unbound_candidates_remain_visible(self) -> None:
        events, transactions = self.base()
        for item in events:
            if item["frame_number"] == 120:
                item["header"]["teid"] = 99
        for item in transactions["transactions"]:
            if item["transaction_reference"] == "s11-delete-a":
                item["request"]["header_teid"] = 99
        result = self.analyze(events, transactions)
        kinds = {item["kind"] for item in result["unbound_evidence"]}
        self.assertIn("transaction_unmatched_by_receiver_scoped_addressing", kinds)
        self.assertEqual(result["unbound_evidence_count"], len(result["unbound_evidence"]))

    def test_d10_input_reordering_does_not_change_selected_relationships(self) -> None:
        events, transactions = self.base()
        first = self.analyze(events, transactions)
        shuffled_events = list(reversed(events))
        shuffled_transactions = dict(transactions)
        shuffled_transactions["transactions"] = list(
            reversed(transactions["transactions"])
        )
        second = self.analyze(shuffled_events, shuffled_transactions)
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )


# ---------------------------------------------------------------------------
# E — unified invariance expressible against this capability
# ---------------------------------------------------------------------------
class UnifiedInvarianceTests(SessionIdentityTestCase):
    def test_e08_no_subscriber_identity_or_apn_is_published(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        serialized = json.dumps(result).lower()
        for forbidden in ("imsi", "msisdn", "imei", "apn", "pdn_address", "subscriber"):
            self.assertNotIn(f'"{forbidden}"', serialized)

    def test_e10_repeated_runs_are_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            events, transactions = self.base()
            events_path = Path(tmp) / "events.jsonl"
            transactions_path = Path(tmp) / "transactions.json"
            events_path.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in events),
                encoding="utf-8",
            )
            transactions_path.write_text(
                json.dumps(transactions, sort_keys=True), encoding="utf-8"
            )
            outputs = []
            for index in (1, 2):
                output = Path(tmp) / f"analysis-{index}.json"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(CLI),
                        "--gtpv2",
                        str(events_path),
                        "--transactions",
                        str(transactions_path),
                        "--output",
                        str(output),
                        "--force",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                outputs.append(output.read_bytes())
            self.assertEqual(outputs[0], outputs[1])

    def test_e09_json_and_text_outputs_agree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            events, transactions = self.base()
            events_path = Path(tmp) / "events.jsonl"
            transactions_path = Path(tmp) / "transactions.json"
            events_path.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in events),
                encoding="utf-8",
            )
            transactions_path.write_text(
                json.dumps(transactions, sort_keys=True), encoding="utf-8"
            )
            output = Path(tmp) / "analysis.json"
            report = Path(tmp) / "report.txt"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "--gtpv2",
                    str(events_path),
                    "--transactions",
                    str(transactions_path),
                    "--output",
                    str(output),
                    "--report",
                    str(report),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            analysis = json.loads(output.read_text(encoding="utf-8"))
            text = report.read_text(encoding="utf-8")
            self.assertIn(
                f"hop-local contexts: {analysis['hop_local_context_count']}", text
            )
            self.assertIn(
                f"cross-interface session identity links: {analysis['session_identity_count']}",
                text,
            )
            self.assertIn(
                f"release-to-session bindings: {analysis['release_session_binding_count']}",
                text,
            )

    def test_e11_malformed_input_fails_visibly_and_preserves_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            events_path = Path(tmp) / "events.jsonl"
            transactions_path = Path(tmp) / "transactions.json"
            events_path.write_text("{not json}\n", encoding="utf-8")
            transactions_path.write_text("{}", encoding="utf-8")
            output = Path(tmp) / "analysis.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "--gtpv2",
                    str(events_path),
                    "--transactions",
                    str(transactions_path),
                    "--output",
                    str(output),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, model.EXIT_MALFORMED_INPUT)
            self.assertFalse(output.exists())

    def test_e11b_existing_output_is_never_replaced_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            events, transactions = self.base()
            events_path = Path(tmp) / "events.jsonl"
            transactions_path = Path(tmp) / "transactions.json"
            events_path.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in events),
                encoding="utf-8",
            )
            transactions_path.write_text(
                json.dumps(transactions, sort_keys=True), encoding="utf-8"
            )
            output = Path(tmp) / "analysis.json"
            output.write_text("previous\n", encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "--gtpv2",
                    str(events_path),
                    "--transactions",
                    str(transactions_path),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, model.EXIT_OUTPUT_FAILURE)
            self.assertEqual(output.read_text(encoding="utf-8"), "previous\n")

    def test_e12_no_user_plane_delivery_or_root_cause_verdict_is_emitted(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        serialized = json.dumps(result).lower()
        for forbidden in (
            "packet_loss",
            "delivery_confirmed",
            "user_received_packet",
            "application_reachable",
            "root cause",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_empty_inputs_produce_an_explicit_document(self) -> None:
        result = self.analyze([], tx_document())
        self.assertEqual(result["hop_local_context_count"], 0)
        self.assertEqual(result["release_session_binding_count"], 0)
        self.assertTrue(
            any(
                "no accepted GTPv2-C transaction correlation" in item
                for item in result["evidence_limitations"]
            )
        )


# ---------------------------------------------------------------------------
# Lifecycle integration: the reviewed session-context release path
# ---------------------------------------------------------------------------
def run_lifecycle(tmp: Path, events_path: Path, transactions_path: Path, identity_path: Path | None, output: Path) -> subprocess.CompletedProcess:
    command = [
        sys.executable,
        str(LIFECYCLE_CLI),
        "--gtpv2",
        str(events_path),
        "--transactions",
        str(transactions_path),
        "--output",
        str(output),
        "--force",
    ]
    if identity_path is not None:
        command.extend(["--session-identity", str(identity_path)])
    return subprocess.run(command, capture_output=True, text=True, check=False)


class LifecycleIntegrationTests(SessionIdentityTestCase):
    def prepare(self, tmp: Path):
        events, transactions = self.base()
        events_path = tmp / "events.jsonl"
        transactions_path = tmp / "transactions.json"
        events_path.write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in events),
            encoding="utf-8",
        )
        transactions_path.write_text(
            json.dumps(transactions, sort_keys=True), encoding="utf-8"
        )
        return events_path, transactions_path

    def test_lifecycle_without_identity_stays_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            events_path, transactions_path = self.prepare(Path(tmp))
            output = Path(tmp) / "lifecycle.json"
            completed = run_lifecycle(Path(tmp), events_path, transactions_path, None, output)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            analysis = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(analysis["lifecycle_subject_count"], 2)
            self.assertEqual(analysis["generation_boundary_count"], 0)
            for subject in analysis["lifecycle_subjects"]:
                self.assertIsNone(subject["generation_boundary"])

    def test_lifecycle_with_identity_closes_through_the_session_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events_path, transactions_path = self.prepare(tmp_path)
            identity_output = tmp_path / "identity.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "--gtpv2",
                    str(events_path),
                    "--transactions",
                    str(transactions_path),
                    "--output",
                    str(identity_output),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = tmp_path / "lifecycle.json"
            completed = run_lifecycle(
                tmp_path, events_path, transactions_path, identity_output, output
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            analysis = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(analysis["lifecycle_subject_count"], 2)
            self.assertEqual(analysis["generation_boundary_count"], 2)
            for subject in analysis["lifecycle_subjects"]:
                boundary = subject["generation_boundary"]
                self.assertIsNotNone(boundary)
                self.assertEqual(
                    boundary["basis"],
                    "accepted_release_response_bound_by_reviewed_session_context",
                )
                self.assertEqual(boundary["release_request_frame"], 120)
                self.assertEqual(boundary["release_confirmation_frame"], 121)
                self.assertFalse(boundary["release_effective_frame_proven"])
                self.assertTrue(
                    any(
                        "session-context release path" in item
                        for item in subject["limitations"]
                    )
                )

    def test_lifecycle_rejected_release_stays_open_with_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            for item in events:
                if item["frame_number"] == 121:
                    item["message_cause"] = {
                        "cause_code": 72,
                        "cause_name": "No resources available",
                        "scope": "message",
                    }
            events_path = tmp_path / "events.jsonl"
            transactions_path = tmp_path / "transactions.json"
            events_path.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in events),
                encoding="utf-8",
            )
            transactions_path.write_text(
                json.dumps(transactions, sort_keys=True), encoding="utf-8"
            )
            identity_output = tmp_path / "identity.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "--gtpv2",
                    str(events_path),
                    "--transactions",
                    str(transactions_path),
                    "--output",
                    str(identity_output),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = tmp_path / "lifecycle.json"
            completed = run_lifecycle(
                tmp_path, events_path, transactions_path, identity_output, output
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            analysis = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(analysis["generation_boundary_count"], 0)

    def test_lifecycle_ambiguous_binding_closes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            # A second S11 allocation claiming the same control-plane F-TEID
            # makes the release binding ambiguous; nothing may close.
            build_session(
                events,
                transactions,
                "b",
                frame=500,
                seq=11,
                sgw_cteid=14,
                pgw_cteid=9,
                gen_sgw_teid=58,
                gen_enb_teid=16777992,
            )
            events_path = tmp_path / "events.jsonl"
            transactions_path = tmp_path / "transactions.json"
            events_path.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in events),
                encoding="utf-8",
            )
            transactions_path.write_text(
                json.dumps(transactions, sort_keys=True), encoding="utf-8"
            )
            identity_output = tmp_path / "identity.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "--gtpv2",
                    str(events_path),
                    "--transactions",
                    str(transactions_path),
                    "--output",
                    str(identity_output),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = tmp_path / "lifecycle.json"
            completed = run_lifecycle(
                tmp_path, events_path, transactions_path, identity_output, output
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            analysis = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(analysis["generation_boundary_count"], 0)

    def test_direct_endpoint_path_takes_precedence_and_keeps_its_basis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            # A Delete Session that carries the released S1-U endpoint in its
            # bearer context names the endpoint directly; the direct path is
            # authoritative even when a session-identity analysis is supplied.
            for item in events:
                if item["frame_number"] == 120:
                    item["bearer_contexts"] = [
                        bearer_context(5, [bearer_fteid(1, 56, SGW_S1U)])
                    ]
            events_path = tmp_path / "events.jsonl"
            transactions_path = tmp_path / "transactions.json"
            events_path.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in events),
                encoding="utf-8",
            )
            transactions_path.write_text(
                json.dumps(transactions, sort_keys=True), encoding="utf-8"
            )
            identity_output = tmp_path / "identity.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "--gtpv2",
                    str(events_path),
                    "--transactions",
                    str(transactions_path),
                    "--output",
                    str(identity_output),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = tmp_path / "lifecycle.json"
            completed = run_lifecycle(
                tmp_path, events_path, transactions_path, identity_output, output
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            analysis = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(analysis["generation_boundary_count"], 2)
            bases = {
                subject["generation_boundary"]["basis"]
                for subject in analysis["lifecycle_subjects"]
                if subject["generation_boundary"]
            }
            # The sgw_s1u generation closes through the direct path; the
            # enodeb generation has no direct endpoint match and closes
            # through the reviewed session-context path.
            self.assertIn(
                "accepted_release_response_bound_to_the_same_control_plane_context",
                bases,
            )
            self.assertIn(
                "accepted_release_response_bound_by_reviewed_session_context",
                bases,
            )


# ---------------------------------------------------------------------------
# P1-C-I-C — allocation-outcome classification (A01-A08)
# ---------------------------------------------------------------------------
class AllocationOutcomeTests(SessionIdentityTestCase):
    def test_a01_matched_strong_cause_16_establishes_eligible_allocation(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        for context in result["hop_local_contexts"]:
            self.assertEqual(context["association_status"], ESTABLISHED)
            self.assertTrue(context["transaction_correlation_proved"])
            self.assertEqual(context["allocation_outcome_status"], "ACCEPTED")

    def test_a02_matched_strong_cause_72_cannot_establish_accepted_allocation(self) -> None:
        events, transactions = self.base()
        for item in events:
            if item["frame_number"] in (102, 103):
                item["message_cause"] = {
                    "cause_code": 72,
                    "cause_name": "No resources available",
                    "scope": "message",
                }
        result = self.analyze(events, transactions)
        for context in result["hop_local_contexts"]:
            self.assertEqual(context["association_status"], NOT_ESTABLISHED)
            self.assertEqual(context["association_basis"], "allocation_outcome_rejected_observed")
            self.assertEqual(context["allocation_outcome_status"], "REJECTED_OBSERVED")
            self.assertTrue(context["transaction_correlation_proved"])
        self.assertEqual(
            sum(
                1
                for item in result["session_to_generation_links"]
                if item["association_status"] == ESTABLISHED
            ),
            0,
        )
        self.assertEqual(result["established_closure_candidate_count"], 0)

    def test_a03_missing_message_cause_cannot_establish_accepted_allocation(self) -> None:
        events, transactions = self.base()
        for item in events:
            if item["frame_number"] in (102, 103):
                item["message_cause"] = None
        result = self.analyze(events, transactions)
        for context in result["hop_local_contexts"]:
            self.assertEqual(context["association_status"], NOT_ESTABLISHED)
            self.assertEqual(context["association_basis"], "allocation_outcome_unresolved")
            self.assertEqual(context["allocation_outcome_status"], "UNRESOLVED")

    def test_a04_open_request_cannot_establish_a_completed_allocation(self) -> None:
        events, transactions = self.base()
        events.append(
            event(
                300,
                "Create Session Request",
                "create-session",
                src=MME,
                dst=SGW,
                teid=0,
                seq=60,
                fteids=[fteid(10, 1, MME)],
            )
        )
        transactions["transactions"].append(
            transaction(
                "s11-create-open",
                "create-session",
                (300, "Create Session Request", 0, 60),
                None,
                status="OPEN_REQUEST",
            )
        )
        result = self.analyze(events, transactions)
        context = next(
            item
            for item in result["hop_local_contexts"]
            if item["allocation_transaction_reference"] == "s11-create-open"
        )
        self.assertEqual(context["association_status"], NOT_ESTABLISHED)
        self.assertEqual(
            context["association_basis"], "allocation_transaction_correlation_open_request"
        )

    def test_a05_ambiguous_transaction_cannot_establish_a_proved_accepted_context(self) -> None:
        events, transactions = self.base()
        events.append(
            event(
                300,
                "Create Session Request",
                "create-session",
                src=MME,
                dst=SGW,
                teid=0,
                seq=60,
                fteids=[fteid(10, 1, MME)],
            )
        )
        events.append(
            event(
                301,
                "Create Session Response",
                "create-session",
                src=SGW,
                dst=MME,
                teid=1,
                seq=60,
                cause=16,
                fteids=[fteid(11, 30, SGW)],
            )
        )
        transactions["transactions"].append(
            transaction(
                "s11-create-amb",
                "create-session",
                (300, "Create Session Request", 0, 60),
                (301, "Create Session Response", 1, 60),
                status="AMBIGUOUS",
            )
        )
        result = self.analyze(events, transactions)
        context = next(
            item
            for item in result["hop_local_contexts"]
            if item["allocation_transaction_reference"] == "s11-create-amb"
        )
        self.assertEqual(context["association_status"], NOT_ESTABLISHED)
        self.assertEqual(
            context["association_basis"], "allocation_transaction_correlation_ambiguous"
        )
        self.assertFalse(context["transaction_correlation_proved"])

    def test_a06_response_only_cannot_manufacture_allocation_identity(self) -> None:
        events, transactions = self.base()
        # A response observed at a frame its transaction names but whose request
        # was never captured: the transaction cannot bind, so no context exists.
        events.append(
            event(
                302,
                "Create Session Response",
                "create-session",
                src=SGW,
                dst=MME,
                teid=1,
                seq=61,
                cause=16,
                fteids=[fteid(11, 31, SGW)],
            )
        )
        transactions["transactions"].append(
            transaction(
                "s11-create-resp-only",
                "create-session",
                (303, "Create Session Request", 0, 61),
                (302, "Create Session Response", 1, 61),
                status="RESPONSE_ONLY",
            )
        )
        result = self.analyze(events, transactions)
        self.assertFalse(
            any(
                context["allocation_transaction_reference"] == "s11-create-resp-only"
                for context in result["hop_local_contexts"]
            )
        )
        self.assertTrue(
            any(
                item.get("transaction_reference") == "s11-create-resp-only"
                for item in result["unbound_evidence"]
            )
        )

    def test_a07_correlation_strength_none_cannot_establish_accepted_identity(self) -> None:
        events, transactions = self.base()
        for item in transactions["transactions"]:
            if item["transaction_reference"] in ("s11-create-a", "s5-create-a"):
                item["correlation_strength"] = "NONE"
        result = self.analyze(events, transactions)
        contexts = {
            item["allocation_transaction_reference"]: item
            for item in result["hop_local_contexts"]
        }
        self.assertEqual(contexts["s11-create-a"]["association_status"], NOT_ESTABLISHED)
        self.assertFalse(contexts["s11-create-a"]["transaction_correlation_proved"])
        self.assertEqual(result["established_hop_local_context_count"], 0)

    def test_a08_request_side_cause_16_cannot_override_response_cause_72(self) -> None:
        events, transactions = self.base()
        for item in events:
            if item["frame_number"] == 100:
                item["message_cause"] = {
                    "cause_code": 16,
                    "cause_name": "Request accepted",
                    "scope": "message",
                }
            if item["frame_number"] in (102, 103):
                item["message_cause"] = {
                    "cause_code": 72,
                    "cause_name": "No resources available",
                    "scope": "message",
                }
        result = self.analyze(events, transactions)
        for context in result["hop_local_contexts"]:
            self.assertEqual(context["allocation_outcome_status"], "REJECTED_OBSERVED")
            self.assertEqual(context["association_status"], NOT_ESTABLISHED)


# ---------------------------------------------------------------------------
# P1-C-I-C — bearer-scope identity (B01-B07)
# ---------------------------------------------------------------------------
class BearerScopeTests(SessionIdentityTestCase):
    def test_b01_message_cause_16_plus_bearer_cause_72_does_not_establish_that_bearer(self) -> None:
        events, transactions = self.base()
        for item in events:
            if item["frame_number"] == 103:
                for bearer in item["bearer_contexts"]:
                    if any(ft["interface_type"] == 1 for ft in bearer["f_teids"]):
                        bearer["cause"] = {
                            "cause_code": 72,
                            "cause_name": "No resources available",
                            "scope": "bearer",
                        }
        result = self.analyze(events, transactions)
        link = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "sgw_s1u"
        )
        self.assertEqual(link["association_status"], NOT_ESTABLISHED)
        self.assertEqual(link["association_basis"], "bearer_item_rejected_observed")
        # The other endpoint's items are untouched: bearer scoping is selective.
        other = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "enodeb_s1u"
        )
        self.assertEqual(other["association_status"], ESTABLISHED)
        candidate = next(
            item
            for item in result["generation_closure_candidates"]
            if item["bearer_endpoint_reference"] == link["target_subject_reference"]
        )
        self.assertEqual(candidate["association_status"], NOT_ESTABLISHED)

    def test_b02_bearer_cause_16_remains_scoped_to_its_actual_grouped_item(self) -> None:
        events, transactions = self.base()
        for item in events:
            if item["frame_number"] == 103:
                for bearer in item["bearer_contexts"]:
                    bearer["cause"] = {
                        "cause_code": 16,
                        "cause_name": "Request accepted",
                        "scope": "bearer",
                    }
        result = self.analyze(events, transactions)
        for link in result["session_to_generation_links"]:
            self.assertEqual(link["association_status"], ESTABLISHED)

    def test_b03_ebi_5_and_ebi_6_in_distinct_bearer_items_do_not_merge(self) -> None:
        events, transactions = self.base()
        for item in events:
            if item["frame_number"] == 103:
                item["bearer_contexts"] = [
                    bearer_context(5, [bearer_fteid(1, 56, SGW_S1U)]),
                    bearer_context(6, [bearer_fteid(1, 56, SGW_S1U)]),
                ]
        result = self.analyze(events, transactions)
        link = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "sgw_s1u"
        )
        self.assertEqual(link["association_status"], AMBIGUOUS)
        self.assertEqual(link["association_basis"], "distinct_bearer_identities_share_one_endpoint")
        self.assertEqual(link["bearer_endpoint"]["eps_bearer_identities"], [5, 6])
        self.assertEqual(
            sum(
                1
                for item in result["generation_closure_candidates"]
                if item["association_status"] == ESTABLISHED
                    and item["bearer_endpoint"]["role"] == "sgw_s1u"
            ),
            0,
        )

    def test_b04_same_endpoint_value_across_two_bearer_identities_remains_ambiguous(self) -> None:
        events, transactions = self.base()
        # The second identity arrives in another transaction that re-advertises
        # the same endpoint value under EBI 6.
        for item in events:
            if item["frame_number"] == 111:
                item["bearer_contexts"] = [bearer_context(6, [bearer_fteid(0, 16777736, ENB_S1U)])]
        result = self.analyze(events, transactions)
        link = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "enodeb_s1u"
        )
        self.assertEqual(link["association_status"], AMBIGUOUS)
        self.assertEqual(link["association_basis"], "distinct_bearer_identities_share_one_endpoint")

    def test_b05_flat_unbound_cause_cannot_be_assigned_to_an_item_by_position(self) -> None:
        events, transactions = self.base()
        # The grouped item carries no Cause; the unbound flat list exists but no
        # code path may borrow an outcome from it. The item resolves only
        # through its own transaction's correlated response message Cause.
        for item in events:
            if item["frame_number"] == 103:
                for bearer in item["bearer_contexts"]:
                    bearer["cause"] = None
                item["unbound_ie_metadata"] = {
                    "binding_basis": "test",
                    "ebi_values": [5],
                    "limitations": ["flat unbound values"],
                }
        result = self.analyze(events, transactions)
        link = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "sgw_s1u"
        )
        self.assertEqual(link["association_status"], ESTABLISHED)

    def test_b06_unique_accepted_ebi_5_item_preserves_the_valid_identity_link(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        established = [
            item
            for item in result["session_to_generation_links"]
            if item["association_status"] == ESTABLISHED
        ]
        self.assertEqual(len(established), 2)
        for link in established:
            self.assertEqual(link["bearer_endpoint"]["eps_bearer_identities"], [5])

    def test_b07_a_rejected_bearer_does_not_produce_an_established_closure_candidate(self) -> None:
        events, transactions = self.base()
        for item in events:
            if item["frame_number"] == 103:
                for bearer in item["bearer_contexts"]:
                    bearer["cause"] = {
                        "cause_code": 72,
                        "cause_name": "No resources available",
                        "scope": "bearer",
                    }
            if item["frame_number"] in (110, 111):
                for bearer in item.get("bearer_contexts") or []:
                    bearer["cause"] = {
                        "cause_code": 72,
                        "cause_name": "No resources available",
                        "scope": "bearer",
                    }
        result = self.analyze(events, transactions)
        self.assertEqual(result["established_closure_candidate_count"], 0)
        self.assertEqual(
            sum(
                1
                for item in result["session_to_generation_links"]
                if item["association_status"] == ESTABLISHED
            ),
            0,
        )


# ---------------------------------------------------------------------------
# P1-C-I-C — hop and interface proof (H01-H07)
# ---------------------------------------------------------------------------
class HopInterfaceTests(SessionIdentityTestCase):
    def test_h01_request_with_s11_control_plane_fteid_seeds_s11(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        context = next(
            item
            for item in result["hop_local_contexts"]
            if item["allocation_transaction_reference"] == "s11-create-a"
        )
        self.assertEqual(context["interface_class"], "S11")
        published = {
            (record["interface_type"], record["teid"], record["address"])
            for record in context["control_plane_fteids"]
        }
        self.assertIn((10, 1, MME), published)

    def test_h02_request_with_s5s8_control_plane_fteid_seeds_s5s8(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        context = next(
            item
            for item in result["hop_local_contexts"]
            if item["allocation_transaction_reference"] == "s5-create-a"
        )
        self.assertEqual(context["interface_class"], "S5/S8")

    def test_h03_foreign_relayed_fteid_alone_cannot_establish_hop_identity(self) -> None:
        events = [
            event(400, "Create Session Request", "create-session", src=MME, dst=SGW, teid=0, seq=30),
            event(
                401,
                "Create Session Response",
                "create-session",
                src=SGW,
                dst=MME,
                teid=1,
                seq=30,
                cause=16,
                fteids=[fteid(7, 5, PGW)],
            ),
        ]
        transactions = tx_document(
            transaction(
                "s11-create-foreign",
                "create-session",
                (400, "Create Session Request", 0, 30),
                (401, "Create Session Response", 1, 30),
            )
        )
        result = self.analyze(events, transactions)
        self.assertEqual(result["hop_local_context_count"], 0)
        kinds = [item["kind"] for item in result["unbound_evidence"]]
        self.assertIn("transaction_insufficient_hop_evidence", kinds)

    def test_h04_reviewed_independent_response_side_hop_evidence_remains_usable(self) -> None:
        events = [
            event(410, "Create Session Request", "create-session", src=MME, dst=SGW, teid=0, seq=31),
            event(
                411,
                "Create Session Response",
                "create-session",
                src=SGW,
                dst=MME,
                teid=1,
                seq=31,
                cause=16,
                fteids=[fteid(11, 40, SGW)],
                contexts=[bearer_context(5, [bearer_fteid(1, 66, SGW_S1U)])],
            ),
        ]
        transactions = tx_document(
            transaction(
                "s11-create-resp-evidence",
                "create-session",
                (410, "Create Session Request", 0, 31),
                (411, "Create Session Response", 1, 31),
            )
        )
        result = self.analyze(events, transactions)
        self.assertEqual(result["established_hop_local_context_count"], 1)
        context = result["hop_local_contexts"][0]
        self.assertEqual(context["interface_class"], "S11")
        self.assertEqual(context["association_status"], ESTABLISHED)

    def test_h05_header_teid_1_shared_across_contexts_never_establishes_a_join(self) -> None:
        events, transactions = self.base()
        build_session(events, transactions, "b", frame=500, seq=11, sgw_cteid=15, pgw_cteid=9)
        for item in events:
            if item["frame_number"] == 120:
                item["header"]["teid"] = 1
                item["source"], item["destination"] = (
                    {"address": SGW, "port": 2123},
                    {"address": MME, "port": 2123},
                )
        for item in transactions["transactions"]:
            if item["transaction_reference"] == "s11-delete-a":
                item["request"]["header_teid"] = 1
        result = self.analyze(events, transactions)
        binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s11-delete-a"
        )
        self.assertEqual(binding["association_status"], AMBIGUOUS)
        self.assertEqual(len(binding["competing_candidates"]), 2)

    def test_h06_cross_capture_frame_collisions_remain_isolated(self) -> None:
        events, transactions = self.base()
        build_session(
            events,
            transactions,
            "b",
            capture=CAPTURE_B,
            frame=100,
            seq=1,
            sgw_cteid=15,
            pgw_cteid=9,
        )
        result = self.analyze(events, transactions)
        self.assertEqual(result["hop_local_context_count"], 0)
        self.assertTrue(
            any(
                "could not be bound" in item for item in result["evidence_limitations"]
            )
        )

    def test_h07_cross_interface_bridge_evidence_remains_distinct_from_correspondence(self) -> None:
        events, transactions = self.base()
        result = self.analyze(events, transactions)
        self.assertEqual(result["endpoint_correspondence_links"][0]["association_status"], SUPPORTED)
        self.assertEqual(
            result["endpoint_correspondence_links"][0]["relationship_type"],
            "CROSS_INTERFACE_ENDPOINT_CORRESPONDENCE",
        )
        self.assertEqual(result["session_identity_links"][0]["association_status"], ESTABLISHED)
        self.assertEqual(
            result["session_identity_links"][0]["relationship_type"],
            "CROSS_INTERFACE_SESSION_IDENTITY",
        )


# ---------------------------------------------------------------------------
# P1-C-I-C — lifecycle closure completeness (L01-L12)
# ---------------------------------------------------------------------------
def s1u_stream(reference: str, *, destination: str, teid: int, direction: str, packets: int, octets: int, first: int, last: int) -> dict:
    return {
        "stream_reference": reference,
        "capture_file": CAPTURE_A,
        "outer_source": "10.9.9.1",
        "outer_destination": destination,
        "teid": teid,
        "direction": direction,
        "first_frame": first,
        "last_frame": last,
        "observed_g_pdu_packet_count": packets,
        "observed_payload_byte_count": octets,
        "association_status": "SUPPORTED",
        "message_types": ["G-PDU"],
    }


def gtpu_frame_event(frame: int, *, destination: str, teid: int, length: int = 100) -> dict:
    return {
        "capture_file": CAPTURE_A,
        "frame_number": frame,
        "header": {"message_type": "G-PDU", "teid": teid, "message_length": length},
        "outer": {"source_address": "10.9.9.1", "destination_address": destination},
    }


class LifecycleClosureCompletenessTests(SessionIdentityTestCase):
    def test_l01_accepted_release_accepted_allocation_unique_binding_closes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, identity
            )
            self.assertEqual(code, 0)
            self.assertEqual(analysis["generation_boundary_count"], 2)

    def test_l02_rejected_allocation_plus_accepted_release_closes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            for item in events:
                if item["frame_number"] in (102, 103):
                    item["message_cause"] = {
                        "cause_code": 72,
                        "cause_name": "No resources available",
                        "scope": "message",
                    }
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            identity_doc = json.loads(identity.read_text(encoding="utf-8"))
            self.assertEqual(identity_doc["established_hop_local_context_count"], 0)
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, identity
            )
            self.assertEqual(code, 0)
            self.assertEqual(analysis["generation_boundary_count"], 0)
            # The accepted release stays visible regardless.
            self.assertEqual(
                sum(
                    1
                    for item in analysis["generation_boundary_evidence"]
                    if item["release_outcome"] == "ACCEPTED"
                ),
                2,
            )

    def test_l03_rejected_bearer_item_blocks_that_bearer_generation_closure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            for item in events:
                if item["frame_number"] == 103:
                    for bearer in item["bearer_contexts"]:
                        if any(ft["interface_type"] == 1 for ft in bearer["f_teids"]):
                            bearer["cause"] = {
                                "cause_code": 72,
                                "cause_name": "No resources available",
                                "scope": "bearer",
                            }
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            identity_doc = json.loads(identity.read_text(encoding="utf-8"))
            rejected_links = [
                item
                for item in identity_doc["session_to_generation_links"]
                if item["association_basis"] == "bearer_item_rejected_observed"
            ]
            self.assertEqual(len(rejected_links), 1)
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, identity
            )
            self.assertEqual(code, 0)
            self.assertEqual(analysis["generation_boundary_count"], 1)

    def test_l04_two_bearer_identities_sharing_one_endpoint_close_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            for item in events:
                if item["frame_number"] == 103:
                    item["bearer_contexts"] = [
                        bearer_context(5, [bearer_fteid(1, 56, SGW_S1U)]),
                        bearer_context(6, [bearer_fteid(1, 56, SGW_S1U)]),
                    ]
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, identity
            )
            self.assertEqual(code, 0)
            # The shared endpoint's bearer identity is ambiguous, so that
            # generation cannot close; the endpoint's own items are unaffected
            # for the other receiving role, whose generation closes normally.
            self.assertEqual(analysis["generation_boundary_count"], 1)
            closed_roles = {
                subject["receiving_endpoint_role"]
                for subject in analysis["lifecycle_subjects"]
                if subject["generation_boundary"]
            }
            self.assertEqual(closed_roles, {"enodeb_s1u"})

    def test_l05_candidate_count_mismatch_blocks_unsafe_closure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            doctored = json.loads(identity.read_text(encoding="utf-8"))
            doctored["generation_closure_candidate_count"] = 257
            filler = json.loads(json.dumps(doctored["generation_closure_candidates"][0]))
            filler = dict(filler)
            filler.pop("generation_closure_candidate_reference", None)
            doctored["generation_closure_candidates"] = doctored[
                "generation_closure_candidates"
            ] * 1 + [filler] * (256 - len(doctored["generation_closure_candidates"]))
            doctored_path = tmp_path / "identity-truncated.json"
            doctored_path.write_text(json.dumps(doctored, sort_keys=True), encoding="utf-8")
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, doctored_path
            )
            self.assertEqual(code, 0)
            self.assertEqual(analysis["generation_boundary_count"], 0)
            self.assertTrue(
                any(
                    "SOURCE_CANDIDATES_TRUNCATED" in item
                    for item in analysis["evidence_limitations"]
                )
            )

    def test_l06_exactly_complete_unique_candidate_arrays_permit_closure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            identity_doc = json.loads(identity.read_text(encoding="utf-8"))
            self.assertEqual(
                identity_doc["generation_closure_candidate_count"],
                len(identity_doc["generation_closure_candidates"]),
            )
            self.assertEqual(
                identity_doc["release_session_binding_count"],
                len(identity_doc["release_session_bindings"]),
            )
            self.assertEqual(
                identity_doc["session_to_generation_count"],
                len(identity_doc["session_to_generation_links"]),
            )
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, identity
            )
            self.assertEqual(code, 0)
            self.assertEqual(analysis["generation_boundary_count"], 2)

    def test_l07_a_release_from_another_capture_cannot_close_the_local_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            build_session(
                events,
                transactions,
                "b",
                capture=CAPTURE_B,
                frame=700,
                seq=11,
                sgw_cteid=14,
                pgw_cteid=9,
            )
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, identity
            )
            self.assertEqual(code, 0)
            # Each capture's own accepted releases close its own generations:
            # capture A closes exactly its two subjects through capture-A
            # transactions, and capture B the same, so nothing crossed the
            # capture boundary.
            self.assertEqual(analysis["generation_boundary_count"], 4)
            for subject in analysis["lifecycle_subjects"]:
                boundary = subject["generation_boundary"]
                self.assertIsNotNone(boundary)
                evidence = next(
                    item
                    for item in analysis["generation_boundary_evidence"]
                    if item["transaction_reference"] == boundary["transaction_reference"]
                    and item["capture_file"] == subject["capture_file"]
                )
                self.assertEqual(evidence["capture_file"], subject["capture_file"])

    def test_l08_a_release_for_another_context_cannot_close_the_local_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            for item in events:
                if item["frame_number"] == 120:
                    item["header"]["teid"] = 99
            for item in transactions["transactions"]:
                if item["transaction_reference"] == "s11-delete-a":
                    item["request"]["header_teid"] = 99
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, identity
            )
            self.assertEqual(code, 0)
            self.assertEqual(analysis["generation_boundary_count"], 0)

    def test_l09_release_request_and_response_retain_separate_evidence_roles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, identity
            )
            self.assertEqual(code, 0)
            boundary = analysis["generation_boundary_evidence"][0]
            self.assertEqual(boundary["request_frame"], 120)
            self.assertEqual(boundary["response_frame"], 121)
            self.assertEqual(
                [ref["frame_number"] for ref in boundary["evidence_refs"]], [120, 121]
            )

    def test_l10_pending_release_stays_conservative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, identity
            )
            self.assertEqual(code, 0)
            for subject in analysis["lifecycle_subjects"]:
                boundary = subject["generation_boundary"]
                self.assertIsNotNone(boundary)
                self.assertFalse(boundary["release_effective_frame_proven"])

    def test_l11_no_double_attribution_of_gtpu_frames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            s1u = {
                "stream_observations": [
                    s1u_stream(
                        "stream-enb",
                        destination=ENB_S1U,
                        teid=16777736,
                        direction="DOWNLINK",
                        packets=2,
                        octets=200,
                        first=110,
                        last=111,
                    )
                ]
            }
            s1u_path = tmp_path / "s1u.json"
            s1u_path.write_text(json.dumps(s1u, sort_keys=True), encoding="utf-8")
            gtpu = [
                gtpu_frame_event(110, destination=ENB_S1U, teid=16777736),
                gtpu_frame_event(111, destination=ENB_S1U, teid=16777736),
            ]
            gtpu_path = tmp_path / "gtpu.jsonl"
            gtpu_path.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in gtpu),
                encoding="utf-8",
            )
            output = tmp_path / "lifecycle.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(LIFECYCLE_CLI),
                    "--gtpv2",
                    str(events_path),
                    "--transactions",
                    str(transactions_path),
                    "--session-identity",
                    str(identity),
                    "--s1u",
                    str(s1u_path),
                    "--gtpu",
                    str(gtpu_path),
                    "--output",
                    str(output),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            analysis = json.loads(output.read_text(encoding="utf-8"))
            scoped = analysis["generation_scoped_s1u_observations"]
            self.assertEqual(sum(item["observed_g_pdu_count"] for item in scoped), 2)
            frames = [frame for item in scoped for frame in item.get("frames", [])]
            self.assertEqual(len(frames), len(set(frames)))

    def test_l12_gtpu_and_payload_octet_accounting_remains_conserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            s1u = {
                "stream_observations": [
                    s1u_stream(
                        "stream-enb",
                        destination=ENB_S1U,
                        teid=16777736,
                        direction="DOWNLINK",
                        packets=3,
                        octets=300,
                        first=110,
                        last=118,
                    )
                ]
            }
            s1u_path = tmp_path / "s1u.json"
            s1u_path.write_text(json.dumps(s1u, sort_keys=True), encoding="utf-8")
            gtpu = [
                gtpu_frame_event(110, destination=ENB_S1U, teid=16777736),
                gtpu_frame_event(111, destination=ENB_S1U, teid=16777736),
                gtpu_frame_event(118, destination=ENB_S1U, teid=16777736),
            ]
            gtpu_path = tmp_path / "gtpu.jsonl"
            gtpu_path.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in gtpu),
                encoding="utf-8",
            )
            output = tmp_path / "lifecycle.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(LIFECYCLE_CLI),
                    "--gtpv2",
                    str(events_path),
                    "--transactions",
                    str(transactions_path),
                    "--session-identity",
                    str(identity),
                    "--s1u",
                    str(s1u_path),
                    "--gtpu",
                    str(gtpu_path),
                    "--output",
                    str(output),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            analysis = json.loads(output.read_text(encoding="utf-8"))
            accounting = analysis["accounting"]
            self.assertEqual(accounting["aggregate_g_pdu_count"], 3)
            self.assertTrue(accounting["conserved_g_pdu"])
            self.assertTrue(accounting["conserved_payload_octets"])
            self.assertEqual(
                accounting["attributed_g_pdu_count"] + accounting["unresolved_g_pdu_count"],
                accounting["aggregate_g_pdu_count"],
            )

    def test_i10_identity_failure_preserves_usable_earlier_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            malformed = tmp_path / "identity-broken.json"
            malformed.write_text("{not json}\n", encoding="utf-8")
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, malformed
            )
            self.assertEqual(code, 5)
            self.assertIsNone(analysis)
            # Without the identity input the lifecycle still publishes its own
            # evidence with every generation open.
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, None
            )
            self.assertEqual(code, 0)
            self.assertEqual(analysis["lifecycle_subject_count"], 2)
            self.assertEqual(analysis["generation_boundary_count"], 0)


# ---------------------------------------------------------------------------
# P1-C-I-C — repository invariance expressible here (I07-I09)
# ---------------------------------------------------------------------------
class InvarianceTests(SessionIdentityTestCase):
    def test_i07_no_subscriber_identity_or_inner_address_leaks(self) -> None:
        events, transactions = self.base()
        identity = self.analyze(events, transactions)
        serialized = json.dumps(identity).lower()
        for forbidden in ("imsi", "msisdn", "imei", "apn", "pdn_address", "subscriber"):
            self.assertNotIn(f'"{forbidden}"', serialized)

    def test_i08_json_and_text_reports_agree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            events, transactions = self.base()
            events_path = Path(tmp) / "events.jsonl"
            transactions_path = Path(tmp) / "transactions.json"
            events_path.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in events),
                encoding="utf-8",
            )
            transactions_path.write_text(
                json.dumps(transactions, sort_keys=True), encoding="utf-8"
            )
            output = Path(tmp) / "analysis.json"
            report = Path(tmp) / "report.txt"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "--gtpv2",
                    str(events_path),
                    "--transactions",
                    str(transactions_path),
                    "--output",
                    str(output),
                    "--report",
                    str(report),
                    "--force",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            analysis = json.loads(output.read_text(encoding="utf-8"))
            text = report.read_text(encoding="utf-8")
            self.assertIn(
                f"hop-local contexts: {analysis['hop_local_context_count']}", text
            )
            self.assertIn(
                f"release-to-session bindings: {analysis['release_session_binding_count']}",
                text,
            )
            self.assertIn(
                f"generation closure candidates: {analysis['generation_closure_candidate_count']}",
                text,
            )

    def test_i09_identical_executions_produce_byte_identical_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            events, transactions = self.base()
            events_path = Path(tmp) / "events.jsonl"
            transactions_path = Path(tmp) / "transactions.json"
            events_path.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in events),
                encoding="utf-8",
            )
            transactions_path.write_text(
                json.dumps(transactions, sort_keys=True), encoding="utf-8"
            )
            outputs = []
            for index in (1, 2):
                output = Path(tmp) / f"analysis-{index}.json"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(CLI),
                        "--gtpv2",
                        str(events_path),
                        "--transactions",
                        str(transactions_path),
                        "--output",
                        str(output),
                        "--force",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                outputs.append(output.read_bytes())
            self.assertEqual(outputs[0], outputs[1])


# ---------------------------------------------------------------------------
# P1-C-I-C-R — C1: missing grouped bearer-item identity (eight cases)
# ---------------------------------------------------------------------------
def message_scope_only_fixture() -> tuple[list[dict], dict]:
    events, transactions = base_document()
    for item in events:
        if item["frame_number"] == 103:
            item["bearer_contexts"] = []
            item["f_teids"] = [fteid(11, 14, SGW), fteid(1, 56, SGW_S1U)]
    return events, transactions


class MissingBearerIdentityTests(SessionIdentityTestCase):
    def test_c1_1_message_scope_only_endpoint_cannot_establish(self) -> None:
        events, transactions = message_scope_only_fixture()
        result = self.analyze(events, transactions)
        link = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "sgw_s1u"
        )
        self.assertEqual(link["association_status"], NOT_ESTABLISHED)
        self.assertEqual(link["association_basis"], "grouped_bearer_item_identity_missing")
        other = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "enodeb_s1u"
        )
        self.assertEqual(other["association_status"], ESTABLISHED)
        candidate = next(
            item
            for item in result["generation_closure_candidates"]
            if item["bearer_endpoint_reference"] == link["target_subject_reference"]
        )
        self.assertEqual(candidate["association_status"], NOT_ESTABLISHED)
        self.assertEqual(result["established_closure_candidate_count"], 1)

    def test_c1_2_grouped_bearer_item_with_missing_ebi_cannot_establish(self) -> None:
        events, transactions = base_document()
        for item in events:
            if item["frame_number"] == 103:
                item["bearer_contexts"] = [
                    {"ebi": None, "cause": None, "f_teids": [bearer_fteid(1, 56, SGW_S1U)]}
                ]
        result = self.analyze(events, transactions)
        link = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "sgw_s1u"
        )
        self.assertEqual(link["association_status"], NOT_ESTABLISHED)
        self.assertEqual(link["association_basis"], "grouped_bearer_item_identity_missing")

    def test_c1_3_accepted_grouped_ebi5_item_establishes(self) -> None:
        events, transactions = base_document()
        result = self.analyze(events, transactions)
        link = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "sgw_s1u"
        )
        self.assertEqual(link["association_status"], ESTABLISHED)
        self.assertEqual(link["bearer_endpoint"]["eps_bearer_identities"], [5])

    def test_c1_4_grouped_item_with_duplicate_message_scope_advertisement(self) -> None:
        events, transactions = base_document()
        for item in events:
            if item["frame_number"] == 103:
                item["f_teids"] = item["f_teids"] + [fteid(1, 56, SGW_S1U)]
        result = self.analyze(events, transactions)
        link = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "sgw_s1u"
        )
        self.assertEqual(link["association_status"], ESTABLISHED)
        self.assertEqual(link["association_basis"], model.BASIS_ENDPOINT_LINK)

    def test_c1_5_two_grouped_identities_remain_ambiguous(self) -> None:
        events, transactions = base_document()
        for item in events:
            if item["frame_number"] == 103:
                item["bearer_contexts"] = [
                    bearer_context(5, [bearer_fteid(1, 56, SGW_S1U)]),
                    bearer_context(6, [bearer_fteid(1, 56, SGW_S1U)]),
                ]
        result = self.analyze(events, transactions)
        link = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "sgw_s1u"
        )
        self.assertEqual(link["association_status"], AMBIGUOUS)
        self.assertEqual(link["association_basis"], "distinct_bearer_identities_share_one_endpoint")

    def test_c1_6_rejected_grouped_item_is_not_overridden_by_message_cause(self) -> None:
        events, transactions = base_document()
        for item in events:
            if item["frame_number"] == 103:
                for bearer in item["bearer_contexts"]:
                    if any(ft["interface_type"] == 1 for ft in bearer["f_teids"]):
                        bearer["cause"] = {
                            "cause_code": 72,
                            "cause_name": "No resources available",
                            "scope": "bearer",
                        }
        result = self.analyze(events, transactions)
        link = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "sgw_s1u"
        )
        self.assertEqual(link["association_status"], NOT_ESTABLISHED)
        self.assertEqual(link["association_basis"], "bearer_item_rejected_observed")

    def test_c1_7_accepted_delete_keeps_binding_but_no_closure_candidate(self) -> None:
        events, transactions = message_scope_only_fixture()
        result = self.analyze(events, transactions)
        binding = next(
            item
            for item in result["release_session_bindings"]
            if item["source_subject_reference"] == "s11-delete-a"
        )
        self.assertEqual(binding["association_status"], ESTABLISHED)
        self.assertEqual(binding["release_outcome_status"], "ACCEPTED")
        sgw_link = next(
            item
            for item in result["session_to_generation_links"]
            if item["bearer_endpoint"]["role"] == "sgw_s1u"
        )
        candidate = next(
            item
            for item in result["generation_closure_candidates"]
            if item["bearer_endpoint_reference"] == sgw_link["target_subject_reference"]
        )
        self.assertEqual(candidate["association_status"], NOT_ESTABLISHED)

    def test_c1_8_lifecycle_does_not_close_the_missing_identity_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = message_scope_only_fixture()
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, identity
            )
            self.assertEqual(code, 0)
            self.assertEqual(analysis["generation_boundary_count"], 1)
            closed_roles = {
                subject["receiving_endpoint_role"]
                for subject in analysis["lifecycle_subjects"]
                if subject["generation_boundary"]
            }
            self.assertEqual(closed_roles, {"enodeb_s1u"})
            open_roles = {
                subject["receiving_endpoint_role"]
                for subject in analysis["lifecycle_subjects"]
                if subject["generation_boundary"] is None
            }
            self.assertEqual(open_roles, {"sgw_s1u"})


# ---------------------------------------------------------------------------
# P1-C-I-C-R — C2: completeness metadata fail-closed (six variants)
# ---------------------------------------------------------------------------
class CompletenessMetadataTests(SessionIdentityTestCase):
    def closure_verdict(self, doc: dict) -> tuple[bool, str | None, int, dict]:
        index = lifecycle_model._session_identity_closure_index(doc)
        events, transactions = base_document()
        idx = lifecycle_model.transaction_index(transactions, events)
        boundaries = lifecycle_model.release_boundaries(events, idx)
        records = lifecycle_model.endpoint_records(events)
        conflicts = lifecycle_model.transaction_endpoint_values(transactions, events, idx)
        families = lifecycle_model.build_advertisement_families(records, idx, conflicts, boundaries)
        generations, _ = lifecycle_model.build_generations(families, boundaries, index)
        closed = sum(
            1 for item in generations if item["generation_state"] == "CLOSED_BY_ACCEPTED_RELEASE"
        )
        return index.get("complete"), index.get("limitation"), closed, boundaries

    def variant_doc(self, mutate) -> dict:
        events, transactions = base_document()
        doc = self.analyze(events, transactions)
        doc = json.loads(json.dumps(doc))
        mutate(doc)
        return doc

    def test_c2_a_missing_count_fails_closed(self) -> None:
        def mutate(doc):
            doc.pop("generation_closure_candidate_count")

        complete, limitation, closed, boundaries = self.closure_verdict(self.variant_doc(mutate))
        self.assertFalse(complete)
        self.assertIn("SOURCE_CANDIDATES_METADATA_INVALID", limitation)
        self.assertIn("generation_closure_candidate_count", limitation)
        self.assertEqual(closed, 0)
        self.assertEqual(
            sum(1 for item in boundaries if item["release_outcome"] == "ACCEPTED"), 2
        )

    def test_c2_b_invalid_count_fails_closed(self) -> None:
        for invalid in ("many", None, True, 1.5):
            def mutate(doc, invalid=invalid):
                doc["generation_closure_candidate_count"] = invalid

            complete, limitation, closed, _ = self.closure_verdict(self.variant_doc(mutate))
            self.assertFalse(complete, repr(invalid))
            self.assertIn("SOURCE_CANDIDATES_METADATA_INVALID", limitation)
            self.assertEqual(closed, 0, repr(invalid))

    def test_c2_c_underdeclared_count_fails_closed(self) -> None:
        def mutate(doc):
            doc["generation_closure_candidate_count"] = 1

        complete, limitation, closed, _ = self.closure_verdict(self.variant_doc(mutate))
        self.assertFalse(complete)
        self.assertIn("SOURCE_CANDIDATES_METADATA_INVALID", limitation)
        self.assertIn("underdeclares", limitation)
        self.assertEqual(closed, 0)

    def test_c2_d_nonzero_omitted_count_fails_closed(self) -> None:
        def mutate(doc):
            doc["generation_closure_candidates_omitted"] = 5

        complete, limitation, closed, _ = self.closure_verdict(self.variant_doc(mutate))
        self.assertFalse(complete)
        self.assertIn("SOURCE_CANDIDATES_METADATA_INVALID", limitation)
        self.assertIn("generation_closure_candidates_omitted", limitation)
        self.assertEqual(closed, 0)

    def test_c2_e_truncation_remains_blocked_with_its_own_token(self) -> None:
        def mutate(doc):
            doc["generation_closure_candidate_count"] = 257
            filler = json.loads(json.dumps(doc["generation_closure_candidates"][0]))
            filler.pop("generation_closure_candidate_reference", None)
            doc["generation_closure_candidates"] = doc["generation_closure_candidates"] + [
                filler
            ] * (256 - len(doc["generation_closure_candidates"]))

        complete, limitation, closed, _ = self.closure_verdict(self.variant_doc(mutate))
        self.assertFalse(complete)
        self.assertIn("SOURCE_CANDIDATES_TRUNCATED", limitation)
        self.assertEqual(closed, 0)

    def test_c2_f_valid_complete_document_permits_closure(self) -> None:
        events, transactions = base_document()
        doc = self.analyze(events, transactions)
        complete, limitation, closed, _ = self.closure_verdict(json.loads(json.dumps(doc)))
        self.assertTrue(complete)
        self.assertIsNone(limitation)
        self.assertEqual(closed, 2)

    def test_c2_no_input_order_fallback_selects_a_candidate(self) -> None:
        def mutate(doc):
            doc["generation_closure_candidate_count"] = 1

        doc = self.variant_doc(mutate)
        doc["generation_closure_candidates"] = list(
            reversed(doc["generation_closure_candidates"])
        )
        complete, limitation, closed, _ = self.closure_verdict(doc)
        self.assertFalse(complete)
        self.assertEqual(closed, 0)

    def test_c2_cli_end_to_end_missing_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            events, transactions = self.base()
            events_path, transactions_path = self.write_inputs(tmp_path, events, transactions)
            identity = self.run_identity(tmp_path, events_path, transactions_path)
            doctored = json.loads(identity.read_text(encoding="utf-8"))
            doctored.pop("generation_closure_candidate_count")
            broken = tmp_path / "identity-missing-count.json"
            broken.write_text(json.dumps(doctored, sort_keys=True), encoding="utf-8")
            code, analysis = self.run_lifecycle(
                tmp_path, events_path, transactions_path, broken
            )
            self.assertEqual(code, 0)
            self.assertIsNotNone(analysis)
            self.assertEqual(analysis["generation_boundary_count"], 0)
            self.assertTrue(
                any(
                    "SOURCE_CANDIDATES_METADATA_INVALID" in item
                    for item in analysis["evidence_limitations"]
                )
            )
            # The accepted release outcomes stay visible and unchanged.
            self.assertEqual(
                sum(
                    1
                    for item in analysis["generation_boundary_evidence"]
                    if item["release_outcome"] == "ACCEPTED"
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main()
