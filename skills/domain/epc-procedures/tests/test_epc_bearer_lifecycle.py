#!/usr/bin/env python3
"""Standalone tests for the bounded EPC bearer lifecycle-generation capability."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
CLI = SCRIPTS / "analyze_epc_bearer_lifecycle.py"
EXAMPLES = PACKAGE / "examples" / "lifecycle"

sys.path.insert(0, str(SCRIPTS))
import epc_bearer_lifecycle_model as model  # noqa: E402

CAPTURE = "fixture.pcap"


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(CLI), *args], capture_output=True, text=True, check=False)


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
def fteid(interface_type: int, teid: int, address: str) -> dict:
    return {"scope": "bearer", "interface_type": interface_type, "teid": teid, "ipv4": address}


def context(ebi: int, teids: list[dict], cause: int | None = None) -> dict:
    return {
        "ebi": ebi,
        "cause": {"cause_code": cause, "cause_name": "Request accepted", "scope": "bearer"}
        if cause is not None
        else None,
        "f_teids": teids,
    }


def gtpv2_event(
    frame: int,
    message: str,
    family: str,
    *,
    contexts: list[dict] | None = None,
    cause: int | None = None,
    capture: str = CAPTURE,
) -> dict:
    return {
        "capture_file": capture,
        "frame_number": frame,
        "message_type": message,
        "procedure_family": family,
        "cause": {"cause_code": cause, "cause_name": "Request accepted"} if cause is not None else None,
        "f_teids": [],
        "bearer_contexts": contexts or [],
    }


def tx_message(
    frame: int,
    message: str,
    *,
    session_teid: int = 1,
    cause: int | None = None,
    state: str = "PRESENT",
) -> dict:
    message_payload = {
        "frame_number": frame,
        "header_teid": session_teid,
        "header_teid_state": state,
        "message_type": message,
        "message_type_code": 0,
        "sequence_number": 1,
    }
    if cause is not None:
        message_payload["cause_code"] = cause
    return message_payload


def transaction(
    reference: str,
    family: str,
    request: tuple[int, str],
    response: tuple[int, str] | None,
    *,
    status: str = "MATCHED",
    strength: str = "STRONG",
    retransmissions: list[tuple[int, str]] | None = None,
    session_teid: int = 1,
    request_teid: int | None = None,
    response_cause: int | None = None,
) -> dict:
    response_message = (
        tx_message(*response, session_teid=session_teid, cause=response_cause) if response else None
    )
    return {
        "transaction_reference": reference,
        "procedure_family": family,
        "message_family": family,
        "request": tx_message(
            *request, session_teid=session_teid if request_teid is None else request_teid
        ),
        "response": response_message,
        "response_candidates": [response_message] if response_message else [],
        "correlation_status": status,
        "correlation_strength": strength,
        "correlation_basis": ["request/response message identity"],
        "corroboration": {"teid_echo": True},
        "retransmissions": [tx_message(*item) for item in retransmissions or []],
        "observation_window": {
            "start_frame": request[0],
            "end_frame": response[0] if response else request[0],
        },
        "evidence_refs": [
            tx_message(*request, session_teid=session_teid if request_teid is None else request_teid)
        ]
        + ([response_message] if response_message else []),
        "limitations": [],
    }


def tx_document(*transactions: dict) -> dict:
    return {
        "protocol": "gtpv2",
        "capture_files": [CAPTURE],
        "transaction_count": len(transactions),
        "matched_count": sum(1 for item in transactions if item["correlation_status"] == "MATCHED"),
        "open_request_count": sum(1 for item in transactions if item["correlation_status"] == "OPEN_REQUEST"),
        "response_only_count": sum(1 for item in transactions if item["correlation_status"] == "RESPONSE_ONLY"),
        "ambiguous_count": sum(1 for item in transactions if item["correlation_status"] == "AMBIGUOUS"),
        "retransmission_count": sum(len(item["retransmissions"]) for item in transactions),
        "transactions": list(transactions),
        "limitations": [],
    }


def stream(
    reference: str = "epc-s1u-stream-0000000001",
    *,
    direction: str = "UPLINK",
    destination: str = "198.51.100.2",
    teid: int = 100,
    packets: int = 3,
    octets: int = 300,
    first: int = 10,
    last: int = 20,
    status: str = "SUPPORTED",
    capture: str = CAPTURE,
    source: str = "198.51.100.1",
) -> dict:
    return {
        "stream_reference": reference,
        "capture_file": capture,
        "outer_source": source,
        "outer_destination": destination,
        "teid": teid,
        "direction": direction,
        "first_frame": first,
        "last_frame": last,
        "observed_g_pdu_packet_count": packets,
        "observed_payload_byte_count": octets,
        "association_status": status,
        "message_types": ["G-PDU"],
    }


def s1u_document(*streams: dict) -> dict:
    return {"stream_observations": list(streams)}


def gtpu_event(
    frame: int,
    *,
    source: str = "198.51.100.1",
    destination: str = "198.51.100.2",
    teid: int = 100,
    length: int = 100,
    message_type: str = "G-PDU",
    capture: str = CAPTURE,
) -> dict:
    return {
        "capture_file": capture,
        "frame_number": frame,
        "header": {"message_type": message_type, "teid": teid, "message_length": length},
        "outer": {"source_address": source, "destination_address": destination},
    }


def matched_pair(
    request_frame: int = 100,
    response_frame: int = 106,
    *,
    interface_type: int = 1,
    teid: int = 100,
    address: str = "198.51.100.2",
    ebi: int = 5,
    reference: str = "gtpv2-modify-bearer-100-1",
    family: str = "modify-bearer",
    status: str = "MATCHED",
    strength: str = "STRONG",
    request_cause: int | None = None,
    response_cause: int = 16,
) -> tuple[list[dict], dict]:
    events = [
        gtpv2_event(
            request_frame,
            "Modify Bearer Request" if family == "modify-bearer" else "Create Session Request",
            family,
            contexts=[context(ebi, [fteid(interface_type, teid, address)])],
            cause=request_cause,
        ),
        gtpv2_event(
            response_frame,
            "Modify Bearer Response" if family == "modify-bearer" else "Create Session Response",
            family,
            contexts=[context(ebi, [fteid(interface_type, teid, address)], cause=response_cause)],
            cause=response_cause,
        ),
    ]
    transactions = tx_document(
        transaction(
            reference,
            family,
            (request_frame, events[0]["message_type"]),
            (response_frame, events[1]["message_type"]),
            status=status,
            strength=strength,
        )
    )
    return events, transactions


# ---------------------------------------------------------------------------
# A — advertisement families
# ---------------------------------------------------------------------------
class AdvertisementFamilyTests(unittest.TestCase):
    def analyze(self, events, transactions, **kwargs):
        return model.analyze(events, transactions=transactions, **kwargs)

    def families(self, analysis):
        return analysis["advertisement_families"]

    # A01 / A02 ------------------------------------------------------------
    def test_matched_request_and_response_form_one_family(self) -> None:
        events, transactions = matched_pair()
        analysis = self.analyze(events, transactions)
        families = self.families(analysis)
        self.assertEqual(len(families), 1)
        family = families[0]
        self.assertEqual(family["family_classification"], "SAME_TRANSACTION_ADVERTISEMENTS")
        self.assertEqual(family["advertisement_count"], 2)
        self.assertEqual(family["source_frames"], [100, 106])
        self.assertEqual(
            family["source_message_types"], ["Modify Bearer Request", "Modify Bearer Response"]
        )
        self.assertEqual(family["source_transaction_references"], ["gtpv2-modify-bearer-100-1"])
        self.assertEqual(family["correlation_status"], "MATCHED")
        self.assertEqual(family["correlation_strength"], "STRONG")
        self.assertEqual(family["bearer_identity_scope"], [5])
        self.assertEqual(family["reviewed_interface_type"], 1)
        self.assertEqual(family["receiving_endpoint_role"], "sgw_s1u")

    def test_both_source_frames_stay_in_the_evidence(self) -> None:
        events, transactions = matched_pair()
        analysis = self.analyze(events, transactions)
        frames = [ref["frame_number"] for ref in self.families(analysis)[0]["evidence_refs"]]
        self.assertEqual(frames, [100, 106])
        self.assertTrue(all(ref["protocol"] == "GTPv2-C" for ref in self.families(analysis)[0]["evidence_refs"]))

    # A03 ------------------------------------------------------------------
    def test_retransmission_does_not_create_another_allocation(self) -> None:
        events, transactions = matched_pair()
        events.append(
            gtpv2_event(
                112,
                "Modify Bearer Request",
                "modify-bearer",
                contexts=[context(5, [fteid(1, 100, "198.51.100.2")])],
            )
        )
        transactions["transactions"][0]["retransmissions"] = [tx_message(112, "Modify Bearer Request")]
        transactions["retransmission_count"] = 1
        analysis = self.analyze(events, transactions)
        families = self.families(analysis)
        self.assertEqual(len(families), 1)
        self.assertEqual(families[0]["family_classification"], "SAME_TRANSACTION_ADVERTISEMENTS")
        self.assertEqual(families[0]["source_frames"], [100, 106, 112])
        self.assertEqual(analysis["lifecycle_subject_count"], 1)

    # A04 ------------------------------------------------------------------
    def test_two_allocation_transactions_with_one_endpoint_do_not_merge(self) -> None:
        events = [
            gtpv2_event(100, "Create Session Request", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
            gtpv2_event(106, "Create Session Response", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)]),
            gtpv2_event(200, "Create Session Request", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
            gtpv2_event(206, "Create Session Response", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)]),
        ]
        transactions = tx_document(
            transaction("gtpv2-create-session-100-1", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
            transaction("gtpv2-create-session-200-2", "create-session", (200, "Create Session Request"), (206, "Create Session Response")),
        )
        analysis = self.analyze(events, transactions)
        families = self.families(analysis)
        self.assertEqual(len(families), 1)
        self.assertEqual(families[0]["family_classification"], "INSUFFICIENT_GENERATION_EVIDENCE")
        self.assertEqual(families[0]["classification_basis"], "more_than_one_allocation_transaction_advertises_this_endpoint")
        self.assertEqual(analysis["lifecycle_subject_count"], 0)
        self.assertTrue(analysis["unbound_evidence"])

    # A05 ------------------------------------------------------------------
    def test_conflicting_bearer_identities_block_consolidation(self) -> None:
        events = [
            gtpv2_event(100, "Modify Bearer Request", "modify-bearer", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
            gtpv2_event(106, "Modify Bearer Response", "modify-bearer", contexts=[context(6, [fteid(1, 100, "198.51.100.2")], cause=16)]),
        ]
        transactions = tx_document(
            transaction("gtpv2-modify-bearer-100-1", "modify-bearer", (100, "Modify Bearer Request"), (106, "Modify Bearer Response"))
        )
        analysis = self.analyze(events, transactions)
        family = self.families(analysis)[0]
        self.assertEqual(family["family_classification"], "COMPETING_ALLOCATION_EVIDENCE")
        self.assertEqual(family["classification_basis"], "bearer_identity_conflict_within_transaction")
        self.assertEqual(family["bearer_identity_scope"], [5, 6])
        self.assertEqual(analysis["lifecycle_subject_count"], 0)

    # A06 ------------------------------------------------------------------
    def test_response_only_transaction_establishes_no_family(self) -> None:
        events = [
            gtpv2_event(106, "Modify Bearer Response", "modify-bearer", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)])
        ]
        transactions = tx_document(
            transaction(
                "gtpv2-modify-bearer-106-1", "modify-bearer", (106, "Modify Bearer Response"), None,
                status="RESPONSE_ONLY",
            )
        )
        analysis = self.analyze(events, transactions)
        family = self.families(analysis)[0]
        self.assertEqual(family["family_classification"], "INSUFFICIENT_GENERATION_EVIDENCE")
        self.assertEqual(analysis["lifecycle_subject_count"], 0)

    # A07 ------------------------------------------------------------------
    def test_open_request_establishes_no_accepted_allocation(self) -> None:
        events = [
            gtpv2_event(100, "Create Session Request", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])])
        ]
        transactions = tx_document(
            transaction(
                "gtpv2-create-session-100-1", "create-session", (100, "Create Session Request"), None,
                status="OPEN_REQUEST",
            )
        )
        analysis = self.analyze(events, transactions)
        family = self.families(analysis)[0]
        self.assertEqual(family["family_classification"], "INSUFFICIENT_GENERATION_EVIDENCE")
        self.assertEqual(family["classification_basis"], "transaction_correlation_open_request")

    # A08 ------------------------------------------------------------------
    def test_ambiguous_correlation_establishes_no_family(self) -> None:
        events, transactions = matched_pair(status="AMBIGUOUS")
        analysis = self.analyze(events, transactions)
        family = self.families(analysis)[0]
        self.assertEqual(family["family_classification"], "INSUFFICIENT_GENERATION_EVIDENCE")
        self.assertEqual(family["classification_basis"], "transaction_correlation_ambiguous")

    # A09 ------------------------------------------------------------------
    def test_negative_cause_is_not_successful_provisioning(self) -> None:
        events, transactions = matched_pair(response_cause=64)
        analysis = self.analyze(events, transactions)
        family = self.families(analysis)[0]
        self.assertEqual(family["family_classification"], "INSUFFICIENT_GENERATION_EVIDENCE")
        self.assertEqual(family["classification_basis"], "non_accepted_cause_observed")

    # A10 ------------------------------------------------------------------
    def test_distinct_endpoints_in_one_transaction_stay_separable(self) -> None:
        events = [
            gtpv2_event(
                100,
                "Create Session Request",
                "create-session",
                contexts=[
                    context(5, [fteid(1, 100, "198.51.100.2")]),
                    context(6, [fteid(1, 200, "198.51.100.3")]),
                ],
            )
        ]
        transactions = tx_document(
            transaction(
                "gtpv2-create-session-100-1", "create-session", (100, "Create Session Request"), None,
                status="OPEN_REQUEST",
            )
        )
        analysis = self.analyze(events, transactions)
        families = self.families(analysis)
        self.assertEqual(len(families), 2)
        self.assertEqual(
            sorted((family["receiving_endpoint_teid"], family["bearer_identity_scope"][0]) for family in families),
            [(100, 5), (200, 6)],
        )


# ---------------------------------------------------------------------------
# L — lifecycle generations
# ---------------------------------------------------------------------------
class LifecycleGenerationTests(unittest.TestCase):
    def analyze(self, events, transactions, **kwargs):
        return model.analyze(events, transactions=transactions, **kwargs)

    # L01 ------------------------------------------------------------------
    def test_accepted_release_bound_to_the_endpoint_closes_the_generation(self) -> None:
        events, transactions = matched_pair()
        events.extend(
            [
                gtpv2_event(300, "Delete Session Request", "delete-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
                gtpv2_event(306, "Delete Session Response", "delete-session", contexts=[], cause=16),
            ]
        )
        transactions["transactions"].append(
            transaction("gtpv2-delete-session-300-2", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response"))
        )
        analysis = self.analyze(events, transactions)
        generation = analysis["lifecycle_subjects"][0]
        self.assertEqual(generation["generation_state"], "CLOSED_BY_ACCEPTED_RELEASE")
        boundary = generation["generation_boundary"]
        # The request initiates the release; only the correlated response confirms it.
        self.assertEqual(boundary["release_request_frame"], 300)
        self.assertEqual(boundary["release_confirmation_frame"], 306)
        self.assertEqual(boundary["frame_number"], 306)
        self.assertFalse(boundary["release_effective_frame_proven"])
        self.assertEqual(
            boundary["basis"],
            "accepted_release_response_bound_to_the_same_control_plane_context",
        )
        self.assertIn("RELEASE_REQUEST_OBSERVED", generation["observations"])
        self.assertIn("RELEASE_ACCEPTED_OBSERVED", generation["observations"])
        self.assertIn("GENERATION_BOUNDARY_ESTABLISHED", generation["observations"])

    # L02 ------------------------------------------------------------------
    def test_release_without_an_accepted_outcome_closes_nothing(self) -> None:
        events, transactions = matched_pair()
        events.extend(
            [
                gtpv2_event(300, "Delete Session Request", "delete-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
                gtpv2_event(306, "Delete Session Response", "delete-session", contexts=[]),
            ]
        )
        transactions["transactions"].append(
            transaction("gtpv2-delete-session-300-2", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response"))
        )
        analysis = self.analyze(events, transactions)
        generation = analysis["lifecycle_subjects"][0]
        self.assertEqual(generation["generation_state"], "OPEN_AT_CAPTURE_END")
        self.assertIn("RELEASE_STATUS_UNRESOLVED", generation["observations"])
        self.assertIsNone(generation["generation_boundary"])
        self.assertTrue(any("accepted outcome" in item for item in analysis["evidence_limitations"]))

    def test_release_that_names_no_endpoint_closes_nothing(self) -> None:
        events, transactions = matched_pair()
        events.extend(
            [
                gtpv2_event(300, "Delete Session Request", "delete-session", contexts=[]),
                gtpv2_event(306, "Delete Session Response", "delete-session", contexts=[], cause=16),
            ]
        )
        transactions["transactions"].append(
            transaction("gtpv2-delete-session-300-2", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response"))
        )
        analysis = self.analyze(events, transactions)
        self.assertEqual(analysis["lifecycle_subjects"][0]["generation_state"], "OPEN_AT_CAPTURE_END")

    # L03 ------------------------------------------------------------------
    def test_reuse_across_a_proved_boundary_stays_separate(self) -> None:
        events, transactions = matched_pair()
        events.extend(
            [
                gtpv2_event(300, "Delete Session Request", "delete-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
                gtpv2_event(306, "Delete Session Response", "delete-session", contexts=[], cause=16),
                gtpv2_event(400, "Create Session Request", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
                gtpv2_event(406, "Create Session Response", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)]),
            ]
        )
        transactions["transactions"].extend(
            [
                transaction("gtpv2-delete-session-300-2", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response")),
                transaction("gtpv2-create-session-400-3", "create-session", (400, "Create Session Request"), (406, "Create Session Response")),
            ]
        )
        analysis = self.analyze(events, transactions)
        self.assertEqual(analysis["lifecycle_subject_count"], 2)
        reuse = analysis["endpoint_reuse_observations"]
        self.assertEqual(len(reuse), 1)
        self.assertEqual(reuse[0]["basis"], "release_boundary_separates_generations")
        self.assertNotEqual(
            reuse[0]["previous_generation_reference"], reuse[0]["current_generation_reference"]
        )

    # L04 ------------------------------------------------------------------
    def test_reuse_without_a_proved_boundary_stays_ambiguous(self) -> None:
        events = [
            gtpv2_event(100, "Create Session Request", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
            gtpv2_event(106, "Create Session Response", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)]),
            gtpv2_event(200, "Create Session Request", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
            gtpv2_event(206, "Create Session Response", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)]),
        ]
        transactions = tx_document(
            transaction("gtpv2-create-session-100-1", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
            transaction("gtpv2-create-session-200-2", "create-session", (200, "Create Session Request"), (206, "Create Session Response")),
        )
        analysis = self.analyze(events, transactions)
        self.assertEqual(analysis["lifecycle_subject_count"], 0)
        self.assertEqual(analysis["endpoint_reuse_observation_count"], 0)
        self.assertTrue(analysis["unbound_evidence"])

    # L05 ------------------------------------------------------------------
    def test_same_bearer_identity_on_different_contexts_does_not_merge(self) -> None:
        events = [
            gtpv2_event(100, "Create Session Request", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
            gtpv2_event(106, "Create Session Response", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)]),
            gtpv2_event(200, "Create Session Request", "create-session", contexts=[context(5, [fteid(1, 200, "198.51.100.3")])]),
            gtpv2_event(206, "Create Session Response", "create-session", contexts=[context(5, [fteid(1, 200, "198.51.100.3")], cause=16)]),
        ]
        transactions = tx_document(
            transaction("gtpv2-create-session-100-1", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
            transaction("gtpv2-create-session-200-2", "create-session", (200, "Create Session Request"), (206, "Create Session Response")),
        )
        analysis = self.analyze(events, transactions)
        self.assertEqual(analysis["lifecycle_subject_count"], 2)
        self.assertNotEqual(
            analysis["lifecycle_subjects"][0]["generation_reference"],
            analysis["lifecycle_subjects"][1]["generation_reference"],
        )

    # L06 ------------------------------------------------------------------
    def test_same_teid_on_different_addresses_does_not_merge(self) -> None:
        events = [
            gtpv2_event(100, "Create Session Request", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
            gtpv2_event(106, "Create Session Response", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)]),
            gtpv2_event(200, "Create Session Request", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.9")])]),
            gtpv2_event(206, "Create Session Response", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.9")], cause=16)]),
        ]
        transactions = tx_document(
            transaction("gtpv2-create-session-100-1", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
            transaction("gtpv2-create-session-200-2", "create-session", (200, "Create Session Request"), (206, "Create Session Response")),
        )
        analysis = self.analyze(events, transactions)
        self.assertEqual(analysis["lifecycle_subject_count"], 2)
        self.assertEqual(analysis["endpoint_reuse_observation_count"], 0)

    # L07 ------------------------------------------------------------------
    def test_different_interface_types_stay_distinct(self) -> None:
        events = [
            gtpv2_event(100, "Create Session Response", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)]),
            gtpv2_event(200, "Modify Bearer Response", "modify-bearer", contexts=[context(5, [fteid(0, 100, "198.51.100.2")], cause=16)]),
        ]
        transactions = tx_document(
            transaction("gtpv2-create-session-100-1", "create-session", (100, "Create Session Response"), None, status="RESPONSE_ONLY"),
            transaction("gtpv2-modify-bearer-200-2", "modify-bearer", (200, "Modify Bearer Response"), None, status="RESPONSE_ONLY"),
        )
        analysis = self.analyze(events, transactions)
        families = analysis["advertisement_families"]
        self.assertEqual(len(families), 2)
        self.assertEqual(sorted(family["reviewed_interface_type"] for family in families), [0, 1])
        self.assertEqual(
            sorted(family["receiving_endpoint_role"] for family in families), ["enodeb_s1u", "sgw_s1u"]
        )

    # L08 ------------------------------------------------------------------
    def test_s11_and_s5s8_are_never_joined(self) -> None:
        events, transactions = matched_pair()
        analysis = self.analyze(events, transactions)
        self.assertTrue(
            any("no S11 to S5/S8 session identity is asserted" == item for item in analysis["not_confirmed"])
        )
        for family in analysis["advertisement_families"]:
            self.assertNotIn("session_reference", family)
        for generation in analysis["lifecycle_subjects"]:
            self.assertNotIn("session_reference", generation)

    # L09 ------------------------------------------------------------------
    def test_repeated_endpoint_updates_do_not_fabricate_a_generation(self) -> None:
        events = [
            gtpv2_event(100, "Create Session Request", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
            gtpv2_event(106, "Create Session Response", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)]),
            gtpv2_event(200, "Modify Bearer Request", "modify-bearer", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
            gtpv2_event(206, "Modify Bearer Response", "modify-bearer", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)]),
        ]
        transactions = tx_document(
            transaction("gtpv2-create-session-100-1", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
            transaction("gtpv2-modify-bearer-200-2", "modify-bearer", (200, "Modify Bearer Request"), (206, "Modify Bearer Response")),
        )
        analysis = self.analyze(events, transactions)
        self.assertEqual(analysis["lifecycle_subject_count"], 1)
        self.assertEqual(
            analysis["advertisement_families"][0]["family_classification"],
            "SAME_GENERATION_UPDATE_SUPPORTED",
        )
        self.assertEqual(analysis["endpoint_reuse_observation_count"], 0)

    # L10 ------------------------------------------------------------------
    def test_generation_references_are_deterministic_and_scoped(self) -> None:
        events, transactions = matched_pair()
        first = self.analyze(events, transactions)
        second = self.analyze(json.loads(json.dumps(events)), json.loads(json.dumps(transactions)))
        self.assertEqual(first, second)
        reference = first["lifecycle_subjects"][0]["generation_reference"]
        self.assertTrue(reference.startswith("epc-bearer-generation-"))
        other_capture = json.loads(json.dumps(events))
        for event in other_capture:
            event["capture_file"] = "other.pcap"
        other = self.analyze(other_capture, transactions)
        self.assertNotEqual(other["lifecycle_subjects"][0]["generation_reference"], reference)


# ---------------------------------------------------------------------------
# U — generation-aware GTP-U attribution
# ---------------------------------------------------------------------------
class GenerationPacketAttributionTests(unittest.TestCase):
    def analyze(self, events, transactions, streams, gtpu, **kwargs):
        return model.analyze(
            events,
            transactions=transactions,
            s1u_analysis=s1u_document(*streams),
            gtpu_events=gtpu,
            **kwargs,
        )

    # U01 / U08 ------------------------------------------------------------
    def test_aggregate_counts_are_conserved(self) -> None:
        events, transactions = matched_pair()
        streams = [stream(packets=3, octets=300, first=110, last=120)]
        gtpu = [gtpu_event(frame, length=100) for frame in (110, 114, 118)]
        analysis = self.analyze(events, transactions, streams, gtpu)
        accounting = analysis["accounting"]
        self.assertEqual(accounting["aggregate_g_pdu_count"], 3)
        self.assertEqual(accounting["attributed_g_pdu_count"], 3)
        self.assertEqual(accounting["unresolved_g_pdu_count"], 0)
        self.assertTrue(accounting["conserved_g_pdu"])
        self.assertTrue(accounting["conserved_payload_octets"])

    # U02 ------------------------------------------------------------------
    def test_attribution_is_derived_from_frame_events(self) -> None:
        events, transactions = matched_pair()
        streams = [stream(packets=5, octets=500, first=110, last=140)]
        gtpu = [gtpu_event(frame, length=100) for frame in (110, 120, 130)]
        analysis = self.analyze(events, transactions, streams, gtpu)
        scoped = analysis["generation_scoped_s1u_observations"][0]
        self.assertEqual(scoped["observed_g_pdu_count"], 3)
        unresolved = analysis["unresolved_packet_observations"][0]
        self.assertEqual(unresolved["observed_g_pdu_count"], 2)
        self.assertEqual(
            unresolved["basis"], "frames_outside_the_proved_generation_window"
        )

    # U03 ------------------------------------------------------------------
    def test_no_packet_belongs_to_two_segments(self) -> None:
        events, transactions = matched_pair()
        streams = [stream(packets=3, octets=300, first=110, last=140)]
        gtpu = [gtpu_event(frame, length=100) for frame in (110, 120, 130)]
        analysis = self.analyze(events, transactions, streams, gtpu)
        total = sum(
            item["observed_g_pdu_count"]
            for item in analysis["generation_scoped_s1u_observations"]
            + analysis["unresolved_packet_observations"]
        )
        self.assertEqual(total, 3)

    # U04 ------------------------------------------------------------------
    def test_unsupported_stream_stays_unresolved(self) -> None:
        events, transactions = matched_pair()
        streams = [stream(status="NOT_ESTABLISHED", packets=4, octets=400)]
        gtpu = [gtpu_event(frame) for frame in (10, 11, 12, 13)]
        analysis = self.analyze(events, transactions, streams, gtpu)
        self.assertEqual(analysis["generation_scoped_observation_count"], 0)
        unresolved = analysis["unresolved_packet_observations"][0]
        self.assertEqual(unresolved["observed_g_pdu_count"], 4)
        self.assertEqual(unresolved["association_status"], "GENERATION_UNRESOLVED")

    # U05 ------------------------------------------------------------------
    def test_packets_before_a_boundary_are_not_assigned_to_the_later_generation(self) -> None:
        events, transactions = matched_pair()
        events.extend(
            [
                gtpv2_event(300, "Delete Session Request", "delete-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
                gtpv2_event(306, "Delete Session Response", "delete-session", contexts=[], cause=16),
                gtpv2_event(400, "Create Session Request", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
                gtpv2_event(406, "Create Session Response", "create-session", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)]),
            ]
        )
        transactions["transactions"].extend(
            [
                transaction("gtpv2-delete-session-300-2", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response")),
                transaction("gtpv2-create-session-400-3", "create-session", (400, "Create Session Request"), (406, "Create Session Response")),
            ]
        )
        # The stream spans both generations, so no single generation covers it.
        streams = [stream(packets=4, octets=400, first=150, last=450)]
        gtpu = [gtpu_event(frame, length=100) for frame in (150, 250, 350, 450)]
        analysis = self.analyze(events, transactions, streams, gtpu)
        self.assertEqual(analysis["ambiguous_association_count"], 1)
        self.assertEqual(analysis["generation_scoped_observation_count"], 0)
        unresolved = analysis["unresolved_packet_observations"][0]
        self.assertEqual(unresolved["observed_g_pdu_count"], 4)
        self.assertEqual(unresolved["basis"], "several_generations_cover_this_endpoint")

    # U06 ------------------------------------------------------------------
    def test_direction_semantics_are_unchanged(self) -> None:
        events, transactions = matched_pair(interface_type=0, address="198.51.100.9", teid=500)
        streams = [
            stream(direction="DOWNLINK", destination="198.51.100.9", teid=500, source="198.51.100.2",
                   packets=2, octets=200, first=110, last=120)
        ]
        gtpu = [
            gtpu_event(110, source="198.51.100.2", destination="198.51.100.9", teid=500, length=100),
            gtpu_event(120, source="198.51.100.2", destination="198.51.100.9", teid=500, length=100),
        ]
        analysis = self.analyze(events, transactions, streams, gtpu)
        scoped = analysis["generation_scoped_s1u_observations"][0]
        self.assertEqual(scoped["direction"], "DOWNLINK")
        self.assertEqual(scoped["receiving_endpoint_role"], "enodeb_s1u")

    # U07 ------------------------------------------------------------------
    def test_type_zero_and_type_one_semantics_are_unchanged(self) -> None:
        self.assertEqual(model.INTERFACE_TYPE_ROLE, {1: "sgw_s1u", 0: "enodeb_s1u"})
        self.assertEqual(model.ROLE_INTERFACE_TYPE, {"sgw_s1u": 1, "enodeb_s1u": 0})

    # U09 ------------------------------------------------------------------
    def test_an_empty_window_does_not_prove_failure(self) -> None:
        events, transactions = matched_pair()
        streams = [stream(packets=0, octets=0, first=110, last=110)]
        analysis = self.analyze(events, transactions, streams, [])
        self.assertTrue(analysis["evidence_limitations"])
        serialized = json.dumps(analysis)
        for forbidden in ("TUNNEL_FAILED", "PACKET_LOSS", "DELIVERY_CONFIRMED", "USER_RECEIVED_PACKET"):
            self.assertNotIn(forbidden, serialized)

    # U10 ------------------------------------------------------------------
    def test_unsupported_lifecycle_claims_are_absent(self) -> None:
        events, transactions = matched_pair()
        analysis = self.analyze(events, transactions, [stream()], [gtpu_event(12)])
        serialized = json.dumps(analysis)
        for forbidden in (
            "ESTABLISHED_LIFECYCLE",
            "BEARER_ACTIVE",
            "APPLICATION_REACHABLE",
            "SUBSCRIBER_IDENTIFIED",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(analysis["boundary_selection_status"], "NOT_APPLICABLE")
        self.assertIsNone(analysis["first_abnormal_boundary"])
        self.assertTrue(analysis["not_confirmed"])


# ---------------------------------------------------------------------------
# Standalone CLI and example
# ---------------------------------------------------------------------------
class CliContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def analyze_example(self, name: str = "analysis.json", extra: tuple[str, ...] = ()) -> Path:
        output = self.base / name
        completed = run(
            "--gtpv2", str(EXAMPLES / "gtpv2-events.jsonl"),
            "--transactions", str(EXAMPLES / "gtpv2-transactions.json"),
            "--s1u", str(EXAMPLES / "s1u-observation.json"),
            "--gtpu", str(EXAMPLES / "gtpu-events.jsonl"),
            "--output", str(output),
            *extra,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output

    def test_example_reproduces_the_committed_analysis(self) -> None:
        produced = load_json(self.analyze_example())
        expected = load_json(EXAMPLES / "expected-analysis.json")
        produced.pop("input_provenance", None)
        expected.pop("input_provenance", None)
        self.assertEqual(produced, expected)

    def test_timeline_output_is_written(self) -> None:
        output = self.analyze_example("analysis.json", ("--timeline-output", str(self.base / "timeline.jsonl")))
        self.assertTrue(output.is_file())
        rows = load_jsonl(self.base / "timeline.jsonl")
        self.assertTrue(rows)
        self.assertTrue(all("generation_reference" in row for row in rows))

    def test_existing_output_requires_force(self) -> None:
        self.analyze_example()
        completed = run(
            "--gtpv2", str(EXAMPLES / "gtpv2-events.jsonl"),
            "--transactions", str(EXAMPLES / "gtpv2-transactions.json"),
            "--output", str(self.base / "analysis.json"),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("already exists", completed.stderr)

    def test_malformed_input_fails_visibly(self) -> None:
        broken = self.base / "broken.jsonl"
        broken.write_text("{not json}\n", encoding="utf-8")
        completed = run(
            "--gtpv2", str(broken),
            "--transactions", str(EXAMPLES / "gtpv2-transactions.json"),
            "--output", str(self.base / "analysis.json"),
        )
        self.assertEqual(completed.returncode, model.EXIT_MALFORMED_INPUT)
        self.assertIn("invalid JSON Lines", completed.stderr)

    def test_partial_inputs_publish_limitations(self) -> None:
        output = self.base / "partial.json"
        completed = run(
            "--gtpv2", str(EXAMPLES / "gtpv2-events.jsonl"),
            "--transactions", str(EXAMPLES / "gtpv2-transactions.json"),
            "--output", str(output),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        analysis = load_json(output)
        self.assertTrue(any("S1-U observation" in item for item in analysis["evidence_limitations"]))

    def test_output_is_deterministic(self) -> None:
        first = load_json(self.analyze_example("first.json"))
        second = load_json(self.analyze_example("second.json"))
        first.pop("input_provenance", None)
        second.pop("input_provenance", None)
        self.assertEqual(first, second)


# ---------------------------------------------------------------------------
# C — capture and control-plane context isolation
# ---------------------------------------------------------------------------
def allocation(
    frame: int,
    *,
    capture: str = CAPTURE,
    teid: int = 100,
    address: str = "198.51.100.2",
    interface_type: int = 1,
    ebi: int = 5,
) -> list[dict]:
    return [
        gtpv2_event(
            frame,
            "Create Session Request",
            "create-session",
            contexts=[context(ebi, [fteid(interface_type, teid, address)])],
            capture=capture,
        ),
        gtpv2_event(
            frame + 6,
            "Create Session Response",
            "create-session",
            contexts=[context(ebi, [fteid(interface_type, teid, address)], cause=16)],
            cause=16,
            capture=capture,
        ),
    ]


def release(
    frame: int,
    *,
    capture: str = CAPTURE,
    teid: int = 100,
    address: str = "198.51.100.2",
    interface_type: int = 1,
    ebi: int = 5,
    cause: int = 16,
) -> list[dict]:
    return [
        gtpv2_event(
            frame,
            "Delete Session Request",
            "delete-session",
            contexts=[context(ebi, [fteid(interface_type, teid, address)])],
            capture=capture,
        ),
        gtpv2_event(
            frame + 6,
            "Delete Session Response",
            "delete-session",
            contexts=[],
            cause=cause,
            capture=capture,
        ),
    ]


class ReleaseProvenanceTests(unittest.TestCase):
    """C: a release may only close a generation of its own capture and context."""

    def analyze(self, events, transactions):
        return model.analyze(events, transactions=transactions)

    def generations(self, analysis):
        return analysis["lifecycle_subjects"]

    # C01 -----------------------------------------------------------------
    def test_cross_capture_release_never_closes_another_capture(self) -> None:
        events = allocation(100, capture="A.pcap") + release(300, capture="B.pcap")
        transactions = tx_document(
            transaction("cs-A", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
            transaction("ds-B", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response")),
        )
        analysis = self.analyze(events, transactions)
        generation = self.generations(analysis)[0]
        self.assertEqual(generation["capture_file"], "A.pcap")
        self.assertEqual(generation["generation_state"], "OPEN_AT_CAPTURE_END")
        self.assertIsNone(generation["generation_boundary"])
        self.assertIn("RELEASE_STATUS_UNRESOLVED", generation["observations"])
        boundary = analysis["generation_boundary_evidence"][0]
        self.assertEqual(boundary["capture_file"], "B.pcap")
        self.assertEqual(boundary["release_outcome"], "ACCEPTED")

    # C02 -----------------------------------------------------------------
    def test_equal_teids_in_distinct_captures_stay_separate(self) -> None:
        events = (
            allocation(100, capture="A.pcap")
            + release(300, capture="A.pcap")
            + allocation(500, capture="B.pcap")
            + release(700, capture="B.pcap")
        )
        transactions = tx_document(
            transaction("cs-A", "create-session", (100, "Create Session Request"), (106, "Create Session Response"), session_teid=1),
            transaction("ds-A", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response"), session_teid=1, response_cause=16),
            transaction("cs-B", "create-session", (500, "Create Session Request"), (506, "Create Session Response"), session_teid=2),
            transaction("ds-B", "delete-session", (700, "Delete Session Request"), (706, "Delete Session Response"), session_teid=2, response_cause=16),
        )
        analysis = self.analyze(events, transactions)
        by_capture = {item["capture_file"]: item for item in self.generations(analysis)}
        self.assertEqual(sorted(by_capture), ["A.pcap", "B.pcap"])
        for capture, generation in by_capture.items():
            self.assertEqual(generation["generation_state"], "CLOSED_BY_ACCEPTED_RELEASE", capture)
            self.assertEqual(
                generation["generation_boundary"]["release_request_frame"],
                300 if capture == "A.pcap" else 700,
            )
        self.assertEqual(analysis["endpoint_reuse_observation_count"], 0)

    # C03 -----------------------------------------------------------------
    def test_same_capture_but_another_control_plane_context_does_not_close(self) -> None:
        events = allocation(100) + release(300)
        transactions = tx_document(
            transaction("cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response"), session_teid=3),
            transaction("ds", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response"), session_teid=7),
        )
        analysis = self.analyze(events, transactions)
        generation = self.generations(analysis)[0]
        self.assertEqual(generation["generation_state"], "OPEN_AT_CAPTURE_END")
        self.assertIsNone(generation["generation_boundary"])

    def test_missing_control_plane_context_keeps_the_release_unresolved(self) -> None:
        events = allocation(100) + release(300)
        transactions = tx_document(
            transaction(
                "cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response"),
                session_teid=0, response_cause=16,
            ),
            transaction("ds", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response")),
        )
        for item in transactions["transactions"]:
            item["response"]["header_teid_state"] = "ZERO"
        analysis = self.analyze(events, transactions)
        generation = self.generations(analysis)[0]
        self.assertEqual(generation["generation_state"], "OPEN_AT_CAPTURE_END")

    # C04 -----------------------------------------------------------------
    def test_incompatible_interface_type_does_not_close(self) -> None:
        events = allocation(100, interface_type=1) + release(300, interface_type=0)
        transactions = tx_document(
            transaction("cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
            transaction("ds", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response")),
        )
        analysis = self.analyze(events, transactions)
        self.assertEqual(self.generations(analysis)[0]["generation_state"], "OPEN_AT_CAPTURE_END")

    # C05 -----------------------------------------------------------------
    def test_several_candidate_releases_keep_the_association_unresolved(self) -> None:
        events = allocation(100) + release(300) + release(400)
        transactions = tx_document(
            transaction("cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
            transaction("ds1", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response")),
            transaction("ds2", "delete-session", (400, "Delete Session Request"), (406, "Delete Session Response")),
        )
        analysis = self.analyze(events, transactions)
        self.assertEqual(self.generations(analysis)[0]["generation_state"], "OPEN_AT_CAPTURE_END")

    # C06 -----------------------------------------------------------------
    def test_boundary_retains_full_provenance(self) -> None:
        events = allocation(100) + release(300)
        transactions = tx_document(
            transaction("cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
            transaction("ds", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response")),
        )
        analysis = self.analyze(events, transactions)
        boundary = analysis["generation_boundary_evidence"][0]
        self.assertEqual(boundary["capture_file"], CAPTURE)
        self.assertEqual(boundary["request_frame"], 300)
        self.assertEqual(boundary["request_message_type"], "Delete Session Request")
        self.assertEqual(boundary["response_frame"], 306)
        self.assertEqual(boundary["response_message_type"], "Delete Session Response")
        self.assertEqual(boundary["correlation_status"], "MATCHED")
        self.assertEqual(boundary["correlation_strength"], "STRONG")
        self.assertEqual(boundary["release_outcome"], "ACCEPTED")
        self.assertEqual(
            [ref["frame_number"] for ref in boundary["evidence_refs"]], [300, 306]
        )


# ---------------------------------------------------------------------------
# R — release outcome proof
# ---------------------------------------------------------------------------
class ReleaseOutcomeTests(unittest.TestCase):
    """R: acceptance is established only by the correlated response."""

    def analyze(self, events, transactions):
        return model.analyze(events, transactions=transactions)

    def generation(self, analysis):
        return analysis["lifecycle_subjects"][0]

    def build(self, *, status="MATCHED", strength="STRONG", response_cause=16,
              request_cause=None, bearer_cause=None, response_event_cause="auto"):
        events = allocation(100)
        delete_events = release(300, cause=response_cause if response_cause is not None else 0)
        if request_cause is not None:
            delete_events[0]["cause"] = {"cause_code": request_cause, "cause_name": "x"}
        if bearer_cause is not None:
            delete_events[1]["bearer_contexts"] = [context(5, [], cause=bearer_cause)]
        if response_event_cause == "drop":
            delete_events[1]["cause"] = None
        elif response_event_cause == "none":
            delete_events[1]["cause"] = None
        events = events + delete_events
        transactions = tx_document(
            transaction("cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
            transaction(
                "ds", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response"),
                status=status, strength=strength,
                response_cause=None if response_cause is None else response_cause,
            ),
        )
        return events, transactions

    # R01 -----------------------------------------------------------------
    def test_matched_accepted_response_supports_the_release(self) -> None:
        events, transactions = self.build()
        generation = self.generation(self.analyze(events, transactions))
        self.assertEqual(generation["generation_state"], "CLOSED_BY_ACCEPTED_RELEASE")

    # R02 -----------------------------------------------------------------
    def test_ambiguous_transaction_cannot_establish_acceptance(self) -> None:
        events, transactions = self.build(status="AMBIGUOUS")
        analysis = self.analyze(events, transactions)
        self.assertEqual(self.generation(analysis)["generation_state"], "OPEN_AT_CAPTURE_END")
        boundary = analysis["generation_boundary_evidence"][0]
        self.assertEqual(boundary["release_outcome"], "UNRESOLVED")
        self.assertEqual(boundary["release_outcome_basis"], "release_correlation_ambiguous")

    # R03 -----------------------------------------------------------------
    def test_open_request_cannot_close_a_generation(self) -> None:
        events, transactions = self.build(status="OPEN_REQUEST")
        analysis = self.analyze(events, transactions)
        self.assertEqual(self.generation(analysis)["generation_state"], "OPEN_AT_CAPTURE_END")
        self.assertEqual(
            analysis["generation_boundary_evidence"][0]["release_outcome_basis"],
            "release_correlation_open_request",
        )

    # R04 -----------------------------------------------------------------
    def test_response_only_cannot_fabricate_a_pair(self) -> None:
        events = allocation(100) + release(300)
        transactions = tx_document(
            transaction("cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
            transaction("ds", "delete-session", (300, "Delete Session Request"), None, status="RESPONSE_ONLY"),
        )
        analysis = self.analyze(events, transactions)
        self.assertEqual(self.generation(analysis)["generation_state"], "OPEN_AT_CAPTURE_END")
        self.assertEqual(
            analysis["generation_boundary_evidence"][0]["release_outcome_basis"],
            "release_correlation_response_only",
        )

    # R05 -----------------------------------------------------------------
    def test_negative_response_cannot_be_overridden_by_request_cause(self) -> None:
        events, transactions = self.build(response_cause=72, request_cause=16)
        analysis = self.analyze(events, transactions)
        generation = self.generation(analysis)
        self.assertEqual(generation["generation_state"], "OPEN_AT_CAPTURE_END")
        self.assertIn("RELEASE_REJECTED_OBSERVED", generation["observations"])
        self.assertNotIn("RELEASE_ACCEPTED_OBSERVED", generation["observations"])
        self.assertEqual(
            analysis["generation_boundary_evidence"][0]["release_outcome"], "REJECTED_OBSERVED"
        )

    # R06 -----------------------------------------------------------------
    def test_unrelated_bearer_scope_cause_cannot_override_a_negative_response(self) -> None:
        events, transactions = self.build(response_cause=72, bearer_cause=16)
        analysis = self.analyze(events, transactions)
        self.assertEqual(self.generation(analysis)["generation_state"], "OPEN_AT_CAPTURE_END")
        self.assertEqual(
            analysis["generation_boundary_evidence"][0]["release_outcome"], "REJECTED_OBSERVED"
        )

    # R07 -----------------------------------------------------------------
    def test_missing_response_cause_leaves_acceptance_unproved(self) -> None:
        events, transactions = self.build(response_cause=None, response_event_cause="none")
        analysis = self.analyze(events, transactions)
        self.assertEqual(self.generation(analysis)["generation_state"], "OPEN_AT_CAPTURE_END")
        self.assertEqual(
            analysis["generation_boundary_evidence"][0]["release_outcome_basis"],
            "release_response_cause_unavailable",
        )

    # R08 / R09 ------------------------------------------------------------
    def test_response_carries_acceptance_and_request_carries_initiation(self) -> None:
        events, transactions = self.build()
        analysis = self.analyze(events, transactions)
        generation = self.generation(analysis)
        boundary = generation["generation_boundary"]
        self.assertEqual(boundary["release_request_frame"], 300)
        self.assertEqual(boundary["release_confirmation_frame"], 306)
        self.assertEqual(boundary["frame_number"], 306)
        frames = [ref["frame_number"] for ref in generation["evidence_refs"]]
        self.assertIn(300, frames)
        self.assertIn(306, frames)

    # R10 -----------------------------------------------------------------
    def test_pending_release_interval_is_not_attributed(self) -> None:
        events, transactions = self.build()
        streams = [stream(packets=3, octets=300, first=200, last=400)]
        gtpu = [gtpu_event(frame, length=100) for frame in (200, 303, 400)]
        analysis = model.analyze(
            events,
            transactions=transactions,
            s1u_analysis=s1u_document(*streams),
            gtpu_events=gtpu,
        )
        scoped = analysis["generation_scoped_s1u_observations"][0]
        self.assertEqual(scoped["observed_g_pdu_count"], 1)
        bases = {item["basis"]: item["observed_g_pdu_count"] for item in analysis["unresolved_packet_observations"]}
        self.assertEqual(bases.get("release_in_progress_interval"), 1)
        self.assertEqual(bases.get("frames_outside_the_proved_generation_window"), 1)
        self.assertTrue(analysis["accounting"]["conserved_g_pdu"])


# ---------------------------------------------------------------------------
# S — correlation strength
# ---------------------------------------------------------------------------
class CorrelationStrengthTests(unittest.TestCase):
    """S: only a reviewed, corroborated strength may carry a proof."""

    def family(self, strength):
        events = [
            gtpv2_event(100, "Modify Bearer Request", "modify-bearer", contexts=[context(5, [fteid(1, 100, "198.51.100.2")])]),
            gtpv2_event(106, "Modify Bearer Response", "modify-bearer", contexts=[context(5, [fteid(1, 100, "198.51.100.2")], cause=16)], cause=16),
        ]
        transactions = tx_document(
            transaction("mb", "modify-bearer", (100, "Modify Bearer Request"), (106, "Modify Bearer Response"), strength=strength)
        )
        analysis = model.analyze(events, transactions=transactions)
        return analysis["advertisement_families"][0], analysis

    def test_strong_is_accepted(self) -> None:
        family, analysis = self.family("STRONG")
        self.assertEqual(family["family_classification"], "SAME_TRANSACTION_ADVERTISEMENTS")
        self.assertEqual(analysis["lifecycle_subject_count"], 1)

    def test_supported_is_accepted(self) -> None:
        family, analysis = self.family("SUPPORTED")
        self.assertEqual(family["family_classification"], "SAME_TRANSACTION_ADVERTISEMENTS")
        self.assertEqual(family["correlation_strength"], "SUPPORTED")

    def test_none_cannot_prove_a_family(self) -> None:
        family, analysis = self.family("NONE")
        self.assertEqual(family["family_classification"], "INSUFFICIENT_GENERATION_EVIDENCE")
        self.assertEqual(family["classification_basis"], "correlation_strength_none")
        self.assertEqual(analysis["lifecycle_subject_count"], 0)

    def test_missing_strength_cannot_pass(self) -> None:
        family, analysis = self.family(None)
        self.assertEqual(family["classification_basis"], "correlation_strength_unavailable")
        self.assertEqual(analysis["lifecycle_subject_count"], 0)

    def test_unknown_strength_is_rejected(self) -> None:
        family, _analysis = self.family("WEAK")
        self.assertEqual(family["classification_basis"], "correlation_strength_unreviewed")

    def test_both_models_share_the_reviewed_strength_policy(self) -> None:
        sys.path.insert(0, str(SCRIPTS))
        import epc_default_bearer_model as bearer_model  # noqa: E402

        self.assertEqual(model.PROOF_STRENGTHS, bearer_model.PROOF_STRENGTHS)
        self.assertEqual(model.REVIEWED_STRENGTHS, {"STRONG", "SUPPORTED", "NONE"})
        self.assertNotIn("WEAK", model.REVIEWED_STRENGTHS)
        self.assertNotIn("WEAK", bearer_model.PROOF_STRENGTHS)


# ---------------------------------------------------------------------------
# G — allocation, release and reuse
# ---------------------------------------------------------------------------
class AllocationReuseTests(unittest.TestCase):
    """G: a proved release separates exactly one allocation from the next."""

    def analyze(self, events, transactions):
        return model.analyze(events, transactions=transactions)

    def three_way(self, *, release_capture=CAPTURE, release_teid=1, release_cause=16, status="MATCHED"):
        events = allocation(100) + release(300, capture=release_capture, teid=100, cause=release_cause) + allocation(400)
        transactions = tx_document(
            transaction("cs1", "create-session", (100, "Create Session Request"), (106, "Create Session Response"), session_teid=1),
            transaction(
                "ds", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response"),
                status=status, session_teid=release_teid, response_cause=release_cause,
            ),
            transaction("cs2", "create-session", (400, "Create Session Request"), (406, "Create Session Response"), session_teid=9),
        )
        return events, transactions

    # G01 -----------------------------------------------------------------
    def test_two_allocations_separated_by_a_bound_release_split(self) -> None:
        events, transactions = self.three_way()
        analysis = self.analyze(events, transactions)
        self.assertEqual(
            analysis["advertisement_families"][0]["family_classification"],
            "SEPARATE_GENERATIONS_ESTABLISHED",
        )
        self.assertEqual(analysis["lifecycle_subject_count"], 2)
        self.assertEqual(analysis["endpoint_reuse_observation_count"], 1)
        states = [item["generation_state"] for item in analysis["lifecycle_subjects"]]
        self.assertEqual(states.count("CLOSED_BY_ACCEPTED_RELEASE"), 1)
        self.assertEqual(states.count("OPEN_AT_CAPTURE_END"), 1)
        reuse = analysis["endpoint_reuse_observations"][0]
        self.assertEqual(reuse["basis"], "release_boundary_separates_generations")

    # G02 -----------------------------------------------------------------
    def test_two_allocations_without_a_release_stay_unresolved(self) -> None:
        events = allocation(100) + allocation(400)
        transactions = tx_document(
            transaction("cs1", "create-session", (100, "Create Session Request"), (106, "Create Session Response")),
            transaction("cs2", "create-session", (400, "Create Session Request"), (406, "Create Session Response"), session_teid=9),
        )
        analysis = self.analyze(events, transactions)
        self.assertEqual(
            analysis["advertisement_families"][0]["family_classification"],
            "INSUFFICIENT_GENERATION_EVIDENCE",
        )
        self.assertEqual(analysis["lifecycle_subject_count"], 0)

    # G03 -----------------------------------------------------------------
    def test_release_from_another_capture_cannot_separate(self) -> None:
        events, transactions = self.three_way(release_capture="other.pcap")
        analysis = self.analyze(events, transactions)
        self.assertEqual(
            analysis["advertisement_families"][0]["family_classification"],
            "INSUFFICIENT_GENERATION_EVIDENCE",
        )
        self.assertEqual(analysis["lifecycle_subject_count"], 0)

    # G04 -----------------------------------------------------------------
    def test_release_from_another_context_cannot_separate(self) -> None:
        events, transactions = self.three_way(release_teid=42)
        analysis = self.analyze(events, transactions)
        self.assertEqual(
            analysis["advertisement_families"][0]["family_classification"],
            "INSUFFICIENT_GENERATION_EVIDENCE",
        )

    # G05 -----------------------------------------------------------------
    def test_rejected_release_does_not_separate(self) -> None:
        events, transactions = self.three_way(release_cause=72)
        analysis = self.analyze(events, transactions)
        self.assertEqual(
            analysis["advertisement_families"][0]["family_classification"],
            "INSUFFICIENT_GENERATION_EVIDENCE",
        )

    # G06 -----------------------------------------------------------------
    def test_one_release_cannot_close_multiple_allocations(self) -> None:
        events = allocation(100) + release(300) + allocation(400) + allocation(700)
        transactions = tx_document(
            transaction("cs1", "create-session", (100, "Create Session Request"), (106, "Create Session Response"), session_teid=1),
            transaction("ds", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response"), session_teid=1, response_cause=16),
            transaction("cs2", "create-session", (400, "Create Session Request"), (406, "Create Session Response"), session_teid=9),
            transaction("cs3", "create-session", (700, "Create Session Request"), (706, "Create Session Response"), session_teid=11),
        )
        analysis = self.analyze(events, transactions)
        self.assertEqual(
            analysis["advertisement_families"][0]["family_classification"],
            "INSUFFICIENT_GENERATION_EVIDENCE",
        )
        self.assertEqual(analysis["lifecycle_subject_count"], 0)

    # G07 / G08 ------------------------------------------------------------
    def test_same_transaction_family_and_retransmission_stay_intact(self) -> None:
        events = allocation(100)
        analysis = self.analyze(
            events,
            tx_document(
                transaction(
                    "cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response"),
                    retransmissions=[(112, "Create Session Request")],
                )
            ),
        )
        family = analysis["advertisement_families"][0]
        self.assertEqual(family["family_classification"], "SAME_TRANSACTION_ADVERTISEMENTS")
        self.assertEqual(analysis["lifecycle_subject_count"], 1)

    # G09 -----------------------------------------------------------------
    def test_no_cross_interface_identity_is_fabricated(self) -> None:
        events, transactions = self.three_way()
        analysis = self.analyze(events, transactions)
        for family in analysis["advertisement_families"]:
            self.assertNotIn("session_reference", family)
        for generation in analysis["lifecycle_subjects"]:
            self.assertNotIn("session_reference", generation)
        self.assertTrue(any("S11" in item for item in analysis["not_confirmed"]))

    # G10 -----------------------------------------------------------------
    def test_generation_references_remain_deterministic_and_scoped(self) -> None:
        events, transactions = self.three_way()
        first = self.analyze(json.loads(json.dumps(events)), json.loads(json.dumps(transactions)))
        second = self.analyze(json.loads(json.dumps(events)), json.loads(json.dumps(transactions)))
        self.assertEqual(first, second)
        references = [item["generation_reference"] for item in first["lifecycle_subjects"]]
        self.assertEqual(len(set(references)), len(references))
        self.assertTrue(all(item.startswith("epc-bearer-generation-") for item in references))


# ---------------------------------------------------------------------------
# I — accounting and invariance
# ---------------------------------------------------------------------------
class AccountingInvarianceTests(unittest.TestCase):
    """I: attribution never duplicates a packet and never invents a verdict."""

    def analyze(self, **kwargs):
        events = allocation(100) + release(300) + allocation(400)
        transactions = tx_document(
            transaction("cs1", "create-session", (100, "Create Session Request"), (106, "Create Session Response"), session_teid=1),
            transaction("ds", "delete-session", (300, "Delete Session Request"), (306, "Delete Session Response"), session_teid=1, response_cause=16),
            transaction("cs2", "create-session", (400, "Create Session Request"), (406, "Create Session Response"), session_teid=9),
        )
        return model.analyze(events, transactions=transactions, **kwargs)

    def test_no_packet_is_attributed_twice(self) -> None:
        streams = [stream(packets=4, octets=400, first=150, last=450)]
        gtpu = [gtpu_event(frame, length=100) for frame in (150, 303, 350, 450)]
        analysis = self.analyze(s1u_analysis=s1u_document(*streams), gtpu_events=gtpu)
        total = sum(
            item["observed_g_pdu_count"]
            for item in analysis["generation_scoped_s1u_observations"]
            + analysis["unresolved_packet_observations"]
        )
        self.assertEqual(total, 4)
        self.assertTrue(analysis["accounting"]["conserved_g_pdu"])
        self.assertTrue(analysis["accounting"]["conserved_payload_octets"])

    def test_pending_release_is_not_a_delivery_outcome(self) -> None:
        streams = [stream(packets=3, octets=300, first=200, last=400)]
        gtpu = [gtpu_event(frame, length=100) for frame in (200, 303, 400)]
        analysis = self.analyze(s1u_analysis=s1u_document(*streams), gtpu_events=gtpu)
        serialized = json.dumps(analysis)
        for forbidden in ("DELIVERY_CONFIRMED", "PACKET_LOSS", "TUNNEL_FAILED", "APPLICATION_REACHABLE"):
            self.assertNotIn(forbidden, serialized)
        self.assertIsNone(analysis["first_abnormal_boundary"])

    def test_direction_semantics_are_unchanged(self) -> None:
        # One generation only, so the stream has a single proved owner.
        events = allocation(100)
        transactions = tx_document(
            transaction("cs", "create-session", (100, "Create Session Request"), (106, "Create Session Response"))
        )
        streams = [stream(direction="UPLINK", packets=2, octets=200, first=150, last=160)]
        gtpu = [gtpu_event(150, length=100), gtpu_event(160, length=100)]
        analysis = model.analyze(
            events, transactions=transactions, s1u_analysis=s1u_document(*streams), gtpu_events=gtpu
        )
        scoped = analysis["generation_scoped_s1u_observations"][0]
        self.assertEqual(scoped["direction"], "UPLINK")
        self.assertEqual(scoped["receiving_endpoint_role"], "sgw_s1u")


if __name__ == "__main__":
    unittest.main()
