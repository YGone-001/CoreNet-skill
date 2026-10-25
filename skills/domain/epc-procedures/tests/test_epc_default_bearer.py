#!/usr/bin/env python3
"""Standalone tests for the bounded EPS default-bearer Domain capability."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
CLI = SCRIPTS / "analyze_epc_default_bearer.py"
EXAMPLES = PACKAGE / "examples" / "default-bearer"

sys.path.insert(0, str(SCRIPTS))
import epc_default_bearer_model as model  # noqa: E402


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CLI), *args], capture_output=True, text=True, check=False
    )


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def esm_message(
    code: int,
    name: str,
    *,
    frame: int,
    ebi: int | None = 0,
    pti: int | None = 1,
    cause: tuple[int, str] | None = None,
    apn: bool = False,
    capture: str = "fixture.pcap",
) -> dict:
    return {
        "occurrence_index": 0,
        "message_type_code": code,
        "message_type": name,
        "support_status": "SUPPORTED",
        "procedure": None,
        "result": "REQUEST",
        "eps_bearer_identity": ebi,
        "procedure_transaction_identity": pti,
        "esm_cause": {"value": cause[0], "name": cause[1]} if cause else None,
        "pdn_type": {"value": 1, "name": "IPv4"},
        "request_type": {"value": 1, "name": "initial request"},
        "apn_present": apn,
        "apn_length": 8 if apn else None,
        "pdn_address_present": False,
        "pdn_address_family": None,
        "qos_present": False,
        "pco_present": False,
        "information_element_count": 1 if apn else 0,
        "container": {
            "kind": "esm_message_container",
            "enclosing_emm_message_type_code": 66,
            "enclosing_emm_message_type": "Attach accept",
            "frame_number": frame,
            "basis": "pdml_esm_container_ie",
        },
        "protection_state": "INTEGRITY_AND_CIPHERED",
        "protection_state_basis": "enclosing_nas_security_header",
        "direction": "downlink",
        "direction_basis": "enclosing_nas_message",
        "binding_basis": "pdml_grouped_ie",
        "frame_number": frame,
        "capture_file": capture,
        "evidence": {"level": "OBSERVED", "source": f"capture:{capture}#frame={frame}"},
        "limitations": [],
    }


def nas_event(
    frame: int,
    messages: list[dict],
    *,
    capture: str = "fixture.pcap",
    association: int = 1,
    ciphered: bool = False,
    container_present: bool = True,
) -> dict:
    return {
        "timestamp": f"2026-01-01T00:00:{frame:02d}.000000Z",
        "frame_number": frame,
        "capture_file": capture,
        "sctp": {"association_id": association},
        "message_type": "Attach accept",
        "protection": "INTEGRITY_AND_CIPHERED",
        "ciphered_payload_present": ciphered,
        "esm_container_present": bool(messages) or container_present,
        "esm_messages": messages,
    }


def s1ap_event(
    frame: int,
    *,
    enb: int = 1,
    mme: int = 9,
    capture: str = "fixture.pcap",
    association: int = 1,
    message: str = "DownlinkNASTransport",
    nas_pdu: bool = True,
    nas_embedded: bool = False,
    erab_items: list[dict] | None = None,
) -> dict:
    event = {
        "timestamp": f"2026-01-01T00:00:{frame:02d}.000000Z",
        "frame_number": frame,
        "capture_file": capture,
        "sctp": {"association_id": association},
        "message_type": message,
        "enb_ue_s1ap_id": enb,
        "mme_ue_s1ap_id": mme,
        "nas_pdu_present": nas_pdu,
        "nas_pdu_embedded": nas_embedded,
        "evidence": {"level": "OBSERVED", "source": f"capture:{capture}#frame={frame}"},
    }
    if erab_items:
        event["erab_items"] = erab_items
    return event


def erab_item(
    identifier: int,
    address: str,
    teid: int,
    *,
    frame: int,
    qci: int = 9,
    role: str = "sgw_s1u",
) -> dict:
    """One item-scoped E-RAB endpoint with its reviewed receiving role."""
    request = role == "sgw_s1u"
    return {
        "operation": "INITIAL_CONTEXT_SETUP",
        "list_role": "REQUEST" if request else "SUCCESS",
        "item_index": 0,
        "erab_id": identifier,
        "qci": qci,
        "arp_present": True,
        "transport_layer_address": address,
        "transport_layer_address_family": "IPv4",
        "gtp_teid": teid,
        "gtp_teid_hex": f"{teid:08x}",
        "endpoint_role": role,
        "endpoint_role_basis": (
            "initial_context_setup_request_erab_semantics"
            if request
            else "initial_context_setup_response_erab_semantics"
        ),
        "binding_basis": "pdml_grouped_ie",
        "frame_number": frame,
        "capture_file": "fixture.pcap",
        "limitations": [],
    }


def gtpv2_event(
    frame: int, *, address: str, teid: int, ebi: int = 5, interface_type: int = 1
) -> dict:
    return {
        "capture_file": "fixture.pcap",
        "frame_number": frame,
        "message_type": "Create Session Response",
        "procedure_family": "create-session",
        "f_teids": [],
        "bearer_contexts": [
            {
                "item_index": 0,
                "ebi": ebi,
                "cause": {"cause_code": 16, "cause_name": "Request accepted", "scope": "bearer"},
                "f_teids": [
                    {"scope": "bearer", "interface_type": interface_type, "teid": teid, "ipv4": address}
                ],
            }
        ],
    }


class ExampleTests(unittest.TestCase):
    """The committed real-capture example is reproducible and bounded."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def analyze_example(self, name: str = "analysis.json", extra: tuple[str, ...] = ()) -> Path:
        output = self.base / name
        completed = run(
            "--nas",
            str(EXAMPLES / "nas-eps-events.jsonl"),
            "--s1ap",
            str(EXAMPLES / "s1ap-events.jsonl"),
            "--attach",
            str(EXAMPLES / "attach-analysis.json"),
            "--session",
            str(EXAMPLES / "session-analysis.json"),
            "--gtpv2",
            str(EXAMPLES / "gtpv2-events.jsonl"),
            "--transactions",
            str(EXAMPLES / "gtpv2-transactions.json"),
            "--output",
            str(output),
            *extra,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output

    # D01 / D02 / D03 ------------------------------------------------------
    def test_example_reproduces_the_committed_analysis(self) -> None:
        produced = load_json(self.analyze_example())
        expected = load_json(EXAMPLES / "expected-analysis.json")
        self.assertEqual(produced, expected)

    def test_observed_stages_and_outcomes(self) -> None:
        analysis = load_json(self.analyze_example())
        instance = analysis["default_bearer_instances"][0]
        stages = {stage["stage_id"]: stage for stage in instance["stages"]}
        self.assertEqual(stages["pdn-connectivity-request"]["status"], "OBSERVED")
        self.assertEqual(stages["pdn-connectivity-request"]["first_frame"], 9)
        self.assertEqual(stages["default-bearer-activation-request"]["status"], "OBSERVED")
        self.assertEqual(stages["default-bearer-activation-request"]["first_frame"], 23)
        self.assertEqual(stages["default-bearer-activation-response"]["status"], "OBSERVED")
        self.assertEqual(stages["default-bearer-activation-response"]["first_frame"], 26)
        self.assertIn("PDN_CONNECTIVITY_REQUEST_OBSERVED", instance["outcomes"])
        self.assertIn("DEFAULT_BEARER_ACTIVATION_REQUEST_OBSERVED", instance["outcomes"])
        self.assertIn("DEFAULT_BEARER_ACTIVATION_ACCEPT_OBSERVED", instance["outcomes"])

    def test_accepted_response_is_protocol_evidence_only(self) -> None:
        analysis = load_json(self.analyze_example())
        self.assertTrue(analysis["not_confirmed"])
        self.assertTrue(
            any("does not prove that the default bearer carries user traffic" in item for item in analysis["not_confirmed"])
        )
        serialized = json.dumps(analysis)
        for forbidden in ("user_plane_success", "BEARER_ACTIVE", "PDN_CONNECTED", "NETWORK_HEALTHY"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(analysis["boundary_selection_status"], "NOT_EVALUATED")
        self.assertIsNone(analysis["first_abnormal_boundary"])

    # D07 / D08 ------------------------------------------------------------
    def test_decoded_ebi_and_tunnel_evidence_keep_their_frames(self) -> None:
        analysis = load_json(self.analyze_example())
        instance = analysis["default_bearer_instances"][0]
        self.assertEqual(instance["bearer_context"]["eps_bearer_identity"], 5)
        self.assertEqual(
            instance["bearer_context"]["eps_bearer_identity_basis"],
            "decoded_activate_default_bearer_context_header",
        )
        self.assertEqual(instance["bearer_context"]["pdn_type"], "IPv4")
        self.assertTrue(instance["bearer_context"]["apn_present"])
        self.assertEqual(instance["bearer_context"]["apn_length"], 8)
        self.assertEqual([item["frame_number"] for item in instance["erab_items"]], [23, 24])
        link = [item for item in analysis["established_links"] if item["link_type"] == "s1ap_erab_to_gtpv2_bearer"][0]
        self.assertEqual(link["status"], "SUPPORTED")
        self.assertEqual(link["source_frame"], 23)
        self.assertEqual(link["target_frame"], 22)
        self.assertEqual(link["s1u_transport_layer_address"], "192.168.64.128")
        self.assertEqual(link["s1u_gtp_teid"], 49676)
        self.assertEqual(
            [reference["frame_number"] for reference in link["evidence_refs"]], [23, 22]
        )
        self.assertEqual(link["ordering"], "gtpv2_precedes_s1ap")

    def test_attach_and_session_links_are_explicit(self) -> None:
        analysis = load_json(self.analyze_example())
        instance = analysis["default_bearer_instances"][0]
        self.assertEqual(instance["attach_link"]["status"], "ESTABLISHED")
        self.assertTrue(instance["attach_link"]["target_subject_reference"].startswith("epc-attach-"))
        link_types = {item["link_type"] for item in analysis["established_links"]}
        self.assertEqual(
            link_types, {"esm_to_s1ap_ue_context", "esm_to_eps_attach", "s1ap_erab_to_gtpv2_bearer"}
        )

    def test_role_specific_endpoint_matching_keeps_the_two_sides_apart(self) -> None:
        analysis = load_json(self.analyze_example())
        supported = [
            item
            for item in analysis["established_links"]
            if item.get("link_type") == "s1ap_erab_to_gtpv2_bearer"
        ]
        by_frame = {item["source_frame"]: item for item in supported}
        self.assertEqual(sorted(by_frame), [23, 24])

        # The SGW-U endpoint from the Initial Context Setup Request is compared
        # with the S1-U F-TEID of interface type 1 only.
        request_link = by_frame[23]
        self.assertEqual(request_link["source_endpoint_role"], "sgw_s1u")
        self.assertEqual(request_link["target_interface_type"], 1)
        self.assertIsNone(request_link["advertisement_family"])

        # The eNodeB endpoint from the Initial Context Setup Response is compared
        # with interface type 0 records only. Two records publish it, and both are
        # the request and response of one accepted Modify Bearer transaction, so
        # they are one advertisement family rather than a second allocation.
        response_link = by_frame[24]
        self.assertEqual(response_link["source_endpoint_role"], "enodeb_s1u")
        self.assertEqual(response_link["target_interface_type"], 0)
        family = response_link["advertisement_family"]
        self.assertIsNotNone(family)
        self.assertEqual(family["classification"], "SAME_TRANSACTION_ADVERTISEMENTS")
        self.assertEqual(family["frames"], [27, 29])
        self.assertEqual(family["bearer_identity"], 5)
        self.assertEqual(family["correlation_status"], "MATCHED")
        self.assertEqual(
            [ref["frame_number"] for ref in response_link["evidence_refs"]],
            [24, 27, 29],
            "both advertisement frames must stay in the published evidence",
        )
        self.assertFalse(
            [
                item
                for item in analysis["ambiguous_links"]
                if item.get("link_type") == "s1ap_erab_to_gtpv2_bearer"
            ],
            "a proved advertisement family removes duplicate-message ambiguity",
        )
        self.assertFalse(
            [item for item in analysis["unbound_evidence"] if item.get("link_type")],
            "both E-RAB endpoints have a compatible GTPv2-C record of their own role",
        )

    def test_endpoint_without_a_compatible_interface_type_stays_unestablished(self) -> None:
        # A Type 1 record can never satisfy an eNodeB-role endpoint, and no Type 0
        # record exists here, so the relationship stays unestablished.
        nas = [nas_event(10, [esm_message(193, "Activate default EPS bearer context request", frame=10, ebi=5)])]
        s1ap = [
            s1ap_event(
                10,
                message="InitialContextSetupResponse",
                nas_pdu=False,
                nas_embedded=True,
                erab_items=[erab_item(5, "198.51.100.2", 100, frame=10, role="enodeb_s1u")],
            )
        ]
        analysis = model.analyze(
            nas, s1ap, gtpv2_events=[gtpv2_event(8, address="198.51.100.2", teid=100, interface_type=1)]
        )
        link = [item for item in analysis["unbound_evidence"] if item.get("link_type")][0]
        self.assertEqual(link["status"], "NOT_ESTABLISHED")
        self.assertEqual(link["source_endpoint_role"], "enodeb_s1u")
        self.assertEqual(link["link_basis"], "no_gtpv2_s1u_f_teid_matches_this_endpoint")

    def test_no_s11_to_s5s8_association_is_asserted(self) -> None:
        analysis = load_json(self.analyze_example())
        serialized = json.dumps(analysis)
        self.assertNotIn("s11_to_s5", serialized)
        self.assertNotIn("session_subject_reference", serialized)
        for instance in analysis["default_bearer_instances"]:
            self.assertEqual(instance["stages"][-1]["stage_id"], "supporting-gtpv2-session-control")
        self.assertTrue(
            any("no reviewed identity bridge" in item for item in analysis["evidence_limitations"])
        )

    def test_output_is_deterministic(self) -> None:
        first = self.analyze_example("a.json").read_bytes()
        second = self.analyze_example("b.json").read_bytes()
        self.assertEqual(first, second)

    def test_timeline_rows_are_ordered(self) -> None:
        output = self.base / "timeline.jsonl"
        self.analyze_example(extra=("--timeline-output", str(output)))
        rows = load_jsonl(output)
        self.assertEqual(len(rows), 6)
        frames = [row["first_frame"] for row in rows if row["first_frame"] is not None]
        self.assertEqual(frames, sorted(frames))


class SyntheticTests(unittest.TestCase):
    """Negative, ambiguous, protected and partial-input behaviour."""

    def analyze(self, nas: list[dict], s1ap: list[dict], **kwargs) -> dict:
        return model.analyze(nas, s1ap, **kwargs)

    # D04 -----------------------------------------------------------------
    def test_activation_reject_is_a_typed_frame_anchored_deviation(self) -> None:
        messages = [
            esm_message(208, "PDN connectivity request", frame=10, ebi=0),
            esm_message(193, "Activate default EPS bearer context request", frame=12, ebi=5),
            esm_message(
                195,
                "Activate default EPS bearer context reject",
                frame=14,
                ebi=5,
                cause=(26, "Insufficient resources"),
            ),
        ]
        nas = [nas_event(10, [messages[0]]), nas_event(12, [messages[1]]), nas_event(14, [messages[2]])]
        s1ap = [s1ap_event(frame) for frame in (10, 12, 14)]
        analysis = self.analyze(nas, s1ap)
        deviations = analysis["procedure_local_deviations"]
        self.assertEqual(len(deviations), 1)
        deviation = deviations[0]
        self.assertEqual(deviation["deviation_type"], "DEFAULT_BEARER_ACTIVATION_REJECT_OBSERVED")
        self.assertEqual(deviation["frame_number"], 14)
        self.assertEqual(deviation["esm_cause_code"], 26)
        self.assertEqual(deviation["esm_cause_name"], "Insufficient resources")
        self.assertEqual(deviation["evidence_level"], "OBSERVED")
        instance = analysis["default_bearer_instances"][0]
        self.assertIn("DEFAULT_BEARER_ACTIVATION_REJECT_OBSERVED", instance["outcomes"])
        self.assertNotIn("DEFAULT_BEARER_ACTIVATION_ACCEPT_OBSERVED", instance["outcomes"])

    def test_pdn_connectivity_reject_is_a_typed_deviation(self) -> None:
        messages = [
            esm_message(208, "PDN connectivity request", frame=10, ebi=0),
            esm_message(209, "PDN connectivity reject", frame=12, ebi=0, cause=(27, "Missing or unknown APN")),
        ]
        nas = [nas_event(10, [messages[0]]), nas_event(12, [messages[1]])]
        analysis = self.analyze(nas, [s1ap_event(10), s1ap_event(12)])
        deviation = analysis["procedure_local_deviations"][0]
        self.assertEqual(deviation["deviation_type"], "PDN_CONNECTIVITY_REJECT_OBSERVED")
        self.assertEqual(deviation["frame_number"], 12)
        self.assertEqual(deviation["esm_cause_code"], 27)

    # D05 / D06 -----------------------------------------------------------
    def test_protected_esm_is_unavailable_not_absent(self) -> None:
        nas = [nas_event(20, [], ciphered=True)]
        s1ap = [s1ap_event(20, message="DownlinkNASTransport")]
        analysis = self.analyze(nas, s1ap)
        instance = analysis["default_bearer_instances"][0]
        stages = {stage["stage_id"]: stage for stage in instance["stages"]}
        self.assertEqual(stages["default-bearer-activation-request"]["status"], "UNAVAILABLE_PROTECTED")
        self.assertEqual(stages["pdn-connectivity-request"]["status"], "UNAVAILABLE_PROTECTED")
        self.assertIn("PROTECTED_ESM_UNAVAILABLE", instance["outcomes"])
        self.assertEqual(analysis["procedure_local_deviations"], [])
        self.assertTrue(any("readable ESM content" in item for item in analysis["additional_evidence_needed"]))

    def test_missing_esm_does_not_fabricate_a_failure(self) -> None:
        nas = [nas_event(30, [])]
        s1ap = [s1ap_event(30)]
        analysis = self.analyze(nas, s1ap)
        instance = analysis["default_bearer_instances"][0]
        self.assertEqual(instance["outcomes"], [])
        self.assertEqual(analysis["procedure_local_deviations"], [])
        stages = {stage["stage_id"]: stage for stage in instance["stages"]}
        self.assertEqual(stages["default-bearer-activation-request"]["status"], "INSUFFICIENT_EVIDENCE")

    # D09 -----------------------------------------------------------------
    def test_conflicting_tunnel_candidates_stay_ambiguous(self) -> None:
        nas = [nas_event(10, [esm_message(193, "Activate default EPS bearer context request", frame=10, ebi=5)])]
        s1ap = [
            s1ap_event(
                10,
                message="InitialContextSetupRequest",
                nas_pdu=False,
                nas_embedded=True,
                erab_items=[erab_item(5, "198.51.100.10", 4242, frame=10)],
            )
        ]
        gtpv2 = [
            gtpv2_event(8, address="198.51.100.10", teid=4242, ebi=5),
            gtpv2_event(9, address="198.51.100.10", teid=4242, ebi=5),
        ]
        analysis = self.analyze(nas, s1ap, gtpv2_events=gtpv2)
        ambiguous = [item for item in analysis["ambiguous_links"] if item["link_type"] == "s1ap_erab_to_gtpv2_bearer"]
        self.assertEqual(len(ambiguous), 1)
        self.assertEqual(ambiguous[0]["status"], "AMBIGUOUS")
        self.assertEqual(len(ambiguous[0]["evidence_refs"]), 3)
        self.assertFalse(
            [item for item in analysis["established_links"] if item["link_type"] == "s1ap_erab_to_gtpv2_bearer"]
        )
        deviations = [item for item in analysis["procedure_local_deviations"] if item["deviation_type"] == "TUNNEL_ENDPOINT_LINK_AMBIGUOUS"]
        self.assertEqual(len(deviations), 1)

    def test_endpoint_without_a_gtpv2_match_stays_unestablished(self) -> None:
        nas = [nas_event(10, [esm_message(193, "Activate default EPS bearer context request", frame=10, ebi=5)])]
        s1ap = [
            s1ap_event(
                10,
                message="InitialContextSetupRequest",
                nas_pdu=False,
                nas_embedded=True,
                erab_items=[erab_item(5, "198.51.100.10", 4242, frame=10)],
            )
        ]
        analysis = self.analyze(nas, s1ap, gtpv2_events=[])
        unbound = [item for item in analysis["unbound_evidence"] if item.get("link_type")]
        self.assertEqual(unbound[0]["status"], "NOT_ESTABLISHED")
        self.assertEqual(unbound[0]["link_basis"], "no_gtpv2_s1u_f_teid_matches_this_endpoint")

    # D10 -----------------------------------------------------------------
    def test_teid_reuse_across_ue_contexts_does_not_merge_generations(self) -> None:
        first = nas_event(10, [esm_message(193, "Activate default EPS bearer context request", frame=10, ebi=5)])
        second = nas_event(40, [esm_message(193, "Activate default EPS bearer context request", frame=40, ebi=5)])
        s1ap = [
            s1ap_event(10, enb=1, mme=9, message="InitialContextSetupRequest", nas_pdu=False, nas_embedded=True,
                       erab_items=[erab_item(5, "198.51.100.10", 4242, frame=10)]),
            s1ap_event(40, enb=2, mme=11, message="InitialContextSetupRequest", nas_pdu=False, nas_embedded=True,
                       erab_items=[erab_item(5, "198.51.100.10", 4242, frame=40)]),
        ]
        analysis = self.analyze(
            [first, second], s1ap, gtpv2_events=[gtpv2_event(8, address="198.51.100.10", teid=4242)]
        )
        self.assertEqual(analysis["instance_count"], 2)
        references = {instance["instance_reference"] for instance in analysis["default_bearer_instances"]}
        self.assertEqual(len(references), 2)
        # The two UE contexts stay separate, and neither may claim the single
        # GTPv2-C record as its own bearer allocation.
        tunnel = [
            link
            for link in analysis["established_links"] + analysis["ambiguous_links"]
            if link.get("link_type") == "s1ap_erab_to_gtpv2_bearer"
        ]
        self.assertEqual(len(tunnel), 2)
        self.assertFalse([link for link in tunnel if link["status"] == "SUPPORTED"])
        for link in tunnel:
            self.assertEqual(link["status"], "AMBIGUOUS")
            self.assertEqual(link["bearer_association_status"], "AMBIGUOUS")
            self.assertEqual(
                link["link_basis"], "one_gtpv2_s1u_f_teid_matched_by_several_ue_contexts"
            )
            self.assertTrue(link["endpoint_equality_observed"])
            self.assertTrue(link["endpoint_reuse_across_subjects"])
            self.assertEqual(link["candidate_target_frames"], [8])
            self.assertIsNone(link["target_subject_reference"])
            self.assertEqual(len(link["competing_source_subjects"]), 1)
            self.assertNotIn(link["source_subject_reference"], link["competing_source_subjects"])
        self.assertEqual(
            {link["source_subject_reference"] for link in tunnel},
            {link["competing_source_subjects"][0] for link in tunnel},
        )

    # D11 -----------------------------------------------------------------
    def test_session_analysis_is_provenance_only(self) -> None:
        nas = [nas_event(10, [esm_message(193, "Activate default EPS bearer context request", frame=10, ebi=5)])]
        s1ap = [s1ap_event(10)]
        session = {
            "control_plane_subjects": [
                {"subject_reference": "epc-session-1", "interface": "S11", "bearer_contexts": [{"ebi": 5}]}
            ]
        }
        analysis = self.analyze(nas, s1ap, session_analysis=session)
        instance = analysis["default_bearer_instances"][0]
        self.assertNotIn("session_subject_reference", instance)
        self.assertEqual(instance["stages"][-1]["status"], "INSUFFICIENT_EVIDENCE")
        self.assertTrue(any("provenance only" in item for item in analysis["evidence_limitations"]))

    # D12 -----------------------------------------------------------------
    def test_no_user_plane_or_root_cause_claim_is_emitted(self) -> None:
        nas = [nas_event(10, [esm_message(208, "PDN connectivity request", frame=10, ebi=0)])]
        analysis = self.analyze(nas, [s1ap_event(10)])
        serialized = json.dumps(analysis).lower()
        # Only claim shapes are forbidden; the negations that deny them are required.
        for forbidden in (
            "caused_by",
            "root_cause_chain",
            "is responsible for",
            "user_plane_success",
            "bearer_active",
            "pdn_connected",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertIn("does not prove that a gtp-u tunnel forwards packets", serialized)
        self.assertTrue(
            any("root cause" in item for item in analysis["not_confirmed"]),
            "the analysis must deny a root-cause claim explicitly",
        )

    def test_unbound_esm_produces_an_explicit_subject(self) -> None:
        nas = [nas_event(50, [esm_message(208, "PDN connectivity request", frame=50, ebi=0)])]
        analysis = self.analyze(nas, [])
        instance = analysis["default_bearer_instances"][0]
        self.assertEqual(instance["association_strength"], "UNBOUND")
        self.assertEqual(instance["esm_message_count"], 0)
        self.assertEqual(analysis["procedure_local_deviations"][0]["deviation_type"], "ESM_EVIDENCE_UNBOUND")
        self.assertEqual(analysis["procedure_local_deviations"][0]["frame_number"], 50)


class CliContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_missing_nas_input_fails_visibly(self) -> None:
        completed = run("--nas", str(self.base / "missing.jsonl"), "--output", str(self.base / "out.json"))
        self.assertEqual(completed.returncode, model.EXIT_MALFORMED_INPUT)

    def test_no_instance_returns_the_empty_status(self) -> None:
        nas = self.base / "nas.jsonl"
        nas.write_text("", encoding="utf-8")
        completed = run("--nas", str(nas), "--output", str(self.base / "out.json"))
        self.assertEqual(completed.returncode, model.EXIT_NO_INSTANCES)

    def test_existing_output_requires_force(self) -> None:
        output = self.base / "out.json"
        output.write_text("{}", encoding="utf-8")
        completed = run("--nas", str(EXAMPLES / "nas-eps-events.jsonl"), "--output", str(output))
        self.assertEqual(completed.returncode, model.EXIT_OUTPUT_FAILURE)

    def test_output_must_not_replace_an_input(self) -> None:
        completed = run("--nas", str(EXAMPLES / "nas-eps-events.jsonl"), "--output", str(EXAMPLES / "nas-eps-events.jsonl"))
        self.assertEqual(completed.returncode, model.EXIT_OUTPUT_FAILURE)

    def test_partial_input_still_produces_evidence(self) -> None:
        output = self.base / "partial.json"
        completed = run(
            "--nas",
            str(EXAMPLES / "nas-eps-events.jsonl"),
            "--s1ap",
            str(EXAMPLES / "s1ap-events.jsonl"),
            "--output",
            str(output),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        analysis = load_json(output)
        self.assertEqual(analysis["instance_count"], 1)
        self.assertEqual(analysis["gtpv2_supporting_evidence_count"], 0)
        self.assertTrue(
            any("no GTPv2-C event input was supplied" in item for item in analysis["evidence_limitations"])
        )

    def test_analysis_scope_and_vocabulary_are_published(self) -> None:
        analysis = load_json(EXAMPLES / "expected-analysis.json")
        scope = analysis["analysis_scope"]
        self.assertEqual([stage["stage_id"] for stage in scope["stages"]], list(model.STAGE_ORDER))
        self.assertEqual(set(scope["stage_status_vocabulary"]), set(model.STAGE_STATUSES))
        self.assertEqual(set(scope["outcome_vocabulary"]), set(model.OUTCOMES))
        self.assertEqual(set(scope["link_status_vocabulary"]), set(model.LINK_STATUSES))
        for field in (
            "domain",
            "domain_version",
            "analysis_scope",
            "input_provenance",
            "default_bearer_instances",
            "esm_observations",
            "s1_erab_observations",
            "gtpv2_supporting_evidence",
            "established_links",
            "ambiguous_links",
            "unbound_evidence",
            "procedure_local_deviations",
            "evidence_limitations",
            "additional_evidence_needed",
            "not_confirmed",
        ):
            self.assertIn(field, analysis)

    def test_privacy_of_the_committed_example(self) -> None:
        payload = (EXAMPLES / "expected-analysis.json").read_text(encoding="utf-8")
        for forbidden in ("internet", "10.45.0.", "460020000000001", "1122334455667788", "919000001"):
            self.assertNotIn(forbidden, payload)




def _tunnel_event(
    frame: int,
    *,
    address: str = "198.51.100.10",
    teid: int = 4242,
    capture: str = "fixture.pcap",
    interface_type: int = 1,
    scope: str = "bearer",
    ebi: int | None = 5,
    message: str = "Create Session Response",
    family: str = "create-session",
) -> dict:
    fteid = {"scope": scope, "interface_type": interface_type, "teid": teid, "ipv4": address}
    event = {
        "capture_file": capture,
        "frame_number": frame,
        "message_type": message,
        "procedure_family": family,
        "f_teids": [fteid] if scope == "message" else [],
        "bearer_contexts": (
            [
                {
                    "item_index": 0,
                    "ebi": ebi,
                    "cause": {"cause_code": 16, "cause_name": "Request accepted", "scope": "bearer"},
                    "f_teids": [fteid],
                }
            ]
            if scope == "bearer"
            else []
        ),
    }
    return event


def _erab_item(
    identifier: int,
    address: str | None,
    teid: int | None,
    *,
    frame: int,
    binding: str = "pdml_grouped_ie",
    capture: str = "fixture.pcap",
    role: str = "sgw_s1u",
) -> dict:
    request = role == "sgw_s1u"
    return {
        "operation": "INITIAL_CONTEXT_SETUP",
        "list_role": "REQUEST" if request else "SUCCESS",
        "item_index": 0,
        "erab_id": identifier,
        "qci": 9,
        "arp_present": True,
        "transport_layer_address": address,
        "transport_layer_address_family": "IPv4" if address else None,
        "gtp_teid": teid,
        "gtp_teid_hex": f"{teid:08x}" if teid is not None else None,
        "endpoint_role": role if teid is not None else None,
        "endpoint_role_basis": (
            (
                "initial_context_setup_request_erab_semantics"
                if request
                else "initial_context_setup_response_erab_semantics"
            )
            if teid is not None
            else "unavailable"
        ),
        "binding_basis": binding,
        "frame_number": frame,
        "capture_file": capture,
        "limitations": [],
    }


def _activation(frame: int, *, capture: str = "fixture.pcap", association: int = 1) -> dict:
    return nas_event(
        frame,
        [esm_message(193, "Activate default EPS bearer context request", frame=frame, ebi=5, capture=capture)],
        capture=capture,
        association=association,
    )


def _setup(
    frame: int,
    *,
    enb: int = 1,
    mme: int | None = 9,
    capture: str = "fixture.pcap",
    association: int = 1,
    items: list[dict] | None = None,
) -> dict:
    return s1ap_event(
        frame,
        enb=enb,
        mme=mme,
        capture=capture,
        association=association,
        message="InitialContextSetupRequest",
        nas_pdu=False,
        nas_embedded=True,
        erab_items=items,
    )


class TunnelAssociationSafetyTests(unittest.TestCase):
    """Bidirectional candidate uniqueness for S1AP E-RAB to GTPv2-C links."""

    def analyze(self, nas: list[dict], s1ap: list[dict], gtpv2: list[dict]) -> dict:
        return model.analyze(nas, s1ap, gtpv2_events=gtpv2)

    def tunnel_links(self, analysis: dict) -> list[dict]:
        return [
            link
            for link in analysis["established_links"]
            + analysis["ambiguous_links"]
            + analysis["unbound_evidence"]
            if isinstance(link, dict) and link.get("link_type") == "s1ap_erab_to_gtpv2_bearer"
        ]

    # T01 -----------------------------------------------------------------
    def test_unique_endpoint_on_both_sides_stays_supported(self) -> None:
        analysis = self.analyze(
            [_activation(10)],
            [_setup(10, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)])],
            [_tunnel_event(8)],
        )
        links = self.tunnel_links(analysis)
        self.assertEqual(len(links), 1)
        link = links[0]
        self.assertEqual(link["status"], "SUPPORTED")
        self.assertEqual(link["bearer_association_status"], "SUPPORTED")
        self.assertTrue(link["endpoint_equality_observed"])
        self.assertFalse(link["endpoint_reuse_across_subjects"])
        self.assertEqual(link["target_frame"], 8)
        self.assertEqual(link["target_subject_reference"], "gtpv2-frame:8")
        self.assertEqual(link["s1ap_owner_item_count"], 1)
        self.assertEqual(link["competing_source_subjects"], [])

    # T02 -----------------------------------------------------------------
    def test_one_gtpv2_record_matched_by_two_ue_contexts_is_ambiguous(self) -> None:
        analysis = self.analyze(
            [_activation(10), _activation(40, association=2)],
            [
                _setup(10, enb=1, mme=9, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)]),
                _setup(40, enb=2, mme=11, association=2,
                       items=[_erab_item(5, "198.51.100.10", 4242, frame=40)]),
            ],
            [_tunnel_event(8)],
        )
        links = self.tunnel_links(analysis)
        self.assertEqual(len(links), 2)
        self.assertFalse([link for link in links if link["status"] == "SUPPORTED"])
        for link in links:
            self.assertEqual(link["status"], "AMBIGUOUS")
            self.assertEqual(
                link["link_basis"], "one_gtpv2_s1u_f_teid_matched_by_several_ue_contexts"
            )
            self.assertEqual(link["candidate_target_frames"], [8])
            self.assertIsNone(link["target_subject_reference"])
            self.assertTrue(link["limitations"])

    # T03 -----------------------------------------------------------------
    def test_one_erab_item_matching_two_gtpv2_records_is_ambiguous(self) -> None:
        analysis = self.analyze(
            [_activation(10)],
            [_setup(10, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)])],
            [_tunnel_event(8), _tunnel_event(9, message="Modify Bearer Request", family="modify-bearer")],
        )
        links = self.tunnel_links(analysis)
        self.assertEqual(len(links), 1)
        link = links[0]
        self.assertEqual(link["status"], "AMBIGUOUS")
        self.assertEqual(link["link_basis"], "several_gtpv2_s1u_f_teids_match_this_endpoint")
        self.assertEqual(link["candidate_target_frames"], [8, 9])
        self.assertIsNone(link["target_subject_reference"])
        self.assertEqual(len(link["evidence_refs"]), 3)

    # T04 -----------------------------------------------------------------
    def test_reused_endpoint_value_is_not_a_new_generation(self) -> None:
        analysis = self.analyze(
            [_activation(10), _activation(90, association=2)],
            [
                _setup(10, enb=1, mme=9, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)]),
                _setup(90, enb=7, mme=21, association=2,
                       items=[_erab_item(5, "198.51.100.10", 4242, frame=90)]),
            ],
            [_tunnel_event(8)],
        )
        links = self.tunnel_links(analysis)
        for link in links:
            self.assertTrue(link["endpoint_reuse_across_subjects"])
            self.assertEqual(link["status"], "AMBIGUOUS")
            self.assertTrue(
                any("generation" in item for item in link["limitations"]),
                "an unproven reuse must record the missing generation evidence",
            )

    # T05 -----------------------------------------------------------------
    def test_capture_provenance_isolates_candidate_sets(self) -> None:
        analysis = self.analyze(
            [_activation(10, capture="b.pcap")],
            [_setup(10, capture="b.pcap", items=[_erab_item(5, "198.51.100.10", 4242, frame=10, capture="b.pcap")])],
            [_tunnel_event(8, capture="a.pcap")],
        )
        links = self.tunnel_links(analysis)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["status"], "NOT_ESTABLISHED")
        self.assertFalse(links[0]["endpoint_equality_observed"])

    # T06 -----------------------------------------------------------------
    def test_interface_type_mismatch_does_not_create_a_link(self) -> None:
        for interface_type in (0, 4, 5, 6, 7, 10, 11):
            with self.subTest(interface_type=interface_type):
                analysis = self.analyze(
                    [_activation(10)],
                    [_setup(10, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)])],
                    [_tunnel_event(8, interface_type=interface_type)],
                )
                links = self.tunnel_links(analysis)
                self.assertEqual(links[0]["status"], "NOT_ESTABLISHED")

    # T07 -----------------------------------------------------------------
    def test_message_scope_and_bearer_scope_stay_distinguished(self) -> None:
        message_scope = self.analyze(
            [_activation(10)],
            [_setup(10, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)])],
            [_tunnel_event(8, scope="message")],
        )
        link = self.tunnel_links(message_scope)[0]
        self.assertEqual(link["status"], "SUPPORTED")
        self.assertEqual(link["target_scope"], "message")
        self.assertIsNone(link["target_eps_bearer_identity"])

        bearer_scope = self.analyze(
            [_activation(10)],
            [_setup(10, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)])],
            [_tunnel_event(8, scope="bearer", ebi=5)],
        )
        link = self.tunnel_links(bearer_scope)[0]
        self.assertEqual(link["target_scope"], "bearer")
        self.assertEqual(link["target_eps_bearer_identity"], 5)

        both_scopes = self.analyze(
            [_activation(10)],
            [_setup(10, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)])],
            [_tunnel_event(8, scope="message"), _tunnel_event(8, scope="bearer")],
        )
        self.assertEqual(self.tunnel_links(both_scopes)[0]["status"], "AMBIGUOUS")

    # T08 -----------------------------------------------------------------
    def test_flat_erab_evidence_cannot_manufacture_bearer_ownership(self) -> None:
        analysis = self.analyze(
            [_activation(10)],
            [_setup(10, items=[_erab_item(5, None, None, frame=10, binding="flat_fields")])],
            [_tunnel_event(8)],
        )
        self.assertEqual(self.tunnel_links(analysis), [])
        self.assertEqual(analysis["gtpv2_supporting_evidence_count"], 1)

    # T09 -----------------------------------------------------------------
    def test_input_ordering_does_not_change_selection(self) -> None:
        nas = [_activation(10), _activation(40, association=2)]
        s1ap = [
            _setup(10, enb=1, mme=9, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)]),
            _setup(40, enb=2, mme=11, association=2,
                   items=[_erab_item(5, "198.51.100.10", 4242, frame=40)]),
        ]
        gtpv2 = [_tunnel_event(8), _tunnel_event(9, message="Modify Bearer Request", family="modify-bearer")]
        forward = self.analyze(nas, s1ap, gtpv2)
        reverse = self.analyze(list(reversed(nas)), list(reversed(s1ap)), list(reversed(gtpv2)))
        forward_links = sorted(
            (link["source_frame"], link["status"], tuple(link["candidate_target_frames"]))
            for link in self.tunnel_links(forward)
        )
        reverse_links = sorted(
            (link["source_frame"], link["status"], tuple(link["candidate_target_frames"]))
            for link in self.tunnel_links(reverse)
        )
        self.assertEqual(forward_links, reverse_links)

    # T10 -----------------------------------------------------------------
    def test_missing_endpoint_evidence_stays_unbound(self) -> None:
        analysis = self.analyze(
            [_activation(10)],
            [_setup(10, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)])],
            [],
        )
        links = self.tunnel_links(analysis)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["status"], "NOT_ESTABLISHED")
        self.assertEqual(links[0]["link_basis"], "no_gtpv2_s1u_f_teid_matches_this_endpoint")
        self.assertEqual(links[0]["candidate_target_frames"], [])

    # T11 -----------------------------------------------------------------
    def test_real_capture_relationship_remains_supported(self) -> None:
        base = EXAMPLES
        analysis = model.analyze(
            load_jsonl(base / "nas-eps-events.jsonl"),
            load_jsonl(base / "s1ap-events.jsonl"),
            attach_analysis=load_json(base / "attach-analysis.json"),
            session_analysis=load_json(base / "session-analysis.json"),
            gtpv2_events=load_jsonl(base / "gtpv2-events.jsonl"),
        )
        supported = [
            link
            for link in analysis["established_links"]
            if link.get("link_type") == "s1ap_erab_to_gtpv2_bearer"
        ]
        self.assertEqual(len(supported), 1)
        link = supported[0]
        self.assertEqual(link["status"], "SUPPORTED")
        self.assertEqual(link["s1u_transport_layer_address"], "192.168.64.128")
        self.assertEqual(link["s1u_gtp_teid"], 49676)
        self.assertEqual(link["source_frame"], 23)
        self.assertEqual(link["target_frame"], 22)
        self.assertFalse(link["endpoint_reuse_across_subjects"])
        ambiguous = [
            item
            for item in analysis["ambiguous_links"]
            if isinstance(item, dict) and item.get("link_type") == "s1ap_erab_to_gtpv2_bearer"
        ]
        self.assertEqual(len(ambiguous), 1)
        self.assertEqual(ambiguous[0]["source_frame"], 24)
        self.assertEqual(ambiguous[0]["source_endpoint_role"], "enodeb_s1u")
        self.assertEqual(ambiguous[0]["status"], "AMBIGUOUS")

    # T12 -----------------------------------------------------------------
    def test_interface_type_zero_cannot_satisfy_an_sgw_role(self) -> None:
        nas = [nas_event(10, [esm_message(193, "Activate default EPS bearer context request", frame=10, ebi=5)])]
        s1ap = [
            s1ap_event(
                10,
                message="InitialContextSetupRequest",
                nas_pdu=False,
                nas_embedded=True,
                erab_items=[erab_item(5, "198.51.100.2", 100, frame=10, role="sgw_s1u")],
            )
        ]
        analysis = model.analyze(
            nas, s1ap, gtpv2_events=[gtpv2_event(8, address="198.51.100.2", teid=100, interface_type=0)]
        )
        link = [item for item in analysis["unbound_evidence"] if item.get("link_type")][0]
        self.assertEqual(link["status"], "NOT_ESTABLISHED")
        self.assertEqual(link["source_endpoint_role"], "sgw_s1u")
        self.assertFalse(
            [item for item in analysis["established_links"] if item.get("link_type") == "s1ap_erab_to_gtpv2_bearer"]
        )

    def test_evidence_references_keep_exact_frames(self) -> None:
        supported = self.analyze(
            [_activation(10)],
            [_setup(10, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)])],
            [_tunnel_event(8)],
        )
        link = self.tunnel_links(supported)[0]
        self.assertEqual(
            [(ref["protocol"], ref["frame_number"]) for ref in link["evidence_refs"]],
            [("S1AP", 10), ("GTPv2-C", 8)],
        )
        ambiguous = self.analyze(
            [_activation(10), _activation(40, association=2)],
            [
                _setup(10, enb=1, mme=9, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)]),
                _setup(40, enb=2, mme=11, association=2,
                       items=[_erab_item(5, "198.51.100.10", 4242, frame=40)]),
            ],
            [_tunnel_event(8)],
        )
        for link in self.tunnel_links(ambiguous):
            self.assertIn(
                ("GTPv2-C", 8),
                [(ref["protocol"], ref["frame_number"]) for ref in link["evidence_refs"]],
            )
            self.assertIn(
                ("S1AP", link["source_frame"]),
                [(ref["protocol"], ref["frame_number"]) for ref in link["evidence_refs"]],
            )


class UeContextReferenceTests(unittest.TestCase):
    """Scoped, deterministic S1AP UE-context references."""

    def context_link(self, analysis: dict) -> dict:
        return [
            link
            for link in analysis["established_links"] + analysis["ambiguous_links"]
            if isinstance(link, dict) and link.get("link_type") == "esm_to_s1ap_ue_context"
        ][0]

    def analyze(self, s1ap: list[dict], nas: list[dict] | None = None) -> dict:
        return model.analyze(nas or [_activation(10, capture=s1ap[0]["capture_file"])], s1ap)

    # C01 -----------------------------------------------------------------
    def test_same_enb_identifier_in_different_captures_is_distinct(self) -> None:
        first = self.context_link(self.analyze([_setup(10, enb=1, mme=9, capture="a.pcap")]))
        second = self.context_link(self.analyze([_setup(10, enb=1, mme=9, capture="b.pcap")]))
        self.assertNotEqual(first["target_subject_reference"], second["target_subject_reference"])
        self.assertEqual(first["context_scope"]["capture_file"], "a.pcap")
        self.assertEqual(second["context_scope"]["capture_file"], "b.pcap")

    # C02 -----------------------------------------------------------------
    def test_same_enb_identifier_in_different_associations_is_distinct(self) -> None:
        first = self.context_link(self.analyze([_setup(10, enb=1, mme=9, association=1)]))
        second = self.context_link(self.analyze([_setup(10, enb=1, mme=9, association=2)]))
        self.assertNotEqual(first["target_subject_reference"], second["target_subject_reference"])

    # C03 -----------------------------------------------------------------
    def test_different_mme_identifiers_remain_distinct(self) -> None:
        first = self.context_link(self.analyze([_setup(10, enb=1, mme=9)]))
        second = self.context_link(self.analyze([_setup(10, enb=1, mme=12)]))
        self.assertNotEqual(first["target_subject_reference"], second["target_subject_reference"])
        self.assertEqual(second["context_scope"]["mme_ue_s1ap_id"], 12)

    # C04 -----------------------------------------------------------------
    def test_incomplete_context_is_not_published_as_established(self) -> None:
        analysis = self.analyze([_setup(10, enb=1, mme=None)])
        link = self.context_link(analysis)
        self.assertEqual(link["context_completeness"], "PARTIAL")
        self.assertEqual(link["status"], "SUPPORTED")
        self.assertIsNone(link["context_scope"]["mme_ue_s1ap_id"])
        self.assertIn("partial", " ".join(link["limitations"]).lower())
        instance = analysis["default_bearer_instances"][0]
        self.assertEqual(instance["association_strength"], "SUPPORTED")

    # C05 -----------------------------------------------------------------
    def test_complete_context_link_is_deterministic(self) -> None:
        first = self.context_link(self.analyze([_setup(10, enb=1, mme=9)]))
        second = self.context_link(self.analyze([_setup(10, enb=1, mme=9)]))
        self.assertEqual(first, second)
        self.assertEqual(first["context_completeness"], "COMPLETE")
        self.assertEqual(first["status"], "ESTABLISHED")

    # C06 -----------------------------------------------------------------
    def test_reference_is_pseudonymous_and_scoped(self) -> None:
        link = self.context_link(self.analyze([_setup(10, enb=1, mme=9)]))
        reference = link["target_subject_reference"]
        self.assertRegex(reference, r"^s1ap-ue-context-[0-9a-f]{10}$")
        payload = json.dumps(link)
        for forbidden in ("imsi", "msisdn", "imei", "guti", "tmsi"):
            self.assertNotIn(forbidden, payload.lower())
        self.assertEqual(
            reference,
            model.s1ap_context_reference(
                {
                    "capture_file": "fixture.pcap",
                    "sctp_association": "sctp-assoc-1",
                    "enb_ue_s1ap_id": 1,
                    "mme_ue_s1ap_id": 9,
                }
            ),
        )


class InterfaceTypeEvidenceTests(unittest.TestCase):
    """F1/F2: an observed interface type must match its source F-TEID record."""

    def analyze(self, s1ap_items: list[dict], gtpv2: list[dict]) -> dict:
        return model.analyze(
            [_activation(10)],
            [_setup(10, items=s1ap_items)],
            gtpv2_events=gtpv2,
        )

    def links(self, analysis: dict) -> list[dict]:
        return [
            link
            for link in analysis["established_links"]
            + analysis["ambiguous_links"]
            + analysis["unbound_evidence"]
            if isinstance(link, dict) and link.get("link_type") == "s1ap_erab_to_gtpv2_bearer"
        ]

    @staticmethod
    def interface_identifiers(link: dict) -> list[dict]:
        return [
            item
            for item in link.get("supporting_identifiers") or []
            if item.get("identifier") == "f_teid_interface_type"
        ]

    # T01 -----------------------------------------------------------------
    def test_sgw_u_type_one_link_publishes_observed_type_one(self) -> None:
        analysis = self.analyze(
            [_erab_item(5, "198.51.100.10", 4242, frame=10, role="sgw_s1u")],
            [_tunnel_event(8, interface_type=1)],
        )
        link = self.links(analysis)[0]
        self.assertEqual(link["status"], "SUPPORTED")
        self.assertEqual(link["target_interface_type"], 1)
        self.assertEqual(link["observed_interface_types"], [1])
        self.assertEqual(link["expected_interface_type"], 1)
        self.assertEqual(self.interface_identifiers(link), [{"identifier": "f_teid_interface_type", "value": 1}])

    # T02 -----------------------------------------------------------------
    def test_enodeb_type_zero_link_publishes_observed_type_zero(self) -> None:
        analysis = self.analyze(
            [_erab_item(5, "198.51.100.10", 4242, frame=10, role="enodeb_s1u")],
            [_tunnel_event(8, interface_type=0, message="Modify Bearer Request", family="modify-bearer")],
        )
        link = self.links(analysis)[0]
        self.assertEqual(link["status"], "SUPPORTED")
        self.assertEqual(link["source_endpoint_role"], "enodeb_s1u")
        self.assertEqual(link["target_interface_type"], 0)
        self.assertEqual(link["observed_interface_types"], [0])
        self.assertEqual(link["expected_interface_type"], 0)
        self.assertEqual(self.interface_identifiers(link), [{"identifier": "f_teid_interface_type", "value": 0}])

    # T03 -----------------------------------------------------------------
    def test_type_zero_link_never_publishes_type_one(self) -> None:
        analysis = self.analyze(
            [_erab_item(5, "198.51.100.10", 4242, frame=10, role="enodeb_s1u")],
            [_tunnel_event(8, interface_type=0, message="Modify Bearer Request", family="modify-bearer")],
        )
        for link in self.links(analysis):
            values = [item["value"] for item in self.interface_identifiers(link)]
            self.assertNotIn(1, values)
            self.assertEqual(link["target_interface_type"], 0)

    # T04 -----------------------------------------------------------------
    def test_type_one_link_never_publishes_type_zero(self) -> None:
        analysis = self.analyze(
            [_erab_item(5, "198.51.100.10", 4242, frame=10, role="sgw_s1u")],
            [_tunnel_event(8, interface_type=1)],
        )
        for link in self.links(analysis):
            values = [item["value"] for item in self.interface_identifiers(link)]
            self.assertNotIn(0, values)
            self.assertEqual(link["target_interface_type"], 1)

    # T05 -----------------------------------------------------------------
    def test_no_match_link_publishes_no_observed_interface_type(self) -> None:
        analysis = self.analyze(
            [_erab_item(5, "198.51.100.10", 4242, frame=10, role="sgw_s1u")],
            [],
        )
        link = self.links(analysis)[0]
        self.assertEqual(link["status"], "NOT_ESTABLISHED")
        self.assertEqual(self.interface_identifiers(link), [])
        self.assertEqual(link["observed_interface_types"], [])
        self.assertIsNone(link["target_interface_type"])
        # The role still documents its expected type as a rule, never as evidence.
        self.assertEqual(link["expected_interface_type"], 1)

    def test_role_mismatch_link_publishes_no_observed_interface_type(self) -> None:
        analysis = self.analyze(
            [_erab_item(5, "198.51.100.10", 4242, frame=10, role="enodeb_s1u")],
            [_tunnel_event(8, interface_type=1)],
        )
        link = self.links(analysis)[0]
        self.assertEqual(link["status"], "NOT_ESTABLISHED")
        self.assertEqual(self.interface_identifiers(link), [])
        self.assertEqual(link["observed_interface_types"], [])
        self.assertIsNone(link["target_interface_type"])

    # T06 -----------------------------------------------------------------
    def test_ambiguous_link_does_not_select_an_interface_type(self) -> None:
        analysis = self.analyze(
            [_erab_item(5, "198.51.100.10", 4242, frame=10, role="sgw_s1u")],
            [_tunnel_event(8), _tunnel_event(9, message="Modify Bearer Request", family="modify-bearer")],
        )
        link = self.links(analysis)[0]
        self.assertEqual(link["status"], "AMBIGUOUS")
        # Every surviving candidate really carried type 1, so it is published as
        # observed evidence; no owner and no target type are selected.
        self.assertEqual(link["observed_interface_types"], [1])
        self.assertIsNone(link["target_interface_type"])
        self.assertIsNone(link["target_subject_reference"])
        self.assertEqual(link["candidate_target_frames"], [8, 9])

    # T07 -----------------------------------------------------------------
    def test_existing_ownership_protections_are_unchanged(self) -> None:
        analysis = model.analyze(
            [_activation(10), _activation(40, association=2)],
            [
                _setup(10, enb=1, mme=9, items=[_erab_item(5, "198.51.100.10", 4242, frame=10)]),
                _setup(40, enb=2, mme=11, association=2,
                       items=[_erab_item(5, "198.51.100.10", 4242, frame=40)]),
            ],
            gtpv2_events=[_tunnel_event(8)],
        )
        links = self.links(analysis)
        self.assertEqual(len(links), 2)
        for link in links:
            self.assertEqual(link["status"], "AMBIGUOUS")
            self.assertTrue(link["endpoint_reuse_across_subjects"])
            self.assertIsNone(link["target_subject_reference"])

    # T08 / T09 / T10 -----------------------------------------------------
    def test_supporting_inventory_keeps_both_reviewed_interface_types(self) -> None:
        analysis = self.analyze(
            [_erab_item(5, "198.51.100.10", 4242, frame=10, role="sgw_s1u")],
            [
                _tunnel_event(8, interface_type=1),
                _tunnel_event(9, interface_type=0, message="Modify Bearer Request", family="modify-bearer"),
                _tunnel_event(11, interface_type=2, message="Create Session Response"),
                _tunnel_event(12, interface_type=8, message="Create Session Response"),
            ],
        )
        inventory = analysis["gtpv2_supporting_evidence"]
        types = [entry["interface_type"] for entry in inventory]
        self.assertIn(1, types)
        self.assertIn(0, types)
        self.assertNotIn(2, types)
        self.assertNotIn(8, types)
        names = {entry["interface_type"]: entry["interface_type_name"] for entry in inventory}
        self.assertEqual(names[0], "S1-U eNodeB GTP-U interface")
        self.assertEqual(names[1], "S1-U SGW GTP-U interface")

    # T11 -----------------------------------------------------------------
    def test_supporting_inventory_preserves_exact_source_frames(self) -> None:
        analysis = self.analyze(
            [_erab_item(5, "198.51.100.10", 4242, frame=10, role="sgw_s1u")],
            [
                _tunnel_event(8, interface_type=1),
                _tunnel_event(9, interface_type=0, message="Modify Bearer Request", family="modify-bearer"),
            ],
        )
        frames = {
            entry["interface_type"]: (entry["frame_number"], entry["message_type"])
            for entry in analysis["gtpv2_supporting_evidence"]
        }
        self.assertEqual(frames[1], (8, "Create Session Response"))
        self.assertEqual(frames[0], (9, "Modify Bearer Request"))

    # T12 -----------------------------------------------------------------
    def test_message_scope_and_bearer_scope_stay_separate(self) -> None:
        analysis = self.analyze(
            [_erab_item(5, "198.51.100.10", 4242, frame=10, role="sgw_s1u")],
            [
                _tunnel_event(8, interface_type=1, scope="message"),
                _tunnel_event(9, interface_type=0, scope="bearer",
                              message="Modify Bearer Request", family="modify-bearer"),
            ],
        )
        scopes = {
            (entry["interface_type"], entry["scope"]) for entry in analysis["gtpv2_supporting_evidence"]
        }
        self.assertEqual(scopes, {(1, "message"), (0, "bearer")})

    # T13 -----------------------------------------------------------------
    def test_supporting_inventory_creates_no_new_identity_link(self) -> None:
        analysis = self.analyze(
            [_erab_item(5, "198.51.100.10", 4242, frame=10, role="sgw_s1u")],
            [_tunnel_event(9, interface_type=0, message="Modify Bearer Request", family="modify-bearer")],
        )
        self.assertTrue(analysis["gtpv2_supporting_evidence"])
        link_types = {
            link.get("link_type")
            for link in analysis["established_links"] + analysis["ambiguous_links"] + analysis["unbound_evidence"]
            if isinstance(link, dict)
        }
        # Only the two reviewed link types exist; a supporting F-TEID record never
        # becomes an Attach, S11 or S5/S8 identity join.
        self.assertEqual(
            link_types, {"s1ap_erab_to_gtpv2_bearer", "esm_to_s1ap_ue_context"}
        )
        self.assertTrue(
            any("S11" in item for item in analysis["not_confirmed"]),
            "the S11 to S5/S8 identity statement must remain unconfirmed",
        )
        # A type 0 record supports an eNodeB endpoint only; it never turns into a
        # supported relationship for an SGW endpoint.
        self.assertFalse(
            [link for link in analysis["established_links"] if link.get("status") == "SUPPORTED"]
        )


if __name__ == "__main__":
    unittest.main()
