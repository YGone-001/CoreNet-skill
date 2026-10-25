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


def erab_item(identifier: int, address: str, teid: int, *, frame: int, qci: int = 9) -> dict:
    return {
        "operation": "INITIAL_CONTEXT_SETUP",
        "list_role": "REQUEST",
        "item_index": 0,
        "erab_id": identifier,
        "qci": qci,
        "arp_present": True,
        "transport_layer_address": address,
        "transport_layer_address_family": "IPv4",
        "gtp_teid": teid,
        "gtp_teid_hex": f"{teid:08x}",
        "endpoint_role": "enodeb_s1u",
        "endpoint_role_basis": "message_identity",
        "binding_basis": "pdml_grouped_ie",
        "frame_number": frame,
        "capture_file": "fixture.pcap",
        "limitations": [],
    }


def gtpv2_event(frame: int, *, address: str, teid: int, ebi: int = 5) -> dict:
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
                "f_teids": [{"scope": "bearer", "interface_type": 1, "teid": teid, "ipv4": address}],
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

    def test_unmatched_tunnel_endpoint_stays_unestablished(self) -> None:
        analysis = load_json(self.analyze_example())
        unbound = [item for item in analysis["unbound_evidence"] if item.get("link_type")]
        self.assertEqual(len(unbound), 1)
        self.assertEqual(unbound[0]["status"], "NOT_ESTABLISHED")
        self.assertEqual(unbound[0]["source_frame"], 24)
        self.assertEqual(unbound[0]["s1u_transport_layer_address"], "127.0.0.5")

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
        links = [item for item in analysis["established_links"] if item["link_type"] == "s1ap_erab_to_gtpv2_bearer"]
        self.assertEqual(len(links), 2)
        self.assertEqual(len({link["source_subject_reference"] for link in links}), 2)
        self.assertEqual(links[0]["target_frame"], links[1]["target_frame"])

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


if __name__ == "__main__":
    unittest.main()
