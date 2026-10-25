#!/usr/bin/env python3
"""Standalone tests for the bounded EPC S1-U GTP-U observation capability."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
CLI = SCRIPTS / "analyze_epc_s1u.py"
TIMELINE = SCRIPTS / "epc_s1u_timeline.py"
EXAMPLES = PACKAGE / "examples" / "s1u"

sys.path.insert(0, str(SCRIPTS))
import epc_s1u_model as model  # noqa: E402


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(CLI), *args], capture_output=True, text=True, check=False)


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def stream(
    *,
    capture: str = "fixture.pcap",
    source: str = "198.51.100.1",
    destination: str = "198.51.100.2",
    teid: int = 100,
    g_pdu: int = 3,
    octets: int = 300,
    first: int = 10,
    last: int = 12,
    message_types: tuple[str, ...] = ("G-PDU",),
    error_frames: tuple[int, ...] = (),
    end_marker: tuple[int, ...] = (),
) -> dict:
    return {
        "stream_key": f"gtpu-path:{capture}:{source}:2152:{destination}:2152:teid{teid}",
        "capture_file": capture,
        "outer_source": source,
        "outer_destination": destination,
        "udp_source_port": 2152,
        "udp_destination_port": 2152,
        "teid": teid,
        "first_frame": first,
        "last_frame": last,
        "first_timestamp": "2026-01-01T00:00:00.000000Z",
        "last_timestamp": "2026-01-01T00:00:01.000000Z",
        "observed_g_pdu_packet_count": g_pdu,
        "observed_payload_byte_count": octets,
        "byte_count_definition": "sum of the GTP-U Length field",
        "qfi_values": [],
        "sequence_numbers": [],
        "sequence_discontinuity_candidate": None,
        "end_marker_frames": list(end_marker),
        "error_indication_refs": list(error_frames),
        "duplicate_observation_candidates": [],
        "limitations": [],
    }


def gtpu_event(
    frame: int,
    *,
    capture: str = "fixture.pcap",
    source: str = "198.51.100.1",
    destination: str = "198.51.100.2",
    teid: int = 100,
    message_type: str = "G-PDU",
) -> dict:
    return {
        "frame_number": frame,
        "capture_file": capture,
        "header": {"message_type": message_type, "teid": teid},
        "outer": {"source_address": source, "destination_address": destination},
    }


def default_bearer(
    *,
    capture: str = "fixture.pcap",
    reference: str = "epc-default-bearer-0000000001",
    endpoints: tuple[tuple[str, int, int], ...] = (("198.51.100.2", 100, 23),),
    role: str = "sgw_s1u",
) -> dict:
    return {
        "domain": "epc-procedures",
        "domain_version": "0.3.0",
        "procedure": "eps-default-bearer",
        "default_bearer_instances": [
            {
                "instance_reference": reference,
                "ue_context": {"capture_file": capture},
                "erab_items": [
                    {
                        "erab_id": 5,
                        "list_role": "REQUEST" if role == "sgw_s1u" else "SUCCESS",
                        "transport_layer_address": address,
                        "gtp_teid": teid,
                        "endpoint_role": role,
                        "endpoint_role_basis": (
                            "initial_context_setup_request_erab_semantics"
                            if role == "sgw_s1u"
                            else "initial_context_setup_response_erab_semantics"
                        ),
                        "binding_basis": "pdml_grouped_ie",
                        "frame_number": frame,
                    }
                    for address, teid, frame in endpoints
                ],
            }
        ],
    }


def analyze(streams: list[dict], **kwargs) -> dict:
    events = kwargs.pop("events", None)
    if events is None:
        events = [
            gtpu_event(
                item["first_frame"],
                capture=item["capture_file"],
                source=item["outer_source"],
                destination=item["outer_destination"],
                teid=item["teid"],
            )
            for item in streams
        ]
    return model.analyze(events, {"streams": streams}, **kwargs)



def gtpv2_endpoint(
    frame: int,
    *,
    address: str = "198.51.100.2",
    teid: int = 100,
    interface_type: int = 1,
    message: str = "Create Session Response",
    family: str = "create-session",
) -> dict:
    """A GTPv2-C bearer F-TEID advertisement of an S1-U receiving endpoint."""
    return {
        "capture_file": "fixture.pcap",
        "frame_number": frame,
        "message_type": message,
        "procedure_family": family,
        "f_teids": [],
        "bearer_contexts": [
            {
                "ebi": 5,
                "cause": {"cause_code": 16, "cause_name": "Request accepted", "scope": "bearer"},
                "f_teids": [
                    {"scope": "bearer", "interface_type": interface_type, "teid": teid, "ipv4": address}
                ],
            }
        ],
    }


class ExampleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def build(self, name: str = "observation.json", extra: tuple[str, ...] = ()) -> Path:
        output = self.base / name
        completed = run(
            "--gtpu",
            str(EXAMPLES / "gtpu-events.jsonl"),
            "--streams",
            str(EXAMPLES / "gtpu-streams.json"),
            "--default-bearer",
            str(EXAMPLES / "default-bearer.json"),
            "--gtpv2",
            str(EXAMPLES / "gtpv2-endpoints.jsonl"),
            "--output",
            str(output),
            *extra,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output

    def test_example_reproduces_the_committed_observation(self) -> None:
        produced = load_json(self.build())
        expected = load_json(EXAMPLES / "expected-observation.json")
        produced.pop("input_provenance", None)
        expected_without = dict(expected)
        expected_without.pop("input_provenance", None)
        self.assertEqual(produced, expected_without)

    def test_supported_stream_carries_packet_and_byte_counts(self) -> None:
        analysis = load_json(self.build())
        supported = [item for item in analysis["stream_observations"] if item["association_status"] == "SUPPORTED"]
        self.assertEqual(len(supported), 2)
        downlink = supported[0]
        # The example's first endpoint comes from the Initial Context Setup
        # Request, so it is the SGW-U receiver and the traffic into it is uplink.
        self.assertEqual(downlink["direction"], "UPLINK")
        self.assertEqual(downlink["receiving_endpoint_match_status"], "MATCHED")
        self.assertEqual(downlink["bearer_association_status"], "SUPPORTED")
        self.assertEqual(downlink["observed_g_pdu_packet_count"], 6)
        self.assertEqual(downlink["observed_payload_byte_count"], 615)
        self.assertEqual(downlink["user_plane_interface"], "S1_U_CANDIDATE")
        self.assertEqual(downlink["matched_subject_reference"], "epc-default-bearer-04eb0b032d")
        self.assertEqual(downlink["matched_endpoint_role"], "sgw_s1u")
        self.assertIn("G_PDU_OBSERVED", downlink["outcomes"])
        self.assertIn("OBSERVED_PACKET_COUNT", downlink["outcomes"])
        self.assertIn("OBSERVED_BYTE_COUNT", downlink["outcomes"])
        self.assertEqual(analysis["observed_g_pdu_packet_count"], 12)

    def test_unbound_stream_stays_visible(self) -> None:
        analysis = load_json(self.build())
        unbound = [item for item in analysis["stream_observations"] if item["association_status"] == "NOT_ESTABLISHED"]
        self.assertEqual(len(unbound), 3)
        unrelated = [
            item for item in unbound if item["outer_destination"] == "203.0.113.9"
        ][0]
        self.assertEqual(unrelated["user_plane_interface"], "UNKNOWN_USER_PLANE_INTERFACE")
        self.assertEqual(unrelated["direction"], "UNKNOWN")
        self.assertEqual(unrelated["observed_g_pdu_packet_count"], 2)
        self.assertIn("STREAM_BEARER_ASSOCIATION_UNBOUND", unrelated["deviation_types"])

    def test_error_indication_and_end_marker_are_observations(self) -> None:
        analysis = load_json(self.build())
        downlink = analysis["stream_observations"][0]
        self.assertIn(42, downlink["error_indication_frames"])
        self.assertIn(43, downlink["end_marker_frames"])
        self.assertIn("ERROR_INDICATION_OBSERVED", downlink["deviation_types"])
        self.assertEqual(analysis["boundary_selection_status"], "NOT_APPLICABLE")
        self.assertIsNone(analysis["first_abnormal_boundary"])

    def test_public_output_excludes_inner_packet_content(self) -> None:
        payload = self.build().read_text(encoding="utf-8")
        for forbidden in ("inner_packet", "inner_source", "inner_destination", "payload_hex"):
            self.assertNotIn(forbidden, payload)
        for claim in (
            "USER_RECEIVED_PACKET",
            "BEARER_DELIVERY_CONFIRMED",
            "PDN_CONNECTIVITY_SUCCESS_CONFIRMED",
            "S1U_FORWARDING_HEALTHY",
            "APPLICATION_REACHABLE",
        ):
            self.assertNotIn(claim, payload)

    def test_output_is_deterministic(self) -> None:
        first = self.build("a.json").read_bytes()
        second = self.build("b.json").read_bytes()
        self.assertEqual(first, second)

    def test_timeline_rows_are_ordered(self) -> None:
        output = self.base / "timeline.jsonl"
        self.build(extra=("--timeline-output", str(output)))
        rows = load_jsonl(output)
        self.assertEqual(len(rows), 5)
        frames = [row["first_frame"] for row in rows]
        self.assertEqual(frames, sorted(frames))

    def test_without_default_bearer_input_streams_stay_unbound(self) -> None:
        output = self.base / "no-bearer.json"
        completed = run(
            "--gtpu",
            str(EXAMPLES / "gtpu-events.jsonl"),
            "--streams",
            str(EXAMPLES / "gtpu-streams.json"),
            "--output",
            str(output),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        analysis = load_json(output)
        self.assertEqual(analysis["supported_stream_count"], 0)
        self.assertEqual(analysis["unbound_stream_count"], 5)
        self.assertTrue(
            any("no advertised S1-U receiving endpoint" in item for item in analysis["evidence_limitations"])
        )


class MatchingRuleTests(unittest.TestCase):
    # C03 / C04 -----------------------------------------------------------
    def test_receiving_endpoint_match_uses_destination_and_teid(self) -> None:
        analysis = analyze([stream()], default_bearer=default_bearer())
        item = analysis["stream_observations"][0]
        self.assertEqual(item["association_status"], "SUPPORTED")
        self.assertEqual(item["association_basis"], "receiving_endpoint_equality_with_advertised_s1u_f_teid")
        self.assertEqual(item["receiving_endpoint_match_status"], "MATCHED")
        # The Initial Context Setup Request advertises the SGW-U receiver, so
        # traffic into it is uplink.
        self.assertEqual(item["direction"], "UPLINK")

    def test_enodeb_receiver_produces_downlink(self) -> None:
        analysis = analyze([stream()], default_bearer=default_bearer(role="enodeb_s1u"))
        item = analysis["stream_observations"][0]
        self.assertEqual(item["association_status"], "SUPPORTED")
        self.assertEqual(item["direction"], "DOWNLINK")
        self.assertEqual(item["matched_endpoint_role"], "enodeb_s1u")

    def test_source_address_alone_cannot_establish_ownership(self) -> None:
        # The source address equals the advertised endpoint, but the destination
        # does not, so no receiving-endpoint match exists.
        analysis = analyze(
            [stream(source="198.51.100.2", destination="198.51.100.9")],
            default_bearer=default_bearer(),
        )
        item = analysis["stream_observations"][0]
        self.assertEqual(item["association_status"], "NOT_ESTABLISHED")

    def test_teid_alone_cannot_establish_ownership(self) -> None:
        analysis = analyze(
            [stream(destination="198.51.100.9", teid=100)],
            default_bearer=default_bearer(),
        )
        self.assertEqual(analysis["stream_observations"][0]["association_status"], "NOT_ESTABLISHED")

    def test_udp_port_alone_cannot_establish_ownership(self) -> None:
        item = stream(destination="198.51.100.9")
        item["udp_destination_port"] = 2152
        analysis = analyze([item], default_bearer=default_bearer())
        self.assertEqual(analysis["stream_observations"][0]["association_status"], "NOT_ESTABLISHED")

    # C05 / C06 / C07 -----------------------------------------------------
    def test_unique_receiver_endpoint_permits_supported_relationship(self) -> None:
        analysis = analyze([stream()], default_bearer=default_bearer())
        self.assertEqual(analysis["supported_stream_count"], 1)
        self.assertEqual(analysis["stream_observations"][0]["matched_subject_reference"], "epc-default-bearer-0000000001")

    def test_two_bearer_subjects_claiming_one_endpoint_is_ambiguous(self) -> None:
        document = default_bearer()
        clone = json.loads(json.dumps(document["default_bearer_instances"][0]))
        clone["instance_reference"] = "epc-default-bearer-0000000002"
        document["default_bearer_instances"].append(clone)
        analysis = analyze([stream()], default_bearer=document)
        item = analysis["stream_observations"][0]
        self.assertEqual(item["association_status"], "AMBIGUOUS")
        self.assertEqual(item["association_basis"], "one_s1u_endpoint_claimed_by_several_bearer_subjects")
        self.assertEqual(len(item["competing_subject_references"]), 2)
        self.assertIn("LIFECYCLE_ASSOCIATION_AMBIGUOUS", item["deviation_types"])

    def test_two_endpoint_roles_matching_one_stream_is_ambiguous(self) -> None:
        # The same address and TEID advertised once as an eNB endpoint and once as
        # an SGW-U endpoint: the value cannot select a single receiving role.
        document = default_bearer()
        document["default_bearer_instances"][0]["erab_items"].append(
            {
                "erab_id": 5,
                "list_role": "SUCCESS",
                "transport_layer_address": "198.51.100.2",
                "gtp_teid": 100,
                "endpoint_role": "enodeb_s1u",
                "endpoint_role_basis": "initial_context_setup_response_erab_semantics",
                "binding_basis": "pdml_grouped_ie",
                "frame_number": 24,
            }
        )
        gtpv2 = [
            {
                "capture_file": "fixture.pcap",
                "frame_number": 22,
                "message_type": "Create Session Response",
                "procedure_family": "create-session",
                "f_teids": [],
                "bearer_contexts": [
                    {
                        "ebi": 5,
                        "f_teids": [
                            {"scope": "bearer", "interface_type": 1, "teid": 100, "ipv4": "198.51.100.2"}
                        ],
                    }
                ],
            }
        ]
        analysis = analyze([stream()], default_bearer=document, gtpv2_events=gtpv2)
        item = analysis["stream_observations"][0]
        self.assertEqual(item["association_status"], "AMBIGUOUS")
        self.assertEqual(item["association_basis"], "incompatible_endpoint_roles_match_this_stream")
        self.assertEqual(item["direction"], "UNKNOWN")
        self.assertIn("COMPETING_BEARER_CANDIDATES", item["deviation_types"])

    def test_capture_provenance_isolates_stream_matching(self) -> None:
        analysis = analyze(
            [stream(capture="other.pcap")],
            default_bearer=default_bearer(capture="fixture.pcap"),
        )
        self.assertEqual(analysis["stream_observations"][0]["association_status"], "NOT_ESTABLISHED")

    def test_flat_erab_binding_cannot_supply_an_endpoint(self) -> None:
        document = default_bearer()
        for item in document["default_bearer_instances"][0]["erab_items"]:
            item["binding_basis"] = "flat_fields"
        analysis = analyze([stream()], default_bearer=document)
        self.assertEqual(analysis["stream_observations"][0]["association_status"], "NOT_ESTABLISHED")

    # C08 / C09 / C10 / C11 ----------------------------------------------
    def test_unbound_streams_remain_visible(self) -> None:
        analysis = analyze([stream(destination="203.0.113.9")], default_bearer=default_bearer())
        self.assertEqual(analysis["stream_count"], 1)
        self.assertEqual(analysis["stream_observations"][0]["observed_g_pdu_packet_count"], 3)

    def test_no_gtpu_input_reports_not_observed(self) -> None:
        analysis = model.analyze([], {"streams": []})
        self.assertEqual(analysis["stream_count"], 0)
        self.assertEqual(analysis["observed_g_pdu_packet_count"], 0)
        self.assertTrue(any("no directed GTP-U stream" in item for item in analysis["evidence_limitations"]))

    def test_one_direction_does_not_establish_the_reverse_direction(self) -> None:
        analysis = analyze([stream()], default_bearer=default_bearer())
        self.assertTrue(
            any("only one S1-U direction was observed" in item for item in analysis["evidence_limitations"])
        )
        self.assertEqual(
            {item["direction"] for item in analysis["stream_observations"]}, {"UPLINK"}
        )

    def test_packet_observation_is_not_application_reachability(self) -> None:
        analysis = analyze([stream()], default_bearer=default_bearer())
        payload = json.dumps(analysis)
        self.assertIn("does not prove that the UE received the packet", payload)
        for claim in ("APPLICATION_REACHABLE", "BEARER_DELIVERY_CONFIRMED", "S1U_FORWARDING_HEALTHY"):
            self.assertNotIn(claim, payload)

    # C12 / C13 / C14 -----------------------------------------------------
    def test_stream_ordering_is_deterministic(self) -> None:
        streams = [stream(first=30, last=31), stream(destination="198.51.100.2", teid=100, first=10, last=11)]
        forward = analyze(list(streams), default_bearer=default_bearer())
        reverse = analyze(list(reversed(streams)), default_bearer=default_bearer())
        self.assertEqual(
            [item["first_frame"] for item in forward["stream_observations"]],
            [item["first_frame"] for item in reverse["stream_observations"]],
        )

    def test_public_output_excludes_inner_addresses(self) -> None:
        payload = json.dumps(analyze([stream()], default_bearer=default_bearer()))
        for forbidden in ("inner_packet", "inner_source_address", "inner_destination_address", "10.45.0."):
            self.assertNotIn(forbidden, payload)

    def test_caps_publish_omission_counts(self) -> None:
        streams = [stream(first=10 + index, last=10 + index) for index in range(model.MAX_STREAMS + 3)]
        analysis = analyze(streams, default_bearer=default_bearer())
        self.assertEqual(analysis["stream_count"], model.MAX_STREAMS + 3)
        self.assertEqual(len(analysis["stream_observations"]), model.MAX_STREAMS)
        self.assertEqual(analysis["streams_omitted"], 3)


class CliContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_missing_input_fails_visibly(self) -> None:
        completed = run(
            "--gtpu", str(self.base / "missing.jsonl"), "--streams", str(self.base / "missing.json"),
            "--output", str(self.base / "out.json"),
        )
        self.assertEqual(completed.returncode, model.EXIT_MALFORMED_INPUT)

    def test_existing_output_requires_force(self) -> None:
        output = self.base / "out.json"
        output.write_text("{}", encoding="utf-8")
        completed = run(
            "--gtpu", str(EXAMPLES / "gtpu-events.jsonl"), "--streams", str(EXAMPLES / "gtpu-streams.json"),
            "--output", str(output),
        )
        self.assertEqual(completed.returncode, model.EXIT_OUTPUT_FAILURE)

    def test_empty_stream_list_returns_the_empty_status(self) -> None:
        streams = self.base / "streams.json"
        streams.write_text(json.dumps({"streams": [], "unbound_events": [], "limitations": []}), encoding="utf-8")
        completed = run(
            "--gtpu", str(EXAMPLES / "gtpu-events.jsonl"), "--streams", str(streams),
            "--output", str(self.base / "out.json"),
        )
        self.assertEqual(completed.returncode, model.EXIT_NO_STREAMS)

    def test_timeline_renders_without_re_running_the_analysis(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(TIMELINE), str(EXAMPLES / "expected-observation.json")],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("EPC S1-U GTP-U observation", completed.stdout)
        self.assertIn("SUPPORTED", completed.stdout)




class EndpointRoleTests(unittest.TestCase):
    """G01-G05, U04-U06: role-aware matching and evidence provenance."""

    def test_interface_type_one_is_the_sgw_receiver(self) -> None:
        analysis = analyze([stream()], default_bearer=default_bearer(role="sgw_s1u"))
        item = analysis["stream_observations"][0]
        self.assertEqual(item["matched_endpoint_role"], "sgw_s1u")
        self.assertEqual(item["direction"], "UPLINK")

    def test_interface_type_zero_is_the_enodeb_receiver(self) -> None:
        document = default_bearer(role="enodeb_s1u")
        analysis = analyze(
            [stream()], default_bearer=document,
            gtpv2_events=[
                {
                    "capture_file": "fixture.pcap",
                    "frame_number": 9,
                    "message_type": "Modify Bearer Request",
                    "procedure_family": "modify-bearer",
                    "f_teids": [],
                    "bearer_contexts": [
                        {
                            "ebi": 5,
                            "f_teids": [
                                {"scope": "bearer", "interface_type": 0, "teid": 100, "ipv4": "198.51.100.2"}
                            ],
                        }
                    ],
                }
            ],
        )
        item = analysis["stream_observations"][0]
        self.assertEqual(item["matched_endpoint_role"], "enodeb_s1u")
        self.assertEqual(item["direction"], "DOWNLINK")

    def test_matched_endpoint_without_owner_is_not_a_bearer_association(self) -> None:
        # A GTPv2-C F-TEID advertises the endpoint but no default-bearer subject
        # owns it: the endpoint match survives, the bearer association does not.
        analysis = analyze(
            [stream()], default_bearer=None,
            gtpv2_events=[gtpv2_endpoint(8, address="198.51.100.2", teid=100)],
        )
        item = analysis["stream_observations"][0]
        self.assertEqual(item["receiving_endpoint_match_status"], "MATCHED")
        self.assertEqual(item["bearer_association_status"], "NOT_ESTABLISHED")
        self.assertEqual(item["association_status"], "NOT_ESTABLISHED")
        self.assertIsNone(item["matched_subject_reference"])
        self.assertEqual(item["direction"], "UPLINK")
        self.assertEqual(item["association_basis"], "receiving_endpoint_matched_without_bearer_owner")

    def test_s1ap_endpoint_evidence_is_labelled_s1ap(self) -> None:
        analysis = analyze([stream()], default_bearer=default_bearer(role="sgw_s1u"))
        item = analysis["stream_observations"][0]
        refs = [(ref["protocol"], ref["message_type"]) for ref in item["evidence_refs"]]
        self.assertIn(("S1AP", "InitialContextSetupRequest"), refs)
        self.assertNotIn(("S1AP", "InitialContextSetup"), refs)

    def test_gtpv2_endpoint_evidence_is_labelled_gtpv2(self) -> None:
        analysis = analyze(
            [stream()], default_bearer=None,
            gtpv2_events=[gtpv2_endpoint(8, address="198.51.100.2", teid=100)],
        )
        item = analysis["stream_observations"][0]
        refs = [(ref["protocol"], ref["message_type"], ref["frame_number"]) for ref in item["evidence_refs"]]
        self.assertIn(("GTPv2-C", "Create Session Response", 8), refs)
        self.assertFalse([ref for ref in refs if ref[0] == "S1AP"])

    def test_s1ap_matched_endpoint_advertises_no_interface_type(self) -> None:
        analysis = analyze([stream()], default_bearer=default_bearer(role="sgw_s1u"))
        item = analysis["stream_observations"][0]
        self.assertEqual(item["matched_endpoint_role"], "sgw_s1u")
        self.assertEqual(item["matched_endpoint_role_basis"], "initial_context_setup_request_erab_semantics")
        self.assertEqual(item["matched_endpoint_source_protocols"], ["S1AP"])
        self.assertEqual(item["matched_endpoint_interface_types"], [])
        self.assertEqual(item["matched_endpoint_interface_type_names"], [])

    def test_gtpv2_matched_endpoint_publishes_its_interface_type(self) -> None:
        analysis = analyze(
            [stream()], default_bearer=None,
            gtpv2_events=[gtpv2_endpoint(8, address="198.51.100.2", teid=100)],
        )
        item = analysis["stream_observations"][0]
        self.assertEqual(item["matched_endpoint_source_protocols"], ["GTPv2-C"])
        self.assertEqual(item["matched_endpoint_interface_types"], [1])
        self.assertEqual(item["matched_endpoint_interface_type_names"], ["S1-U SGW GTP-U interface"])

    def test_mixed_advertisements_keep_the_gtpv2_interface_type(self) -> None:
        analysis = analyze(
            [stream()],
            default_bearer=default_bearer(role="sgw_s1u"),
            gtpv2_events=[gtpv2_endpoint(8, address="198.51.100.2", teid=100)],
        )
        item = analysis["stream_observations"][0]
        self.assertEqual(item["matched_endpoint_source_protocols"], ["GTPv2-C", "S1AP"])
        self.assertEqual(item["matched_endpoint_interface_types"], [1])
        self.assertIsNone(item["matched_endpoint_role_basis"])


if __name__ == "__main__":
    unittest.main()
