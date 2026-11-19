#!/usr/bin/env python3
"""Deterministic synthetic SDP input records for the SDP Protocol Skill."""

from __future__ import annotations

import json
from pathlib import Path

CAPTURE = "synthetic-sdp.pcapng"
SHA = "0" * 64


def body(lines: list[str], ending: str = "\r\n") -> str:
    return ending.join(lines) + ending


CASES: list[tuple[str, str]] = [
    (
        "valid-single-audio",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Audio",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 0",
            ]
        ),
    ),
    (
        "multiple-media",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Multiple Media",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 0",
                "m=video 49172 RTP/AVP 96",
                "a=rtpmap:96 H264/90000",
            ]
        ),
    ),
    (
        "audio-and-video",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Audio Video",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 0 96",
                "a=rtpmap:96 opus/48000/2",
                "m=video 49172 RTP/AVP 97",
                "a=rtpmap:97 VP8/90000",
            ]
        ),
    ),
    (
        "ipv4-ipv6",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Dual Stack",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 0",
                "m=video 49172 RTP/AVP 96",
                "c=IN IP6 2001:db8::10",
                "a=rtpmap:96 H264/90000",
            ]
        ),
    ),
    (
        "static-dynamic-payloads",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Payloads",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 0 8 96",
                "a=rtpmap:96 opus/48000/2",
            ]
        ),
    ),
    (
        "rtpmap",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic RTP Map",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 96",
                "a=rtpmap:96 opus/48000/2",
            ]
        ),
    ),
    (
        "fmtp",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic FMTP",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 96",
                "a=rtpmap:96 opus/48000/2",
                "a=fmtp:96 useinbandfec=1;max-fs=10",
            ]
        ),
    ),
    (
        "directions",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Directions",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 0",
                "a=sendonly",
                "m=video 49172 RTP/AVP 96",
                "a=recvonly",
                "a=rtpmap:96 H264/90000",
            ]
        ),
    ),
    (
        "session-vs-media-attributes",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Scopes",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "a=sendrecv",
                "a=mid:session-mid",
                "m=audio 49170 RTP/AVP 0",
                "a=inactive",
                "a=mid:media-mid",
            ]
        ),
    ),
    (
        "rtcp-and-mux",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic RTCP",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 0",
                "a=rtcp:49171 IN IP4 10.0.0.2",
                "a=rtcp-mux",
            ]
        ),
    ),
    (
        "bundle",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Bundle",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "a=group:BUNDLE 0 1",
                "m=audio 49170 RTP/AVP 0",
                "a=mid:0",
                "m=video 49172 RTP/AVP 96",
                "a=mid:1",
                "a=rtpmap:96 H264/90000",
            ]
        ),
    ),
    (
        "missing-mandatory",
        body(
            [
                "v=0",
                "c=IN IP4 10.0.0.1",
                "m=audio 49170 RTP/AVP 0",
            ]
        ),
    ),
    (
        "invalid-media-port",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Invalid Port",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 70000 RTP/AVP 0",
            ]
        ),
    ),
    (
        "invalid-payload",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Invalid Payload",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 999",
            ]
        ),
    ),
    (
        "contradictory-attributes",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Conflict",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 96",
                "a=sendonly",
                "a=inactive",
                "a=rtpmap:96 opus/48000/2",
                "a=rtpmap:96 AMR/8000",
            ]
        ),
    ),
    (
        "malformed-line",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Malformed",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "this-is-not-an-sdp-line",
                "m=audio 49170 RTP/AVP 0",
            ]
        ),
    ),
    (
        "mixed-line-endings",
        "v=0\r\n"
        "o=- 1000 2000 IN IP4 10.0.0.1\n"
        "s=Synthetic Mixed Endings\r"
        "c=IN IP4 10.0.0.1\r\n"
        "t=0 0\n"
        "m=audio 49170 RTP/AVP 0\r\n",
    ),
    (
        "unknown-attributes",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Unknown",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "a=x-session-extension:not-published",
                "m=audio 49170 RTP/AVP 0",
                "a=x-media-extension:also-not-published",
            ]
        ),
    ),
    (
        "truncated",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Truncated",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "m=audio 49170 RTP/AVP 0",
            ],
            ending="\r\n",
        ).rstrip("\r\n"),
    ),
    (
        "oversized",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Oversized",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "a=" + "x" * 70000,
            ]
        ),
    ),
    (
        "sensitive-fields",
        body(
            [
                "v=0",
                "o=private-user 1000 2000 IN IP4 203.0.113.10",
                "s=Synthetic Sensitive",
                "c=IN IP4 203.0.113.10",
                "t=0 0",
                "a=ice-ufrag:private-ufrag-value",
                "a=ice-pwd:private-password-value",
                "a=candidate:1 1 udp 2122260223 203.0.113.10 49170 typ host",
                "a=fingerprint:sha-256 AA:BB:CC:DD",
                "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:private-key-material",
                "a=setup:actpass",
                "m=audio 49170 RTP/AVP 0",
            ]
        ),
    ),
    (
        "bundle-unresolved",
        body(
            [
                "v=0",
                "o=- 1000 2000 IN IP4 10.0.0.1",
                "s=Synthetic Broken Bundle",
                "c=IN IP4 10.0.0.1",
                "t=0 0",
                "a=group:BUNDLE 0 9",
                "m=audio 49170 RTP/AVP 0",
                "a=mid:0",
            ]
        ),
    ),
]


def build_records(capture: str = CAPTURE, sha: str = SHA) -> list[dict]:
    records = []
    for index, (_name, sdp_body) in enumerate(CASES, start=1):
        records.append(
            {
                "source_reference": f"sip-body:{capture}:{index}.1",
                "capture_file": capture,
                "capture_sha256": sha,
                "frame_number": index,
                "frame_reference": f"frame:{index}",
                "message_occurrence": 1,
                "sdp_body": sdp_body,
            }
        )
    return records


def write_input(path: Path) -> None:
    path.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in build_records()) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    write_input(Path("skills/protocol/sdp-rtp/examples/inputs/sdp-cases.jsonl"))
    print(f"wrote {len(CASES)} cases")