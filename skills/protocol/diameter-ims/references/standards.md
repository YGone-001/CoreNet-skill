# Standards basis

## Normative references

- 3GPP TS 29.229 — Cx and Dx interfaces based on the Diameter protocol;
  protocol details. The reviewed decoder block identifies version 6.7.0
  Release 6.
- 3GPP TS 29.228 — Cx and Dx interfaces based on the Diameter protocol;
  signalling flows and procedure descriptions.
- RFC 6733 — Diameter Base Protocol.

## Verification basis

Command codes, the Cx/Dx Application-ID and AVP codes were checked against the
Cx/Dx block of the TShark/Wireshark 4.2.2 Diameter dictionary
(`diameter/TGPP.xml`), whose comment identifies 3GPP TS 29.229 version 6.7.0
Release 6. The dictionary defines:

| Item | Reviewed value |
| --- | --- |
| Application name | 3GPP Cx |
| Application-ID | 16777216 |
| User-Authorization | 300 |
| Server-Assignment | 301 |
| Location-Info | 302 |
| Multimedia-Auth | 303 |
| Registration-Termination | 304 |
| Push-Profile | 305 |

The reviewed 3GPP experimental result codes 5001–5012 were checked against the
3GPP result-code table exposed by the same decoder distribution. The base
`Result-Code` value classes follow RFC 6733.

## Release limitation

The TS 29.229 and TS 29.228 specification PDFs were not downloaded for this
implementation. Later specification releases were not compared clause by clause.
The implementation is therefore bounded to the command codes, AVP codes and
result codes present in the reviewed decoder tables. Any code outside that
reviewed set retains its numeric identity and is never assigned invented
application semantics.

TS 29.228 provides procedure context only. This Skill does not model stage-2
procedure flows, state machines or outcomes.

## Interface identity

The Cx and Dx interfaces share the Cx application semantics. The reviewed decoder
does not expose a per-message Cx-versus-Dx discriminator. No trusted external
interface metadata is accepted by this Skill, so `interface_identity` is always
`UNPROVED`.