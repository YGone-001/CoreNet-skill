# S6a/S6d application model

## Application identity

`Application-ID = 16777251` identifies the common S6a/S6d application. It does
not distinguish S6a (MME-HSS) from S6d (SGSN-HSS). The analysis publishes:

```text
interface_identity = UNPROVED
interface_identity_basis = []
```

No MME/SGSN role is inferred from a port, hostname, address, Visited-PLMN-Id or
command set.

## Commands

| Code | Request | Answer | Scope |
| --- | --- | --- | --- |
| 316 | ULR | ULA | bounded message, result and presence evidence |
| 317 | CLR | CLA | recognized, detailed semantics unsupported |
| 318 | AIR | AIA | bounded authentication-information evidence |
| 319 | IDR | IDA | recognized, detailed semantics unsupported |
| 320 | DSR | DSA | recognized, detailed semantics unsupported |
| 321 | NOR | NOA | recognized, detailed semantics unsupported |
| 322 | PUR | PUA | recognized, detailed semantics unsupported |
| 323 | RSR | RSA | recognized, detailed semantics unsupported |

Commands on any other Application-ID are never classified as S6a/S6d.

## AIR presence

Reviewed presence-only checks:

```text
1408  Requested-EUTRAN-Authentication-Info  Vendor 10415
1409  Requested-UTRAN-GERAN-Authentication-Info Vendor 10415
1407  Visited-PLMN-Id                       Vendor 10415
1     User-Name
263   Session-Id
264   Origin-Host
296   Origin-Realm
283   Destination-Realm
293   Destination-Host
277   Auth-Session-State
```

No value is published. A sensitive presence is `PRESENT_REDACTED`.

## AIA authentication information

```text
1413  E-UTRAN-Authentication-Info        Vendor 10415
1414  UTRAN-GERAN-Authentication-Info    Vendor 10415
```

A redacted parent proves only that the grouped AVP was present. The Skill does
not infer vector count, child identities or RAND/AUTN/XRES values.

Authentication-information availability:

```text
PRESENT_REDACTED                     parent present and redacted
NOT_OBSERVED                         parent absent in a complete publication
NOT_OBSERVED_IN_PUBLISHED_SUBSET     parent absent and AVPs were omitted
INCOMPLETE                           parent present but privacy metadata inconsistent
UNAVAILABLE                          no usable answer evidence
```

## ULR/ULA presence

Reviewed presence-only checks:

```text
1032  RAT-Type            Vendor 10415
1405  ULR-Flags           Vendor 10415
1407  Visited-PLMN-Id     Vendor 10415
628   Supported-Features  Vendor 10415
1400  Subscription-Data   Vendor 10415
263   Session-Id
```

`Subscription-Data` is presence-only. No subscription profile is published.

## Presence matching namespace

Presence is matched by both Code and reviewed namespace:

- Base User-Name requires Code 1 in the BASE namespace.
- Base Session-Id requires Code 263 in the BASE namespace.
- Requested-EUTRAN-Authentication-Info requires Code 1408 with Vendor-ID 10415.
- Subscription-Data requires Code 1400 with Vendor-ID 10415.
- An unknown vendor Code 1 or Code 263 collision does not count as reviewed
  presence.

Missing or truncated AVPs remain `NOT_OBSERVED_IN_PUBLISHED_SUBSET`; no absence is
fabricated.

## Bounded interpretation

ULR/ULA support is application-message evidence. It does not reconstruct an EPS
mobility state machine, subscriber authorization, Attach or registration state.