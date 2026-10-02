# PFCP Rule Model

Bounded ownership of the PFCP session rules this Skill preserves. No full
policy, forwarding, QoS or charging implementation model is provided.

## PDR — Packet Detection Rule

Bounded fields preserved per PDR item:

- `id` — the PDR identifier.
- `operation` — CREATE, UPDATE or REMOVE, from the grouped IE context. It is
  never inferred from the identifier.
- `precedence` — the observed precedence value.
- `pdi_present` — whether packet detection information was observed.
- `source_interface` — the reviewed interface name (Access, Core,
  SGi-LAN/N6-LAN, CP-function, 5G VN Internal).
- `f_teid` — the provisioned F-TEID (TEID, IPv4, IPv6, choose flag,
  choose-id).
- `ue_ip` — the UE IP Address IE (IPv4 and/or IPv6).
- `network_instance` — preserved verbatim. It is never renamed to DNN or
  APN inside this Skill.
- `qfi_values` — QFI values directly associated with the rule.
- `far_ids`, `qer_ids`, `urr_ids` — references to the rules that apply to
  matched traffic.
- `binding_basis` — how the nested values were associated with this item.

Not implemented: full PDI packet-filter matching semantics, rule evaluation
order beyond the observed precedence value, and any conclusion about which
traffic a rule actually matches.

## FAR — Forwarding Action Rule

Bounded fields preserved per FAR item:

- `id`, `operation`, `binding_basis`.
- `apply_action` — DROP, FORW, BUFF, NOCP, DUPL flags as observed.
- `forwarding_parameters_present` — whether forwarding parameters were
  observed.
- `destination_interface` — the reviewed interface name.
- `network_instance` — preserved verbatim.
- `outer_header_creation` — presence, description, TEID, IPv4 and IPv6.

Not implemented: end-to-end forwarding diagnosis, tunnel liveness, or any
claim that programmed forwarding parameters are in use.

## QER — QoS Enforcement Rule

Bounded fields preserved per QER item:

- `id`, `operation`, `binding_basis`.
- `gate_status` — the observed uplink and downlink gate values.
- `qfi` — the QFI associated with the rule where directly exposed.
- `ul_mbr`, `dl_mbr`, `ul_gbr`, `dl_gbr` — bit rates where directly exposed.

Not implemented: policy authorization, PCC evaluation, ARP semantics,
reflective QoS, the complete QoS flow lifecycle, and any judgement about
subscriber policy correctness.

## URR — Usage Reporting Rule

Bounded fields preserved per URR item:

- `id`, `operation`, `binding_basis`.
- `measurement_present` — whether measurement metadata was observed.

Not implemented: charging, usage accounting, quota management, and
reporting semantics. Detailed charging belongs to later work if authorized.

## Rule operations

The same rule type may appear under Create, Update and Remove groupings, and
one message may mix them (for example a Modification Request that creates a
QER, updates a FAR and removes a PDR). The operation comes from the grouped
IE context. Two narrow, reviewed derivations are permitted:

- A PFCP Session Establishment Request (code 50) only carries Create groups,
  so its rule operations default to CREATE when structured input does not
  state them.
- A PFCP Session Modification Request (code 52) may mix operations, so its
  operation is never derived from the message type and stays null when it is
  not explicitly known.

A Modification Request may modify only part of a session. Nothing in this
Skill implies that all rules were replaced.

## Binding rules

A grouped IE opens a scope level, and repeated grouped IEs of the same type
each carry their own children. Flattened dissector output does not preserve
that structure, so this Skill applies explicit binding rules instead of
positional zipping:

- **structured-input** — the structured `rule_groups` array declares the
  hierarchy; nested values are bound by construction.
- **single-rule-message** — the message holds exactly one rule item of the
  relevant type (and, for QFI, exactly one rule item in total), so nested
  values are unambiguous.
- **unbound** — anything else. The identifiers are preserved as items with
  a null operation and no nested values, and every nested value that could
  not be attributed is preserved in `unbound_ie_metadata` with a
  limitation.

A rule item is never a global object shared across sessions; it belongs to
the message and endpoint scope that produced it.
