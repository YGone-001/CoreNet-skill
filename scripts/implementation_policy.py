#!/usr/bin/env python3
"""Implementation-neutrality policy shared by repository validators.

CoreNet Skill is a standards-based telecom signaling evidence repository:
repository-owned semantics derive from 3GPP specifications, directly
applicable protocol standards, reviewed dissector contracts, and observable
evidence. Implementation-specific project expertise is not repository
ownership.

This module is the single deterministic source for the repository's
implementation-project token policy. The prohibited complete tokens are NOT
stored literally anywhere in tracked repository files; they are constructed
here from code points so the final tracked tree contains zero literal
occurrences while the detection stays exact, transparent, and auditable.

Every public name is consumed by `validate-repository.py` (whole-tree gate)
and by the per-Skill validators (implementation-mapping antipattern
detection).
"""

from __future__ import annotations

import hashlib
import re


def _token(codes: tuple[int, ...]) -> str:
    """Assemble one policy token from code points (no literal in the source)."""
    return "".join(chr(code) for code in codes)


# Prohibited implementation-project tokens (complete tokens, lowercase).
# Case-insensitivity is handled by case-folding before comparison.
PROHIBITED_TOKENS = frozenset({
    _token((111, 112, 101, 110, 53, 103, 115)),
    _token((102, 114, 101, 101, 53, 103, 99)),
    _token((107, 97, 109, 97, 105, 108, 105, 111)),
    _token((102, 114, 101, 101, 115, 119, 105, 116, 99, 104)),
    _token((114, 116, 112, 101, 110, 103, 105, 110, 101)),
})

# SHA-256 digests of the case-folded prohibited tokens. Whole-tree scanning
# compares case-folded token digests against this set, so the validator can
# reject any capitalization without storing the tokens themselves.
PROHIBITED_TOKEN_DIGESTS = frozenset(
    hashlib.sha256(token.encode("utf-8")).hexdigest()
    for token in PROHIBITED_TOKENS
)

# Flagless alternation group for embedding into larger regexes that carry
# their own inline flags (for example (?is) at the pattern start).
IMPLEMENTATION_TOKEN_GROUP = "(?:" + "|".join(sorted(PROHIBITED_TOKENS)) + ")"

# Complete standalone pattern for consumers that concatenate further
# alternatives: the case-insensitive flag stays at the very start.
IMPLEMENTATION_TOKEN_PATTERN = "(?i)" + IMPLEMENTATION_TOKEN_GROUP

_TOKEN_SPLIT = re.compile(r"[^0-9a-z]+")


def find_prohibited_tokens(text: str) -> list[str]:
    """Return every prohibited complete token occurring in ``text``.

    The scan is capitalization-insensitive: the text is lowercased, split on
    non-alphanumeric boundaries, each complete token is case-folded and
    hashed, and the digest is compared against the policy digest set. This
    detects the tokens in any capitalization (including inside identifiers
    such as ``NAME_SOURCE_HANDLER``) without storing the tokens literally.
    """
    found: list[str] = []
    for raw in _TOKEN_SPLIT.split(text.lower()):
        if not raw:
            continue
        if hashlib.sha256(raw.encode("utf-8")).hexdigest() in PROHIBITED_TOKEN_DIGESTS:
            found.append(raw)
    return found
