"""Repository-level tests for the implementation-neutral vocabulary policy.

The prohibited implementation-project tokens are never written literally in
tracked repository files — including this test module. Negative cases are
constructed at runtime through the shared policy module, whose tokens are
themselves built from code points, so the final repository-wide literal scan
returns zero results while the policy stays fully exercised.
"""

from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

POLICY_SPEC = importlib.util.spec_from_file_location(
    "implementation_policy", ROOT / "scripts" / "implementation_policy.py")
POLICY = importlib.util.module_from_spec(POLICY_SPEC)
assert POLICY_SPEC.loader is not None
POLICY_SPEC.loader.exec_module(POLICY)

VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "validate_repository", ROOT / "scripts" / "validate-repository.py")
VALIDATOR = importlib.util.module_from_spec(VALIDATOR_SPEC)
assert VALIDATOR_SPEC.loader is not None
VALIDATOR_SPEC.loader.exec_module(VALIDATOR)


def assembled_tokens() -> list[str]:
    """Reconstruct the prohibited tokens at runtime for negative cases."""
    return sorted(POLICY.PROHIBITED_TOKENS)


class ImplementationNeutralPolicyTests(unittest.TestCase):
    def test_policy_defines_tokens_without_literals(self):
        tokens = assembled_tokens()
        self.assertEqual(len(tokens), 5)
        self.assertTrue(all(token.islower() and token.isalnum() for token in tokens))
        # The source of this test module and the policy module contain no
        # literal prohibited token (the policy constructs them from codes).
        for guarded in (Path(__file__), ROOT / "scripts" / "implementation_policy.py"):
            found = POLICY.find_prohibited_tokens(guarded.read_text(encoding="utf-8"))
            self.assertEqual(found, [], guarded)

    def test_case_insensitive_detection(self):
        base = assembled_tokens()[0]
        for variant in (base, base.upper(), base.capitalize(),
                        base[:2] + base[2:].upper(), "".join(c.upper() if i % 2 else c for i, c in enumerate(base))):
            with self.subTest(variant=variant):
                self.assertEqual(POLICY.find_prohibited_tokens(f"see {variant} internals"), [base.lower()])

    def test_embedded_identifier_detection(self):
        base = assembled_tokens()[0]
        self.assertEqual(POLICY.find_prohibited_tokens(f"{base.upper()}_SOURCE_HANDLER = 'x'"), [base])
        self.assertEqual(POLICY.find_prohibited_tokens(f"compare-with-{base}-config"), [base])

    def test_standards_terminology_accepted(self):
        for text in ("AMF, SMF, UPF, gNB, UDM, AUSF, PCF, BSF, P-CSCF, I-CSCF, S-CSCF, HSS",
                     "3GPP TS 23.502 Release 19; TS 38.413; Wireshark/TShark 4.7.1; IETF RFC 9113",
                     "N2 handover, Path Switch Request, PFCP Session Modification, GTP-U G-PDU"):
            self.assertEqual(POLICY.find_prohibited_tokens(text), [])

    def test_generic_implementation_wording_accepted(self):
        for text in ("implementation-specific project", "implementation-specific telecom software",
                     "external implementation evidence", "implementation-specific logs",
                     "implementation-specific source code", "implementation-specific configuration",
                     "third-party implementation", "vendor-specific implementation",
                     "implementation mapping"):
            self.assertEqual(POLICY.find_prohibited_tokens(text), [])

    def test_complete_token_semantics(self):
        # A different complete token is not a match: the policy detects whole
        # tokens, not substrings.
        base = assembled_tokens()[0]
        self.assertEqual(POLICY.find_prohibited_tokens(base + "xyz"), [])
        self.assertEqual(POLICY.find_prohibited_tokens("abc" + base), [])

    def test_whole_tree_gate_on_real_repository(self):
        errors = [error for error in VALIDATOR.validate(ROOT)
                  if "prohibited" in error.lower()]
        self.assertEqual(errors, [])

    def test_whole_tree_gate_rejects_reintroduction(self):
        base = assembled_tokens()[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            (root / "docs").mkdir(parents=True)
            (root / "notes.md").write_text(f"See {base.upper()} internals.\n", encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.check_implementation_neutral_vocabulary(root, ["notes.md", "docs/ARCHITECTURE.md"], errors)
            self.assertTrue(any("prohibited" in error.lower() for error in errors), errors)

    def test_whole_tree_gate_accepts_neutral_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            (root / "docs").mkdir(parents=True)
            (root / "docs" / "a.md").write_text("implementation-specific project evidence\n", encoding="utf-8")
            (root / "b.md").write_text("AMF and SMF logs from a third-party implementation\n", encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.check_implementation_neutral_vocabulary(root, ["docs/a.md", "b.md"], errors)
            self.assertEqual(errors, [])

    def test_gate_covers_tracked_filenames(self):
        base = assembled_tokens()[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            (root / "docs").mkdir(parents=True)
            # A tracked path whose NAME contains a prohibited token is caught
            # even when the file content itself is neutral.
            (root / "docs" / f"{base}-notes.md").write_text("neutral content\n", encoding="utf-8")
            errors: list[str] = []
            VALIDATOR.check_implementation_neutral_vocabulary(root, [f"docs/{base}-notes.md"], errors)
            self.assertTrue(any("prohibited" in error.lower() for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
