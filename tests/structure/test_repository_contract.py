import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

_SPEC = importlib.util.spec_from_file_location("validate_repository", ROOT / "scripts/validate-repository.py")
VALIDATOR = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(VALIDATOR)


class RepositoryContractTests(unittest.TestCase):
    def test_template_has_required_contract_files(self):
        template = ROOT / "templates" / "skill-template"
        for relative in ("SKILL.md", "README.md", "manifest.yaml", "references/README.md", "rules/README.md", "scripts/README.md", "filters/README.md", "examples/README.md", "tests/README.md"):
            with self.subTest(relative=relative):
                self.assertTrue((template / relative).is_file())

    def test_repository_validator_succeeds(self):
        completed = subprocess.run([sys.executable, "scripts/validate-repository.py"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_committed_architecture_catalog_is_current(self):
        # The committed docs/ARCHITECTURE.md must not name any implemented
        # Skill as a future candidate.
        errors = [e for e in VALIDATOR.validate(ROOT) if "future candidate" in e]
        self.assertEqual(errors, [])

    def test_implemented_skill_as_candidate_is_rejected(self):
        # Minimal temp repository: one implemented Skill directory plus an
        # ARCHITECTURE.md that lists it as a future candidate.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs" / "ARCHITECTURE.md").write_text(
                "# Architecture\n\nProtocol candidates remain `gtpu`. These names are plans, not implementations.\n",
                encoding="utf-8",
            )
            skill = root / "skills" / "protocol" / "gtpu"
            skill.mkdir(parents=True)
            (skill / "manifest.yaml").write_text("name: gtpu\n", encoding="utf-8")
            errors = VALIDATOR.validate(root)
            self.assertTrue(
                any("lists implemented Skill `gtpu` as a future candidate" in e for e in errors),
                errors,
            )

    def test_candidate_listing_of_unimplemented_skill_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs" / "ARCHITECTURE.md").write_text(
                "# Architecture\n\nProtocol candidates remain `sip` and `diameter-core`. These names are plans, not implementations.\n",
                encoding="utf-8",
            )
            skill = root / "skills" / "protocol" / "gtpu"
            skill.mkdir(parents=True)
            (skill / "manifest.yaml").write_text("name: gtpu\n", encoding="utf-8")
            errors = [e for e in VALIDATOR.validate(root) if "future candidate" in e]
            self.assertEqual(errors, [])
