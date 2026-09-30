import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate-foundation-skills.py"
SPEC = importlib.util.spec_from_file_location("foundation_validator", SCRIPT)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)


class FoundationSkillTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        destination = Path(temporary.name) / "repo"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        return temporary, destination

    def test_committed_foundation_contract_passes(self):
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_modified_embedded_file_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            target = root / "skills/foundation/c-pro/upstream/SKILL.md"
            target.write_text("changed\n", encoding="utf-8")
            self.assertTrue(any("SHA-256 mismatch" in error for error in VALIDATOR.validate(root)))

    def test_missing_required_file_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            (root / "skills/foundation/c-pro/README.md").unlink()
            self.assertTrue(any("missing README.md" in error for error in VALIDATOR.validate(root)))

    def test_incorrect_pinned_commit_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/foundation/c-pro/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace(VALIDATOR.PINNED_COMMIT, "0" * 40), encoding="utf-8")
            self.assertTrue(any("pinned commit" in error for error in VALIDATOR.validate(root)))

    def test_runtime_third_party_reference_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            wrapper = root / "skills/foundation/c-pro/SKILL.md"
            wrapper.write_text(wrapper.read_text(encoding="utf-8") + "\nthird_party/\n", encoding="utf-8")
            self.assertTrue(any("runtime third_party" in error for error in VALIDATOR.validate(root)))

    def test_escaping_package_path_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            wrapper = root / "skills/foundation/c-pro/SKILL.md"
            wrapper.write_text(wrapper.read_text(encoding="utf-8") + "\n../outside\n", encoding="utf-8")
            self.assertTrue(any("escaping the standalone package" in error for error in VALIDATOR.validate(root)))
