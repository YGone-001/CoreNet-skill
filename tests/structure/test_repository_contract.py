import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RepositoryContractTests(unittest.TestCase):
    def test_template_has_required_contract_files(self):
        template = ROOT / "templates" / "skill-template"
        for relative in ("SKILL.md", "README.md", "manifest.yaml", "references/README.md", "rules/README.md", "scripts/README.md", "filters/README.md", "examples/README.md", "tests/README.md"):
            with self.subTest(relative=relative):
                self.assertTrue((template / relative).is_file())

    def test_repository_validator_succeeds(self):
        completed = subprocess.run([sys.executable, "scripts/validate-repository.py"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
