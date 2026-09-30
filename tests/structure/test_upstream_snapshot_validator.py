import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate-upstream-snapshots.py"
SPEC = importlib.util.spec_from_file_location("upstream_snapshot_validator", SCRIPT)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)


class UpstreamSnapshotValidatorTests(unittest.TestCase):
    def build_snapshot(self, root: Path) -> Path:
        snapshot = root / "third_party" / "agentic-awesome-skills"
        skills = snapshot / "skills"
        skills.mkdir(parents=True)
        (snapshot / "UPSTREAM.md").write_text("Pinned provenance.\n", encoding="utf-8")
        (snapshot / "LICENSE").write_text("MIT\n", encoding="utf-8")
        entries = []
        for name in VALIDATOR.EXPECTED_SKILLS:
            skill = skills / name
            skill.mkdir()
            artifact = skill / "SKILL.md"
            artifact.write_text(f"{name}\n", encoding="utf-8")
            entries.append({
                "name": name,
                "source_path": f"skills/{name}",
                "snapshot_path": f"third_party/agentic-awesome-skills/skills/{name}",
                "files": [{
                    "path": "SKILL.md",
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }],
            })
        (snapshot / "MANIFEST.json").write_text(json.dumps({
            "source_commit": VALIDATOR.EXPECTED_COMMIT,
            "skills": entries,
        }), encoding="utf-8")
        return snapshot

    def test_committed_snapshot_passes(self):
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_valid_fixture_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_snapshot(root)
            self.assertEqual(VALIDATOR.validate(root), [])

    def test_missing_file_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = self.build_snapshot(root)
            (snapshot / "skills" / "c-pro" / "SKILL.md").unlink()
            self.assertTrue(any("missing" in error for error in VALIDATOR.validate(root)))

    def test_modified_file_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = self.build_snapshot(root)
            (snapshot / "skills" / "c-pro" / "SKILL.md").write_text("changed\n", encoding="utf-8")
            self.assertTrue(any("SHA-256 mismatch" in error for error in VALIDATOR.validate(root)))

    def test_embedded_git_metadata_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = self.build_snapshot(root)
            (snapshot / ".git").mkdir()
            self.assertTrue(any("embedded Git metadata" in error for error in VALIDATOR.validate(root)))
