"""Deterministic architecture validator tests (six-layer direction)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ARCH = load_module("validate-architecture")
REPO_VALIDATOR = load_module("validate-repository")


def make_repo(directory: Path, skills: list[tuple[str, str, str, list[str], list[str]]]) -> Path:
    """Create a minimal skills tree: (layer, name, category, required, optional)."""
    for layer, name, category, required, optional in skills:
        skill_dir = directory / "skills" / layer / name
        skill_dir.mkdir(parents=True)
        lines = [f"name: {name}", "version: 0.1.0", f"category: {category}", "dependencies:"]
        lines.append("  required:")
        lines.extend(f"    - {item}" for item in required) if required else lines.append("    []")
        lines.append("  optional:")
        lines.extend(f"    - {item}" for item in optional) if optional else lines.append("    []")
        (skill_dir / "manifest.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return directory


class LayerDefinitionTests(unittest.TestCase):
    def test_layer_order_is_authoritative(self):
        self.assertEqual(ARCH.LAYER_ORDER, ("foundation", "protocol", "correlation", "domain", "implementation", "orchestration"))
        self.assertEqual(ARCH.LAYER_RANK["correlation"], 2)
        self.assertEqual(ARCH.LAYER_RANK["domain"], 3)

    def test_repository_validator_layers_match_architecture(self):
        self.assertEqual(REPO_VALIDATOR.LAYERS, ARCH.LAYER_ORDER)


class DependencyDirectionTests(unittest.TestCase):
    REGISTRY = {
        "core-network-pcap": "protocol",
        "ngap": "protocol",
        "nas-5gs": "protocol",
        "diameter-core": "protocol",
        "diameter-ims": "protocol",
        "cross-protocol-evidence": "correlation",
        "5gc-registration-mobility": "domain",
    }

    def direction_errors(self, skill: str, layer: str, dependency: str) -> list[str]:
        errors: list[str] = []
        ARCH.check_dependency_direction(skill, layer, [dependency], self.REGISTRY, errors)
        return errors

    def test_protocol_to_foundation_passes(self):
        self.assertEqual(self.direction_errors("ngap", "protocol", "wireshark-analysis >=0.2.0"), [])
        registry = {**self.REGISTRY, "foundation-method": "foundation"}
        errors: list[str] = []
        ARCH.check_dependency_direction("ngap", "protocol", ["foundation-method"], registry, errors)
        self.assertEqual(errors, [])

    def test_correlation_to_protocol_passes(self):
        self.assertEqual(self.direction_errors("cross-protocol-evidence", "correlation", "ngap >=0.1.0"), [])

    def test_domain_to_correlation_passes(self):
        self.assertEqual(self.direction_errors("5gc-registration-mobility", "domain", "cross-protocol-evidence >=0.1.0"), [])

    def test_domain_to_protocol_passes(self):
        self.assertEqual(self.direction_errors("5gc-registration-mobility", "domain", "nas-5gs >=0.1.0"), [])

    def test_implementation_to_domain_passes(self):
        self.assertEqual(self.direction_errors("amf-impl", "implementation", "5gc-registration-mobility"), [])

    def test_orchestration_to_lower_passes(self):
        self.assertEqual(self.direction_errors("orchestrator", "orchestration", "cross-protocol-evidence >=0.1.0"), [])

    def test_protocol_to_correlation_fails(self):
        errors = self.direction_errors("ngap", "protocol", "cross-protocol-evidence >=0.1.0")
        self.assertTrue(any("direction violation" in error for error in errors))

    def test_correlation_to_domain_fails(self):
        errors = self.direction_errors("cross-protocol-evidence", "correlation", "5gc-registration-mobility")
        self.assertTrue(any("direction violation" in error for error in errors))

    def test_foundation_to_protocol_fails(self):
        errors = self.direction_errors("method-skill", "foundation", "ngap >=0.1.0")
        self.assertTrue(any("direction violation" in error for error in errors))

    def test_same_layer_protocol_to_protocol_passes(self):
        self.assertEqual(self.direction_errors("diameter-ims", "protocol", "diameter-core >=0.1.0"), [])

    def test_external_tool_dependency_passes(self):
        self.assertEqual(self.direction_errors("ngap", "protocol", "tshark"), [])
        self.assertEqual(ARCH.parse_dependency_name("tshark"), "tshark")


class DependencyParsingTests(unittest.TestCase):
    def test_version_specifiers_resolve_to_local_names(self):
        self.assertEqual(ARCH.parse_dependency_name("ngap >=0.1.0"), "ngap")
        self.assertEqual(ARCH.parse_dependency_name("nas-5gs >=0.1.0"), "nas-5gs")
        self.assertEqual(ARCH.parse_dependency_name("core-network-pcap >=0.1.0"), "core-network-pcap")

    def test_garbage_dependency_is_ignored(self):
        self.assertIsNone(ARCH.parse_dependency_name("   "))


class ManifestBlockTests(unittest.TestCase):
    def test_block_and_flow_lists_parse(self):
        block = "dependencies:\n  required: []\n  optional:\n    - ngap >=0.1.0\n    - tshark\n"
        self.assertEqual(ARCH.manifest_dependency_block(block, "required"), [])
        self.assertEqual(ARCH.manifest_dependency_block(block, "optional"), ["ngap >=0.1.0", "tshark"])
        flow = "dependencies:\n  required: [nas-5gs]\n  optional: [tshark]\n"
        self.assertEqual(ARCH.manifest_dependency_block(flow, "required"), ["nas-5gs"])


class FullRepositoryTests(unittest.TestCase):
    def test_committed_repository_passes(self):
        self.assertEqual(ARCH.validate(ROOT), [])

    def test_category_layer_mismatch_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = make_repo(Path(directory), [("protocol", "misplaced", "correlation", [], [])])
            errors = ARCH.validate(root)
            self.assertTrue(any("category/layer mismatch" in error for error in errors))

    def test_missing_layer_directory_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = make_repo(Path(directory), [("protocol", "solo", "protocol", [], [])])
            errors = ARCH.validate(root)
            self.assertTrue(any("missing skill layer directory" in error for error in errors))

    def test_dependency_cycle_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = make_repo(Path(directory), [
                ("protocol", "alpha", "protocol", ["beta"], []),
                ("protocol", "beta", "protocol", ["alpha"], []),
            ])
            errors = ARCH.validate(root)
            self.assertTrue(any("cycle" in error for error in errors))

    def test_validator_cli_exit_codes(self):
        passed = subprocess.run([sys.executable, str(SCRIPTS / "validate-architecture.py")], capture_output=True, text=True)
        self.assertEqual(passed.returncode, 0, passed.stderr)


if __name__ == "__main__":
    unittest.main()
