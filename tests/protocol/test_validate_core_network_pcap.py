import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate-core-network-pcap.py"
SPEC = importlib.util.spec_from_file_location("core_network_pcap_validator", SCRIPT)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)


class CoreNetworkPcapValidatorTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        destination = Path(temporary.name) / "repo"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        return temporary, destination

    def test_committed_contract_passes(self):
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_schema_divergence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema = root / "skills/protocol/core-network-pcap/schemas/trace-event.schema.json"
            schema.write_text("{}\n", encoding="utf-8")
            self.assertTrue(any("schema" in error for error in VALIDATOR.validate(root)))

    def test_production_capture_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/core-network-pcap/examples/extracted/unapproved.pcapng"
            fixture.write_bytes(b"synthetic")
            self.assertTrue(any("binary capture fixture" in error for error in VALIDATOR.validate(root)))

    def test_absolute_package_path_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            readme = root / "skills/protocol/core-network-pcap/README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\nC:\\Users\\example\\capture.pcapng\n", encoding="utf-8")
            self.assertTrue(any("absolute workstation path" in error for error in VALIDATOR.validate(root)))
