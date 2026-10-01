import importlib.util
import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_TEST = ROOT / "skills" / "protocol" / "core-network-pcap" / "tests" / "test_core_network_pcap.py"
SPEC = importlib.util.spec_from_file_location("core_network_pcap_package_tests", PACKAGE_TEST)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(MODULE))
    return tests


class PackageSchemaTests(unittest.TestCase):
    def test_package_schema_matches_shared_contract(self):
        package_schema = ROOT / "skills" / "protocol" / "core-network-pcap" / "schemas" / "trace-event.schema.json"
        shared_schema = ROOT / "shared" / "schemas" / "trace-event.schema.json"
        self.assertEqual(hashlib.sha256(package_schema.read_bytes()).hexdigest(), hashlib.sha256(shared_schema.read_bytes()).hexdigest())
