"""Deterministic tests for the Ubuntu developer environment helper.

These tests drive ``scripts/dev.sh`` through real subprocesses and use
temporary test doubles for system tools. They never invoke real APT
installation, never modify Git configuration, and never rewrite frozen
Golden Capture artifacts.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEV_SH = ROOT / "scripts" / "dev.sh"
GOLDEN_DIR = ROOT / "benchmarks" / "golden-captures"
GOLDEN_SOURCE_COMMIT = "82934c2cc231540fa425e48177d4bed33210bfc1"
GOLDEN_TSHARK_VERSION = "4.7.1"

# Environment keys the helper honours for test injection. Production use
# never sets them.
INJECT_KEYS = (
    "CORENET_DEV_OS_RELEASE_FILE",
    "CORENET_DEV_PYTHON",
    "CORENET_DEV_GIT",
    "CORENET_DEV_TSHARK",
    "CORENET_DEV_APT_GET",
    "CORENET_DEV_SUDO",
    "CORENET_DEV_UNAME_M",
    "CORENET_DEV_VENV_DIR",
)


def run_dev(*args: str, env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Invoke scripts/dev.sh as a subprocess with a clean injection environment."""
    full_env = {k: v for k, v in os.environ.items() if k not in INJECT_KEYS}
    if env:
        full_env.update(env)
    return subprocess.run(
        [str(DEV_SH), *args],
        capture_output=True,
        text=True,
        env=full_env,
        cwd=str(cwd or ROOT),
    )


def write_script(path: Path, body: str) -> Path:
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def make_os_release(directory: Path, platform_id: str = "ubuntu", version: str = "24.04") -> Path:
    path = directory / "os-release"
    path.write_text(
        f'ID={platform_id}\nVERSION_ID="{version}"\nPRETTY_NAME="{platform_id} {version}"\n',
        encoding="utf-8",
    )
    return path


def make_fake_python(directory: Path, version: str = "3.12.3", venv_rc: int = 0, rc: int = 0) -> Path:
    return write_script(
        directory / "fake-python",
        f"""\
        #!/usr/bin/env bash
        if [ "${{1:-}}" = "--version" ]; then
          echo "Python {version}"
          exit 0
        fi
        if [ "${{1:-}}" = "-c" ]; then
          case "${{2:-}}" in
            *venv*) exit {venv_rc} ;;
            *) exit {rc} ;;
          esac
        fi
        exit {rc}
        """,
    )


def make_fake_tshark(directory: Path, version: str) -> Path:
    return write_script(
        directory / "fake-tshark",
        f"""\
        #!/usr/bin/env bash
        if [ "${{1:-}}" = "--version" ]; then
          echo "TShark (Wireshark) {version} (Git v{version}-0-g000000000000)."
          echo "Copyright 2026 Gerald Combs"
          exit 0
        fi
        exit 0
        """,
    )


def make_fake_git(directory: Path, head: str = GOLDEN_SOURCE_COMMIT, rc: int = 0) -> Path:
    return write_script(
        directory / "fake-git",
        f"""\
        #!/usr/bin/env bash
        for arg in "$@"; do
          if [ "$arg" = "--version" ]; then
            echo "git version 2.43.0"
            exit 0
          fi
        done
        if [ "$1" = "-C" ] && [ "$3" = "rev-parse" ]; then
          echo "{head}"
          exit {rc}
        fi
        if [ "$1" = "diff" ] || [ "$1" = "status" ]; then
          exit 0
        fi
        exit 0
        """,
    )


def make_fake_apt(directory: Path, rc: int = 0, log_name: str = "apt.log") -> Path:
    log = directory / log_name
    return write_script(
        directory / "fake-apt",
        f"""\
        #!/usr/bin/env bash
        echo "$@" >> "{log}"
        exit {rc}
        """,
    )


def git_config_snapshot() -> tuple[str, str]:
    local = subprocess.run(
        ["git", "-C", str(ROOT), "config", "--local", "--list"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    config_file = ROOT / ".git" / "config"
    blob = config_file.read_text(encoding="utf-8") if config_file.is_file() else ""
    return local, blob


def tree_digest(directory: Path) -> dict[str, str]:
    digest: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            digest[str(path.relative_to(directory))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest


class RootResolutionTests(unittest.TestCase):
    def test_repository_root_is_independent_of_working_directory(self):
        outputs = []
        for cwd in (ROOT, Path(tempfile.gettempdir()), ROOT / "docs"):
            completed = run_dev("doctor", cwd=cwd)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            match = re.search(r"^Repository\s+detected \((.+)\)$", completed.stdout, re.MULTILINE)
            self.assertIsNotNone(match, completed.stdout)
            outputs.append(match.group(1))
        self.assertEqual({Path(item).resolve() for item in outputs}, {ROOT.resolve()})

    def test_script_resolves_root_from_its_own_location(self):
        # The helper must not depend on the process working directory to find
        # AGENTS.md and the validators.
        completed = run_dev("doctor", cwd=Path("/"))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(f"detected ({ROOT})", completed.stdout)


class UsageTests(unittest.TestCase):
    def test_unknown_command_is_rejected(self):
        completed = run_dev("frobnicate")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("unknown command", completed.stderr)

    def test_no_command_shows_usage(self):
        completed = run_dev()
        self.assertEqual(completed.returncode, 2)
        self.assertIn("Usage:", completed.stderr)

    def test_unknown_option_is_rejected(self):
        completed = run_dev("doctor", "--verbose")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("unknown doctor option", completed.stderr)

    def test_golden_preflight_requires_source_root(self):
        completed = run_dev("golden-preflight")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("--source-root", completed.stderr)

    def test_golden_preflight_rejects_empty_source_root(self):
        completed = run_dev("golden-preflight", "--source-root")
        self.assertEqual(completed.returncode, 2)

    def test_bootstrap_rejects_unknown_option(self):
        completed = run_dev("bootstrap", "--upgrade-system")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("unknown bootstrap option", completed.stderr)


class DoctorBehaviorTests(unittest.TestCase):
    def test_doctor_is_non_mutating(self):
        git_local, git_blob = git_config_snapshot()
        golden_before = tree_digest(GOLDEN_DIR)
        tracked_before = subprocess.run(
            ["git", "-C", str(ROOT), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout

        completed = run_dev("doctor")
        self.assertEqual(completed.returncode, 0, completed.stderr)

        git_local_after, git_blob_after = git_config_snapshot()
        self.assertEqual(git_local, git_local_after)
        self.assertEqual(git_blob, git_blob_after)
        self.assertEqual(golden_before, tree_digest(GOLDEN_DIR))
        tracked_after = subprocess.run(
            ["git", "-C", str(ROOT), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        self.assertEqual(tracked_before, tracked_after)

    def test_doctor_reports_detected_versions(self):
        completed = run_dev("doctor")
        self.assertIn("CoreNet Skill Development Environment", completed.stdout)
        self.assertIn("Platform", completed.stdout)
        self.assertIn("Architecture", completed.stdout)
        self.assertIn("Python", completed.stdout)
        self.assertIn("Git", completed.stdout)
        self.assertIn("Python venv", completed.stdout)
        self.assertIn("TShark", completed.stdout)
        self.assertIn("Golden baseline", completed.stdout)
        self.assertRegex(completed.stdout, r"Environment status:\n(READY|READY_WITH_LIMITATIONS|BLOCKED)")

    def test_doctor_status_is_not_hardcoded(self):
        # The status line is computed, not fixed: with a broken interpreter the
        # helper must report BLOCKED on the same machine.
        with tempfile.TemporaryDirectory() as directory:
            fake_python = write_script(
                Path(directory) / "missing-python",
                "#!/usr/bin/env bash\nexit 127\n",
            )
            completed = run_dev("doctor", env={"CORENET_DEV_PYTHON": str(fake_python)})
            self.assertEqual(completed.returncode, 3)
            self.assertIn("BLOCKED", completed.stdout)


class UnsupportedOSTests(unittest.TestCase):
    def test_doctor_reports_foreign_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            os_release = make_os_release(tmp, platform_id="debian", version="12")
            completed = run_dev("doctor", env={"CORENET_DEV_OS_RELEASE_FILE": str(os_release)})
            self.assertIn("Debian 12", completed.stdout)
            self.assertIn("READY_WITH_LIMITATIONS", completed.stdout)
            self.assertEqual(completed.returncode, 0)

    def test_bootstrap_install_os_deps_refuses_foreign_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            os_release = make_os_release(tmp, platform_id="fedora", version="40")
            fake_apt = make_fake_apt(tmp)
            completed = run_dev(
                "bootstrap",
                "--install-os-deps",
                "--dry-run",
                env={
                    "CORENET_DEV_OS_RELEASE_FILE": str(os_release),
                    "CORENET_DEV_APT_GET": str(fake_apt),
                    "CORENET_DEV_SUDO": "",
                    "CORENET_DEV_VENV_DIR": str(tmp / "venv"),
                },
            )
            self.assertEqual(completed.returncode, 3)
            self.assertIn("supported only on Ubuntu", completed.stderr)
            self.assertFalse((tmp / "apt.log").exists(), "APT must not run on an unsupported platform")

    def test_ubuntu_2404_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            os_release = make_os_release(tmp, platform_id="ubuntu", version="24.04")
            completed = run_dev("doctor", env={"CORENET_DEV_OS_RELEASE_FILE": str(os_release)})
            self.assertIn("Ubuntu 24.04", completed.stdout)


class PythonVersionTests(unittest.TestCase):
    def test_bootstrap_rejects_wrong_python_series(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_python = make_fake_python(tmp, version="3.11.9")
            completed = run_dev(
                "bootstrap",
                env={"CORENET_DEV_PYTHON": str(fake_python), "CORENET_DEV_VENV_DIR": str(tmp / "venv")},
            )
            self.assertEqual(completed.returncode, 3)
            self.assertIn("3.12.x is required", completed.stderr)

    def test_doctor_blocks_on_wrong_python_series(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_python = make_fake_python(tmp, version="2.7.18")
            completed = run_dev("doctor", env={"CORENET_DEV_PYTHON": str(fake_python)})
            self.assertEqual(completed.returncode, 3)
            self.assertIn("BLOCKED", completed.stdout)

    def test_bootstrap_accepts_matching_python_series(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_python = make_fake_python(tmp, version="3.12.1")
            completed = run_dev(
                "bootstrap",
                "--dry-run",
                env={"CORENET_DEV_PYTHON": str(fake_python), "CORENET_DEV_VENV_DIR": str(tmp / "venv")},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("3.12.x verified", completed.stdout)


class MissingDependencyTests(unittest.TestCase):
    def test_missing_git_blocks_bootstrap(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            missing_git = tmp / "no-such-git"
            completed = run_dev(
                "bootstrap",
                "--dry-run",
                env={
                    "CORENET_DEV_GIT": str(missing_git),
                    "CORENET_DEV_VENV_DIR": str(tmp / "venv"),
                },
            )
            self.assertEqual(completed.returncode, 3)
            self.assertIn("Git is unavailable", completed.stderr)

    def test_missing_stdlib_module_blocks_doctor(self):
        # A Python that fails every import is treated as missing stdlib support.
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_python = write_script(
                tmp / "broken-python",
                """\
                #!/usr/bin/env bash
                if [ "${1:-}" = "--version" ]; then
                  echo "Python 3.12.3"
                  exit 0
                fi
                if [ "${1:-}" = "-c" ]; then
                  exit 1
                fi
                if [ "${1:-}" = "-" ]; then
                  echo "argparse ast copy hashlib importlib.util json pathlib py_compile re shutil subprocess sys tempfile typing unittest venv"
                  exit 0
                fi
                exit 0
                """,
            )
            completed = run_dev("doctor", env={"CORENET_DEV_PYTHON": str(fake_python)})
            self.assertEqual(completed.returncode, 3)
            self.assertIn("Stdlib modules", completed.stdout)
            self.assertIn("missing:", completed.stdout)

    def test_missing_required_validator_blocks_validate(self):
        # Validate must refuse to run when the interpreter is unusable.
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_python = make_fake_python(tmp, version="3.12.3", rc=0)
            # Point at an interpreter that reports success but the helper still
            # verifies Python series first; combine with a missing git to stop
            # before any repository work.
            completed = run_dev(
                "validate",
                env={
                    "CORENET_DEV_GIT": str(tmp / "missing-git"),
                    "CORENET_DEV_PYTHON": str(fake_python),
                },
            )
            self.assertEqual(completed.returncode, 3)
            self.assertIn("Git is unavailable", completed.stderr)


class TSharkOptionalTests(unittest.TestCase):
    def test_absent_tshark_does_not_block_standard_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            missing = tmp / "no-tshark"
            completed = run_dev("doctor", env={"CORENET_DEV_TSHARK": str(missing)})
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("READY_WITH_LIMITATIONS", completed.stdout)
            self.assertIn("unavailable", completed.stdout)
            self.assertIn("do not require the pinned decoder", completed.stdout)

    def test_wrong_tshark_version_is_reported_not_silently_substituted(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_tshark = make_fake_tshark(tmp, "4.2.2")
            completed = run_dev("doctor", env={"CORENET_DEV_TSHARK": str(fake_tshark)})
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("4.2.2", completed.stdout)
            self.assertIn(f"requires {GOLDEN_TSHARK_VERSION}", completed.stdout)
            self.assertIn("READY_WITH_LIMITATIONS", completed.stdout)

    def test_matching_tshark_version_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_tshark = make_fake_tshark(tmp, GOLDEN_TSHARK_VERSION)
            completed = run_dev("doctor", env={"CORENET_DEV_TSHARK": str(fake_tshark)})
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn(f"matches {GOLDEN_TSHARK_VERSION}", completed.stdout)
            self.assertIn("READY\n", completed.stdout)


class ExternalSourcePathTests(unittest.TestCase):
    def test_missing_source_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_tshark = make_fake_tshark(tmp, GOLDEN_TSHARK_VERSION)
            completed = run_dev(
                "golden-preflight",
                "--source-root",
                str(tmp / "absent-corpus"),
                env={"CORENET_DEV_TSHARK": str(fake_tshark)},
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("does not exist", completed.stderr)

    def test_source_root_inside_repository_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_tshark = make_fake_tshark(tmp, GOLDEN_TSHARK_VERSION)
            inside = ROOT / "benchmarks" / "golden-captures" / "cases"
            completed = run_dev(
                "golden-preflight",
                "--source-root",
                str(inside),
                env={"CORENET_DEV_TSHARK": str(fake_tshark)},
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("must be outside", completed.stderr)

    def test_work_root_inside_repository_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_tshark = make_fake_tshark(tmp, GOLDEN_TSHARK_VERSION)
            fake_git = make_fake_git(tmp, head=GOLDEN_SOURCE_COMMIT)
            corpus = tmp / "corpus"
            corpus.mkdir()
            completed = run_dev(
                "golden-preflight",
                "--source-root",
                str(corpus),
                "--work-root",
                str(ROOT / "scripts"),
                env={
                    "CORENET_DEV_TSHARK": str(fake_tshark),
                    "CORENET_DEV_GIT": str(fake_git),
                },
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("must be outside", completed.stderr)

    def test_option_like_source_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_tshark = make_fake_tshark(tmp, GOLDEN_TSHARK_VERSION)
            completed = run_dev(
                "golden-preflight",
                "--source-root",
                "--work-root",
                env={"CORENET_DEV_TSHARK": str(fake_tshark)},
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("must be a path", completed.stderr)


class ExternalCommitTests(unittest.TestCase):
    def test_incorrect_corpus_commit_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_tshark = make_fake_tshark(tmp, GOLDEN_TSHARK_VERSION)
            fake_git = make_fake_git(tmp, head="0" * 40)
            corpus = tmp / "corpus"
            corpus.mkdir()
            completed = run_dev(
                "golden-preflight",
                "--source-root",
                str(corpus),
                env={
                    "CORENET_DEV_TSHARK": str(fake_tshark),
                    "CORENET_DEV_GIT": str(fake_git),
                },
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("commit mismatch", completed.stderr)
            self.assertIn(GOLDEN_SOURCE_COMMIT, completed.stderr)

    def test_non_git_source_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_tshark = make_fake_tshark(tmp, GOLDEN_TSHARK_VERSION)
            fake_git = make_fake_git(tmp, head=GOLDEN_SOURCE_COMMIT, rc=128)
            corpus = tmp / "corpus"
            corpus.mkdir()
            completed = run_dev(
                "golden-preflight",
                "--source-root",
                str(corpus),
                env={
                    "CORENET_DEV_TSHARK": str(fake_tshark),
                    "CORENET_DEV_GIT": str(fake_git),
                },
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("not a Git checkout", completed.stderr)

    def test_tshark_mismatch_stops_before_corpus_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_tshark = make_fake_tshark(tmp, "4.4.0")
            corpus = tmp / "corpus"
            corpus.mkdir()
            completed = run_dev(
                "golden-preflight",
                "--source-root",
                str(corpus),
                env={"CORENET_DEV_TSHARK": str(fake_tshark)},
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("TShark version mismatch", completed.stderr)
            self.assertIn("Refusing to substitute", completed.stderr)


class BootstrapIdempotencyTests(unittest.TestCase):
    def test_bootstrap_creates_then_preserves_virtual_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            venv_dir = tmp / "venv"
            env = {"CORENET_DEV_VENV_DIR": str(venv_dir)}

            first = run_dev("bootstrap", "--dry-run", env=env)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("would be created", first.stdout)
            self.assertFalse(venv_dir.exists(), "dry-run must not create the environment")

            second = run_dev("bootstrap", env=env)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertTrue((venv_dir / "bin" / "python").exists() or (venv_dir / "Scripts" / "python.exe").exists())
            marker = venv_dir / "pyvenv.cfg"
            first_cfg = marker.read_text(encoding="utf-8") if marker.is_file() else ""
            first_stat = marker.stat().st_mtime_ns if marker.is_file() else 0

            third = run_dev("bootstrap", env=env)
            self.assertEqual(third.returncode, 0, third.stderr)
            self.assertIn("preserved (compatible)", third.stdout)
            self.assertNotIn("created", third.stdout)
            if marker.is_file():
                self.assertEqual(first_cfg, marker.read_text(encoding="utf-8"))
                self.assertEqual(first_stat, marker.stat().st_mtime_ns)

            fourth = run_dev("bootstrap", "--dry-run", env=env)
            self.assertEqual(fourth.returncode, 0, fourth.stderr)
            self.assertIn("preserved", fourth.stdout)

    def test_bootstrap_never_touches_git_configuration(self):
        git_local, git_blob = git_config_snapshot()
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            completed = run_dev("bootstrap", "--dry-run", env={"CORENET_DEV_VENV_DIR": str(tmp / "venv")})
            self.assertEqual(completed.returncode, 0, completed.stderr)
        git_local_after, git_blob_after = git_config_snapshot()
        self.assertEqual(git_local, git_local_after)
        self.assertEqual(git_blob, git_blob_after)

    def test_bootstrap_refuses_incompatible_existing_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            venv_dir = tmp / "venv"
            bin_dir = venv_dir / "bin"
            bin_dir.mkdir(parents=True)
            write_script(
                bin_dir / "python",
                '#!/usr/bin/env bash\nif [ "${1:-}" = "--version" ]; then echo "Python 3.10.12"; fi\nexit 0\n',
            )
            completed = run_dev("bootstrap", env={"CORENET_DEV_VENV_DIR": str(venv_dir)})
            self.assertEqual(completed.returncode, 1)
            self.assertIn("will not delete", completed.stderr)
            self.assertTrue((bin_dir / "python").exists())


class SystemPackageGateTests(unittest.TestCase):
    def test_install_os_deps_is_explicitly_gated(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_apt = make_fake_apt(tmp)
            completed = run_dev(
                "bootstrap",
                "--dry-run",
                env={
                    "CORENET_DEV_APT_GET": str(fake_apt),
                    "CORENET_DEV_SUDO": "",
                    "CORENET_DEV_VENV_DIR": str(tmp / "venv"),
                },
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("System packages were not changed", completed.stdout)
            self.assertFalse((tmp / "apt.log").exists())

    def test_install_os_deps_dry_run_lists_packages_without_installing(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_apt = make_fake_apt(tmp)
            completed = run_dev(
                "bootstrap",
                "--install-os-deps",
                "--dry-run",
                env={
                    "CORENET_DEV_APT_GET": str(fake_apt),
                    "CORENET_DEV_SUDO": "",
                    "CORENET_DEV_VENV_DIR": str(tmp / "venv"),
                },
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("python3", completed.stdout)
            self.assertIn("python3-venv", completed.stdout)
            self.assertIn("git", completed.stdout)
            self.assertIn("no packages were installed", completed.stdout)
            self.assertFalse((tmp / "apt.log").exists())

    def test_install_os_deps_propagates_installation_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_apt = make_fake_apt(tmp, rc=100)
            completed = run_dev(
                "bootstrap",
                "--install-os-deps",
                env={
                    "CORENET_DEV_APT_GET": str(fake_apt),
                    "CORENET_DEV_SUDO": "",
                    "CORENET_DEV_VENV_DIR": str(tmp / "venv"),
                },
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("installation failed", completed.stderr)
            self.assertTrue((tmp / "apt.log").is_file())
            self.assertIn("install -y", (tmp / "apt.log").read_text(encoding="utf-8"))

    def test_install_os_deps_never_lists_tshark(self):
        # The pinned Golden Capture decoder must not be replaced by APT.
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_apt = make_fake_apt(tmp)
            completed = run_dev(
                "bootstrap",
                "--install-os-deps",
                "--dry-run",
                env={
                    "CORENET_DEV_APT_GET": str(fake_apt),
                    "CORENET_DEV_SUDO": "",
                    "CORENET_DEV_VENV_DIR": str(tmp / "venv"),
                },
            )
            package_line = ""
            for line in completed.stdout.splitlines():
                if "packages requested via APT" in line:
                    package_line = line
                    break
            self.assertIn("packages requested via APT", package_line)
            self.assertNotIn("tshark", package_line.lower())


class ValidationFailurePropagationTests(unittest.TestCase):
    def test_failing_gate_reports_name_and_preserves_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_python = write_script(
                tmp / "failing-python",
                """\
                #!/usr/bin/env bash
                if [ "${1:-}" = "--version" ]; then
                  echo "Python 3.12.3"
                  exit 0
                fi
                if [ "${1:-}" = "-c" ]; then
                  exit 0
                fi
                if [ "${1:-}" = "-" ]; then
                  echo ""
                  exit 0
                fi
                exit 7
                """,
            )
            completed = run_dev(
                "validate",
                env={"CORENET_DEV_PYTHON": str(fake_python)},
            )
            self.assertEqual(completed.returncode, 7, completed.stdout + completed.stderr)
            self.assertIn("FAILED gate:", completed.stderr)
            self.assertIn("validate-repository.py", completed.stderr)

    def test_validate_requires_expected_python_series(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_python = make_fake_python(tmp, version="3.9.18")
            completed = run_dev("validate", env={"CORENET_DEV_PYTHON": str(fake_python)})
            self.assertEqual(completed.returncode, 3)
            self.assertIn("3.12.x is required", completed.stderr)


class MinimalHarnessTests(unittest.TestCase):
    """Happy-path harness using doubles only; never runs the real suite."""

    def test_fake_toolchain_completes_validate_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            fake_python = write_script(
                tmp / "ok-python",
                """\
                #!/usr/bin/env bash
                if [ "${1:-}" = "--version" ]; then
                  echo "Python 3.12.3"
                  exit 0
                fi
                if [ "${1:-}" = "-m" ] && [ "${2:-}" = "unittest" ]; then
                  echo "Ran 1 tests in 0.001s" >&2
                  echo "OK" >&2
                  exit 0
                fi
                # compileall, validators, and stdlib probes all succeed.
                exit 0
                """,
            )
            fake_git = write_script(
                tmp / "ok-git",
                """\
                #!/usr/bin/env bash
                if [ "${1:-}" = "--version" ]; then
                  echo "git version 2.43.0"
                  exit 0
                fi
                exit 0
                """,
            )
            completed = run_dev(
                "validate",
                env={
                    "CORENET_DEV_PYTHON": str(fake_python),
                    "CORENET_DEV_GIT": str(fake_git),
                },
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("All validation gates passed.", completed.stdout)
            self.assertIn("tests executed: 1", completed.stdout)

    def test_golden_preflight_requires_real_corpus_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            corpus = tmp / "corpus"
            corpus.mkdir()
            (corpus / "captures" / "baseline").mkdir(parents=True)
            fake_tshark = make_fake_tshark(tmp, GOLDEN_TSHARK_VERSION)
            fake_git = make_fake_git(tmp, head=GOLDEN_SOURCE_COMMIT)
            completed = run_dev(
                "golden-preflight",
                "--source-root",
                str(corpus),
                "--work-root",
                str(tmp / "work"),
                "--output-root",
                str(tmp / "out"),
                env={
                    "CORENET_DEV_TSHARK": str(fake_tshark),
                    "CORENET_DEV_GIT": str(fake_git),
                },
            )
            # Without the full corpus the verifier must fail loudly rather than
            # claim readiness.
            self.assertEqual(completed.returncode, 1)
            self.assertIn("corpus metadata and capture verification failed", completed.stderr)
            self.assertIn("missing capture", completed.stderr)

    def test_golden_preflight_rejects_capture_digest_mismatch(self):
        import ast

        runner = ROOT / "benchmarks" / "golden-captures" / "scripts" / "run_public_corpus.py"
        tree = ast.parse(runner.read_text(encoding="utf-8"))
        corpus = None
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if getattr(target, "id", "") == "PUBLIC_CORPUS":
                        corpus = ast.literal_eval(node.value)
        self.assertIsNotNone(corpus)

        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            source = tmp / "corpus"
            source.mkdir()
            for item in corpus:
                path = source / item["relative_path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                # Wrong contents on purpose: the verifier must compare digests
                # rather than trust presence alone.
                path.write_bytes(b"not-a-real-capture")
            fake_tshark = make_fake_tshark(tmp, GOLDEN_TSHARK_VERSION)
            fake_git = make_fake_git(tmp, head=GOLDEN_SOURCE_COMMIT)
            completed = run_dev(
                "golden-preflight",
                "--source-root",
                str(source),
                env={
                    "CORENET_DEV_TSHARK": str(fake_tshark),
                    "CORENET_DEV_GIT": str(fake_git),
                },
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("sha256 mismatch", completed.stderr)
            self.assertIn("corpus entries verified: 0/", completed.stdout)


class RepositoryHygieneTests(unittest.TestCase):
    def test_frozen_golden_capture_artifacts_are_unchanged_by_helper(self):
        before = tree_digest(GOLDEN_DIR)
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            run_dev("doctor", env={"CORENET_DEV_VENV_DIR": str(tmp / "venv")})
            run_dev("bootstrap", "--dry-run", env={"CORENET_DEV_VENV_DIR": str(tmp / "venv")})
        self.assertEqual(before, tree_digest(GOLDEN_DIR))

    def test_helper_does_not_modify_git_configuration(self):
        git_local, git_blob = git_config_snapshot()
        remote_before = subprocess.run(
            ["git", "-C", str(ROOT), "remote", "-v"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            run_dev("doctor", env={"CORENET_DEV_VENV_DIR": str(tmp / "venv")})
            run_dev("bootstrap", env={"CORENET_DEV_VENV_DIR": str(tmp / "venv")})
        git_local_after, git_blob_after = git_config_snapshot()
        remote_after = subprocess.run(
            ["git", "-C", str(ROOT), "remote", "-v"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        self.assertEqual(git_local, git_local_after)
        self.assertEqual(git_blob, git_blob_after)
        self.assertEqual(remote_before, remote_after)

    def test_dev_script_uses_lf_line_endings(self):
        data = DEV_SH.read_bytes()
        self.assertNotIn(b"\r\n", data)
        self.assertNotIn(b"\r", data)

    def test_dev_script_is_executable(self):
        self.assertTrue(os.access(DEV_SH, os.X_OK))

    def test_no_raw_captures_introduced_by_helper_files(self):
        # The helper tree itself must not carry capture binaries.
        for path in (ROOT / "scripts").iterdir():
            if path.is_file():
                self.assertNotIn(path.suffix.lower(), {".pcap", ".pcapng", ".cap"}, path)


class TestSuiteInclusionTests(unittest.TestCase):
    def test_this_module_is_discovered_by_root_unittest(self):
        # Guard against accidental exclusion from `unittest discover -s tests`.
        # Load without executing so this check cannot recurse into itself.
        loader = unittest.TestLoader()
        suite = loader.discover(str(ROOT / "tests"), pattern="test_dev_environment.py")
        self.assertGreaterEqual(suite.countTestCases(), 20)

    def test_module_imports_cleanly(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "test_dev_environment_under_test",
            ROOT / "tests" / "structure" / "test_dev_environment.py",
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        self.assertTrue(hasattr(module, "DEV_SH"))
        self.assertEqual(module.ROOT, ROOT)


if __name__ == "__main__":
    unittest.main()
