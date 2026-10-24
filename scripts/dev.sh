#!/usr/bin/env bash
# CoreNet Skill developer environment helper for Ubuntu 24.04.
#
# Entry point:
#   ./scripts/dev.sh doctor
#   ./scripts/dev.sh bootstrap [--install-os-deps] [--dry-run]
#   ./scripts/dev.sh validate
#   ./scripts/dev.sh golden-preflight --source-root PATH [options]
#
# Exit codes:
#   0  success (doctor: READY or READY_WITH_LIMITATIONS)
#   1  a check, gate, or preflight condition failed
#   2  usage error (unknown command, missing or invalid arguments)
#   3  environment blocked (essential prerequisite missing)
#   N  validate propagates the failing command's own exit code when a gate fails
set -euo pipefail

# ---------------------------------------------------------------------------
# Repository root resolution (independent of the current working directory)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"

if [[ ! -f "$ROOT/AGENTS.md" || ! -f "$ROOT/scripts/validate-repository.py" ]]; then
  echo "error: repository root not detected from script location: $ROOT" >&2
  exit 3
fi

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
EXPECTED_PYTHON_SERIES="3.12"
EXPECTED_PLATFORM_ID="ubuntu"
EXPECTED_PLATFORM_VERSION="24.04"
GOLDEN_TSHARK_VERSION="4.7.1"
GOLDEN_SOURCE_COMMIT="82934c2cc231540fa425e48177d4bed33210bfc1"
GOLDEN_SCRIPTS_DIR="$ROOT/benchmarks/golden-captures/scripts"
GOLDEN_CASES_DIR="$ROOT/benchmarks/golden-captures/cases"
DEFAULT_WORK_ROOT="/tmp/corenet-golden-run"

# Required standard-library modules for repository validators and tests.
REQUIRED_STDLIB_MODULES=(
  argparse ast copy hashlib importlib.util json pathlib py_compile re
  shutil subprocess sys tempfile typing unittest venv
)

# Validators in the order exercised by .github/workflows/validate.yml.
VALIDATOR_SCRIPTS=(
  scripts/validate-repository.py
  scripts/validate-architecture.py
  scripts/validate-upstream-snapshots.py
  scripts/validate-foundation-skills.py
  scripts/validate-core-network-pcap.py
  scripts/validate-s1ap.py
  scripts/validate-nas-eps.py
  scripts/validate-epc-procedures.py
  scripts/validate-ngap.py
  scripts/validate-nas-5gs.py
  scripts/validate-pfcp.py
  scripts/validate-gtpu.py
  scripts/validate-sbi-http2.py
  scripts/validate-cross-protocol-evidence.py
  scripts/validate-procedure-evidence.py
  scripts/validate-5gc-registration-mobility.py
  scripts/validate-5gc-pdu-session.py
  scripts/validate-5gc-handover-mobility.py
  scripts/validate-5gc-failure-boundary.py
  scripts/validate-golden-captures.py
)

# Script directories compiled by the accepted CI workflow.
COMPILEALL_DIRS=(
  scripts
  benchmarks/golden-captures/scripts
  skills/protocol/core-network-pcap/scripts
  skills/protocol/s1ap/scripts
  skills/protocol/nas-eps/scripts
  skills/domain/epc-procedures/scripts
  skills/protocol/ngap/scripts
  skills/protocol/nas-5gs/scripts
  skills/protocol/pfcp/scripts
  skills/protocol/gtpu/scripts
  skills/protocol/sbi-http2/scripts
  skills/correlation/cross-protocol-evidence/scripts
  skills/domain/procedure-evidence/scripts
  skills/domain/5gc-registration-mobility/scripts
  skills/domain/5gc-pdu-session/scripts
  skills/domain/5gc-handover-mobility/scripts
  skills/orchestration/5gc-failure-boundary/scripts
)

# Ubuntu packages offered by bootstrap --install-os-deps. TShark is
# deliberately absent: the pinned Golden Capture decoder must not be
# replaced by a distribution package of a different version.
OS_DEPS_PACKAGES=(python3 python3-venv git)

# ---------------------------------------------------------------------------
# Tool overrides (test injection). Normal development never sets these.
# ---------------------------------------------------------------------------
OS_RELEASE_FILE="${CORENET_DEV_OS_RELEASE_FILE:-/etc/os-release}"
PYTHON_BIN="${CORENET_DEV_PYTHON:-python3}"
GIT_BIN="${CORENET_DEV_GIT:-git}"
TSHARK_BIN="${CORENET_DEV_TSHARK:-tshark}"
APT_GET_BIN="${CORENET_DEV_APT_GET:-apt-get}"
SUDO_BIN="${CORENET_DEV_SUDO-sudo}"
UNAME_M_OVERRIDE="${CORENET_DEV_UNAME_M:-}"
VENV_DIR="${CORENET_DEV_VENV_DIR:-$ROOT/.venv}"

# Populated by check_external_path for the caller.
EXTERNAL_PATH=""

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
usage() {
  cat <<'EOF'
Usage:
  ./scripts/dev.sh doctor
  ./scripts/dev.sh bootstrap [--install-os-deps] [--dry-run]
  ./scripts/dev.sh validate
  ./scripts/dev.sh golden-preflight --source-root PATH [--work-root PATH] [--output-root PATH]

Commands:
  doctor            Inspect the environment without modifying it.
  bootstrap         Verify prerequisites and prepare the local virtual environment.
  validate          Run the full local repository validation sequence.
  golden-preflight  Read-only readiness check for external Golden Capture corpus work.

Options:
  --install-os-deps  bootstrap only: install the listed Ubuntu packages via APT.
  --dry-run          bootstrap only: report planned changes without applying them.
  --source-root      golden-preflight: external capture corpus checkout.
  --work-root        golden-preflight: external working directory to validate.
  --output-root      golden-preflight: external output directory to validate.
  -h, --help         Show this help.

Exit codes:
  0  success (doctor reports READY or READY_WITH_LIMITATIONS)
  1  a check, gate, or preflight condition failed
  2  usage error (unknown command, missing or invalid arguments)
  3  environment blocked (essential prerequisite missing)
  N  validate propagates the failing command's exit code when a gate fails
EOF
}

die_usage() {
  echo "error: $*" >&2
  echo "Run './scripts/dev.sh --help' for usage." >&2
  exit 2
}

die_blocked() {
  echo "error: $*" >&2
  exit 3
}

die_failed() {
  echo "error: $*" >&2
  exit 1
}

canonical_path() {
  local target="$1"
  run_tool "$PYTHON_BIN" - "$target" <<'PY'
import errno
import sys
from pathlib import Path

try:
    target = Path(sys.argv[1])
    resolved = target.resolve(strict=False)
    curr = target if target.is_absolute() else (Path.cwd() / target)
    while curr.parent != curr:
        try:
            if curr.is_symlink() or (hasattr(curr, "is_junction") and curr.is_junction()) or curr.exists():
                curr.resolve(strict=True)
                break
        except (OSError, RuntimeError) as exc:
            err = getattr(exc, "errno", 0)
            winerr = getattr(exc, "winerror", 0)
            if err == getattr(errno, "ELOOP", 40) or winerr == 1920 or "loop" in str(exc).lower():
                raise
        curr = curr.parent
    if not resolved.is_absolute():
        sys.exit(1)
    print(resolved)
except Exception:
    sys.exit(1)
PY
}

is_inside_repo() {
  local candidate="$1"
  run_tool "$PYTHON_BIN" - "$ROOT" "$candidate" <<'PY'
import sys
from pathlib import Path

try:
    repo_root = Path(sys.argv[1]).resolve(strict=False)
    candidate = Path(sys.argv[2]).resolve(strict=False)
    if candidate == repo_root or candidate.is_relative_to(repo_root):
        sys.exit(0)
    sys.exit(1)
except Exception:
    sys.exit(0)
PY
}

# Validate an external path and publish its canonical form in EXTERNAL_PATH.
# The third argument is 1 when the path must already exist (capture sources)
# and 0 for destinations that may be created later (work/output directories).
# Returns 2 on usage problems, 1 on failed checks; never runs in a subshell.
check_external_path() {
  local label="$1"
  local raw="$2"
  local must_exist="${3:-1}"
  EXTERNAL_PATH=""
  if [[ -z "$raw" ]]; then
    echo "error: $label must be a non-empty path" >&2
    return 2
  fi
  if [[ "$raw" == -* ]]; then
    echo "error: $label must be a path, not an option: $raw" >&2
    return 2
  fi
  local py_out rc=0
  py_out="$(run_tool "$PYTHON_BIN" - "$ROOT" "$label" "$raw" "$must_exist" <<'PY'
import errno
import sys
from pathlib import Path

repo_root_arg = sys.argv[1]
label = sys.argv[2]
raw_arg = sys.argv[3]
must_exist = (sys.argv[4] == "1")

raw = Path(raw_arg)

try:
    resolved = raw.resolve(strict=False)
    curr = raw if raw.is_absolute() else (Path.cwd() / raw)
    while curr.parent != curr:
        try:
            if curr.is_symlink() or (hasattr(curr, "is_junction") and curr.is_junction()) or curr.exists():
                curr.resolve(strict=True)
                break
        except (OSError, RuntimeError) as exc:
            err = getattr(exc, "errno", 0)
            winerr = getattr(exc, "winerror", 0)
            if err == getattr(errno, "ELOOP", 40) or winerr == 1920 or "loop" in str(exc).lower():
                raise
        curr = curr.parent
except Exception as exc:
    print(f"error: {label} canonicalization failed for {raw_arg}: {exc}", file=sys.stderr)
    sys.exit(1)

if must_exist and not resolved.exists():
    print(f"error: {label} does not exist: {raw_arg}", file=sys.stderr)
    sys.exit(1)

if not must_exist and resolved.exists() and not resolved.is_dir():
    print(f"error: {label} must be a directory or future directory, not an existing file: {raw_arg}", file=sys.stderr)
    sys.exit(1)

if not resolved.is_absolute():
    print(f"error: {label} must be an absolute path or an existing relative path: {raw_arg}", file=sys.stderr)
    sys.exit(1)

try:
    repo_root = Path(repo_root_arg).resolve(strict=False)
    if resolved == repo_root or resolved.is_relative_to(repo_root):
        print(f"error: {label} must be outside the CoreNet Skill repository: {resolved}", file=sys.stderr)
        sys.exit(1)
except Exception as exc:
    print(f"error: {label} containment check failed for {raw_arg}: {exc}", file=sys.stderr)
    sys.exit(1)

print(resolved)
PY
)" || rc=$?

  if [[ "$rc" -ne 0 ]]; then
    return "$rc"
  fi
  EXTERNAL_PATH="$py_out"
  return 0
}

os_release_get() {
  local key="$1"
  [[ -f "$OS_RELEASE_FILE" ]] || return 1
  sed -n "s/^${key}=//p" "$OS_RELEASE_FILE" | tail -n 1 | sed 's/^"//; s/"$//'
}

tool_available() {
  local candidate="$1"
  if [[ "$candidate" == */* ]]; then
    [[ -x "$candidate" ]]
  else
    command -v "$candidate" >/dev/null 2>&1
  fi
}

run_tool() {
  # Run a tool that may be an absolute path or a bare command name.
  local candidate="$1"
  shift
  "$candidate" "$@"
}

detect_architecture() {
  if [[ -n "$UNAME_M_OVERRIDE" ]]; then
    printf '%s\n' "$UNAME_M_OVERRIDE"
  else
    uname -m
  fi
}

detect_python_version() {
  tool_available "$PYTHON_BIN" || return 1
  run_tool "$PYTHON_BIN" --version 2>&1 | sed -n 's/^Python[[:space:]]*//p' | head -n 1
}

python_series() {
  local version="$1"
  printf '%s\n' "$version" | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p'
}

detect_tool_version() {
  local bin="$1"
  tool_available "$bin" || return 1
  run_tool "$bin" --version 2>&1 | head -n 1
}

extract_semver() {
  # First X.Y.Z token found on stdin.
  sed -n 's/^[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -n 1
}

detect_tshark_version() {
  tool_available "$TSHARK_BIN" || return 1
  # Version banner is written to stdout; stderr may carry runtime warnings.
  local version
  version="$(run_tool "$TSHARK_BIN" --version 2>/dev/null | extract_semver)"
  if [[ -z "$version" ]]; then
    version="$(run_tool "$TSHARK_BIN" --version 2>&1 | extract_semver)"
  fi
  [[ -n "$version" ]] || return 1
  printf '%s\n' "$version"
}

missing_stdlib_modules() {
  if ! tool_available "$PYTHON_BIN"; then
    printf '%s\n' "${REQUIRED_STDLIB_MODULES[*]}"
    return 0
  fi
  run_tool "$PYTHON_BIN" - "${REQUIRED_STDLIB_MODULES[@]}" <<'PY'
import importlib
import sys

missing = []
for name in sys.argv[1:]:
    try:
        importlib.import_module(name)
    except Exception:
        missing.append(name)
print(" ".join(missing))
PY
}

detect_worktree_status() {
  tool_available "$GIT_BIN" || return 1
  if [[ ! -d "$ROOT/.git" ]]; then
    printf 'not-a-git-checkout\n'
    return 0
  fi
  local dirty
  if dirty="$(run_tool "$GIT_BIN" -C "$ROOT" status --porcelain 2>/dev/null)" && [[ -z "$dirty" ]]; then
    printf 'clean\n'
  else
    printf 'dirty\n'
  fi
}

# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------
cmd_doctor() {
  local platform_id platform_version platform_label arch
  local python_version python_series_val python_ok="no"
  local git_line bash_line venv_line repo_line worktree_line
  local tshark_line tshark_version golden_line
  local stdlib_missing status
  local notes=()

  platform_id="$(os_release_get ID || true)"
  platform_version="$(os_release_get VERSION_ID || true)"
  if [[ -n "${platform_id:-}" && -n "${platform_version:-}" ]]; then
    platform_label="$(printf '%s %s' "$platform_id" "$platform_version" | sed 's/^./\U&/')"
  else
    platform_label="unknown"
  fi
  arch="$(detect_architecture)"

  python_version="$(detect_python_version || true)"
  python_series_val=""
  if [[ -n "${python_version:-}" ]]; then
    python_series_val="$(python_series "$python_version")"
    if [[ "$python_series_val" == "$EXPECTED_PYTHON_SERIES" ]]; then
      python_ok="yes"
    fi
  fi

  if tool_available "$GIT_BIN"; then
    git_line="available ($(detect_tool_version "$GIT_BIN" | sed 's/^git version //'))"
  else
    git_line="unavailable"
  fi

  # This helper always runs under Bash; report the interpreter version.
  bash_line="available (${BASH_VERSION})"

  if tool_available "$PYTHON_BIN" && run_tool "$PYTHON_BIN" -c 'import venv' >/dev/null 2>&1; then
    venv_line="available"
  else
    venv_line="unavailable"
  fi

  if [[ -f "$ROOT/AGENTS.md" && -d "$ROOT/scripts" ]]; then
    repo_line="detected ($ROOT)"
  else
    repo_line="not detected"
  fi

  worktree_line="$(detect_worktree_status || echo unknown)"

  if tool_available "$TSHARK_BIN"; then
    tshark_version="$(detect_tshark_version || echo unknown)"
    tshark_line="available"
  else
    tshark_version=""
    tshark_line="unavailable"
  fi

  if [[ -n "${tshark_version:-}" ]]; then
    if [[ "$tshark_version" == "$GOLDEN_TSHARK_VERSION" ]]; then
      golden_line="matches $GOLDEN_TSHARK_VERSION (decoder baseline verified; external corpus not verified)"
    else
      golden_line="requires $GOLDEN_TSHARK_VERSION (found ${tshark_version}; do not substitute)"
    fi
  else
    golden_line="requires $GOLDEN_TSHARK_VERSION (not installed)"
  fi

  stdlib_missing="$(missing_stdlib_modules || true)"
  stdlib_missing="$(printf '%s' "$stdlib_missing" | tr -s ' ' | sed 's/^ //; s/ $//')"

  echo "CoreNet Skill Development Environment"
  echo
  printf '%-18s %s\n' "Platform" "$platform_label"
  printf '%-18s %s\n' "Architecture" "$arch"
  printf '%-18s %s\n' "Python" "${python_version:-unavailable} (expected ${EXPECTED_PYTHON_SERIES}.x)"
  printf '%-18s %s\n' "Git" "$git_line"
  printf '%-18s %s\n' "Bash" "$bash_line"
  printf '%-18s %s\n' "Python venv" "$venv_line"
  printf '%-18s %s\n' "Repository" "$repo_line"
  printf '%-18s %s\n' "Worktree" "$worktree_line"
  printf '%-18s %s\n' "TShark" "$tshark_line"
  printf '%-18s %s\n' "TShark version" "${tshark_version:-not detected}"
  printf '%-18s %s\n' "Golden baseline" "$golden_line"
  if [[ -n "${stdlib_missing:-}" ]]; then
    printf '%-18s %s\n' "Stdlib modules" "missing: $stdlib_missing"
  else
    printf '%-18s %s\n' "Stdlib modules" "all required present"
  fi
  echo
  echo "Optional external capture dependencies:"
  echo "  External corpus is not bundled. Provide an explicit checkout to"
  echo "  './scripts/dev.sh golden-preflight --source-root PATH'."
  echo "  Full corpus reproduction stays behind the existing benchmark runner."

  # Essential requirements versus optional Golden Capture reproduction tools.
  local blocked=0
  if [[ "$python_ok" != "yes" ]]; then
    blocked=1
    notes+=("Python ${EXPECTED_PYTHON_SERIES}.x is required for repository validation.")
  fi
  if ! tool_available "$GIT_BIN"; then
    blocked=1
    notes+=("Git is required.")
  fi
  if [[ "$venv_line" != "available" ]]; then
    blocked=1
    notes+=("Python venv support is required for bootstrap.")
  fi
  if [[ -n "${stdlib_missing:-}" ]]; then
    blocked=1
    notes+=("Required standard-library modules are missing.")
  fi
  if [[ "$repo_line" != detected* ]]; then
    blocked=1
    notes+=("Repository root could not be detected.")
  fi

  if [[ "$blocked" -ne 0 ]]; then
    status="BLOCKED"
  elif [[ "$platform_id" == "$EXPECTED_PLATFORM_ID" && "$platform_version" == "$EXPECTED_PLATFORM_VERSION" \
          && "$tshark_version" == "$GOLDEN_TSHARK_VERSION" ]]; then
    status="READY"
  else
    status="READY_WITH_LIMITATIONS"
  fi

  if [[ "$platform_id" != "$EXPECTED_PLATFORM_ID" || "$platform_version" != "$EXPECTED_PLATFORM_VERSION" ]]; then
    notes+=("Target platform is Ubuntu ${EXPECTED_PLATFORM_VERSION}; bootstrap --install-os-deps refuses other systems.")
  fi
  if [[ "$worktree_line" == "dirty" ]]; then
    notes+=("Working tree has local changes; standard validation still runs.")
  fi
  if [[ "$tshark_version" == "$GOLDEN_TSHARK_VERSION" ]]; then
    notes+=("TShark ${GOLDEN_TSHARK_VERSION} matches baseline; external corpus checkout and verification remain required for full reproduction.")
  else
    notes+=("Golden Capture corpus reproduction needs TShark ${GOLDEN_TSHARK_VERSION} exactly.")
    notes+=("Standard repository unit tests do not require the pinned decoder.")
  fi

  if [[ "${#notes[@]}" -gt 0 ]]; then
    echo
    echo "Notes:"
    local note
    for note in "${notes[@]}"; do
      echo "  - $note"
    done
  fi

  echo
  echo "Environment status:"
  echo "$status"

  if [[ "$status" == "BLOCKED" ]]; then
    return 3
  fi
  return 0
}

# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------
cmd_bootstrap() {
  local install_os_deps=0 dry_run=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --install-os-deps) install_os_deps=1 ;;
      --dry-run) dry_run=1 ;;
      -h|--help)
        usage
        return 0
        ;;
      *) die_usage "unknown bootstrap option: $1" ;;
    esac
    shift
  done

  echo "CoreNet Skill developer bootstrap"
  echo
  printf '%-18s %s\n' "Repository" "$ROOT"
  if [[ "$dry_run" -eq 1 ]]; then
    printf '%-18s %s\n' "Mode" "dry-run"
  else
    printf '%-18s %s\n' "Mode" "apply"
  fi

  local platform_id platform_version python_version python_series_val
  platform_id="$(os_release_get ID || true)"
  platform_version="$(os_release_get VERSION_ID || true)"
  python_version="$(detect_python_version || true)"

  if [[ -z "${python_version:-}" ]]; then
    die_blocked "Python is unavailable; install Python ${EXPECTED_PYTHON_SERIES}.x and retry."
  fi
  python_series_val="$(python_series "$python_version")"
  printf '%-18s %s\n' "Python" "$python_version"
  if [[ "$python_series_val" != "$EXPECTED_PYTHON_SERIES" ]]; then
    die_blocked "Python ${EXPECTED_PYTHON_SERIES}.x is required; found ${python_version}."
  fi

  tool_available "$GIT_BIN" || die_blocked "Git is unavailable; install git and retry."

  local ubuntu_ok=0
  if [[ "$platform_id" == "$EXPECTED_PLATFORM_ID" && "$platform_version" == "$EXPECTED_PLATFORM_VERSION" ]]; then
    ubuntu_ok=1
    printf '%-18s %s\n' "Platform" "${platform_id} ${platform_version} (supported)"
  else
    printf '%-18s %s\n' "Platform" "${platform_id:-unknown} ${platform_version:-unknown} (target is ${EXPECTED_PLATFORM_ID} ${EXPECTED_PLATFORM_VERSION})"
  fi

  if run_tool "$PYTHON_BIN" -c 'import venv' >/dev/null 2>&1; then
    printf '%-18s %s\n' "Python venv" "available"
  else
    die_blocked "Python venv support is unavailable. Install the python3-venv package and retry."
  fi

  local stdlib_missing
  stdlib_missing="$(missing_stdlib_modules || true)"
  stdlib_missing="$(printf '%s' "$stdlib_missing" | tr -s ' ' | sed 's/^ //; s/ $//')"
  if [[ -n "${stdlib_missing:-}" ]]; then
    die_blocked "Required standard-library modules are missing: $stdlib_missing"
  fi
  printf '%-18s %s\n' "Stdlib modules" "all required present"

  # Optional Golden Capture toolchain is never installed here.
  local tshark_version=""
  if tool_available "$TSHARK_BIN"; then
    tshark_version="$(detect_tshark_version || true)"
  fi
  if [[ "$tshark_version" == "$GOLDEN_TSHARK_VERSION" ]]; then
    printf '%-18s %s\n' "TShark" "available ($tshark_version)"
  else
    printf '%-18s %s\n' "TShark" "optional, not ready for Golden Capture reproduction${tshark_version:+ (found $tshark_version)}"
    echo "  TShark ${GOLDEN_TSHARK_VERSION} is required only for external corpus reproduction."
    echo "  This bootstrap never installs or replaces TShark."
  fi

  echo
  if [[ "$install_os_deps" -eq 1 ]]; then
    if [[ "$ubuntu_ok" -ne 1 ]]; then
      die_blocked "bootstrap --install-os-deps is supported only on Ubuntu ${EXPECTED_PLATFORM_VERSION}; found ${platform_id:-unknown} ${platform_version:-unknown}."
    fi
    echo "System packages requested via APT: ${OS_DEPS_PACKAGES[*]}"
    echo "No APT sources are modified. No unrelated upgrades are performed."
    if [[ "$dry_run" -eq 1 ]]; then
      echo "Dry run: no packages were installed."
    else
      local apt_cmd=()
      if [[ -n "${SUDO_BIN}" ]] && [[ "$(id -u)" -ne 0 ]]; then
        tool_available "$SUDO_BIN" || die_blocked "sudo is required to install system packages, or run bootstrap --install-os-deps as root."
        apt_cmd=("$SUDO_BIN" "$APT_GET_BIN")
      else
        apt_cmd=("$APT_GET_BIN")
      fi
      tool_available "$APT_GET_BIN" || die_blocked "APT is unavailable; install packages manually: ${OS_DEPS_PACKAGES[*]}"
      echo "Running: ${apt_cmd[*]} install -y ${OS_DEPS_PACKAGES[*]}"
      if ! "${apt_cmd[@]}" install -y "${OS_DEPS_PACKAGES[@]}"; then
        die_failed "system package installation failed; no further changes were attempted."
      fi
      echo "System packages installed."
    fi
  else
    echo "System packages were not changed (pass --install-os-deps to install: ${OS_DEPS_PACKAGES[*]})."
  fi

  # Local virtual environment: create only when genuinely missing.
  echo
  if [[ "$dry_run" -eq 1 ]]; then
    if [[ -x "$VENV_DIR/bin/python" ]]; then
      echo "Dry run: virtual environment preserved ($VENV_DIR)."
    else
      echo "Dry run: virtual environment would be created ($VENV_DIR)."
    fi
  elif [[ -x "$VENV_DIR/bin/python" ]]; then
    local venv_version venv_series
    venv_version="$("$VENV_DIR/bin/python" --version 2>&1 | sed -n 's/^Python[[:space:]]*//p' | head -n 1)"
    venv_series="$(python_series "$venv_version")"
    if [[ "$venv_series" == "$EXPECTED_PYTHON_SERIES" ]]; then
      echo "Virtual environment preserved (compatible): $VENV_DIR"
    else
      die_failed "existing virtual environment at $VENV_DIR uses Python ${venv_version}, expected ${EXPECTED_PYTHON_SERIES}.x. Remove it manually if it is no longer needed; this tool will not delete it."
    fi
  else
    if [[ -e "$VENV_DIR" ]]; then
      die_failed "path exists but is not a usable virtual environment: $VENV_DIR. Resolve it manually; this tool will not delete it."
    fi
    echo "Creating virtual environment: $VENV_DIR"
    if ! run_tool "$PYTHON_BIN" -m venv "$VENV_DIR"; then
      die_failed "virtual environment creation failed at $VENV_DIR"
    fi
    echo "Virtual environment created: $VENV_DIR"
  fi

  echo
  echo "Bootstrap summary:"
  echo "  Python ${EXPECTED_PYTHON_SERIES}.x verified."
  echo "  No tracked files were modified."
  echo "  No Git remotes or credentials were changed."
  echo "  Standard validation is independent of the optional TShark ${GOLDEN_TSHARK_VERSION} toolchain."
  echo "Next: ./scripts/dev.sh validate"
  return 0
}

# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------
run_gate() {
  local label="$1"
  shift
  echo "==> $label"
  local rc=0
  (
    cd "$ROOT"
    "$@"
  ) || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "FAILED gate: $label" >&2
    return "$rc"
  fi
  echo "    ok"
  return 0
}

run_unittests() {
  local label="$1"
  local start_dir="$2"
  local pattern="$3"
  echo "==> $label"
  local out rc=0
  out="$(
    cd "$ROOT"
    run_tool "$PYTHON_BIN" -m unittest discover -s "$start_dir" -p "$pattern" -v 2>&1
  )" || rc=$?
  local count status_line
  count="$(printf '%s\n' "$out" | sed -n 's/^Ran \([0-9][0-9]*\) tests\{0,1\} in .*/\1/p' | tail -n 1)"
  status_line="$(printf '%s\n' "$out" | sed -n '/^OK/p; /^FAILED/p' | tail -n 1)"
  echo "    tests executed: ${count:-unknown}"
  echo "    result: ${status_line:-no-summary}"
  if [[ "$rc" -ne 0 ]]; then
    printf '%s\n' "$out" | tail -n 40 >&2
    echo "FAILED gate: $label" >&2
    return "$rc"
  fi
  echo "    ok"
  return 0
}

cmd_validate() {
  if [[ $# -gt 0 ]]; then
    case "$1" in
      -h|--help) usage; return 0 ;;
      *) die_usage "unknown validate option: $1" ;;
    esac
  fi

  tool_available "$PYTHON_BIN" || die_blocked "Python is unavailable."
  tool_available "$GIT_BIN" || die_blocked "Git is unavailable."

  local python_version python_series_val
  python_version="$(detect_python_version || true)"
  python_series_val="$(python_series "${python_version:-}")"
  if [[ "$python_series_val" != "$EXPECTED_PYTHON_SERIES" ]]; then
    die_blocked "Python ${EXPECTED_PYTHON_SERIES}.x is required for validate; found ${python_version:-unavailable}."
  fi

  echo "CoreNet Skill repository validation"
  echo "Repository: $ROOT"
  echo "Interpreter: $PYTHON_BIN (${python_version})"
  echo

  local script
  for script in "${VALIDATOR_SCRIPTS[@]}"; do
    [[ -f "$ROOT/$script" ]] || die_blocked "missing validator: $script"
    run_gate "validator: $script" run_tool "$PYTHON_BIN" "$script"
  done

  run_unittests "unit tests: s1ap" "skills/protocol/s1ap/tests" "test_*.py"
  run_unittests "unit tests: nas-eps" "skills/protocol/nas-eps/tests" "test_*.py"
  run_unittests "unit tests: epc-procedures" "skills/domain/epc-procedures/tests" "test_*.py"
  run_unittests "unit tests: golden captures" "benchmarks/golden-captures/tests" "test_*.py"
  run_unittests "unit tests: repository root" "tests" "test_*.py"

  local missing_dirs=()
  for script in "${COMPILEALL_DIRS[@]}"; do
    [[ -d "$ROOT/$script" ]] || missing_dirs+=("$script")
  done
  if [[ "${#missing_dirs[@]}" -gt 0 ]]; then
    die_blocked "compileall directories missing: ${missing_dirs[*]}"
  fi
  run_gate "compileall: CI script directories" run_tool "$PYTHON_BIN" -m compileall "${COMPILEALL_DIRS[@]}"

  # Read-only whitespace check; never rewrites the repository.
  run_gate "git whitespace check" run_tool "$GIT_BIN" diff --check

  echo
  echo "Validation summary:"
  echo "  validators: ${#VALIDATOR_SCRIPTS[@]} passed"
  echo "  golden capture and root unittest gates passed"
  echo "  compileall: ${#COMPILEALL_DIRS[@]} directories"
  echo "  whitespace: clean"
  echo "All validation gates passed."
  return 0
}

# ---------------------------------------------------------------------------
# golden-preflight
# ---------------------------------------------------------------------------
cmd_golden_preflight() {
  local source_root="" work_root="" output_root=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --source-root)
        [[ $# -ge 2 ]] || die_usage "--source-root requires a path"
        source_root="$2"
        shift 2
        ;;
      --work-root)
        [[ $# -ge 2 ]] || die_usage "--work-root requires a path"
        work_root="$2"
        shift 2
        ;;
      --output-root)
        [[ $# -ge 2 ]] || die_usage "--output-root requires a path"
        output_root="$2"
        shift 2
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *) die_usage "unknown golden-preflight option: $1" ;;
    esac
  done

  if [[ -z "$source_root" ]]; then
    die_usage "golden-preflight requires --source-root PATH"
  fi

  echo "CoreNet Skill Golden Capture preflight"
  echo
  echo "Read-only check. This command never runs the capture pipeline,"
  echo "never writes Golden Capture outputs, and never downloads captures."
  echo

  # Toolchain
  if ! tool_available "$TSHARK_BIN"; then
    echo "TShark: unavailable" >&2
    echo "Golden Capture reproduction requires TShark ${GOLDEN_TSHARK_VERSION} exactly." >&2
    die_blocked "TShark is unavailable; install TShark ${GOLDEN_TSHARK_VERSION} before external corpus reproduction."
  fi
  local tshark_version
  tshark_version="$(detect_tshark_version || true)"
  if [[ -z "${tshark_version:-}" ]]; then
    die_failed "could not determine TShark version from '$TSHARK_BIN --version'"
  fi
  printf '%-18s %s\n' "TShark version" "$tshark_version"
  if [[ "$tshark_version" != "$GOLDEN_TSHARK_VERSION" ]]; then
    echo "TShark ${GOLDEN_TSHARK_VERSION} is the accepted Golden Capture baseline." >&2
    echo "Refusing to substitute a different decoder version." >&2
    die_failed "TShark version mismatch: required ${GOLDEN_TSHARK_VERSION}, found ${tshark_version}"
  fi
  printf '%-18s %s\n' "Golden baseline" "matches ${GOLDEN_TSHARK_VERSION}"

  # External corpus root
  local source_canonical rc=0
  check_external_path "--source-root" "$source_root" || rc=$?
  if [[ "$rc" -eq 2 ]]; then
    exit 2
  elif [[ "$rc" -ne 0 ]]; then
    exit "$rc"
  fi
  source_canonical="$EXTERNAL_PATH"
  if [[ ! -d "$source_canonical" ]]; then
    die_failed "--source-root must be a directory: $source_canonical"
  fi
  printf '%-18s %s\n' "Source root" "$source_canonical"

  tool_available "$GIT_BIN" || die_blocked "Git is required to verify the external corpus commit."
  local source_commit
  if ! source_commit="$(run_tool "$GIT_BIN" -C "$source_canonical" rev-parse HEAD 2>/dev/null)"; then
    die_failed "external source is not a Git checkout: $source_canonical"
  fi
  source_commit="$(printf '%s' "$source_commit" | tr -d '[:space:]')"
  printf '%-18s %s\n' "Source commit" "$source_commit"
  printf '%-18s %s\n' "Expected commit" "$GOLDEN_SOURCE_COMMIT"
  if [[ "$source_commit" != "$GOLDEN_SOURCE_COMMIT" ]]; then
    die_failed "external corpus commit mismatch: required ${GOLDEN_SOURCE_COMMIT}, found ${source_commit}"
  fi

  # Optional working and output locations must also stay external.
  if [[ -n "$work_root" ]]; then
    check_external_path "--work-root" "$work_root" 0 || exit $?
    work_root="$EXTERNAL_PATH"
    printf '%-18s %s\n' "Work root" "$work_root"
  else
    local default_work
    default_work="$(canonical_path "$DEFAULT_WORK_ROOT")"
    if is_inside_repo "$default_work"; then
      die_failed "default work root resolves inside the repository: $default_work"
    fi
    printf '%-18s %s\n' "Work root" "$DEFAULT_WORK_ROOT (default, outside repository)"
  fi
  if [[ -n "$output_root" ]]; then
    check_external_path "--output-root" "$output_root" 0 || exit $?
    output_root="$EXTERNAL_PATH"
    printf '%-18s %s\n' "Output root" "$output_root"
  else
    printf '%-18s %s\n' "Output root" "not supplied (benchmark runner default stays external)"
  fi

  # Corpus metadata and capture files.
  tool_available "$PYTHON_BIN" || die_blocked "Python is required to verify corpus metadata."
  echo
  echo "Verifying corpus metadata and captures..."
  local verify_rc=0
  run_tool "$PYTHON_BIN" - "$source_canonical" "$GOLDEN_SCRIPTS_DIR" "$GOLDEN_CASES_DIR" <<'PY' || verify_rc=$?
import ast
import hashlib
import json
import sys
from pathlib import Path

source_root = Path(sys.argv[1])
scripts_dir = Path(sys.argv[2])
cases_dir = Path(sys.argv[3])

runner = scripts_dir / "run_public_corpus.py"
if not runner.is_file():
    print(f"error: corpus metadata source missing: {runner}", file=sys.stderr)
    raise SystemExit(1)

tree = ast.parse(runner.read_text(encoding="utf-8"))
corpus = None
for node in tree.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if getattr(target, "id", "") == "PUBLIC_CORPUS":
                corpus = ast.literal_eval(node.value)
if corpus is None:
    print("error: PUBLIC_CORPUS metadata not found in run_public_corpus.py", file=sys.stderr)
    raise SystemExit(1)

errors = []
verified = 0
for item in corpus:
    rel = item["relative_path"]
    path = source_root / rel
    if not path.is_file():
        errors.append(f"missing capture: {rel}")
        continue
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != item["expected_sha256"]:
        errors.append(f"sha256 mismatch: {rel}")
        continue
    if len(data) != item["expected_size"]:
        errors.append(f"size mismatch: {rel} ({len(data)} != {item['expected_size']})")
        continue
    verified += 1

if cases_dir.is_dir():
    for case_json in sorted(cases_dir.glob("*/case.json")):
        try:
            document = json.loads(case_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"invalid case metadata: {case_json.name}: {exc}")
            continue
        rel = document.get("source_capture_path")
        if not rel:
            errors.append(f"missing source_capture_path: {case_json}")
            continue
        if not (source_root / rel).is_file():
            errors.append(f"case metadata references missing capture: {rel}")

print(f"corpus entries verified: {verified}/{len(corpus)}")
if errors:
    print("corpus preflight failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)
PY
  if [[ "$verify_rc" -ne 0 ]]; then
    die_failed "corpus metadata and capture verification failed"
  fi

  echo
  echo "Golden Capture preflight result: READY"
  echo "Full corpus reproduction remains governed by the existing benchmark runner"
  echo "and its separate authorization. This preflight performed no writes."
  return 0
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  if [[ $# -lt 1 ]]; then
    usage >&2
    exit 2
  fi
  local command="$1"
  shift
  case "$command" in
    doctor)
      if [[ $# -gt 0 ]]; then
        case "$1" in
          -h|--help) usage; return 0 ;;
          *) die_usage "unknown doctor option: $1" ;;
        esac
      fi
      cmd_doctor
      ;;
    bootstrap)
      cmd_bootstrap "$@"
      ;;
    validate)
      cmd_validate "$@"
      ;;
    golden-preflight)
      cmd_golden_preflight "$@"
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      die_usage "unknown command: $command"
      ;;
  esac
}

main "$@"
