# Ubuntu Development Environment

This guide describes a small, reproducible developer workflow for CoreNet Skill
on Ubuntu 24.04. It covers environment diagnosis, local bootstrap, one-command
repository validation, and a read-only readiness check for the external Golden
Capture corpus.

The helper entry point is:

```bash
./scripts/dev.sh doctor
./scripts/dev.sh bootstrap
./scripts/dev.sh validate
./scripts/dev.sh golden-preflight --source-root /path/to/external/corpus
```

The script resolves the repository root from its own location, so it can be
invoked from any working directory.

## Supported Operating System

| Item | Expected value |
| --- | --- |
| Operating system | Ubuntu 24.04 LTS (Noble) |
| Architecture | x86_64 |
| Python | 3.12.x |
| Bash | 4.x or newer (Ubuntu ships 5.x) |
| Git | 2.x |
| Golden Capture decoder | TShark 4.7.1 exactly |

Other Linux distributions may run the Python validation steps, but
`bootstrap --install-os-deps` is intentionally limited to Ubuntu 24.04. The
helper reports the detected platform and never silently changes system
configuration.

## Required System Resources

- 2 CPU cores or more.
- 2 GiB free RAM or more.
- 2 GiB free disk for the checkout, Python virtual environment, and test
  temporary directories.
- No inbound network services are required.

## Python 3.12 Expectations

Repository validators and unit tests run on Python 3.12 and use only the
Python standard library. No PyPI dependency is required or installed by the
helper.

Checks performed for Python:

- the `python3` executable is present and reports a `3.12.x` version;
- `venv` support is available (`python3 -m venv`);
- the standard-library modules used by validators and tests are importable.

A different Python series is reported as blocked. The helper never installs
Python packages globally and never uses `pip --break-system-packages`.

## Required and Optional Dependencies

Required for standard repository work:

| Dependency | Purpose |
| --- | --- |
| Python 3.12 | Validators and unit tests |
| Python `venv` | Optional isolated local interpreter |
| Git | Clone, status, and whitespace checks |
| Bash | Runs `scripts/dev.sh` |

Optional, only for external Golden Capture corpus reproduction:

| Dependency | Purpose |
| --- | --- |
| TShark 4.7.1 exactly | Pinned packet decoder used by the frozen benchmark run |
| External capture corpus checkout | Public captures, pinned at a specific commit |
| External working directory | Intermediate pipeline artifacts outside this repository |

A missing or different TShark version does **not** prevent standard repository
unit tests from running. Those tests do not use the pinned decoder.

## Environment Diagnostic Commands

```bash
./scripts/dev.sh doctor
```

`doctor` is read-only. It reports the detected platform, architecture, Python
version, Git and Bash availability, Python `venv` support, required
standard-library modules, repository root resolution, Git worktree status, and
TShark availability and version.

Environment status values:

| Status | Meaning |
| --- | --- |
| `READY` | Essential prerequisites are satisfied and the Golden Capture decoder matches 4.7.1 |
| `READY_WITH_LIMITATIONS` | Standard repository work is possible; optional Golden Capture reproduction tools are missing or differ |
| `BLOCKED` | An essential prerequisite is missing or wrong |

`doctor` exits `0` for `READY` and `READY_WITH_LIMITATIONS`, and `3` for
`BLOCKED`.

## Bootstrap Commands

```bash
./scripts/dev.sh bootstrap
```

Default bootstrap does not require root privileges. It:

1. Confirms Ubuntu 24.04 compatibility and reports the actual platform.
2. Confirms Python 3.12 and required tools.
3. Confirms Python `venv` support and required standard-library modules.
4. Creates the ignored repository-local virtual environment `.venv/` only when
   that directory is missing.
5. Preserves an existing compatible virtual environment instead of recreating
   it.
6. Prints missing-dependency instructions instead of silently installing
   anything.

Repeating `bootstrap` is safe: a healthy `.venv/` is preserved, tracked files
are not modified, Git remotes and credentials are untouched, and caches are not
deleted. If `.venv/` exists but uses a different Python series, bootstrap fails
with instructions and refuses to delete it.

### Explicit System Package Installation

```bash
./scripts/dev.sh bootstrap --install-os-deps
```

This optional mode is the only way the helper installs operating-system
packages. Requirements and behavior:

- Ubuntu 24.04 only; other platforms are rejected.
- The package list is printed before any installation.
- Packages are installed with Ubuntu APT.
- Installation errors fail the command.
- No unrelated operating-system upgrades are performed.
- APT sources are not modified.
- No telecom daemons or unrelated services are installed.
- TShark is deliberately **not** installed or upgraded here, because a
  distribution package would replace the pinned 4.7.1 decoder.

Default package list: `python3`, `python3-venv`, `git`.

Preview without changing the system:

```bash
./scripts/dev.sh bootstrap --install-os-deps --dry-run
```

## One-Command Repository Validation

```bash
./scripts/dev.sh validate
```

This reproduces the validation intent of `.github/workflows/validate.yml`
locally. It stops at the first failing gate, prints that gate's name, and
preserves the failing command's exit code.

Execution order:

1. All repository validators, in the same order as the CI workflow, including
   repository contract, architecture, upstream snapshots, Foundation Skills,
   protocol and domain package validators, failure-boundary orchestration, and
   Golden Capture benchmark validation.
2. Golden Capture unit tests
   (`benchmarks/golden-captures/tests`, pattern `test_*.py`).
3. Repository root unit tests (`tests`, pattern `test_*.py`).
4. `python3 -m compileall` over the same script directories compiled by CI.
5. A read-only `git diff --check` whitespace check.

The command records the actual number of tests executed from the unittest
summary. Totals are never hardcoded. Skipped tests remain skipped and are not
counted as passed.

Validation runs entirely offline. No network access is required.

### Relationship to GitHub Actions

| Aspect | GitHub Actions | `./scripts/dev.sh validate` |
| --- | --- | --- |
| Workflow | `.github/workflows/validate.yml` | Same command sequence |
| Checkout | `actions/checkout` | Local working tree |
| Python setup | `actions/setup-python` with 3.12 | Host `python3` 3.12 |
| Interpreter name | `python` | `python3` |
| Whitespace check | `git diff --check HEAD^ HEAD` | `git diff --check` |
| Network | Runner bootstrap only | None required |

Both environments must run Python 3.12 and the same validators and unittest
discovery roots. Byte-for-byte environment parity is not claimed: the GitHub
runner installs its own toolchain, and the two whitespace checks look at
different revision ranges. Passing local validation does not replace the
remote workflow; both are expected to succeed on the same commit.

## Three Distinct Validation Levels

These levels are not interchangeable:

| Level | Command | What it proves |
| --- | --- | --- |
| Standard repository validation | `./scripts/dev.sh validate` | Contracts, schemas, Skill package rules, unit tests, and script compilation on Python 3.12 |
| Golden Capture unit tests | included in `validate`, or `python3 -m unittest discover -s benchmarks/golden-captures/tests -p 'test_*.py' -v` | Benchmark comparator, sanitizer, hashing, and governance logic |
| Full external PCAP corpus reproduction | existing benchmark runner, separate authorization | Skill pipeline output versus frozen human baselines on the public capture corpus |

Passing standard repository tests does **not** prove compatibility with the
full external capture corpus. That comparison requires TShark 4.7.1, the
pinned external corpus checkout, and a separately authorized benchmark run.

## Golden Capture Preflight

```bash
./scripts/dev.sh golden-preflight --source-root /path/to/external/corpus
```

Optional destinations can also be checked:

```bash
./scripts/dev.sh golden-preflight \
  --source-root /path/to/external/corpus \
  --work-root /path/to/external/work \
  --output-root /path/to/external/output
```

Preflight is read-only. It never runs the capture pipeline, never writes
Golden Capture outputs, never downloads captures, and never stages generated
artifacts.

Checks performed:

1. TShark executable is present.
2. TShark version is exactly the accepted `4.7.1` baseline. A different
   version is rejected; no substitution is performed.
3. `--source-root` is supplied explicitly.
4. The external capture repository exists and is a Git checkout.
5. The external source `HEAD` matches the pinned corpus commit
   `82934c2cc231540fa425e48177d4bed33210bfc1`.
6. Expected corpus metadata and capture files exist, and each capture matches
   the committed SHA-256 and size.
7. Case metadata in `benchmarks/golden-captures/cases/` references captures
   that exist under the supplied corpus root.
8. No capture path, work directory, or output directory points inside the
   CoreNet Skill repository.

Paths are never hardcoded. Every external location must be provided by the
developer.

Full corpus reproduction remains governed by the existing benchmark runner and
its separate authorization. Preflight only answers "is this host and corpus
prepared?".

## TShark Version Compatibility

The frozen Golden Capture records were produced with TShark 4.7.1. Decoder
output is not stable across major Wireshark releases: field availability,
dissection trees, and error behavior can change.

Rules:

- `golden-preflight` accepts exactly version `4.7.1`.
- The helper never installs, upgrades, or replaces TShark.
- Distribution packages (for example Ubuntu's packaged Wireshark) are usually a
  different version and must not be swapped in for the pinned decoder.
- Standard repository unit tests do not require TShark.

If the host carries another TShark build, keep that installation intact and
arrange a separate 4.7.1 toolchain only when external corpus reproduction is
actually authorized.

## Offline Behavior

- `doctor`, `bootstrap`, and `validate` perform no network requests.
- `bootstrap --install-os-deps` uses APT and therefore needs access to Ubuntu
  package mirrors; that mode is explicit and optional.
- `golden-preflight` only inspects a local checkout. It never clones or
  downloads captures.
- Virtual environment creation uses the local interpreter and does not fetch
  packages.

## Common Installation and Permission Problems

| Symptom | Likely cause | Resolution |
| --- | --- | --- |
| `Python 3.12.x is required` | Default `python3` is another series | Install Python 3.12 and ensure `python3` resolves to it |
| `Python venv support is unavailable` | `python3-venv` is missing | `./scripts/dev.sh bootstrap --install-os-deps`, or install `python3-venv` manually |
| `Git is unavailable` | Git is not installed | Install `git`, or run `bootstrap --install-os-deps` |
| `existing virtual environment ... uses Python ...` | `.venv/` was created with another interpreter | Remove `.venv/` manually if it is no longer needed; the helper will not delete it |
| `TShark version mismatch` | Decoder is not 4.7.1 | Keep the current decoder; use a separate 4.7.1 toolchain for authorized corpus work |
| `--source-root must be outside the CoreNet Skill repository` | Corpus path is inside the checkout | Move or clone the corpus outside the repository |
| `external corpus commit mismatch` | Corpus checkout is at another revision | Check out commit `82934c2cc231540fa425e48177d4bed33210bfc1` |
| `system package installation failed` | APT error or missing privileges | Read the APT output; install the listed packages manually |
| `sudo is required to install system packages` | Non-root without `sudo` | Re-run with privileges, or install the listed packages manually |
| Permission denied on `./scripts/dev.sh` | Execute bit missing | `chmod +x scripts/dev.sh` |
| `corpus metadata and capture verification failed` | Missing or altered captures | Restore the pinned corpus; digests must match the committed metadata |

## Expected Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success. `doctor` reporting `READY` or `READY_WITH_LIMITATIONS` is success |
| `1` | A check, gate, or preflight condition failed |
| `2` | Usage error: unknown command, missing argument, or invalid option |
| `3` | Environment blocked: an essential prerequisite is missing or wrong |
| other | `validate` propagates the failing command's own exit code and names the failed gate |

Examples:

```bash
./scripts/dev.sh doctor
echo $?    # 0 when READY or READY_WITH_LIMITATIONS

./scripts/dev.sh frobnicate
echo $?    # 2 usage error

./scripts/dev.sh golden-preflight
echo $?    # 2 missing --source-root
```

## Windows VS Code Remote SSH with an Ubuntu VM

Developers on Windows can keep the repository on an Ubuntu 24.04 virtual
machine and connect with VS Code Remote - SSH.

Recommended setup:

1. Create an Ubuntu 24.04 VM on x86_64 and enable OpenSSH server.
2. From Windows, connect to the VM with VS Code Remote - SSH.
3. Open the repository folder inside the VM filesystem (for example under the
   user's home directory). Avoid editing the checkout over a Windows network
   share; mixed line endings and slower I/O cause unnecessary diffs.
4. Run `./scripts/dev.sh doctor` in the integrated terminal, which executes
   inside the VM.
5. Run `./scripts/dev.sh bootstrap`, then `./scripts/dev.sh validate`.
6. Use the same terminal workflow for `golden-preflight` when external corpus
   work is authorized.

Notes for this workflow:

- Git commits should be created inside the VM so file modes and line endings
  stay consistent. The repository already forces LF endings for `*.sh`.
- Do not run Python validators from a Windows shell against a VM copy of the
  tree; run them in the Ubuntu guest.
- The helper never prints secrets, never modifies Git remotes or credentials,
  and never writes generated output into tracked Skill directories.
- If the VM is cloned or restored from a snapshot, re-run `./scripts/dev.sh
  doctor` before trusting the environment.

## Security and Operational Safety

The helper is intentionally conservative:

- it does not print environment secrets or subscriber data;
- it does not execute downloaded scripts;
- it does not delete arbitrary filesystem paths;
- it does not evaluate untrusted shell input;
- path arguments are quoted and validated;
- unsafe or missing required arguments are rejected;
- Git remotes and credentials are never modified;
- generated files are not written into tracked Skill directories;
- optional external working data stays outside this repository;
- file ownership and permissions are not changed outside authorized local
  files;
- no background service or monitoring daemon is installed.

## Helper File Inventory

| Path | Role |
| --- | --- |
| `scripts/dev.sh` | Developer entry point: `doctor`, `bootstrap`, `validate`, `golden-preflight` |
| `docs/DEVELOPMENT-UBUNTU.md` | This guide |
| `tests/structure/test_dev_environment.py` | Deterministic tests for the helper |

Test-only injection overrides (not needed in normal development):
`CORENET_DEV_OS_RELEASE_FILE`, `CORENET_DEV_PYTHON`, `CORENET_DEV_GIT`,
`CORENET_DEV_TSHARK`, `CORENET_DEV_APT_GET`, `CORENET_DEV_SUDO`,
`CORENET_DEV_UNAME_M`, `CORENET_DEV_VENV_DIR`. They exist so unit tests can
exercise unsupported platforms, missing tools, wrong versions, and APT
failures without touching the host. Production use should leave them unset.
