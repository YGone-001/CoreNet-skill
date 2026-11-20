#!/usr/bin/env python3
"""Create an owner-only local HMAC endpoint key without printing it.

The utility writes exactly 32 random bytes with exclusive creation and POSIX
0600 permissions. It never overwrites an existing file and refuses output
paths inside the current repository.
"""

from __future__ import annotations

import argparse
import os
import secrets
import stat
import sys
from pathlib import Path

KEY_SIZE = 32
KEY_MODE = 0o600


def _repository_root(start: Path) -> Path | None:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
    except ValueError:
        return False
    return True


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--output", type=Path, required=True, help="new key file path")
    result.add_argument(
        "--force",
        action="store_true",
        help="ignored compatibility flag; existing keys are never overwritten",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    destination = args.output
    root = _repository_root(Path(__file__).resolve().parent)
    if root is not None and _inside(destination, root):
        print(
            "create-endpoint-key: refusing to write a key inside the repository",
            file=sys.stderr,
        )
        return 2
    if destination.exists():
        print(
            "create-endpoint-key: output already exists; refusing to overwrite",
            file=sys.stderr,
        )
        return 2
    if not destination.parent.is_dir():
        print(
            "create-endpoint-key: output directory does not exist",
            file=sys.stderr,
        )
        return 2
    descriptor: int | None = None
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            KEY_MODE,
        )
        material = secrets.token_bytes(KEY_SIZE)
        written = 0
        while written < KEY_SIZE:
            written += os.write(descriptor, material[written:])
        os.close(descriptor)
        descriptor = None
        if os.name == "posix":
            os.chmod(destination, KEY_MODE)
            mode = stat.S_IMODE(destination.stat().st_mode)
            if mode != KEY_MODE:
                raise OSError("key file permissions are not owner-only")
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        destination.unlink(missing_ok=True)
        print(f"create-endpoint-key: {exc}", file=sys.stderr)
        return 3
    print(f"created endpoint key: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())