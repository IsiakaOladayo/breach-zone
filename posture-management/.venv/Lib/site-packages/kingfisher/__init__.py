"""Python wrapper for the bundled Kingfisher binary."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

from ._version import __version__


def _binary_name() -> str:
    return "kingfisher.exe" if sys.platform == "win32" else "kingfisher"


def get_binary_path() -> str:
    """Return the path to the bundled Kingfisher binary."""
    binary = Path(__file__).resolve().parent / "bin" / _binary_name()

    if not binary.exists():
        raise FileNotFoundError(
            "Kingfisher binary not found. "
            "This wheel may not match your platform."
        )

    if sys.platform != "win32":
        current_mode = binary.stat().st_mode
        if not (current_mode & stat.S_IXUSR):
            binary.chmod(
                current_mode
                | stat.S_IXUSR
                | stat.S_IXGRP
                | stat.S_IXOTH
            )

    return os.fspath(binary)


def main() -> None:
    """Execute the bundled Kingfisher binary."""
    binary = get_binary_path()

    if sys.platform == "win32":
        raise SystemExit(subprocess.call([binary, *sys.argv[1:]]))

    os.execvp(binary, [binary, *sys.argv[1:]])
