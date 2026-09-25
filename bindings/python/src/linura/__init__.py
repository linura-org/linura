"""Canonical Python entry point for Linura.

The initial package deliberately exposes only stable project metadata,
Control1 transport identifiers, and local installation discovery. It does not
reimplement Linura authority, policy, provider, executor, or persistence logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
from typing import Final

__version__ = "0.0.1"

NAME: Final = "Linura"
HOMEPAGE: Final = "https://linura.org"
REPOSITORY: Final = "https://github.com/linura-org/linura"

CONTROL1_SERVICE: Final = "org.linura.Control1"
CONTROL1_OBJECT_PATH: Final = "/org/linura/Control1"
CONTROL1_INTERFACE: Final = "org.linura.Control1"
CONTROL1_CONTRACT_VERSION: Final = 1
CONTROL1_STABILITY: Final = "experimental"


class LinuraNotInstalledError(RuntimeError):
    """Raised when the local Linura CLI cannot be discovered."""


@dataclass(frozen=True, slots=True)
class Installation:
    """A discovered local Linura installation."""

    linuractl: Path


def find_installation(*, path: str | None = None) -> Installation | None:
    """Discover ``linuractl`` without executing it.

    ``path`` follows ``shutil.which`` semantics and is useful for callers that
    intentionally constrain executable discovery.
    """

    executable = shutil.which("linuractl", path=path)
    if executable is None:
        return None
    return Installation(linuractl=Path(executable))


def require_installation(*, path: str | None = None) -> Installation:
    """Return the local Linura installation or fail explicitly."""

    installation = find_installation(path=path)
    if installation is None:
        raise LinuraNotInstalledError("linuractl was not found on PATH")
    return installation


__all__ = [
    "CONTROL1_CONTRACT_VERSION",
    "CONTROL1_INTERFACE",
    "CONTROL1_OBJECT_PATH",
    "CONTROL1_SERVICE",
    "CONTROL1_STABILITY",
    "HOMEPAGE",
    "Installation",
    "LinuraNotInstalledError",
    "NAME",
    "REPOSITORY",
    "__version__",
    "find_installation",
    "require_installation",
]
