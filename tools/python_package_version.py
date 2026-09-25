#!/usr/bin/env python3
from __future__ import annotations

import re

_VERSION_RE = re.compile(
    r"""
    ^\s*
    v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:
        [-_.]?
        (?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)
        [-_.]?
        (?P<pre_n>[0-9]+)?
    )?
    (?:
        (?P<post_n1>-[0-9]+)
        |
        (?:
            [-_.]?
            (?P<post_l>post|rev|r)
            [-_.]?
            (?P<post_n2>[0-9]+)?
        )
    )?
    (?:
        [-_.]?
        (?P<dev_l>dev)
        [-_.]?
        (?P<dev_n>[0-9]+)?
    )?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$
    """,
    re.IGNORECASE | re.VERBOSE,
)

_PRE_LABELS = {
    "alpha": "a",
    "a": "a",
    "beta": "b",
    "b": "b",
    "preview": "rc",
    "pre": "rc",
    "c": "rc",
    "rc": "rc",
}


class Pep440VersionError(ValueError):
    pass


def normalize_pep440(version: str) -> str:
    """Return the canonical public/local spelling for a PEP 440 version."""

    if not isinstance(version, str) or not version:
        raise Pep440VersionError("version must be a non-empty string")

    match = _VERSION_RE.fullmatch(version)
    if match is None:
        raise Pep440VersionError(f"invalid PEP 440 version: {version!r}")

    parts: list[str] = []
    epoch = int(match.group("epoch") or "0")
    if epoch:
        parts.append(f"{epoch}!")

    release = ".".join(str(int(piece)) for piece in match.group("release").split("."))
    parts.append(release)

    pre_l = match.group("pre_l")
    if pre_l is not None:
        label = _PRE_LABELS[pre_l.lower()]
        number = int(match.group("pre_n") or "0")
        parts.append(f"{label}{number}")

    post_n1 = match.group("post_n1")
    post_l = match.group("post_l")
    if post_n1 is not None:
        parts.append(f".post{int(post_n1[1:])}")
    elif post_l is not None:
        parts.append(f".post{int(match.group('post_n2') or '0')}")

    if match.group("dev_l") is not None:
        parts.append(f".dev{int(match.group('dev_n') or '0')}")

    local = match.group("local")
    if local is not None:
        normalized_local = ".".join(
            str(int(piece)) if piece.isdigit() else piece.lower()
            for piece in re.split(r"[-_.]", local)
        )
        parts.append(f"+{normalized_local}")

    return "".join(parts)


def wheel_version(version: str) -> str:
    """Return the normalized PEP 440 version field for a wheel filename.

    Current wheel filename rules normalize the version according to PEP 440.
    Canonical PEP 440 versions contain no hyphen, so epoch (!) and local (+)
    separators must be preserved rather than escaped.
    """

    return normalize_pep440(version)


__all__ = ["Pep440VersionError", "normalize_pep440", "wheel_version"]
