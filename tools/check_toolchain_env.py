#!/usr/bin/env python3
"""Deny executable shell content in repository-owned toolchain assignments."""

from __future__ import annotations

from pathlib import Path
import re
import sys

SHARED_SEMVER_KEYS = frozenset(
    {
        "RUSTUP_VERSION",
        "RUST_VERSION",
        "CARGO_AUDIT_VERSION",
        "ACTIONLINT_VERSION",
        "RUFF_VERSION",
        "PYTHON_RELEASE",
        "PYTHON_PIP_VERSION",
    }
)
SHARED_DIGEST_KEYS = frozenset({"RUSTUP_INIT_SHA256", "ACTIONLINT_SHA256"})
NATIVE_KEYS = frozenset(
    {
        "NATIVE_PYTHON_RELEASE",
        "NATIVE_PYTHON_SHA256",
        "NATIVE_NODE_VERSION",
        "NATIVE_NODE_SHA256",
    }
)
SHARED_KEYS = (
    SHARED_SEMVER_KEYS
    | SHARED_DIGEST_KEYS
    | frozenset({"PYTHON_MAJOR_MINOR", "HOST_OS", "HOST_ARCH"})
)
SEMVER_KEYS = SHARED_SEMVER_KEYS | {"NATIVE_PYTHON_RELEASE", "NATIVE_NODE_VERSION"}
DIGEST_KEYS = SHARED_DIGEST_KEYS | {"NATIVE_PYTHON_SHA256", "NATIVE_NODE_SHA256"}
EXPECTED_KEYS = SHARED_KEYS | NATIVE_KEYS
PATTERNS = {
    **dict.fromkeys(SEMVER_KEYS, re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")),
    **dict.fromkeys(DIGEST_KEYS, re.compile(r"[0-9a-f]{64}")),
    "PYTHON_MAJOR_MINOR": re.compile(r"[0-9]+\.[0-9]+"),
    "HOST_OS": re.compile(r"Linux"),
    "HOST_ARCH": re.compile(r"x86_64"),
}


def validate_bytes(raw: bytes) -> dict[str, str]:
    if b"\0" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        raise ValueError("invalid toolchain contract byte framing")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as error:
        raise ValueError("toolchain contract must be ASCII") from error
    values: dict[str, str] = {}
    for number, line in enumerate(lines, 1):
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=([A-Za-z0-9_.-]+)", line)
        if match is None:
            raise ValueError(f"unsafe toolchain assignment at line {number}")
        key, value = match.groups()
        if key not in PATTERNS or key in values:
            raise ValueError(f"unknown or duplicate toolchain key at line {number}")
        if PATTERNS[key].fullmatch(value) is None:
            raise ValueError(f"invalid toolchain value for {key}")
        values[key] = value
    if values.keys() != EXPECTED_KEYS:
        raise ValueError("missing or unexpected toolchain assignments")
    return values


def validate(source: Path) -> dict[str, str]:
    for component in (source, *source.parents):
        if component.is_symlink():
            raise ValueError("symlinked toolchain contract")
    if not source.is_file():
        raise ValueError("missing toolchain contract")
    if source.stat().st_mode & 0o111:
        raise ValueError("executable toolchain contract")
    return validate_bytes(source.read_bytes())


# --values is the shared bootstrap/workflow projection. Native-only pins are
# validated by every consumer but do not enter unrelated workflow read arrays.
TOOLCHAIN_FIELDS = tuple(sorted(SHARED_KEYS))


def main() -> int:
    emit_values = len(sys.argv) == 3 and sys.argv[1] == "--values"
    read_version = len(sys.argv) == 2 and sys.argv[1] == "--rust-version"
    read_ruff = len(sys.argv) == 2 and sys.argv[1] == "--ruff-version"
    if not (
        emit_values
        or read_version
        or read_ruff
        or (len(sys.argv) == 2 and not sys.argv[1].startswith("--"))
    ):
        print(
            "usage: check_toolchain_env.py PATH | --rust-version | --ruff-version | --values PATH",
            file=sys.stderr,
        )
        return 2
    source = (
        Path("tools/codex/versions.env")
        if (read_version or read_ruff)
        else Path(sys.argv[-1])
    )
    try:
        values = validate(source)
    except (OSError, ValueError) as error:
        print(f"unsafe toolchain contract: {error}", file=sys.stderr)
        return 1
    if read_version:
        print(values["RUST_VERSION"])
    elif read_ruff:
        print(values["RUFF_VERSION"])
    elif emit_values:
        print(" ".join(values[key] for key in TOOLCHAIN_FIELDS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
