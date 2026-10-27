#!/usr/bin/env python3
"""Classify every tracked file and validate its non-destructive format contract."""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET

from tools.check_multilanguage_formatting import FROZEN_FORMAT_INPUTS
from tools.check_toolchain_env import validate_bytes

ROOT = Path(__file__).resolve().parents[1]
CPP = frozenset(
    {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".ipp", ".tpp"}
)
JS = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"})
SHELL = frozenset({".sh", ".bash"})
PLAIN = frozenset(
    {
        ".gitignore",
        ".gitattributes",
        ".github/CODEOWNERS",
        "LICENSE",
        "apps/linura-shell/security-owner/compose/LICENSE",
        "apps/linura-shell/security-owner/compose/en_US.UTF-8",
        "bindings/python/LICENSE",
        "qualification/v010/session-security/fixtures/linura-s17-qualification.pam",
        "tools/codex/container/.dockerignore",
        "tools/codex/container/ubuntu-snapshot.list",
    }
)
REQUIREMENT_LOCKS = frozenset(
    {
        "bindings/python/build-requirements.lock",
        "tools/python/ruff-requirements.lock",
        "tools/source-format/clang-requirements.lock",
    }
)
PARSER_SUFFIXES = {
    ".md": "markdown",
    ".toml": "toml",
    ".json": "json",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".xml": "xml",
    ".svg": "xml",
    ".policy": "xml",
    ".desktop": "ini",
    ".service": "ini",
    ".path": "ini",
    ".hook": "arch-hook",
    ".ini": "ini",
    ".sql": "text",
}
CONF_KINDS = {
    "apps/linura-shell/security-owner/fonts.conf": "xml",
    "packaging/arch/archiso/pacman.conf": "pacman",
    "packaging/security-owner/fonts.conf": "xml",
    "packaging/systemd/system/user@.service.d/50-linura-security-owner.conf": "ini",
    "packaging/dbus-1/system.d/org.linura.Authority1.conf": "xml",
    "packaging/dbus-1/system.d/org.linura.SecurityOwner1.conf": "xml",
    "packaging/dbus-1/system.d/org.linura.Executor.Session1.conf": "xml",
    "packaging/systemd/sleep.conf.d/50-linura-qualified-sleep.conf": "ini",
    "packaging/systemd/system/systemd-suspend.service.d/50-linura-protective-lock.conf": "ini",
    "packaging/dbus-1/system.d/org.linura.Executor.Systemd1.conf": "xml",
    "qualification/v010/session-security/fixtures/s17-hyprland.conf": "text",
    "packaging/sysusers.d/linura-authority.conf": "sysusers",
    "tests/acceptance/v05/49-linura-v05-qualification-dbus.conf": "xml",
}
POLKIT_RULES = frozenset(
    {
        "packaging/polkit-1/rules.d/50-linura-executor-session.rules",
        "packaging/polkit-1/rules.d/50-linura-executor-systemd.rules",
        "tests/acceptance/v05/49-linura-v05-qualification.rules",
        "tests/acceptance/v06/49-linura-v06-qualification.rules",
    }
)
PRETTIER_PARSERS = {"markdown", "yaml", "babel"}
EXPECTED_PRETTIER = "3.6.2"


def tracked(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--stage", "-z"],
        capture_output=True,
        check=False,
        timeout=20,
    )
    if result.returncode:
        raise ValueError("tracked inventory unavailable")
    names: set[str] = set()
    found: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            header, raw_name = raw.split(b"\t", 1)
            mode, digest, stage = header.decode("ascii").split(" ")
            name = raw_name.decode("utf-8")
        except (ValueError, UnicodeError) as error:
            raise ValueError("malformed tracked source entry") from error
        relative = PurePosixPath(name)
        if (
            mode not in {"100644", "100755"}
            or stage != "0"
            or len(digest) != 40
            or re.fullmatch(r"[0-9a-f]{40}", digest) is None
            or relative.is_absolute()
            or ".." in relative.parts
            or "." in relative.parts
            or name in names
            or relative.as_posix() != name
        ):
            raise ValueError(f"unsafe tracked source entry: {name}")
        if name == "tools/codex/versions.env" and mode != "100644":
            raise ValueError("executable tracked toolchain contract")
        names.add(name)
        candidate = root
        for part in relative.parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise ValueError(f"symlinked tracked source: {name}")
        if not candidate.is_file():
            raise ValueError(f"missing tracked source: {name}")
        found.append(Path(name))
    if not found:
        raise ValueError("empty tracked source inventory")
    return sorted(found)


def classify(path: Path, content: bytes) -> str:
    name = path.as_posix()
    if name in FROZEN_FORMAT_INPUTS:
        return "protected"
    if name in PLAIN:
        return "text"
    if name in REQUIREMENT_LOCKS:
        return "requirements-lock"
    if name == "Cargo.lock":
        return "toml"
    if name in {
        "Makefile",
        "apps/linura-shell/ui/CMakeLists.txt",
        "apps/linura-shell/bridge/CMakeLists.txt",
        "apps/linura-shell/security-owner/CMakeLists.txt",
        "apps/linura-hyprland-display/CMakeLists.txt",
        "apps/linura-hyprland-display/integration_identity.cmake",
        "qualification/v010/session-security/CMakeLists.txt",
        "tools/codex/container/Dockerfile",
    }:
        return "build"
    if name == ".clang-format" or name == "CITATION.cff":
        return "yaml"
    if name == ".editorconfig":
        return "editorconfig"
    if name == "tools/codex/versions.env":
        return "env"
    if name == "packaging/arch/archiso/packages.linura":
        return "packages"
    suffix = path.suffix.lower()
    if suffix in PARSER_SUFFIXES:
        return PARSER_SUFFIXES[suffix]
    if suffix == ".conf":
        return CONF_KINDS.get(name, "unclassified")
    if suffix == ".rules":
        return "babel" if name in POLKIT_RULES else "unclassified"
    if suffix in {".rs", ".py", ".pyi"} | CPP | JS | SHELL | {".qml", ".lua"}:
        return "formatter"
    if content.startswith(b"#!"):
        tokens = content.split(b"\n", 1)[0][2:].strip().split()
        executable = tokens[0].rsplit(b"/", 1)[-1] if tokens else b""
        if executable == b"env":
            args = tokens[1:]
            if args and args[0] == b"-S":
                args = args[1:]
            executable = args[0].rsplit(b"/", 1)[-1] if args else b""
        if executable in {b"bash", b"sh", b"dash", b"ksh", b"ash", b"mksh"}:
            return "formatter"
    return "unclassified"


def _unique_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values: dict[str, object] = {}
    for key, value in pairs:
        if key in values:
            raise ValueError(f"duplicate JSON object key: {key}")
        values[key] = value
    return values


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def format_errors(path: Path, content: bytes, kind: str) -> list[str]:
    errors: list[str] = []
    label = path.as_posix()
    if (
        b"\0" in content
        or b"\r" in content
        or (content and not content.endswith(b"\n"))
    ):
        errors.append(f"{label}: invalid text framing (NUL/CR/final newline)")
    try:
        text = content.decode("utf-8")
    except UnicodeError:
        return errors + [f"{label}: invalid UTF-8"]
    try:
        if kind == "protected":
            expected = FROZEN_FORMAT_INPUTS[label]
            if hashlib.sha256(content).hexdigest() != expected:
                errors.append(f"{label}: immutable source digest changed")
        elif kind == "toml":
            tomllib.loads(text)
        elif kind == "json":
            json.loads(
                text,
                object_pairs_hook=_unique_json_pairs,
                parse_constant=_reject_json_constant,
            )
        elif kind == "xml":
            ET.fromstring(content)
        elif kind in {"ini", "editorconfig", "pacman", "arch-hook"}:
            section = "__root__" if kind == "editorconfig" else None
            seen: set[tuple[str, str]] = set()
            section_names: set[str] = set()
            for number, physical_line in enumerate(text.splitlines(), 1):
                statement = physical_line.strip()
                if not statement or statement.startswith(("#", ";")):
                    continue
                if physical_line.startswith((" ", "\t")):
                    raise ValueError(f"indented directive at line {number}")
                if statement.startswith("[") and statement.endswith("]"):
                    section = statement[1:-1]
                    if not section or section in section_names:
                        raise ValueError(f"empty or duplicate section at line {number}")
                    section_names.add(section)
                    continue
                if section is None:
                    raise ValueError(f"missing section at line {number}")
                if "=" in statement:
                    name, _ = statement.split("=", 1)
                    name = name.strip()
                    if re.fullmatch(r"[A-Za-z0-9_.-]+", name) is None:
                        raise ValueError(f"invalid assignment at line {number}")
                    entry = (section, name.lower())
                    repeated_unit_field = (
                        (
                            path.suffix == ".service"
                            and kind == "ini"
                            and section == "Service"
                            and name in {"Environment", "LoadCredential"}
                        )
                        or (
                            path.suffix == ".path"
                            and kind == "ini"
                            and section == "Path"
                            and name == "PathExistsGlob"
                        )
                        or (
                            kind == "arch-hook"
                            and section == "Trigger"
                            and name in {"Operation", "Target"}
                        )
                    )
                    if entry in seen and not repeated_unit_field:
                        raise ValueError(f"duplicate directive at line {number}")
                    seen.add(entry)
                    continue
                if kind == "pacman" and statement in {"CheckSpace", "Color"}:
                    continue
                if (
                    kind == "arch-hook"
                    and section == "Action"
                    and statement == "AbortOnFail"
                ):
                    continue
                raise ValueError(f"valueless directive at line {number}")
            parser = configparser.ConfigParser(
                interpolation=None,
                strict=False,
                allow_no_value=kind in {"pacman", "arch-hook"},
                delimiters=("=",),
                inline_comment_prefixes=None,
            )
            parser.read_string(
                "[__root__]\n" + text if kind == "editorconfig" else text
            )
            if kind == "arch-hook":
                for section in parser.sections():
                    for option, value in parser.items(section, raw=True):
                        if value is None and not (
                            section == "Action" and option == "abortonfail"
                        ):
                            raise ValueError("unsupported bare Arch hook directive")
        elif kind == "sysusers":
            entries = [
                shlex.split(line, comments=True, posix=True)
                for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            if (
                len(entries) != 1
                or len(entries[0]) != 6
                or entries[0][0] != "u"
                or entries[0][1] != "linura-authority"
                or entries[0][2] != "-"
                or entries[0][4] != "/var/lib/linura-authority"
                or entries[0][5] != "/usr/sbin/nologin"
            ):
                raise ValueError("invalid reviewed sysusers user declaration")
        elif kind == "env":
            validate_bytes(content)
        elif kind == "packages":
            items = [
                line for line in text.splitlines() if line and not line.startswith("#")
            ]
            if len(items) != len(set(items)) or any(
                re.fullmatch(r"[a-z0-9@._+-]+", item) is None for item in items
            ):
                raise ValueError("invalid or duplicate package")
        elif kind == "unclassified":
            errors.append(f"{label}: unclassified tracked format (fail closed)")
    except (ValueError, configparser.Error, ET.ParseError) as error:
        errors.append(f"{label}: invalid {kind}: {error}")
    return errors


def prettier_errors(root: Path, binary: str, files: list[Path], kind: str) -> list[str]:
    if not files:
        return []
    # Parse only. Legacy docs/contract bytes must not be silently rewritten.
    command = [
        binary,
        "--parser",
        kind,
        "--config=.prettierrc.json",
        "--ignore-path=/dev/null",
        "--with-node-modules",
        "--",
        *(f"./{path.as_posix()}" for path in files),
    ]
    result = subprocess.run(
        command,
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=180,
    )
    if result.returncode:
        return [
            f"{kind}: pinned Prettier parser rejected tracked inputs: {result.stderr[:1800]}"
        ]
    return []


def check(root: Path = ROOT, prettier: str | None = None) -> list[str]:
    errors: list[str] = []
    groups: dict[str, list[Path]] = {kind: [] for kind in PRETTIER_PARSERS}
    inventory = tracked(root)
    for path in inventory:
        content = (root / path).read_bytes()
        kind = classify(path, content)
        errors.extend(format_errors(path, content, kind))
        if kind in groups:
            groups[kind].append(path)
    if prettier is None:
        errors.append("pinned Prettier 3.6.2 executable required")
        return errors
    executable = shutil.which(prettier)
    if executable is None:
        errors.append("pinned Prettier unavailable")
        return errors
    version = subprocess.run(
        [executable, "--version"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    if version.returncode or version.stdout.strip() != EXPECTED_PRETTIER:
        errors.append("pinned Prettier version mismatch")
        return errors
    for kind in sorted(groups):
        errors.extend(prettier_errors(root, executable, groups[kind], kind))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prettier", default="prettier")
    args = parser.parse_args()
    try:
        failures = check(ROOT, args.prettier)
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"tracked-format contract denied: {error}", file=sys.stderr)
        return 1
    for failure in failures:
        print(f"tracked-format contract denied: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("every tracked file classified; protected and structured format gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
