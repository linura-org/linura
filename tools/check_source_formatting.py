#!/usr/bin/env python3
"""Enforce repository-wide source-text invariants on tracked language files."""

from __future__ import annotations

from pathlib import Path
import io
import subprocess
import sys
import tokenize

ROOT = Path(__file__).resolve().parents[1]
SOURCE_EXTENSIONS = frozenset(
    {
        ".rs",
        ".py",
        ".pyi",
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
        ".js",
        ".mjs",
        ".cjs",
        ".jsx",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
        ".bash",
        ".zsh",
        ".ksh",
        ".cxx",
        ".hxx",
        ".hh",
        ".cmake",
        ".qml",
        ".lua",
        ".sh",
    }
)
SOURCE_NAMES = frozenset({"CMakeLists.txt"})
EXTENSIONLESS_SHELL = frozenset(
    {
        "qualification/v010/shell-runtime/fixtures/forking-app",
        "qualification/v010/shell-runtime/fixtures/linger-app",
    }
)


def has_symlink_component(relative: Path, root: Path) -> bool:
    path = root
    for component in relative.parts:
        path /= component
        if path.is_symlink():
            return True
    return False


def is_shebang_source(relative: Path, root: Path) -> bool:
    if relative.as_posix() in EXTENSIONLESS_SHELL:
        return True
    if has_symlink_component(relative, root):
        return True
    candidate = root / relative
    if not candidate.is_file():
        return False
    with candidate.open("rb") as source:
        return source.readline(256).startswith(b"#!")


def check(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached"],
        check=False,
        capture_output=True,
        timeout=20,
    )
    if result.returncode:
        return ["could not inventory the tracked source files"]
    try:
        names = result.stdout.decode("utf-8").split("\0")
    except UnicodeDecodeError:
        return ["non-UTF-8 tracked filename"]

    errors: list[str] = []
    for name in sorted(filter(None, names)):
        relative = Path(name)
        suffix = relative.suffix.lower()
        if (
            suffix not in SOURCE_EXTENSIONS
            and relative.name not in SOURCE_NAMES
            and not is_shebang_source(relative, root)
        ):
            continue
        candidate = root / relative
        if has_symlink_component(relative, root) or not candidate.is_file():
            errors.append(f"{name}: missing, symlinked or non-regular source")
            continue
        content = candidate.read_bytes()
        if b"\0" in content:
            errors.append(f"{name}: NUL byte in source")
        if b"\r" in content:
            errors.append(f"{name}: non-LF line ending")
        if content and not content.endswith(b"\n"):
            errors.append(f"{name}: missing final newline")
        literal_lines: set[int] = set()
        if suffix in (".py", ".pyi"):
            try:
                for token in tokenize.generate_tokens(
                    io.StringIO(content.decode("utf-8")).readline
                ):
                    if token.type == tokenize.STRING and token.start[0] < token.end[0]:
                        literal_lines.update(range(token.start[0], token.end[0]))
            except (UnicodeDecodeError, tokenize.TokenError):
                errors.append(f"{name}: invalid Python source encoding or tokenization")
        for line, value in enumerate(content.split(b"\n"), start=1):
            if line not in literal_lines and value.endswith((b" ", b"\t")):
                errors.append(f"{name}:{line}: trailing whitespace")
            if b"\t" in value:
                errors.append(f"{name}:{line}: tab indentation/content")
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{name}: non-UTF-8 source bytes")
    return errors


def main() -> int:
    errors = check(ROOT)
    if errors:
        for error in errors:
            print(f"source formatting: {error}", file=sys.stderr)
        return 1
    print("tracked language source formatting invariants passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
