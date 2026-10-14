#!/usr/bin/env python3
"""Check pinned, deterministic language formatters without mutating tracked source."""

from __future__ import annotations

from pathlib import Path
import hashlib
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CPP = frozenset(
    {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".ipp", ".tpp"}
)
JS = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"})
PRETTIER_CONFIG = (
    ".prettierrc.json",
    "tools/source-format/package.json",
    "tools/source-format/package-lock.json",
)
FROZEN_FORMAT_INPUTS = {
    # Existing byte-sensitive QML contract exception from #219. S17 reviews the
    # exact native-unmap change and its stronger removal/callback-count tests;
    # no additional file or pattern is exempted from pinned formatting.
    "apps/linura-shell/tray/SystemTrayView.qml": "e58bba825d7a73ed1668f31bf6db1c5ac3f08d9f22107d25f09b0ae2eb6ff38e",
    "apps/linura-shell/plugins/notifications-osd/LifecycleFeedback.qml": "6edc749d07c6b1f22bc5915665dc17c2c2c66b4d6d6ec32b1893a92ef171fe78",
    "apps/linura-shell/plugins/quick-settings/QuickSettingsPanel.qml": "154ac33fa33424e630b181c0fb5cb28df07d4fd347e635d76e1eebcdc95b83ef",
    "apps/linura-shell/plugins/command-palette/CommandPalette.qml": "86b7300c6763d2101cf1e5dcd56147b4d9ca5afd8f352db0aabcfbb2e6229631",
    "apps/linura-shell/integrations/hyprland/WorkspaceNavigationController.qml": "79ea195e5a03ef9f3e27d30ec7e49e7d2d8b79d97a9786175180468d6664e964",
    "apps/linura-shell/shell.qml": "5ae841bb1899ecb5bc60468bf6ce7fb85e9c850debdc726d4b29e64521765507",
    "apps/linura-shell/ui/LinuraDialog.qml": "38eea04373ee6e529d4caaf8d8b9f2bd5a87429cd794a93dbba88b006d461196",
    "apps/linura-shell/bridge/audio_session_controller.cpp": "8d2ccee988dfff9b55f690954fff0a4628967580be21dbadd2d4bb0b9b4229b5",
    "apps/linura-shell/bridge/audio_session_controller.h": "ad34a06d80726946c583c0bab2db3e9aa7fecb49aa2900d29584f87b5b1cffae",
    "packaging/wireplumber/linura-session-audio.lua": "a63caddb8df6cd8584c355f7fb289b08abe09eca8b46521d274d84a408100d10",
    "qualification/v010/shell-runtime/run-shell-runtime.sh": "3533143a2a37fa733204daae9ba9177cffea726ce499e024d2968df433956b6b",
    "qualification/v010/workstation-acceptance/record-session.sh": "97fee418e4d144e9500b86907cea18dd716e877fa7b981ae2c12b2684850d318",
    "qualification/v010/workstation-acceptance/launch-interactive.sh": "03ba66997d4ad338815cff10ed1446dc90cc005ae528805f0ac9cd1fdf869627",
    "qualification/v010/workstation-acceptance/capture-hardware-session.sh": "87c5b48938f9eae997a0a8e6c7bc75607ffd2c3c14f274e2ab9ec251dc242386",
    "scripts/qualification/v09-adversarial-guest.sh": "4e68b9434f07c8df61f6ac636cd13f59800a3cc1bc7666a547f6c2ed0a3a03fd",
    "apps/linura-shell/panel/WorkstationPanel.qml": "cb93655f4ea5d86d3d76a5fe17c217a51d681010750e56bb1b4524c041d4a055",
}
REQUIRED_VERSION = {
    "clang-format": "clang-format version 18.1.8",
    "prettier": "3.6.2",
    "stylua": "stylua 2.5.2",
    "shfmt": "v3.11.0",
    "qmlformat": "qmlformat 6.4.2",
}


EXTENSIONLESS_SHELL = frozenset(
    {
        "qualification/v010/shell-runtime/fixtures/forking-app",
        "qualification/v010/shell-runtime/fixtures/linger-app",
    }
)
SHELL_INTERPRETERS = frozenset({b"sh", b"bash", b"dash", b"ash", b"ksh", b"mksh"})


def is_shell_source(path: Path, root: Path) -> bool:
    name = path.name.lower()
    if (
        path.suffix.lower() in {".sh", ".bash"}
        or name.endswith((".sh.in", ".bash.in"))
        or path.as_posix() in EXTENSIONLESS_SHELL
    ):
        return True
    with (root / path).open("rb") as source:
        first_line = source.readline(512)
    if not first_line.startswith(b"#!"):
        return False
    tokens = first_line[2:].strip().split()
    if not tokens:
        return False
    executable = tokens[0].rsplit(b"/", 1)[-1]
    if executable == b"env":
        arguments = tokens[1:]
        if arguments and arguments[0] == b"-S":
            arguments = arguments[1:]
        while arguments and b"=" in arguments[0] and not arguments[0].startswith(b"/"):
            arguments = arguments[1:]
        if not arguments:
            return False
        executable = arguments[0].rsplit(b"/", 1)[-1]
    return executable in SHELL_INTERPRETERS


def tracked_paths(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "-z"],
        capture_output=True,
        check=False,
        timeout=20,
    )
    if result.returncode != 0:
        raise RuntimeError("cannot inventory tracked source")
    names = result.stdout.decode("utf-8").split("\0")
    paths: list[Path] = []
    for name in names:
        if not name:
            continue
        path = Path(name)
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeError(f"unsafe tracked format input: {name}")
        candidate = root
        for component in path.parts:
            candidate = candidate / component
            if candidate.is_symlink():
                raise RuntimeError(f"unsafe tracked format input: {name}")
        if not candidate.is_file():
            raise RuntimeError(f"missing or unsafe tracked format input: {name}")
        if path.suffix.lower() in CPP | JS | {".lua", ".qml"} or is_shell_source(
            path, root
        ):
            paths.append(path)
    return sorted(paths)


def command(
    program: str, *arguments: str, timeout: int = 90
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [program, *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=timeout,
    )


def check(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    paths = tracked_paths(root)
    editable: list[Path] = []
    for path in paths:
        expected = FROZEN_FORMAT_INPUTS.get(path.as_posix())
        if expected is None:
            editable.append(path)
        elif hashlib.sha256((root / path).read_bytes()).hexdigest() != expected:
            errors.append(f"{path}: protected format-exception source digest changed")
    groups = {
        "clang-format": [str(p) for p in editable if p.suffix.lower() in CPP],
        "prettier": [str(p) for p in editable if p.suffix.lower() in JS],
        "stylua": [str(p) for p in editable if p.suffix.lower() == ".lua"],
        "shfmt": [str(p) for p in editable if is_shell_source(p, root)],
        "qmlformat": [str(p) for p in editable if p.suffix.lower() == ".qml"],
    }
    groups["prettier"].extend(PRETTIER_CONFIG)
    for program, version in REQUIRED_VERSION.items():
        location = shutil.which(program)
        if location is None:
            errors.append(f"required language formatter missing: {program}")
            continue
        observed = command(location, "--version")
        if observed.returncode != 0 or observed.stdout.strip() != version:
            errors.append(
                f"{program}: expected {version!r}, observed {observed.stdout.strip()!r}"
            )
            continue
        files = groups[program]
        if not files:
            continue
        if program == "clang-format":
            for path in files:
                result = command(
                    location, "--dry-run", "--Werror", "--style=file", "--", path
                )
                if result.returncode != 0:
                    errors.append(f"{program}: {path}: {result.stderr.strip()[:1000]}")
        elif program == "prettier":
            result = command(
                location,
                "--check",
                "--config=.prettierrc.json",
                "--ignore-path=/dev/null",
                "--with-node-modules",
                "--",
                *files,
            )
            if result.returncode != 0:
                errors.append(
                    f"{program}: {result.stdout.strip()[:1500]} {result.stderr.strip()[:500]}"
                )
        elif program == "stylua":
            result = command(location, "--check", "--", *files)
            if result.returncode != 0:
                errors.append(
                    f"{program}: {result.stdout.strip()[:1500]} {result.stderr.strip()[:500]}"
                )
        elif program == "shfmt":
            result = command(location, "-d", "-i", "4", "-ci", "--", *files)
            if result.returncode != 0 or result.stdout:
                errors.append(
                    f"{program}: {result.stdout.strip()[:1500]} {result.stderr.strip()[:500]}"
                )
        else:
            with tempfile.TemporaryDirectory(prefix="linura-qml-format-") as directory:
                shadow_root = Path(directory)
                shutil.copyfile(root / ".qmlformat.ini", shadow_root / ".qmlformat.ini")
                for path in files:
                    source = root / path
                    candidate = shadow_root / path
                    candidate.parent.mkdir(parents=True, exist_ok=True)
                    candidate.write_bytes(source.read_bytes())
                    result = command(
                        location, "-w", "4", "-l", "unix", "-i", str(candidate)
                    )
                    if result.returncode != 0:
                        errors.append(
                            f"{program}: {path}: {result.stderr.strip()[:1000]}"
                        )
                    elif candidate.read_bytes() != source.read_bytes():
                        errors.append(f"{program}: {path}: format drift")
    return errors


def main() -> int:
    try:
        failures = check(ROOT)
    except (OSError, UnicodeError, subprocess.TimeoutExpired, RuntimeError) as exc:
        print(f"source format check denied: {exc}", file=sys.stderr)
        return 1
    if failures:
        for failure in failures:
            print(f"source format check denied: {failure}", file=sys.stderr)
        return 1
    print("pinned C/C++, JS/MJS, Lua, QML and shell formatter checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
