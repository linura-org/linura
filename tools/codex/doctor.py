#!/usr/bin/env python3
"""Non-installing capability inventory; readiness is never test evidence."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ("core", "shell", "bindings", "vm", "image", "visual")
QT_MODULES = ("Qt6Core", "Qt6DBus", "Qt6Qml", "Qt6Quick", "Qt6QuickControls2")


@dataclass(frozen=True)
class Check:
    profile: str
    name: str
    ready: bool
    remedy: str


def versions() -> dict[str, str]:
    # Parse data rather than executing a shell contract in the diagnostic tool.
    result = {}
    for line in (ROOT / "tools/codex/versions.env").read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z_][A-Z0-9_]*)=([A-Za-z0-9_.-]+)", line)
        if not match or match[1] in result:
            raise ValueError("invalid or duplicate Codex version entry")
        result[match[1]] = match[2]
    return result


PROBE_TIMEOUT_SECONDS = 30
PROBE_MAX_STDOUT_BYTES = 64 * 1024


def probe(argv: list[str], env: dict[str, str]) -> str | None:
    """Bound probe time and memory; discard stderr and never expose output."""
    process: subprocess.Popen[bytes] | None = None
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        assert process.stdout is not None
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    return None
                # Read no more than one byte past the cap. Stop immediately
                # when the child tries to stream an unbounded result.
                chunk = os.read(
                    process.stdout.fileno(),
                    min(4096, PROBE_MAX_STDOUT_BYTES + 1 - len(output)),
                )
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > PROBE_MAX_STDOUT_BYTES:
                    return None
        remaining = max(0, deadline - time.monotonic())
        if process.wait(timeout=remaining) != 0:
            return None
        decoded = output.decode("utf-8").strip()
        return decoded
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return None
    finally:
        if process is not None:
            # The parent may exit successfully while a grandchild survives
            # with redirected stdio. Always stop the private process group:
            # successful version output does not grant descendants a lifetime.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.stdout is not None:
                process.stdout.close()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()



def probe_status(argv: list[str], env: dict[str, str]) -> bool:
    """Bound a status-only probe while discarding arbitrarily large output."""
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return process.wait(timeout=PROBE_TIMEOUT_SECONDS) == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
    finally:
        if process is not None:
            # A successful exit may still leave descendants; terminating this
            # private process group bounds their lifetime as well as output.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def exact_version(output: str | None, expected: str) -> bool:
    return output is not None and expected in [token.removeprefix("v") for token in output.split()]


def inventory(selected: set[str]) -> list[Check]:
    pins = versions()
    env = os.environ.copy()
    cargo_home = Path(env.get("CARGO_HOME", str(Path.home() / ".cargo")))
    tool_root = Path.home() / ".local/linura-tools"
    env["CARGO_HOME"] = str(cargo_home)
    env["PATH"] = f"{cargo_home}/bin:{Path.home()}/.local/bin:{env.get('PATH', '')}"
    # Diagnostic Rust calls cannot trigger downloads or toolchain self-updates.
    env["RUSTUP_AUTO_INSTALL"] = "0"
    env["CARGO_NET_OFFLINE"] = "true"
    checks: list[Check] = []

    def add(profile: str, name: str, ready: bool, remedy: str) -> None:
        checks.append(Check(profile, name, ready, remedy))

    def commands(profile: str, names: tuple[str, ...]) -> None:
        for name in names:
            add(profile, name, shutil.which(name, path=env["PATH"]) is not None,
                f"Provide {name} in the configured base image; see docs/codex-development.md.")

    add("core", "host", platform.system() == pins["HOST_OS"] and platform.machine() == pins["HOST_ARCH"],
        "Select the declared Linux x86_64 base image.")
    libc = probe(["getconf", "GNU_LIBC_VERSION"], env)
    match = re.fullmatch(r"glibc (\d+)\.(\d+)", libc or "")
    add("core", "glibc", bool(match and tuple(map(int, match.groups())) >= (2, 17)),
        "Select a glibc >= 2.17 base image; musl is unsupported.")
    add("core", "python", f"{sys.version_info.major}.{sys.version_info.minor}" == pins["PYTHON_MAJOR_MINOR"],
        "Select the repository-declared Python major/minor in the base environment.")
    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    add("core", "rust-pin-alignment", channel == pins["RUST_VERSION"],
        "Align the reviewed Codex contract with rust-toolchain.toml.")
    commands("core", ("bash", "cc", "curl", "getconf", "git", "python3",
                      "sha256sum", "tar", "uname", "awk", "tr", "mktemp",
                      "mkdir", "ln", "chmod", "rm", "head", "rustup", "cargo-audit",
                      "ruff"))
    for binary, expected in (
        ("rustup", pins["RUSTUP_VERSION"]),
        ("cargo-audit", pins["CARGO_AUDIT_VERSION"]),
        ("ruff", pins["RUFF_VERSION"]),
    ):
        add("core", f"{binary}-version", exact_version(probe([binary, "--version"], env), expected),
            "Run setup/maintenance during environment preparation, then restart the task.")
    toolchain = f"{pins['RUST_VERSION']}-x86_64-unknown-linux-gnu"
    active = probe(["rustup", "show", "active-toolchain"], env)
    add("core", "active-toolchain", bool(active and active.split()[0] == toolchain),
        "Run setup/maintenance; remove conflicting task-level Rust toolchain overrides.")
    for binary, args in (("rustc", ["--version"]), ("cargo", ["--version"]),
                         ("cargo", ["fmt", "--version"]), ("cargo", ["clippy", "--version"])):
        output = probe(["rustup", "run", toolchain, binary, *args], env)
        ready = output is not None
        if binary == "rustc" or args == ["--version"]:
            ready = exact_version(output, pins["RUST_VERSION"])
        add("core", f"{binary}-{'-'.join(args).replace('--', '')}", ready,
            "Run setup/maintenance to provision the exact Rust toolchain and components.")
    actionlint = tool_root / "actionlint" / pins["ACTIONLINT_VERSION"] / "actionlint"
    add("core", "actionlint-version", exact_version(probe([str(actionlint), "-version"], env), pins["ACTIONLINT_VERSION"]),
        "Run setup/maintenance to provision the digest-verified actionlint archive.")
    # Cargo metadata can emit megabytes of JSON. Its exit status establishes
    # locked offline graph readiness; capturing that JSON is unnecessary.
    add("core", "locked-offline-cargo-graph", probe_status([
        "rustup", "run", toolchain, "cargo", "metadata", "--locked", "--offline", "--format-version", "1"
    ], env), "Run maintenance at the selected checkout to warm its locked Cargo graph.")

    if "shell" in selected or "image" in selected:
        commands("shell", ("cmake", "ninja", "pkg-config", "c++"))
        cmake = probe(["cmake", "--version"], env)
        match = re.search(r"cmake version (\d+)\.(\d+)", cmake or "")
        add("shell", "cmake-minimum", bool(match and tuple(map(int, match.groups())) >= (3, 24)),
            "Provide CMake >= 3.24 in the base image.")
        add("shell", "qt6-development-modules", probe([
            "pkg-config", "--atleast-version=6.4", *QT_MODULES
        ], env) is not None, "Provide Qt >= 6.4 Core/DBus/Qml/Quick/QuickControls2 development packages.")
    if "bindings" in selected:
        python = tool_root / "python/bin/python3"
        lock = (ROOT / "bindings/python/build-requirements.lock").read_text()
        requirements = re.findall(r"(?m)^([a-zA-Z0-9-]+)==([^\s]+)", lock)
        # An existing version match alone cannot establish a clean cache:
        # reject extras, changed hashes for identical versions and partial
        # installs from an interrupted maintenance run.
        import hashlib

        lock_digest = hashlib.sha256((ROOT / "bindings/python/build-requirements.lock").read_bytes()).hexdigest()
        marker = tool_root / "python/.linura-bindings-lock-sha256"
        try:
            digest_matches = marker.is_file() and not marker.is_symlink() and marker.read_text().strip() == lock_digest
        except (OSError, UnicodeError):
            digest_matches = False
        code = (
            "import importlib.metadata as m; import re; "
            f"required = {requirements!r}; "
            "normalize = lambda value: re.sub(r'[-_.]+', '-', value).lower(); "
            "installed = sorted((normalize(dist.metadata['Name']), dist.version) "
            "for dist in m.distributions()); "
            "expected = sorted((normalize(name), version) for name, version in required); "
            "assert installed == expected"
        )
        distributions_match = probe([str(python), "-c", code], env) is not None
        add("bindings", "hash-locked-build-environment", bool(digest_matches and distributions_match),
            "Run setup/maintenance --bindings to recreate the exact hash-locked Python environment.")
    if "vm" in selected:
        commands("vm", ("qemu-system-x86_64", "qemu-img", "ssh", "scp", "ssh-keygen", "curl", "timeout"))
        add("vm", "canonical-vm-doctor", probe([sys.executable, "tools/vm.py", "doctor"], env) is not None,
            "Run python3 tools/vm.py doctor; TCG is valid when KVM is unavailable.")
    if "image" in selected:
        commands("image", ("mkarchiso",))
        add("image", "archiso-releng", Path("/usr/share/archiso/configs/releng").is_dir(),
            "Use a separately provisioned Arch image builder with its canonical releng profile.")
    if "visual" in selected:
        commands("visual", ("compare", "ffmpeg", "ffprobe"))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    selected = set(PROFILES if args.all else (args.profile or ["core"]))
    selected.add("core")
    if "image" in selected:
        selected.add("shell")
    try:
        checks = inventory(selected)
    except (OSError, ValueError, KeyError):
        print("Invalid Codex readiness contract; inspect tools/codex/versions.env.", file=sys.stderr)
        return 2
    ready = all(check.ready for check in checks)
    if args.json:
        print(json.dumps({"schema_version": 1, "profiles": sorted(selected),
                          "ready": ready, "qualification_evidence": False,
                          "checks": [asdict(check) for check in checks]}, indent=2))
    else:
        for check in checks:
            print(f"{check.profile}/{check.name}: {'ready' if check.ready else 'missing or incompatible'}")
            if not check.ready:
                print(f"  {check.remedy}")
        print("Readiness inventory only; no test or qualification success is asserted.")
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
