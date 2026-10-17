#!/usr/bin/env python3
"""Bounded native-build readiness only; never runtime/qualification evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shlex
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent
TIMEOUT_SECONDS = 15
MAX_OUTPUT_BYTES = 64 * 1024
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/tmp"}
MODULES = {
    "Qt6Core",
    "Qt6DBus",
    "Qt6Gui",
    "Qt6Qml",
    "Qt6Quick",
    "Qt6QuickControls2",
    "glib-2.0",
    "polkit-agent-1",
    "wayland-client",
    "wayland-server",
    "wayland-protocols",
    "xkbcommon",
}
QML_PACKAGES = (
    "qml6-module-qtqml",
    "qml6-module-qtqml-models",
    "qml6-module-qtqml-workerscript",
    "qml6-module-qtquick",
    "qml6-module-qtquick-controls",
    "qml6-module-qtquick-layouts",
    "qml6-module-qtquick-templates",
    "qml6-module-qtquick-window",
)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate native build pin")
        result[key] = value
    return result


def validate_contract(contract: dict) -> None:
    expected = {
        "schema_version",
        "purpose",
        "qualification_evidence",
        "base_image",
        "platform",
        "ubuntu_version",
        "snapshot",
        "python_version",
        "qml_runtime_version",
        "installed_packages_sha256",
        "tools",
        "modules",
    }
    if (
        set(contract) != expected
        or type(contract["schema_version"]) is not int
        or contract["schema_version"] != 1
        or contract["purpose"] != "development-build-only"
        or contract["qualification_evidence"] is not False
        or contract["platform"] != "linux/amd64"
        or contract["ubuntu_version"] != "24.04"
        or not re.fullmatch(
            r"docker.io/library/buildpack-deps@sha256:[0-9a-f]{64}",
            contract["base_image"],
        )
        or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", contract["snapshot"])
        or not re.fullmatch(r"[0-9a-f]{64}", contract["installed_packages_sha256"])
        or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+\+dfsg-[0-9a-z]+", contract["qml_runtime_version"]
        )
        or set(contract["modules"]) != MODULES
        or set(contract["tools"])
        != {"c++", "cmake", "ninja", "pkg-config", "wayland-scanner"}
        or any(
            not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value)
            for value in [
                contract["python_version"],
                *contract["modules"].values(),
                *contract["tools"].values(),
            ]
        )
    ):
        raise ValueError("incomplete or unsupported native build pins")


def probe(
    argv: list[str], input_bytes: bytes | None = None, *, merge_stderr: bool = False
) -> str | None:
    """Fixed native tools; bounded time/output, no ambient library/SDK overrides."""
    if input_bytes is not None and len(input_bytes) > 4096:
        return None
    process = None
    deadline = time.monotonic() + TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            argv,
            env=ENVIRONMENT,
            cwd="/tmp",
            start_new_session=True,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL,
        )
        if input_bytes is not None:
            assert process.stdin is not None
            process.stdin.write(input_bytes)
            process.stdin.close()
        assert process.stdout is not None
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    return None
                chunk = os.read(
                    process.stdout.fileno(),
                    min(4096, MAX_OUTPUT_BYTES + 1 - len(output)),
                )
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_OUTPUT_BYTES:
                    return None
        if process.wait(timeout=max(0, deadline - time.monotonic())) != 0:
            return None
        return output.decode("utf-8").strip()
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return None
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.stdout is not None:
                process.stdout.close()
            if process.stdin is not None:
                process.stdin.close()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


API_PROBE = b"""
#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE
#include <polkitagent/polkitagent.h>
#include <gio/gio.h>
#include <QObject>
#include <type_traits>
static_assert(std::is_same_v<decltype(&polkit_agent_session_new),
    PolkitAgentSession* (*)(PolkitIdentity*, const gchar*)>);
static_assert(std::is_same_v<decltype(&polkit_agent_session_response),
    void (*)(PolkitAgentSession*, const gchar*)>);
static_assert(std::is_same_v<decltype(&polkit_agent_session_cancel),
    void (*)(PolkitAgentSession*)>);
int main() {
    PolkitAgentListenerClass* listener = nullptr;
    (void)listener->initiate_authentication;
    (void)listener->initiate_authentication_finish;
    return 0;
}
"""


def checks(contract: dict) -> dict[str, bool]:
    validate_contract(contract)
    result = {
        "declared-build-only": contract.get("schema_version") == 1
        and contract.get("purpose") == "development-build-only"
        and contract.get("qualification_evidence") is False,
        "platform": platform.system() == "Linux" and platform.machine() == "x86_64",
        "ubuntu": False,
        "non-root": os.getuid() == 1000 and os.geteuid() == 1000,
        "python": platform.python_version() == contract["python_version"],
    }
    release = Path("/etc/os-release").read_text(encoding="utf-8")
    fields = dict(line.split("=", 1) for line in release.splitlines() if "=" in line)
    result["ubuntu"] = (
        fields.get("ID") == "ubuntu" and fields.get("VERSION_ID") == '"24.04"'
    )
    inventory = probe(
        ["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"]
    )
    result["exact-installed-package-graph"] = (
        inventory is not None
        and hashlib.sha256((inventory + "\n").encode("utf-8")).hexdigest()
        == contract["installed_packages_sha256"]
    )
    qml_packages = probe(
        [
            "/usr/bin/dpkg-query",
            "-W",
            "-f=${db:Status-Abbrev}\t${Version}\n",
            *QML_PACKAGES,
        ]
    )
    result["official-qml-runtime-packages"] = (
        qml_packages is not None
        and qml_packages.splitlines()
        == ["ii \t" + contract["qml_runtime_version"]] * len(QML_PACKAGES)
    )
    for module, expected in contract["modules"].items():
        result[f"module:{module}"] = (
            probe(["/usr/bin/pkg-config", "--modversion", module]) == expected
        )
    flags = probe(
        ["/usr/bin/pkg-config", "--cflags", "Qt6Core", "polkit-agent-1", "glib-2.0"]
    )
    result["official-authentication-headers"] = (
        flags is not None
        and probe(
            [
                "/usr/bin/c++",
                "-std=c++20",
                "-DQT_NO_KEYWORDS",
                "-fPIC",
                *shlex.split(flags or ""),
                "-x",
                "c++",
                "-fsyntax-only",
                "-",
            ],
            API_PROBE,
        )
        is not None
    )
    for tool, expected in contract["tools"].items():
        # The official scanner writes its version to stderr. Capture only this
        # fixed version probe; retain exact matching and the same byte/deadline
        # bounds. Compiler/header diagnostics remain suppressed.
        value = probe(
            [f"/usr/bin/{tool}", "-dumpfullversion" if tool == "c++" else "--version"],
            merge_stderr=tool == "wayland-scanner",
        )
        if value is not None and tool == "cmake":
            value = value.splitlines()[0].removeprefix("cmake version ")
        if value is not None and tool == "wayland-scanner":
            value = value.removeprefix("wayland-scanner ")
        result[f"tool:{tool}"] = value == expected
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        contract = json.loads(
            (ROOT / "contract.json").read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
        )
        status = checks(contract)
    except (OSError, ValueError, KeyError, TypeError):
        status = {"valid-build-contract": False}
    ready = all(status.values())
    report = {
        "purpose": "development-build-only",
        "qualification_evidence": False,
        "ready": ready,
        "checks": status,
    }
    if arguments.json:
        print(json.dumps(report, sort_keys=True))
    else:
        for name, passed in status.items():
            print(f"{'ready' if passed else 'missing/mismatched'}: {name}")
        print("Build readiness only; native qualification was not run.")
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
