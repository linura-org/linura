#!/usr/bin/env python3
"""Run real owner-access denial probes without relying on ambient Yama policy.

Only the disposable qualification guest is changed. The original Yama setting
is restored even on test failure; no production policy or host is modified.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import signal
import stat
import subprocess
import sys


ROOT = Path("/opt/linura-source/qualification/v010/session-security")
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


def require_guest() -> None:
    if os.geteuid() != 0 or socket.gethostname() != "linura-v010-shell":
        raise RuntimeError("native fixture requires the dedicated root VM context")
    virtual = subprocess.run(
        ["/usr/bin/systemd-detect-virt", "--vm"],
        env=ENVIRONMENT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=5,
    )
    if virtual.returncode != 0 or virtual.stdout.strip() not in {b"qemu", b"kvm"}:
        raise RuntimeError(
            "native fixture refuses other virtualization or physical hosts"
        )
    for path in (
        Path("/opt"),
        Path("/opt/linura-source"),
        Path("/opt/linura-source/qualification"),
        ROOT.parent,
        ROOT,
    ):
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError("native fixture source is not root immutable")
    for name in ("provision-native-session.py", "probe-same-uid.py"):
        metadata = (ROOT / name).lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or metadata.st_nlink != 1
        ):
            raise RuntimeError("native fixture helper is not root immutable")
    spec = importlib.util.spec_from_file_location(
        "s17_provision", ROOT / "provision-native-session.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("native qualification guest guard is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.require_disposable_guest()


def set_scope(value: str) -> None:
    if value not in {"0", "1", "2"}:
        raise RuntimeError("native fixture ptrace scope is unsupported")
    subprocess.run(
        ["/usr/bin/sysctl", "-q", "-w", f"kernel.yama.ptrace_scope={value}"],
        env=ENVIRONMENT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=5,
    )


def validate_report(report: object) -> dict[str, object]:
    expected_checks = {
        f"same-uid-{name}-open-denied" for name in ("mem", "environ", "auxv")
    }
    expected_checks.add("same-uid-ptrace-seize-denied")
    expected_fields = {
        "schema_version",
        "claim",
        "native_owner_pid",
        "native_owner_invocation",
        "owner_start_ticks",
        "ptrace_scope",
        "checks",
        "s17_complete",
        "native_authentication_qualified",
        "release_support_promotion",
    }
    if not isinstance(report, dict) or set(report) != expected_fields:
        raise RuntimeError("native same-UID report is incomplete")
    checks = report["checks"]
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or report["claim"] != "native-same-uid-process-access-cases-only"
        or type(report["native_owner_pid"]) is not int
        or not 1 < report["native_owner_pid"] < 2**31
        or not isinstance(report["native_owner_invocation"], str)
        or re.fullmatch(r"[0-9a-f]{32}", report["native_owner_invocation"]) is None
        or report["native_owner_invocation"] == "0" * 32
        or not isinstance(report["owner_start_ticks"], str)
        or re.fullmatch(r"[1-9][0-9]{0,19}", report["owner_start_ticks"]) is None
        or type(report["ptrace_scope"]) is not int
        or report["ptrace_scope"] != 0
        or not isinstance(checks, dict)
        or set(checks) != expected_checks
        or any(value is not True for value in checks.values())
        or report["s17_complete"] is not False
        or report["native_authentication_qualified"] is not False
        or report["release_support_promotion"] is not False
    ):
        raise RuntimeError("native same-UID report is incomplete")
    return report


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate native probe field")
        result[key] = value
    return result


def run() -> dict[str, object]:
    require_guest()  # No sysctl or process-attach probe before the root VM guard.
    with Path("/proc/sys/kernel/yama/ptrace_scope").open(encoding="ascii") as source:
        original = source.read(5).strip()
    if original not in {"0", "1", "2"}:
        raise RuntimeError("native attack probes require a reversible Yama fixture")
    try:
        set_scope("0")
        result = subprocess.run(
            [
                "/usr/bin/runuser",
                "-u",
                "linura",
                "--",
                "/usr/bin/python3",
                "-I",
                "-S",
                str(ROOT / "probe-same-uid.py"),
            ],
            env=ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=20,
        )
        if result.returncode != 0 or len(result.stdout) > 16384:
            raise RuntimeError("native same-UID probes failed")
        return validate_report(
            json.loads(result.stdout, object_pairs_hook=unique_object)
        )
    finally:
        set_scope(original)


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()

    def interrupted(_signal, _frame):
        raise RuntimeError("native fixture interrupted")

    previous = {
        number: signal.signal(number, interrupted)
        for number in (signal.SIGTERM, signal.SIGINT)
    }
    try:
        print(json.dumps(run(), sort_keys=True))
        return 0
    except Exception:
        print("native same-UID fixture failed", file=sys.stderr)
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    raise SystemExit(main())
