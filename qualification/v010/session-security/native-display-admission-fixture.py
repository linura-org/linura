#!/usr/bin/env python3
"""Read-only real supervised-owner admission cases inside the disposable guest.

No layout operation, input, service restart, policy change or authority is issued.
The executable uses the exact compositor predicate with real systemd evidence.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat

ROOT = Path("/opt/linura-source/qualification/v010/session-security")
BINARY = Path("/usr/lib/linura/qualification/linura-s21-owner-admission-probe")
CHECKS = {
    "root-supervised-owner-admitted",
    "same-uid-probe-denied",
    "root-uid-denied",
    "invalid-pid-denied",
}


def immutable(path: Path) -> None:
    for current in (*reversed(path.parents), path):
        item = current.lstat()
        if item.st_uid != 0 or item.st_mode & 0o022:
            raise RuntimeError("native admission fixture source is untrusted")
        if current == path:
            if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
                raise RuntimeError("native admission fixture source is unsupported")
        elif not stat.S_ISDIR(item.st_mode):
            raise RuntimeError("native admission fixture ancestry is unsupported")


def validate_report(value: dict[str, str], uid: int, pid: int, invocation: str) -> dict:
    if (
        set(value)
        != {
            "schema_version",
            "native_owner_pid",
            "native_owner_uid",
            "native_owner_invocation",
        }
        | CHECKS
        or value["schema_version"] != "1"
        or value["native_owner_pid"] != str(pid)
        or value["native_owner_uid"] != str(uid)
        or value["native_owner_invocation"] != invocation
        or any(value[check] != "true" for check in CHECKS)
    ):
        raise RuntimeError(
            "native admission probe did not prove its exact supervised scope"
        )
    return {
        "schema_version": 1,
        "claim": "native-display-owner-admission-predicate-cases-only",
        "native_owner_pid": pid,
        "native_owner_uid": uid,
        "native_owner_invocation": invocation,
        "checks": dict.fromkeys(sorted(CHECKS), True),
        "s21_2_complete": False,
        "release_support_promotion": False,
    }


def qualify() -> dict:
    if os.geteuid() != 0:
        raise RuntimeError(
            "native admission fixture requires the root disposable guest"
        )
    immutable(ROOT / "native-display-admission-fixture.py")
    helper = ROOT / "native-assistive-fixture.py"
    immutable(helper)
    spec = importlib.util.spec_from_file_location("s21_admission_guest", helper)
    if spec is None or spec.loader is None:
        raise RuntimeError("native admission guest guard is unavailable")
    assistive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(assistive)
    fixture, codec = assistive.shared()  # Fixed Arch/QEMU/source/account guard.
    return run_probe(assistive, fixture, codec)


def run_probe(assistive, fixture, codec) -> dict:
    assistive.immutable(BINARY, executable=True)
    if fixture.command(["/usr/bin/getcap", "-n", str(BINARY)]).strip():
        raise RuntimeError("native admission probe must have no file capabilities")
    uid = pwd.getpwnam("linura").pw_uid
    before = assistive.identity(fixture, codec)
    raw = fixture.command([str(BINARY), str(before[0])], budget=2, owner=True)
    if assistive.identity(fixture, codec) != before:
        raise RuntimeError("native admission probe crossed an owner replacement")
    return validate_report(codec.fields(raw), uid, before[0], before[1])


if __name__ == "__main__":
    try:
        print(json.dumps(qualify(), indent=2, sort_keys=True))
    except (OSError, RuntimeError, ValueError) as error:
        raise SystemExit(f"native admission qualification refused: {error}") from None
