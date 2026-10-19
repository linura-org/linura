#!/usr/bin/env python3
"""Fixed disposable-guest AT-SPI probe; never product authority or input."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat

ROOT = Path("/opt/linura-source/qualification/v010/session-security")
BINARY = Path("/usr/lib/linura/qualification/linura-s17-assistive-probe")
CHECKS = {
    "registry-discovers-actual-native-owner",
    "typed-protected-presentation-tree",
    "no-text-value-editable-action-or-geometry-interface",
    "remote-input-and-relabel-methods-rejected",
}


def immutable(path: Path, executable: bool = False) -> None:
    for current in (*reversed(path.parents), path):
        metadata = current.lstat()
        if metadata.st_uid or metadata.st_mode & 0o022:
            raise RuntimeError("native assistive fixture path is not root immutable")
        if current == path:
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o6000
                or (executable and not metadata.st_mode & 0o111)
            ):
                raise RuntimeError("native assistive fixture file is unsupported")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("native assistive fixture ancestry is unsupported")


def shared():
    if os.geteuid() != 0:
        raise RuntimeError(
            "native assistive fixture requires the root disposable guest"
        )
    for name in ("native-assistive-fixture.py", "native-suspend-fixture.py"):
        immutable(ROOT / name)
    spec = importlib.util.spec_from_file_location(
        "s17_assistive_guest", ROOT / "native-suspend-fixture.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("native assistive fixture guard is unavailable")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    codec = fixture.shared()  # Includes the fixed Arch/QEMU/source/account guard.
    immutable(BINARY, executable=True)
    if fixture.command(["/usr/bin/getcap", "-n", str(BINARY)]).strip():
        raise RuntimeError("native assistive probe must not have file capabilities")
    return fixture, codec


def identity(fixture, codec) -> tuple[int, str, str]:
    uid = pwd.getpwnam("linura").pw_uid
    if uid == 0:
        raise RuntimeError("native assistive fixture owner is unsupported")
    value = codec.fields(
        fixture.command(
            [
                "/usr/bin/systemctl",
                "show",
                f"linura-security-owner@{uid}.service",
                "--property=MainPID,InvocationID,ActiveState,SubState,User",
                "--no-pager",
            ]
        )
    )
    if (
        set(value) != {"MainPID", "InvocationID", "ActiveState", "SubState", "User"}
        or value["ActiveState"] != "active"
        or value["SubState"] != "running"
        or value["User"] != str(uid)
        or re.fullmatch(r"[1-9][0-9]{0,9}", value["MainPID"]) is None
        or not 1 < int(value["MainPID"]) < 2**31
        or re.fullmatch(r"[0-9a-f]{32}", value["InvocationID"]) is None
        or value["InvocationID"] == "0" * 32
    ):
        raise RuntimeError("native assistive owner is not the supervised invocation")
    pid = int(value["MainPID"])
    if Path(f"/proc/{pid}/exe").resolve() != Path(
        "/usr/lib/linura/linura-security-owner"
    ):
        raise RuntimeError("native assistive owner is not the installed executable")
    with Path(f"/proc/{pid}/stat").open("rb") as source:
        wire = source.read(4097)
    if len(wire) > 4096 or not wire.startswith((str(pid) + " (").encode()):
        raise RuntimeError("native assistive owner process facts are unsupported")
    delimiter = wire.rfind(b") ")
    fields = wire[delimiter + 2 :].split() if delimiter >= 0 else []
    if (
        len(fields) < 20
        or re.fullmatch(rb"[1-9][0-9]{0,19}", fields[19]) is None
        or int(fields[19]) >= 2**64
    ):
        raise RuntimeError("native assistive owner start identity is unsupported")
    return pid, value["InvocationID"], fields[19].decode("ascii")


def validate_report(value: object, pid: int, phase: str) -> dict:
    if (
        phase not in {"locked", "unlock-prompt"}
        or not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "claim",
            "phase",
            "native_owner_pid",
            "checks",
            "s17_complete",
            "release_support_promotion",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["claim"] != "native-assistive-metadata-cases-only"
        or value["phase"] != phase
        or type(value["native_owner_pid"]) is not int
        or value["native_owner_pid"] != pid
        or not isinstance(value["checks"], dict)
        or set(value["checks"]) != CHECKS
        or any(result is not True for result in value["checks"].values())
        or value["s17_complete"] is not False
        or value["release_support_promotion"] is not False
    ):
        raise RuntimeError(
            "native assistive report is not exact positive partial evidence"
        )
    return value


def operate(phase: str) -> dict:
    if phase not in {"locked", "unlock-prompt"}:
        raise RuntimeError("native assistive fixture phase is unsupported")
    fixture, codec = shared()  # Before commands, process probes or execution.
    before = identity(fixture, codec)
    wire = fixture.command([str(BINARY), str(before[0]), phase], budget=12, owner=True)
    try:
        value = json.loads(wire, object_pairs_hook=codec.unique_object)
    except (ValueError, RecursionError):
        raise RuntimeError("native assistive fixture report is malformed") from None
    value = validate_report(value, before[0], phase)
    if identity(fixture, codec) != before:
        raise RuntimeError("native assistive owner changed across the probe")
    return {
        **value,
        "native_owner_invocation": before[1],
        "native_owner_start_ticks": before[2],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("locked", "unlock-prompt"))
    args = parser.parse_args()
    print(json.dumps(operate(args.phase), sort_keys=True))


if __name__ == "__main__":
    main()
