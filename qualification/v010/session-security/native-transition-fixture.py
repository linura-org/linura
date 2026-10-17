#!/usr/bin/env python3
"""Fixed disposable-guest terminating requests; retained records are NOT authority.

No direct logind/power commands, inhibitor overrides, login termination helpers,
PAM changes or automatic resubmission. Only production typed managed requests.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

ROOT = Path("/opt/linura-source/qualification/v010/session-security")
STATE = Path("/var/lib/linura-s17-transition-cases")
PURPOSES = ("logout", "reboot", "power-off")


def shared():
    if os.geteuid() != 0:
        raise RuntimeError("terminating fixture requires the root disposable guest")
    for path in (*reversed(ROOT.parents), ROOT):
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError("terminating fixture source is not root immutable")
    for name in ("native-transition-fixture.py", "native-suspend-fixture.py"):
        metadata = (ROOT / name).lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid
            or metadata.st_mode & 0o022
            or metadata.st_nlink != 1
        ):
            raise RuntimeError("terminating fixture helper is untrusted")
    spec = importlib.util.spec_from_file_location(
        "s17_terminating_guest", ROOT / "native-suspend-fixture.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("terminating fixture guard is unavailable")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    codec = (
        fixture.shared()
    )  # Includes every shared dependency and disposable-VM guard.
    return fixture, codec


def boot() -> str:
    with Path("/proc/sys/kernel/random/boot_id").open("rb") as source:
        wire = source.read(38)
    if re.fullmatch(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n", wire) is None:
        raise RuntimeError("terminating fixture boot identity is unavailable")
    return wire.decode("ascii").strip()


def validate_pending(value: dict, purpose: str, codec) -> None:
    if purpose not in PURPOSES or set(value) != {
        "operation",
        "purpose",
        "resource",
        "target",
    }:
        raise RuntimeError("terminating fixture request shape is unsupported")
    if (
        value["purpose"] != purpose
        or not all(isinstance(field, str) for field in value.values())
        or re.fullmatch(r"s17-native-" + purpose + r"-[0-9a-f]{16}", value["operation"])
        is None
    ):
        raise RuntimeError("terminating fixture request purpose is unsupported")
    codec.lock_resource(value["resource"])
    if (
        value["target"]
        != "session:transition:" + purpose + ":0:" + value["resource"][13:]
    ):
        raise RuntimeError("terminating fixture target generation differs")


def worker(fixture, codec, purpose: str) -> None:
    pending = fixture.read_record("pending.json", codec)
    validate_pending(pending, purpose, codec)
    if pending["resource"].split(":")[2] != boot():
        raise RuntimeError("terminating fixture cannot resubmit an earlier boot")
    deadline = time.monotonic() + 20
    while not fixture.only_target_session(pending["resource"], codec, deadline):
        if time.monotonic() >= deadline:
            raise RuntimeError("another login still inhibits the terminating case")
        time.sleep(0.1)
    if time.monotonic() >= deadline:
        raise RuntimeError("terminating fixture session deadline expired")
    target = codec.fields(
        fixture.command(
            ["/usr/bin/linuractl", "own-session-transition", purpose], owner=True
        )
    )
    if target != {"resource": pending["target"]}:
        raise RuntimeError("terminating fixture target changed before submission")
    # Write-once admission prevents restarting this worker from replaying a
    # request. This record proves neither dispatch nor native completion.
    fixture.write_record("submission.json", {"state": "submitting", **pending})
    receipt = fixture.command(
        [
            "/usr/bin/linuractl",
            "transition-session",
            purpose,
            pending["operation"],
            "S17-native-terminating-qualification",
        ],
        budget=90,
        owner=True,
    )
    fixture.write_record(
        "result.json",
        {"state": "returned", **pending, "receipt": receipt.decode("ascii")},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("queue", "worker", "status"))
    parser.add_argument("purpose", choices=PURPOSES)
    args = parser.parse_args()
    fixture, codec = shared()  # Before commands or persistent state creation.
    for parent in (Path("/var"), Path("/var/lib")):
        metadata = parent.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError("terminating fixture state ancestry is untrusted")
    if args.action == "queue":
        try:
            STATE.mkdir(mode=0o700)
        except FileExistsError:
            pass
    fixture.select_terminating_case(None)
    fixture.directory()
    fixture.select_terminating_case(args.purpose)
    if args.action == "queue":
        lock = codec.fields(
            fixture.command(["/usr/bin/linuractl", "own-session-lock"], owner=True)
        )
        target = codec.fields(
            fixture.command(
                ["/usr/bin/linuractl", "own-session-transition", args.purpose],
                owner=True,
            )
        )
        if set(lock) != {"resource"} or set(target) != {"resource"}:
            raise RuntimeError("terminating fixture target query is malformed")
        pending = {
            "operation": "s17-native-" + args.purpose + "-" + secrets.token_hex(8),
            "purpose": args.purpose,
            "resource": lock["resource"],
            "target": target["resource"],
        }
        validate_pending(pending, args.purpose, codec)
        if pending["resource"].split(":")[2] != boot():
            raise RuntimeError("terminating fixture queue boot differs")
        fixture.STATE.mkdir(mode=0o700)  # Never reuse or overwrite a case.
        fixture.write_record("pending.json", pending)
        fixture.command(
            [
                "/usr/bin/systemd-run",
                "--quiet",
                "--unit=linura-s17-" + args.purpose + "-case",
                "--property=Type=exec",
                "--property=RuntimeMaxSec=150",
                "--property=LimitCORE=0",
                "--property=UMask=0077",
                "--",
                "/usr/bin/python3",
                "-I",
                "-S",
                str(ROOT / "native-transition-fixture.py"),
                "worker",
                args.purpose,
            ]
        )
        print(json.dumps(pending, sort_keys=True))
    elif args.action == "worker":
        try:
            worker(fixture, codec, args.purpose)
        except Exception:
            # No exception/command output or authentication data in the journal.
            raise RuntimeError(
                "terminating fixture failed; no successful evidence"
            ) from None
    else:
        pending = fixture.read_record("pending.json", codec)
        validate_pending(pending, args.purpose, codec)
        current_boot = boot()
        present = False
        if current_boot == pending["resource"].split(":")[2]:
            rows = (
                fixture.command(
                    ["/usr/bin/loginctl", "list-sessions", "--no-legend", "--no-pager"]
                )
                .decode("ascii")
                .splitlines()
            )
            sessions = [row.split()[0] for row in rows if row.split()]
            if (
                len(rows) > 16
                or len(sessions) != len(rows)
                or len(set(sessions)) != len(sessions)
                or any(
                    re.fullmatch(r"[A-Za-z0-9]{1,64}", item) is None
                    for item in sessions
                )
            ):
                raise RuntimeError(
                    "terminating fixture session inventory is unsupported"
                )
            present = pending["resource"].split(":")[4] in sessions
        print(
            json.dumps(
                {"boot": current_boot, "original_session_present": present, **pending},
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
