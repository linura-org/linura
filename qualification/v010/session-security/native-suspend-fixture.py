#!/usr/bin/env python3
"""Fixed disposable-guest suspend client; never a product authority or credential.

Submit only through production linuractl, after independent other-session
enumeration. Never terminate logins, alter inhibitors, override PAM/Polkit, call
native sleep directly, or replay an uncertain transition.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import selectors
import signal
import stat
import subprocess
import time

ROOT = Path("/opt/linura-source/qualification/v010/session-security")
STATE = Path("/run/linura-s17-suspend-case")
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
LIMIT = 16384


def select_terminating_case(purpose: str | None) -> None:
    """Fixed fixture storage only; no caller-selected filesystem destination."""
    if purpose not in {None, "logout", "reboot", "power-off"}:
        raise RuntimeError("native terminating fixture storage scope is unsupported")
    global STATE
    parent = Path("/var/lib/linura-s17-transition-cases")
    STATE = parent if purpose is None else parent / purpose


def shared():
    if os.geteuid() != 0:
        raise RuntimeError("native suspend fixture requires the root disposable guest")
    for path in (*reversed(ROOT.parents), ROOT):
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError("native suspend fixture source is not root immutable")
    modules = []
    for name in (
        "native-suspend-fixture",
        "native-auth-fixture",
        "qualify-native-auth",
    ):
        path = ROOT / (name + ".py")
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or metadata.st_nlink != 1
        ):
            raise RuntimeError("native suspend fixture helper is untrusted")
        if name == "native-suspend-fixture":
            continue
        spec = importlib.util.spec_from_file_location(
            "s17_suspend_" + name.replace("-", "_"), path
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("native suspend fixture guard is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)
    guard, codec = modules
    guard.require_guest()
    return codec


def command(arguments: list[str], budget: float = 15, owner: bool = False) -> bytes:
    if not 0 < budget <= 90:
        raise RuntimeError("native suspend fixture command budget is unsupported")
    account = pwd.getpwnam("linura")
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise RuntimeError("native suspend fixture owner is unsupported")
    deadline = time.monotonic() + budget
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=ENVIRONMENT,
        start_new_session=True,
        user=account.pw_uid if owner else None,
        group=account.pw_gid if owner else None,
        extra_groups=() if owner else None,
    )
    assert process.stdout is not None
    wire = bytearray()
    try:
        with selectors.DefaultSelector() as reader:
            reader.register(process.stdout, selectors.EVENT_READ)
            while process.poll() is None or reader.get_map():
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "native suspend fixture command exceeded its original deadline"
                    )
                for key, _ in reader.select(0.05):
                    chunk = os.read(key.fd, min(4096, LIMIT + 1 - len(wire)))
                    if not chunk:
                        reader.unregister(key.fileobj)
                    else:
                        wire.extend(chunk)
                        if len(wire) > LIMIT:
                            raise RuntimeError(
                                "native suspend fixture command output exceeds its bound"
                            )
        if process.returncode != 0:
            raise RuntimeError("native suspend fixture command was refused")
        return bytes(wire)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        process.stdout.close()


def directory() -> None:
    metadata = STATE.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RuntimeError("native suspend fixture state directory is untrusted")


def write_record(name: str, value: dict[str, object]) -> None:
    directory()
    wire = json.dumps(value, sort_keys=True).encode("ascii")
    if (
        name not in {"pending.json", "submission.json", "result.json"}
        or len(wire) > LIMIT
    ):
        raise RuntimeError("native suspend fixture record is unsupported")
    destination = STATE / name
    temporary = STATE / (name + ".writing")
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("native suspend fixture record is already published")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(wire)
            target.flush()
            os.fsync(target.fileno())
        # A unique root-private directory and one fixed service writer own this
        # publication. Readers must never see a partially written JSON report.
        os.rename(temporary, destination)
        directory_descriptor = os.open(
            STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_record(name: str, codec) -> dict:
    directory()
    if name not in {"pending.json", "submission.json", "result.json"}:
        raise RuntimeError("native suspend fixture record is unsupported")
    descriptor = os.open(STATE / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > LIMIT
        ):
            raise RuntimeError("native suspend fixture record is untrusted")
        wire = source.read(LIMIT + 1)
    if len(wire) > LIMIT or len(wire) != metadata.st_size:
        raise RuntimeError("native suspend fixture record changed or exceeds its bound")
    value = json.loads(wire, object_pairs_hook=codec.unique_object)
    if not isinstance(value, dict):
        raise RuntimeError("native suspend fixture record is malformed")
    return value


def only_target_session(resource: str, codec, deadline: float) -> bool:
    codec.lock_resource(resource)
    _, _, _, uid, session, created, _, _ = resource.split(":")

    def observe(arguments):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("native suspend fixture session deadline expired")
        result = command(arguments, budget=min(15, remaining))
        if time.monotonic() >= deadline:
            raise RuntimeError("native suspend fixture session deadline expired")
        return result

    rows = (
        observe(["/usr/bin/loginctl", "list-sessions", "--no-legend", "--no-pager"])
        .decode("ascii")
        .splitlines()
    )
    if not 1 <= len(rows) <= 16:
        raise RuntimeError("native suspend fixture session inventory is unsupported")
    seen = set()
    found = False
    for row in rows:
        fields = row.split()
        if (
            not fields
            or re.fullmatch(r"[A-Za-z0-9]{1,64}", fields[0]) is None
            or fields[0] in seen
        ):
            raise RuntimeError("native suspend fixture session inventory is ambiguous")
        current = fields[0]
        seen.add(current)
        facts = codec.fields(
            observe(
                [
                    "/usr/bin/loginctl",
                    "show-session",
                    current,
                    "--no-pager",
                    "--property=User,Class,Type,Active,Remote,State,TimestampMonotonic",
                ]
            )
        )
        if current == session:
            expected = {
                "User": uid,
                "Class": "user",
                "Type": "wayland",
                "Active": "yes",
                "Remote": "no",
                "State": "active",
                "TimestampMonotonic": created,
            }
            if facts != expected:
                raise RuntimeError("native suspend fixture target generation changed")
            found = True
        elif facts.get("Class") not in {"manager", "greeter", "lock-screen"}:
            return False  # Wait for SSH to end, never kill or ignore that login.
    return found


def worker(codec) -> None:
    pending = read_record("pending.json", codec)
    if (
        set(pending) != {"operation", "resource"}
        or not isinstance(pending["operation"], str)
        or not isinstance(pending["resource"], str)
        or re.fullmatch(
            r"s17-native-suspend-[0-9a-f]{16}", pending.get("operation", "")
        )
        is None
    ):
        raise RuntimeError("native suspend fixture request is malformed")
    resource = pending["resource"]
    codec.lock_resource(resource)
    deadline = time.monotonic() + 20
    while not only_target_session(resource, codec, deadline):
        if time.monotonic() >= deadline:
            raise RuntimeError("another native login still inhibits the suspend case")
        time.sleep(0.1)
    if time.monotonic() >= deadline:
        raise RuntimeError("native suspend fixture session deadline expired")
    target = codec.fields(
        command(["/usr/bin/linuractl", "own-session-transition", "suspend"], owner=True)
    )
    if set(target) != {"resource"}:
        raise RuntimeError("native suspend fixture target query is malformed")
    receipt = command(
        [
            "/usr/bin/linuractl",
            "transition-session",
            "suspend",
            pending["operation"],
            "S17-native-suspend-qualification",
        ],
        budget=90,
        owner=True,
    )
    write_record(
        "result.json",
        {
            "state": "completed",
            "operation": pending["operation"],
            "lock_resource": resource,
            "target": target["resource"],
            "receipt": receipt.decode("ascii"),
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("queue", "worker", "status"))
    args = parser.parse_args()
    codec = shared()  # Guard before any command, state creation or account use.
    if args.action == "queue":
        value = codec.fields(
            command(["/usr/bin/linuractl", "own-session-lock"], owner=True)
        )
        if set(value) != {"resource"}:
            raise RuntimeError("native suspend fixture lock query is malformed")
        codec.lock_resource(value["resource"])
        STATE.mkdir(mode=0o700)  # No overwrite, reuse, deletion or automatic retry.
        pending = {
            "operation": "s17-native-suspend-" + secrets.token_hex(8),
            "resource": value["resource"],
        }
        write_record("pending.json", pending)
        command(
            [
                "/usr/bin/systemd-run",
                "--quiet",
                "--unit=linura-s17-suspend-case",
                "--property=Type=exec",
                "--property=RuntimeMaxSec=150",
                "--property=LimitCORE=0",
                "--property=UMask=0077",
                "--",
                "/usr/bin/python3",
                "-I",
                "-S",
                str(ROOT / "native-suspend-fixture.py"),
                "worker",
            ]
        )
        print(json.dumps(pending, sort_keys=True))  # Queue receipt only, NOT execution.
    elif args.action == "worker":
        try:
            worker(codec)
        except Exception:
            write_record("result.json", {"state": "failed"})
            raise RuntimeError(
                "native suspend fixture failed; no successful evidence"
            ) from None
    else:
        try:
            value = read_record("result.json", codec)
        except FileNotFoundError:
            value = {"state": "pending"}
        print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
