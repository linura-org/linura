#!/usr/bin/env python3
"""Fixed ephemeral password setup/cleanup ONLY in the disposable S17 guest.

No response is accepted in arguments, environment, logs or retained fixtures.
Distribution PAM/Polkit and production authority checks are never changed.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path("/opt/linura-source/qualification/v010/session-security")
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


def require_guest() -> None:
    if os.geteuid() != 0:
        raise RuntimeError(
            "native authentication fixture requires the root disposable guest"
        )
    for path in reversed(ROOT.parents):
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError(
                "native authentication fixture source is not root immutable"
            )
    for path in (ROOT,):
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError("native authentication fixture directory is untrusted")
    for name in ("native-auth-fixture.py", "provision-native-session.py"):
        metadata = (ROOT / name).lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or metadata.st_nlink != 1
        ):
            raise RuntimeError("native authentication fixture helper is untrusted")
    spec = importlib.util.spec_from_file_location(
        "s17_auth_provision", ROOT / "provision-native-session.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("native authentication fixture guest guard is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.require_disposable_guest()


def require_locked_fixture_account() -> None:
    path = Path("/etc/shadow")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o077
        or metadata.st_nlink != 1
    ):
        raise RuntimeError(
            "native authentication fixture account database is untrusted"
        )
    # Inspect only the fixed disposable account's lock marker. Never retain,
    # return or log a hash; an existing usable password refuses replacement.
    with path.open("rb") as source:
        for _ in range(4096):
            line = source.readline(4097)
            if not line or len(line) > 4096:
                break
            if line.startswith(b"linura:"):
                marker = line.split(b":", 2)[1]
                if marker.startswith((b"!", b"*")):
                    return
                break
    raise RuntimeError(
        "native authentication fixture account is not initially password-locked"
    )


def operate(action: str, response: bytes | None = None) -> None:
    require_guest()
    if action == "set-response":
        require_locked_fixture_account()
        if response is None or re.fullmatch(rb"[a-f0-9]{24}\n", response) is None:
            raise RuntimeError("native authentication fixture response is unsupported")
        arguments = ["/usr/bin/chpasswd"]
        payload = b"linura:" + response
    elif action == "clear-response" and response is None:
        arguments = ["/usr/bin/passwd", "--lock", "linura"]
        payload = None
    else:
        raise RuntimeError("unsupported fixed native authentication fixture action")
    try:
        result = subprocess.run(
            arguments,
            input=payload,
            env=ENVIRONMENT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError(
            "native authentication fixture account operation failed"
        ) from None
    if result.returncode != 0:
        raise RuntimeError(
            "native authentication fixture account operation was refused"
        )
    if action == "clear-response":
        # A subprocess acknowledgement is not proof the password lock returned.
        require_locked_fixture_account()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("set-response", "clear-response"))
    args = parser.parse_args()
    # Guard BEFORE accepting even bounded secret input in an unexpected context.
    require_guest()
    operate(
        args.action,
        sys.stdin.buffer.read(26) if args.action == "set-response" else None,
    )


if __name__ == "__main__":
    main()
