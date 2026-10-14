#!/usr/bin/env python3
"""Real same-UID process-access probes inside the dedicated disposable VM only.

This never reads protected process memory, input or environment values. A denied
open/attach is the measured result. It does not qualify PAM or complete S17.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys


ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
SOURCE_ROOT = Path("/opt/linura-source")


def bounded_command(arguments: list[str]) -> str:
    result = subprocess.run(
        arguments,
        env=ENVIRONMENT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout) > 16384:
        raise RuntimeError("native probe fact is unavailable")
    return result.stdout.decode("ascii").strip()


def require_guest() -> int:
    uid = os.getuid()
    if (
        uid == 0
        or os.getresuid() != (uid, uid, uid)
        or pwd.getpwnam("linura").pw_uid != uid
    ):
        raise RuntimeError(
            "native attack probe requires the unprivileged fixture owner"
        )
    if (
        bounded_command(["/usr/bin/systemd-detect-virt", "--vm"]) not in {"qemu", "kvm"}
        or socket.gethostname() != "linura-v010-shell"
    ):
        raise RuntimeError("native attack probe refuses other hosts")
    if "ID=arch\n" not in Path("/etc/os-release").read_text(encoding="ascii"):
        raise RuntimeError("native attack probe requires the pinned Arch guest")
    # Refuse to exercise ptrace from user-writable/copied qualification code.
    if (
        Path(__file__)
        != SOURCE_ROOT / "qualification/v010/session-security/probe-same-uid.py"
    ):
        raise RuntimeError("native attack probe requires the exact-source fixture")
    for path in (
        Path("/opt"),
        SOURCE_ROOT,
        SOURCE_ROOT / "qualification",
        SOURCE_ROOT / "qualification/v010",
        SOURCE_ROOT / "qualification/v010/session-security",
    ):
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError("native attack probe source is not root immutable")
    metadata = Path(__file__).lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or metadata.st_nlink != 1
    ):
        raise RuntimeError("native attack probe source is not root immutable")
    if (
        Path("/proc/sys/kernel/yama/ptrace_scope").read_text(encoding="ascii").strip()
        != "0"
    ):
        raise RuntimeError(
            "native probe must not mistake Yama denial for owner protection"
        )
    return uid


def service_identity(uid: int) -> tuple[int, str]:
    reply = bounded_command(
        [
            "/usr/bin/systemctl",
            "show",
            f"linura-security-owner@{uid}.service",
            "--property=MainPID,InvocationID,ActiveState,SubState",
            "--no-pager",
        ]
    )
    fields = {}
    for line in reply.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise RuntimeError("native owner service identity is malformed")
        fields[key] = value
    if (
        set(fields) != {"MainPID", "InvocationID", "ActiveState", "SubState"}
        or fields["ActiveState"] != "active"
        or fields["SubState"] != "running"
    ):
        raise RuntimeError("native owner is not supervised and running")
    if (
        re.fullmatch(r"[1-9][0-9]{0,9}", fields["MainPID"]) is None
        or re.fullmatch(r"[0-9a-f]{32}", fields["InvocationID"]) is None
    ):
        raise RuntimeError("native owner process identity is noncanonical")
    pid = int(fields["MainPID"])
    if pid <= 1 or pid > 2**31 - 1:
        raise RuntimeError("native owner PID is unsupported")
    return pid, fields["InvocationID"]


def process_state(pid: int, uid: int) -> str:
    with Path(f"/proc/{pid}/status").open(encoding="ascii") as source:
        text = source.read(16385)
    if len(text) > 16384:
        raise RuntimeError("native process status exceeds its bound")
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator or key in fields:
            raise RuntimeError("native process status is malformed")
        fields[key] = value.strip()
    if (
        fields.get("Uid", "").split() != [str(uid)] * 4
        or fields.get("TracerPid") != "0"
        or any(
            fields.get(name) != "0000000000000000"
            for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")
        )
    ):
        raise RuntimeError("native owner credentials/tracer state is unsuitable")
    with Path(f"/proc/{pid}/stat").open(encoding="ascii") as source:
        record = source.read(4097)
    # Field 22 after the bounded process comm; do not split comm on spaces.
    suffix = record.rsplit(") ", 1)
    if len(record) > 4096 or len(suffix) != 2 or len(suffix[1].split()) < 20:
        raise RuntimeError("native owner generation is unavailable")
    start = suffix[1].split()[19]
    if re.fullmatch(r"[1-9][0-9]{0,19}", start) is None:
        raise RuntimeError("native owner generation is noncanonical")
    return start


def denied_open(path: Path) -> bool:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        )
    except OSError as error:
        return error.errno in {errno.EPERM, errno.EACCES}
    else:
        os.close(descriptor)  # Never read even when the protection failed.
        return False


def probe() -> dict[str, object]:
    uid = require_guest()
    identity = service_identity(uid)
    pid, invocation = identity
    generation = process_state(pid, uid)
    checks = {
        f"same-uid-{name}-open-denied": denied_open(Path(f"/proc/{pid}/{name}"))
        for name in ("mem", "environ", "auxv")
    }
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    libc.ptrace.restype = ctypes.c_long
    ctypes.set_errno(0)
    # SEIZE does not stop the owner. No EXITKILL option, memory read/write,
    # signal injection or ptrace resume is used. If unexpectedly permitted,
    # this short-lived probe exits and the kernel detaches its tracee.
    result = libc.ptrace(0x4206, pid, None, None)
    checks["same-uid-ptrace-seize-denied"] = (
        result == -1 and ctypes.get_errno() == errno.EPERM
    )
    if not all(checks.values()):
        raise RuntimeError("native owner same-UID protection failed")
    if service_identity(uid) != identity or process_state(pid, uid) != generation:
        raise RuntimeError("native owner changed during adversarial probes")
    return {
        "schema_version": 1,
        "claim": "native-same-uid-process-access-cases-only",
        "native_owner_pid": pid,
        "native_owner_invocation": invocation,
        "owner_start_ticks": generation,
        "ptrace_scope": 0,
        "checks": checks,
        "s17_complete": False,
        "native_authentication_qualified": False,
        "release_support_promotion": False,
    }


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        print(json.dumps(probe(), sort_keys=True))
        return 0
    except Exception:
        # Only fixed diagnostics, including unexpected native failures.
        print("native same-UID protection probe failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
