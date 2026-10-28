#!/usr/bin/env python3
"""Exercise real S17 first-login bootstrap, NOT complete security qualification."""

from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import time


ROOT = Path(__file__).resolve().parent
SLEEP_GATE_ASSETS = (
    (
        "packaging/systemd/system/systemd-suspend.service.d/50-linura-protective-lock.conf",
        "usr/lib/systemd/system/systemd-suspend.service.d/50-linura-protective-lock.conf",
    ),
    (
        "packaging/systemd/sleep.conf.d/50-linura-qualified-sleep.conf",
        "usr/lib/systemd/sleep.conf.d/50-linura-qualified-sleep.conf",
    ),
    (
        "packaging/dbus-1/system.d/org.linura.Authority1.conf",
        "usr/share/dbus-1/system.d/org.linura.Authority1.conf",
    ),
    (
        "interfaces/dbus/org.linura.SleepGate1.xml",
        "usr/share/dbus-1/interfaces/org.linura.SleepGate1.xml",
    ),
)


def bounded_asset(path: Path) -> bytes:
    # A missing/mutable/link-substituted installation is not deployment evidence.
    for parent in reversed(path.parents):
        metadata = parent.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError("native sleep asset ancestor is not root immutable")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or metadata.st_size > 65536
    ):
        raise RuntimeError("native sleep asset is not a bounded root immutable file")
    with path.open("rb") as source:
        data = source.read(65537)
    if len(data) > 65536 or len(data) != metadata.st_size:
        raise RuntimeError("native sleep asset changed or exceeds its bound")
    return data


def inspect_sleep_gate_assets() -> dict[str, str]:
    # Called only AFTER the disposable-guest guard. This asserts actual installed
    # bytes, never PAM, lock coverage, enforcement or successful suspend/resume.
    source_root = Path("/opt/linura-source")
    installed_root = Path("/")
    digests: dict[str, str] = {}
    for source, installed in SLEEP_GATE_ASSETS:
        expected = bounded_asset(source_root / source)
        actual = bounded_asset(installed_root / installed)
        if actual != expected:
            raise RuntimeError(
                "native sleep gate installation differs from exact source"
            )
        digests[installed] = hashlib.sha256(actual).hexdigest()
    return digests


def command(*args: str) -> str:
    result = subprocess.check_output(args, text=True, timeout=10)
    if len(result.encode("utf-8")) > 65536:
        raise RuntimeError("native qualification reply exceeds its bound")
    return result.strip()


def properties(*args: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in command(*args).splitlines():
        key, delimiter, value = line.partition("=")
        if not delimiter or not key or key in values:
            raise RuntimeError("native qualification properties are malformed")
        values[key] = value
    return values


def validate_session(facts: dict[str, str], uid: int, leader: int) -> None:
    required = {
        "User": str(uid),
        "Leader": str(leader),
        "Type": "wayland",
        "Class": "user",
        "State": "active",
        "Active": "yes",
        "Remote": "no",
        "Seat": "seat0",
        "VTNr": "1",
        "Service": "linura-s17-qualification",
    }
    if any(facts.get(key) != value for key, value in required.items()):
        raise RuntimeError(
            "real native session does not satisfy the S17 bootstrap contract"
        )
    if re.fullmatch(r"[A-Za-z0-9]{1,64}", facts.get("Id", "")) is None:
        raise RuntimeError("native session identity is unsupported")
    if re.fullmatch(r"[1-9][0-9]{0,19}", facts.get("TimestampMonotonic", "")) is None:
        raise RuntimeError("native session generation is absent or noncanonical")


# Independent guest-side attestation of the exact distribution daemon profile.
# This is required before accepting native owner bootstrap, not a substitute
# for the owner's D-Bus/systemd peer guard or an authorization decision.
POLKIT_IMAGE = "/usr/lib/polkit-1/polkitd"
POLKIT_ARGV = (POLKIT_IMAGE, "--no-debug", "--log-level=notice")


def validate_native_polkit_process(
    facts: dict[str, str], cmdline: bytes, status: dict[str, str], uid: int
) -> dict[str, object]:
    required = {
        "ActiveState": "active",
        "SubState": "running",
        "FragmentPath": "/usr/lib/systemd/system/polkit.service",
        "DropInPaths": "",
    }
    if any(facts.get(name) != value for name, value in required.items()):
        raise RuntimeError("native Polkit supervised service identity differs")
    pid_text = facts.get("MainPID", "")
    if re.fullmatch(r"[1-9][0-9]{0,9}", pid_text) is None or int(pid_text) <= 1:
        raise RuntimeError("native Polkit supervised PID is invalid")
    invocation = facts.get("InvocationID", "")
    if re.fullmatch(r"[0-9a-f]{32}", invocation) is None or invocation == "0" * 32:
        raise RuntimeError("native Polkit invocation is not fresh and canonical")
    if not 0 < uid < 2**32 or not cmdline.endswith(b"\x00"):
        raise RuntimeError("native Polkit process credentials are invalid")
    expected_command = (
        b"\x00".join(word.encode("ascii") for word in POLKIT_ARGV) + b"\x00"
    )
    if cmdline != expected_command or len(cmdline) > 512:
        raise RuntimeError("native Polkit process argv differs from pinned launch")
    if status.get("Uid", "").split() != [str(uid)] * 4:
        raise RuntimeError(
            "native Polkit process UID differs from local service account"
        )
    if (
        len(facts.get("ExecStart", "")) > 4096
        or facts.get("ExecStart", "").count("{") != 1
        or facts.get("ExecStart", "").count("}") != 1
    ):
        raise RuntimeError("native Polkit systemd launch metadata is malformed")
    start = facts["ExecStart"]
    if not start.startswith("{") or not start.endswith("}"):
        raise RuntimeError("native Polkit systemd launch metadata is malformed")
    entries: dict[str, str] = {}
    for entry in start[1:-1].split(";"):
        key, separator, value = entry.strip().partition("=")
        if not separator or key in entries or not key:
            raise RuntimeError("native Polkit systemd launch metadata is ambiguous")
        entries[key] = value.strip()
    if (
        entries.get("path") != POLKIT_IMAGE
        or entries.get("argv[]") != " ".join(POLKIT_ARGV)
        or entries.get("ignore_errors") != "no"
        or entries.get("pid") != pid_text
    ):
        raise RuntimeError("native Polkit systemd argv differs from running daemon")
    return {
        "pid": int(pid_text),
        "uid": uid,
        "invocation": invocation,
        "image": POLKIT_IMAGE,
        "argv": list(POLKIT_ARGV),
    }


def inspect_native_polkit() -> dict[str, object]:
    # Called only from inspect() after the disposable-guest guard. Compare the
    # running kernel process and the supervised systemd record, not the unit
    # filename alone. No authorization credentials or PAM responses are read.
    query = (
        "systemctl",
        "show",
        "polkit.service",
        "--no-pager",
        "--property=ActiveState,SubState,FragmentPath,DropInPaths,"
        "MainPID,InvocationID,ExecStart",
    )
    facts = properties(*query)
    pid_text = facts.get("MainPID", "")
    if re.fullmatch(r"[1-9][0-9]{0,9}", pid_text) is None:
        raise RuntimeError("native Polkit daemon has no supervised process")
    pid = int(pid_text)
    image = Path(POLKIT_IMAGE)
    for path in (Path("/usr/lib/systemd/system/polkit.service"), image):
        for parent in reversed(path.parents):
            metadata = parent.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & 0o022
            ):
                raise RuntimeError("native Polkit binary/unit parent is mutable")
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError("native Polkit binary/unit is mutable or substituted")
    if Path(f"/proc/{pid}/exe").resolve() != image:
        raise RuntimeError("native Polkit executing image differs from systemd")
    proc_cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    expected_uid = command("id", "-u", "polkitd")
    if re.fullmatch(r"[1-9][0-9]{0,9}", expected_uid) is None:
        raise RuntimeError("native Polkit local service user is missing")
    verified = validate_native_polkit_process(
        facts,
        proc_cmdline,
        properties_from_proc(Path(f"/proc/{pid}/status")),
        int(expected_uid),
    )
    fresh = properties(*query)
    if any(
        fresh.get(key) != facts.get(key)
        for key in ("MainPID", "InvocationID", "ExecStart", "ActiveState", "SubState")
    ):
        raise RuntimeError(
            "native Polkit supervised identity changed during inspection"
        )
    return verified


def automatic_watcher_state(wire: str) -> tuple[str, str]:
    # Only fixed systemd categories may enter failure diagnostics. Never retain
    # arbitrary property values, unit names, process arguments or journal text.
    if len(wire) > 128:
        raise RuntimeError("automatic native owner watcher reply exceeds its bound")
    values: dict[str, str] = {}
    for line in wire.splitlines():
        name, separator, value = line.partition("=")
        if not separator or name in values:
            raise RuntimeError("automatic native owner watcher reply is malformed")
        values[name] = value
    if (
        set(values) != {"ActiveState", "Result"}
        or values["ActiveState"]
        not in {"active", "inactive", "activating", "deactivating", "failed"}
        or values["Result"]
        not in {
            "success",
            "resources",
            "start-limit-hit",
            "unit-start-limit-hit",
            "trigger-limit-hit",
        }
    ):
        raise RuntimeError("automatic native owner watcher state is unsupported")
    return values["ActiveState"], values["Result"]


def wait_for_automatic_watcher(uid: int) -> None:
    # user@ can become active before its ordered dependent path has started.
    # Observe readiness within the original ten-second allowance; never start,
    # reset or enable the watcher to manufacture automatic activation.
    deadline = time.monotonic() + 10
    for _ in range(100):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        result = subprocess.run(
            [
                "systemctl",
                "show",
                "--property=ActiveState,Result",
                f"linura-security-owner@{uid}.path",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=remaining,
        )
        if time.monotonic() >= deadline:
            break
        if result.returncode != 0:
            raise RuntimeError("automatic native owner watcher observation failed")
        state, outcome = automatic_watcher_state(result.stdout)
        if state == "active" and outcome == "success":
            return
        if (
            state not in {"inactive", "activating", "deactivating"}
            or outcome != "success"
        ):
            raise RuntimeError(
                "automatic native owner watcher is unavailable: "
                f"state={state}; result={outcome}"
            )
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    raise RuntimeError("automatic native owner watcher readiness timed out")


def inspect() -> dict[str, object]:
    spec = importlib.util.spec_from_file_location(
        "s17_guest_provision", ROOT / "provision-native-session.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("disposable guest guard is missing")
    provision = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provision)
    provision.require_disposable_guest()
    uid_text = command("id", "-u", "linura")
    if re.fullmatch(r"[1-9][0-9]{3,9}", uid_text) is None:
        raise RuntimeError("qualification owner UID is unsupported")
    uid = int(uid_text)
    if uid >= 2**32:
        raise RuntimeError("qualification UID exceeds the native contract")
    # Recreate first-login ordering. Do not manually enable/start the owner's
    # watcher: its installed root user@ dependency is the production mechanism.
    subprocess.run(["loginctl", "disable-linger", "linura"], check=True, timeout=15)
    subprocess.run(
        ["systemctl", "restart", f"user@{uid}.service"], check=True, timeout=30
    )
    wait_for_automatic_watcher(uid)
    subprocess.run(
        ["systemctl", "start", "linura-s17-session.service"], check=True, timeout=30
    )
    leader = int(
        command(
            "systemctl",
            "show",
            "--property=MainPID",
            "--value",
            "linura-s17-session.service",
        )
    )
    if leader <= 1 or Path(f"/proc/{leader}/exe").resolve() != Path(
        "/usr/bin/Hyprland"
    ):
        raise RuntimeError("the real compositor is not the service's executing leader")
    native_display_candidate = provision.inspect_display_candidate(leader)
    deadline = time.monotonic() + 20
    facts: dict[str, str] | None = None
    while time.monotonic() < deadline:
        rows = command(
            "loginctl", "list-sessions", "--no-legend", "--no-pager"
        ).splitlines()
        if len(rows) > 16:
            raise RuntimeError("native session enumeration is ambiguous")
        candidates = []
        for row in rows:
            session = row.split()[0]
            if re.fullmatch(r"[A-Za-z0-9]{1,64}", session) is None:
                raise RuntimeError("native session handle is unsupported")
            state = properties("loginctl", "show-session", session, "--no-pager")
            if state.get("Service") == "linura-s17-qualification":
                candidates.append(state)
        if len(candidates) > 1:
            raise RuntimeError("duplicate native qualification sessions")
        if candidates:
            subprocess.run(
                ["loginctl", "activate", candidates[0]["Id"]], check=True, timeout=10
            )
            facts = properties(
                "loginctl", "show-session", candidates[0]["Id"], "--no-pager"
            )
            validate_session(facts, uid, leader)
            break
        time.sleep(0.1)
    if facts is None:
        raise RuntimeError("no genuine PAM/logind session appeared")
    lock = ""
    while time.monotonic() < deadline:
        query = subprocess.run(
            ["runuser", "-u", "linura", "--", "/usr/bin/linuractl", "own-session-lock"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        if query.returncode == 0:
            lock = query.stdout.strip()
            break
        time.sleep(0.1)
    invocation = command(
        "systemctl",
        "show",
        "--property=InvocationID",
        "--value",
        f"linura-security-owner@{uid}.service",
    )
    if re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
        raise RuntimeError("native owner invocation is missing")
    uuid = f"{invocation[:8]}-{invocation[8:12]}-{invocation[12:16]}-{invocation[16:20]}-{invocation[20:]}"
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    expected = f"resource=session:lock:{boot}:{uid}:{facts['Id']}:{facts['TimestampMonotonic']}:{uuid}:1"
    if not lock:
        raise RuntimeError(
            "native security owner did not publish an own-session identity"
        )
    if lock != expected:
        raise RuntimeError(
            "public own-session identity does not match the real native bootstrap"
        )
    # This strict guard remains part of the actual production startup.
    capability = command(
        "/usr/bin/getcap", "-n", "/usr/lib/linura/linura-security-owner"
    )
    if capability != "/usr/lib/linura/linura-security-owner cap_ipc_lock=ep":
        raise RuntimeError(
            "native owner capability is not the fixed secure-exec contract"
        )
    owner_pid = int(
        command(
            "systemctl",
            "show",
            "--property=MainPID",
            "--value",
            f"linura-security-owner@{uid}.service",
        )
    )
    owner_status = properties_from_proc(Path(f"/proc/{owner_pid}/status"))
    if owner_status.get("NoNewPrivs") != "0" or any(
        owner_status.get(name) != "0000000000000000"
        for name in ("CapInh", "CapPrm", "CapEff", "CapAmb")
    ):
        raise RuntimeError(
            "native owner did not enter the required post-drop process state"
        )
    # The automatically activated owner requires and orders polkit.service.
    # A cold boot has no provisioning-time daemon; attest its fresh supervised
    # identity after that normal activation, before accepting any bootstrap.
    native_polkit = inspect_native_polkit()
    return {
        "schema_version": 1,
        "claim": "native-session-bootstrap-only",
        "session": facts,
        "compositor_pid": leader,
        "native_display_compositor_build": native_display_candidate,
        "native_owner_pid": owner_pid,
        "native_polkit_supervision": native_polkit,
        "lock_resource": lock.removeprefix("resource="),
        "file_capability": capability,
        "automatic_owner_activation": True,
        "native_sleep_gate_installed_asset_digests": inspect_sleep_gate_assets(),
        "native_sleep_gate_enforcement_qualified": False,
        "native_authentication_qualified": False,
        "s17_complete": False,
        "release_support_promotion": False,
    }


def properties_from_proc(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="ascii")
    if len(text) > 16384:
        raise RuntimeError("native process status exceeds its bound")
    return dict(
        (key, value.strip())
        for key, separator, value in (line.partition(":") for line in text.splitlines())
        if separator
    )


if __name__ == "__main__":
    print(json.dumps(inspect(), indent=2, sort_keys=True))
