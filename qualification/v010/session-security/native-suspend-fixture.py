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


class CommandRefused(RuntimeError):
    def __init__(self, returncode: int, categories: str = "unclassified"):
        super().__init__("native suspend fixture command was refused")
        self.returncode = returncode
        self.categories = categories


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


def command(
    arguments: list[str], budget: float = 15, owner: bool = False, codec=None
) -> bytes:
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
        stderr=subprocess.PIPE,
        env=ENVIRONMENT,
        start_new_session=True,
        user=account.pw_uid if owner else None,
        group=account.pw_gid if owner else None,
        extra_groups=() if owner else None,
    )
    assert process.stdout is not None and process.stderr is not None
    wire = bytearray()
    diagnostics = bytearray()
    try:
        with selectors.DefaultSelector() as reader:
            reader.register(process.stdout, selectors.EVENT_READ)
            reader.register(process.stderr, selectors.EVENT_READ)
            while process.poll() is None or reader.get_map():
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "native suspend fixture command exceeded its original deadline"
                    )
                for key, _ in reader.select(0.05):
                    chunk = os.read(
                        key.fd, min(4096, LIMIT + 1 - len(wire) - len(diagnostics))
                    )
                    if not chunk:
                        reader.unregister(key.fileobj)
                    else:
                        (wire if key.fileobj is process.stdout else diagnostics).extend(
                            chunk
                        )
                        if len(wire) + len(diagnostics) > LIMIT:
                            raise RuntimeError(
                                "native suspend fixture command output exceeds its bound"
                            )
        if process.returncode != 0:
            raise CommandRefused(
                process.returncode,
                codec.failure_categories(diagnostics)
                if codec is not None
                else "unclassified",
            )
        return bytes(wire)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


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
        name
        not in {
            "pending.json",
            "submission.json",
            "result.json",
            "sync.json",
            "prompt-failure.json",
            "worker-failure.json",
        }
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
    if name not in {
        "pending.json",
        "submission.json",
        "result.json",
        "sync.json",
        "prompt-failure.json",
        "worker-failure.json",
    }:
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


def inventory_command(arguments: list[str], codec, deadline: float) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise codec.InventoryFailure("session-inventory-timeout")
    try:
        result = command(arguments, budget=min(15, remaining), codec=codec)
    except CommandRefused as error:
        category = (
            "session-list-refused"
            if arguments[1] == "list-sessions"
            else "session-properties-refused"
        )
        raise CommandRefused(error.returncode, category) from None
    if time.monotonic() >= deadline:
        raise codec.InventoryFailure("session-inventory-timeout")
    return result


def session_rows(codec, deadline: float) -> list[tuple[str, int]]:
    # The pinned loginctl table is presentation, not a machine protocol. JSON
    # preserves complete typed identities independently of glyphs or width.
    wire = inventory_command(
        ["/usr/bin/loginctl", "list-sessions", "--json=short", "--no-pager"],
        codec,
        deadline,
    )
    if len(wire) > LIMIT:
        raise codec.InventoryFailure("session-inventory-bound")
    try:
        rows = json.loads(wire, object_pairs_hook=codec.unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise codec.InventoryFailure("session-inventory-wire") from None
    if not isinstance(rows, list) or len(rows) > 16:
        raise codec.InventoryFailure("session-inventory-bound")
    seen = set()
    result = []
    for row in rows:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("session"), str)
            or re.fullmatch(r"[A-Za-z0-9]{1,64}", row["session"]) is None
            or row["session"] in seen
            or type(row.get("uid")) is not int
            or not 0 <= row["uid"] < 2**32 - 1
        ):
            raise codec.InventoryFailure("session-inventory-identity")
        seen.add(row["session"])
        result.append((row["session"], row["uid"]))
    return result


def session_facts(session: str, uid: int, codec, deadline: float) -> dict[str, str]:
    wire = inventory_command(
        [
            "/usr/bin/loginctl",
            "show-session",
            session,
            "--no-pager",
            "--property=Id",
            "--property=User",
            "--property=Class",
            "--property=Type",
            "--property=Active",
            "--property=Remote",
            "--property=State",
            "--property=TimestampMonotonic",
        ],
        codec,
        deadline,
    )
    try:
        facts = codec.fields(wire)
    except RuntimeError:
        raise codec.InventoryFailure("session-inventory-fields") from None
    if (
        set(facts)
        != {
            "Id",
            "User",
            "Class",
            "Type",
            "Active",
            "Remote",
            "State",
            "TimestampMonotonic",
        }
        or facts["Active"] not in {"yes", "no"}
        or facts["Remote"] not in {"yes", "no"}
        or facts["State"] not in {"opening", "online", "active", "closing"}
        or any(
            re.fullmatch(r"[A-Za-z0-9_-]{1,64}", facts[key]) is None
            for key in ("Class", "Type")
        )
        or re.fullmatch(r"[1-9][0-9]{0,19}", facts["TimestampMonotonic"]) is None
        or int(facts["TimestampMonotonic"]) >= 2**64
    ):
        raise codec.InventoryFailure("session-inventory-fields")
    if facts["Id"] != session or facts["User"] != str(uid):
        raise codec.InventoryFailure("session-inventory-drift")
    return facts


def only_target_session(resource: str, codec, deadline: float) -> bool:
    codec.lock_resource(resource)
    _, _, _, uid, session, created, _, _ = resource.split(":")
    found = False
    blocked = False
    for current, row_uid in session_rows(codec, deadline):
        facts = session_facts(current, row_uid, codec, deadline)
        if current == session:
            expected = {
                "Id": session,
                "User": uid,
                "Class": "user",
                "Type": "wayland",
                "Active": "yes",
                "Remote": "no",
                "State": "active",
                "TimestampMonotonic": created,
            }
            if facts != expected:
                raise codec.InventoryFailure("session-target-generation")
            found = True
        elif facts["Class"] in {
            "manager",
            "manager-early",
            "background",
            "background-light",
        }:
            # Mirror the canonical observer's same-owner service-session rule.
            # Foreign UID service sessions still block. This preflight grants
            # nothing: Control independently reobserves and authorizes power.
            blocked |= row_uid != int(uid)
        elif facts["Class"] in {
            "user",
            "user-early",
            "user-incomplete",
            "user-light",
            "user-early-light",
            "greeter",
            "lock-screen",
        }:
            blocked = True  # Closing, remote, inactive and same-UID logins too.
        else:
            raise codec.InventoryFailure("session-class-unsupported")
    if not found:
        raise codec.InventoryFailure("session-target-absent")
    return not blocked


def original_session_present(resource: str, codec, deadline: float) -> bool:
    codec.lock_resource(resource)
    _, _, _, uid, session, created, _, _ = resource.split(":")
    last_refusal = None
    while time.monotonic() < deadline:
        try:
            present = False
            for current, row_uid in session_rows(codec, deadline):
                if current == session:
                    facts = session_facts(current, row_uid, codec, deadline)
                    present = (
                        facts["User"] == uid and facts["TimestampMonotonic"] == created
                    )
                    break
            if time.monotonic() >= deadline:
                raise codec.InventoryFailure("session-inventory-timeout")
            return present
        except CommandRefused as error:
            last_refusal = error
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    if last_refusal is not None:
        raise last_refusal
    raise codec.InventoryFailure("session-inventory-timeout")


def wait_for_only_target_session(resource: str, codec, deadline: float) -> None:
    # A departing SSH login may disappear between enumeration and GetSession.
    # A refused read invalidates the WHOLE snapshot. Start a fresh enumeration,
    # within the original budget; never treat missing properties as absence.
    last_refusal = None
    while time.monotonic() < deadline:
        try:
            if only_target_session(resource, codec, deadline):
                if time.monotonic() >= deadline:
                    raise codec.InventoryFailure("session-inventory-timeout")
                return
            last_refusal = None
        except CommandRefused as error:
            last_refusal = error
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    if last_refusal is not None:
        raise last_refusal
    raise codec.InventoryFailure("session-other-login")


PROMPT_PHASES = {
    "suspend-prompt",
    "logout-prompt",
    "reboot-prompt",
    "power-off-prompt",
}
SYNC_PATTERN = re.compile(r"[0-9a-f]{32}")
SERIAL_DEVICE = Path("/dev/ttyS0")
SERIAL_PREFIX = "LINURA-S17-PROMPT-STATE"


def prompt_watch(codec, phase: str, token: str) -> None:
    if phase not in PROMPT_PHASES or SYNC_PATTERN.fullmatch(token) is None:
        raise RuntimeError("native prompt synchronization identity is unsupported")
    synchronization = read_record("sync.json", codec)
    if (
        set(synchronization) != {"phase", "token", "resource"}
        or synchronization["phase"] != phase
        or synchronization["token"] != token
        or not isinstance(synchronization["resource"], str)
    ):
        raise RuntimeError("native prompt synchronization record was substituted")
    resource = synchronization["resource"]
    codec.lock_resource(resource)
    deadline = time.monotonic() + 30
    probe = ROOT / "native-assistive-fixture.py"
    previous = None
    sequence = 0
    last_error = None
    owner_identity = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if last_error is not None:
                raise last_error
            raise RuntimeError("native protected prompt did not become ready")
        try:
            wire = command(
                ["/usr/bin/python3", "-I", "-S", str(probe), phase],
                budget=min(12, remaining),
                codec=codec,
            )
        except CommandRefused as error:
            last_error = error
            time.sleep(0.05)
            continue
        value = codec.validate_assistive_report(wire, resource, phase)
        identity = tuple(
            value[key]
            for key in (
                "native_owner_pid",
                "native_owner_invocation",
                "native_owner_start_ticks",
            )
        )
        if owner_identity is not None and identity != owner_identity:
            raise RuntimeError("native prompt owner changed across selection")
        owner_identity = identity
        prompt = codec.validate_power_prompt(value["native_prompt"])
        if time.monotonic() >= deadline:
            raise RuntimeError("native protected prompt exceeded its original deadline")
        if prompt != previous:
            sequence += 1
            if sequence > 9:
                raise RuntimeError("native prompt state exceeded its bound")
            serial_state(phase, token, sequence, prompt, deadline)
            previous = prompt
        if prompt["kind"] == "response":
            return
        time.sleep(0.05)


def serial_state(
    phase: str, token: str, sequence: int, prompt: dict, deadline: float
) -> None:
    descriptor = os.open(
        SERIAL_DEVICE,
        os.O_WRONLY | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISCHR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or os.major(metadata.st_rdev) != 4
            or os.minor(metadata.st_rdev) != 64
        ):
            raise RuntimeError(
                "native prompt synchronization serial device is unsupported"
            )
        # Complete, bounded, nonsecret metadata only. The host controls native
        # physical keys; this read-only watcher has no input or effect handle.
        wire = (
            f"\n{SERIAL_PREFIX} {phase} {token} {sequence} "
            f"{prompt['kind']} {prompt['uid']} {prompt['index']} {prompt['count']}\n"
        ).encode("ascii")
        offset = 0
        while offset < len(wire):
            if time.monotonic() >= deadline:
                raise RuntimeError("native prompt synchronization serial write expired")
            try:
                written = os.write(descriptor, wire[offset:])
            except BlockingIOError:
                time.sleep(0.01)
                continue
            if written <= 0:
                raise RuntimeError("native prompt synchronization serial write failed")
            offset += written
    finally:
        os.close(descriptor)


FAILURE_STAGE = "pending-record"
FAILURE_STAGES = {
    "pending-record",
    "session-inventory",
    "target-query",
    "submission",
    "completion-record",
    "prompt-watch",
}


def retain_failure(name: str, stage: str, error: Exception, codec) -> None:
    if (
        name not in {"prompt-failure.json", "worker-failure.json"}
        or stage not in FAILURE_STAGES
    ):
        raise RuntimeError("native power failure diagnostic scope is unsupported")
    categories = "unclassified"
    if isinstance(error, CommandRefused):
        categories = error.categories
    elif isinstance(error, codec.InventoryFailure):
        category = getattr(error, "category", None)
        if (
            not isinstance(category, str)
            or category not in codec.POWER_INVENTORY_FAILURES
        ):
            raise RuntimeError("native inventory failure category is unsupported")
        categories = category
    write_record(
        name,
        {
            "stage": stage,
            "exit": error.returncode if isinstance(error, CommandRefused) else None,
            "categories": categories,
        },
    )


def sleep_unit_diagnostics(codec) -> set[str]:
    """Closed current unit context only; never proof of an invocation or effect."""
    try:
        wire = command(
            [
                "/usr/bin/systemctl",
                "show",
                "systemd-suspend.service",
                "--no-pager",
                "--property=ActiveState",
                "--property=SubState",
                "--property=Result",
                "--property=ExecMainPID",
            ],
            budget=2,
        )
        if len(wire) > LIMIT:
            raise ValueError("diagnostic bound")
        rows = wire.decode("ascii").splitlines()
        pairs = [row.split("=", 1) for row in rows]
        if len(pairs) != 4 or any(len(pair) != 2 for pair in pairs):
            raise ValueError("diagnostic fields")
        fields = {pair[0]: pair[1] for pair in pairs}
        if set(fields) != {*codec.SLEEP_UNIT_DIAGNOSTIC_VALUES, "ExecMainPID"}:
            raise ValueError("diagnostic fields")
        labels = set()
        for key, values in codec.SLEEP_UNIT_DIAGNOSTIC_VALUES.items():
            if fields[key] not in values:
                raise ValueError("diagnostic enum")
            labels.add(f"sleep-unit-{key.lower()}-{fields[key]}")
        pid = fields["ExecMainPID"]
        if (
            re.fullmatch(r"0|[1-9][0-9]{0,9}", pid) is None
            or not 0 <= int(pid) <= 0xFFFFFFFF
            or pid == "1"
        ):
            raise ValueError("diagnostic process")
        labels.add(
            "sleep-unit-main-pid-zero" if pid == "0" else "sleep-unit-main-pid-present"
        )
        return labels
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
        return {"sleep-unit-diagnostics-unavailable"}


def failure_diagnostics(codec) -> dict:
    records = {}
    for name in ("prompt-failure.json", "worker-failure.json"):
        try:
            records[name] = read_record(name, codec)
        except FileNotFoundError:
            records[name] = None
    worker = records["worker-failure.json"]
    if (
        STATE == Path("/run/linura-s17-suspend-case")
        and isinstance(worker, dict)
        and worker.get("stage") == "submission"
        and isinstance(worker.get("categories"), str)
    ):
        # Current-boot failure context only, never an invocation attestation or
        # postcondition. No raw journal bytes leave this root fixture. Preserve
        # the original failure even if bounded read-only diagnostics fail.
        labels = {"sleep-gate-diagnostics-unavailable"}
        try:
            wire = command(
                [
                    "/usr/bin/journalctl",
                    "--boot=0",
                    "--no-pager",
                    "--quiet",
                    "--output=cat",
                    "--lines=64",
                    "--unit=systemd-suspend.service",
                    "--unit=linura-authorityd.service",
                    "--unit=linura-security-owner@1000.service",
                ],
                budget=3,
            )
            if len(wire) > LIMIT:
                raise RuntimeError("native sleep diagnostic output exceeds its bound")
            labels = {
                label
                for label, marker in codec.SLEEP_GATE_FAILURE_MARKERS
                if marker in wire
            }
        except (RuntimeError, OSError, subprocess.SubprocessError):
            pass
        labels.update(sleep_unit_diagnostics(codec))
        categories = ",".join(sorted(set(worker["categories"].split(",")) | labels))
        if len(categories) <= 4096:
            records["worker-failure.json"] = {**worker, "categories": categories}
    return {"claim": "failure-diagnostics-only", "records": records}


def start_prompt_watch(
    phase: str, token: str, unit: str, state_purpose: str | None = None
) -> None:
    if (
        phase not in PROMPT_PHASES
        or SYNC_PATTERN.fullmatch(token) is None
        or re.fullmatch(r"linura-s17-[a-z0-9-]+-prompt", unit) is None
        or state_purpose not in {None, "logout", "reboot", "power-off"}
    ):
        raise RuntimeError("native prompt watcher launch is unsupported")
    arguments = [
        "/usr/bin/systemd-run",
        "--quiet",
        "--unit=" + unit,
        "--property=Type=exec",
        "--property=RuntimeMaxSec=45",
        "--property=LimitCORE=0",
        "--property=UMask=0077",
        "--",
        "/usr/bin/python3",
        "-I",
        "-S",
        str(ROOT / "native-suspend-fixture.py"),
        "prompt-watch",
        "--phase",
        phase,
        "--sync-token",
        token,
    ]
    if state_purpose is not None:
        arguments.extend(["--state-purpose", state_purpose])
    command(arguments)


def worker(codec) -> None:
    global FAILURE_STAGE
    FAILURE_STAGE = "pending-record"
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
    FAILURE_STAGE = "session-inventory"
    deadline = time.monotonic() + 20
    wait_for_only_target_session(resource, codec, deadline)
    FAILURE_STAGE = "target-query"
    target = codec.fields(
        command(
            ["/usr/bin/linuractl", "own-session-transition", "suspend"],
            owner=True,
            codec=codec,
        )
    )
    if set(target) != {"resource"}:
        raise RuntimeError("native suspend fixture target query is malformed")
    FAILURE_STAGE = "submission"
    # Write-once admission also prevents a restarted suspend worker from replaying.
    write_record("submission.json", {"state": "submitting", **pending})
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
        codec=codec,
    )
    FAILURE_STAGE = "completion-record"
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
    parser.add_argument(
        "action", choices=("queue", "worker", "status", "prompt-watch", "diagnostics")
    )
    parser.add_argument("--sync-token")
    parser.add_argument("--phase", choices=sorted(PROMPT_PHASES))
    parser.add_argument("--state-purpose", choices=("logout", "reboot", "power-off"))
    args = parser.parse_args()
    codec = shared()  # Guard before any command, state creation or account use.
    if args.action == "prompt-watch":
        if args.sync_token is None or args.phase is None:
            raise RuntimeError(
                "native prompt watcher requires an exact phase and token"
            )
        if args.state_purpose is not None:
            select_terminating_case(args.state_purpose)
        try:
            prompt_watch(codec, args.phase, args.sync_token)
        except Exception as error:
            retain_failure("prompt-failure.json", "prompt-watch", error, codec)
            raise RuntimeError(
                "native prompt watcher failed; no positive evidence"
            ) from None
        return
    if args.phase is not None or args.state_purpose is not None:
        raise RuntimeError("native suspend fixture received prompt-only arguments")
    if args.action != "queue" and args.sync_token is not None:
        raise RuntimeError(
            "native suspend fixture received an unused synchronization token"
        )
    if args.action == "queue":
        if args.sync_token is None or SYNC_PATTERN.fullmatch(args.sync_token) is None:
            raise RuntimeError(
                "native suspend queue requires a canonical synchronization token"
            )
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
        write_record(
            "sync.json",
            {
                "phase": "suspend-prompt",
                "token": args.sync_token,
                "resource": pending["resource"],
            },
        )
        start_prompt_watch(
            "suspend-prompt",
            args.sync_token,
            "linura-s17-suspend-prompt",
        )
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
        except Exception as error:
            retain_failure("worker-failure.json", FAILURE_STAGE, error, codec)
            write_record("result.json", {"state": "failed"})
            raise RuntimeError(
                "native suspend fixture failed; no successful evidence"
            ) from None
    elif args.action == "diagnostics":
        print(json.dumps(failure_diagnostics(codec), sort_keys=True))
    else:
        try:
            value = read_record("result.json", codec)
        except FileNotFoundError:
            value = {"state": "pending"}
        print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
