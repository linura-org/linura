#!/usr/bin/env python3
"""Actual managed suspend/resume and observe-only recovery on the pinned guest.

No direct native suspend, inhibitor bypass, alternate PAM or replay. This subset
is not logout/reboot/power-off, physical Q11, or complete S17 evidence.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parent
HELPER = "sudo -n /usr/bin/python3 -I -S /opt/linura-source/qualification/v010/session-security/native-suspend-fixture.py "
PREFIX = "sudo -n runuser -u linura -- /usr/bin/linuractl "
SERIAL_PREFIX = b"LINURA-S17-PROMPT-STATE"
SYNC_PATTERN = re.compile(r"[0-9a-f]{32}")
PROMPT_PHASES = {
    "suspend": "suspend-prompt",
    "logout": "logout-prompt",
    "reboot": "reboot-prompt",
    "power-off": "power-off-prompt",
}


class PromptLog:
    def __init__(self, path: Path):
        if not path.is_absolute():
            raise RuntimeError("native prompt synchronization log path is unsupported")
        self._descriptor = -1
        try:
            self._descriptor = os.open(
                path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            )
            metadata = os.fstat(self._descriptor)
            self._offset = os.lseek(self._descriptor, 0, os.SEEK_END)
        except OSError:
            self.close()
            raise RuntimeError(
                "native prompt synchronization log is unavailable"
            ) from None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
        ):
            self.close()
            raise RuntimeError("native prompt synchronization log is untrusted")
        self._identity = (metadata.st_dev, metadata.st_ino)

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def wait(
        self, phase: str, token: str, resource: str, native_input, budget: float = 35
    ) -> None:
        codec.lock_resource(resource)
        owner_uid = int(resource.split(":")[3])
        if (
            phase not in PROMPT_PHASES.values()
            or SYNC_PATTERN.fullmatch(token) is None
            or not 0 < budget <= 40
        ):
            raise RuntimeError("native prompt synchronization request is unsupported")
        prefix = (
            SERIAL_PREFIX + b" " + phase.encode("ascii") + b" " + token.encode("ascii")
        )
        deadline = time.monotonic() + budget
        retained = bytearray()
        processed = 0
        sequence = 0
        choices: list[int] = []
        count = None
        selected = False
        while time.monotonic() < deadline:
            try:
                metadata = os.fstat(self._descriptor)
            except OSError:
                raise RuntimeError(
                    "native prompt synchronization log is unavailable"
                ) from None
            if (
                metadata.st_dev,
                metadata.st_ino,
            ) != self._identity or (
                metadata.st_size < self._offset
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o022
            ):
                raise RuntimeError("native prompt synchronization log changed")
            if metadata.st_size > self._offset:
                amount = min(16384, metadata.st_size - self._offset)
                try:
                    chunk = os.pread(self._descriptor, amount, self._offset)
                except OSError:
                    raise RuntimeError(
                        "native prompt synchronization log is unavailable"
                    ) from None
                if not chunk:
                    raise RuntimeError(
                        "native prompt synchronization log became unreadable"
                    )
                self._offset += len(chunk)
                retained.extend(chunk)
                if len(retained) > 256 * 1024:
                    raise RuntimeError(
                        "native prompt synchronization log exceeded its bound"
                    )
                while (end := retained.find(b"\n", processed)) >= 0:
                    line = bytes(retained[processed:end]).removesuffix(b"\r")
                    processed = end + 1
                    if not line.startswith(prefix + b" "):
                        continue
                    fields = line[len(prefix) + 1 :].split(b" ")
                    if len(fields) != 5 or any(
                        re.fullmatch(rb"0|[1-9][0-9]{0,9}", fields[i]) is None
                        for i in (0, 2, 3, 4)
                    ):
                        raise RuntimeError(
                            "native prompt synchronization state is malformed"
                        )
                    try:
                        prompt = codec.validate_power_prompt(
                            {
                                "kind": fields[1].decode("ascii"),
                                "uid": int(fields[2]),
                                "index": int(fields[3]),
                                "count": int(fields[4]),
                            }
                        )
                    except (UnicodeError, ValueError):
                        raise RuntimeError(
                            "native prompt synchronization state is malformed"
                        ) from None
                    sequence += 1
                    if (
                        int(fields[0]) != sequence
                        or sequence > 9
                        or time.monotonic() >= deadline
                    ):
                        raise RuntimeError(
                            "native prompt synchronization sequence changed or expired"
                        )
                    if prompt["kind"] == "response":
                        if prompt["uid"] != owner_uid or (choices and not selected):
                            raise RuntimeError(
                                "native password prompt is for another identity"
                            )
                        return
                    if (
                        selected
                        or prompt["index"] != len(choices) + 1
                        or prompt["uid"] in choices
                        or (count is not None and prompt["count"] != count)
                    ):
                        raise RuntimeError(
                            "native administrator selection changed or repeated"
                        )
                    count = prompt["count"]
                    choices.append(prompt["uid"])
                    if prompt["uid"] == owner_uid:
                        selected = True
                        native_input.key("ret")
                    elif len(choices) < count:
                        native_input.key("down")
                    else:
                        raise RuntimeError(
                            "native administrator selection excludes the fixture owner"
                        )
            time.sleep(0.05)
        raise RuntimeError("native protected prompt readiness exceeded its deadline")


def load(name: str):
    spec = importlib.util.spec_from_file_location(
        "s17_suspend_" + name.replace("-", "_"), ROOT / (name + ".py")
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("native suspend qualification dependency is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


codec = load("qualify-native-auth")


def report(wire: bytes) -> dict:
    if len(wire) > codec.MAXIMUM_OUTPUT:
        raise RuntimeError("native suspend report exceeds its bound")
    try:
        value = json.loads(wire, object_pairs_hook=codec.unique_object)
    except (ValueError, RecursionError):
        raise RuntimeError("native suspend report is malformed") from None
    if not isinstance(value, dict):
        raise RuntimeError("native suspend report is malformed")
    return value


def failure_diagnostics(guest, command: str) -> None:
    try:
        value = report(guest.run(command))
        if (
            set(value) != {"claim", "records"}
            or value["claim"] != "failure-diagnostics-only"
            or not isinstance(value["records"], dict)
            or set(value["records"]) != {"prompt-failure.json", "worker-failure.json"}
        ):
            raise RuntimeError("native power failure diagnostics are unsupported")
        labels = (
            {label for label, _ in codec.FAILURE_MARKERS}
            | codec.POWER_INVENTORY_FAILURES
            | {"unclassified"}
        )
        for record in value["records"].values():
            if record is None:
                continue
            if (
                not isinstance(record, dict)
                or set(record) != {"stage", "exit", "categories"}
                or record["stage"]
                not in {
                    "pending-record",
                    "session-inventory",
                    "target-query",
                    "submission",
                    "completion-record",
                    "prompt-watch",
                }
                or (
                    record["exit"] is not None
                    and (
                        type(record["exit"]) is not int
                        or not -64 <= record["exit"] <= 255
                    )
                )
                or not isinstance(record["categories"], str)
                or not record["categories"]
                or len(record["categories"]) > 4096
                or any(label not in labels for label in record["categories"].split(","))
            ):
                raise RuntimeError("native power failure diagnostics are unsupported")
    except (RuntimeError, OSError, TypeError):
        value = {"claim": "failure-diagnostics-only", "unavailable": True}
    print(
        "native-power-failure-state=" + json.dumps(value, sort_keys=True),
        file=sys.stderr,
    )


def validate_receipt(
    wire: bytes, operation: str, target: str, resource: str, recovered: bool
) -> dict[str, str]:
    prefix = "session:transition:suspend:"
    if not target.startswith(prefix):
        raise RuntimeError("native suspend target has another purpose")
    baseline, separator, suffix = target[len(prefix) :].partition(":")
    if (
        not separator
        or re.fullmatch(r"0|[1-9][0-9]{0,19}", baseline) is None
        or int(baseline) >= 2**64 - 1
        or "session:lock:" + suffix != resource
    ):
        raise RuntimeError("native suspend target identity is unsupported")
    codec.lock_resource(resource)
    value = codec.fields(wire)
    expected = {
        "request_id": "request:v010:session-transition:" + operation,
        "resource": target,
        "completion": "verified-committed-reconciled",
        "postcondition": "resumed-securely",
        "current_native_power_state": "not-inferred",
        "recovered": str(recovered).lower(),
        "stages": codec.STAGES,
    }
    if (
        set(value) != set(expected) | {"transaction_id", "effect_digest"}
        or any(
            value.get(key) != expected_value for key, expected_value in expected.items()
        )
        or re.fullmatch(r"transaction:v1:[0-9a-f]{64}", value["transaction_id"]) is None
        or re.fullmatch(r"[0-9a-f]{64}", value["effect_digest"]) is None
    ):
        raise RuntimeError(
            "native suspend did not produce exact independent managed completion"
        )
    return value


def qualify(guest, native_input, prompt_log, source_sha: str) -> dict:
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise RuntimeError("native suspend source identity is unsupported")
    native_input.require_suspend_wakeup()  # Before setting a password or locking.
    response = secrets.token_hex(12)
    nonce = secrets.token_hex(8)
    checks = {}
    receipts: dict[str, dict[str, str]] = {}
    lock = None
    try:
        guest.run(
            codec.FIXTURE_COMMAND + "set-response",
            payload=(response + "\n").encode("ascii"),
        )
        resource = codec.fields(guest.run(PREFIX + "own-session-lock"))
        if set(resource) != {"resource"}:
            raise RuntimeError("native suspend lock query is malformed")
        lock = resource["resource"]
        codec.lock_resource(lock)
        receipt = guest.run(
            PREFIX + f"lock-session s17-suspend-lock-{nonce} S17-native-qualification",
            lambda: native_input.key("ret"),
        )
        receipts["lock"] = codec.validate_lock_receipt(
            receipt, "s17-suspend-lock-" + nonce, lock, True, False
        )
        sync_token = secrets.token_hex(16)
        pending = report(guest.run(HELPER + "queue --sync-token " + sync_token))
        if (
            set(pending) != {"operation", "resource"}
            or pending["resource"] != lock
            or not isinstance(pending["operation"], str)
            or re.fullmatch(r"s17-native-suspend-[0-9a-f]{16}", pending["operation"])
            is None
        ):
            raise RuntimeError("native suspend queued identity is unsupported")
        # No SSH session is kept open across the action. A separate root
        # qualification watcher performs read-only AT-SPI attestation and emits
        # only a random nonsecret serial marker after the exact protected suspend
        # prompt is accepting and focused. QMP remains the sole input channel.
        prompt_log.wait(PROMPT_PHASES["suspend"], sync_token, lock, native_input)
        checks["protected-suspend-prompt-focused-before-qmp-response"] = True
        native_input.response(response)
        native_input.wait_suspended_and_wake()
        checks["qmp-observed-real-suspend-and-single-wake"] = True
        deadline = time.monotonic() + 20
        while True:
            completed = report(guest.run(HELPER + "status"))
            if completed != {"state": "pending"}:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("native suspend completion remains pending")
            time.sleep(0.1)
        if (
            set(completed)
            != {"state", "operation", "lock_resource", "target", "receipt"}
            or completed["state"] != "completed"
            or completed["operation"] != pending["operation"]
            or completed["lock_resource"] != lock
            or not isinstance(completed["target"], str)
            or not isinstance(completed["receipt"], str)
        ):
            raise RuntimeError("native suspend worker did not retain exact completion")
        receipts["suspend"] = validate_receipt(
            completed["receipt"].encode("ascii"),
            pending["operation"],
            completed["target"],
            lock,
            False,
        )
        checks["native-kernel-cycle-and-secure-coverage-verified-committed"] = True
        guest.run("sudo -n /usr/bin/systemctl restart linura-authorityd.service")
        recovered = guest.run(
            PREFIX
            + "recover-session-transition request:v010:session-transition:"
            + pending["operation"]
        )
        receipts["suspend-recovery"] = validate_receipt(
            recovered, pending["operation"], completed["target"], lock, True
        )
        codec.require_same_retained_effect(
            receipts["suspend"], receipts["suspend-recovery"]
        )
        checks["control-restart-observe-only-suspend-recovery"] = True
        unlocked = guest.run(
            PREFIX
            + f"unlock-session s17-suspend-unlock-{nonce} S17-native-qualification",
            lambda: native_input.response(response),
        )
        receipts["unlock"] = codec.validate_lock_receipt(
            unlocked, "s17-suspend-unlock-" + nonce, lock, False, False
        )
        checks["suspend-fences-retired-before-owner-authenticated-unlock"] = True
    except RuntimeError:
        failure_diagnostics(guest, HELPER + "diagnostics")
        if lock is not None:
            print(
                "native-owner-failure-state="
                + json.dumps(
                    codec.owner_failure_diagnostics(guest, lock), sort_keys=True
                ),
                file=sys.stderr,
            )
        raise
    finally:
        guest.run(codec.FIXTURE_COMMAND + "clear-response")
    return {
        "schema_version": 1,
        "source_sha": source_sha,
        "claim": "native-managed-suspend-and-retained-recovery-cases-only",
        "checks": checks,
        "lock_resource": lock,
        "receipts": receipts,
        "s17_complete": False,
        "release_support_promotion": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmp-socket", type=Path, required=True)
    parser.add_argument("--ssh-identity", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--vm-log", type=Path, required=True)
    args = parser.parse_args()
    with (
        load("native_input").NativeInput(args.qmp_socket) as native_input,
        PromptLog(args.vm_log) as prompt_log,
    ):
        value = qualify(
            codec.Guest(args.ssh_identity), native_input, prompt_log, args.source_sha
        )
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
