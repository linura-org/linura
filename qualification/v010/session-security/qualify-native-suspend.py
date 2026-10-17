#!/usr/bin/env python3
"""Actual managed suspend/resume and observe-only recovery on the pinned guest.

No direct native suspend, inhibitor bypass, alternate PAM or replay. This subset
is not logout/reboot/power-off, physical Q11, or complete S17 evidence.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import secrets
import time

ROOT = Path(__file__).resolve().parent
HELPER = "sudo -n /usr/bin/python3 -I -S /opt/linura-source/qualification/v010/session-security/native-suspend-fixture.py "
PREFIX = "sudo -n runuser -u linura -- /usr/bin/linuractl "


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


def qualify(guest, native_input, source_sha: str) -> dict:
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise RuntimeError("native suspend source identity is unsupported")
    native_input.require_suspend_wakeup()  # Before setting a password or locking.
    response = secrets.token_hex(12)
    nonce = secrets.token_hex(8)
    checks = {}
    receipts: dict[str, dict[str, str]] = {}
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
        pending = report(guest.run(HELPER + "queue"))
        if (
            set(pending) != {"operation", "resource"}
            or pending["resource"] != lock
            or not isinstance(pending["operation"], str)
            or re.fullmatch(r"s17-native-suspend-[0-9a-f]{16}", pending["operation"])
            is None
        ):
            raise RuntimeError("native suspend queued identity is unsupported")
        # No SSH session is kept open across the action. The fixed guest worker
        # independently waits for all other non-manager logins to disappear.
        time.sleep(3)
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
    args = parser.parse_args()
    with load("native_input").NativeInput(args.qmp_socket) as native_input:
        value = qualify(codec.Guest(args.ssh_identity), native_input, args.source_sha)
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
