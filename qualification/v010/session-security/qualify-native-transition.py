#!/usr/bin/env python3
"""Native logout/reboot/power-off with exact retained, observe-only recovery.

Two phases allow QEMU to exit on power-off, then boot the SAME disposable disk.
The handoff is explicitly incomplete; no report passes before account cleanup.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import secrets
import stat
import sys
import time
import importlib.util

ROOT = Path(__file__).resolve().parent
HELPER = "sudo -n /usr/bin/python3 -I -S /opt/linura-source/qualification/v010/session-security/native-transition-fixture.py "
PREFIX = "sudo -n runuser -u linura -- /usr/bin/linuractl "
PURPOSES = ("logout", "reboot", "power-off")


def load(name: str):
    spec = importlib.util.spec_from_file_location(
        "s17_ending_" + name.replace("-", "_"), ROOT / (name + ".py")
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("terminating qualification dependency is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


suspend = load("qualify-native-suspend")
codec = suspend.codec


def validate_pending(value: dict, purpose: str) -> None:
    if purpose not in PURPOSES or set(value) != {
        "operation",
        "purpose",
        "resource",
        "target",
    }:
        raise RuntimeError("terminating handoff shape is unsupported")
    if (
        not all(isinstance(item, str) for item in value.values())
        or value["purpose"] != purpose
        or re.fullmatch(r"s17-native-" + purpose + r"-[0-9a-f]{16}", value["operation"])
        is None
    ):
        raise RuntimeError("terminating handoff identity is unsupported")
    codec.lock_resource(value["resource"])
    if value["target"] != "session:transition:" + purpose + ":0:" + value[
        "resource"
    ].removeprefix("session:lock:"):
        raise RuntimeError("terminating handoff generation differs")


def validate_handoff(value: dict, purpose: str, source_sha: str) -> dict:
    if (
        re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
        or set(value)
        != {
            "schema_version",
            "source_sha",
            "pending",
            "cleanup_required",
            "s17_complete",
            "release_support_promotion",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["source_sha"] != source_sha
        or value["cleanup_required"] is not True
        or value["s17_complete"] is not False
        or value["release_support_promotion"] is not False
        or not isinstance(value["pending"], dict)
    ):
        raise RuntimeError(
            "terminating handoff is not an exact incomplete source-bound case"
        )
    validate_pending(value["pending"], purpose)
    return value["pending"]


def prepare(guest, native_input, prompt_log, purpose: str, source_sha: str) -> dict:
    if purpose not in PURPOSES or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise RuntimeError("terminating case purpose/source is unsupported")
    response = secrets.token_hex(12)
    nonce = secrets.token_hex(8)
    resource = None
    try:
        guest.run(
            codec.FIXTURE_COMMAND + "set-response",
            payload=(response + "\n").encode("ascii"),
        )
        lock = codec.fields(guest.run(PREFIX + "own-session-lock"))
        if set(lock) != {"resource"}:
            raise RuntimeError("terminating case lock query is malformed")
        resource = lock["resource"]
        codec.lock_resource(resource)
        operation = "s17-ending-lock-" + nonce
        receipt = guest.run(
            PREFIX + "lock-session " + operation + " S17-native-qualification",
            lambda: native_input.key("ret"),
        )
        codec.validate_lock_receipt(receipt, operation, resource, True, False)
        sync_token = secrets.token_hex(16)
        pending = suspend.report(
            guest.run(HELPER + "queue " + purpose + " --sync-token " + sync_token)
        )
        validate_pending(pending, purpose)
        if pending["resource"] != resource:
            raise RuntimeError(
                "terminating queue replaced the original lock generation"
            )
        # The one-shot guest service waits for this SSH login to end. A separate
        # read-only prompt watcher emits a nonsecret serial marker only after the
        # exact protected purpose-bound prompt is focused; QMP remains the sole
        # credential/input path and the effect is never retried.
        prompt_log.wait(
            suspend.PROMPT_PHASES[purpose], sync_token, resource, native_input
        )
        native_input.response(response)
        if purpose != "logout":
            native_input.wait_guest_termination(purpose)
        return {
            "schema_version": 1,
            "source_sha": source_sha,
            "pending": pending,
            "cleanup_required": True,
            "s17_complete": False,
            "release_support_promotion": False,
        }
    except Exception:
        suspend.failure_diagnostics(guest, HELPER + "diagnostics " + purpose)
        if resource is not None:
            print(
                "native-owner-failure-state="
                + json.dumps(
                    codec.owner_failure_diagnostics(guest, resource), sort_keys=True
                ),
                file=sys.stderr,
            )
        # If the guest is already gone, cleanup failure invalidates this case;
        # the workflow must discard the entire private VM rather than retain it.
        guest.run(codec.FIXTURE_COMMAND + "clear-response")
        raise


def validate_receipt(wire: bytes, pending: dict) -> tuple[str, str]:
    validate_pending(pending, pending["purpose"])
    value = codec.fields(wire)
    expected = {
        "request_id": "request:v010:session-transition:" + pending["operation"],
        "resource": pending["target"],
        "completion": "verified-committed-reconciled",
        "postcondition": "original-session-ended"
        if pending["purpose"] == "logout"
        else "original-boot-ended",
        "current_native_power_state": "not-inferred",
        "recovered": "true",
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
            "terminating case lacks exact verified observe-only completion"
        )
    return value["transaction_id"], value["effect_digest"]


def verify(guest, handoff: dict, purpose: str, source_sha: str) -> dict:
    pending = validate_handoff(handoff, purpose, source_sha)
    checks = {}
    try:
        # Bounded SSH/readiness polling only, never another transition submission.
        deadline = time.monotonic() + 420
        while True:
            try:
                current = suspend.report(guest.run(HELPER + "status " + purpose))
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "terminating guest did not return within its original bound"
                    ) from None
                time.sleep(2)
                continue
            if (
                time.monotonic() >= deadline
                or set(current) != set(pending) | {"boot", "original_session_present"}
                or any(current.get(key) != item for key, item in pending.items())
                or type(current["original_session_present"]) is not bool
            ):
                raise RuntimeError(
                    "terminating guest lost the exact private pending request"
                )
            if purpose != "logout" or current["original_session_present"] is False:
                break
            time.sleep(0.1)
        old_boot = pending["resource"].split(":")[2]
        if (
            not isinstance(current["boot"], str)
            or re.fullmatch(
                r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", current["boot"]
            )
            is None
        ):
            raise RuntimeError("terminating guest boot identity is malformed")
        if (current["boot"] == old_boot) != (purpose == "logout"):
            raise RuntimeError(
                "terminating guest has the wrong original/new boot relationship"
            )
        guest.run("sudo -n /usr/bin/systemctl restart linura-authorityd.service")
        command = (
            PREFIX
            + "recover-session-transition request:v010:session-transition:"
            + pending["operation"]
        )
        first = validate_receipt(guest.run(command), pending)
        guest.run("sudo -n /usr/bin/systemctl restart linura-authorityd.service")
        second = validate_receipt(guest.run(command), pending)
        if first != second:
            raise RuntimeError(
                "terminating recovery changed transaction/effect identity"
            )
        checks[
            "independent-original-session-ended"
            if purpose == "logout"
            else "independent-original-boot-ended"
        ] = True
        checks["exact-durable-request-survived-session-or-boot-loss"] = True
        checks["repeated-control-restart-observe-only-recovery-no-effect-replay"] = True
    finally:
        guest.run(codec.FIXTURE_COMMAND + "clear-response")
    checks["disposable-account-independently-relocked"] = True
    return {
        "schema_version": 1,
        "source_sha": source_sha,
        "purpose": purpose,
        "request_id": "request:v010:session-transition:" + pending["operation"],
        "resource": pending["target"],
        "transaction_id": first[0],
        "effect_digest": first[1],
        "original_boot_id": old_boot,
        "observed_boot_id": current["boot"],
        "claim": "native-terminating-transition-retained-recovery-cases-only",
        "checks": checks,
        "s17_complete": False,
        "release_support_promotion": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("prepare", "verify"), required=True)
    parser.add_argument("--purpose", choices=PURPOSES, required=True)
    parser.add_argument("--ssh-identity", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--qmp-socket", type=Path)
    parser.add_argument("--vm-log", type=Path)
    parser.add_argument("--handoff", type=Path)
    args = parser.parse_args()
    guest = codec.Guest(args.ssh_identity)
    if args.phase == "prepare":
        if args.qmp_socket is None or args.vm_log is None or args.handoff is not None:
            parser.error("prepare requires private QMP, VM log and no input handoff")
        with (
            load("native_input").NativeInput(args.qmp_socket) as native_input,
            suspend.PromptLog(args.vm_log) as prompt_log,
        ):
            result = prepare(
                guest, native_input, prompt_log, args.purpose, args.source_sha
            )
    else:
        if (
            args.handoff is None
            or args.qmp_socket is not None
            or args.vm_log is not None
        ):
            parser.error("verify requires the original handoff and no QMP/VM-log input")
        metadata = args.handoff.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > codec.MAXIMUM_OUTPUT
        ):
            raise RuntimeError("terminating handoff file is untrusted or excessive")
        with args.handoff.open("rb") as source:
            wire = source.read(codec.MAXIMUM_OUTPUT + 1)
        if len(wire) != metadata.st_size:
            raise RuntimeError("terminating handoff changed while reading")
        result = verify(guest, suspend.report(wire), args.purpose, args.source_sha)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
