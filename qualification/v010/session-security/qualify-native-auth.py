#!/usr/bin/env python3
"""Real QMP input → production PAM → managed S17 qualification cases.

This is a runner, not evidence until executed on the exact pinned native guest.
It does not qualify power, hotplug, compositor failures, AT-SPI or physical Q11.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import stat
import subprocess
import time
from typing import Callable, Protocol

ROOT = Path(__file__).resolve().parent
MAXIMUM_OUTPUT = 16384
STAGES = "request-intent,observe,plan,validate,authorize,prepare,execute,verify,commit,audit,reconcile"
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
FIXTURE_COMMAND = "sudo -n /usr/bin/python3 -I -S /opt/linura-source/qualification/v010/session-security/native-auth-fixture.py "
ASSISTIVE_COMMAND = "sudo -n /usr/bin/python3 -I -S /opt/linura-source/qualification/v010/session-security/native-assistive-fixture.py "
# NativeApproval::FailureCooldownMs is five seconds. Respect that production
# boundary between negative cases; never restart the owner or reset its state
# to make the next authentication pass. This wait grants no authentication.
NATIVE_DENIAL_SETTLE_SECONDS = 5.25


class NativeInputPort(Protocol):
    def key(self, qcode: str) -> None: ...
    def response(self, ephemeral_response: str) -> None: ...


def fields(wire: bytes) -> dict[str, str]:
    if len(wire) > MAXIMUM_OUTPUT:
        raise RuntimeError("native authentication report exceeds its bound")
    try:
        lines = wire.decode("ascii").splitlines()
    except UnicodeError:
        raise RuntimeError("native authentication report is malformed") from None
    result: dict[str, str] = {}
    for line in lines:
        key, delimiter, value = line.partition("=")
        if not delimiter or not key or key in result or any(ord(c) < 32 for c in value):
            raise RuntimeError("native authentication report is malformed")
        result[key] = value
    return result


def lock_resource(value: str) -> None:
    uuid = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    match = re.fullmatch(
        rf"session:lock:({uuid}):([1-9][0-9]{{0,9}}):[A-Za-z0-9]{{1,64}}:([1-9][0-9]{{0,19}}):({uuid}):([1-9][0-9]{{0,19}})",
        value,
    )
    if (
        match is None
        or match[1] == "00000000-0000-0000-0000-000000000000"
        or match[4] == "00000000-0000-0000-0000-000000000000"
        or int(match[2]) >= 2**32
        or int(match[3]) >= 2**64
        or int(match[5]) >= 2**64
    ):
        raise RuntimeError("native authentication login identity is unsupported")


def validate_lock_receipt(
    wire: bytes, operation: str, resource: str, secure: bool, recovered: bool
) -> dict[str, str]:
    result = fields(wire)
    expected = {
        "request_id": "request:v010:session-lock:" + operation,
        "resource": resource,
        "desired_secure": str(secure).lower(),
        "completion": "verified-committed-reconciled",
        "recovered": str(recovered).lower(),
        "stages": STAGES,
    }
    if (
        set(result) != set(expected) | {"transaction_id", "effect_digest"}
        or any(result.get(key) != value for key, value in expected.items())
        or re.fullmatch(
            r"transaction:v1:[0-9a-f]{64}", result.get("transaction_id", "")
        )
        is None
        or re.fullmatch(r"[0-9a-f]{64}", result.get("effect_digest", "")) is None
    ):
        raise RuntimeError(
            "native authentication did not produce exact verified managed completion"
        )
    return result


def validate_setting(
    wire: bytes, operation: str, resource: str, enabled: bool, latest: bool
) -> dict[str, str]:
    result = fields(wire)
    expected = {
        "request_id": "request:v010:protective-lock-setting:" + operation,
        "confirmation_lock": resource,
        "recorded_consent": "enabled" if enabled else "revoked",
        "latest_for_recorded_epoch": str(latest).lower(),
        "current_native_protection": "not-queried",
    }
    if set(result) != set(expected) | {
        "intent_id",
        "revision_id",
        "confirmed_at_unix_ms",
    } or any(result.get(key) != value for key, value in expected.items()):
        raise RuntimeError(
            "native owner consent history differs from the exact request"
        )
    for key, prefix in (
        ("intent_id", "intent:s17:protective-lock:"),
        ("revision_id", "policy:protective-lock:v1:"),
    ):
        digest = result[key].removeprefix(prefix)
        if (
            not result[key].startswith(prefix)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or digest == "0" * 64
        ):
            raise RuntimeError("native owner consent lineage is unsupported")
    stamp = result["confirmed_at_unix_ms"]
    if re.fullmatch(r"[1-9][0-9]{0,18}", stamp) is None or int(stamp) >= 2**63:
        raise RuntimeError("native owner consent timestamp is unsupported")
    return result


def validate_unlock_history(
    wire: bytes, operation: str, resource: str
) -> dict[str, str]:
    result = fields(wire)
    expected = {
        "request_id": "request:v010:session-lock:" + operation,
        "resource": resource,
        "desired_secure": "false",
        "historical_transaction_state": "committed",
        "current_native_coverage": "not-queried",
    }
    if (
        set(result) != set(expected) | {"transaction_id"}
        or any(result.get(key) != value for key, value in expected.items())
        or re.fullmatch(r"transaction:v1:[0-9a-f]{64}", result["transaction_id"])
        is None
    ):
        raise RuntimeError("native unlock history lost its exact retained identity")
    return result


def require_same_retained_effect(
    original: dict[str, str], recovered: dict[str, str]
) -> None:
    # Both receipts must already have passed their exact typed validators.
    # A valid-looking newly allocated transaction/effect is not recovery.
    if (
        original.get("recovered") != "false"
        or recovered.get("recovered") != "true"
        or {key: value for key, value in original.items() if key != "recovered"}
        != {key: value for key, value in recovered.items() if key != "recovered"}
    ):
        raise RuntimeError(
            "native recovery replaced the retained transaction or effect"
        )


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate native bootstrap field")
        result[key] = value
    return result


def validate_assistive_report(
    wire: bytes, resource: str, phase: str
) -> dict[str, object]:
    lock_resource(resource)
    if len(wire) > MAXIMUM_OUTPUT:
        raise RuntimeError("native assistive report exceeds its bound")
    try:
        value = json.loads(wire, object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        raise RuntimeError("native assistive report is malformed") from None
    checks = {
        "registry-discovers-actual-native-owner",
        "typed-protected-presentation-tree",
        "no-text-value-editable-action-or-geometry-interface",
        "remote-input-and-relabel-methods-rejected",
    }
    if (
        phase not in {"locked", "unlock-prompt"}
        or not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "claim",
            "phase",
            "native_owner_pid",
            "native_owner_invocation",
            "native_owner_start_ticks",
            "checks",
            "s17_complete",
            "release_support_promotion",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["claim"] != "native-assistive-metadata-cases-only"
        or value["phase"] != phase
        or type(value["native_owner_pid"]) is not int
        or not 1 < value["native_owner_pid"] < 2**31
        or value["native_owner_invocation"] != resource.split(":")[6].replace("-", "")
        or not isinstance(value["native_owner_start_ticks"], str)
        or re.fullmatch(r"[1-9][0-9]{0,19}", value["native_owner_start_ticks"]) is None
        or int(value["native_owner_start_ticks"]) >= 2**64
        or not isinstance(value["checks"], dict)
        or set(value["checks"]) != checks
        or any(result is not True for result in value["checks"].values())
        or value["s17_complete"] is not False
        or value["release_support_promotion"] is not False
    ):
        raise RuntimeError(
            "native assistive report differs from the exact owner/phase and partial claim"
        )
    return value


def bootstrap_lock(path: Path) -> str:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > MAXIMUM_OUTPUT
    ):
        raise RuntimeError("native bootstrap report is untrusted or excessive")
    with path.open("rb") as source:
        wire = source.read(MAXIMUM_OUTPUT + 1)
    if len(wire) > MAXIMUM_OUTPUT or len(wire) != metadata.st_size:
        raise RuntimeError("native bootstrap report exceeds its bound or changed")
    try:
        bootstrap = json.loads(wire, object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        raise RuntimeError("native bootstrap report is malformed") from None
    if (
        not isinstance(bootstrap, dict)
        or type(bootstrap.get("schema_version")) is not int
        or bootstrap["schema_version"] != 1
        or bootstrap.get("claim") != "native-session-bootstrap-only"
        or bootstrap.get("s17_complete") is not False
        or bootstrap.get("release_support_promotion") is not False
        or bootstrap.get("automatic_owner_activation") is not True
        or not isinstance(bootstrap.get("lock_resource"), str)
    ):
        raise RuntimeError("genuine native bootstrap evidence is unavailable")
    resource = bootstrap["lock_resource"]
    lock_resource(resource)
    return resource


class Guest:
    def __init__(self, identity: Path):
        metadata = identity.lstat()
        if (
            not identity.is_absolute()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
        ):
            raise RuntimeError(
                "native runner SSH identity is not private and runner-owned"
            )
        self.ssh = [
            "/usr/bin/ssh",
            "-F",
            "/dev/null",
            "-i",
            str(identity),
            "-p",
            "2223",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=3",
            "linura@127.0.0.1",
        ]

    def run(
        self,
        command: str,
        interaction: Callable[[], None] | None = None,
        payload: bytes | None = None,
        expect_failure: bool = False,
        allow_early_denial: bool = False,
    ) -> bytes:
        if allow_early_denial and not expect_failure:
            raise RuntimeError("early native denial is restricted to negative cases")
        # Only fixed call sites below construct commands; no model, arbitrary
        # command option, response argument or production credential is accepted.
        with selectors.DefaultSelector() as reader:
            process = subprocess.Popen(
                self.ssh + [command],
                stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=ENVIRONMENT,
            )
            deadline = time.monotonic() + 85
            assert process.stdout is not None
            reader.register(process.stdout, selectors.EVENT_READ)
            wire = bytearray()
            try:
                if payload is not None:
                    assert process.stdin is not None
                    process.stdin.write(payload)
                    process.stdin.close()
                if interaction is not None:
                    time.sleep(2)
                    if process.poll() is not None:
                        if not allow_early_denial:
                            raise RuntimeError(
                                "native action ended before the required real interaction"
                            )
                    else:
                        interaction()
                while process.poll() is None or reader.get_map():
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "native action exceeded its original deadline or output bound"
                        )
                    for key, _ in reader.select(0.05):
                        chunk = os.read(
                            key.fd, min(4096, MAXIMUM_OUTPUT + 1 - len(wire))
                        )
                        if not chunk:
                            reader.unregister(key.fileobj)
                        else:
                            wire.extend(chunk)
                            if len(wire) > MAXIMUM_OUTPUT:
                                raise RuntimeError(
                                    "native action output exceeds its bound"
                                )
                if process.returncode != (1 if expect_failure else 0):
                    raise RuntimeError(
                        "native action result differs from its required acceptance outcome"
                    )
                return bytes(wire)
            except (OSError, subprocess.SubprocessError):
                raise RuntimeError("native qualification transport failed") from None
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                process.stdout.close()
                if process.stdin is not None:
                    process.stdin.close()


def qualify(
    guest: Guest, native_input: NativeInputPort, resource: str, source_sha: str
) -> dict[str, object]:
    lock_resource(resource)
    # Fixed call sites only; generated request IDs are canonical non-secret IDs.
    suffix = secrets.token_hex(8)
    locked = "s17-native-lock-" + suffix
    unlocked = "s17-native-unlock-" + suffix
    enabled = "s17-native-enable-" + suffix
    revoked = "s17-native-revoke-" + suffix
    response = secrets.token_hex(12)
    prefix = "sudo -n runuser -u linura -- /usr/bin/linuractl "
    checks: dict[str, bool] = {}
    receipts: dict[str, dict[str, str]] = {}
    assistive: dict[str, dict[str, object]] = {}
    try:
        guest.run(
            FIXTURE_COMMAND + "set-response", payload=(response + "\n").encode("ascii")
        )
        receipt = guest.run(
            prefix + f"lock-session {locked} S17-native-qualification",
            lambda: native_input.key("ret"),
        )
        receipts["lock"] = validate_lock_receipt(receipt, locked, resource, True, False)
        checks["real-hardware-confirmed-managed-lock"] = True
        assistive["locked"] = validate_assistive_report(
            guest.run(ASSISTIVE_COMMAND + "locked"), resource, "locked"
        )
        checks["native-registry-discovers-protected-locked-presentation"] = True
        guest.run("sudo -n /usr/bin/systemctl restart linura-authorityd.service")
        receipt = guest.run(
            prefix + "recover-session-lock request:v010:session-lock:" + locked
        )
        receipts["lock-recovery"] = validate_lock_receipt(
            receipt, locked, resource, True, True
        )
        require_same_retained_effect(receipts["lock"], receipts["lock-recovery"])
        checks["control-restart-observe-only-lock-recovery"] = True
        for operation, decision, consent in (
            (enabled, "enable", True),
            (revoked, "revoke", False),
        ):
            receipt = guest.run(
                prefix + f"configure-protective-lock {decision} {operation} {resource}",
                lambda: native_input.response(response),
            )
            receipts["consent-" + decision] = validate_setting(
                receipt, operation, resource, consent, True
            )
            checks["native-owner-pam-" + decision + "-consent"] = True
        receipt = guest.run(
            prefix
            + "protective-lock-setting-status request:v010:protective-lock-setting:"
            + enabled
        )
        receipts["consent-enable-history"] = validate_setting(
            receipt, enabled, resource, True, False
        )
        if {
            key: value
            for key, value in receipts["consent-enable"].items()
            if key != "latest_for_recorded_epoch"
        } != {
            key: value
            for key, value in receipts["consent-enable-history"].items()
            if key != "latest_for_recorded_epoch"
        }:
            raise RuntimeError("native consent history replaced the approved record")
        checks["superseded-consent-history-never-reenrolls"] = True
        # Cancellation alone must not prove owner identity. It produces no
        # successful receipt, then the exact same still-secure generation must
        # support the independently verified positive PAM unlock below.
        guest.run(
            prefix
            + f"unlock-session s17-native-cancel-{suffix} S17-native-cancellation",
            lambda: native_input.key("esc"),
            expect_failure=True,
        )
        checks["native-cancellation-does-not-complete-unlock"] = True
        time.sleep(NATIVE_DENIAL_SETTLE_SECONDS)
        # One deliberately incorrect response, not repeated password guessing.
        # Even if PAM refuses it by timeout, it must never complete release.
        # The correct-response completion below must retain this same generation.
        incorrect = ("0" if response[0] != "0" else "1") + response[1:]
        guest.run(
            prefix + f"unlock-session s17-native-incorrect-{suffix} S17-native-denial",
            lambda: native_input.response(incorrect),
            expect_failure=True,
        )
        checks["incorrect-response-does-not-complete-unlock"] = True
        time.sleep(NATIVE_DENIAL_SETTLE_SECONDS)

        # Exercise native account denial without a PAM override. The root
        # disposable helper independently verifies the password lock, then the
        # correct response must still fail. Restore only through private stdin.
        guest.run(FIXTURE_COMMAND + "clear-response")
        guest.run(
            prefix
            + f"unlock-session s17-native-account-locked-{suffix} S17-native-account-denial",
            lambda: native_input.response(response),
            expect_failure=True,
            # Native account rejection can precede a prompt. It must still be
            # an actual exit-1 denial, never SSH failure/timeout or success.
            allow_early_denial=True,
        )
        checks["password-locked-account-cannot-complete-unlock"] = True
        time.sleep(NATIVE_DENIAL_SETTLE_SECONDS)
        guest.run(
            FIXTURE_COMMAND + "set-response", payload=(response + "\n").encode("ascii")
        )

        def respond_to_unlock() -> None:
            assistive["unlock-prompt"] = validate_assistive_report(
                guest.run(ASSISTIVE_COMMAND + "unlock-prompt"),
                resource,
                "unlock-prompt",
            )
            checks["native-password-role-metadata-and-remote-input-denial"] = True
            native_input.response(response)

        receipt = guest.run(
            prefix + f"unlock-session {unlocked} S17-native-qualification",
            respond_to_unlock,
        )
        receipts["unlock"] = validate_lock_receipt(
            receipt, unlocked, resource, False, False
        )
        checks["real-pam-owner-unlock-verified-committed"] = True
        history = guest.run(
            prefix + "session-lock-status request:v010:session-lock:" + unlocked
        )
        receipts["unlock-history"] = validate_unlock_history(
            history, unlocked, resource
        )
        if any(
            receipts["unlock"][key] != receipts["unlock-history"][key]
            for key in (
                "request_id",
                "resource",
                "desired_secure",
                "transaction_id",
            )
        ):
            raise RuntimeError(
                "native unlock history replaced the committed transaction"
            )
        checks["durable-unlock-history-not-current-coverage"] = True
    finally:
        # Cleanup failure fails qualification too. A forcibly killed runner may
        # not clean up; its disposable VM must be discarded, never retained.
        guest.run(FIXTURE_COMMAND + "clear-response")
    return {
        "schema_version": 1,
        "source_sha": source_sha,
        "claim": "native-owner-authentication-and-retained-recovery-cases-only",
        "checks": checks,
        "lock_resource": resource,
        "receipts": receipts,
        "assistive_probes": assistive,
        "s17_complete": False,
        "release_support_promotion": False,
        "power_hotplug_compositor_and_accessibility_qualified": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmp-socket", type=Path, required=True)
    parser.add_argument("--ssh-identity", type=Path, required=True)
    parser.add_argument("--bootstrap", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.source_sha) is None:
        raise RuntimeError("native qualification source identity is unsupported")
    resource = bootstrap_lock(args.bootstrap)
    spec = importlib.util.spec_from_file_location(
        "s17_auth_native_input", ROOT / "native_input.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("native hardware input mechanism is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with module.NativeInput(args.qmp_socket) as native_input:
        report = qualify(
            Guest(args.ssh_identity),
            native_input,
            resource,
            args.source_sha,
        )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
