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
import sys
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


SLEEP_UNIT_DIAGNOSTIC_VALUES = {
    "ActiveState": (
        "active",
        "inactive",
        "failed",
        "activating",
        "deactivating",
        "reloading",
        "maintenance",
        "refreshing",
    ),
    "SubState": (
        "dead",
        "condition",
        "start-pre",
        "start",
        "start-post",
        "running",
        "exited",
        "reload",
        "stop",
        "stop-sigterm",
        "stop-sigkill",
        "stop-post",
        "final-sigterm",
        "final-sigkill",
        "failed",
        "auto-restart",
    ),
    "Result": (
        "success",
        "resources",
        "protocol",
        "timeout",
        "exit-code",
        "signal",
        "core-dump",
        "watchdog",
        "start-limit-hit",
        "oom-kill",
        "exec-condition",
    ),
}
SLEEP_UNIT_DIAGNOSTIC_LABELS = {
    *(
        f"sleep-unit-{key.lower()}-{value}"
        for key, values in SLEEP_UNIT_DIAGNOSTIC_VALUES.items()
        for value in values
    ),
    "sleep-unit-main-pid-zero",
    "sleep-unit-main-pid-present",
    "sleep-unit-diagnostics-unavailable",
}


SLEEP_GATE_FAILURE_MARKERS = (
    *(
        (
            f"sleep-owner-{reason}",
            f"native-sleep-owner-denied reason={reason}\n".encode("ascii"),
        )
        for reason in (
            "peer",
            "binding",
            "scope",
            "mechanism",
            "compositor",
            "counter",
            "unit-snapshot",
            "transition",
            "session",
            "peer-generation",
            "counter-generation",
            "coverage",
            "arm",
            "unit-owner",
            "unit-uid",
            "unit-assets",
            "unit-lookup",
            "lookup-timeout",
            "lookup-deadline",
            "lookup-denied",
            "lookup-arguments",
            "lookup-disconnected",
            "lookup-unsupported",
            "lookup-owner-lost",
            "lookup-error-other",
            "lookup-reply-substitution",
            "lookup-invalid-type",
            "unit-absence",
            "unit-path",
            "unit-property",
            "unit-codec",
            "unit-revalidation",
            "codec-fields",
            "codec-drop-ins",
            "codec-commands",
            "codec-extra-signature",
            "codec-extra-command",
            "codec-success-signature",
            "codec-success-status",
        )
    ),
    *(
        (
            f"sleep-gate-{stage}-{reason}",
            f"native-sleep-gate-denied stage={stage} reason={reason}".encode("ascii"),
        )
        for stage in ("attestation", "entry", "coverage", "completion", "unclassified")
        for reason in (
            "helper-image",
            "helper-arguments",
            "helper-mismatch",
            "helper-identity",
            "unit-contract",
            "unit-programs",
            "unit-codec",
            "assets",
            "generation",
            "deadline",
            "supervisor",
            "no-session",
            "session-class",
            "session-inventory",
            "control-busy",
            "coverage-generation",
            "fence-refused",
            "transport-denied",
            "transport-timeout",
            "process-generation",
            "unclassified",
        )
    ),
    (
        "sleep-helper-privilege",
        b"native sleep helper has not dropped every reusable privilege",
    ),
    (
        "sleep-helper-entry",
        b"native sleep helper could not enter its fixed unprivileged identity",
    ),
    (
        "sleep-helper-credentials",
        b"native sleep helper credential facts are unsupported",
    ),
    (
        "sleep-helper-transport-denied",
        b"native session call failed: class=access-denied; stage=mechanism",
    ),
    (
        "sleep-helper-transport-timeout",
        b"native session call failed: class=no-reply; stage=mechanism",
    ),
    ("sleep-gate-diagnostics-unavailable", b"sleep-gate-diagnostics-unavailable"),
)


FAILURE_MARKERS = (
    *SLEEP_GATE_FAILURE_MARKERS,
    *((label, label.encode("ascii")) for label in sorted(SLEEP_UNIT_DIAGNOSTIC_LABELS)),
    *(
        (
            "assistive-" + category,
            ("native assistive probe failed: " + category).encode("ascii"),
        )
        for category in (
            "input",
            "session-bus",
            "accessibility-bus",
            "owner-discovery",
            "registry",
            "application-tree",
            "presentation-tree",
            "protected-interfaces",
            "remote-input-denial",
            "report",
            "call-deadline",
            "call-peer-unavailable",
            "call-disconnected",
            "unclassified",
        )
    ),
    ("owner-refused-scope", b"native owner refused the scoped interaction"),
    (
        "owner-missing-proof",
        b"native owner did not prove fresh purpose-bound authentication",
    ),
    (
        "owner-release-unverified",
        b"native owner did not independently confirm release",
    ),
    (
        "release-commit-pending",
        b"release was committed but its native generation acknowledgement is pending",
    ),
    (
        "release-recovery-pending",
        b"verified release is durable but native acknowledgement is pending",
    ),
    ("dispatch-refused", b"native lock precondition refused dispatch"),
    ("dispatch-ambiguous", b"native lock transport outcome is indeterminate"),
    ("native-owner-changed", b"native security owner changed during the operation"),
    ("native-owner-ambiguous", b"native owner has ambiguous bus connections"),
    ("native-owner-absent", b"native owner has no authenticated bus connection"),
    (
        "owner-discovery-churn",
        b"native owner discovery remained unstable within its bounded probe",
    ),
    (
        "owner-discovery-changed",
        b"native security owner changed during discovery",
    ),
    (
        "owner-discovery-timeout",
        b"native owner discovery exceeded its original deadline",
    ),
    (
        "owner-discovery-bound",
        b"native bus enumeration exceeds its aggregate bound",
    ),
    ("owner-discovery-codec", b"native endpoint introspection"),
    (
        "native-generation-mismatch",
        b"native lock generation differs from the requested generation",
    ),
    ("native-observation-codec", b"native lock observation codec mismatch"),
    ("native-lock-codec", b"native lock call result is malformed"),
    ("native-approval-codec", b"native approval result is malformed"),
    ("native-reply-bound", b"native session reply exceeded its time or size bound"),
    ("native-reply-size", b"native session reply exceeded its size bound"),
    (
        "native-auth-denied",
        b"native owner authentication was denied or still challenged",
    ),
    ("native-auth-daemon", b"native authentication daemon"),
    ("native-auth-service", b"native authentication service"),
    ("native-auth-subject", b"native authentication subject"),
    ("native-auth-account", b"native authentication account"),
    ("native-auth-process", b"native process"),
    ("native-call", b"native session call"),
    *(
        ("native-call-" + category, ("class=" + category).encode("ascii"))
        for category in (
            "peer-unavailable",
            "access-denied",
            "no-reply",
            "unsupported",
            "arguments",
            "transport",
            "malformed",
            "remote-failure",
            "native-unavailable",
            "transition-pending",
            "deadline",
        )
    ),
    *(
        ("native-stage-" + stage, ("stage=" + stage).encode("ascii"))
        for stage in (
            "approval-arm",
            "approval-consume",
            "owner-lookup",
            "properties",
            "credentials",
            "unit-lookup",
            "session-lookup",
            "authentication",
            "mechanism",
            "lock-observation",
            "release-verification",
            "retained-release",
            "release-commit",
            "lock-dispatch",
        )
    ),
    ("approval-boundary", b"trusted approval boundary failed"),
    ("authority", b"durable authority failed"),
    ("executor", b"privileged executor failed"),
    ("execution-rejected", b"effect was rejected before dispatch"),
    ("verification", b"independent verification failed"),
    (
        "session-evidence-identity",
        b"session evidence does not bind the exact current epoch",
    ),
    (
        "session-state-unsupported",
        b"session state is unsupported, ambiguous or unsafe",
    ),
    (
        "session-coverage-unverified",
        b"compositor has not verified exact-session secure coverage",
    ),
    (
        "verification-unsatisfied",
        b"independent verification did not prove intended state",
    ),
    ("indeterminate", b"managed mutation remains indeterminate"),
    ("terminal", b"durable transaction is terminal and cannot be replayed"),
    ("reconciliation", b"post-commit reconciliation failed"),
    ("contract", b"managed lifecycle contract failed"),
    ("effect-contract", b"unsupported v0.6 effect"),
    ("request-identity", b"invalid v0.6 request identity"),
    (
        "native-supervision",
        b"native owner is not the exact immutable supervised invocation",
    ),
    *(
        ("native-supervision-" + stage, ("supervision=" + stage).encode("ascii"))
        for stage in (
            "process",
            "user",
            "unit",
            "state",
            "invocation",
            "launch",
            "assets",
        )
    ),
    ("access-denied", b"AccessDenied"),
    ("timeout", b"deadline"),
    ("codec", b"signature"),
    ("native-property", b"native service property"),
    ("freshness", b"stale"),
    ("clock", b"clock"),
    ("request-journal", b"request journal"),
    ("policy", b"policy"),
    ("observation", b"observation"),
    ("planning", b"plan"),
    ("provider", b"provider"),
    ("native", b"native"),
)


def failure_categories(wire: bytes | bytearray) -> str:
    # Never return untrusted diagnostic text or authentication material.
    return (
        ",".join(code for code, marker in FAILURE_MARKERS if marker in wire)
        or "unclassified"
    )


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


POWER_INVENTORY_FAILURES = {
    "session-list-refused",
    "session-properties-refused",
    "session-inventory-wire",
    "session-inventory-bound",
    "session-inventory-identity",
    "session-inventory-timeout",
    "session-inventory-fields",
    "session-inventory-drift",
    "session-target-generation",
    "session-target-absent",
    "session-class-unsupported",
    "session-other-login",
}


class InventoryFailure(RuntimeError):
    def __init__(self, category: str):
        if category not in POWER_INVENTORY_FAILURES:
            raise RuntimeError("native inventory failure category is unsupported")
        super().__init__("native power inventory failed: " + category)
        self.category = category


POWER_PROMPT_PHASES = {
    "suspend-prompt",
    "logout-prompt",
    "reboot-prompt",
    "power-off-prompt",
}


def validate_power_prompt(value: object) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != {"kind", "uid", "index", "count"}
        or type(value["uid"]) is not int
        or not 0 <= value["uid"] < 2**31
        or type(value["index"]) is not int
        or type(value["count"]) is not int
        or not (
            (value["kind"] == "response" and value["index"] == value["count"] == 0)
            or (
                value["kind"] == "identity-selection"
                and 1 <= value["index"] <= value["count"] <= 8
                and value["count"] >= 2
            )
        )
    ):
        raise RuntimeError("native power prompt metadata is unsupported")
    return value


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
        phase
        not in {
            "locked",
            "unlock-prompt",
            "suspend-prompt",
            "logout-prompt",
            "reboot-prompt",
            "power-off-prompt",
        }
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
        | ({"native_prompt"} if phase in POWER_PROMPT_PHASES else set())
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
    if phase in POWER_PROMPT_PHASES:
        validate_power_prompt(value["native_prompt"])
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
    # The original #224 bootstrap report did not bind the daemon whose
    # supervised identity the merged native owner must attest. Refuse old
    # first-login reports with no independently checked Polkit process.
    daemon = bootstrap.get("native_polkit_supervision")
    expected_argv = ["/usr/lib/polkit-1/polkitd", "--no-debug", "--log-level=notice"]
    if (
        not isinstance(daemon, dict)
        or set(daemon) != {"pid", "uid", "invocation", "image", "argv"}
        or type(daemon["pid"]) is not int
        or not 1 < daemon["pid"] < 2**31
        or type(daemon["uid"]) is not int
        or not 0 < daemon["uid"] < 2**32
        or not isinstance(daemon["invocation"], str)
        or re.fullmatch(r"[0-9a-f]{32}", daemon["invocation"]) is None
        or daemon["invocation"] == "0" * 32
        or daemon["image"] != "/usr/lib/polkit-1/polkitd"
        or daemon["argv"] != expected_argv
    ):
        raise RuntimeError("native bootstrap lacks exact Polkit supervision evidence")
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
                stderr=subprocess.PIPE,
                env=ENVIRONMENT,
            )
            deadline = time.monotonic() + 85
            assert process.stdout is not None
            assert process.stderr is not None
            reader.register(process.stdout, selectors.EVENT_READ)
            reader.register(process.stderr, selectors.EVENT_READ)
            wire = bytearray()
            diagnostics = bytearray()
            ended_before_interaction = False
            try:
                if payload is not None:
                    assert process.stdin is not None
                    process.stdin.write(payload)
                    process.stdin.close()
                if interaction is not None:
                    time.sleep(2)
                    if process.poll() is not None:
                        if not allow_early_denial:
                            ended_before_interaction = True
                    else:
                        interaction()
                while process.poll() is None or reader.get_map():
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "native action exceeded its original deadline or output bound"
                        )
                    for key, _ in reader.select(0.05):
                        chunk = os.read(
                            key.fd,
                            min(
                                4096, MAXIMUM_OUTPUT + 1 - len(wire) - len(diagnostics)
                            ),
                        )
                        if not chunk:
                            reader.unregister(key.fileobj)
                        else:
                            target = (
                                wire if key.fileobj is process.stdout else diagnostics
                            )
                            target.extend(chunk)
                            if len(wire) + len(diagnostics) > MAXIMUM_OUTPUT:
                                raise RuntimeError(
                                    "native action output exceeds its bound"
                                )
                if ended_before_interaction:
                    raise RuntimeError(
                        "native action ended before the required real interaction: "
                        f"exit={process.returncode}; categories={failure_categories(diagnostics)}"
                    )
                if process.returncode != (1 if expect_failure else 0):
                    raise RuntimeError(
                        "native action result differs from its required acceptance outcome: "
                        f"exit={process.returncode}; categories={failure_categories(diagnostics)}"
                    )
                return bytes(wire)
            except (OSError, subprocess.SubprocessError):
                raise RuntimeError("native qualification transport failed") from None
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                process.stdout.close()
                process.stderr.close()
                if process.stdin is not None:
                    process.stdin.close()


def native_owner_failure_state(wire: bytes, resource: str) -> dict[str, object]:
    """Failure diagnostics only; never current-state or acceptance evidence."""
    lock_resource(resource)
    value = fields(wire)
    if set(value) != {
        "ActiveState",
        "SubState",
        "Result",
        "ExecMainCode",
        "ExecMainStatus",
        "MainPID",
        "InvocationID",
    }:
        raise RuntimeError("native owner failure diagnostics are unavailable")
    if value["ActiveState"] not in {"active", "inactive", "failed"} or value[
        "SubState"
    ] not in {"running", "dead", "failed", "exited"}:
        raise RuntimeError("native owner failure state is unsupported")
    for key, maximum in (
        ("ExecMainCode", 6),
        ("ExecMainStatus", 255),
        ("MainPID", 2**31 - 1),
    ):
        if (
            re.fullmatch(r"0|[1-9][0-9]{0,9}", value[key]) is None
            or int(value[key]) > maximum
        ):
            raise RuntimeError("native owner failure diagnostics are unsupported")
    result = value["Result"]
    if result not in {
        "success",
        "exit-code",
        "signal",
        "core-dump",
        "timeout",
        "watchdog",
        "start-limit-hit",
        "resources",
        "protocol",
        "oom-kill",
        "exec-condition",
    }:
        raise RuntimeError("native owner failure result is unsupported")
    invocation = value["InvocationID"]
    if invocation and re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
        raise RuntimeError("native owner failure invocation is unsupported")
    return {
        "claim": "failure-diagnostics-only",
        "active": value["ActiveState"] == "active",
        "running": value["SubState"] == "running",
        "pid_present": int(value["MainPID"]) > 1,
        "main_code": int(value["ExecMainCode"]),
        "main_status": int(value["ExecMainStatus"]),
        "result": result,
        "same_invocation": invocation == resource.split(":")[6].replace("-", ""),
    }


OWNER_TIMEOUT_STAGES = frozenset(
    {
        "bus-authentication",
        "runtime-initialization",
        "approval-arm",
        "sleep-entry",
        "sleep-recovery",
        "power-permission",
        "wayland-initialization",
        "wayland-pump",
        "wayland-repaint",
        "lock-acquisition",
        "lock-release",
        "assistive-callback",
        "unclassified",
    }
)

OWNER_LOCK_PROGRESS = frozenset(
    {
        "requested",
        "surface-configured",
        "frame-flushed",
        "all-surfaces-flushed",
        "acknowledged",
        "released",
    }
)


def native_owner_failure_journal(wire: bytes) -> dict[str, object]:
    """Decode closed exit/timeout fields; discard raw text and identifiers."""
    if len(wire) > MAXIMUM_OUTPUT:
        raise RuntimeError("native owner exit diagnostics exceed their bound")
    rows = wire.splitlines()
    if len(rows) > 64:
        raise RuntimeError("native owner exit diagnostics exceed their bound")
    exits = []
    timeouts: set[str] = set()
    progress: list[str] = []
    for row in rows:
        try:
            value = json.loads(row, object_pairs_hook=unique_object)
        except (ValueError, RecursionError):
            raise RuntimeError("native owner exit diagnostics are malformed") from None
        if not isinstance(value, dict):
            raise RuntimeError("native owner exit diagnostics are malformed")
        message = value.get("MESSAGE")
        if isinstance(message, str):
            for stage in OWNER_TIMEOUT_STAGES:
                if message.removesuffix("\n") == "native-owner-timeout stage=" + stage:
                    timeouts.add(stage)
            for stage in OWNER_LOCK_PROGRESS:
                if (
                    message.removesuffix("\n")
                    == "native-owner-lock-progress stage=" + stage
                ):
                    progress.append(stage)
        if "EXIT_CODE" not in value and "EXIT_STATUS" not in value:
            continue
        code, status = value.get("EXIT_CODE"), value.get("EXIT_STATUS")
        if (
            not isinstance(code, str)
            or code not in {"exited", "killed", "dumped"}
            or not isinstance(status, str)
            or re.fullmatch(r"0|[1-9][0-9]{0,2}", status) is None
            or int(status) > 255
        ):
            raise RuntimeError("native owner exit diagnostics are unsupported")
        exits.append({"code": code, "status": int(status)})
    return {"exits": exits, "timeouts": sorted(timeouts), "lock_progress": progress}


def compositor_failure_monitors(wire: bytes) -> dict[str, int]:
    if len(wire) > MAXIMUM_OUTPUT:
        raise RuntimeError("native compositor diagnostics exceed their bound")
    try:
        rows = json.loads(wire, object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        raise RuntimeError("native compositor diagnostics are malformed") from None
    if not isinstance(rows, list) or len(rows) > 16:
        raise RuntimeError("native compositor diagnostics are unsupported")
    seen = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or type(row.get("id")) is not int
            or not 0 <= row["id"] < 2**31
            or row["id"] in seen
            or any(type(row.get(key)) is not bool for key in ("disabled", "dpmsStatus"))
            or any(
                type(row.get(key)) is not int or not 0 <= row[key] <= 32768
                for key in ("width", "height")
            )
        ):
            raise RuntimeError("native compositor diagnostics are unsupported")
        seen.add(row["id"])
    # Aggregate current context only. No identifiers, dimensions or names leave
    # this decoder, and no count can prove coverage of the original generation.
    return {
        "count": len(rows),
        "enabled_count": sum(not row["disabled"] for row in rows),
        "powered_count": sum(not row["disabled"] and row["dpmsStatus"] for row in rows),
        "zero_mode_count": sum(row["width"] == 0 or row["height"] == 0 for row in rows),
    }


def corroborate_locked_output_inventory(guest: Guest, resource: str) -> dict[str, int]:
    """Read-only compositor context; never evidence of secure lock coverage."""
    lock_resource(resource)
    # Native lock receipts and protected owner prove security. Hyprctl's first
    # discovered instance is only a bounded corroborating observation and must
    # never be treated as the attested original Wayland connection.
    uid = resource.split(":")[3]
    command = (
        "sudo -n /usr/bin/timeout --kill-after=1 2 "
        "/usr/bin/runuser -u linura -- /usr/bin/env "
        f"XDG_RUNTIME_DIR=/run/user/{uid} "
        "/usr/bin/hyprctl -i 0 -j monitors all"
    )
    counts = compositor_failure_monitors(guest.run(command))
    if counts["enabled_count"] == 0 or counts["powered_count"] == 0:
        raise RuntimeError("native compositor has no usable observed output")
    return counts


def exercise_locked_headless_hotplug(
    guest: Guest, resource: str, suffix: str, baseline: dict[str, int]
) -> dict[str, dict[str, int]]:
    """Native VM topology exercise; not independent lock-coverage proof."""
    lock_resource(resource)
    if re.fullmatch(r"[0-9a-f]{16}", suffix) is None or baseline["count"] >= 16:
        raise RuntimeError("native qualification output identity is unsupported")
    uid = resource.split(":")[3]
    prefix = (
        "sudo -n /usr/bin/timeout --kill-after=1 2 "
        "/usr/bin/runuser -u linura -- /usr/bin/env "
        f"XDG_RUNTIME_DIR=/run/user/{uid} /usr/bin/hyprctl -i 0 "
    )
    name = "linura-s17-" + suffix
    during: dict[str, int] | None = None
    try:
        # An uncertain create result must still attempt cleanup.
        if guest.run(prefix + "output create headless " + name).strip() != b"ok":
            raise RuntimeError("native headless output creation was not acknowledged")
        for _ in range(5):
            sample = corroborate_locked_output_inventory(guest, resource)
            if (
                sample["count"] == baseline["count"] + 1
                and sample["enabled_count"] == baseline["enabled_count"] + 1
                and sample["powered_count"] == baseline["powered_count"] + 1
                and sample["zero_mode_count"] == baseline["zero_mode_count"]
            ):
                during = sample
                break
            time.sleep(0.1)
        if during is None:
            raise RuntimeError("native headless output did not become usable")
        # First-party metadata must still be present. It is not secure coverage.
        validate_assistive_report(
            guest.run(ASSISTIVE_COMMAND + "locked"), resource, "locked"
        )
    finally:
        if guest.run(prefix + "output remove " + name).strip() != b"ok":
            raise RuntimeError("native headless output cleanup was not acknowledged")
    restored = corroborate_locked_output_inventory(guest, resource)
    if restored != baseline:
        raise RuntimeError("native compositor output topology was not restored")
    return {"during-hotplug": during, "after-hotplug": restored}


COMPOSITOR_FAILURE_MARKERS = (
    ("lock-request", "New sessionLock with id "),
    ("lock-admitted", "Session got locked by "),
    ("surface-request", "New sessionLockSurface with id "),
    ("lock-fallback", "Sending locked after a 5 second timeout."),
    ("null-buffer", "SessionLock attached a null buffer"),
    ("missing-configure-ack", "SessionLock committed without an ack"),
    ("departed-output", "onGetLockSurface: monitor is gone for output resource"),
    ("invalid-output", "onGetLockSurface: invalid output resource"),
    ("departed-configure-output", "sendConfigure: monitor is gone"),
    ("restore-denied", "Cannot re-lock, misc:allow_session_lock_restore is disabled"),
    ("swapchain-unavailable", "Failed to acquire swapchain buffer for "),
    ("texture-unavailable", "Cannot create a texture:"),
    ("render-pass-unavailable", "failed to start a render pass for output "),
    ("renderer-unavailable", "renderer: couldn't beginRender()!"),
    ("invalid-mode", "Refusing to render a monitor because of an invalid pixel size:"),
    ("session-inactive", "drm: Session inactive"),
    ("render-session-inactive", "Attempted to render frame on inactive session!"),
    ("session-activated", "Session got activated!"),
    ("session-deactivated", "Session got deactivated!"),
    ("device-restore", "drm: Restoring after VT switch"),
    ("stale-flip-cleared", "drm: Clearing stale page-flip state for "),
    ("monitor-damaged", "Damage: Monitor "),
    ("page-flip", "drm: pf event seq "),
    ("buffer-committed", "drm: Committed a buffer, updating state"),
    ("page-flip-without-frame", "drm: Ignoring pf event on "),
    ("page-flip-departed", "drm: Ignoring a pf event whose connector is gone"),
    ("page-flip-inactive", "drm: Ignoring a pf event from a disabled crtc / connector"),
    ("restore-failed", " failed restore"),
    ("commit-failed", "atomic drm request: failed to commit:"),
    ("flip-blocked", "drm: Cannot commit when a page-flip is awaiting"),
    ("frame-discarded", "dropping its frame"),
    ("stale-flip", "drm: Ignoring a stale pf event, flip "),
    ("enable-without-mode", "drm: No mode on enable commit"),
    ("commit-without-buffer", "drm: No buffer committed"),
)


def compositor_failure_log(wire: bytes) -> list[str]:
    if len(wire) > MAXIMUM_OUTPUT:
        raise RuntimeError("native compositor diagnostics exceed their bound")
    try:
        rows = wire.decode("utf-8").splitlines()
    except UnicodeError:
        raise RuntimeError("native compositor diagnostics are malformed") from None
    if len(rows) > 256:
        raise RuntimeError("native compositor diagnostics exceed their bound")
    labels = []
    # Aquamarine-only tracing: retain scheduler flags, never raw device, input,
    # framebuffer, timestamp or object data. General compositor/Wayland tracing
    # stays disabled. This read cannot repair or qualify the failed operation.
    for row in rows:
        labels.extend(
            label for label, marker in COMPOSITOR_FAILURE_MARKERS if marker in row
        )
        match = re.search(
            r"CDRMOutput::scheduleFrame: reason ([0-9]{1,3}), needsFrame (true|false), "
            r"isPageFlipPending (true|false), frameEventScheduled (true|false)$",
            row,
        )
        if match is not None and int(match[1]) <= 255:
            labels.append(
                "frame-schedule:needs="
                + str(int(match[2] == "true"))
                + ":in-flight="
                + str(int(match[3] == "true"))
                + ":scheduled="
                + str(int(match[4] == "true"))
            )
    return labels


def owner_failure_diagnostics(guest: Guest, resource: str) -> dict[str, object]:
    try:
        lock_resource(resource)
    except Exception:
        return {"claim": "failure-diagnostics-only", "unavailable": True}
    unit = "linura-security-owner@" + resource.split(":")[3] + ".service"
    try:
        # Fixed read-only query, independently bounded and restricted to the
        # validated owner's unit. Raw properties never leave this decoder.
        state = native_owner_failure_state(
            guest.run(
                "sudo -n /usr/bin/timeout 3 /usr/bin/systemctl show " + unit + " "
                "--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MainPID,InvocationID --no-pager"
            ),
            resource,
        )
    except Exception:
        state = {"claim": "failure-diagnostics-only", "unavailable": True}
    try:
        state.update(
            native_owner_failure_journal(
                guest.run(
                    "sudo -n /usr/bin/timeout 3 /usr/bin/journalctl --boot=0 --no-pager --quiet "
                    "--output=json --output-fields=EXIT_CODE,EXIT_STATUS,MESSAGE --lines=64 --unit="
                    + unit
                )
            )
        )
    except Exception:
        state["journal_unavailable"] = True
    # Fixed read-only compositor context after failure, under the disposable
    # account. Select the first live instance explicitly: this SSH context has
    # no HYPRLAND_INSTANCE_SIGNATURE, which hyprctl otherwise requires. Ambient
    # instance discovery is NOT original-invocation evidence.
    # Original failure/cleanup remain mandatory even when either query fails.
    prefix = (
        "sudo -n /usr/bin/timeout --kill-after=1 2 /usr/bin/runuser -u linura -- /usr/bin/env "
        "XDG_RUNTIME_DIR=/run/user/"
        + resource.split(":")[3]
        + " /usr/bin/hyprctl -i 0 "
    )
    try:
        state["compositor_monitors"] = compositor_failure_monitors(
            guest.run(prefix + "-j monitors all")
        )
    except Exception:
        state["compositor_monitors_unavailable"] = True
    try:
        state["compositor_events"] = compositor_failure_log(
            guest.run(
                "set -o pipefail; "
                + prefix
                + "rollinglog | /usr/bin/tail -c 12000 | /usr/bin/tail -n +2 | /usr/bin/tail -n 128"
            )
        )
    except Exception:
        state["compositor_log_unavailable"] = True
    return state


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
    output_context: dict[str, dict[str, int]] = {}

    def require_locked_presentation() -> None:
        # A retired consent prompt or elapsed denial must leave native retry
        # usable. This reads protected metadata; it cannot reset a cooldown or
        # start/authenticate an unlock request.
        validate_assistive_report(
            guest.run(ASSISTIVE_COMMAND + "locked"), resource, "locked"
        )

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
        output_context["after-lock"] = corroborate_locked_output_inventory(
            guest, resource
        )
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
        output_context["after-recovery"] = corroborate_locked_output_inventory(
            guest, resource
        )
        if output_context["after-recovery"] != output_context["after-lock"]:
            raise RuntimeError(
                "native compositor output context changed during retained lock"
            )
        checks["locked-compositor-output-context-corroborated"] = True
        output_context.update(
            exercise_locked_headless_hotplug(
                guest, resource, suffix, output_context["after-recovery"]
            )
        )
        checks["headless-output-hotplug-observed-under-retained-lock"] = True
        # Exercise account denial before consent's successful PAM conversation.
        # Three consecutive negative cases can legitimately trigger the distro's
        # failure lockout. Only real subsequent authentication may clear its tally;
        # never reset it, alter PAM or replace the native owner for this runner.
        guest.run(FIXTURE_COMMAND + "clear-response")
        guest.run(
            prefix
            + f"unlock-session s17-native-account-locked-{suffix} S17-native-account-denial",
            lambda: native_input.response(response),
            expect_failure=True,
            # Account rejection may precede a prompt; only actual exit-1 denial
            # qualifies, never SSH failure, timeout or success.
            allow_early_denial=True,
        )
        checks["password-locked-account-cannot-complete-unlock"] = True
        time.sleep(NATIVE_DENIAL_SETTLE_SECONDS)
        require_locked_presentation()
        guest.run(
            FIXTURE_COMMAND + "set-response", payload=(response + "\n").encode("ascii")
        )
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
            require_locked_presentation()
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
        require_locked_presentation()
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
        require_locked_presentation()

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
    except RuntimeError:
        print(
            "native-owner-failure-state="
            + json.dumps(owner_failure_diagnostics(guest, resource), sort_keys=True),
            file=sys.stderr,
        )
        raise
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
        "compositor_output_context": output_context,
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
