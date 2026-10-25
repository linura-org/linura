"""Bounded qualification-only QMP input/suspend wake; never a product authority.

Only a private local socket belonging to the disposable runner is accepted.
No human-monitor shell, guest agent, arbitrary command, TCP or credential argv.
Component tests of this transport are not native authentication evidence.
"""

from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import re
import socket
import stat
import time
from typing import Any


MAXIMUM_REPLY = 16384


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate QMP field")
        result[key] = value
    return result


def validate_socket(path: Path) -> None:
    if (
        not path.is_absolute()
        or len(os.fsencode(path)) > 100
        or re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)) is None
    ):
        raise RuntimeError("native input socket path is unsupported")
    try:
        parent = path.parent.lstat()
        metadata = path.lstat()
        trusted = (
            path.parent.resolve(strict=True) == path.parent
            and stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == os.getuid()
            and stat.S_IMODE(parent.st_mode) == 0o700
            and stat.S_ISSOCK(metadata.st_mode)
            and metadata.st_uid == os.getuid()
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) & 0o077 == 0
        )
    except OSError:
        trusted = False
    if not trusted:
        raise RuntimeError("native input socket is not private and runner-owned")


class NativeInput:
    def __init__(self, path: Path):
        validate_socket(path)
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(2)
        self._sequence = 0
        self._buffer = bytearray()
        self._events: deque[dict[str, Any]] = deque()
        try:
            self._socket.connect(str(path))
            greeting = self._read(time.monotonic() + 2)
            if set(greeting) != {"QMP"} or not isinstance(greeting["QMP"], dict):
                raise RuntimeError("native input QMP greeting is malformed")
            self._request("qmp_capabilities")
            status = self._request("query-status")
            if (
                not isinstance(status, dict)
                or status.get("running") is not True
                or status.get("status") != "running"
            ):
                raise RuntimeError("native input requires a running qualification VM")
        except Exception:
            self.close()
            raise RuntimeError("native input QMP initialization failed") from None

    def close(self) -> None:
        self._socket.close()

    def __enter__(self) -> NativeInput:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _read(self, deadline: float) -> dict[str, Any]:
        try:
            while b"\n" not in self._buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or len(self._buffer) >= MAXIMUM_REPLY:
                    raise ValueError("bounded QMP message missing")
                self._socket.settimeout(remaining)
                chunk = self._socket.recv(min(4096, MAXIMUM_REPLY - len(self._buffer)))
                if not chunk:
                    raise ValueError("QMP disconnected")
                self._buffer.extend(chunk)
            end = self._buffer.index(b"\n") + 1
            wire = bytes(self._buffer[:end])
            del self._buffer[:end]
            value = json.loads(wire, object_pairs_hook=unique_object)
            if not isinstance(value, dict):
                raise ValueError("QMP object missing")
            return value
        except (OSError, ValueError, RecursionError):
            # Never include wire bytes, responses or credentials in diagnostics.
            raise RuntimeError(
                "native input QMP reply is unavailable or malformed"
            ) from None

    def _request(self, method: str, arguments: dict[str, Any] | None = None) -> Any:
        if method not in {
            "qmp_capabilities",
            "query-status",
            "input-send-event",
            "query-current-machine",
            "system_wakeup",
        }:
            raise RuntimeError("unsupported native input mechanism")
        self._sequence += 1
        request: dict[str, Any] = {"execute": method, "id": self._sequence}
        if arguments is not None:
            request["arguments"] = arguments
        deadline = time.monotonic() + 2
        try:
            self._socket.settimeout(2)
            self._socket.sendall(
                json.dumps(request, separators=(",", ":")).encode("ascii") + b"\n"
            )
            for _ in range(32):
                if time.monotonic() >= deadline:
                    raise RuntimeError("native input QMP deadline exceeded")
                reply = self._read(deadline)
                if "event" in reply and "id" not in reply:
                    # Guest termination can race the final input acknowledgement.
                    # Retain bounded wire evidence for the transition observer
                    # instead of losing it while waiting for a command reply.
                    if len(self._events) >= 32:
                        raise RuntimeError("native input QMP event budget exceeded")
                    self._events.append(reply)
                    continue
                if (
                    type(reply.get("id")) is not int
                    or reply["id"] != self._sequence
                    or set(reply) != {"id", "return"}
                ):
                    raise RuntimeError("native input QMP response mismatch or denial")
                return reply["return"]
        except OSError:
            raise RuntimeError("native input QMP transport failed") from None
        raise RuntimeError("native input QMP event budget exceeded")

    def require_suspend_wakeup(self) -> None:
        machine = self._request("query-current-machine")
        if (
            not isinstance(machine, dict)
            or machine.get("wakeup-suspend-support") is not True
        ):
            raise RuntimeError(
                "qualification VM cannot safely wake from native suspend"
            )

    def wait_suspended_and_wake(self, budget: int = 75) -> None:
        if type(budget) is not int or not 1 <= budget <= 80:
            raise RuntimeError("native suspend observation budget is unsupported")
        self.require_suspend_wakeup()
        deadline = time.monotonic() + budget
        woke = False
        while time.monotonic() < deadline:
            status = self._request("query-status")
            if time.monotonic() >= deadline:
                break
            if not isinstance(status, dict) or type(status.get("running")) is not bool:
                raise RuntimeError("native suspend QMP state is malformed")
            if status.get("status") == "running" and status["running"] is True:
                if woke:
                    return
            elif status.get("status") == "suspended" and status["running"] is False:
                if not woke:
                    # Exactly one wake, only after independent suspended state.
                    # QMP acknowledgement alone never proves native completion.
                    if self._request("system_wakeup") != {}:
                        raise RuntimeError(
                            "native suspend wake acknowledgement is malformed"
                        )
                    woke = True
            else:
                raise RuntimeError("unexpected native suspend QMP state")
            time.sleep(0.1)
        raise RuntimeError("native suspend/resume exceeded its original deadline")

    def wait_guest_termination(self, purpose: str, budget: int = 80) -> None:
        if (
            purpose not in {"reboot", "power-off"}
            or type(budget) is not int
            or not 1 <= budget <= 80
        ):
            raise RuntimeError("native terminating observation is unsupported")
        expected = "RESET" if purpose == "reboot" else "SHUTDOWN"
        reason = "guest-reset" if purpose == "reboot" else "guest-shutdown"
        deadline = time.monotonic() + budget
        for _ in range(32):
            if time.monotonic() >= deadline:
                break
            event = self._events.popleft() if self._events else self._read(deadline)
            if time.monotonic() >= deadline:
                break
            if event.get("event") in {"STOP", "RESUME"} and "id" not in event:
                continue
            if (
                set(event) != {"event", "data", "timestamp"}
                or event["event"] != expected
                or event["data"] != {"guest": True, "reason": reason}
                or not isinstance(event["data"], dict)
                or event["data"].get("guest") is not True
            ):
                raise RuntimeError("native transition was not the required guest event")
            # Corroboration only. Independent native verification must still
            # prove the original session/boot ended for the retained request.
            return
        raise RuntimeError("native terminating event exceeded its original bound")

    def key(self, qcode: str) -> None:
        if re.fullmatch(r"[a-z0-9]|ret|esc|backspace|tab|up|down", qcode) is None:
            raise RuntimeError("unsupported native input key")
        # One physical press/release, not a virtual-keyboard Wayland client.
        self._request(
            "input-send-event",
            {
                "events": [
                    {
                        "type": "key",
                        "data": {"down": down, "key": {"type": "qcode", "data": qcode}},
                    }
                    for down in (True, False)
                ]
            },
        )

    def response(self, ephemeral_response: str) -> None:
        if re.fullmatch(r"[a-z0-9]{24}", ephemeral_response) is None:
            raise RuntimeError("qualification response shape is unsupported")
        for character in ephemeral_response:
            self.key(character)
            # QMP acknowledges enqueueing, not guest consumption. The PC's PS/2
            # device drops scan codes beyond its 16-byte queue; a response burst
            # can lose its final Enter and expire the real protected prompt.
            # Fixed human-speed input fits the original interaction deadline.
            time.sleep(0.05)
        self.key("ret")

    def click(self, x: int, y: int) -> None:
        if (
            type(x) is not int
            or type(y) is not int
            or not (0 <= x <= 32767 and 0 <= y <= 32767)
        ):
            raise RuntimeError("native pointer coordinates are unsupported")
        self._request(
            "input-send-event",
            {
                "events": [
                    {"type": "abs", "data": {"axis": "x", "value": x}},
                    {"type": "abs", "data": {"axis": "y", "value": y}},
                    {"type": "btn", "data": {"down": True, "button": "left"}},
                    {"type": "btn", "data": {"down": False, "button": "left"}},
                ]
            },
        )
