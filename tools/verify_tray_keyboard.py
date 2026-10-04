#!/usr/bin/env python3
"""Independent receiver assertions for native tray input, never video-derived."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def strict_json(value: str):
    def unique(pairs: list) -> dict:
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate tray snapshot field")
            result[key] = item
        return result

    return json.loads(value, object_pairs_hook=unique)


def decode_snapshot(value: str) -> dict:
    if len(value) > 4096:
        raise ValueError("oversized tray snapshot")
    snapshot = strict_json(value)
    fields = {"activations", "opens", "presses", "releases", "repeats", "pressMs", "releaseMs", "visible"}
    if not isinstance(snapshot, dict) or set(snapshot) != fields:
        raise ValueError("invalid tray snapshot fields")
    for name in fields - {"visible"}:
        if type(snapshot[name]) is not int or not 0 <= snapshot[name] <= 2**53 - 1:
            raise ValueError("invalid tray snapshot counter or timestamp")
    if type(snapshot["visible"]) is not bool:
        raise ValueError("invalid tray snapshot visibility")
    return snapshot


def verify(mode: str, before: dict, after: dict, producer: str, held: dict | None = None) -> dict:
    if mode not in {"tap", "hold"}:
        raise ValueError("unsupported tray input mode")
    receipt = re.fullmatch(r"(tap|hold) press_ms=(\d{1,10}) release_ms=(\d{1,10})", producer)
    if receipt is None or receipt[1] != mode:
        raise ValueError("invalid native input receipt")
    press, release = int(receipt[2]), int(receipt[3])
    if press > 2**32 - 1 or release > 2**32 - 1:
        raise ValueError("invalid native input timestamps")
    if before["visible"] or not after["visible"]:
        raise ValueError("tray did not transition from closed to open")
    for key in ("activations", "opens", "presses", "releases"):
        if after[key] != before[key] + 1:
            raise ValueError(f"tray {key} was not observed exactly once")
    if after["repeats"] < before["repeats"]:
        raise ValueError("tray repeat counter regressed")
    if mode == "hold" and after["repeats"] <= before["repeats"]:
        raise ValueError("receiver did not exercise auto-repeat filtering")
    if mode == "hold":
        if held is None or not holding_ready(before, held) or after["repeats"] < held["repeats"]:
            raise ValueError("held-key receiver checkpoint missing or invalid")
    elif held is not None:
        raise ValueError("unexpected held-key checkpoint for tap")
    if after["releaseMs"] < after["pressMs"] or after["pressMs"] < before["pressMs"]:
        raise ValueError("tray receiver timestamps regressed")
    return {"mode": mode, "before": before, "held": held, "after": after, "producer": producer}


def holding_ready(before: dict, after: dict) -> bool:
    # No activation or popup is permitted while the original key is held.
    for key in ("activations", "opens", "releases"):
        if after[key] != before[key]:
            raise ValueError("tray activated before physical key release")
    if before["visible"] or after["visible"]:
        raise ValueError("tray opened before physical key release")
    return after["presses"] == before["presses"] + 1 and after["repeats"] > before["repeats"]


def verify_records(value: str) -> None:
    if len(value) > 65536:
        raise ValueError("oversized tray behavior report")
    rows = value.splitlines()
    if len(rows) != 6:
        raise ValueError("tray behavior report requires five taps and one hold")
    previous = None
    for index, line in enumerate(rows):
        record = strict_json(line)
        if not isinstance(record, dict) or set(record) != {"mode", "before", "held", "after", "producer"}:
            raise ValueError("invalid tray behavior record")
        before = decode_snapshot(json.dumps(record["before"]))
        after = decode_snapshot(json.dumps(record["after"]))
        expected = "hold" if index == 5 else "tap"
        if record["mode"] != expected:
            raise ValueError("tray input case order changed")
        held = None if record["held"] is None else decode_snapshot(json.dumps(record["held"]))
        verify(expected, before, after, record["producer"], held)
        if previous is not None:
            for key in ("activations", "opens", "presses", "releases", "repeats"):
                if before[key] != previous[key]:
                    raise ValueError("unaccounted tray input between cases")
        previous = after


def verify_retained(behavior_path: Path, events_path: Path, digest_path: Path) -> None:
    def bounded_text(path: Path, limit: int) -> str:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("oversized native input evidence")
        return data.decode("utf-8")

    report = bounded_text(behavior_path, 65536)
    verify_records(report)
    producers = [json.loads(line)["producer"] for line in report.splitlines()]
    events = bounded_text(events_path, 4096).splitlines()
    if len(events) != 9 or events[:5] != producers[:5] or events[6] != producers[5] or events[-1] != "quit":
        raise ValueError("native input receipts disagree with receiver evidence")
    hold_start = re.fullmatch(r"held press_ms=(\d{1,10})", events[5])
    if hold_start is None or not events[6].startswith(f"hold press_ms={hold_start[1]} release_ms="):
        raise ValueError("native hold lifecycle receipts disagree")
    if re.fullmatch(r"escape press_ms=\d{1,10} release_ms=\d{1,10}", events[7]) is None:
        raise ValueError("native Escape receipt missing")
    digest = bounded_text(digest_path, 256).strip()
    if re.fullmatch(r"[0-9a-f]{64}  /usr/local/lib/linura-qualification/native-keyboard", digest) is None:
        raise ValueError("native input binary digest missing or malformed")


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "holding":
        try:
            ready = holding_ready(decode_snapshot(sys.argv[2]), decode_snapshot(sys.argv[3]))
        except (ValueError, TypeError, KeyError) as error:
            raise SystemExit(f"native held-key verification failed: {error}") from error
        raise SystemExit(0 if ready else 1)
    if len(sys.argv) != 6:
        raise SystemExit("usage: verify_tray_keyboard.py tap|hold BEFORE_JSON AFTER_JSON RECEIPT HELD_JSON|null")
    try:
        result = verify(sys.argv[1], decode_snapshot(sys.argv[2]),
                        decode_snapshot(sys.argv[3]), sys.argv[4],
                        None if sys.argv[5] == "null" else decode_snapshot(sys.argv[5]))
    except (ValueError, TypeError, KeyError) as error:
        raise SystemExit(f"native tray input verification failed: {error}") from error
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
