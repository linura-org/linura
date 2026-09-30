#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tomllib
from typing import Any

VALID_STATUS = {"complete", "planned"}


class SliceGraphError(ValueError):
    pass


def load_contract(path: Path) -> dict[str, Any]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SliceGraphError(f"slice ledger not found: {path}") from error
    except Exception as error:
        raise SliceGraphError(f"invalid slice ledger: {error}") from error
    if not isinstance(data, dict):
        raise SliceGraphError("slice ledger root must be a table")
    return data


def _slices(contract: dict[str, Any]) -> list[dict[str, Any]]:
    value = contract.get("slice")
    if not isinstance(value, list):
        raise SliceGraphError("slice ledger must define [[slice]] entries")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            raise SliceGraphError(f"slice #{index} must be a table")
        result.append(item)
    return result


def validate_graph_contract(contract: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    try:
        slices = _slices(contract)
    except SliceGraphError as error:
        return [str(error)]

    index: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for position, item in enumerate(slices, start=1):
        slice_id = item.get("id")
        if not isinstance(slice_id, str) or not slice_id:
            failures.append(f"slice #{position}: id must be a non-empty string")
            continue
        if slice_id in index:
            failures.append(f"{slice_id}: duplicate slice id")
            continue
        index[slice_id] = item
        order.append(slice_id)

    for slice_id in order:
        item = index[slice_id]
        status = item.get("status")
        if status not in VALID_STATUS:
            failures.append(f"{slice_id}: status must be complete or planned")
        dependencies = item.get("depends_on")
        if not isinstance(dependencies, list) or not all(
            isinstance(value, str) and value for value in dependencies
        ):
            failures.append(f"{slice_id}: depends_on must be a string list")
            continue
        if len(set(dependencies)) != len(dependencies):
            failures.append(f"{slice_id}: depends_on contains duplicate dependencies")
        for dependency in dependencies:
            if dependency == slice_id:
                failures.append(f"{slice_id}: slice cannot depend on itself")
            elif dependency not in index:
                failures.append(f"{slice_id}: unknown dependency {dependency}")
        if status == "complete":
            for dependency in dependencies:
                dependency_item = index.get(dependency)
                if dependency_item is not None and dependency_item.get("status") != "complete":
                    failures.append(
                        f"{slice_id}: completed slice dependency {dependency} is not complete"
                    )

    color: dict[str, int] = {slice_id: 0 for slice_id in order}
    stack: list[str] = []

    def visit(slice_id: str) -> None:
        if color[slice_id] == 2:
            return
        if color[slice_id] == 1:
            if slice_id in stack:
                start = stack.index(slice_id)
                cycle = stack[start:] + [slice_id]
            else:
                cycle = stack + [slice_id]
            failures.append("v0.10 slice dependency graph contains cycle: " + " -> ".join(cycle))
            return
        color[slice_id] = 1
        stack.append(slice_id)
        dependencies = index[slice_id].get("depends_on")
        if isinstance(dependencies, list):
            for dependency in dependencies:
                if dependency in index:
                    visit(dependency)
        stack.pop()
        color[slice_id] = 2

    for slice_id in order:
        if color[slice_id] == 0:
            visit(slice_id)

    return failures


def _validated_index(contract: dict[str, Any]) -> tuple[list[str], dict[str, dict[str, Any]]]:
    failures = validate_graph_contract(contract)
    if failures:
        raise SliceGraphError("; ".join(failures))
    slices = _slices(contract)
    order = [str(item["id"]) for item in slices]
    return order, {str(item["id"]): item for item in slices}


def ready_slice_ids(contract: dict[str, Any]) -> list[str]:
    order, index = _validated_index(contract)
    completed = {
        slice_id for slice_id in order if index[slice_id].get("status") == "complete"
    }
    ready: list[str] = []
    for slice_id in order:
        item = index[slice_id]
        if item.get("status") != "planned":
            continue
        dependencies = item.get("depends_on", [])
        if all(dependency in completed for dependency in dependencies):
            ready.append(slice_id)
    return ready


def blocked_slice_ids(contract: dict[str, Any]) -> dict[str, list[str]]:
    order, index = _validated_index(contract)
    completed = {
        slice_id for slice_id in order if index[slice_id].get("status") == "complete"
    }
    blocked: dict[str, list[str]] = {}
    for slice_id in order:
        item = index[slice_id]
        if item.get("status") != "planned":
            continue
        missing = [
            dependency
            for dependency in item.get("depends_on", [])
            if dependency not in completed
        ]
        if missing:
            blocked[slice_id] = missing
    return blocked


def schedule_waves(contract: dict[str, Any]) -> list[list[str]]:
    order, index = _validated_index(contract)
    satisfied = {
        slice_id for slice_id in order if index[slice_id].get("status") == "complete"
    }
    remaining = [
        slice_id for slice_id in order if index[slice_id].get("status") == "planned"
    ]
    waves: list[list[str]] = []
    while remaining:
        wave = [
            slice_id
            for slice_id in remaining
            if all(
                dependency in satisfied
                for dependency in index[slice_id].get("depends_on", [])
            )
        ]
        if not wave:
            raise SliceGraphError("planned slice graph has no schedulable frontier")
        waves.append(wave)
        satisfied.update(wave)
        selected = set(wave)
        remaining = [slice_id for slice_id in remaining if slice_id not in selected]
    return waves


def status_payload(contract: dict[str, Any]) -> dict[str, Any]:
    order, index = _validated_index(contract)
    ready = ready_slice_ids(contract)
    blocked = blocked_slice_ids(contract)
    max_parallel = contract.get("max_parallel_active")
    if type(max_parallel) is not int or max_parallel < 1:
        raise SliceGraphError("max_parallel_active must be a positive integer")
    return {
        "schema_version": contract.get("schema_version"),
        "milestone": contract.get("milestone"),
        "completed": [
            slice_id for slice_id in order if index[slice_id].get("status") == "complete"
        ],
        "ready": ready,
        "recommended_batch": ready[:max_parallel],
        "blocked": blocked,
        "max_parallel_active": max_parallel,
        "waves": schedule_waves(contract),
    }


def _print_text(payload: dict[str, Any]) -> None:
    print("completed: " + (", ".join(payload["completed"]) or "-"))
    print("ready: " + (", ".join(payload["ready"]) or "-"))
    print("recommended_batch: " + (", ".join(payload["recommended_batch"]) or "-"))
    print(f"max_parallel_active: {payload['max_parallel_active']}")
    if payload["blocked"]:
        print("blocked:")
        for slice_id, dependencies in payload["blocked"].items():
            print(f"  {slice_id}: {', '.join(dependencies)}")
    else:
        print("blocked: -")
    print("waves:")
    for index, wave in enumerate(payload["waves"], start=1):
        print(f"  {index}: {', '.join(wave)}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect the v0.10 workstation slice dependency graph."
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "contracts/v010-workstation-slices.toml",
    )
    parser.add_argument("--json", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("ready")
    check = sub.add_parser("check")
    check.add_argument("slice_id")
    sub.add_parser("waves")
    args = parser.parse_args(argv[1:])

    try:
        contract = load_contract(args.ledger)
        payload = status_payload(contract)
    except SliceGraphError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    if args.command == "status":
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            _print_text(payload)
        return 0
    if args.command == "ready":
        values = payload["ready"]
        if args.json:
            print(json.dumps(values))
        else:
            for value in values:
                print(value)
        return 0
    if args.command == "waves":
        values = payload["waves"]
        if args.json:
            print(json.dumps(values))
        else:
            for index, wave in enumerate(values, start=1):
                print(f"{index}\t" + ",".join(wave))
        return 0

    slice_id = args.slice_id
    completed = set(payload["completed"])
    ready = set(payload["ready"])
    blocked = payload["blocked"]
    if slice_id in completed:
        state = {"slice": slice_id, "state": "complete", "blocked_by": []}
    elif slice_id in ready:
        state = {"slice": slice_id, "state": "ready", "blocked_by": []}
    elif slice_id in blocked:
        state = {"slice": slice_id, "state": "blocked", "blocked_by": blocked[slice_id]}
    else:
        print(f"ERROR: unknown slice id: {slice_id}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(state, sort_keys=True))
    else:
        print(state["state"])
        if state["blocked_by"]:
            print("blocked_by=" + ",".join(state["blocked_by"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
