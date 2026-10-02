#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tomllib
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = Path("contracts/v010-workstation-slices.toml")


class SliceGraphError(RuntimeError):
    pass


def load_contract(root: Path = ROOT) -> dict[str, Any]:
    path = root / CONTRACT_PATH
    if not path.is_file() or path.is_symlink():
        raise SliceGraphError(f"missing or unsafe slice contract: {CONTRACT_PATH}")
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise SliceGraphError(f"invalid slice contract: {error}") from error


def _slice_entries(contract: dict[str, Any]) -> list[dict[str, Any]]:
    entries = contract.get("slice")
    if not isinstance(entries, list):
        raise SliceGraphError("slice contract must define [[slice]] entries")
    if not all(isinstance(item, dict) for item in entries):
        raise SliceGraphError("every slice entry must be a table")
    return entries


def validate_graph(contract: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        entries = _slice_entries(contract)
    except SliceGraphError as error:
        return [str(error)]
    ids: list[str] = []
    by_id: dict[str, dict[str, Any]] = {}

    for index, item in enumerate(entries, start=1):
        slice_id = item.get("id")
        if not isinstance(slice_id, str) or not slice_id:
            errors.append(f"slice #{index} has invalid id")
            continue
        if slice_id in by_id:
            errors.append(f"duplicate slice id: {slice_id}")
            continue
        ids.append(slice_id)
        by_id[slice_id] = item

    for slice_id in ids:
        item = by_id[slice_id]
        status = item.get("status")
        if not isinstance(status, str) or status not in {"complete", "planned"}:
            errors.append(f"{slice_id}: status must be complete or planned")
        dependencies = item.get("depends_on")
        if not isinstance(dependencies, list) or not all(
            isinstance(value, str) and value for value in dependencies
        ):
            errors.append(f"{slice_id}: depends_on must be a string array")
            continue
        if len(set(dependencies)) != len(dependencies):
            errors.append(f"{slice_id}: depends_on must not contain duplicates")
        if slice_id in dependencies:
            errors.append(f"{slice_id}: slice cannot depend on itself")
        for dependency in dependencies:
            if dependency not in by_id:
                errors.append(f"{slice_id}: unknown dependency {dependency}")

    if errors:
        return errors

    state: dict[str, int] = {slice_id: 0 for slice_id in ids}
    stack: list[str] = []
    cycle_reported = False

    def visit(slice_id: str) -> None:
        nonlocal cycle_reported
        if cycle_reported:
            return
        state[slice_id] = 1
        stack.append(slice_id)
        dependencies = by_id[slice_id]["depends_on"]
        for dependency in dependencies:
            if state[dependency] == 0:
                visit(dependency)
                if cycle_reported:
                    return
            elif state[dependency] == 1:
                start = stack.index(dependency)
                cycle = stack[start:] + [dependency]
                errors.append("slice dependency graph contains cycle: " + " -> ".join(cycle))
                cycle_reported = True
                return
        stack.pop()
        state[slice_id] = 2

    for slice_id in ids:
        if state[slice_id] == 0:
            visit(slice_id)
        if cycle_reported:
            break

    if errors:
        return errors

    complete = {
        slice_id
        for slice_id in ids
        if by_id[slice_id].get("status") == "complete"
    }
    for slice_id in ids:
        if slice_id not in complete:
            continue
        missing = [
            dependency
            for dependency in by_id[slice_id]["depends_on"]
            if dependency not in complete
        ]
        if missing:
            errors.append(
                f"{slice_id}: completed slice has incomplete dependencies: "
                + ", ".join(missing)
            )

    return errors


def _validated_index(
    contract: dict[str, Any],
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    errors = validate_graph(contract)
    if errors:
        raise SliceGraphError("; ".join(errors))
    entries = _slice_entries(contract)
    ids = [item["id"] for item in entries]
    return ids, {item["id"]: item for item in entries}


def ready_ids(contract: dict[str, Any]) -> list[str]:
    ids, by_id = _validated_index(contract)
    complete = {
        slice_id
        for slice_id in ids
        if by_id[slice_id]["status"] == "complete"
    }
    return [
        slice_id
        for slice_id in ids
        if by_id[slice_id]["status"] == "planned"
        and all(dependency in complete for dependency in by_id[slice_id]["depends_on"])
    ]


def execution_waves(contract: dict[str, Any]) -> list[list[str]]:
    ids, by_id = _validated_index(contract)
    complete = {
        slice_id
        for slice_id in ids
        if by_id[slice_id]["status"] == "complete"
    }
    pending = [
        slice_id
        for slice_id in ids
        if by_id[slice_id]["status"] == "planned"
    ]
    waves: list[list[str]] = []

    while pending:
        wave = [
            slice_id
            for slice_id in pending
            if all(dependency in complete for dependency in by_id[slice_id]["depends_on"])
        ]
        if not wave:
            raise SliceGraphError(
                "slice graph has no schedulable frontier; dependency validation is inconsistent"
            )
        waves.append(wave)
        complete.update(wave)
        wave_set = set(wave)
        pending = [slice_id for slice_id in pending if slice_id not in wave_set]

    return waves


def explain_slice(contract: dict[str, Any], slice_id: str) -> dict[str, Any]:
    ids, by_id = _validated_index(contract)
    if slice_id not in by_id:
        raise SliceGraphError(f"unknown slice: {slice_id}")
    item = by_id[slice_id]
    complete = {
        value
        for value in ids
        if by_id[value]["status"] == "complete"
    }
    dependencies = list(item["depends_on"])
    blockers = [value for value in dependencies if value not in complete]
    dependents = [
        value
        for value in ids
        if slice_id in by_id[value]["depends_on"]
    ]
    return {
        "id": slice_id,
        "title": item.get("title"),
        "status": item["status"],
        "depends_on": dependencies,
        "blocked_by": blockers,
        "direct_dependents": dependents,
        "ready": item["status"] == "planned" and not blockers,
    }


def _print_ready(contract: dict[str, Any], as_json: bool) -> None:
    ids, by_id = _validated_index(contract)
    ready = ready_ids(contract)
    if as_json:
        print(
            json.dumps(
                [
                    {"id": slice_id, "title": by_id[slice_id].get("title")}
                    for slice_id in ready
                ],
                indent=2,
            )
        )
        return
    for slice_id in ready:
        print(f"{slice_id}\t{by_id[slice_id].get('title', '')}")


def _print_waves(contract: dict[str, Any], as_json: bool) -> None:
    ids, by_id = _validated_index(contract)
    waves = execution_waves(contract)
    if as_json:
        print(
            json.dumps(
                [
                    [
                        {"id": slice_id, "title": by_id[slice_id].get("title")}
                        for slice_id in wave
                    ]
                    for wave in waves
                ],
                indent=2,
            )
        )
        return
    for index, wave in enumerate(waves, start=1):
        print(f"wave {index}: " + " ".join(wave))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect the v0.10 workstation slice dependency graph"
    )
    parser.add_argument("--root", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="command", required=True)

    ready = sub.add_parser("ready")
    ready.add_argument("--json", action="store_true")

    waves = sub.add_parser("waves")
    waves.add_argument("--json", action="store_true")

    explain = sub.add_parser("explain")
    explain.add_argument("slice_id")
    explain.add_argument("--json", action="store_true")

    args = parser.parse_args()
    try:
        contract = load_contract(args.root.resolve())
        if args.command == "ready":
            _print_ready(contract, args.json)
            return 0
        if args.command == "waves":
            _print_waves(contract, args.json)
            return 0
        if args.command == "explain":
            result = explain_slice(contract, args.slice_id)
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(f"{result['id']}: {result['title']}")
                print(f"status: {result['status']}")
                print("depends_on: " + (" ".join(result["depends_on"]) or "-"))
                print("blocked_by: " + (" ".join(result["blocked_by"]) or "-"))
                print("direct_dependents: " + (" ".join(result["direct_dependents"]) or "-"))
                print(f"ready: {'yes' if result['ready'] else 'no'}")
            return 0
        raise SliceGraphError(f"unsupported command: {args.command}")
    except (SliceGraphError, OSError, KeyError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
