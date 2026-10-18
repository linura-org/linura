#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "tests/acceptance"


def scenarios() -> list[dict]:
    result = []
    for path in sorted(SCENARIOS.glob("*.json")):
        item = json.loads(path.read_text(encoding="utf-8"))
        status = item.get("execution_status")
        if status not in ("executable", "reserved"):
            raise SystemExit(f"scenario has invalid execution status: {path}")
        reason = item.get("reservation_reason")
        if status == "reserved" and (not isinstance(reason, str) or not reason.strip()):
            raise SystemExit(f"reserved scenario needs a reason: {path}")
        if status == "executable" and reason is not None:
            raise SystemExit(f"executable scenario cannot carry a reservation: {path}")
        item["_path"] = path
        result.append(item)
    return result


def find_scenario(scenario_id: str) -> dict:
    for scenario in scenarios():
        if scenario["id"] == scenario_id:
            return scenario
    raise SystemExit(f"unknown acceptance scenario: {scenario_id}")


def ssh_base(host: str, user: str, port: int, identity: str | None) -> list[str]:
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=10",
        "-p",
        str(port),
    ]
    if identity:
        command.extend(["-i", identity])
    command.append(f"{user}@{host}")
    return command


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Linura disposable-machine acceptance runner"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    listing = sub.add_parser("list")
    listing.add_argument("--json", action="store_true")
    run = sub.add_parser("run")
    run.add_argument("scenario")
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--user", default="linura")
    run.add_argument("--port", type=int, default=2222)
    run.add_argument("--identity")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--result-file", type=Path)
    run.add_argument("--source-sha")
    args = parser.parse_args()

    if args.command == "list":
        items = scenarios()
        if args.json:
            print(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scenarios": [
                            {
                                "id": item["id"],
                                "path": item["_path"].relative_to(ROOT).as_posix(),
                                "description": item["description"],
                                "execution_status": item["execution_status"],
                                "requires": item["requires"],
                            }
                            for item in items
                        ],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            for item in items:
                print(
                    f"{item['id']} [{item['execution_status']}]: {item['description']}"
                )
        return 0

    scenario = find_scenario(args.scenario)
    if scenario["execution_status"] != "executable":
        raise SystemExit(
            f"scenario {scenario['id']} is reserved: {scenario['reservation_reason']}"
        )
    if args.dry_run and args.result_file is not None:
        raise SystemExit("--dry-run cannot produce acceptance result evidence")
    if args.result_file is not None and (
        args.source_sha is None
        or len(args.source_sha) != 40
        or any(ch not in "0123456789abcdef" for ch in args.source_sha)
    ):
        raise SystemExit("--result-file requires a full lowercase --source-sha")
    print(f"scenario: {scenario['id']} — {scenario['description']}")
    result_steps: list[dict[str, object]] = []

    def write_result(result: str) -> None:
        if args.result_file is None:
            return
        scenario_path = scenario["_path"]
        payload = {
            "schema_version": 1,
            "source_sha": args.source_sha,
            "scenario": {
                "id": scenario["id"],
                "path": scenario_path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(scenario_path.read_bytes()).hexdigest(),
            },
            "steps": result_steps,
            "result": result,
        }
        args.result_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.result_file.with_name(args.result_file.name + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(args.result_file)

    for step in scenario["steps"]:
        command_text = step["command"]
        command = ssh_base(args.host, args.user, args.port, args.identity) + [
            command_text
        ]
        print(f"[{step['name']}] {shlex.join(command)}")
        returncode = 0
        if not args.dry_run:
            completed = subprocess.run(command, check=False)
            returncode = completed.returncode
        result_steps.append(
            {
                "name": step["name"],
                "command_sha256": hashlib.sha256(
                    command_text.encode("utf-8")
                ).hexdigest(),
                "returncode": returncode,
            }
        )
        if returncode != 0:
            write_result("failed")
            print(f"FAILED: {step['name']} exited {returncode}", file=sys.stderr)
            return returncode
    write_result("passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
