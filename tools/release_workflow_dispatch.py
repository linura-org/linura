#!/usr/bin/env python3
"""Dispatch and authenticate GitHub Actions runs by nonce, then freeze exact run IDs."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import sys
import time
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

ACTIVE = {"queued", "in_progress", "pending", "waiting", "requested"}


def _token() -> str:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GH_TOKEN or GITHUB_TOKEN is required")
    return token


def _api(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    base = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        f"{base}{path}",
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {_token()}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "linura-release-control",
            **({"Content-Type": "application/json"} if data is not None else {}),
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read()
            return None if not raw else json.loads(raw.decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API {method} {path} failed: HTTP {exc.code}: {body}") from exc


def _workflow_path(workflow: str) -> str:
    return f".github/workflows/{workflow}"


def _list_runs(repository: str, workflow: str, ref: str) -> list[dict[str, Any]]:
    query = urlencode({"event": "workflow_dispatch", "branch": ref, "per_page": 100})
    payload = _api("GET", f"/repos/{repository}/actions/workflows/{quote(workflow, safe='')}/runs?{query}")
    runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
    if not isinstance(runs, list):
        raise RuntimeError("workflow-runs response is malformed")
    return [item for item in runs if isinstance(item, dict)]


def _workflow_name(repository: str, workflow: str) -> str:
    payload = _api("GET", f"/repos/{repository}/actions/workflows/{quote(workflow, safe='')}")
    name = payload.get("name") if isinstance(payload, dict) else None
    if not isinstance(name, str) or not name:
        raise RuntimeError(f"workflow metadata has no name: {workflow}")
    return name


def matching_runs(
    runs: list[dict[str, Any]], *, boundary: int, head_sha: str, ref: str, title: str, workflow: str
) -> list[dict[str, Any]]:
    expected_path = _workflow_path(workflow)
    return [
        run
        for run in runs
        if isinstance(run.get("id"), int)
        and run["id"] > boundary
        and run.get("event") == "workflow_dispatch"
        and run.get("head_sha") == head_sha
        and run.get("head_branch") == ref
        and run.get("display_title") == title
        and run.get("path") == expected_path
    ]


def validate_run(run: dict[str, Any], evidence: dict[str, Any]) -> None:
    expected = {
        "id": evidence["run_id"],
        "event": "workflow_dispatch",
        "head_sha": evidence["head_sha"],
        "head_branch": evidence["ref"],
        "display_title": evidence["title"],
        "path": _workflow_path(evidence["workflow"]),
    }
    for key, value in expected.items():
        if run.get(key) != value:
            raise RuntimeError(
                f"run identity mismatch for {evidence['workflow']} {evidence['run_id']}: "
                f"{key}={run.get(key)!r}, expected {value!r}"
            )


def _load_evidence(path: Path, expected_count: int) -> list[dict[str, Any]]:
    if not path.is_file():
        raise RuntimeError(f"evidence file is missing: {path}")
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(records) != expected_count:
        raise RuntimeError(f"expected {expected_count} dispatched runs, found {len(records)}")
    run_ids = [record.get("run_id") for record in records]
    if len(set(run_ids)) != len(run_ids):
        raise RuntimeError("duplicate run IDs in dispatch evidence")
    workflows = [record.get("workflow") for record in records]
    if len(set(workflows)) != len(workflows):
        raise RuntimeError("duplicate workflows in dispatch evidence")
    return records


def dispatch(args: argparse.Namespace) -> int:
    if not args.head_sha or len(args.head_sha) != 40:
        raise RuntimeError("head SHA must be a full 40-character commit SHA")
    evidence_path = Path(args.evidence_file)
    workflow_name = _workflow_name(args.repository, args.workflow)
    existing = _list_runs(args.repository, args.workflow, args.ref)
    boundary = max((run["id"] for run in existing if isinstance(run.get("id"), int)), default=0)
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "0")
    nonce = f"{args.phase}-{run_id}-{run_attempt}-{secrets.token_hex(16)}"
    title = f"{workflow_name} :: {nonce}"

    _api(
        "POST",
        f"/repos/{args.repository}/actions/workflows/{quote(args.workflow, safe='')}/dispatches",
        {"ref": args.ref, "inputs": {"dispatch_nonce": nonce}},
    )

    deadline = time.monotonic() + args.resolve_timeout_seconds
    selected: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        matches = matching_runs(
            _list_runs(args.repository, args.workflow, args.ref),
            boundary=boundary,
            head_sha=args.head_sha,
            ref=args.ref,
            title=title,
            workflow=args.workflow,
        )
        if len(matches) > 1:
            raise RuntimeError(
                f"ambiguous nonce-correlated dispatch for {args.workflow}: "
                f"{[run['id'] for run in matches]}"
            )
        if len(matches) == 1:
            selected = matches[0]
            break
        time.sleep(args.poll_seconds)
    if selected is None:
        raise RuntimeError(f"timed out resolving nonce-correlated run for {args.workflow}")

    record = {
        "repository": args.repository,
        "workflow": args.workflow,
        "run_id": selected["id"],
        "nonce": nonce,
        "title": title,
        "ref": args.ref,
        "head_sha": args.head_sha,
        "boundary": boundary,
    }
    validate_run(selected, record)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    with evidence_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    print(selected["id"])
    return 0


def _get_exact_run(record: dict[str, Any]) -> dict[str, Any]:
    payload = _api("GET", f"/repos/{record['repository']}/actions/runs/{record['run_id']}")
    if not isinstance(payload, dict):
        raise RuntimeError(f"run response is malformed: {record['run_id']}")
    validate_run(payload, record)
    return payload


def verify_records(records: list[dict[str, Any]]) -> None:
    for record in records:
        run = _get_exact_run(record)
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            raise RuntimeError(
                f"exact run is not successful: {record['workflow']}#{record['run_id']} "
                f"status={run.get('status')} conclusion={run.get('conclusion')}"
            )


def verify(args: argparse.Namespace) -> int:
    verify_records(_load_evidence(Path(args.evidence_file), args.expected_count))
    return 0


def wait(args: argparse.Namespace) -> int:
    records = _load_evidence(Path(args.evidence_file), args.expected_count)
    pending = {record["run_id"]: record for record in records}
    deadline = time.monotonic() + args.timeout_seconds
    while pending and time.monotonic() < deadline:
        for run_id, record in list(pending.items()):
            run = _get_exact_run(record)
            status = run.get("status")
            conclusion = run.get("conclusion")
            if status == "completed":
                if conclusion != "success":
                    raise RuntimeError(
                        f"exact dispatched run failed: {record['workflow']}#{run_id} conclusion={conclusion}"
                    )
                del pending[run_id]
            elif status not in ACTIVE:
                raise RuntimeError(f"unexpected run status: {record['workflow']}#{run_id} status={status}")
        if pending:
            time.sleep(args.poll_seconds)
    if pending:
        raise RuntimeError(f"timed out waiting for exact dispatched runs: {sorted(pending)}")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)
    dispatch_cmd = sub.add_parser("dispatch")
    dispatch_cmd.add_argument("--repository", required=True)
    dispatch_cmd.add_argument("--workflow", required=True)
    dispatch_cmd.add_argument("--ref", required=True)
    dispatch_cmd.add_argument("--head-sha", required=True)
    dispatch_cmd.add_argument("--phase", required=True)
    dispatch_cmd.add_argument("--evidence-file", required=True)
    dispatch_cmd.add_argument("--resolve-timeout-seconds", type=int, default=90)
    dispatch_cmd.add_argument("--poll-seconds", type=float, default=2.0)
    dispatch_cmd.set_defaults(func=dispatch)

    for name, func in (("wait", wait), ("verify", verify)):
        cmd = sub.add_parser(name)
        cmd.add_argument("--evidence-file", required=True)
        cmd.add_argument("--expected-count", type=int, default=3)
        if name == "wait":
            cmd.add_argument("--timeout-seconds", type=int, default=1800)
            cmd.add_argument("--poll-seconds", type=float, default=5.0)
        cmd.set_defaults(func=func)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        return args.func(args)
    except (RuntimeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"release workflow dispatch error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
