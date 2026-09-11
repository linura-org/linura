#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

API_VERSION = "2022-11-28"
USER_AGENT = "linura-release-native-gates"
ACTIVE_STATUSES = {"queued", "in_progress", "pending", "waiting", "requested"}
REQUIRED_WORKFLOWS = (
    ".github/workflows/ci.yml",
    ".github/workflows/security.yml",
    ".github/workflows/codeql.yml",
)


class NativeGateError(RuntimeError):
    pass


@dataclass(frozen=True)
class GateState:
    ready: bool
    detail: str


def _token() -> str:
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise NativeGateError("GH_TOKEN is required")
    return token


def _request(
    method: str,
    url: str,
    *,
    token: str,
    body: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        try:
            payload: Any = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            payload = raw
        return error.code, payload


def _expect(status: int, expected: set[int], payload: Any, label: str) -> Any:
    if status not in expected:
        raise NativeGateError(f"{label} failed with HTTP {status}: {payload!r}")
    return payload


def _runs(
    repository: str,
    *,
    head_sha: str,
    event: str,
    head_branch: str,
    pr_number: int | None,
    token: str,
) -> GateState:
    query = urllib.parse.urlencode(
        {"head_sha": head_sha, "event": event, "per_page": "100"}
    )
    status, payload = _request(
        "GET",
        f"https://api.github.com/repos/{repository}/actions/runs?{query}",
        token=token,
    )
    payload = _expect(status, {200}, payload, "workflow-run lookup")
    if not isinstance(payload, dict) or not isinstance(payload.get("workflow_runs"), list):
        raise NativeGateError("workflow-run lookup returned an invalid payload")

    runs = payload["workflow_runs"]
    details: list[str] = []
    ready = True
    for path in REQUIRED_WORKFLOWS:
        candidates: list[dict[str, Any]] = []
        for run in runs:
            if not isinstance(run, dict):
                continue
            if run.get("path") != path:
                continue
            if run.get("head_sha") != head_sha or run.get("event") != event:
                continue
            if run.get("head_branch") != head_branch:
                continue
            if pr_number is not None:
                prs = run.get("pull_requests")
                if not isinstance(prs, list) or not any(
                    isinstance(pr, dict) and pr.get("number") == pr_number for pr in prs
                ):
                    continue
            candidates.append(run)

        if not candidates:
            ready = False
            details.append(f"{path}: missing")
            continue

        latest = max(candidates, key=lambda item: int(item.get("id") or 0))
        run_status = latest.get("status")
        conclusion = latest.get("conclusion")
        run_id = latest.get("id")
        if run_status in ACTIVE_STATUSES:
            ready = False
            details.append(f"{path}: {run_status} (run {run_id})")
            continue
        if run_status != "completed":
            ready = False
            details.append(f"{path}: unexpected status {run_status!r} (run {run_id})")
            continue
        if conclusion != "success":
            raise NativeGateError(
                f"{path} native {event} run {run_id} concluded {conclusion!r}; "
                "release automation refuses to substitute workflow_dispatch evidence"
            )
        details.append(f"{path}: success (run {run_id})")

    return GateState(ready=ready, detail="; ".join(details))


def _unresolved_threads(repository: str, pr_number: int, token: str) -> int:
    owner, name = repository.split("/", 1)
    query = """
      query($owner:String!, $name:String!, $number:Int!, $cursor:String) {
        repository(owner:$owner, name:$name) {
          pullRequest(number:$number) {
            reviewThreads(first:100, after:$cursor) {
              nodes { isResolved }
              pageInfo { hasNextPage endCursor }
            }
          }
        }
      }
    """
    cursor: str | None = None
    unresolved = 0
    while True:
        status, payload = _request(
            "POST",
            "https://api.github.com/graphql",
            token=token,
            body={
                "query": query,
                "variables": {
                    "owner": owner,
                    "name": name,
                    "number": pr_number,
                    "cursor": cursor,
                },
            },
        )
        payload = _expect(status, {200}, payload, "review-thread lookup")
        if not isinstance(payload, dict) or payload.get("errors"):
            raise NativeGateError(f"review-thread lookup returned errors: {payload!r}")
        try:
            threads = payload["data"]["repository"]["pullRequest"]["reviewThreads"]
            nodes = threads["nodes"]
            page_info = threads["pageInfo"]
        except (KeyError, TypeError) as error:
            raise NativeGateError("review-thread lookup returned an invalid payload") from error
        unresolved += sum(
            1
            for node in nodes
            if isinstance(node, dict) and node.get("isResolved") is False
        )
        if not page_info.get("hasNextPage"):
            return unresolved
        cursor = page_info.get("endCursor")
        if not isinstance(cursor, str) or not cursor:
            raise NativeGateError("review-thread pagination lost its end cursor")


def _pr_state(
    repository: str,
    *,
    pr_number: int,
    head_sha: str,
    head_branch: str,
    base_sha: str,
    expected_changed_files: int,
    token: str,
) -> GateState:
    status, payload = _request(
        "GET",
        f"https://api.github.com/repos/{repository}/pulls/{pr_number}",
        token=token,
    )
    payload = _expect(status, {200}, payload, "pull-request lookup")
    if not isinstance(payload, dict):
        raise NativeGateError("pull-request lookup returned an invalid payload")
    if payload.get("state") != "open":
        raise NativeGateError(f"pull request #{pr_number} is not open")
    if (payload.get("head") or {}).get("sha") != head_sha:
        raise NativeGateError(f"pull request #{pr_number} head SHA changed")
    if (payload.get("head") or {}).get("ref") != head_branch:
        raise NativeGateError(f"pull request #{pr_number} head branch changed")
    if (payload.get("base") or {}).get("ref") != "main":
        raise NativeGateError(f"pull request #{pr_number} no longer targets main")
    if (payload.get("base") or {}).get("sha") != base_sha:
        raise NativeGateError(f"pull request #{pr_number} base SHA changed")
    if payload.get("changed_files") != expected_changed_files:
        raise NativeGateError(
            f"pull request #{pr_number} changed-file count is {payload.get('changed_files')!r}, "
            f"expected {expected_changed_files}"
        )

    gates = _runs(
        repository,
        head_sha=head_sha,
        event="pull_request",
        head_branch=head_branch,
        pr_number=pr_number,
        token=token,
    )
    if not gates.ready:
        return gates

    unresolved = _unresolved_threads(repository, pr_number, token)
    if unresolved:
        raise NativeGateError(
            f"pull request #{pr_number} has {unresolved} unresolved review thread(s)"
        )

    mergeable = payload.get("mergeable")
    mergeable_state = payload.get("mergeable_state")
    if mergeable is None or mergeable_state == "unknown":
        return GateState(False, "GitHub mergeability is still being computed")
    if mergeable is not True:
        raise NativeGateError(
            f"pull request #{pr_number} is not mergeable: mergeable={mergeable!r}, "
            f"state={mergeable_state!r}"
        )
    if mergeable_state != "clean":
        return GateState(
            False,
            f"native checks are green but GitHub ruleset state is {mergeable_state!r}",
        )
    return GateState(True, gates.detail + "; review threads: 0; ruleset: clean")


def wait_for_state(check, *, timeout_seconds: int, interval_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    first = True
    while True:
        state = check()
        print(state.detail, flush=True)
        if state.ready:
            return
        if timeout_seconds == 0 or (not first and time.monotonic() >= deadline):
            raise NativeGateError(f"native gates did not become ready: {state.detail}")
        first = False
        sleep_for = min(interval_seconds, max(0.0, deadline - time.monotonic()))
        if sleep_for <= 0:
            raise NativeGateError(f"native gates timed out: {state.detail}")
        time.sleep(sleep_for)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Wait for GitHub-native CI/Security/CodeQL gates used by protected release PRs and main pushes."
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--head-branch", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--interval-seconds", type=int, default=5)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    pr = subparsers.add_parser("pr")
    pr.add_argument("--pr-number", type=int, required=True)
    pr.add_argument("--base-sha", required=True)
    pr.add_argument("--expected-changed-files", type=int, required=True)

    commit = subparsers.add_parser("commit")
    commit.add_argument("--event", choices=("push",), default="push")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if not args.repository or args.repository.count("/") != 1:
            raise NativeGateError("repository must be in owner/name form")
        if len(args.head_sha) != 40 or any(c not in "0123456789abcdef" for c in args.head_sha):
            raise NativeGateError("head SHA must be 40 lowercase hexadecimal characters")
        if args.timeout_seconds < 0 or args.interval_seconds <= 0:
            raise NativeGateError("timeout must be non-negative and interval must be positive")
        token = _token()
        if args.mode == "pr":
            if len(args.base_sha) != 40 or any(c not in "0123456789abcdef" for c in args.base_sha):
                raise NativeGateError("base SHA must be 40 lowercase hexadecimal characters")
            wait_for_state(
                lambda: _pr_state(
                    args.repository,
                    pr_number=args.pr_number,
                    head_sha=args.head_sha,
                    head_branch=args.head_branch,
                    base_sha=args.base_sha,
                    expected_changed_files=args.expected_changed_files,
                    token=token,
                ),
                timeout_seconds=args.timeout_seconds,
                interval_seconds=args.interval_seconds,
            )
        else:
            wait_for_state(
                lambda: _runs(
                    args.repository,
                    head_sha=args.head_sha,
                    event=args.event,
                    head_branch=args.head_branch,
                    pr_number=None,
                    token=token,
                ),
                timeout_seconds=args.timeout_seconds,
                interval_seconds=args.interval_seconds,
            )
    except NativeGateError as error:
        print(f"native release gate failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
