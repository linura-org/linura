#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

API_VERSION = "2022-11-28"
USER_AGENT = "linura-release-branch-cleanup"


class CleanupError(RuntimeError):
    pass


@dataclass(frozen=True)
class Candidate:
    name: str
    expected_sha: str | None
    source: str


def _request(
    method: str,
    url: str,
    *,
    token: str,
    body: dict[str, Any] | None = None,
    expected: set[int] = {200},
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
            payload: Any = json.loads(raw) if raw else None
            if response.status not in expected:
                raise CleanupError(
                    f"unexpected HTTP {response.status} from {url}: {payload!r}"
                )
            return response.status, payload
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            payload = raw
        if error.code in expected:
            return error.code, payload
        raise CleanupError(f"HTTP {error.code} from {url}: {payload!r}") from error


def _branch_patterns(tag: str) -> tuple[re.Pattern[str], ...]:
    escaped = re.escape(tag)
    return (
        re.compile(rf"automation/release-prep-{escaped}-[0-9a-f]{{12}}"),
        re.compile(rf"automation/release-reprepare-{escaped}-[0-9a-f]{{12}}"),
        re.compile(rf"automation/release-authorization-{escaped}-[0-9a-f]{{12}}"),
        re.compile(rf"automation/post-release-{escaped}-[0-9]+"),
        re.compile(rf"verify-release/{escaped}"),
    )


def load_legacy(path: pathlib.Path, tag: str) -> dict[str, str]:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise CleanupError("unsupported release branch cleanup schema")
    legacy: dict[str, str] = {}
    for item in payload.get("legacy_branch", []):
        if not isinstance(item, dict) or item.get("release") != tag:
            continue
        name = item.get("name")
        expected_sha = item.get("expected_sha")
        if not isinstance(name, str) or not name.startswith("tmp/"):
            raise CleanupError(f"invalid legacy cleanup branch name: {name!r}")
        if (
            not isinstance(expected_sha, str)
            or re.fullmatch(r"[0-9a-f]{40}", expected_sha) is None
        ):
            raise CleanupError(f"invalid legacy cleanup SHA for {name!r}")
        if name in legacy:
            raise CleanupError(f"duplicate legacy cleanup branch: {name}")
        legacy[name] = expected_sha
    return legacy


def select_candidates(branches: list[str], tag: str, legacy: dict[str, str]) -> list[Candidate]:
    patterns = _branch_patterns(tag)
    selected: list[Candidate] = []
    for branch in sorted(set(branches)):
        if branch == "main":
            continue
        if any(pattern.fullmatch(branch) for pattern in patterns):
            selected.append(Candidate(branch, None, "automation-owned"))
        elif branch in legacy:
            selected.append(Candidate(branch, legacy[branch], "legacy-ledger"))
    return selected


def _list_branches(repository: str, token: str) -> list[str]:
    result: list[str] = []
    page = 1
    while True:
        query = urllib.parse.urlencode({"per_page": 100, "page": page})
        _, payload = _request(
            "GET",
            f"https://api.github.com/repos/{repository}/branches?{query}",
            token=token,
        )
        if not isinstance(payload, list):
            raise CleanupError("branch listing returned an invalid payload")
        names = [item.get("name") for item in payload if isinstance(item, dict)]
        if any(not isinstance(name, str) for name in names):
            raise CleanupError("branch listing contained an invalid branch name")
        result.extend(name for name in names if isinstance(name, str))
        if len(payload) < 100:
            return result
        page += 1


def _ref_sha(repository: str, branch: str, token: str) -> str | None:
    encoded = urllib.parse.quote(branch, safe="")
    status, payload = _request(
        "GET",
        f"https://api.github.com/repos/{repository}/git/ref/heads/{encoded}",
        token=token,
        expected={200, 404},
    )
    if status == 404:
        return None
    if not isinstance(payload, dict):
        raise CleanupError(f"invalid ref payload for {branch}")
    sha = (payload.get("object") or {}).get("sha")
    if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
        raise CleanupError(f"invalid ref SHA for {branch}: {sha!r}")
    return sha


def _open_pr_count(repository: str, branch: str, token: str) -> int:
    owner = repository.split("/", 1)[0]
    query = urllib.parse.urlencode(
        {"state": "open", "head": f"{owner}:{branch}", "per_page": 100}
    )
    _, payload = _request(
        "GET",
        f"https://api.github.com/repos/{repository}/pulls?{query}",
        token=token,
    )
    if not isinstance(payload, list):
        raise CleanupError(f"open-PR lookup returned an invalid payload for {branch}")
    return len(payload)


def delete_candidate(repository: str, candidate: Candidate, token: str) -> str:
    if candidate.name == "main":
        raise CleanupError("refusing to delete main")
    if _open_pr_count(repository, candidate.name, token) != 0:
        return f"preserved open-PR branch {candidate.name}"

    first = _ref_sha(repository, candidate.name, token)
    if first is None:
        return f"already absent {candidate.name}"
    lease = candidate.expected_sha or first
    if candidate.expected_sha is not None and first != candidate.expected_sha:
        return (
            f"preserved moved legacy branch {candidate.name}: "
            f"current={first} reviewed={candidate.expected_sha}"
        )

    # Re-read immediately before deletion. This is the deletion lease: a branch
    # that moved after selection is preserved rather than deleting new work.
    second = _ref_sha(repository, candidate.name, token)
    if second is None:
        return f"already absent {candidate.name}"
    if second != lease:
        return f"preserved concurrently moved branch {candidate.name}: {lease} -> {second}"

    encoded = urllib.parse.quote(candidate.name, safe="")
    status, _ = _request(
        "DELETE",
        f"https://api.github.com/repos/{repository}/git/refs/heads/{encoded}",
        token=token,
        expected={204, 404},
    )
    if status == 404:
        return f"already absent {candidate.name}"
    return f"deleted {candidate.name} at {lease}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Delete only release-owned branches under exact-SHA leases after terminal release qualification."
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--tag", required=True)
    parser.add_argument(
        "--contract",
        type=pathlib.Path,
        default=pathlib.Path("contracts/release-branch-cleanup.toml"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if not args.repository or args.repository.count("/") != 1:
            raise CleanupError("repository must be in owner/name form")
        if re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", args.tag) is None:
            raise CleanupError("invalid release tag")
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            raise CleanupError("GH_TOKEN is required")
        legacy = load_legacy(args.contract, args.tag)
        branches = _list_branches(args.repository, token)
        candidates = select_candidates(branches, args.tag, legacy)
        print(f"selected {len(candidates)} cleanup candidate(s) for {args.tag}")
        for candidate in candidates:
            result = delete_candidate(args.repository, candidate, token)
            print(result)
            # Small spacing makes an accidental rapid ref churn less likely to
            # collapse both lease reads into the same remote observation window.
            time.sleep(0.05)
    except CleanupError as error:
        print(f"release branch cleanup failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
