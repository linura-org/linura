#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

API_VERSION = "2022-11-28"
USER_AGENT = "linura-release-branch-cleanup"
FULL_SHA_RE = re.compile(r"[0-9a-f]{40}")


class CleanupError(RuntimeError):
    pass


@dataclass(frozen=True)
class Candidate:
    name: str
    expected_sha: str
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
        re.compile(rf"automation/release-prep-{escaped}-(?P<sha>[0-9a-f]{{40}})"),
        re.compile(rf"automation/release-reprepare-{escaped}-(?P<sha>[0-9a-f]{{40}})"),
        re.compile(rf"automation/release-authorization-{escaped}-(?P<sha>[0-9a-f]{{40}})"),
        re.compile(rf"automation/post-release-{escaped}-(?P<sha>[0-9a-f]{{40}})"),
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
        if (
            not isinstance(name, str)
            or not name
            or name == "main"
            or name.startswith("refs/")
            or ".." in name
            or name.startswith("/")
            or name.endswith("/")
        ):
            raise CleanupError(f"invalid explicit cleanup branch name: {name!r}")
        if not isinstance(expected_sha, str) or FULL_SHA_RE.fullmatch(expected_sha) is None:
            raise CleanupError(f"invalid cleanup SHA for {name!r}")
        if name in legacy:
            raise CleanupError(f"duplicate cleanup branch: {name}")
        legacy[name] = expected_sha
    return legacy


def select_candidates(
    branches: list[str], tag: str, legacy: dict[str, str]
) -> list[Candidate]:
    patterns = _branch_patterns(tag)
    selected: list[Candidate] = []
    for branch in sorted(set(branches)):
        if branch == "main":
            continue
        matched = None
        for pattern in patterns:
            matched = pattern.fullmatch(branch)
            if matched is not None:
                break
        if matched is not None:
            selected.append(
                Candidate(branch, matched.group("sha"), "sha-addressed-automation")
            )
        elif branch in legacy:
            selected.append(Candidate(branch, legacy[branch], "explicit-ledger"))
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
    if not isinstance(sha, str) or FULL_SHA_RE.fullmatch(sha) is None:
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


def _atomic_delete(
    repository: str, branch: str, expected_sha: str, token: str
) -> subprocess.CompletedProcess[str]:
    credential = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {credential}",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    ref = f"refs/heads/{branch}"
    return subprocess.run(
        [
            "git",
            "push",
            "--porcelain",
            f"--force-with-lease={ref}:{expected_sha}",
            f"https://github.com/{repository}.git",
            f":{ref}",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def delete_candidate(repository: str, candidate: Candidate, token: str) -> str:
    if candidate.name == "main":
        raise CleanupError("refusing to delete main")
    if FULL_SHA_RE.fullmatch(candidate.expected_sha) is None:
        raise CleanupError(f"invalid cleanup lease for {candidate.name}")
    if _open_pr_count(repository, candidate.name, token) != 0:
        return f"preserved open-PR branch {candidate.name}"

    current = _ref_sha(repository, candidate.name, token)
    if current is None:
        return f"already absent {candidate.name}"
    if current != candidate.expected_sha:
        return (
            f"preserved moved branch {candidate.name}: "
            f"current={current} reviewed={candidate.expected_sha}"
        )

    result = _atomic_delete(
        repository, candidate.name, candidate.expected_sha, token
    )
    if result.returncode == 0:
        return f"deleted {candidate.name} at {candidate.expected_sha}"

    after = _ref_sha(repository, candidate.name, token)
    if after is None:
        return f"already absent {candidate.name}"
    if after != candidate.expected_sha:
        return (
            f"preserved concurrently moved branch {candidate.name}: "
            f"{candidate.expected_sha} -> {after}"
        )
    detail = (result.stderr or result.stdout).strip()
    raise CleanupError(
        f"atomic leased deletion failed for {candidate.name} at "
        f"{candidate.expected_sha}: {detail}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Delete only release-owned SHA-addressed branches or exact ledger "
            "entries using atomic ref leases after terminal release qualification."
        )
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
        if re.fullmatch(
            r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)",
            args.tag,
        ) is None:
            raise CleanupError("invalid release tag")
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            raise CleanupError("GH_TOKEN is required")
        legacy = load_legacy(args.contract, args.tag)
        branches = _list_branches(args.repository, token)
        candidates = select_candidates(branches, args.tag, legacy)
        print(f"selected {len(candidates)} cleanup candidate(s) for {args.tag}")
        for candidate in candidates:
            print(delete_candidate(args.repository, candidate, token))
    except CleanupError as error:
        print(f"release branch cleanup failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
