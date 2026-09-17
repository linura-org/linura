#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any

API_VERSION = "2022-11-28"
USER_AGENT = "linura-release-branch-discovery"
FULL_SHA_RE = re.compile(r"[0-9a-f]{40}")
DISCOVERY_PREFIXES = (
    "tmp/",
    "work/",
    "chore/",
    "automation/",
    "verify-release/",
    "release/",
)


class DiscoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class BranchRef:
    name: str
    sha: str
    protected: bool


@dataclass(frozen=True)
class Discovery:
    name: str
    sha: str
    protected: bool
    has_open_pr: bool


def _request(
    url: str,
    *,
    token: str,
    expected: set[int] = {200},
) -> tuple[int, Any]:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            payload: Any = json.loads(raw) if raw else None
            if response.status not in expected:
                raise DiscoveryError(
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
        raise DiscoveryError(f"HTTP {error.code} from {url}: {payload!r}") from error


def _list_branches(repository: str, token: str) -> list[BranchRef]:
    result: list[BranchRef] = []
    seen: set[str] = set()
    page = 1
    while True:
        query = urllib.parse.urlencode({"per_page": 100, "page": page})
        _, payload = _request(
            f"https://api.github.com/repos/{repository}/branches?{query}",
            token=token,
        )
        if not isinstance(payload, list):
            raise DiscoveryError("branch listing returned an invalid payload")
        for item in payload:
            if not isinstance(item, dict):
                raise DiscoveryError("branch listing contained an invalid branch entry")
            name = item.get("name")
            sha = (item.get("commit") or {}).get("sha")
            protected = item.get("protected")
            if (
                not isinstance(name, str)
                or not name
                or name in seen
                or not isinstance(sha, str)
                or FULL_SHA_RE.fullmatch(sha) is None
                or not isinstance(protected, bool)
            ):
                raise DiscoveryError("branch listing contained invalid branch metadata")
            seen.add(name)
            result.append(BranchRef(name=name, sha=sha, protected=protected))
        if len(payload) < 100:
            return result
        page += 1


def select_discoveries(branches: list[BranchRef]) -> list[BranchRef]:
    return sorted(
        (
            branch
            for branch in branches
            if branch.name != "main" and branch.name.startswith(DISCOVERY_PREFIXES)
        ),
        key=lambda branch: branch.name,
    )


def _has_open_pr(repository: str, branch: str, token: str) -> bool:
    owner = repository.split("/", 1)[0]
    query = urllib.parse.urlencode(
        {"state": "open", "head": f"{owner}:{branch}", "per_page": 1}
    )
    _, payload = _request(
        f"https://api.github.com/repos/{repository}/pulls?{query}",
        token=token,
    )
    if not isinstance(payload, list):
        raise DiscoveryError(f"open-PR lookup returned an invalid payload for {branch}")
    return bool(payload)


def inspect_discoveries(
    repository: str, branches: list[BranchRef], token: str
) -> list[Discovery]:
    return [
        Discovery(
            name=branch.name,
            sha=branch.sha,
            protected=branch.protected,
            has_open_pr=_has_open_pr(repository, branch.name, token),
        )
        for branch in select_discoveries(branches)
    ]


def render_text(items: list[Discovery]) -> str:
    if not items:
        return "no release-adjacent branch residue discovered"
    lines = [f"discovered {len(items)} release-adjacent branch(es); discovery is read-only"]
    for item in items:
        lines.append(
            "branch "
            f"name={json.dumps(item.name)} "
            f"sha={item.sha} "
            f"protected={str(item.protected).lower()} "
            f"open_pr={str(item.has_open_pr).lower()}"
        )
    lines.append(
        "generic discoveries are not deletion authority; exact SHA-addressed release "
        "ownership or a reviewed exact name+SHA cleanup ledger is required for mutation"
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only discovery of release-adjacent branch namespaces. This tool "
            "never grants cleanup authority or mutates refs."
        )
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if not args.repository or args.repository.count("/") != 1:
            raise DiscoveryError("repository must be in owner/name form")
        token = os.environ.get("GH_TOKEN", "")
        if not token:
            raise DiscoveryError("GH_TOKEN is required")
        branches = _list_branches(args.repository, token)
        items = inspect_discoveries(args.repository, branches, token)
        if args.format == "json":
            print(json.dumps([asdict(item) for item in items], sort_keys=True))
        else:
            print(render_text(items))
    except DiscoveryError as error:
        print(f"release branch discovery failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
