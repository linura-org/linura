#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API_VERSION = "2022-11-28"
USER_AGENT = "linura-release-automation-authority-probe"
MISSING_WORKFLOW_REF = "0000000000000000000000000000000000000000"
WORKFLOW_PROBE = "ci.yml"


class AuthorityProbeError(RuntimeError):
    pass


def _credential_name(credential_source: str) -> str:
    names = {
        "github": "repository GITHUB_TOKEN",
        "github-app": "dedicated Linura Release GitHub App token",
        "dedicated": "dedicated RELEASE_AUTOMATION_TOKEN",
    }
    try:
        return names[credential_source]
    except KeyError as error:
        raise AuthorityProbeError(f"unsupported credential source: {credential_source!r}") from error


def _missing_permission_guidance(credential_source: str, permission: str) -> str:
    if credential_source == "github-app":
        return (
            f"Linura Release GitHub App lacks {permission}; grant only Actions write, Contents write, "
            "and Pull requests write to the repository installation, then approve the installation permission update"
        )
    if credential_source == "dedicated":
        return (
            f"RELEASE_AUTOMATION_TOKEN lacks {permission}; grant Pull requests write, Contents write, "
            "and Actions write access to this repository"
        )
    return (
        f"repository GITHUB_TOKEN lacks {permission}; keep the corresponding isolated job permission and verify "
        "the repository/organization Actions policy permits it"
    )


def _decode_json(body: str, label: str) -> dict[str, object]:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise AuthorityProbeError(f"{label} returned a non-JSON GitHub response") from error
    if not isinstance(payload, dict):
        raise AuthorityProbeError(f"{label} returned a non-object GitHub response")
    return payload


def _validation_message(base: str, head: str) -> str:
    return f"No commits between {base} and {head}"


def validate_contents_probe_response(*, status: int, credential_source: str) -> str:
    # GitHub's merge endpoint requires Contents: write. With identical base/head
    # it returns 204 and performs no merge, so this proves the capability without
    # creating a commit, branch, tag, or other repository state.
    if status == 204:
        return _credential_name(credential_source)

    if status in {403, 404}:
        raise AuthorityProbeError(
            _missing_permission_guidance(credential_source, "Contents write")
        )

    if 200 <= status < 300:
        raise AuthorityProbeError(
            "the intentionally non-mutating same-head merge probe unexpectedly changed repository state or returned an unsupported success response"
        )

    raise AuthorityProbeError(
        f"Contents-write merge authority probe returned unexpected HTTP status {status}"
    )


def validate_pr_probe_response(
    *, status: int, body: str, base: str, head: str, credential_source: str
) -> str:
    if status == 422:
        payload = _decode_json(body, "PR-create endpoint")
        expected = {
            "resource": "PullRequest",
            "code": "custom",
            "message": _validation_message(base, head),
        }
        errors = payload.get("errors")
        if payload.get("message") == "Validation Failed" and isinstance(errors, list) and errors == [expected]:
            return _credential_name(credential_source)
        raise AuthorityProbeError(
            "PR-create endpoint returned an unexpected HTTP 422 response; refusing to treat ambiguous validation, abuse, or spam responses as PR authority"
        )

    if status == 403:
        if credential_source == "github":
            raise AuthorityProbeError(
                "GitHub Actions cannot create pull requests with repository GITHUB_TOKEN; release mutation PRs must use the dedicated Linura Release GitHub App so native PR workflows run without approval"
            )
        raise AuthorityProbeError(
            _missing_permission_guidance(credential_source, "Pull requests write")
        )

    if 200 <= status < 300:
        raise AuthorityProbeError(
            "the intentionally invalid same-head/base pull request unexpectedly succeeded; refusing to continue release automation"
        )

    raise AuthorityProbeError(f"PR-create authority probe returned unexpected HTTP status {status}")


def validate_actions_probe_response(
    *, status: int, body: str, missing_ref: str, credential_source: str
) -> str:
    if status == 422:
        payload = _decode_json(body, "Actions-dispatch endpoint")
        message = payload.get("message")
        if isinstance(message, str) and missing_ref in message and "ref" in message.casefold():
            return _credential_name(credential_source)
        raise AuthorityProbeError(
            "Actions-dispatch endpoint returned an unexpected HTTP 422 response; refusing to treat ambiguous validation as Actions write authority"
        )

    if status in {403, 404}:
        raise AuthorityProbeError(
            _missing_permission_guidance(credential_source, "Actions write")
        )

    if 200 <= status < 300:
        raise AuthorityProbeError(
            "the intentionally invalid workflow-dispatch probe unexpectedly succeeded; refusing to continue release automation"
        )

    raise AuthorityProbeError(
        f"Actions-dispatch authority probe returned unexpected HTTP status {status}"
    )


def _request(
    *, method: str, url: str, token: str, body: dict[str, object] | None = None
) -> tuple[int, str]:
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
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", errors="replace")


def probe(*, repository: str, token: str, base: str, head: str, credential_source: str) -> str:
    if not repository or repository.count("/") != 1:
        raise AuthorityProbeError("repository must be in owner/name form")
    if not token:
        raise AuthorityProbeError("GH_TOKEN is required")
    if credential_source not in {"github", "github-app", "dedicated"}:
        raise AuthorityProbeError(
            "credential source must be 'github', 'github-app', or 'dedicated'"
        )
    if base != head:
        raise AuthorityProbeError(
            "authority probe requires identical base/head so its merge and PR checks cannot create repository state"
        )

    api_root = f"https://api.github.com/repos/{repository}"

    contents_status, _contents_body = _request(
        method="POST",
        url=f"{api_root}/merges",
        token=token,
        body={"base": base, "head": head},
    )
    validate_contents_probe_response(
        status=contents_status,
        credential_source=credential_source,
    )

    pr_status, pr_body = _request(
        method="POST",
        url=f"{api_root}/pulls",
        token=token,
        body={
            "title": "Linura release automation authority probe",
            "head": head,
            "base": base,
        },
    )
    validate_pr_probe_response(
        status=pr_status,
        body=pr_body,
        base=base,
        head=head,
        credential_source=credential_source,
    )

    actions_status, actions_body = _request(
        method="POST",
        url=f"{api_root}/actions/workflows/{WORKFLOW_PROBE}/dispatches",
        token=token,
        body={"ref": MISSING_WORKFLOW_REF},
    )
    accepted = validate_actions_probe_response(
        status=actions_status,
        body=actions_body,
        missing_ref=MISSING_WORKFLOW_REF,
        credential_source=credential_source,
    )
    return accepted


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Non-mutating proof that the release-automation credential has the Contents-write, "
            "pull-request-create, and Actions-dispatch capabilities required by the protected release lifecycle."
        )
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--base", default="main")
    parser.add_argument("--head", default="main")
    parser.add_argument(
        "--credential-source",
        choices=("github", "github-app", "dedicated"),
        required=True,
        help=(
            "Which credential supplied GH_TOKEN: repository GITHUB_TOKEN, dedicated Linura Release GitHub App, "
            "or legacy dedicated RELEASE_AUTOMATION_TOKEN."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        accepted = probe(
            repository=args.repository,
            token=os.environ.get("GH_TOKEN", ""),
            base=args.base,
            head=args.head,
            credential_source=args.credential_source,
        )
    except AuthorityProbeError as error:
        print(f"release automation authority probe failed: {error}", file=sys.stderr)
        return 2

    print(
        f"release automation authority: {accepted} proved Contents write, PR-create, and Actions-dispatch capability"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
