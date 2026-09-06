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
    return (
        "dedicated RELEASE_AUTOMATION_TOKEN"
        if credential_source == "dedicated"
        else "repository GITHUB_TOKEN"
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


def validate_repository_access_response(
    *, status: int, body: str, credential_source: str
) -> str:
    if status != 200:
        raise AuthorityProbeError(
            f"repository capability probe returned HTTP {status}; cannot prove Contents write authority for {_credential_name(credential_source)}"
        )

    payload = _decode_json(body, "repository capability probe")
    permissions = payload.get("permissions")
    if not isinstance(permissions, dict) or permissions.get("push") is not True:
        if credential_source == "dedicated":
            raise AuthorityProbeError(
                "RELEASE_AUTOMATION_TOKEN does not have repository write authority; grant Contents write in addition to Pull requests write and Actions write"
            )
        raise AuthorityProbeError(
            "repository GITHUB_TOKEN did not receive Contents write authority required to push/merge closure state; keep contents: write on the isolated readiness/closure job and verify organization/repository Actions policy permits it"
        )
    return _credential_name(credential_source)


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
        if credential_source == "dedicated":
            raise AuthorityProbeError(
                "RELEASE_AUTOMATION_TOKEN cannot create pull requests; grant Pull requests write, Contents write, and Actions write access to this repository"
            )
        raise AuthorityProbeError(
            "GitHub Actions cannot create pull requests; enable Settings > Actions > General > Workflow permissions > Allow GitHub Actions to create and approve pull requests, or configure RELEASE_AUTOMATION_TOKEN with Pull requests, Contents, and Actions write access"
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
        if credential_source == "dedicated":
            raise AuthorityProbeError(
                "RELEASE_AUTOMATION_TOKEN cannot dispatch repository workflows; grant Actions write in addition to Pull requests write and Contents write"
            )
        raise AuthorityProbeError(
            "repository GITHUB_TOKEN cannot dispatch repository workflows with the requested readiness permissions; keep actions: write on the readiness/closure job and verify Actions policy permits it"
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
    if credential_source not in {"github", "dedicated"}:
        raise AuthorityProbeError("credential source must be 'github' or 'dedicated'")
    if base != head:
        raise AuthorityProbeError(
            "authority probe requires identical base/head so the PR probe cannot create repository state"
        )

    api_root = f"https://api.github.com/repos/{repository}"

    repo_status, repo_body = _request(method="GET", url=api_root, token=token)
    validate_repository_access_response(
        status=repo_status,
        body=repo_body,
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
            "Non-mutating proof that the release-automation credential has the repository-write, "
            "pull-request-create, and Actions-dispatch capabilities required by protected post-release closure."
        )
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--base", default="main")
    parser.add_argument("--head", default="main")
    parser.add_argument(
        "--credential-source",
        choices=("github", "dedicated"),
        required=True,
        help="Which credential supplied GH_TOKEN: repository GITHUB_TOKEN or dedicated RELEASE_AUTOMATION_TOKEN.",
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
