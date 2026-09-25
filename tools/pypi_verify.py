#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request

if __package__:
    from .python_package_version import Pep440VersionError, normalize_pep440
else:
    from python_package_version import Pep440VersionError, normalize_pep440

PYPI_JSON_BASE = "https://pypi.org/pypi"
PYPI_FILE_HOST = "files.pythonhosted.org"
USER_AGENT = "linura-release-verifier/1"


class VerificationError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_project(pyproject: Path) -> tuple[str, str]:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data.get("project")
    if not isinstance(project, dict):
        raise VerificationError("Python package metadata is missing [project]")
    name = project.get("name")
    version = project.get("version")
    if name != "linura":
        raise VerificationError(f"unexpected Python package name: {name!r}")
    if not isinstance(version, str) or not version:
        raise VerificationError("Python package version must be explicit")
    try:
        normalized_version = normalize_pep440(version)
    except Pep440VersionError as error:
        raise VerificationError(str(error)) from error
    return name, normalized_version


def local_artifacts(paths: list[Path]) -> dict[str, tuple[Path, str]]:
    artifacts: dict[str, tuple[Path, str]] = {}
    for raw in paths:
        path = raw.resolve()
        if path.is_symlink() or not path.is_file():
            raise VerificationError(f"artifact must be a regular file: {raw}")
        name = path.name
        if name in artifacts:
            raise VerificationError(f"duplicate local artifact filename: {name}")
        artifacts[name] = (path, sha256(path))
    if not artifacts:
        raise VerificationError("at least one sealed artifact is required")
    return artifacts


def request_json(url: str, timeout: int) -> dict[str, object] | None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    if not isinstance(value, dict):
        raise VerificationError("PyPI returned non-object metadata")
    return value


def download_digest(url: str, timeout: int) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != PYPI_FILE_HOST:
        raise VerificationError(f"unexpected PyPI artifact URL: {url!r}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    digest = hashlib.sha256()
    with urllib.request.urlopen(request, timeout=timeout) as response:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def verify_metadata(
    metadata: dict[str, object],
    *,
    project_name: str,
    version: str,
    artifacts: dict[str, tuple[Path, str]],
    download: bool,
    timeout: int,
) -> None:
    info = metadata.get("info")
    if not isinstance(info, dict):
        raise VerificationError("PyPI metadata is missing info")
    remote_name = info.get("name")
    remote_version = info.get("version")
    if remote_name != project_name or not isinstance(remote_version, str):
        raise VerificationError("PyPI project/version identity mismatch")
    try:
        normalized_remote_version = normalize_pep440(remote_version)
    except Pep440VersionError as error:
        raise VerificationError(f"PyPI returned an invalid version: {remote_version!r}") from error
    if normalized_remote_version != version:
        raise VerificationError("PyPI project/version identity mismatch")

    urls = metadata.get("urls")
    if not isinstance(urls, list):
        raise VerificationError("PyPI metadata is missing release files")

    remote: dict[str, dict[str, object]] = {}
    for item in urls:
        if not isinstance(item, dict):
            raise VerificationError("invalid PyPI release file metadata")
        filename = item.get("filename")
        if not isinstance(filename, str) or not filename:
            raise VerificationError("PyPI release file is missing a filename")
        if filename in remote:
            raise VerificationError(f"duplicate PyPI release filename: {filename}")
        remote[filename] = item

    expected_names = set(artifacts)
    remote_names = set(remote)
    if remote_names != expected_names:
        raise VerificationError(
            "PyPI release file set differs from sealed artifacts: "
            f"remote={sorted(remote_names)} expected={sorted(expected_names)}"
        )

    for filename, (_path, expected_digest) in artifacts.items():
        item = remote[filename]
        if item.get("yanked") is True:
            raise VerificationError(f"sealed PyPI artifact is yanked: {filename}")
        digests = item.get("digests")
        if not isinstance(digests, dict) or digests.get("sha256") != expected_digest:
            raise VerificationError(f"PyPI metadata digest differs from sealed artifact: {filename}")
        url = item.get("url")
        if not isinstance(url, str) or not url:
            raise VerificationError(f"PyPI artifact URL is missing: {filename}")
        if download and download_digest(url, timeout) != expected_digest:
            raise VerificationError(f"fresh PyPI download differs from sealed artifact: {filename}")


def verify_release(
    *,
    pyproject: Path,
    artifact_paths: list[Path],
    allow_missing: bool,
    download: bool,
    timeout: int,
    retries: int,
    retry_delay: float,
) -> str:
    project_name, version = load_project(pyproject)
    artifacts = local_artifacts(artifact_paths)
    url = (
        f"{PYPI_JSON_BASE}/"
        f"{urllib.parse.quote(project_name, safe='')}/"
        f"{urllib.parse.quote(version, safe='')}/json"
    )

    attempts = max(1, retries)
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            metadata = request_json(url, timeout)
            if metadata is None:
                if allow_missing:
                    return "missing"
                raise VerificationError(f"PyPI release does not exist: {project_name}=={version}")
            verify_metadata(
                metadata,
                project_name=project_name,
                version=version,
                artifacts=artifacts,
                download=download,
                timeout=timeout,
            )
            return "exact"
        except (VerificationError, urllib.error.URLError, TimeoutError) as error:
            last_error = error
            if attempt + 1 >= attempts:
                break
            time.sleep(retry_delay)
    assert last_error is not None
    raise last_error


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the complete PyPI release file set against sealed Linura artifacts"
    )
    parser.add_argument("--pyproject", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, action="append", required=True)
    parser.add_argument("--allow-missing", action="store_true")
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--retry-delay", type=float, default=5.0)
    args = parser.parse_args()

    if args.timeout <= 0 or args.retries <= 0 or args.retry_delay < 0:
        print("invalid timeout/retry configuration", file=sys.stderr)
        return 2

    try:
        status = verify_release(
            pyproject=args.pyproject,
            artifact_paths=args.artifact,
            allow_missing=args.allow_missing,
            download=args.download,
            timeout=args.timeout,
            retries=args.retries,
            retry_delay=args.retry_delay,
        )
    except (OSError, tomllib.TOMLDecodeError, VerificationError, urllib.error.URLError) as error:
        print(f"PyPI verification failed: {error}", file=sys.stderr)
        return 1

    print(status)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
