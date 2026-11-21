#!/usr/bin/env python3
"""Digest-verified image caching and the pinned Ubuntu qualification CLI.

This is a transport/cache helper, not a qualification or authorization oracle.
A cache hit is never evidence of passing a guest test.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
from typing import BinaryIO, Callable
import subprocess
import sys
import tempfile
import time

ORIGIN = "https://cloud-images.ubuntu.com/releases/noble/release-20260725/ubuntu-24.04-server-cloudimg-amd64.img"
TRANSPORT = "https://mirror.iscas.ac.cn/ubuntu-cloud-images/releases/noble/release-20260725/ubuntu-24.04-server-cloudimg-amd64.img"
DIGEST = "d1940f7d69d343355e183dff1e08a59852d32e7309baa7a4bad8365b11b005ac"
ALLOWED_NAMES = frozenset(
    {
        "ubuntu-noble-base.qcow2",
        "ubuntu-noble-enospc-base.qcow2",
        "ubuntu-noble-v06-base.qcow2",
    }
)
ATTEMPTS = 4
# The reviewed image is ~595 MiB; refuse oversized cached and downloaded bytes.
MAX_IMAGE_BYTES = 1024 * 1024 * 1024


class ImageError(RuntimeError):
    """No artifact was accepted or published."""


def checked_reader(path: Path) -> BinaryIO:
    """Open one regular, singly linked, bounded inode without following links.

    O_NONBLOCK prevents a switched-in FIFO from stalling the qualification job;
    fstat authenticates the *opened* object rather than an earlier path check.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError as exc:
        raise ImageError(f"missing image: {path}") from exc
    except OSError as exc:
        raise ImageError(f"nonregular, linked or substituted image: {path}") from exc
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ImageError(f"nonregular, linked or substituted image: {path}")
        if not 0 < details.st_size <= MAX_IMAGE_BYTES:
            raise ImageError(f"image size exceeds reviewed bound: {path}")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    total = 0
    with checked_reader(path) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            if total > MAX_IMAGE_BYTES:
                raise ImageError(f"image size exceeds reviewed bound: {path}")
            value.update(block)
    return value.hexdigest()


def require_digest(path: Path, expected: str) -> None:
    if sha256_file(path) != expected:
        raise ImageError(f"image SHA-256 mismatch: {path}")


def curl_transfer(path: Path, url: str, resume: bool) -> int:
    # --disable must be curl's first option; never ingest a runner's .curlrc.
    args = [
        "/usr/bin/curl",
        "--disable",
        "--fail",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "--connect-timeout",
        "25",
        "--max-time",
        "900",
        "--max-filesize",
        str(MAX_IMAGE_BYTES),
        "--output",
        str(path),
    ]
    if resume:
        args += ["--continue-at", "-"]
    args += [url]
    return subprocess.run(args, check=False).returncode


def acquire(
    cached: Path,
    destination: Path,
    expected: str,
    url: str,
    transfer: Callable[[Path, str, bool], int] = curl_transfer,
    pause: Callable[[float], None] = time.sleep,
) -> str:
    """Acquire, authenticate, and stage a *fresh* disposable-guest input.

    An invalid restored cache is fatal: it cannot be treated as an approved
    fallback or silently republished under an existing immutable cache key.
    """
    for root in (cached.parent, destination.parent):
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise ImageError(f"unqualified image storage root: {root}")
    if cached == destination:
        raise ImageError("cache and guest input must be separate files")
    if cached.exists() or cached.is_symlink():
        require_digest(cached, expected)
        source = "verified-cache"
    else:
        fd, name = tempfile.mkstemp(prefix=".ubuntu-image-", dir=cached.parent)
        os.close(fd)
        partial = Path(name)
        try:
            for index in range(ATTEMPTS):
                resume = partial.stat().st_size > 0
                result = transfer(partial, url, resume)
                if result == 0:
                    require_digest(partial, expected)
                    break
                if result in (33, 36):
                    # The server refused byte ranges: retry without resuming.
                    with partial.open("wb"):
                        pass
                if index == ATTEMPTS - 1:
                    raise ImageError(
                        f"image transport failed after {ATTEMPTS} attempts: curl exit {result}"
                    )
                pause(min(2 ** (index + 1), 8))
            try:
                os.link(partial, cached)  # exclusive publication; never overwrite
            except FileExistsError:
                pass  # authenticate the concurrently published file below
            partial.unlink(
                missing_ok=True
            )  # restore one-link invariant before readback
            require_digest(cached, expected)
        finally:
            partial.unlink(missing_ok=True)
        source = "verified-https-download"
    if destination.exists() or destination.is_symlink():
        raise ImageError(f"destination already exists: {destination}")
    fd, name = tempfile.mkstemp(prefix=".ubuntu-stage-", dir=destination.parent)
    staged = Path(name)
    try:
        with os.fdopen(fd, "wb") as output, checked_reader(cached) as image:
            total = 0
            for block in iter(lambda: image.read(1024 * 1024), b""):
                total += len(block)
                if total > MAX_IMAGE_BYTES:
                    raise ImageError(f"image size exceeds reviewed bound: {cached}")
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        require_digest(staged, expected)
        os.link(staged, destination)  # fail closed on races; do not overwrite
    finally:
        staged.unlink(missing_ok=True)
    require_digest(destination, expected)
    return source


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    if (
        os.environ.get("BASE_IMAGE_URL") != ORIGIN
        or os.environ.get("BASE_IMAGE_DOWNLOAD_URL") != TRANSPORT
        or os.environ.get("BASE_IMAGE_SHA256") != DIGEST
    ):
        raise ImageError(
            "repository-approved image origin, transport or SHA-256 drifted"
        )
    base = Path(os.environ["LINURA_VM_BASE_DIR"])
    run = Path(os.environ["LINURA_VM_DIR"])
    destination = args.destination
    if destination.parent != run or destination.name not in ALLOWED_NAMES:
        raise ImageError("destination is outside the reviewed guest input paths")
    cache = base / f"ubuntu-noble-{DIGEST}.img"
    source = acquire(cache, destination, DIGEST, TRANSPORT)
    environment = Path(os.environ["GITHUB_ENV"])
    if environment.is_symlink() or not environment.is_file():
        raise ImageError("GitHub environment output is missing or unsafe")
    with environment.open("a", encoding="utf-8") as stream:
        stream.write(f"BASE_IMAGE={destination}\n")
    print(
        f"ubuntu-qualification-image={source},sha256={DIGEST},guest={destination.name}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ImageError, KeyError, OSError) as exc:
        print(f"qualification-image-infrastructure-error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
