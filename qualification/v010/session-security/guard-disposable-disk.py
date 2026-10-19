#!/usr/bin/env python3
"""Read-only guard for S17's private persistent VM copy; never qualification evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAXIMUM_IMAGE_BYTES = 20 * 1024**3


def metadata(path: Path):
    value = path.lstat()
    if (
        not path.is_absolute()
        or path.resolve(strict=True) != path
        or not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.getuid()
        or value.st_nlink != 1
        or not 0 < value.st_size <= MAXIMUM_IMAGE_BYTES
    ):
        raise RuntimeError("S17 disposable disk is not a bounded owned regular file")
    return value


def identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def digest(path: Path, expected_metadata) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        if identity(os.fstat(source.fileno())) != identity(expected_metadata):
            raise RuntimeError("S17 disk changed before bounded digest verification")
        value = hashlib.sha256()
        remaining = expected_metadata.st_size
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise RuntimeError("S17 disk truncated during digest verification")
            value.update(chunk)
            remaining -= len(chunk)
        if source.read(1) or identity(os.fstat(source.fileno())) != identity(
            expected_metadata
        ):
            raise RuntimeError("S17 disk changed during digest verification")
    if identity(path.lstat()) != identity(expected_metadata):
        raise RuntimeError("S17 disk path changed during digest verification")
    return value.hexdigest()


def verify(source: Path, copy: Path, expected_sha: str, phase: str) -> dict:
    if (
        phase not in {"before", "after"}
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha) is None
    ):
        raise RuntimeError("S17 disposable disk guard scope is unsupported")
    source_metadata, copy_metadata = metadata(source), metadata(copy)
    parent = copy.parent.lstat()
    if (
        copy.name != "guest.qcow2"
        or re.fullmatch(r"linura-s17-disk\.[A-Za-z0-9]{6}", copy.parent.name) is None
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
        or stat.S_IMODE(copy_metadata.st_mode) != 0o600
        or (source_metadata.st_dev, source_metadata.st_ino)
        == (copy_metadata.st_dev, copy_metadata.st_ino)
    ):
        raise RuntimeError(
            "S17 persistent VM must use its distinct private disposable copy"
        )
    if digest(source, source_metadata) != expected_sha:
        raise RuntimeError("S17 prepared substrate bytes changed; evidence is invalid")
    if phase == "before" and digest(copy, copy_metadata) != expected_sha:
        raise RuntimeError(
            "S17 initial private copy differs from the verified substrate"
        )
    return {
        "schema_version": 1,
        "phase": phase,
        "prepared_substrate_sha256": expected_sha,
        "disk_mode": "verified-private-disposable-persistent-copy",
        "qualification_evidence": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--copy", type=Path, required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            verify(args.source, args.copy, args.expected_source_sha, args.phase),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
