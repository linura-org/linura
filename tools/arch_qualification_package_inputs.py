#!/usr/bin/env python3
"""Stage exact archived package inputs only in a disposable qualification guest.

The pinned databases select the filenames/hashes. Native signatures and normal
pacman installation remain mandatory. These bytes are never execution evidence.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import development_storage as storage  # noqa: E402
from tools.hyprland_display_environment import (  # noqa: E402
    CONTRACT,
    archived_repository_package_inputs as package_inputs,
    load_contract,
)

ORIGIN = "https://umea.archive.pkgbuild.com/packages"
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_REPOSITORY_EXPANDED_BYTES = 128 * 1024 * 1024


def open_input(path: Path, maximum: int):
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    stream = os.fdopen(descriptor, "rb")
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or not 0 < info.st_size <= maximum
    ):
        stream.close()
        raise ValueError("unsafe archive package input file")
    return stream, info


def unchanged(before, after) -> bool:
    return all(
        getattr(before, key) == getattr(after, key)
        for key in (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_mode",
        )
    )


def hash_stream(stream, size: int) -> str:
    value = hashlib.sha256()
    remaining = size
    while remaining:
        block = stream.read(min(remaining, 1024 * 1024))
        if not block:
            raise ValueError("archive input truncated during hashing")
        value.update(block)
        remaining -= len(block)
    if stream.read(1):
        raise ValueError("archive input grew during hashing")
    return value.hexdigest()


def digest(path: Path) -> str:
    stream, before = open_input(path, 512 * 1024 * 1024)
    with stream:
        value = hash_stream(stream, before.st_size)
        if not unchanged(before, os.fstat(stream.fileno())):
            raise ValueError("archive package input changed during hashing")
        return value


def acquire(url: str, path: Path, maximum: int, expected: str | None = None) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("archive input destination must be fresh")
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(descriptor, "wb") as output:
        subprocess.run(
            [
                "curl",
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--connect-timeout",
                "15",
                "--max-time",
                "120",
                "--retry",
                "2",
                "--retry-max-time",
                "180",
                "--max-filesize",
                str(maximum),
                "--output",
                "-",
                url,
            ],
            check=True,
            timeout=310,
            stdout=output,
        )
    if (
        not 0 < path.stat().st_size <= maximum
        or expected is not None
        and digest(path) != expected
    ):
        raise ValueError("archive input differs from its complete digest/size bound")


class RepositoryReader(io.BufferedIOBase):
    def __init__(self, stream: io.BufferedIOBase):
        super().__init__()
        self.stream = stream
        self.remaining = MAX_REPOSITORY_EXPANDED_BYTES

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return False

    def read(self, size: int | None = -1) -> bytes:
        if self.closed:
            raise ValueError("read of closed repository input")
        size = (
            self.remaining + 1
            if size is None or size < 0
            else min(size, self.remaining + 1)
        )
        block = self.stream.read(size)
        if len(block) > self.remaining:
            raise ValueError("expanded repository exceeds its byte bound")
        self.remaining -= len(block)
        return block


def repository_records(path: Path, expected: str) -> dict:
    stream, before = open_input(path, 64 * 1024 * 1024)
    observed = {}
    with stream:
        if hash_stream(stream, before.st_size) != expected:
            raise ValueError("archive input database differs from its pin")
        stream.seek(0)
        header = stream.read(2)
        stream.seek(0)
        decoded = gzip.GzipFile(fileobj=stream) if header == b"\x1f\x8b" else stream
        try:
            with tarfile.open(fileobj=RepositoryReader(decoded), mode="r|") as archive:
                count = 0
                for member in archive:
                    count += 1
                    if count > 131072 or member.size > 1024 * 1024:
                        raise ValueError("repository metadata exceeds its bound")
                    if not member.name.endswith("/desc"):
                        continue
                    payload = archive.extractfile(member) if member.isfile() else None
                    if payload is None:
                        raise ValueError("missing repository package metadata")
                    fields = {}
                    for section in (
                        payload.read(member.size + 1).decode().strip().split("\n\n")
                    ):
                        lines = section.splitlines()
                        key = lines[0].strip("%") if lines else ""
                        if not key or key in fields:
                            raise ValueError("malformed repository package metadata")
                        fields[key] = lines[1:]
                    name = fields.get("NAME", [])
                    if len(name) != 1 or name[0] in observed:
                        raise ValueError("ambiguous repository package identity")
                    observed[name[0]] = fields
        finally:
            if decoded is not stream:
                decoded.close()
        if not unchanged(before, os.fstat(stream.fileno())):
            raise ValueError("repository changed during decoding")
    return observed


def verify_repository_inputs(data: dict, directory: Path, records: list[dict]) -> None:
    observed = {}
    for repository, expected in sorted(data["repository_sha256"].items()):
        rows = repository_records(directory / (repository + ".db"), expected)
        if observed.keys() & rows.keys():
            raise ValueError("ambiguous repository package identity")
        observed.update(rows)
    total = 0
    for record in records:
        fields = observed.get(record["name"], {})
        if fields.get("FILENAME") != [record["filename"]] or fields.get(
            "SHA256SUM"
        ) != [record["sha256"]]:
            raise ValueError(
                "archive package input differs from pinned dependency resolution"
            )
        sizes = fields.get("CSIZE", [])
        if len(sizes) != 1 or re.fullmatch(r"[1-9][0-9]{0,9}", sizes[0]) is None:
            raise ValueError("archive package size is unavailable")
        size = int(sizes[0])
        if size > record["max_bytes"]:
            raise ValueError("archive package exceeds its reviewed size bound")
        total += size
    if total > MAX_TOTAL_BYTES:
        raise ValueError("archive package input set exceeds its aggregate bound")


def acquire_inputs(data: dict, directory: Path) -> list[dict]:
    records = package_inputs(data)
    for repository, expected in sorted(data["repository_sha256"].items()):
        url = (
            data["arch_archive_url"]
            .replace("$repo", repository)
            .replace("$arch", data["architecture"])
        )
        acquire(
            url + "/" + repository + ".db",
            directory / (repository + ".db"),
            64 * 1024 * 1024,
            expected,
        )
    verify_repository_inputs(data, directory, records)
    total = 0
    for record in records:
        url = f"{ORIGIN}/{record['name'][0]}/{record['name']}/{record['filename']}"
        acquire(
            url, directory / record["filename"], record["max_bytes"], record["sha256"]
        )
        acquire(url + ".sig", directory / (record["filename"] + ".sig"), 1024 * 1024)
        total += (directory / record["filename"]).stat().st_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError(
                "downloaded archive package set exceeds its aggregate bound"
            )
    return records


def cache_script(records: list[dict]) -> str:
    # The complete set is independently checked before any cache publication.
    # It still enters native pacman's unchanged repository/signature checks.
    lines = ["set -euo pipefail", 'cd -- "$1"']
    for record in records:
        filename = shlex.quote(record["filename"])
        lines += [
            "printf '%s\\n' "
            + shlex.quote(record["sha256"] + "  " + record["filename"])
            + " | sha256sum --check --strict",
            "sudo -n pacman-key --verify "
            + shlex.quote(record["filename"] + ".sig")
            + " "
            + filename,
        ]
    lines.append("sudo -n install -d -m 0755 -- /var/cache/pacman/pkg")
    for record in records:
        filename = shlex.quote(record["filename"])
        target = "/var/cache/pacman/pkg/" + record["filename"]
        lines += [
            "sudo -n install -m 0644 -- " + filename + " " + shlex.quote(target),
            "printf '%s\\n' "
            + shlex.quote(record["sha256"] + "  " + target)
            + " | sha256sum --check --strict",
        ]
    return "\n".join(lines) + "\n"


def guest_script(records: list[dict]) -> str:
    return (
        "set -euo pipefail\n"
        'test "$(hostname)" = linura-v010-shell\n'
        'case "$(systemd-detect-virt --vm)" in qemu|kvm) ;; *) exit 1 ;; esac\n'
        "grep -qx 'ID=arch' /etc/os-release\n" + cache_script(records)
    )


def add_input(
    archive: tarfile.TarFile, path: Path, maximum: int, expected: str | None
) -> None:
    stream, before = open_input(path, maximum)
    with stream:
        if expected is not None and hash_stream(stream, before.st_size) != expected:
            raise ValueError("staged package no longer matches its complete pin")
        stream.seek(0)
        entry = tarfile.TarInfo(path.name)
        entry.mode = 0o644
        entry.size = before.st_size
        archive.addfile(entry, stream)
        if not unchanged(before, os.fstat(stream.fileno())):
            raise ValueError("archive input changed during staging")


def stage_inputs(data: dict, directory: Path, ssh_key: Path) -> None:
    records = package_inputs(data)
    verify_repository_inputs(data, directory, records)
    if (
        sum((directory / r["filename"]).stat().st_size for r in records)
        > MAX_TOTAL_BYTES
    ):
        raise ValueError("staged package set exceeds its aggregate bound")
    # Recreate fixture instructions from current source. Never execute a script
    # retained in a cache or trust a previous transfer's success record.
    script = guest_script(records).encode()
    with tempfile.NamedTemporaryFile(
        prefix="package-inputs-", suffix=".tar", dir=directory
    ) as bundle:
        with tarfile.open(fileobj=bundle, mode="w") as archive:
            entry = tarfile.TarInfo("install-inputs.sh")
            entry.mode = 0o600
            entry.size = len(script)
            archive.addfile(entry, io.BytesIO(script))
            for record in records:
                add_input(
                    archive,
                    directory / record["filename"],
                    record["max_bytes"],
                    record["sha256"],
                )
                add_input(
                    archive,
                    directory / (record["filename"] + ".sig"),
                    1024 * 1024,
                    None,
                )
        bundle.flush()
        bundle.seek(0)
        remote = 'set -euo pipefail; umask 077; work=$(mktemp -d /tmp/linura-arch-inputs.XXXXXXXX); trap \'rm -rf -- "$work"\' EXIT; tar --extract --no-same-owner --no-same-permissions --file - --directory "$work"; bash "$work/install-inputs.sh" "$work"'
        subprocess.run(
            [
                "ssh",
                "-i",
                str(ssh_key),
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=3",
                "-p",
                "2223",
                "linura@127.0.0.1",
                "timeout",
                "--signal=TERM",
                "--kill-after=10s",
                "300",
                "bash",
                "-c",
                shlex.quote(remote),
            ],
            stdin=bundle,
            check=True,
            timeout=320,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--phase", choices=("acquire", "stage"), required=True)
    args = parser.parse_args()
    data = load_contract(args.contract)
    run = os.environ.get("LINURA_RUN_ID")
    directory = storage.require_destination(
        ROOT,
        "arch-hyprland-runtime",
        args.work_root,
        "temporary",
        run=run,
        fresh=args.phase == "acquire",
    )
    if args.phase == "acquire":
        directory.mkdir(mode=0o700)
        records = acquire_inputs(data, directory)
        (directory / "input-result.json").write_text(
            json.dumps(
                {
                    "package_sha256": {r["filename"]: r["sha256"] for r in records},
                    "qualification_evidence": False,
                },
                indent=2,
            )
            + "\n"
        )
    else:
        stage_inputs(data, directory, args.ssh_key)


if __name__ == "__main__":
    main()
