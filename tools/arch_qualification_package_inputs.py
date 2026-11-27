#!/usr/bin/env python3
"""Stage exact archived package inputs only in a disposable qualification guest.

The pinned databases select the filenames/hashes. Native signatures and normal
pacman installation remain mandatory. These bytes are never execution evidence.
"""

from __future__ import annotations

import argparse
import ctypes
import gzip
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socketserver
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
from typing import BinaryIO, Callable

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
MAX_CACHE_FILES = 1024
MAX_CACHE_REQUESTS = 4096
MAX_CACHE_SECONDS = 3600
MAX_CACHE_WORKERS = 8


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


def rename_fresh(directory: int, staged: str, destination: str) -> None:
    # Linux qualification only. RENAME_NOREPLACE publishes one complete inode
    # without overwriting a concurrent destination or exposing a two-link phase.
    # A missing syscall/filesystem capability refuses; there is no racy fallback.
    try:
        rename = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        raise ValueError("atomic archive input publication is unavailable") from None
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    if (
        rename(directory, os.fsencode(staged), directory, os.fsencode(destination), 1)
        != 0
    ):
        raise OSError(ctypes.get_errno(), "atomic archive input publication failed")


def publish_fresh(
    path: Path,
    maximum: int,
    expected: str | None,
    writer: Callable[[BinaryIO], object],
) -> None:
    """Validate/fsync private staging, then exclusively publish complete bytes.

    Interrupted acquisition leaves no final cache entry. SIGKILL may retain an
    unpublished staging file in this fresh run's private directory; it cannot
    become a package or readiness record. Never repair/replace an existing name.
    """
    if type(maximum) is not int or not 0 < maximum <= 512 * 1024 * 1024:
        raise ValueError("unsupported archive input size bound")
    directory = os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    staged = ".archive-input-" + secrets.token_hex(16)
    identity: tuple[int, int] | None = None
    try:
        parent = os.fstat(directory)
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise ValueError(
                "archive input publication requires an owned private directory"
            )
        try:
            os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("archive input destination must be fresh")
        descriptor = os.open(
            staged,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        with os.fdopen(descriptor, "w+b") as output:
            first = os.fstat(output.fileno())
            identity = (first.st_dev, first.st_ino)
            writer(output)
            output.flush()
            before = os.fstat(output.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or before.st_mode & 0o022
                or not 0 < before.st_size <= maximum
            ):
                raise ValueError(
                    "archive input differs from its complete digest/size bound"
                )
            output.seek(0)
            if expected is not None and hash_stream(output, before.st_size) != expected:
                raise ValueError(
                    "archive input differs from its complete digest/size bound"
                )
            os.fsync(output.fileno())
            if not unchanged(before, os.fstat(output.fileno())) or not unchanged(
                before, os.stat(staged, dir_fd=directory, follow_symlinks=False)
            ):
                raise ValueError("staged archive input changed before publication")
            rename_fresh(directory, staged, path.name)
            os.fsync(directory)
            # The exact inode remains held across publication. The final name
            # must refer to that single-link regular file, never an alias/reply.
            if not unchanged(
                os.fstat(output.fileno()),
                os.stat(path.name, dir_fd=directory, follow_symlinks=False),
            ):
                raise ValueError("archive input publication readback changed")
    finally:
        try:
            if identity is not None:
                try:
                    item = os.stat(staged, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    # Clean only our exact unpublished staging inode. Unknown
                    # substitutions remain a failure, not cleanup candidates.
                    if (
                        stat.S_ISREG(item.st_mode)
                        and (item.st_dev, item.st_ino) == identity
                    ):
                        os.unlink(staged, dir_fd=directory)
        finally:
            os.close(directory)


def acquire(url: str, path: Path, maximum: int, expected: str | None = None) -> None:
    def download(output: BinaryIO) -> None:
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

    publish_fresh(path, maximum, expected, download)


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
        signature = shlex.quote(record["filename"] + ".sig")
        target = "/var/cache/pacman/pkg/" + record["filename"]
        lines += [
            "sudo -n install -m 0644 -- " + filename + " " + shlex.quote(target),
            "printf '%s\\n' "
            + shlex.quote(record["sha256"] + "  " + target)
            + " | sha256sum --check --strict",
            # libalpm deliberately redownloads a cached package when its
            # detached signature is absent. Publish the verified pair and
            # require byte-for-byte signature readback as well.
            "signature_digest=$(sha256sum -- " + signature + ")",
            "signature_digest=${signature_digest%% *}",
            "sudo -n install -m 0644 -- "
            + signature
            + " "
            + shlex.quote(target + ".sig"),
            "printf '%s\\n' \"$signature_digest  "
            + target
            + '.sig" | sha256sum --check --strict',
        ]
    return "\n".join(lines) + "\n"


def guest_script(records: list[dict]) -> str:
    return (
        "set -euo pipefail\n"
        # uname is supplied by the same coreutils dependency as sha256sum and
        # install; the minimal pinned image does not include inetutils/hostname.
        "guest_hostname=$(uname -n)\n"
        'test "$guest_hostname" = linura-v010-substrate\n'
        "guest_virtualization=$(systemd-detect-virt --vm)\n"
        'case "$guest_virtualization" in qemu|kvm) ;; *) exit 1 ;; esac\n'
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


def repository_catalog(data: dict, directory: Path) -> dict[str, dict]:
    """Exact immutable repository inputs, never a second dependency resolver."""
    catalog = {}
    seen = set()
    for repository, expected in sorted(data["repository_sha256"].items()):
        for name, fields in repository_records(
            directory / (repository + ".db"), expected
        ).items():
            filename = fields.get("FILENAME", [])
            hashes = fields.get("SHA256SUM", [])
            sizes = fields.get("CSIZE", [])
            if (
                re.fullmatch(r"[a-z0-9@][a-z0-9@._+\-]{0,127}", name) is None
                or len(filename) != 1
                or re.fullmatch(
                    r"[A-Za-z0-9@._+:\-]{1,240}\.pkg\.tar\.(zst|xz)", filename[0]
                )
                is None
                or not filename[0].startswith(name + "-")
                or len(hashes) != 1
                or re.fullmatch(r"[0-9a-f]{64}", hashes[0]) is None
                or hashes[0] == "0" * 64
                or len(sizes) != 1
                or re.fullmatch(r"[1-9][0-9]{0,9}", sizes[0]) is None
                or filename[0] in seen
            ):
                raise ValueError("unsupported pinned package catalog entry")
            seen.add(filename[0])
            if len(seen) > 65536:
                raise ValueError("pinned package catalog exceeds its bound")
            # A pinned repository may contain unrelated multi-gigabyte inputs.
            # Such files are unavailable through this bounded cache; native
            # resolution is neither replaced nor silently altered.
            if int(sizes[0]) > 512 * 1024 * 1024:
                continue
            catalog[filename[0]] = dict(name=name, sha256=hashes[0], size=int(sizes[0]))
    if not catalog or len(catalog) > 65536:
        raise ValueError("pinned package catalog exceeds its bound")
    return catalog


class PinnedPackageCache:
    """Disposable, bounded input cache. Native pacman still resolves/verifies."""

    def __init__(self, data: dict, directory: Path):
        self.catalog = repository_catalog(data, directory)
        self.directory = directory
        self.deadline = time.monotonic() + MAX_CACHE_SECONDS
        self.requests = 0
        self.files: set[str] = set()
        # Include the initial staged pairs even if pacman never requests them.
        # Charging a subsequently requested initial pair again is conservative.
        initial = package_inputs(data)
        self.initial_files = 2 * len(initial)
        self.bytes = 0
        for record in initial:
            pinned = self.catalog.get(record["filename"])
            if (
                pinned is None
                or pinned["name"] != record["name"]
                or pinned["sha256"] != record["sha256"]
                or pinned["size"] > record["max_bytes"]
            ):
                raise ValueError("initial cache input differs from pinned repository")
            # The catalog's exact CSIZE bounds retained bytes; max_bytes is an
            # acquisition ceiling, not the size of every retained package.
            self.bytes += pinned["size"] + 1024 * 1024
        if self.bytes > MAX_TOTAL_BYTES or self.initial_files > MAX_CACHE_FILES:
            raise ValueError("initial pinned package cache capacity exhausted")
        self.lock = threading.Lock()
        self.file_locks: dict[str, threading.Lock] = {}

    def require_request_budget(self) -> None:
        with self.lock:
            self.requests += 1
            if self.requests > MAX_CACHE_REQUESTS or time.monotonic() >= self.deadline:
                raise ValueError("pinned package cache budget exhausted")

    def open(self, request: str):
        self.require_request_budget()
        if (
            len(request) > 1024
            or not request.startswith("/")
            or request.startswith("//")
        ):
            raise ValueError("unsupported package cache request")
        parsed = urllib.parse.urlsplit(request)
        if parsed.query or parsed.fragment or parsed.netloc or parsed.scheme:
            raise ValueError("unsupported package cache request")
        name = urllib.parse.unquote_to_bytes(parsed.path[1:]).decode("ascii")
        signature = name.endswith(".sig")
        package = name.removesuffix(".sig") if signature else name
        record = self.catalog.get(package)
        if record is None:
            raise KeyError("package is absent from pinned repositories")
        maximum = 1024 * 1024 if signature else record["size"]
        with self.lock:
            if name not in self.files:
                if (
                    len(self.files) + self.initial_files >= MAX_CACHE_FILES
                    or self.bytes + maximum > MAX_TOTAL_BYTES
                ):
                    raise ValueError("pinned package cache capacity exhausted")
                # Spend capacity before acquisition, including failed downloads.
                self.files.add(name)
                self.bytes += maximum
            file_lock = self.file_locks.setdefault(name, threading.Lock())
        # Different packages proceed concurrently; duplicate requests share one
        # acquisition. Capacity and request budgets remain global and atomic.
        with file_lock:
            return self.open_file(name, record, signature, maximum)

    def open_file(self, name: str, record: dict, signature: bool, maximum: int):
        path = self.directory / name
        if not path.exists() and not path.is_symlink():
            acquire(
                f"{ORIGIN}/{record['name'][0]}/{record['name']}/{name}",
                path,
                maximum,
                None if signature else record["sha256"],
            )
        stream, before = open_input(path, maximum)
        try:
            if not signature and (
                before.st_size != record["size"]
                or hash_stream(stream, before.st_size) != record["sha256"]
            ):
                raise ValueError("cached package differs from pinned repository")
            if not unchanged(before, os.fstat(stream.fileno())):
                raise ValueError("cached input changed during verification")
            stream.seek(0)
            return stream, before
        except BaseException:
            stream.close()
            raise


def cache_server(cache: PinnedPackageCache) -> http.server.HTTPServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            # Requests are untrusted, public input paths; never log their text.
            pass

        def do_GET(self):
            if self.path == "/health" and time.monotonic() < cache.deadline:
                try:
                    cache.require_request_budget()
                except ValueError:
                    self.send_error(503, "Pinned package cache budget exhausted")
                    return
                self.send_response(200)
                self.send_header("Content-Length", "6")
                self.end_headers()
                self.wfile.write(b"ready\n")
                return
            try:
                stream, before = cache.open(self.path)
            except KeyError:
                self.send_error(404, "Not in pinned package catalog")
                return
            except (OSError, ValueError, subprocess.SubprocessError):
                self.send_error(503, "Pinned package input unavailable")
                return
            try:
                with stream:
                    start = 0
                    requested = self.headers.get("Range")
                    if requested is not None:
                        matched = re.fullmatch(r"bytes=([0-9]{1,12})-", requested)
                        if matched is None or int(matched[1]) >= before.st_size:
                            self.send_error(416, "Unsupported byte range")
                            return
                        start = int(matched[1])
                        stream.seek(start)
                    self.send_response(206 if requested is not None else 200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(before.st_size - start))
                    if requested is not None:
                        self.send_header(
                            "Content-Range",
                            f"bytes {start}-{before.st_size - 1}/{before.st_size}",
                        )
                    self.end_headers()
                    remaining = before.st_size - start
                    while remaining:
                        chunk = stream.read(min(remaining, 65536))
                        if not chunk:
                            raise ValueError("cached input truncated during transfer")
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
                    if not unchanged(before, os.fstat(stream.fileno())):
                        raise ValueError("cached input changed during transfer")
            except (OSError, ValueError):
                # A partial/changed transfer is never an accepted input. Native
                # pacman's unchanged digest and signature verification follows.
                self.close_connection = True

    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

        def __init__(self, *args, **kwargs):
            self.slots = threading.BoundedSemaphore(MAX_CACHE_WORKERS)
            super().__init__(*args, **kwargs)

        def process_request(self, request, client_address):
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                self.slots.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self.slots.release()

        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(15)
            return connection, address

    server = Server(("127.0.0.1", 0), Handler)
    server.timeout = 1
    return server


def serve_cache(data: dict, directory: Path) -> None:
    # Own the process group so the builder's trap also terminates any bounded
    # downloader child. No persistent host daemon or public listener is created.
    os.setsid()
    cache = PinnedPackageCache(data, directory)
    with cache_server(cache) as server:
        port = server.server_address[1]
        if not 1024 <= port <= 65535:
            raise ValueError("unsupported pinned package cache port")

        def write_port(output: BinaryIO) -> None:
            output.write(f"{port}\n".encode("ascii"))

        publish_fresh(directory / "cache-port", 6, None, write_port)
        while time.monotonic() < cache.deadline:
            server.handle_request()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--phase", choices=("acquire", "stage", "serve"), required=True)
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
    elif args.phase == "stage":
        stage_inputs(data, directory, args.ssh_key)
    else:
        serve_cache(data, directory)


if __name__ == "__main__":
    main()
