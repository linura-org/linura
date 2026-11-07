"""Bind exact-source files and retain dedicated-volume build outputs for replay.

Build artifacts cannot be described as checkout-relative inputs. Copy them into
private qualification evidence so independent admission can hash the same bytes
again after the original build directory has been discarded.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _open_source(path: Path) -> int:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    )
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError(f"not a regular build or source input: {path}")
    return descriptor


def _check_source(path: Path, descriptor: int, before: os.stat_result) -> None:
    after = os.fstat(descriptor)
    named = path.lstat()
    if (
        _identity(before) != _identity(after)
        or not stat.S_ISREG(named.st_mode)
        or named.st_dev != after.st_dev
        or named.st_ino != after.st_ino
    ):
        raise ValueError(f"build or source input changed while binding: {path}")


def _bind_file(
    path: Path, copy_to: Path | None = None, *, max_size: int | None = None
) -> tuple[str, int]:
    source_fd = _open_source(path)
    target_fd = None
    try:
        before = os.fstat(source_fd)
        if max_size is not None and (
            type(max_size) is not int or max_size <= 0 or before.st_size > max_size
        ):
            raise ValueError("build input exceeds its binding budget")
        if copy_to is not None:
            target_fd = os.open(
                copy_to,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
        digest = hashlib.sha256()
        size = 0
        while block := os.read(
            source_fd,
            1024 * 1024 if max_size is None else min(1024 * 1024, max_size + 1 - size),
        ):
            digest.update(block)
            size += len(block)
            if max_size is not None and size > max_size:
                raise ValueError("build input grew beyond its binding budget")
            if target_fd is not None:
                view = memoryview(block)
                while view:
                    written = os.write(target_fd, view)
                    if written <= 0:
                        raise OSError(
                            "short write retaining qualification build output"
                        )
                    view = view[written:]
        _check_source(path, source_fd, before)
        if target_fd is not None:
            if copy_to is None:
                raise ValueError("retained build destination is missing")
            os.fsync(target_fd)
            saved = os.fstat(target_fd)
            if (
                saved.st_size != size
                or saved.st_nlink != 1
                or stat.S_IMODE(saved.st_mode) != 0o600
                or saved.st_dev != copy_to.parent.stat().st_dev
            ):
                raise ValueError("retained build output is not private and complete")
        return digest.hexdigest(), size
    finally:
        if target_fd is not None:
            os.close(target_fd)
        os.close(source_fd)


def bind_artifacts(
    source_root: Path,
    evidence_root: Path,
    inputs: dict[str, Path],
    generated: dict[str, str],
    *,
    max_sizes: dict[str, int] | None = None,
) -> dict[str, dict[str, str | int]]:
    """Record exact checked paths; retained binaries are bound by bundle name."""
    if not generated.keys() <= inputs.keys():
        raise ValueError("unrecognized generated artifact")
    if len(set(generated.values())) != len(generated):
        raise ValueError("reused generated artifact name")
    if max_sizes is not None and not max_sizes.keys() <= inputs.keys():
        raise ValueError("unrecognized build artifact budget")
    results = {}
    for name, path in inputs.items():
        if name in generated:
            filename = generated[name]
            if (
                not filename
                or filename in (".", "..")
                or Path(filename).name != filename
                or ":" in filename
            ):
                raise ValueError("unsafe retained build artifact filename")
            digest, size = _bind_file(
                path, evidence_root / filename, max_size=(max_sizes or {}).get(name)
            )
            recorded_path = f"retained:{filename}"
        else:
            recorded_path = path.relative_to(source_root).as_posix()
            if (
                not recorded_path
                or ".." in Path(recorded_path).parts
                or not path.resolve().is_relative_to(source_root.resolve())
            ):
                raise ValueError("invalid repository artifact path")
            digest, size = _bind_file(path, max_size=(max_sizes or {}).get(name))
        results[name] = {"path": recorded_path, "sha256": digest, "size": size}
    return results
