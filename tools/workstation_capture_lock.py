#!/usr/bin/env python3
"""Hold the global Level C capture lock on a verified no-follow file descriptor.

The parent Bash process keeps this helper's stdin pipe open throughout capture.
The helper releases its flock only after that pipe closes (or the process dies).
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import stat
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("UNSAFE", flush=True)
        print("Level C capture lock requires exactly one path", file=sys.stderr)
        return 2

    lock_path = Path(sys.argv[1])
    directory_fd = -1
    lock_fd = -1
    try:
        directory_fd = os.open(
            lock_path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        directory = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
        ):
            raise ValueError("capture state directory must be owned by this user and mode 0700")

        lock_fd = os.open(
            lock_path.name,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        lock = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock.st_mode)
            or lock.st_uid != os.geteuid()
            or lock.st_nlink != 1
            or stat.S_IMODE(lock.st_mode) != 0o600
        ):
            raise ValueError("capture lock must be a user-owned single-link regular file, mode 0600")

        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("BUSY", flush=True)
            # Keep the coprocess alive until Bash reads this status. Otherwise
            # Bash may discard the coproc descriptors before its first read.
            sys.stdin.buffer.read()
            return 1

        current = os.stat(lock_path.name, dir_fd=directory_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (lock.st_dev, lock.st_ino):
            raise ValueError("capture lock pathname changed while acquiring the lock")

        print("LOCKED", flush=True)
        sys.stdin.buffer.read()
        return 0
    except (OSError, ValueError) as exc:
        print("UNSAFE", flush=True)
        print(f"Level C capture lock refused: {exc}", file=sys.stderr)
        sys.stdin.buffer.read()
        return 1
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        if directory_fd >= 0:
            os.close(directory_fd)


if __name__ == "__main__":
    raise SystemExit(main())
