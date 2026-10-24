"""Read-only disk isolation guard tests; these are not VM qualification evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "s17_disk_guard",
    ROOT / "qualification/v010/session-security/guard-disposable-disk.py",
)
assert spec and spec.loader
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class DisposableDiskTests(unittest.TestCase):
    def files(self, root):
        source = root / "prepared.qcow2"
        source.write_bytes(b"component image bytes, never a real prepared guest")
        directory = root / "linura-s17-disk.abc123"
        directory.mkdir(mode=0o700)
        copy = directory / "guest.qcow2"
        copy.write_bytes(source.read_bytes())
        copy.chmod(0o600)
        return source, copy, hashlib.sha256(source.read_bytes()).hexdigest()

    def test_only_new_private_copy_is_writable_and_substrate_must_stay_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            source, copy, expected = self.files(Path(directory))
            value = guard.verify(source, copy, expected, "before")
            self.assertFalse(value["qualification_evidence"])
            copy.write_bytes(b"changed disposable runtime state")
            self.assertFalse(
                guard.verify(source, copy, expected, "after")["qualification_evidence"]
            )
            with self.assertRaises(RuntimeError):
                guard.verify(source, copy, expected, "before")
            source.write_bytes(b"modified cached substrate")
            with self.assertRaises(RuntimeError):
                guard.verify(source, copy, expected, "after")

    def test_links_public_permissions_empty_and_excessive_files_are_rejected(self):
        for mutation in (
            "symlink",
            "hardlink",
            "public-directory",
            "public-file",
            "empty",
            "excessive",
            "wrong-name",
            "source-symlink",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                source, copy, expected = self.files(Path(directory))
                if mutation == "symlink":
                    copy.unlink()
                    copy.symlink_to(source)
                elif mutation == "hardlink":
                    copy.unlink()
                    os.link(source, copy)
                elif mutation == "public-directory":
                    copy.parent.chmod(0o755)
                elif mutation == "public-file":
                    copy.chmod(0o644)
                elif mutation == "empty":
                    copy.write_bytes(b"")
                elif mutation == "excessive":
                    with (
                        patch.object(guard, "MAXIMUM_IMAGE_BYTES", 1),
                        self.assertRaises(RuntimeError),
                    ):
                        guard.verify(source, copy, expected, "before")
                    continue
                elif mutation == "wrong-name":
                    copy = copy.rename(copy.parent / "other.qcow2")
                elif mutation == "source-symlink":
                    link = source.parent / "link.qcow2"
                    link.symlink_to(source)
                    source = link
                with self.assertRaises(RuntimeError):
                    guard.verify(source, copy, expected, "before")

    def test_wrong_digest_unknown_phase_and_changed_bytes_during_hash_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            source, copy, expected = self.files(Path(directory))
            for digest, phase in (
                ("b" * 64, "before"),
                ("invalid", "after"),
                (expected, "repair"),
            ):
                with self.subTest(phase=phase), self.assertRaises(RuntimeError):
                    guard.verify(source, copy, digest, phase)
            metadata = source.lstat()
            source.write_bytes(b"drifted before open")
            with self.assertRaises(RuntimeError):
                guard.digest(source, metadata)


if __name__ == "__main__":
    unittest.main()
