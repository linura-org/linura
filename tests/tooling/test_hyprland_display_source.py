from __future__ import annotations

import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import hyprland_display_source as source


def archive_bytes(entries: list[tuple[str, bytes | str, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                member.linkname = str(content)
                archive.addfile(member)
            else:
                assert isinstance(content, bytes)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


class HyprlandDisplaySourceTests(unittest.TestCase):
    def extract(self, directory: Path, data: bytes, digest: str | None = None) -> Path:
        archive = directory / "source.tar.gz"
        archive.write_bytes(data)
        return source.extract_verified_archive(
            archive,
            directory / "staging",
            digest or hashlib.sha256(data).hexdigest(),
            "native",
        )

    def test_verified_regular_source_and_existing_destination(self) -> None:
        data = archive_bytes(
            [("native/source.cpp", b"reviewed source\n", tarfile.REGTYPE)]
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staged = self.extract(root, data)
            self.assertEqual((staged / "source.cpp").read_bytes(), b"reviewed source\n")
            with self.assertRaises(FileExistsError):
                self.extract(root, data)
            self.assertEqual((staged / "source.cpp").read_bytes(), b"reviewed source\n")

    def test_wrong_digest_never_creates_destination(self) -> None:
        data = archive_bytes([("native/source.cpp", b"unreviewed", tarfile.REGTYPE)])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(source.SourceError, "checksum"):
                self.extract(root, data, "0" * 64)
            self.assertFalse((root / "staging").exists())

    def test_archive_paths_links_and_duplicate_entries_rejected_before_writes(
        self,
    ) -> None:
        cases = [
            [("../escape", b"bad", tarfile.REGTYPE)],
            [("/native/absolute", b"bad", tarfile.REGTYPE)],
            [("native/../escape", b"bad", tarfile.REGTYPE)],
            [("other/source.cpp", b"bad", tarfile.REGTYPE)],
            [("native/link", "../escape", tarfile.SYMTYPE)],
            [("native/link", "native/source.cpp", tarfile.LNKTYPE)],
            [("native/fifo", b"", tarfile.FIFOTYPE)],
            [("native/dev", b"", tarfile.CHRTYPE)],
            [
                ("native/a", b"one", tarfile.REGTYPE),
                ("native/a", b"two", tarfile.REGTYPE),
            ],
            [
                ("native/a/b", b"one", tarfile.REGTYPE),
                ("native/a", b"two", tarfile.REGTYPE),
            ],
            [("native/a\\b", b"bad", tarfile.REGTYPE)],
            [("native/a\nb", b"bad", tarfile.REGTYPE)],
            [("native//a", b"bad", tarfile.REGTYPE)],
        ]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with self.assertRaises(source.SourceError):
                    self.extract(root, archive_bytes(entries))
                self.assertFalse((root / "staging").exists())
                self.assertFalse((root / "escape").exists())

    def test_resource_limits_reject_before_extraction(self) -> None:
        data = archive_bytes([("native/source.cpp", b"12345", tarfile.REGTYPE)])
        for limit, value in [
            ("MAX_UNPACKED", 4),
            ("MAX_MEMBERS", 0),
            ("MAX_ARCHIVE", 4),
        ]:
            with self.subTest(limit=limit), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with (
                    patch.object(source, limit, value),
                    self.assertRaises(source.SourceError),
                ):
                    self.extract(root, data)
                self.assertFalse((root / "staging").exists())

    def test_archive_in_place_replacement_after_hash_cannot_change_extracted_bytes(
        self,
    ) -> None:
        good = archive_bytes([("native/source.cpp", b"reviewed", tarfile.REGTYPE)])
        bad = archive_bytes([("native/source.cpp", b"attacker", tarfile.REGTYPE)])
        actual_open = tarfile.open
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "source.tar.gz"
            archive.write_bytes(good)

            def mutate_then_open(*args, **kwargs):
                # An in-place write changes the same inode, defeating the
                # otherwise tempting verify-then-extract-from-open-FD pattern.
                archive.write_bytes(bad)
                return actual_open(*args, **kwargs)

            with patch.object(source.tarfile, "open", side_effect=mutate_then_open):
                staged = source.extract_verified_archive(
                    archive,
                    root / "staging",
                    hashlib.sha256(good).hexdigest(),
                    "native",
                )
            self.assertEqual((staged / "source.cpp").read_bytes(), b"reviewed")
            self.assertEqual(archive.read_bytes(), bad)

    def test_archive_symlink_and_destination_symlink_are_rejected(self) -> None:
        data = archive_bytes([("native/source.cpp", b"reviewed", tarfile.REGTYPE)])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real.tar.gz"
            real.write_bytes(data)
            link = root / "link.tar.gz"
            link.symlink_to(real)
            with self.assertRaises(OSError):
                source.extract_verified_archive(
                    link, root / "staging", hashlib.sha256(data).hexdigest(), "native"
                )
            victim = root / "victim"
            victim.mkdir()
            (root / "staging").symlink_to(victim, target_is_directory=True)
            with self.assertRaises(FileExistsError):
                self.extract(root, data)
            self.assertEqual(list(victim.iterdir()), [])

    def test_integration_points_must_match_exactly_without_fuzzy_fallback(self) -> None:
        for text in ["other", "point\npoint"]:
            with self.subTest(text=text), self.assertRaises(source.SourceError):
                source.replace_exact(text, "point", "replacement")
        self.assertEqual(
            source.replace_exact("before\npoint\nafter", "point", "replacement"),
            "before\nreplacement\nafter",
        )

    def test_release_template_keeps_upstream_identity_and_marks_modification(
        self,
    ) -> None:
        commit = "a" * 40
        template = f'#define GIT_COMMIT_HASH    "{commit}"\n#define GIT_DIRTY          "clean"\n#define GIT_TAG            "v0.56.2"\n'
        stamped = source.stamp_version_template(template, commit)
        self.assertIn(commit, stamped)
        self.assertIn('"linura-display-integration"', stamped)
        self.assertIn('"v0.56.2+linura-display-v1"', stamped)
        self.assertNotIn('"clean"', stamped)
        for candidate, pin in (
            (template, "b" * 40),
            (template + template, commit),
            (stamped, commit),
        ):
            with (
                self.subTest(candidate=candidate, pin=pin),
                self.assertRaises(source.SourceError),
            ):
                source.stamp_version_template(candidate, pin)


if __name__ == "__main__":
    unittest.main()
