"""Adversarial offline tests for the verified Ubuntu guest-image input cache."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qualification_base_image as image


class QualificationImageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.cache_dir = root / "cache"
        self.guest_dir = root / "guest"
        self.cache_dir.mkdir()
        self.guest_dir.mkdir()
        self.cached = self.cache_dir / "pinned.img"
        self.guest = self.guest_dir / "fresh.qcow2"
        self.payload = b"real reviewed fixture bytes"
        self.digest = hashlib.sha256(self.payload).hexdigest()

    def test_first_download_verifies_and_stages_without_overwriting(self) -> None:
        calls = []

        def deliver(path: Path, url: str, resume: bool) -> int:
            calls.append((url, resume))
            path.write_bytes(self.payload)
            return 0

        status = image.acquire(
            self.cached,
            self.guest,
            self.digest,
            "https://example.invalid/reviewed.img",
            deliver,
        )
        self.assertEqual(status, "verified-https-download")
        self.assertEqual(self.cached.read_bytes(), self.payload)
        self.assertEqual(self.guest.read_bytes(), self.payload)
        self.assertEqual(len(calls), 1)
        self.assertFalse(calls[0][1])

    def test_cache_hit_is_rehashed_and_never_downloads(self) -> None:
        self.cached.write_bytes(self.payload)

        def forbidden(*args: object) -> int:
            self.fail("valid cache must not request a remote image")

        self.assertEqual(
            image.acquire(
                self.cached,
                self.guest,
                self.digest,
                "https://example.invalid/x",
                forbidden,
            ),
            "verified-cache",
        )
        self.assertEqual(self.guest.read_bytes(), self.payload)

    def test_corrupt_cache_is_not_repaired_or_used(self) -> None:
        self.cached.write_bytes(b"substituted content")
        with self.assertRaisesRegex(image.ImageError, "SHA-256 mismatch"):
            image.acquire(
                self.cached,
                self.guest,
                self.digest,
                "https://example.invalid/x",
                lambda *_: self.fail("corrupt cache cannot trigger implicit fallback"),
            )
        self.assertFalse(self.guest.exists())

    def test_symlink_cache_is_rejected(self) -> None:
        victim = self.cache_dir / "other.img"
        victim.write_bytes(self.payload)
        self.cached.symlink_to(victim)
        with self.assertRaisesRegex(image.ImageError, "nonregular"):
            image.acquire(
                self.cached, self.guest, self.digest, "https://example.invalid/x"
            )
        self.assertFalse(self.guest.exists())

    def test_hardlinked_cache_is_rejected(self) -> None:
        self.cached.write_bytes(self.payload)
        os.link(self.cached, self.cache_dir / "shadow")
        with self.assertRaisesRegex(image.ImageError, "linked"):
            image.acquire(
                self.cached, self.guest, self.digest, "https://example.invalid/x"
            )
        self.assertFalse(self.guest.exists())

    def test_partial_download_resumes_without_relaxing_digest(self) -> None:
        seen = []

        def flaky(path: Path, url: str, resume: bool) -> int:
            seen.append(resume)
            if len(seen) == 1:
                path.write_bytes(self.payload[:7])
                return 56
            with path.open("ab") as stream:
                stream.write(self.payload[7:])
            return 0

        image.acquire(
            self.cached,
            self.guest,
            self.digest,
            "https://example.invalid/x",
            flaky,
            lambda _: None,
        )
        self.assertEqual(seen, [False, True])
        self.assertEqual(self.guest.read_bytes(), self.payload)

    def test_unsupported_range_resets_partial_before_retry(self) -> None:
        sizes = []

        def no_range(path: Path, url: str, resume: bool) -> int:
            sizes.append(path.stat().st_size)
            if len(sizes) == 1:
                path.write_bytes(self.payload[:6])
                return 33
            self.assertFalse(resume)
            path.write_bytes(self.payload)
            return 0

        image.acquire(
            self.cached,
            self.guest,
            self.digest,
            "https://example.invalid/x",
            no_range,
            lambda _: None,
        )
        self.assertEqual(sizes, [0, 0])

    def test_wrong_download_digest_cannot_populate_cache(self) -> None:
        with self.assertRaisesRegex(image.ImageError, "SHA-256 mismatch"):
            image.acquire(
                self.cached,
                self.guest,
                self.digest,
                "https://example.invalid/x",
                lambda path, url, resume: (path.write_bytes(b"wrong"), 0)[1],
            )
        self.assertFalse(self.cached.exists())
        self.assertFalse(self.guest.exists())

    def test_transport_failure_is_bounded_and_preserves_no_final_image(self) -> None:
        calls = []

        def broken(path: Path, url: str, resume: bool) -> int:
            calls.append(resume)
            path.write_bytes(b"partial")
            return 56

        with self.assertRaisesRegex(image.ImageError, "after 4 attempts"):
            image.acquire(
                self.cached,
                self.guest,
                self.digest,
                "https://example.invalid/x",
                broken,
                lambda _: None,
            )
        self.assertEqual(len(calls), 4)
        self.assertFalse(self.cached.exists())
        self.assertFalse(self.guest.exists())

    def test_existing_guest_destination_is_not_overwritten(self) -> None:
        self.cached.write_bytes(self.payload)
        self.guest.write_bytes(b"guest data")
        with self.assertRaisesRegex(image.ImageError, "already exists"):
            image.acquire(
                self.cached, self.guest, self.digest, "https://example.invalid/x"
            )
        self.assertEqual(self.guest.read_bytes(), b"guest data")

    def test_swapped_cache_symlink_is_refused(self) -> None:
        self.cached.write_bytes(self.payload)
        victim = self.cache_dir / "other-valid-file"
        victim.write_bytes(self.payload)
        original_check = image.require_digest

        def swap_after_verified(path: Path, expected: str) -> None:
            original_check(path, expected)
            if path == self.cached:
                self.cached.unlink()
                self.cached.symlink_to(victim)

        with patch.object(image, "require_digest", side_effect=swap_after_verified):
            with self.assertRaisesRegex(image.ImageError, "nonregular"):
                image.acquire(
                    self.cached, self.guest, self.digest, "https://example.invalid/x"
                )
        self.assertFalse(self.guest.exists())

    def test_fifo_cache_cannot_stall_validation(self) -> None:
        os.mkfifo(self.cached)
        with self.assertRaisesRegex(image.ImageError, "nonregular"):
            image.acquire(
                self.cached, self.guest, self.digest, "https://example.invalid/x"
            )
        self.assertFalse(self.guest.exists())

    def test_oversized_sparse_cache_is_rejected_without_hashing(self) -> None:
        with self.cached.open("wb") as stream:
            stream.truncate(image.MAX_IMAGE_BYTES + 1)
        with self.assertRaisesRegex(image.ImageError, "exceeds reviewed bound"):
            image.acquire(
                self.cached, self.guest, self.digest, "https://example.invalid/x"
            )
        self.assertFalse(self.guest.exists())

    def test_oversized_download_cannot_be_cached_or_staged(self) -> None:
        def oversize(path: Path, url: str, resume: bool) -> int:
            with path.open("wb") as stream:
                stream.truncate(image.MAX_IMAGE_BYTES + 1)
            return 0

        with self.assertRaisesRegex(image.ImageError, "exceeds reviewed bound"):
            image.acquire(
                self.cached,
                self.guest,
                self.digest,
                "https://example.invalid/x",
                oversize,
            )
        self.assertFalse(self.cached.exists())
        self.assertFalse(self.guest.exists())

    def test_curl_restricts_protocol_redirects_resumption_and_size(self) -> None:
        with patch.object(image.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertEqual(
                image.curl_transfer(
                    self.cached, "https://example.invalid/reviewed.img", True
                ),
                0,
            )
        args = run.call_args.args[0]
        self.assertEqual(args[:2], ["/usr/bin/curl", "--disable"])
        self.assertEqual(args[args.index("--proto") + 1], "=https")
        self.assertEqual(args[args.index("--proto-redir") + 1], "=https")
        self.assertEqual(
            args[args.index("--max-filesize") + 1], str(image.MAX_IMAGE_BYTES)
        )
        self.assertEqual(args[args.index("--continue-at") + 1], "-")
        self.assertNotIn("--insecure", args)

    def test_approved_input_identity_is_not_runtime_configurable(self) -> None:
        with patch.dict(
            os.environ,
            {
                "BASE_IMAGE_URL": image.ORIGIN,
                "BASE_IMAGE_DOWNLOAD_URL": "https://example.invalid/substituted",
                "BASE_IMAGE_SHA256": image.DIGEST,
            },
        ):
            with patch(
                "sys.argv",
                [
                    "qualification_base_image.py",
                    "--destination",
                    str(self.guest),
                ],
            ):
                with self.assertRaisesRegex(image.ImageError, "drifted"):
                    image.main()


if __name__ == "__main__":
    unittest.main()
