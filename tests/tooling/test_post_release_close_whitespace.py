from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASE_TEST_PATH = ROOT / "tests/tooling/test_post_release_close.py"
SPEC = importlib.util.spec_from_file_location(
    "post_release_close_base_tests", BASE_TEST_PATH
)
assert SPEC is not None and SPEC.loader is not None
base_tests = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base_tests)


class PostReleaseCloseWhitespaceTests(unittest.TestCase):
    def test_generated_v05_status_has_no_trailing_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            base_tests.PostReleaseCloseTests()._fixture(root)
            base_tests.post_release_close.close_release(base_tests.Args(root))

            roadmap = (root / "docs/roadmap.md").read_text(encoding="utf-8")
            v05 = roadmap.split(
                "## v0.5.0 — first narrow privileged executor and independent verifier\n",
                1,
            )[1].split("## v0.6.0 —", 1)[0]
            self.assertIn("**Status:** released\n", v05)
            self.assertNotIn("**Status:** released  \n", v05)
            self.assertFalse(
                any(
                    line.startswith("**Status:** released")
                    and line.endswith((" ", "\t"))
                    for line in v05.splitlines()
                ),
                v05,
            )


if __name__ == "__main__":
    unittest.main()
