from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools/run_tooling_tests.py"


class ToolingRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="linura-tooling-runner-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        scripts = self.root / "tools"
        tests = self.root / "tests/tooling"
        scripts.mkdir(parents=True)
        tests.mkdir(parents=True)
        shutil.copy2(SOURCE, scripts / SOURCE.name)
        (tests / "test_a.py").write_text(
            "import unittest\n"
            "class A(unittest.TestCase):\n"
            " def test_one(self): self.assertTrue(True)\n"
            " def test_two(self): self.assertEqual(1, 1)\n",
            encoding="utf-8",
        )
        (tests / "test_b.py").write_text(
            "import unittest\n"
            "class B(unittest.TestCase):\n"
            " def test_three(self): self.assertFalse(False)\n",
            encoding="utf-8",
        )

    def run_suite(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "tools/run_tooling_tests.py"],
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    def test_all_discovered_tests_execute_exactly_once(self) -> None:
        completed = self.run_suite()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Tooling tests: 3/3 completed", completed.stderr)
        for case in ("test_a.A.test_one", "test_a.A.test_two", "test_b.B.test_three"):
            self.assertIn(case, completed.stderr)

    def test_failed_test_causes_failed_canonical_suite(self) -> None:
        path = self.root / "tests/tooling/test_b.py"
        path.write_text(
            path.read_text().replace("assertFalse(False)", "assertFalse(True)")
        )
        completed = self.run_suite()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("FAIL: test_three", completed.stderr)

    def test_import_error_fails_closed(self) -> None:
        (self.root / "tests/tooling/test_b.py").write_text(
            "import module_that_does_not_exist\n", encoding="utf-8"
        )
        completed = self.run_suite()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("tooling discovery failed", completed.stderr)

    def test_duplicate_test_ids_fail_closed(self) -> None:
        (self.root / "tests/tooling/test_b.py").write_text(
            "import unittest\n"
            "class B(unittest.TestCase):\n"
            " def test_one(self): pass\n"
            "def load_tests(loader, tests, pattern):\n"
            " return unittest.TestSuite([B('test_one'), B('test_one')])\n",
            encoding="utf-8",
        )
        completed = self.run_suite()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("duplicate IDs", completed.stderr)

    def test_discovery_changes_between_parent_and_worker_fail_closed(self) -> None:
        (self.root / "tests/tooling/test_b.py").write_text(
            "import os, unittest\n"
            "class B(unittest.TestCase):\n"
            " def test_first(self): pass\n"
            " def test_second(self): pass\n"
            "def load_tests(loader, tests, pattern):\n"
            " return unittest.TestSuite([B('test_first' if len(os.sys.argv) == 1 "
            "else 'test_second')])\n",
            encoding="utf-8",
        )
        completed = self.run_suite()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("inventory mismatch", completed.stderr)
