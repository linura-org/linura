from __future__ import annotations

from pathlib import Path
import os
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

    def test_isolated_validation_cases_shard_without_missing_or_duplicate_ids(self):
        source = (
            "import os\n"
            "import unittest\n"
            "class ValidationGateTests(unittest.TestCase):\n"
            " def record(self, value):\n"
            "  with open('gate-' + str(os.getpid()) + '.txt', 'a') as output:\n"
            "   output.write(value + '\\n')\n"
            " def test_0(self): self.record('0')\n"
            " def test_1(self): self.record('1')\n"
            " def test_2(self): self.record('2')\n"
            " def test_3(self): self.record('3')\n"
            " def test_4(self): self.record('4')\n"
            " def test_5(self): self.record('5')\n"
        )
        (self.root / "tests/tooling/test_validation_gates.py").write_text(
            source, encoding="utf-8"
        )
        completed = self.run_suite()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        available_cpus = (
            len(os.sched_getaffinity(0))
            if hasattr(os, "sched_getaffinity")
            else (os.cpu_count() or 1)
        )
        expected_workers = min(2, available_cpus)
        self.assertIn(
            f"Tooling tests: 9/9 completed across {expected_workers} workers",
            completed.stderr,
        )
        manifests = list(self.root.glob("gate-*.txt"))
        self.assertEqual(len(manifests), expected_workers)
        self.assertEqual(
            sorted("".join(path.read_text() for path in manifests).splitlines()),
            list("012345"),
        )

    def test_validation_sharding_rejects_shared_class_fixture(self):
        source = (
            "import unittest\n"
            "class ValidationGateTests(unittest.TestCase):\n"
            " @classmethod\n"
            " def setUpClass(cls): pass\n"
            " def test_one(self): pass\n"
        )
        (self.root / "tests/tooling/test_validation_gates.py").write_text(
            source, encoding="utf-8"
        )
        completed = self.run_suite()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("tooling shard policy rejects shared fixtures", completed.stderr)

    def test_validation_sharding_rejects_inherited_shared_fixture(self):
        source = (
            "import unittest\n"
            "class SharedFixture(unittest.TestCase):\n"
            " @classmethod\n"
            " def setUpClass(cls): pass\n"
            "class ValidationGateTests(SharedFixture):\n"
            " def test_one(self): pass\n"
        )
        (self.root / "tests/tooling/test_validation_gates.py").write_text(
            source, encoding="utf-8"
        )
        completed = self.run_suite()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("tooling shard policy rejects shared fixtures", completed.stderr)

    def test_failed_sharded_validation_case_fails_the_full_inventory(self):
        (self.root / "tests/tooling/test_validation_gates.py").write_text(
            "import unittest\n"
            "class ValidationGateTests(unittest.TestCase):\n"
            " def test_pass(self): self.assertTrue(True)\n"
            " def test_fail(self): self.assertEqual(1, 2)\n",
            encoding="utf-8",
        )
        completed = self.run_suite()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("FAIL: test_fail", completed.stderr)
        self.assertIn("Tooling tests: 5/5 completed", completed.stderr)

    def test_validation_sharding_rejects_module_level_shared_fixtures(self):
        for fixture in ("setUpModule", "tearDownModule"):
            with self.subTest(fixture=fixture):
                (self.root / "tests/tooling/test_validation_gates.py").write_text(
                    "import unittest\n"
                    f"def {fixture}(): pass\n"
                    "class ValidationGateTests(unittest.TestCase):\n"
                    " def test_one(self): pass\n",
                    encoding="utf-8",
                )
                completed = self.run_suite()
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    "tooling shard policy rejects shared fixtures", completed.stderr
                )

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
