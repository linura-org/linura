#!/usr/bin/env python3
"""Run every discovered tooling test, with independent worker inventories."""

from __future__ import annotations

from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEST_DIRECTORY = ROOT / "tests/tooling"
# Only this module uses independent per-test temporary fixture roots; all other
# modules retain one-worker-per-module semantics for shared-fixture isolation.
SHARDABLE_MODULE = "test_validation_gates"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def flatten(suite: unittest.TestSuite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def discover() -> list[unittest.case.TestCase]:
    loader = unittest.TestLoader()
    tests = list(flatten(loader.discover(str(TEST_DIRECTORY), pattern="test_*.py")))
    if loader.errors:
        details = "\n".join(str(error) for error in loader.errors)
        raise RuntimeError(f"tooling discovery failed:\n{details}")
    ids = [test.id() for test in tests]
    if not ids or len(ids) != len(set(ids)):
        raise RuntimeError("tooling test inventory is empty or contains duplicate IDs")
    return tests


class TimedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timings: list[tuple[float, str]] = []

    def startTest(self, test):
        self._started = time.monotonic()
        super().startTest(test)

    def stopTest(self, test):
        self.timings.append((time.monotonic() - self._started, test.id()))
        super().stopTest(test)


def worker(assigned: Path, output: Path, log: Path) -> int:
    expected_ids = json.loads(assigned.read_text(encoding="utf-8"))
    if (
        not isinstance(expected_ids, list)
        or not expected_ids
        or any(not isinstance(item, str) or not item for item in expected_ids)
        or len(set(expected_ids)) != len(expected_ids)
    ):
        raise RuntimeError("tooling worker inventory mismatch: invalid assigned IDs")
    assigned_ids = set(expected_ids)
    tests = [test for test in discover() if test.id() in assigned_ids]
    if {test.id() for test in tests} != assigned_ids or len(tests) != len(expected_ids):
        raise RuntimeError("tooling worker inventory mismatch: selected IDs changed")
    with log.open("w", encoding="utf-8") as stream:
        runner = unittest.TextTestRunner(
            stream=stream, verbosity=1, resultclass=TimedResult
        )
        result = runner.run(unittest.TestSuite(tests))
    if not isinstance(result, TimedResult):
        raise RuntimeError("tooling result class changed")
    output.write_text(
        json.dumps(
            {
                "ids": [test.id() for test in tests],
                "executed": result.testsRun,
                "successful": result.wasSuccessful(),
                "timings": result.timings,
            }
        ),
        encoding="utf-8",
    )
    return 0 if result.wasSuccessful() and result.testsRun == len(tests) else 1


def main() -> int:
    os.chdir(ROOT)
    if len(sys.argv) == 5 and sys.argv[1] == "--worker":
        return worker(*(Path(arg) for arg in sys.argv[2:]))
    if len(sys.argv) != 1:
        raise RuntimeError("unexpected tooling runner arguments")
    tests = discover()
    expected = Counter(test.id() for test in tests)
    by_module = defaultdict(list)
    independent_tests = []
    for test in tests:
        module = type(test).__module__
        if module == SHARDABLE_MODULE:
            # ValidationGateTests gives each test a private TemporaryDirectory;
            # reject added shared class/module fixtures instead of silently
            # distributing stateful tests across independent worker processes.
            cls = type(test)
            source_module = sys.modules.get(module)
            if (
                cls.__bases__ != (unittest.TestCase,)
                or cls.__name__ != "ValidationGateTests"
                or "setUpClass" in cls.__dict__
                or "tearDownClass" in cls.__dict__
                or source_module is None
                or callable(getattr(source_module, "setUpModule", None))
                or callable(getattr(source_module, "tearDownModule", None))
            ):
                raise RuntimeError("tooling shard policy rejects shared fixtures")
            independent_tests.append(test.id())
        else:
            by_module[module].append(test.id())
    # Preserve single-process module fixtures except for the explicitly audited
    # independent validation cases. Count-balanced modules alone put 757s of
    # validation checks on one worker and 56s on the other.
    cpu_count = (
        len(os.sched_getaffinity(0))
        if hasattr(os, "sched_getaffinity")
        else (os.cpu_count() or 1)
    )
    workers = min(2, cpu_count, len(by_module) + bool(independent_tests))
    assignments = [[] for _ in range(workers)]
    weights = [0] * workers
    for position, identifier in enumerate(sorted(independent_tests)):
        index = position % workers
        assignments[index].append(identifier)
        weights[index] += 1
    for module in sorted(by_module, key=lambda value: (-len(by_module[value]), value)):
        index = weights.index(min(weights))
        assignments[index].extend(by_module[module])
        weights[index] += len(by_module[module])

    with tempfile.TemporaryDirectory(prefix="linura-tooling-tests-") as directory:
        temp = Path(directory)
        processes = []
        for index, identifiers in enumerate(assignments):
            selection = temp / f"worker-{index}.json"
            manifest = temp / f"result-{index}.json"
            log = temp / f"worker-{index}.log"
            selection.write_text(json.dumps(identifiers), encoding="utf-8")
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--worker",
                    str(selection),
                    str(manifest),
                    str(log),
                ],
                cwd=ROOT,
            )
            processes.append((process, manifest, log))

        actual = Counter()
        timings = []
        valid = True
        for index, (process, manifest, log) in enumerate(processes):
            code = process.wait()
            if log.is_file():
                sys.stderr.write(f"\nTooling worker {index + 1}/{workers}:\n")
                sys.stderr.write(log.read_text(encoding="utf-8"))
            if not manifest.is_file():
                valid = False
                continue
            result = json.loads(manifest.read_text(encoding="utf-8"))
            if code:
                valid = False
            ids = result["ids"]
            actual.update(ids)
            timings.extend(result["timings"])
            if result["executed"] != len(ids) or not result["successful"]:
                valid = False
        if actual != expected:
            sys.stderr.write(
                f"Tooling inventory mismatch: expected {sum(expected.values())}, "
                f"observed {sum(actual.values())}\n"
            )
            valid = False
        sys.stderr.write(
            f"Tooling tests: {sum(actual.values())}/{sum(expected.values())} "
            f"completed across {workers} workers\n"
        )
        sys.stderr.write("Slowest tooling tests (wall-clock seconds):\n")
        for elapsed, case in sorted(timings, key=lambda entry: (-entry[0], entry[1]))[
            :20
        ]:
            sys.stderr.write(f"  {elapsed:.3f}s {case}\n")
        return 0 if valid else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(f"tooling test runner failed closed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
