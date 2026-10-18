from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_changelog", ROOT / "tools/check_changelog.py"
)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

ROADMAP = {
    "milestone": [
        {"version": "v0.8.0", "status": "released"},
        {"version": "v0.9.0", "status": "released"},
        {"version": "v0.10.0", "status": "planned"},
    ]
}
GOOD = """# Changelog

## [Unreleased]

Target milestone: [v0.10.0](docs/milestones/v0.10.0.md) — work in progress, not released.

### Changes since v0.9.0
- Continue qualification and desktop integration.

## [0.9.0] - 2026-09-17

Experimental First Boot. [Release contract](docs/releases/v0.9.0.md).

## [0.8.0] - 2026-09-10

Proposal-only adapters. [Release contract](docs/releases/v0.8.0.md).
"""


class ChangelogTests(unittest.TestCase):
    def check(self, content: str, *, candidate: str | None = None) -> list[str]:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "CHANGELOG.md").write_text(content, encoding="utf-8")
            return checker.validate(root, ROADMAP, release_candidate=candidate)

    def test_repository_changelog_agrees_with_canonical_roadmap(self) -> None:
        roadmap = tomllib.loads(
            (ROOT / "contracts/roadmap.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(checker.validate(ROOT, roadmap), [])

    def test_released_versions_and_pending_milestone(self) -> None:
        self.assertEqual(self.check(GOOD, candidate="v0.10.0"), [])

    def test_rejects_missing_published_version(self) -> None:
        broken = GOOD.replace("## [0.9.0] - 2026-09-17", "## [0.7.0] - 2026-09-17")
        errors = self.check(broken)
        self.assertTrue(any("v0.9.0: released milestone missing" in e for e in errors))

    def test_rejects_dated_unpublished_milestone(self) -> None:
        broken = GOOD.replace(
            "## [0.9.0]",
            "## [0.10.0] - 2026-09-17\n\nFuture milestone.\n\n## [0.9.0]",
        )
        errors = self.check(broken)
        self.assertTrue(
            any("dated changelog entry has no released" in e for e in errors)
        )

    def test_rejects_missing_contract_link(self) -> None:
        broken = GOOD.replace("docs/releases/v0.9.0.md", "docs/releases/v0.8.0.md")
        errors = self.check(broken)
        self.assertTrue(
            any("must link the frozen release contract" in e for e in errors)
        )

    def test_rejects_missing_or_duplicate_unreleased(self) -> None:
        self.assertTrue(
            any(
                "must start" in e
                for e in self.check(GOOD.replace("## [Unreleased]", "## [Draft]"))
            )
        )
        broken = GOOD.replace("## [0.9.0]", "## [Unreleased]\n\n## [0.9.0]")
        self.assertTrue(any("duplicate changelog" in e for e in self.check(broken)))

    def test_rejects_bad_dates_and_order(self) -> None:
        broken = GOOD.replace("2026-09-17", "2026-02-31")
        self.assertTrue(any("invalid release date" in e for e in self.check(broken)))
        broken = GOOD.replace("## [0.9.0]", "## [TMP]")
        broken = broken.replace("## [0.8.0]", "## [0.9.0]")
        broken = broken.replace("## [TMP]", "## [0.8.0]")
        self.assertTrue(
            any("descending version order" in e for e in self.check(broken))
        )

    def test_preparation_requires_notes_and_target(self) -> None:
        broken = GOOD.replace(
            "- Continue qualification and desktop integration.", "Not documented."
        )
        errors = self.check(broken, candidate="v0.10.0")
        self.assertTrue(any("substantive change notes" in e for e in errors))
        broken = GOOD.replace(
            "docs/milestones/v0.10.0.md", "docs/milestones/v0.11.0.md"
        )
        errors = self.check(broken, candidate="v0.10.0")
        self.assertTrue(any("prepublication milestone marker" in e for e in errors))

    def test_verified_terminal_closure_is_idempotent(self) -> None:
        updated = checker.finalize_release(GOOD, "v0.10.0", "2026-11-03T12:00:00Z")
        self.assertIn("## [0.10.0] - 2026-11-03", updated)
        self.assertIn("docs/releases/v0.10.0.md", updated)
        self.assertNotIn("not released.", updated)
        self.assertEqual(
            updated,
            checker.finalize_release(updated, "v0.10.0", "2026-11-03T12:00:00Z"),
        )
        promoted = {
            "milestone": [
                {**item, "status": "released"} for item in ROADMAP["milestone"]
            ]
        }
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "CHANGELOG.md").write_text(updated, encoding="utf-8")
            self.assertEqual(checker.validate(root, promoted), [])

    def test_closure_rejects_untrusted_or_inconsistent_inputs(self) -> None:
        for content, timestamp in (
            (
                GOOD.replace("Target milestone:", "Different milestone:"),
                "2026-11-03T12:00:00Z",
            ),
            (GOOD, "2026-11-03T12:00:00"),
            (GOOD, "not-a-date"),
        ):
            with self.subTest(timestamp=timestamp):
                with self.assertRaises(checker.ChangelogClosureError):
                    checker.finalize_release(content, "v0.10.0", timestamp)

    def test_empty_unreleased_is_allowed_outside_release_preparation(self) -> None:
        closed = GOOD.replace(
            "Target milestone: [v0.10.0](docs/milestones/v0.10.0.md) — work in progress, not released.\n\n"
            "### Changes since v0.9.0\n- Continue qualification and desktop integration.",
            "",
        )
        self.assertEqual(self.check(closed), [])


if __name__ == "__main__":
    unittest.main()
