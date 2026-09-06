from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/post_release_close.py"
SPEC = importlib.util.spec_from_file_location("post_release_close", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
post_release_close = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(post_release_close)


class ReviewRegressionTests(unittest.TestCase):
    def test_release_review_normalizes_live_prepublication_assertions(self) -> None:
        text = '''# review

**Status:** implementation qualified; release-preparation candidate; protected publication evidence pending.

Release-preparation changes now advance version/lockfile and freeze candidate-facing evidence without marking v0.6.0 published.

Trusted Release Proof must still rerun it on the later exact release authorization; implementation evidence does not substitute for release proof.

## Decision

**Current decision: READY FOR RELEASE PREPARATION; PUBLICATION PENDING.**

Publication remains fail-closed behind the release-preparation exact-head gates, proof and publication. Unchecked publication items remain intentionally pending until those artifacts actually exist.
'''
        updated = post_release_close.normalize_terminal_review(text, "v0.6.0")
        self.assertIn("terminal publication subsequently completed", updated)
        self.assertIn("terminal release proof subsequently succeeded", updated)
        self.assertNotIn("Release-preparation changes now advance", updated)
        self.assertNotIn("must still rerun", updated)
        self.assertNotIn("**Current decision:", updated)
        self.assertNotIn("Publication remains fail-closed", updated)

    def test_qualification_uses_milestone_claim_class(self) -> None:
        text = '''# qualification

**Status:** implementation qualified; release-authorization and terminal publication evidence pending.

## Exit criterion

This dossier is complete only when the final release source has immutable exact-SHA evidence for every required gate and the frozen release contract accurately records that evidence. Until then, v1.0 remains an implementation candidate, not a published qualified release.
'''
        updated = post_release_close.normalize_terminal_qualification(text, "v1.0.0", "Stable")
        self.assertIn("published, independently verified Stable release", updated)
        self.assertNotIn("independently verified Experimental release", updated)

    def test_review_normalizer_removes_known_live_marker(self) -> None:
        text = '''# review

**Status:** released; terminal publication and independent verification complete.

Release-preparation changes now advance version/lockfile and freeze candidate-facing evidence without marking v0.6.0 published.
'''
        updated = post_release_close.normalize_terminal_review(text, "v0.6.0")
        self.assertNotIn("Release-preparation changes now advance", updated)


if __name__ == "__main__":
    unittest.main()
