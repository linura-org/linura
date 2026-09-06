from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/post_release_close.py"
SPEC = importlib.util.spec_from_file_location("post_release_close_terminal_audit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
post_release_close = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(post_release_close)


class PostReleaseTerminalAuditTests(unittest.TestCase):
    def test_terminal_qualification_keeps_frozen_contract_as_boundary_only(self) -> None:
        text = """# qualification

**Status:** implementation qualified; release-authorization and terminal publication evidence pending.

## Exit criterion

This dossier is complete only when the final release source has immutable exact-SHA evidence for every required gate and the frozen release contract accurately records that evidence. Until then, v0.6 remains an implementation candidate, not a published qualified release.
"""

        updated = post_release_close.normalize_terminal_qualification(text, "v0.6.0", "Experimental")

        self.assertIn("**Status:** released; terminal publication and independent verification complete.", updated)
        self.assertIn("The frozen release contract remains the pre-publication claim boundary", updated)
        self.assertIn("docs/qualification/v0.6.0-publication.md", updated)
        self.assertNotIn("frozen release contract accurately recorded that evidence", updated)
        self.assertNotIn("not a published qualified release", updated)

    def test_api_versioning_candidate_becomes_released_without_widening_stability(self) -> None:
        text = """# API versioning

### v0.5.0

v0.5 remains Experimental.

### v0.6.0 candidate

v0.6 remains Experimental. It introduces `Authority1` generation 1.

The release candidate makes no Stable compatibility promise for:

- `Authority1` wire shape;

### v0.7.0

Future section.
"""

        updated = post_release_close.normalize_api_versioning(text, "v0.6.0")

        self.assertIn("### v0.6.0\n", updated)
        self.assertNotIn("### v0.6.0 candidate", updated)
        self.assertIn("v0.6 remains Experimental", updated)
        self.assertIn("The released version makes no Stable compatibility promise", updated)
        self.assertNotIn("The release candidate", updated)

    def test_api_versioning_absent_target_is_unchanged(self) -> None:
        text = "# API versioning\n\n### v0.5.0\n\nHistorical.\n"
        self.assertEqual(text, post_release_close.normalize_api_versioning(text, "v0.6.0"))


if __name__ == "__main__":
    unittest.main()
