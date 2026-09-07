from __future__ import annotations

import importlib.util
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/post_release_close.py"
SPEC = importlib.util.spec_from_file_location("post_release_close_gate_contract", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
post_release_close = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(post_release_close)

CANONICAL_TERMINAL_CRITERIA = (
    "- [ ] tag-last publication succeeds;",
    "- [ ] independent published-release verification succeeds;",
    "- [ ] post-release closure advances machine roadmap state only after immutable publication evidence exists.",
)


class ReleaseGateCandidateContractTests(unittest.TestCase):
    def _active_release_candidate_milestone(self) -> tuple[str, Path]:
        roadmap = tomllib.loads((ROOT / "contracts/roadmap.toml").read_text(encoding="utf-8"))
        tag = roadmap["next_release"]
        milestone = next(item for item in roadmap["milestone"] if item["version"] == tag)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        status_lines = [line for line in readme.splitlines() if line.startswith("Status:")]
        self.assertEqual(1, len(status_lines), "README must contain exactly one canonical Status line")
        status = status_lines[0]

        # Future roadmap milestones intentionally may not have a frozen milestone
        # contract yet. Determine candidate status before dereferencing that field so
        # post-release closure can advance next_release without breaking its own
        # exact-closure-SHA CI run.
        if f"`{tag}`" not in status or "release candidate" not in status:
            self.skipTest(f"{tag} is not represented as the active release candidate")

        milestone_contract = milestone.get("milestone_contract")
        self.assertIsInstance(
            milestone_contract,
            str,
            f"active release candidate {tag} must declare milestone_contract",
        )
        assert isinstance(milestone_contract, str)
        path = ROOT / milestone_contract
        self.assertTrue(path.is_file(), f"active release candidate milestone contract is missing: {path}")
        return tag, path

    def test_next_release_uses_canonical_terminal_closure_criteria(self) -> None:
        tag, milestone_path = self._active_release_candidate_milestone()
        text = milestone_path.read_text(encoding="utf-8")

        for criterion in CANONICAL_TERMINAL_CRITERIA:
            self.assertIn(criterion, text, f"{tag} must preserve the canonical terminal closure criterion: {criterion}")

    def test_release_candidate_gate_is_fully_closure_mappable(self) -> None:
        tag, milestone_path = self._active_release_candidate_milestone()
        text = milestone_path.read_text(encoding="utf-8")
        updated = post_release_close.close_release_control_criteria(text, tag)
        gate = updated.split("## Release gate", 1)[1].split("## ", 1)[0]

        self.assertNotIn("- [ ]", gate)
        self.assertIn("- [x] tag-last publication succeeds;", gate)
        self.assertIn("- [x] independent published-release verification succeeds;", gate)
        self.assertIn(
            "- [x] post-release closure advances machine roadmap state only after immutable publication evidence exists.",
            gate,
        )


if __name__ == "__main__":
    unittest.main()
