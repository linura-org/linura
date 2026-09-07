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
    def _next_release_milestone(self) -> tuple[str, Path]:
        roadmap = tomllib.loads((ROOT / "contracts/roadmap.toml").read_text(encoding="utf-8"))
        tag = roadmap["next_release"]
        milestone = next(item for item in roadmap["milestone"] if item["version"] == tag)
        path = ROOT / milestone["milestone_contract"]
        return tag, path

    def test_next_release_uses_canonical_terminal_closure_criteria(self) -> None:
        tag, milestone_path = self._next_release_milestone()
        text = milestone_path.read_text(encoding="utf-8")

        for criterion in CANONICAL_TERMINAL_CRITERIA:
            self.assertIn(criterion, text, f"{tag} must preserve the canonical terminal closure criterion: {criterion}")

    def test_release_candidate_gate_is_fully_closure_mappable(self) -> None:
        tag, milestone_path = self._next_release_milestone()
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        if tag not in readme or "release candidate" not in readme:
            self.skipTest(f"{tag} is not represented as the active release candidate")

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
