from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/post_release_close.py"
SPEC = importlib.util.spec_from_file_location("post_release_close", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
post_release_close = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(post_release_close)


class Args:
    tag = "v0.5.0"
    source_sha = "a" * 40
    proof_run_id = 101
    promotion_run_id = 102
    release_run_id = 103
    release_id = 104
    verification_run_id = 105
    published_at = "2026-09-05T12:57:27Z"

    def __init__(self, root: Path) -> None:
        self.root = root


class PostReleaseCloseTests(unittest.TestCase):
    def _fixture(self, root: Path) -> None:
        files = {
            "contracts/roadmap.toml": '''schema_version = 1
current_release = "v0.4.0"
next_release = "v0.5.0"

[[milestone]]
version = "v0.4.0"
title = "durable foundation"
status = "released"
claim_class = "Experimental"
depends_on = []
durable_recovery = true
executor_state = "none"
complete_lifecycle = false
managed_mutation_support = "none"
agent_role = "none"
platform_support = "none"
release_contract = "docs/releases/v0.4.0.md"

[[milestone]]
version = "v0.5.0"
title = "first narrow privileged executor and independent verifier"
status = "planned"
claim_class = "Experimental"
depends_on = ["v0.4.0"]
durable_recovery = true
executor_state = "isolated-qualified"
complete_lifecycle = false
managed_mutation_support = "none"
agent_role = "none"
platform_support = "none"
milestone_contract = "docs/milestones/v0.5.0.md"
release_contract = "docs/releases/v0.5.0.md"
qualification = "docs/qualification/v0.5.0.md"

[[milestone]]
version = "v0.6.0"
title = "complete eleven-stage managed mutation"
status = "planned"
claim_class = "Experimental"
depends_on = ["v0.5.0"]
durable_recovery = true
executor_state = "integrated-narrow"
complete_lifecycle = true
managed_mutation_support = "narrow-experimental"
agent_role = "none"
platform_support = "none"
''',
            "docs/roadmap.md": '''# Roadmap

## v0.4.0 — durable foundation

**Status:** released
**Claim class:** Experimental

## v0.5.0 — first narrow privileged executor and independent verifier

**Status:** planned  
**Target claim class:** Experimental

Qualification-only scope.

## v0.6.0 — complete eleven-stage managed mutation

**Status:** planned  
**Target claim class:** Experimental
''',
            "docs/milestones/v0.5.0.md": '''# v0.5.0

**Status:** release candidate; publication pending

## Exit criteria

- [x] implementation complete
- [ ] Protected proof-first/tag-last publication and independent Release Verification complete before roadmap bookkeeping advances to v0.6.
''',
            "README.md": '''# Linura

Status: `v0.5.0` release candidate — pending.
''',
            "docs/qualification/v0.5.0.md": '''# qualification

## Release-proof handoff

Publication and independent verification remain pending until those repository-controlled terminal events complete.
''',
            "docs/qualification/v0.5.0-release-review.md": '''# review

## Terminal publication evidence

Pending.
''',
            "docs/releases/v0.4.0.md": "# v0.4.0\n",
            "docs/releases/v0.5.0.md": "# immutable v0.5.0 contract\n",
        }
        for rel, content in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def test_closure_advances_bookkeeping_and_preserves_frozen_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._fixture(root)
            frozen = (root / "docs/releases/v0.5.0.md").read_bytes()
            changed = post_release_close.close_release(Args(root))

            contract = (root / "contracts/roadmap.toml").read_text(encoding="utf-8")
            self.assertIn('current_release = "v0.5.0"', contract)
            self.assertIn('next_release = "v0.6.0"', contract)
            v05 = contract.split('version = "v0.5.0"', 1)[1].split('[[milestone]]', 1)[0]
            self.assertIn('status = "released"', v05)
            self.assertIn("docs/qualification/v0.5.0-publication.md", changed)
            self.assertEqual((root / "docs/releases/v0.5.0.md").read_bytes(), frozen)

            review = (root / "docs/qualification/v0.5.0-release-review.md").read_text(encoding="utf-8")
            self.assertIn("Trusted Release Proof: GitHub Actions run `101` — success", review)
            self.assertIn("Independent Release Verification: run `105` — success", review)
            self.assertNotIn("Pending.", review)

            milestone = (root / "docs/milestones/v0.5.0.md").read_text(encoding="utf-8")
            self.assertIn("**Status:** released", milestone)
            self.assertIn("- [x] Protected proof-first/tag-last publication", milestone)

    def test_split_release_gate_closes_each_evidenced_control_criterion(self) -> None:
        milestone = '''# v0.6.0

## Release gate

v0.6.0 is not releaseable until:

- [ ] canonical CI, Security and CodeQL pass on the exact candidate source;
- [ ] dedicated v0.6 managed-lifecycle disposable-VM qualification passes on the exact candidate source;
- [ ] Trusted Release Proof reruns all mandatory inherited v0.4/v0.5 qualifications plus the v0.6 qualification against the exact release authorization;
- [ ] independent binary reproduction succeeds;
- [ ] tag-last publication succeeds;
- [ ] independent published-release verification succeeds;
- [ ] post-release closure advances machine roadmap state only after immutable publication evidence exists.

## Explicit non-claims

No widened claim.
'''
        updated = post_release_close.close_release_control_criteria(milestone, "v0.6.0")

        self.assertNotIn("- [ ]", updated.split("## Explicit non-claims", 1)[0])
        self.assertEqual(7, updated.count("- [x]"))
        self.assertIn("- [x] tag-last publication succeeds;", updated)
        self.assertIn("- [x] independent published-release verification succeeds;", updated)
        self.assertIn("- [x] post-release closure advances machine roadmap state", updated)

    def test_release_gate_rejects_unmapped_unchecked_criterion(self) -> None:
        milestone = '''# future

## Release gate

- [ ] tag-last publication succeeds;
- [ ] independent published-release verification succeeds;
- [ ] manually rotate an unrelated external credential.
'''
        with self.assertRaisesRegex(
            post_release_close.ClosureError,
            "unchecked release-gate criteria are not exactly mapped to terminal release evidence",
        ):
            post_release_close.close_release_control_criteria(milestone, "v9.9.9")

    def test_release_gate_rejects_misleading_keyword_collision(self) -> None:
        milestone = '''# future

## Release gate

- [ ] tag-last publication succeeds;
- [ ] independent published-release verification succeeds;
- [ ] Security tabletop exercise with external responders is complete.
'''
        with self.assertRaisesRegex(
            post_release_close.ClosureError,
            "Security tabletop exercise with external responders is complete",
        ):
            post_release_close.close_release_control_criteria(milestone, "v9.9.9")

    def test_release_gate_requires_exact_publication_and_verification_mappings(self) -> None:
        milestone = '''# future

## Release gate

- [ ] Trusted Release Proof succeeds.
'''
        with self.assertRaisesRegex(post_release_close.ClosureError, "exactly mapped publication criterion"):
            post_release_close.close_release_control_criteria(milestone, "v9.9.9")

    def test_closure_rejects_non_next_release(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._fixture(root)
            contract = root / "contracts/roadmap.toml"
            contract.write_text(
                contract.read_text(encoding="utf-8").replace(
                    'next_release = "v0.5.0"', 'next_release = "v0.6.0"', 1
                ),
                encoding="utf-8",
            )
            with self.assertRaises(post_release_close.ClosureError):
                post_release_close.close_release(Args(root))

    def test_existing_publication_evidence_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._fixture(root)
            publication = root / "docs/qualification/v0.5.0-publication.md"
            publication.write_text("conflicting evidence\n", encoding="utf-8")
            with self.assertRaises(post_release_close.ClosureError):
                post_release_close.close_release(Args(root))

    def test_workflow_pins_protected_closure_sequence(self) -> None:
        workflow = (ROOT / ".github/workflows/post-release-closure.yml").read_text(encoding="utf-8")
        for marker in (
            'workflows: ["Verify published release"]',
            "github.event.workflow_run.conclusion == 'success'",
            "python3 tools/post_release_close.py",
            'gh workflow run "$workflow" --repo "$GITHUB_REPOSITORY" --ref "$BRANCH"',
            'wait_for ci.yml canonical-check',
            'wait_for security.yml dependency-audit',
            'wait_for codeql.yml analyze',
            'gh pr merge "$PR_NUMBER" --squash --delete-branch',
            'gh workflow run "$workflow" --repo "$GITHUB_REPOSITORY" --ref main',
            'Delete obsolete release-scoped branches',
        ):
            self.assertIn(marker, workflow)
        self.assertNotIn("git push origin main", workflow)

        for path in ("ci.yml", "security.yml", "codeql.yml"):
            text = (ROOT / ".github/workflows" / path).read_text(encoding="utf-8")
            self.assertIn("workflow_dispatch:", text)


if __name__ == "__main__":
    unittest.main()
