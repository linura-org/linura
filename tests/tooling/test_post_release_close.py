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

**Status:** implementation qualified; release-authorization and terminal publication evidence pending.
**Claim class:** Experimental

The compacted implementation has completed its exact-head and protected-main implementation gates; the later tree-identical release authorization must still regenerate protected release proof. This is not publication evidence and must not be read as a claim that v0.5 is already released.

## Release-proof handoff

Publication and independent verification remain pending until those repository-controlled terminal events complete.

## Evidence state at release preparation

The following remain mandatory before publication and must be recorded only after they actually occur:

- terminal release proof.

## Exit criterion

This dossier is complete only when the final release source has immutable exact-SHA evidence for every required gate and the frozen release contract accurately records that evidence. Until then, v0.5 remains an implementation candidate, not a published qualified release.
''',
            "docs/qualification/v0.5.0-release-review.md": '''# review

**Status:** implementation qualified; release-preparation candidate; protected publication evidence pending.
**Claim class:** Experimental

This review is the final pre-publication cross-check between implementation and release control.

## Frozen release-contract review

- [ ] release-intent source validates against workspace version.

## Trusted Release Proof review

- [ ] exact protected-main CI success.

## Publication review

- [ ] independent Release Verification redownloads/revalidates assets.

## Decision

**Current decision: READY FOR RELEASE PREPARATION; PUBLICATION PENDING.**

Publication remains fail-closed behind the release-preparation exact-head gates, a tree-identical authorization and release verification. Unchecked publication items remain intentionally pending until those artifacts actually exist.

## Terminal publication evidence

Pending.
''',
            "docs/qualification/v0.5.0-security.md": '''# security

**Status:** implementation security qualified; release-authorization and terminal publication evidence pending.
**Claim class:** Experimental

## Implementation security evidence

These results close implementation security review only. The release authorization must still pass fresh protected-main gates and the complete Trusted Release Proof graph before publication.

## Release-blocking security conditions

Terminal security evidence must be recorded only after final exact-head and release-authorization runs actually succeed.
''',
            "docs/releases/v0.4.0.md": "# v0.4.0\n",
            "docs/releases/v0.5.0.md": "# immutable v0.5.0 contract\n",
        }
        for rel, content in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def test_closure_advances_bookkeeping_preserves_frozen_contract_and_reconciles_terminal_state(self) -> None:
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
            self.assertIn("docs/qualification/v0.5.0-security.md", changed)
            self.assertEqual((root / "docs/releases/v0.5.0.md").read_bytes(), frozen)

            exact_url = f"https://github.com/linura-org/linura/commit/{'a' * 40}"

            qualification = (root / "docs/qualification/v0.5.0.md").read_text(encoding="utf-8")
            self.assertIn("**Status:** released; terminal publication and independent verification complete.", qualification)
            self.assertIn("**Terminal state note:**", qualification)
            self.assertIn("## Historical evidence state at release preparation", qualification)
            self.assertIn("## Historical pre-publication exit criterion", qualification)
            self.assertNotIn("not a published qualified release", qualification)
            self.assertIn(exact_url, qualification)

            review = (root / "docs/qualification/v0.5.0-release-review.md").read_text(encoding="utf-8")
            self.assertIn("Trusted Release Proof: GitHub Actions run `101` — success", review)
            self.assertIn("Independent Release Verification: run `105` — success", review)
            self.assertIn("## Trusted Release Proof review — historical pre-publication checklist", review)
            self.assertIn("## Publication review — historical pre-publication checklist", review)
            self.assertIn("## Historical pre-publication decision", review)
            self.assertIn("**Decision at release preparation:", review)
            self.assertNotIn("**Current decision:", review)
            self.assertNotIn("Pending.", review)
            self.assertIn(exact_url, review)

            security = (root / "docs/qualification/v0.5.0-security.md").read_text(encoding="utf-8")
            self.assertIn("**Status:** released; terminal release-security evidence complete.", security)
            self.assertIn("subsequently passed fresh protected-main gates", security)
            self.assertIn("Terminal security evidence was recorded only after", security)
            self.assertIn("## Terminal publication evidence", security)
            self.assertNotIn("evidence pending", security)
            self.assertIn(exact_url, security)

            publication = (root / "docs/qualification/v0.5.0-publication.md").read_text(encoding="utf-8")
            self.assertIn(f"- Metadata-only release-authorization commit: {exact_url}.", publication)
            self.assertIn(f"- Immutable tag: `v0.5.0` → {exact_url}.", publication)

            milestone = (root / "docs/milestones/v0.5.0.md").read_text(encoding="utf-8")
            self.assertIn("**Status:** released", milestone)
            self.assertIn("- [x] Protected proof-first/tag-last publication", milestone)

    def test_terminal_provenance_uses_full_canonical_commit_url(self) -> None:
        args = Args(Path("."))
        url = f"https://github.com/linura-org/linura/commit/{args.source_sha}"
        terminal = post_release_close.terminal_body(args, "v0.6.0")
        publication = post_release_close.publication_document(
            args,
            {
                "claim_class": "Experimental",
                "executor_state": "isolated-qualified",
                "managed_mutation_support": "none",
                "complete_lifecycle": False,
                "platform_support": "none",
            },
            "v0.6.0",
        )
        self.assertGreaterEqual(terminal.count(url), 2)
        self.assertGreaterEqual(publication.count(url), 2)
        self.assertNotIn(f"release authorization: `{args.source_sha}`", terminal)
        self.assertNotIn(f"release-authorization commit: `{args.source_sha}`", publication)

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
