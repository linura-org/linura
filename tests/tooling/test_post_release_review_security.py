from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/post-release-closure.yml"
CODEX_BOT_USER_ID = "199175422"


class PostReleaseReviewSecurityTests(unittest.TestCase):
    def _workflow(self) -> str:
        return WORKFLOW.read_text(encoding="utf-8")

    def _request_block(self) -> str:
        workflow = self._workflow()
        return workflow.split("- name: Request exact-head Codex review", 1)[1].split(
            "- name: Require native exact-head checks and completed clean Codex review", 1
        )[0]

    def _poll_block(self) -> str:
        workflow = self._workflow()
        return workflow.split(
            "- name: Require native exact-head checks and completed clean Codex review", 1
        )[1].split("- name: Re-prove and squash merge exact reviewed closure", 1)[0]

    def _merge_block(self) -> str:
        workflow = self._workflow()
        return workflow.split("- name: Re-prove and squash merge exact reviewed closure", 1)[1].split(
            "- name: Resolve post-closure protected-main SHA", 1
        )[0]

    def _cleanup_block(self) -> str:
        return self._workflow().split("- name: Delete obsolete release-scoped branches", 1)[1]

    def test_codex_completion_uses_immutable_numeric_identity(self) -> None:
        workflow = self._workflow()
        self.assertIn(f'CODEX_BOT_USER_ID: "{CODEX_BOT_USER_ID}"', workflow)
        self.assertNotIn('startswith("chatgpt-codex-connector")', workflow)

        for block in (self._poll_block(), self._merge_block()):
            # Review threads use GraphQL cursor pagination. Submitted reviews and
            # clean review comments are independent REST collections and both
            # must be fully paginated before exact-head evidence is evaluated.
            self.assertIn("gh api graphql --paginate", block)
            self.assertGreaterEqual(block.count("gh api --paginate"), 2)
            self.assertIn("pulls/$PR_NUMBER/reviews?per_page=100", block)
            self.assertIn("issues/$PR_NUMBER/comments?per_page=100", block)
            self.assertGreaterEqual(block.count("jq -s -r"), 2)
            self.assertGreaterEqual(block.count('--argjson bot_id "$CODEX_BOT_USER_ID"'), 2)
            self.assertGreaterEqual(block.count(".user.id == $bot_id"), 2)
            self.assertIn(".commit_id == $sha", block)
            self.assertIn('contains("Codex Review: Didn")', block)
            self.assertIn('contains("major issues")', block)

    def test_review_and_clean_comment_completion_sources_are_fully_paginated(self) -> None:
        for block in (self._poll_block(), self._merge_block()):
            self.assertIn(
                'gh api --paginate -H \'Accept: application/vnd.github+json\' \\\n              "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER/reviews?per_page=100"',
                block,
            )
            self.assertIn(
                'gh api --paginate -H \'Accept: application/vnd.github+json\' \\\n              "repos/$GITHUB_REPOSITORY/issues/$PR_NUMBER/comments?per_page=100"',
                block,
            )
            self.assertGreaterEqual(block.count("--jq '.[]'"), 2)
            self.assertNotIn("/reactions?", block)

    def test_clean_comments_are_intrinsically_bound_to_the_exact_head(self) -> None:
        request = self._request_block()
        self.assertIn("@codex review", request)
        self.assertIn("$HEAD_SHA", request)
        self.assertNotIn("REVIEW_REQUESTED_AT", request)
        self.assertNotIn("REVIEW_COMMENT_ID", request)

        for block in (self._poll_block(), self._merge_block()):
            self.assertIn("has_clean_codex_comment", block)
            self.assertIn("Reviewed commit:", block)
            self.assertIn("[0-9a-f]{10,40}", block)
            self.assertIn("$sha | startswith($prefix)", block)
            self.assertIn(".user.id == $bot_id", block)
            self.assertNotIn("REVIEW_REQUESTED_AT", block)
            self.assertNotIn("REVIEW_COMMENT_ID", block)
            self.assertNotIn("codex_clean_reaction", block)
            self.assertNotIn("/reactions?", block)

    def test_cleanup_queries_each_candidate_for_open_pull_requests(self) -> None:
        cleanup = self._cleanup_block()
        self.assertNotIn("gh pr list --state open --limit 100", cleanup)
        self.assertIn('gh api --paginate --method GET "repos/$GITHUB_REPOSITORY/pulls"', cleanup)
        self.assertIn("-f state=open", cleanup)
        self.assertIn('-f head="${GITHUB_REPOSITORY%/*}:$branch"', cleanup)
        self.assertIn("-f per_page=100", cleanup)
        self.assertIn("open_pr_count", cleanup)
        self.assertIn("awk '{ total += $1 } END { print total + 0 }'", cleanup)
        self.assertIn("preserving branch used by an open PR", cleanup)


if __name__ == "__main__":
    unittest.main()
