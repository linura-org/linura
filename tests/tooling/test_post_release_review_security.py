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
            # Review threads use GraphQL cursor pagination. Review submissions,
            # request-comment reactions, and PR-level reactions are independent
            # REST collections and all must paginate before evidence is evaluated.
            self.assertIn("gh api graphql --paginate", block)
            self.assertGreaterEqual(block.count("gh api --paginate"), 3)
            self.assertIn("pulls/$PR_NUMBER/reviews?per_page=100", block)
            self.assertIn("issues/comments/$REVIEW_COMMENT_ID/reactions?per_page=100", block)
            self.assertIn("issues/$PR_NUMBER/reactions?per_page=100", block)
            self.assertGreaterEqual(block.count("jq -s -r"), 2)
            self.assertGreaterEqual(block.count('--argjson bot_id "$CODEX_BOT_USER_ID"'), 2)
            self.assertGreaterEqual(block.count(".user.id == $bot_id"), 2)
            self.assertIn(".commit_id == $sha", block)
            self.assertIn('.content == "+1"', block)

    def test_review_and_reaction_completion_sources_are_fully_paginated(self) -> None:
        for block in (self._poll_block(), self._merge_block()):
            self.assertIn(
                'gh api --paginate -H \'Accept: application/vnd.github+json\' \\\n              "repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER/reviews?per_page=100"',
                block,
            )
            self.assertIn(
                '"repos/$GITHUB_REPOSITORY/issues/comments/$REVIEW_COMMENT_ID/reactions?per_page=100"',
                block,
            )
            self.assertIn(
                '"repos/$GITHUB_REPOSITORY/issues/$PR_NUMBER/reactions?per_page=100"',
                block,
            )
            self.assertGreaterEqual(block.count("--jq '.[]'"), 3)

    def test_clean_reactions_are_bound_to_this_exact_head_request(self) -> None:
        request = self._request_block()
        self.assertIn('requested_at="$(jq -r .created_at <<<"$payload")"', request)
        self.assertIn("printf 'requested_at=%s\\n'", request)

        for block in (self._poll_block(), self._merge_block()):
            self.assertIn("REVIEW_REQUESTED_AT: ${{ steps.review_request.outputs.requested_at }}", block)
            self.assertIn('--arg requested_at "$REVIEW_REQUESTED_AT"', block)
            self.assertIn('(.created_at // "") >= $requested_at', block)
            self.assertIn("issues/$PR_NUMBER/reactions?per_page=100", block)

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
