from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/probe_release_automation_authority.py"
SPEC = importlib.util.spec_from_file_location("probe_release_automation_authority", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def same_head_body() -> str:
    return json.dumps(
        {
            "message": "Validation Failed",
            "errors": [
                {
                    "resource": "PullRequest",
                    "code": "custom",
                    "message": "No commits between main and main",
                }
            ],
        }
    )


class ReleaseAutomationAuthorityGateTests(unittest.TestCase):
    def test_repository_write_capability_is_required(self) -> None:
        accepted = probe.validate_repository_access_response(
            status=200,
            body=json.dumps({"permissions": {"push": True}}),
            credential_source="github",
        )
        self.assertEqual("repository GITHUB_TOKEN", accepted)

        with self.assertRaisesRegex(probe.AuthorityProbeError, "Contents write authority"):
            probe.validate_repository_access_response(
                status=200,
                body=json.dumps({"permissions": {"push": False}}),
                credential_source="github",
            )

    def test_dedicated_token_without_contents_write_is_rejected(self) -> None:
        with self.assertRaisesRegex(probe.AuthorityProbeError, "Contents write"):
            probe.validate_repository_access_response(
                status=200,
                body=json.dumps({"permissions": {"push": False}}),
                credential_source="dedicated",
            )

    def test_exact_same_head_validation_proves_pr_endpoint_authority(self) -> None:
        accepted = probe.validate_pr_probe_response(
            status=422,
            body=same_head_body(),
            base="main",
            head="main",
            credential_source="github",
        )
        self.assertEqual("repository GITHUB_TOKEN", accepted)

    def test_exact_same_head_validation_identifies_dedicated_credential(self) -> None:
        accepted = probe.validate_pr_probe_response(
            status=422,
            body=same_head_body(),
            base="main",
            head="main",
            credential_source="dedicated",
        )
        self.assertEqual("dedicated RELEASE_AUTOMATION_TOKEN", accepted)

    def test_ambiguous_pr_422_is_rejected(self) -> None:
        body = json.dumps(
            {
                "message": "Validation Failed",
                "errors": [
                    {
                        "resource": "PullRequest",
                        "code": "custom",
                        "message": "A pull request already exists",
                    }
                ],
            }
        )
        with self.assertRaisesRegex(probe.AuthorityProbeError, "unexpected HTTP 422"):
            probe.validate_pr_probe_response(
                status=422,
                body=body,
                base="main",
                head="main",
                credential_source="github",
            )

    def test_unparseable_pr_422_is_rejected(self) -> None:
        with self.assertRaisesRegex(probe.AuthorityProbeError, "non-JSON GitHub response"):
            probe.validate_pr_probe_response(
                status=422,
                body="not-json",
                base="main",
                head="main",
                credential_source="github",
            )

    def test_repository_policy_403_has_actionable_fail_closed_guidance(self) -> None:
        with self.assertRaisesRegex(
            probe.AuthorityProbeError,
            "Allow GitHub Actions to create and approve pull requests",
        ):
            probe.validate_pr_probe_response(
                status=403,
                body='{"message":"GitHub Actions is not permitted to create or approve pull requests."}',
                base="main",
                head="main",
                credential_source="github",
            )

    def test_dedicated_pr_token_403_has_least_ambiguity_guidance(self) -> None:
        with self.assertRaisesRegex(probe.AuthorityProbeError, "Pull requests write"):
            probe.validate_pr_probe_response(
                status=403,
                body='{"message":"Resource not accessible by personal access token"}',
                base="main",
                head="main",
                credential_source="dedicated",
            )

    def test_exact_missing_ref_validation_proves_actions_dispatch_authority(self) -> None:
        accepted = probe.validate_actions_probe_response(
            status=422,
            body=json.dumps({"message": f"No ref found for: {probe.MISSING_WORKFLOW_REF}"}),
            missing_ref=probe.MISSING_WORKFLOW_REF,
            credential_source="github",
        )
        self.assertEqual("repository GITHUB_TOKEN", accepted)

    def test_ambiguous_actions_422_is_rejected(self) -> None:
        with self.assertRaisesRegex(probe.AuthorityProbeError, "unexpected HTTP 422"):
            probe.validate_actions_probe_response(
                status=422,
                body=json.dumps({"message": "Validation Failed"}),
                missing_ref=probe.MISSING_WORKFLOW_REF,
                credential_source="github",
            )

    def test_dedicated_token_without_actions_write_is_rejected(self) -> None:
        with self.assertRaisesRegex(probe.AuthorityProbeError, "Actions write"):
            probe.validate_actions_probe_response(
                status=403,
                body='{"message":"Resource not accessible by personal access token"}',
                missing_ref=probe.MISSING_WORKFLOW_REF,
                credential_source="dedicated",
            )

    def test_probe_requires_identical_base_and_head(self) -> None:
        with self.assertRaisesRegex(probe.AuthorityProbeError, "identical base/head"):
            probe.probe(
                repository="linura-org/linura",
                token="unused",
                base="main",
                head="topic",
                credential_source="github",
            )

    def test_release_promotion_isolates_full_closure_authority_before_publication_dispatch(self) -> None:
        workflow = (ROOT / ".github/workflows/release-promotion.yml").read_text(encoding="utf-8")
        self.assertIn("closure-readiness:", workflow)
        self.assertIn("name: prove automatic post-release closure authority", workflow)
        self.assertIn("actions: write", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("pull-requests: write", workflow)
        self.assertIn(
            "GH_TOKEN: ${{ secrets.RELEASE_AUTOMATION_TOKEN || github.token }}",
            workflow,
        )
        self.assertIn("tools/probe_release_automation_authority.py", workflow)
        self.assertIn("RELEASE_AUTOMATION_CREDENTIAL_SOURCE", workflow)
        self.assertIn("needs: [validate, closure-readiness]", workflow)

        readiness_index = workflow.index("closure-readiness:")
        probe_index = workflow.index("tools/probe_release_automation_authority.py")
        dispatch_job_index = workflow.index("\n  dispatch:")
        dispatch_index = workflow.index("gh workflow run release.yml")
        self.assertLess(readiness_index, probe_index)
        self.assertLess(probe_index, dispatch_job_index)
        self.assertLess(dispatch_job_index, dispatch_index)

    def test_release_dispatch_job_does_not_inherit_closure_write_credential(self) -> None:
        workflow = (ROOT / ".github/workflows/release-promotion.yml").read_text(encoding="utf-8")
        dispatch = workflow.split("\n  dispatch:", 1)[1]
        self.assertIn("GH_TOKEN: ${{ github.token }}", dispatch)
        self.assertNotIn("RELEASE_AUTOMATION_TOKEN", dispatch)
        self.assertNotIn("contents: write", dispatch)
        self.assertNotIn("pull-requests: write", dispatch)

    def test_normal_publication_still_dispatches_exact_tag_verification(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("verification-dispatch:", workflow)
        self.assertIn("needs: [validate, publish]", workflow)
        self.assertIn(
            'gh workflow run release-verification.yml --repo "$GITHUB_REPOSITORY" --ref "$RELEASE_TAG" -f tag="$RELEASE_TAG"',
            workflow,
        )

    def test_verifier_does_not_require_downloaded_executable_mode(self) -> None:
        workflow = (ROOT / ".github/workflows/release-verification.yml").read_text(encoding="utf-8")
        self.assertIn("test -f published/linura-authorityd", workflow)
        self.assertNotIn("test -x published/linura-authorityd", workflow)
        self.assertIn("python3 tools/release_contract.py verify", workflow)
        self.assertIn("gh release verify-asset", workflow)
        self.assertIn("gh attestation verify", workflow)


if __name__ == "__main__":
    unittest.main()
