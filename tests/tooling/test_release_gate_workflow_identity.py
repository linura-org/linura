import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
STABLE_PATH = '.path == (".github/workflows/" + ($workflow | ascii_downcase) + ".yml")'
EXACT_SHA = ".head_sha == env.SOURCE_SHA"
PUSH_ONLY = '.event == "push"'
PUSH_OR_DISPATCH = '(.event == "push" or .event == "workflow_dispatch")'
TERMINAL_SUCCESS = '.status == "completed" and .conclusion == "success"'


def step_block(workflow: str, step_name: str) -> str:
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    marker = f"      - name: {step_name}\n"
    start = text.find(marker)
    if start < 0:
        raise AssertionError(f"missing step {step_name!r} in {workflow}")
    end = text.find("\n      - name:", start + len(marker))
    if end < 0:
        end = len(text)
    return text[start:end]


class ReleaseGateWorkflowIdentityTests(unittest.TestCase):
    def assert_state_gate_contract(self, block: str, event_predicate: str) -> None:
        selector = (
            f"[.workflow_runs[] | select({STABLE_PATH} and {EXACT_SHA} and {event_predicate})]"
        )
        self.assertIn(selector, block)
        self.assertIn(
            f'if any(.[]; {TERMINAL_SUCCESS}) then "success"',
            block,
        )
        self.assertNotIn(".name == $workflow", block)

    def assert_count_gate_contract(self, block: str, event_predicate: str) -> None:
        selector = (
            f"[.workflow_runs[] | select({STABLE_PATH} and {EXACT_SHA} and "
            f'{event_predicate} and {TERMINAL_SUCCESS})] | length'
        )
        self.assertIn(selector, block)
        self.assertNotIn(".name == $workflow", block)

    def test_release_proof_dispatch_gate_is_step_scoped_and_fail_closed(self) -> None:
        block = step_block(
            "release-proof-dispatch.yml",
            "Verify exact-main release intent and dispatch proof",
        )
        self.assertIn(
            'actions/runs?head_sha=$SOURCE_SHA&event=push&per_page=100',
            block,
        )
        self.assert_state_gate_contract(block, PUSH_ONLY)
        self.assertNotIn(PUSH_OR_DISPATCH, block)

    def test_trusted_release_proof_gate_is_step_scoped_and_fail_closed(self) -> None:
        block = step_block(
            "trusted-release-proof.yml",
            "Verify permanent exact-SHA gates",
        )
        self.assert_count_gate_contract(block, PUSH_OR_DISPATCH)

    def test_release_publication_gate_is_step_scoped_and_fail_closed(self) -> None:
        block = step_block(
            "release.yml",
            "Verify permanent exact-SHA gates",
        )
        self.assert_count_gate_contract(block, PUSH_OR_DISPATCH)

    def test_release_authorization_requires_exact_native_main_push_gates(self) -> None:
        block = step_block(
            "release-authorization.yml",
            "Require native protected-main gates on prepared source",
        )
        self.assertIn("python3 tools/release_native_gates.py", block)
        self.assertIn('--head-sha "$SOURCE_SHA"', block)
        self.assertIn("--head-branch main", block)
        self.assertIn("--timeout-seconds 1800", block)
        self.assertIn("commit --event push", block)
        self.assertNotIn("release_workflow_dispatch.py", block)
        self.assertNotIn("workflow_dispatch", block)

    def test_canonical_gate_workflows_keep_nonce_run_names(self) -> None:
        for name, workflow in (
            ("ci.yml", "CI"),
            ("security.yml", "Security"),
            ("codeql.yml", "CodeQL"),
        ):
            with self.subTest(workflow=name):
                text = (WORKFLOWS / name).read_text(encoding="utf-8")
                self.assertIn("dispatch_nonce:", text)
                self.assertIn(
                    f"run-name: '${{{{ github.workflow }}}} :: "
                    f"${{{{ inputs.dispatch_nonce || github.sha }}}}'",
                    text,
                )
                self.assertIn(f"name: {workflow}", text)


if __name__ == "__main__":
    unittest.main()
