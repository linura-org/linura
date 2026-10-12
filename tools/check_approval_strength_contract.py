#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import sys
import tempfile

POLICY_SOURCE = Path("crates/linura-policy/src/lib.rs")
PROTECTED_TEST = "protected_approval_strength_is_actor_invariant"


@dataclass(frozen=True)
class Mutation:
    name: str
    before: str
    after: str


MUTATIONS = (
    Mutation(
        name="system-mutation-class-changed",
        before=(
            "RiskClass::SystemMutation => PolicyDecision::RequireApproval {\n"
            "                class: ApprovalClass::InteractiveUser,"
        ),
        after=(
            "RiskClass::SystemMutation => PolicyDecision::RequireApproval {\n"
            "                class: ApprovalClass::Administrator,"
        ),
    ),
    Mutation(
        name="security-sensitive-approval-weakened",
        before=(
            "RiskClass::SecuritySensitive => PolicyDecision::RequireApproval {\n"
            "                class: ApprovalClass::Administrator,"
        ),
        after=(
            "RiskClass::SecuritySensitive => PolicyDecision::RequireApproval {\n"
            "                class: ApprovalClass::InteractiveUser,"
        ),
    ),
    Mutation(
        name="destructive-approval-weakened",
        before=(
            "RiskClass::Destructive => PolicyDecision::RequireApproval {\n"
            "                class: ApprovalClass::DestructiveAction,"
        ),
        after=(
            "RiskClass::Destructive => PolicyDecision::RequireApproval {\n"
            "                class: ApprovalClass::Administrator,"
        ),
    ),
)


def _run_contract(worktree: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("CARGO_TERM_COLOR", "never")
    return subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "linura-policy",
            "--test",
            "approval_strength",
            PROTECTED_TEST,
            "--",
            "--exact",
        ],
        cwd=worktree,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _tail(result: subprocess.CompletedProcess[str], limit: int = 4000) -> str:
    combined = f"{result.stdout}\n{result.stderr}".strip()
    return combined[-limit:]


def validate(root: Path) -> list[str]:
    root = root.resolve()
    policy_path = root / POLICY_SOURCE
    if not policy_path.is_file():
        return [f"missing production policy source: {POLICY_SOURCE}"]

    original = policy_path.read_text(encoding="utf-8")
    for mutation in MUTATIONS:
        if original.count(mutation.before) != 1:
            return [
                f"mutation anchor {mutation.name!r} is not unique in {POLICY_SOURCE}; "
                "update the mutation contract deliberately"
            ]

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="linura-approval-mutation-") as temp_dir:
        worktree = Path(temp_dir) / "worktree"
        add = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "worktree",
                "add",
                "--detach",
                str(worktree),
                "HEAD",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if add.returncode != 0:
            return [f"failed to create isolated mutation worktree: {_tail(add)}"]

        try:
            worktree_policy = worktree / POLICY_SOURCE
            baseline = _run_contract(worktree)
            if baseline.returncode != 0:
                return [
                    "approval-strength contract must pass before mutation testing; "
                    f"baseline failed:\n{_tail(baseline)}"
                ]

            for mutation in MUTATIONS:
                mutated = original.replace(mutation.before, mutation.after, 1)
                worktree_policy.write_text(mutated, encoding="utf-8")
                result = _run_contract(worktree)
                worktree_policy.write_text(original, encoding="utf-8")

                if result.returncode == 0:
                    failures.append(
                        f"approval-strength contract did not kill production mutation: {mutation.name}"
                    )
                    continue

                combined = f"{result.stdout}\n{result.stderr}"
                failure_marker = f"test {PROTECTED_TEST} ... FAILED"
                if failure_marker not in combined:
                    failures.append(
                        "approval mutation run failed for an unrelated compile/infrastructure reason "
                        f"instead of the protected test: {mutation.name}\n{_tail(result)}"
                    )
        finally:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "worktree",
                    "remove",
                    "--force",
                    str(worktree),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

    return failures


def main(argv: list[str]) -> int:
    root = (
        Path(argv[1]).resolve()
        if len(argv) > 1
        else Path(__file__).resolve().parents[1]
    )
    failures = validate(root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("approval-strength mutation contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
