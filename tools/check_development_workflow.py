#!/usr/bin/env python3
"""Check development-workflow guidance for structural drift.

This checks checked-in policy and validation wiring, not whether a contributor
actually performed a human review or whether external qualification passed.
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

STAGES = (
    "implement",
    "→ internal architecture/code/adversarial review",
    "→ fix every valid finding",
    "→ compact to one coherent clean commit",
    "→ run the full inherited + milestone gate set",
    "→ request Codex review",
    "→ fix only genuinely new valid findings",
    "→ merge only when required checks are green",
)

REQUIRED_SCOPED_AGENTS = (
    "apps/linura-shell/AGENTS.md",
    "bindings/python/AGENTS.md",
    "crates/AGENTS.md",
    "docs/AGENTS.md",
    "executors/AGENTS.md",
    "qualification/AGENTS.md",
    "scripts/AGENTS.md",
    "tools/AGENTS.md",
    "verifiers/AGENTS.md",
)

REQUIRED = {
    "AGENTS.md": (
        "## Change procedure",
        "regression-impact review",
        "## Codex repository workflow",
        "internal architecture/code/adversarial review",
        "internal-review record",
        "compact to one clean commit",
        "merge only when green",
    ),
    "CONTRIBUTING.md": (
        "## Regression-impact and internal review",
        "regression-impact review",
        "## Development quality gate",
        "## Pull requests",
        "Regression impact",
        "Internal review",
        "exact-head",
    ),
    "docs/development-infrastructure.md": (
        "## Pull-request qualification sequence",
        "regression-impact review",
        "internal-review record",
        "exact-source qualification",
    ),
    "docs/codex-development.md": (
        "## Review and handoff",
        "regression-impact review",
        "internal-review record",
        "merge only when green",
    ),
    ".github/PULL_REQUEST_TEMPLATE.md": (
        "## Regression impact",
        "## Internal review",
        "## Applicable qualification",
        "## Verification",
        "- [ ] Reviewed existing consumers, tests and regression assumptions before changing behavior",
        "- [ ] Architecture, ownership and public-contract review complete (or not applicable with reason)",
        "- [ ] Code, security/trust-boundary and adversarial review complete (or not applicable with reason)",
        "- [ ] All valid internal findings resolved; no tests or gates weakened to clear failures",
        "- [ ] Change compacted into one clean commit after internal review",
        "- [ ] All applicable checks passed on the final exact head; no stale-source pass substituted",
        "- [ ] Final Codex review requested only after internal review and green gates; new findings addressed and revalidated",
    ),
    "scripts/check_repository.py": (),
}

GENERATED_DISCOVERY_PARTS = frozenset({
    ".git", ".mypy_cache", ".nox", ".pytest_cache", ".ruff_cache", ".tox",
    ".venv", "__pycache__", "node_modules", "target", "venv",
})

CANONICAL_REPOSITORY_HOOK = """development_result = subprocess.run(
    [sys.executable, str(ROOT / "tools/check_development_workflow.py"), str(ROOT)],
    check=False, capture_output=True, text=True,
)
if development_result.returncode != 0:
    details = development_result.stderr.strip() or development_result.stdout.strip()
    failures.append(f"development workflow alignment failed: {details}")
"""

CANONICAL_REPOSITORY_EPILOGUE = """if failures:
    for failure in failures:
        print(f"ERROR: {failure}", file=sys.stderr)
    return 1

print("repository checks passed")
return 0
"""

CANONICAL_REPOSITORY_ENTRY = """if __name__ == "__main__":
    raise SystemExit(main())
"""


def discover_scoped_agents(root: Path) -> tuple[str, ...]:
    """Discover repository-owned scoped AGENTS.md files, excluding the root."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=False,
            capture_output=True,
        )
    except OSError:
        result = None

    if result is not None and result.returncode == 0:
        candidates = {
            entry.decode("utf-8")
            for entry in result.stdout.split(b"\0")
            if entry
        }
        return tuple(sorted(
            path for path in candidates
            if path != "AGENTS.md" and Path(path).name == "AGENTS.md"
        ))

    discovered: list[str] = []
    for candidate in root.rglob("AGENTS.md"):
        relative = candidate.relative_to(root)
        if relative.as_posix() == "AGENTS.md":
            continue
        if any(part in GENERATED_DISCOVERY_PARTS for part in relative.parts):
            continue
        discovered.append(relative.as_posix())
    return tuple(sorted(discovered))


def _call_exits_process(expression: ast.expr) -> bool:
    if not isinstance(expression, ast.Call):
        return False
    function = expression.func
    if isinstance(function, ast.Name):
        return function.id in {"exit", "quit"}
    return (
        isinstance(function, ast.Attribute)
        and isinstance(function.value, ast.Name)
        and function.value.id == "sys"
        and function.attr == "exit"
    )


def _statement_contains_exit(statement: ast.stmt) -> bool:
    """Detect exits in executable control flow without entering nested scopes."""

    class ExitVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.found = False

        def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
            self.found = True

        def visit_Raise(self, node: ast.Raise) -> None:  # noqa: N802
            self.found = True

        def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
            if _call_exits_process(node):
                self.found = True
                return
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
            return

    visitor = ExitVisitor()
    visitor.visit(statement)
    return visitor.found


def _expression_references_failures(expression: ast.AST | None) -> bool:
    if expression is None:
        return False
    return any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id == "failures"
        for node in ast.walk(expression)
    )


def _target_references_failures(target: ast.expr) -> bool:
    if isinstance(target, ast.Name):
        return target.id == "failures"
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_target_references_failures(item) for item in target.elts)
    if isinstance(target, (ast.Attribute, ast.Subscript)):
        return (
            isinstance(target.value, ast.Name)
            and target.value.id == "failures"
        )
    return False


def _statement_clobbers_failures(statement: ast.stmt) -> bool:
    for node in ast.walk(statement):
        if isinstance(node, ast.Assign):
            if any(_target_references_failures(target) for target in node.targets):
                return True
            if _expression_references_failures(node.value):
                return True
        elif isinstance(node, ast.AnnAssign):
            if _target_references_failures(node.target):
                return True
            if _expression_references_failures(node.value):
                return True
        elif isinstance(node, ast.AugAssign):
            if _target_references_failures(node.target):
                return True
            if _expression_references_failures(node.value):
                return True
        elif isinstance(node, ast.NamedExpr):
            if _target_references_failures(node.target):
                return True
            if _expression_references_failures(node.value):
                return True
        elif isinstance(node, ast.Delete):
            if any(_target_references_failures(target) for target in node.targets):
                return True
        elif isinstance(node, ast.Call):
            function = node.func
            if (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id == "failures"
                and function.attr != "append"
            ):
                return True
            if any(
                _expression_references_failures(argument)
                for argument in (*node.args, *(keyword.value for keyword in node.keywords))
            ):
                return True
    return False


def repository_checker_hook_connected(source: str) -> bool:
    """Require reachable execution and fail-closed propagation to main()'s exit."""
    try:
        tree = ast.parse(source)
        expected_hook = ast.parse(CANONICAL_REPOSITORY_HOOK).body
        expected_epilogue = ast.parse(CANONICAL_REPOSITORY_EPILOGUE).body
        expected_entry = ast.parse(CANONICAL_REPOSITORY_ENTRY).body
    except SyntaxError:
        return False
    mains = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "main"
    ]
    if (
        len(mains) != 1
        or len(expected_hook) != 2
        or len(expected_epilogue) != 3
        or len(expected_entry) != 1
    ):
        return False
    if not tree.body:
        return False
    if (
        ast.dump(tree.body[-1], include_attributes=False)
        != ast.dump(expected_entry[0], include_attributes=False)
    ):
        return False

    body = mains[0].body
    if len(body) < len(expected_hook) + len(expected_epilogue):
        return False

    epilogue_index = len(body) - len(expected_epilogue)
    actual_epilogue = tuple(
        ast.dump(node, include_attributes=False)
        for node in body[epilogue_index:]
    )
    expected_epilogue_shapes = tuple(
        ast.dump(node, include_attributes=False)
        for node in expected_epilogue
    )
    if actual_epilogue != expected_epilogue_shapes:
        return False

    expected_hook_shapes = tuple(
        ast.dump(node, include_attributes=False)
        for node in expected_hook
    )
    for index in range(epilogue_index - 1):
        actual_hook_shapes = (
            ast.dump(body[index], include_attributes=False),
            ast.dump(body[index + 1], include_attributes=False),
        )
        if actual_hook_shapes != expected_hook_shapes:
            continue
        if any(_statement_contains_exit(statement) for statement in body[:index]):
            continue
        remainder = body[index + len(expected_hook):epilogue_index]
        if any(_statement_contains_exit(statement) for statement in remainder):
            continue
        if any(_statement_clobbers_failures(statement) for statement in remainder):
            continue
        return True
    return False


def check(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    contents: dict[str, str] = {}
    for path, fragments in REQUIRED.items():
        try:
            contents[path] = (root / path).read_text(encoding="utf-8")
        except OSError:
            errors.append("missing development-workflow file: " + path)
            continue
        for fragment in fragments:
            if fragment not in contents[path]:
                errors.append(path + ": missing development-workflow contract: " +
                              fragment)

    scoped_agents = set(discover_scoped_agents(root))
    for path in REQUIRED_SCOPED_AGENTS:
        if path not in scoped_agents:
            errors.append("missing scoped agent instructions: " + path)
    for path in sorted(scoped_agents):
        try:
            text = (root / path).read_text(encoding="utf-8")
        except OSError:
            errors.append("missing scoped agent instructions: " + path)
            continue
        if "Root `AGENTS.md` remains applicable." not in text:
            errors.append(path + ": must explicitly inherit root AGENTS.md")

    repository_check = contents.get("scripts/check_repository.py", "")
    if repository_check and not repository_checker_hook_connected(repository_check):
        errors.append(
            "scripts/check_repository.py: canonical development-workflow checker "
            "invocation disconnected"
        )

    canonical = contents.get("docs/development-infrastructure.md", "")
    section = canonical.split("## Pull-request qualification sequence\n", 1)
    if len(section) != 2:
        errors.append("development infrastructure: missing canonical review sequence")
    else:
        body = section[1].split("\n## ", 1)[0]
        blocks = body.split("```text\n", 1)
        if len(blocks) != 2 or "\n```" not in blocks[1]:
            errors.append("development infrastructure: missing canonical review stages")
        else:
            stages = tuple(blocks[1].split("\n```", 1)[0].splitlines())
            if stages != STAGES:
                errors.append("development infrastructure: review stage order drift")

    root_agent = contents.get("AGENTS.md", "")
    compact = re.sub(r"\s+", " ", root_agent)
    if ("Implement → internal architecture/code/adversarial review → fix findings "
            "→ compact to one clean commit → full gates → Codex review → fix genuinely "
            "new findings → merge only when green." not in compact):
        errors.append("AGENTS.md: root review-stage order drift")
    codex = re.sub(r"\s+", " ", contents.get("docs/codex-development.md", ""))
    if ("Implement → internal architecture/code/adversarial review → fix findings "
            "→ compact to one clean commit → run full gates → request Codex review "
            "→ fix genuinely new findings → merge only when green." not in codex):
        errors.append("codex development: review-stage order drift")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    args = parser.parse_args()
    failures = check(args.root)
    for failure in failures:
        print("ERROR: " + failure, file=sys.stderr)
    if failures:
        return 1
    print("development workflow alignment passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
