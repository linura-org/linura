#!/usr/bin/env python3
from __future__ import annotations

import ast
from pathlib import Path
import re
import sys
import tomllib

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
ALLOWED_MATURITY = (
    "roadmap-scaffold",
    "foundation",
    "integrated-experimental",
    "stable",
)
ALLOWED_KINDS = {"app", "crate", "executor", "verifier", "tool", "planned-app"}
VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
RELEASE_BINARIES_COMMAND = "python3 tools/check_component_maturity.py --release-binaries"
RELEASE_PAYLOAD_VERIFY_COMMAND = (
    'python3 tools/release_verify.py "$PAYLOAD_DIR" --component-contract contracts/components.toml'
)


def version_key(value: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"invalid milestone version: {value!r}")
    return tuple(int(part) for part in match.groups())


def image_binaries(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not any(isinstance(target, ast.Name) and target.id == "BINARIES" for target in targets):
                continue
            value = ast.literal_eval(node.value)
            if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
                raise ValueError("tools/image.py BINARIES must be a literal string-keyed mapping")
            return set(value)
    raise ValueError("tools/image.py does not declare a literal BINARIES mapping")


def release_binaries_from_contract(contract: dict[str, object]) -> list[str]:
    raw_components = contract.get("component", [])
    if not isinstance(raw_components, list):
        raise ValueError("components contract must contain a component list")
    binaries: list[str] = []
    for component in raw_components:
        if not isinstance(component, dict) or component.get("release_artifact") is not True:
            continue
        binary = component.get("binary")
        if not isinstance(binary, str) or not binary:
            raise ValueError("every release artifact must declare a non-empty binary")
        binaries.append(binary)
    if len(binaries) != len(set(binaries)):
        raise ValueError("release artifact binary names must be unique")
    return sorted(binaries)


def check(root: Path) -> list[str]:
    failures: list[str] = []
    contract_path = root / "contracts/components.toml"
    roadmap_path = root / "contracts/roadmap.toml"
    workspace_path = root / "Cargo.toml"
    release_workflow = root / ".github/workflows/reusable-release-build.yml"
    release_verifier = root / "tools/release_verify.py"
    image_harness = root / "tools/image.py"

    for path in (
        contract_path,
        roadmap_path,
        workspace_path,
        release_workflow,
        release_verifier,
        image_harness,
    ):
        if not path.is_file():
            failures.append(f"missing component-maturity dependency: {path.relative_to(root)}")
    if failures:
        return failures

    try:
        contract = tomllib.loads(contract_path.read_text(encoding="utf-8"))
        roadmap = tomllib.loads(roadmap_path.read_text(encoding="utf-8"))
        workspace = tomllib.loads(workspace_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"cannot parse component-maturity contracts: {error}"]

    if contract.get("schema_version") != 1:
        failures.append("contracts/components.toml schema_version must be 1")
    if contract.get("roadmap_contract") != "contracts/roadmap.toml":
        failures.append("components contract must bind the canonical roadmap contract")
    if contract.get("release_workflow") != ".github/workflows/reusable-release-build.yml":
        failures.append("components contract must bind the canonical release workflow")
    if tuple(contract.get("maturity_order", ())) != ALLOWED_MATURITY:
        failures.append("component maturity order changed without an explicit contract revision")

    raw_milestones = [item for item in roadmap.get("milestone", []) if isinstance(item, dict)]
    milestones_by_version = {
        item.get("version"): item for item in raw_milestones if isinstance(item.get("version"), str)
    }
    milestones = set(milestones_by_version)
    current_release = roadmap.get("current_release")
    next_release = roadmap.get("next_release")
    try:
        current_key = version_key(current_release)
        next_key = version_key(next_release)
    except (TypeError, ValueError) as error:
        failures.append(str(error))
        return failures
    if next_key <= current_key:
        failures.append("roadmap next_release must be newer than current_release")

    raw_components = contract.get("component", [])
    if not isinstance(raw_components, list) or not raw_components:
        failures.append("components contract must declare at least one [[component]]")
        return failures

    by_id: dict[str, dict[str, object]] = {}
    by_path: dict[str, dict[str, object]] = {}
    release_binaries: set[str] = set()
    for index, component in enumerate(raw_components):
        if not isinstance(component, dict):
            failures.append(f"component #{index + 1} must be a table")
            continue
        component_id = component.get("id")
        path = component.get("path")
        kind = component.get("kind")
        maturity = component.get("maturity")
        activation = component.get("activation_milestone")
        workspace_member = component.get("workspace_member")
        release_artifact = component.get("release_artifact")
        authority_role = component.get("authority_role")
        scope = component.get("scope")
        binary = component.get("binary")

        if not isinstance(component_id, str) or not component_id:
            failures.append(f"component #{index + 1} has invalid id")
            continue
        if component_id in by_id:
            failures.append(f"duplicate component id: {component_id}")
        by_id[component_id] = component

        if not isinstance(path, str) or not path:
            failures.append(f"{component_id}: invalid path")
            continue
        if path in by_path:
            failures.append(f"duplicate component path: {path}")
        by_path[path] = component
        if not (root / path).is_dir():
            failures.append(f"{component_id}: component path does not exist: {path}")

        if kind not in ALLOWED_KINDS:
            failures.append(f"{component_id}: unsupported kind {kind!r}")
        if maturity not in ALLOWED_MATURITY:
            failures.append(f"{component_id}: unsupported maturity {maturity!r}")
        if not isinstance(workspace_member, bool):
            failures.append(f"{component_id}: workspace_member must be boolean")
        if not isinstance(release_artifact, bool):
            failures.append(f"{component_id}: release_artifact must be boolean")
        if not isinstance(authority_role, str) or not authority_role:
            failures.append(f"{component_id}: authority_role must be explicit")
        if not isinstance(scope, str) or not scope.strip():
            failures.append(f"{component_id}: scope must be explicit")

        activation_milestone: dict[str, object] | None = None
        if not isinstance(activation, str) or activation not in milestones:
            failures.append(f"{component_id}: activation_milestone {activation!r} is not in the canonical roadmap")
            activation_key = None
        else:
            activation_milestone = milestones_by_version[activation]
            try:
                activation_key = version_key(activation)
            except ValueError as error:
                failures.append(f"{component_id}: {error}")
                activation_key = None

        if maturity == "roadmap-scaffold":
            if release_artifact is True:
                failures.append(f"{component_id}: roadmap scaffold cannot be a release artifact")
            if activation_key is not None and activation_key <= current_key:
                failures.append(f"{component_id}: roadmap scaffold activation must remain in a future milestone")

        if maturity == "integrated-experimental" and activation_key is not None and activation_key > next_key:
            failures.append(
                f"{component_id}: integrated component activation {activation} is later than candidate {next_release}"
            )

        if maturity == "stable":
            if activation_key is not None and activation_key > next_key:
                failures.append(
                    f"{component_id}: stable component activation {activation} is later than candidate {next_release}"
                )
            if activation_milestone is not None and activation_milestone.get("claim_class") != "Stable":
                failures.append(f"{component_id}: stable maturity requires a Stable activation milestone")
            if activation_milestone is not None:
                for evidence_field in ("release_contract", "qualification"):
                    evidence = activation_milestone.get(evidence_field)
                    if not isinstance(evidence, str) or not evidence:
                        failures.append(
                            f"{component_id}: stable maturity requires activation milestone {evidence_field} evidence"
                        )
                    elif not (root / evidence).is_file():
                        failures.append(
                            f"{component_id}: stable maturity evidence does not exist: {evidence}"
                        )
            if activation_key is not None and activation_key <= current_key:
                product_stability = str(roadmap.get("product_stability", "")).lower()
                if product_stability != "stable":
                    failures.append(
                        f"{component_id}: released stable maturity requires roadmap product_stability = 'stable'"
                    )

        if release_artifact is True:
            if maturity not in {"integrated-experimental", "stable"}:
                failures.append(f"{component_id}: release artifact must be integrated or stable")
            if activation_key is not None and activation_key > next_key:
                failures.append(
                    f"{component_id}: future component for {activation} cannot ship in candidate {next_release}"
                )
            if not isinstance(binary, str) or not binary:
                failures.append(f"{component_id}: release artifact must declare its binary name")
            elif binary in release_binaries:
                failures.append(f"duplicate release binary declaration: {binary}")
            else:
                release_binaries.add(binary)
        elif binary is not None:
            failures.append(f"{component_id}: non-release component must not declare a binary")

        if authority_role == "privileged-executor" and kind != "executor":
            failures.append(f"{component_id}: privileged-executor role is reserved for executor components")
        if authority_role == "privileged-executor" and release_artifact is not True:
            failures.append(f"{component_id}: active privileged executor must be an explicit release artifact")
        if authority_role == "proposal-only" and release_artifact is True:
            failures.append(f"{component_id}: proposal-only component cannot be a release artifact")
        if authority_role == "authority-runtime" and (kind != "app" or release_artifact is not True):
            failures.append(f"{component_id}: authority runtime must be an explicit released app boundary")

    declared_workspace = {path for path, item in by_path.items() if item.get("workspace_member") is True}
    actual_workspace = set(workspace.get("workspace", {}).get("members", []))
    missing = sorted(actual_workspace - declared_workspace)
    extra = sorted(declared_workspace - actual_workspace)
    if missing:
        failures.append(f"workspace members missing component maturity ownership: {missing}")
    if extra:
        failures.append(f"component contract claims non-members as workspace members: {extra}")

    planned_app_dirs = {
        path.relative_to(root).as_posix()
        for path in (root / "apps").iterdir()
        if path.is_dir() and (path / "README.md").is_file() and path.relative_to(root).as_posix() not in actual_workspace
    }
    declared_planned = {path for path, item in by_path.items() if item.get("kind") == "planned-app"}
    if planned_app_dirs != declared_planned:
        failures.append(
            "planned app maturity ownership mismatch: "
            f"expected {sorted(planned_app_dirs)}, declared {sorted(declared_planned)}"
        )

    release_text = release_workflow.read_text(encoding="utf-8")
    if release_text.count(RELEASE_BINARIES_COMMAND) < 2:
        failures.append(
            "release workflow must derive both assembly and reproduction binary sets from contracts/components.toml"
        )
    if RELEASE_PAYLOAD_VERIFY_COMMAND not in release_text:
        failures.append(
            "release workflow must verify the complete payload against contracts/components.toml"
        )

    try:
        staged_image_binaries = image_binaries(image_harness)
    except (OSError, SyntaxError, ValueError) as error:
        failures.append(f"cannot inspect image binary contract: {error}")
    else:
        if staged_image_binaries != release_binaries:
            failures.append(
                "development image binary set disagrees with component maturity contract: "
                f"image={sorted(staged_image_binaries)}, declared={sorted(release_binaries)}"
            )

    return failures


def print_release_binaries(root: Path) -> int:
    try:
        contract = tomllib.loads((root / "contracts/components.toml").read_text(encoding="utf-8"))
        binaries = release_binaries_from_contract(contract)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
        print(f"cannot derive release binaries: {error}", file=sys.stderr)
        return 2
    for binary in binaries:
        print(binary)
    return 0


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--release-binaries":
        if len(sys.argv) > 3:
            print("usage: check_component_maturity.py --release-binaries [root]", file=sys.stderr)
            return 2
        root = Path(sys.argv[2]).resolve() if len(sys.argv) == 3 else DEFAULT_ROOT
        return print_release_binaries(root)

    if len(sys.argv) > 2:
        print("usage: check_component_maturity.py [root]", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_ROOT
    failures = check(root)
    if failures:
        for failure in failures:
            print(f"component maturity contract failed: {failure}", file=sys.stderr)
        return 1
    print("component maturity contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
