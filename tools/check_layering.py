#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys
import tomllib

EXPECTED_VERSION = 1
EXPECTED_SEMANTICS = {
    "principal_term": "authenticated-authority-identity",
    "actor_term": "request-provenance",
    "canonical_observation": "linura-observation::ObservationEnvelope",
    "query_orchestration": "control-plane-owned",
    "policy_orchestration": "linura-control-only",
    "transport_role": "adapter-only",
}
DEPENDENCY_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")
DBUS_TRANSPORT_PACKAGES = {"zbus", "dbus", "dbus-tokio", "dbus-crossroads"}
EXPECTED_RULE_PACKAGES = {
    "linura-core",
    "linura-intent",
    "linura-capability-sdk",
    "linura-planner",
    "linura-observation",
    "linura-provider-sdk",
    "linura-graph",
    "linura-observation-control",
    "linura-protocol",
    "linura-policy",
    "linura-lifecycle",
    "linura-agent-runtime",
    "linura-provenance",
    "linura-transaction",
    "linura-persistence-sqlite",
    "linura-control",
    "linura-sdk",
    "linura-linux-observation",
    "linura-dbus",
    "linura-executor-systemd",
    "linura-verifier-systemd",
}
POLICY_ORCHESTRATOR = "linura-control"
POLICY_PACKAGE = "linura-policy"
TRANSACTION_PACKAGE = "linura-transaction"
TRANSACTION_CONSUMERS = {"linura-control", "linura-persistence-sqlite", "linura-authorityd"}
PERSISTENCE_PACKAGE = "linura-persistence-sqlite"
PERSISTENCE_CONSUMERS = {"linura-authorityd"}
TRANSACTION_PACKAGE = "linura-transaction"
TRANSACTION_ALLOWED_CONSUMERS = {"linura-control", "linura-persistence-sqlite", "linura-authorityd"}


def resolved_dependency_name(
    alias: object,
    spec: object,
    workspace_dependencies: dict[str, str],
) -> str:
    name = str(alias)
    if isinstance(spec, dict):
        package = spec.get("package")
        if isinstance(package, str) and package:
            return package
        if spec.get("workspace") is True:
            return workspace_dependencies.get(name, name)
    return name


def dependency_names(
    manifest: dict[str, object],
    workspace_dependencies: dict[str, str],
) -> set[str]:
    names: set[str] = set()

    def collect(container: object) -> None:
        if not isinstance(container, dict):
            return
        for section in DEPENDENCY_SECTIONS:
            dependencies = container.get(section, {})
            if not isinstance(dependencies, dict):
                continue
            for alias, spec in dependencies.items():
                names.add(resolved_dependency_name(alias, spec, workspace_dependencies))

    collect(manifest)

    targets = manifest.get("target", {})
    if isinstance(targets, dict):
        for target in targets.values():
            collect(target)

    return names


def workspace_dependency_names(workspace: dict[str, object]) -> dict[str, str]:
    workspace_table = workspace.get("workspace", {})
    if not isinstance(workspace_table, dict):
        return {}
    dependencies = workspace_table.get("dependencies", {})
    if not isinstance(dependencies, dict):
        return {}
    resolved: dict[str, str] = {}
    for alias, spec in dependencies.items():
        resolved[str(alias)] = resolved_dependency_name(alias, spec, {})
    return resolved


def load_workspace(root: Path) -> tuple[set[str], dict[str, Path], dict[str, str]]:
    workspace_path = root / "Cargo.toml"
    workspace = tomllib.loads(workspace_path.read_text(encoding="utf-8"))
    workspace_table = workspace.get("workspace", {})
    members = workspace_table.get("members", []) if isinstance(workspace_table, dict) else []
    if not isinstance(members, list):
        raise ValueError("workspace.members must be a list")

    names: set[str] = set()
    manifests: dict[str, Path] = {}
    for member in members:
        if not isinstance(member, str):
            raise ValueError("workspace member must be a string")
        manifest_path = root / member / "Cargo.toml"
        if not manifest_path.is_file():
            raise ValueError(f"workspace manifest missing: {member}/Cargo.toml")
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        package = manifest.get("package", {})
        name = package.get("name") if isinstance(package, dict) else None
        if not isinstance(name, str) or not name:
            raise ValueError(f"workspace package name missing: {member}/Cargo.toml")
        if name in manifests:
            raise ValueError(f"duplicate workspace package name: {name}")
        names.add(name)
        manifests[name] = manifest_path
    return names, manifests, workspace_dependency_names(workspace)


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    contract_path = root / "contracts/layering.toml"
    if not contract_path.is_file():
        return ["missing layering contract: contracts/layering.toml"]

    try:
        contract = tomllib.loads(contract_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return [f"invalid layering contract: {error}"]

    if contract.get("version") != EXPECTED_VERSION:
        failures.append(
            f"layering contract version must remain {EXPECTED_VERSION}, got {contract.get('version')!r}"
        )

    semantics = contract.get("semantics", {})
    if not isinstance(semantics, dict):
        failures.append("layering contract semantics must be a table")
    else:
        for key, expected in EXPECTED_SEMANTICS.items():
            actual = semantics.get(key)
            if actual != expected:
                failures.append(
                    f"layering semantic {key} must remain {expected!r}, got {actual!r}"
                )

    try:
        workspace_names, manifests, workspace_dependencies = load_workspace(root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        failures.append(f"cannot load workspace for layering validation: {error}")
        return failures

    all_dependencies: dict[str, set[str]] = {}
    for package, manifest_path in manifests.items():
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        all_dependencies[package] = dependency_names(manifest, workspace_dependencies)

    policy_consumers = {
        package for package, dependencies in all_dependencies.items() if POLICY_PACKAGE in dependencies
    }
    if policy_consumers != {POLICY_ORCHESTRATOR}:
        failures.append(
            "linura-policy must be consumed only by linura-control; found policy consumers: "
            f"{sorted(policy_consumers)}"
        )

    transaction_consumers: set[str] = set()
    persistence_consumers: set[str] = set()
    for package, manifest_path in manifests.items():
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        dependencies = dependency_names(manifest, workspace_dependencies)
        if TRANSACTION_PACKAGE in dependencies:
            transaction_consumers.add(package)
        if PERSISTENCE_PACKAGE in dependencies:
            persistence_consumers.add(package)
    if transaction_consumers != TRANSACTION_CONSUMERS:
        failures.append(
            "linura-transaction may be consumed only by Control and the SQLite adapter; found: "
            f"{sorted(transaction_consumers)}"
        )
    if persistence_consumers != PERSISTENCE_CONSUMERS:
        failures.append(
            "linura-persistence-sqlite may be consumed directly only by the trusted v0.6 authority runtime; found: "
            f"{sorted(persistence_consumers)}"
        )

    transaction_consumers = {
        package
        for package, dependencies in all_dependencies.items()
        if TRANSACTION_PACKAGE in dependencies
    }
    unexpected_transaction_consumers = sorted(
        transaction_consumers - TRANSACTION_ALLOWED_CONSUMERS
    )
    if unexpected_transaction_consumers:
        failures.append(
            "linura-transaction may be consumed only by linura-control, "
            "linura-persistence-sqlite and linura-authorityd; found unexpected consumers: "
            f"{unexpected_transaction_consumers}"
        )

    rules = contract.get("rules", [])
    if not isinstance(rules, list) or not rules:
        failures.append("layering contract must define at least one [[rules]] entry")
        return failures

    seen_packages: set[str] = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            failures.append(f"layering rule {index} must be a table")
            continue
        package = rule.get("package")
        if not isinstance(package, str) or not package:
            failures.append(f"layering rule {index} has no valid package")
            continue
        if package in seen_packages:
            failures.append(f"duplicate layering rule for package {package}")
            continue
        seen_packages.add(package)
        manifest_path = manifests.get(package)
        if manifest_path is None:
            failures.append(f"layering rule references unknown workspace package {package}")
            continue

        dependencies = all_dependencies[package]
        local_dependencies = dependencies & workspace_names
        external_dependencies = dependencies - workspace_names

        def string_list(field: str) -> list[str]:
            value = rule.get(field, [])
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                failures.append(f"layering rule {package} field {field} must be a string list")
                return []
            return value

        forbidden_local = string_list("forbid_local")
        forbidden_prefixes = string_list("forbid_local_prefixes")
        forbidden_external = set(string_list("forbid_external"))
        if "zbus" in forbidden_external:
            forbidden_external.update(DBUS_TRANSPORT_PACKAGES)

        leaked_local = sorted(local_dependencies & set(forbidden_local))
        if leaked_local:
            failures.append(
                f"{package} violates inward dependency boundary via local dependencies: {leaked_local}"
            )

        leaked_prefixed = sorted(
            dependency
            for dependency in local_dependencies
            if any(dependency.startswith(prefix) for prefix in forbidden_prefixes)
        )
        if leaked_prefixed:
            failures.append(
                f"{package} violates concrete executor/provider boundary via local dependencies: {leaked_prefixed}"
            )

        leaked_external = sorted(external_dependencies & forbidden_external)
        if leaked_external:
            failures.append(
                f"{package} violates transport-neutral boundary via external dependencies: {leaked_external}"
            )

    missing_rules = sorted(EXPECTED_RULE_PACKAGES - seen_packages)
    unexpected_rules = sorted(seen_packages - EXPECTED_RULE_PACKAGES)
    if missing_rules:
        failures.append(f"layering contract missing required package rules: {missing_rules}")
    if unexpected_rules:
        failures.append(
            "layering contract package set changed; explicitly update checker expectations for: "
            f"{unexpected_rules}"
        )

    markers = contract.get("markers", [])
    if not isinstance(markers, list):
        failures.append("layering contract markers must be a list")
        markers = []
    for index, marker in enumerate(markers):
        if not isinstance(marker, dict):
            failures.append(f"layering marker {index} must be a table")
            continue
        path = marker.get("path")
        required = marker.get("contains")
        if not isinstance(path, str) or not isinstance(required, str) or not path or not required:
            failures.append(f"layering marker {index} requires non-empty path and contains strings")
            continue
        target = root / path
        if not target.is_file():
            failures.append(f"layering marker file missing: {path}")
            continue
        text = target.read_text(encoding="utf-8")
        if required not in text:
            failures.append(f"layering marker missing from {path}: {required}")

    return failures


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    failures = validate(root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("layering contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
