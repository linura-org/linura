#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import json
import re
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "README.md", "SECURITY.md", "AGENTS.md", "CONTRIBUTING.md", "Cargo.toml", "rust-toolchain.toml",
    "docs/product-vision.md", "docs/vision-coverage.md", "docs/architecture.md", "docs/naming.md", "docs/sdk.md", "docs/intent-model.md",
    "docs/system-graph.md", "docs/capability-composition.md", "docs/semantic-provenance.md", "docs/reusable-setups.md",
    "docs/agent-architecture.md", "docs/provider-model.md", "docs/state-model.md", "docs/terminology.md",
    "docs/first-boot.md", "docs/machine-profiles.md", "docs/workflow-model.md",
    "docs/derived-surfaces.md", "docs/bootstrap-recovery.md", "docs/security-model.md", "docs/threat-model.md",
    "docs/development-plan.md", "docs/development-infrastructure.md", "docs/installer-bootstrap.md",
    "docs/migrations.md", "docs/managed-configuration.md", "docs/hardware-validation.md", "docs/vm-acceptance.md",
    "docs/visual-testing.md", "docs/application-supervision.md", "docs/lifecycle-workflows.md",
    "docs/release-engineering.md", "docs/api-versioning.md", "docs/omarchy-development-lessons.md",
    "docs/roadmap.md", "docs/system-domains.md", "docs/adr/README.md", "docs/adr/0017-bounded-probes-context-query.md",
    "tools/check_adrs.py", "tests/tooling/test_adrs.py",
    "contracts/stability.toml", "tools/check_contract_stability.py", "tests/tooling/test_contract_stability.py",
    "contracts/roadmap.toml", "tools/check_roadmap.py", "tests/tooling/test_roadmap.py",
    "contracts/layering.toml", "tools/check_layering.py", "tests/tooling/test_layering.py",
    "contracts/components.toml", "tools/check_component_maturity.py", "tests/tooling/test_component_maturity.py",
    "profiles/arch-hyprland-v1.toml",
    "crates/linura-intent/Cargo.toml", "crates/linura-graph/Cargo.toml", "crates/linura-capability-sdk/Cargo.toml",
    "crates/linura-planner/Cargo.toml", "crates/linura-provenance/Cargo.toml", "crates/linura-agent-runtime/Cargo.toml",
    "crates/linura-control/Cargo.toml", "crates/linura-sdk/Cargo.toml",
    "crates/linura-bootstrap/Cargo.toml", "crates/linura-migrations/Cargo.toml", "crates/linura-update/Cargo.toml",
    "crates/linura-config/Cargo.toml", "crates/linura-hardware/Cargo.toml", "crates/linura-testkit/Cargo.toml",
    "crates/linura-lifecycle/Cargo.toml", "apps/linura-update-guard/Cargo.toml", "tools/xtask/Cargo.toml",
    "apps/linura-firstboot/Cargo.toml", "apps/linura-control-center/README.md", "apps/linura-agent-ui/README.md", "apps/linura-shell/README.md",
    "interfaces/dbus/org.linura.Control1.xml", "interfaces/dbus/org.linura.Authority1.xml", ".cargo/config.toml",
    "scripts/validate_assets.py", "tools/acceptance.py", "tools/vm.py", "tools/image.py", "tools/visual.py",
    "hardware/support-matrix.json", "packaging/arch/archiso/profiledef.sh", "packaging/arch/hooks/95-linura-update-guard.hook",
    "schemas/intent.v1.schema.json", "schemas/intent-proposal.v1.schema.json", "schemas/setup.v1.schema.json", "schemas/portable-profile.v1.schema.json",
    "schemas/desired-state.v1.schema.json", "schemas/system-graph.v1.schema.json", "schemas/capability-blueprint.v1.schema.json",
    "schemas/bootstrap.v1.schema.json", "schemas/migration.v1.schema.json", "schemas/update-plan.v1.schema.json",
    "schemas/managed-resource.v1.schema.json", "schemas/hardware-fixture.v1.schema.json", "schemas/acceptance-scenario.v1.schema.json",
    "schemas/visual-baseline.v1.schema.json", "schemas/lifecycle-workflow.v1.schema.json", "schemas/app-supervision.v1.schema.json",
]

FORBIDDEN_SNIPPETS = ["sudo bash -c", "chmod 777"]
LEGACY_BRANDS = ["sys" + "plane", "luna" + "rchy"]
LEGACY_COMPONENTS = ["linura-runtime", "linura_runtime", "apps/control-center", "apps/agent-ui", "apps/shell"]
TEXT_SUFFIXES = {".md", ".rs", ".toml", ".py", ".yml", ".yaml", ".xml", ".json", ".service", ".policy", ".hook", ".sh", ".conf"}
GENERATED_DIRS = {
    ".cache",
    ".direnv",
    ".git",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "target",
    "venv",
}


def repository_files() -> list[Path]:
    """Return repository-owned files, excluding generated build/cache content.

    A Git checkout provides the strongest definition of repository ownership:
    tracked files. Source archives may not contain ``.git``, so they fall back
    to a filesystem walk with a conservative generated-directory exclusion.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            check=False,
            capture_output=True,
        )
    except OSError:
        result = None

    if result is not None and result.returncode == 0:
        return [
            ROOT / entry.decode("utf-8")
            for entry in result.stdout.split(b"\0")
            if entry
        ]

    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and not any(part in GENERATED_DIRS for part in path.relative_to(ROOT).parts)
    ]


def main() -> int:
    failures: list[str] = []
    for rel in REQUIRED:
        if not (ROOT / rel).is_file():
            failures.append(f"missing required file: {rel}")

    owned_files = repository_files()

    for path in owned_files:
        if path == Path(__file__).resolve():
            continue
        if path.suffix not in TEXT_SUFFIXES and path.name not in {"Makefile", "Cargo.lock"}:
            continue
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(ROOT)
        if "\r\n" in text:
            failures.append(f"CRLF line endings: {rel}")
        if not text.endswith("\n"):
            failures.append(f"missing final newline: {rel}")
        lowered = text.lower()
        for legacy in LEGACY_BRANDS:
            if legacy in lowered:
                failures.append(f"legacy brand {legacy!r}: {rel}")
        for legacy in LEGACY_COMPONENTS:
            if legacy in text:
                failures.append(f"legacy component {legacy!r}: {rel}")
        for snippet in FORBIDDEN_SNIPPETS:
            if snippet in text:
                failures.append(f"forbidden snippet {snippet!r}: {rel}")

        try:
            if path.suffix == ".toml":
                tomllib.loads(text)
            elif path.suffix == ".json":
                json.loads(text)
            elif path.suffix == ".xml":
                ET.fromstring(text)
        except Exception as error:  # repository validation should report parser failures compactly
            failures.append(f"invalid structured file {rel}: {error}")

    # Validate workspace member and local dependency paths without requiring Cargo in the bootstrap environment.
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    for member in workspace.get("workspace", {}).get("members", []):
        manifest = ROOT / member / "Cargo.toml"
        if not manifest.is_file():
            failures.append(f"workspace member missing Cargo.toml: {member}")
        elif not (ROOT / member).is_dir():
            failures.append(f"workspace member missing directory: {member}")

    manifests = [path for path in owned_files if path.name == "Cargo.toml"]
    for manifest in manifests:
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, spec in data.get(section, {}).items():
                if isinstance(spec, dict) and "path" in spec:
                    target = (manifest.parent / spec["path"] / "Cargo.toml").resolve()
                    if not target.is_file():
                        failures.append(f"broken local dependency {name}: {manifest.relative_to(ROOT)} -> {spec['path']}")

    # Lock the public client boundary: ordinary clients use linura-sdk, while the SDK
    # must never expose authority/provider/executor internals.
    def local_dependency_names(manifest_path: Path) -> set[str]:
        data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        names: set[str] = set()
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, spec in data.get(section, {}).items():
                if isinstance(spec, dict) and "path" in spec:
                    names.add(name)
        return names

    cli_deps = local_dependency_names(ROOT / "apps/linuractl/Cargo.toml")
    if cli_deps != {"linura-sdk"}:
        failures.append(f"linuractl must depend only on linura-sdk among local crates, found: {sorted(cli_deps)}")

    sdk_deps = local_dependency_names(ROOT / "crates/linura-sdk/Cargo.toml")
    forbidden_sdk_deps = {"linura-control", "linura-provider-sdk", "linura-policy", "linura-agent-runtime"}
    leaked = sorted(sdk_deps & forbidden_sdk_deps)
    if leaked:
        failures.append(f"linura-sdk exposes internal authority/provider/agent dependencies: {leaked}")

    # Cargo.lock must include every workspace package so --locked candidate builds cannot fail
    # merely because the workspace gained a new local crate.
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    locked_names = {package.get("name") for package in lock.get("package", [])}
    workspace_names: set[str] = set()
    for member in workspace.get("workspace", {}).get("members", []):
        manifest_data = tomllib.loads((ROOT / member / "Cargo.toml").read_text(encoding="utf-8"))
        name = manifest_data.get("package", {}).get("name")
        if isinstance(name, str):
            workspace_names.add(name)
    missing_locked = sorted(workspace_names - locked_names)
    if missing_locked:
        failures.append(f"Cargo.lock missing workspace packages: {missing_locked}")

    locked_packages = {package.get("name"): package for package in lock.get("package", []) if isinstance(package.get("name"), str)}
    for member in workspace.get("workspace", {}).get("members", []):
        manifest_path = ROOT / member / "Cargo.toml"
        manifest_data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        package_name = manifest_data.get("package", {}).get("name")
        if not isinstance(package_name, str) or package_name not in locked_packages:
            continue
        expected_local: set[str] = set()
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for dep_name, spec in manifest_data.get(section, {}).items():
                if isinstance(spec, dict) and "path" in spec:
                    expected_local.add(dep_name)
        actual_local = {str(dep).split(" ", 1)[0] for dep in locked_packages[package_name].get("dependencies", []) if str(dep).split(" ", 1)[0] in workspace_names}
        if expected_local != actual_local:
            failures.append(
                f"Cargo.lock local dependencies stale for {package_name}: expected {sorted(expected_local)}, found {sorted(actual_local)}"
            )

    # Task-specific agent guides are an intentional part of the development contract.
    skill_files = sorted((ROOT / "agents/skills").glob("*.md"))
    if len(skill_files) < 10:
        failures.append(f"expected at least 10 task-specific agent skill guides, found {len(skill_files)}")

    # GitHub Actions are supply-chain inputs: require immutable 40-hex action refs.
    uses_pattern = re.compile(r"^\s*-?\s*uses:\s*[^@\s]+@([^\s#]+)", re.MULTILINE)
    sha_pattern = re.compile(r"^[0-9a-f]{40}$")
    for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
        workflow_text = workflow.read_text(encoding="utf-8")
        for ref in uses_pattern.findall(workflow_text):
            if not sha_pattern.fullmatch(ref):
                failures.append(f"GitHub Action is not pinned to immutable SHA: {workflow.relative_to(ROOT)} -> {ref}")

    # Check ordinary relative Markdown links. Fragments and external links are excluded.
    link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for markdown in (path for path in owned_files if path.suffix == ".md"):
        text = markdown.read_text(encoding="utf-8")
        for target in link_pattern.findall(text):
            target = target.strip().split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            candidate = (markdown.parent / target).resolve()
            if not candidate.exists():
                failures.append(f"broken Markdown link: {markdown.relative_to(ROOT)} -> {target}")

    adr_result = subprocess.run(
        [sys.executable, str(ROOT / "tools/check_adrs.py"), str(ROOT)],
        check=False,
        capture_output=True,
        text=True,
    )
    if adr_result.returncode != 0:
        details = adr_result.stderr.strip() or adr_result.stdout.strip()
        failures.append(f"ADR governance validation failed: {details}")

    contract_result = subprocess.run(
        [sys.executable, str(ROOT / "tools/check_contract_stability.py"), "--root", str(ROOT)],
        check=False,
        capture_output=True,
        text=True,
    )
    if contract_result.returncode != 0:
        details = contract_result.stderr.strip() or contract_result.stdout.strip()
        failures.append(f"contract stability validation failed: {details}")

    roadmap_result = subprocess.run(
        [sys.executable, str(ROOT / "tools/check_roadmap.py"), str(ROOT)],
        check=False,
        capture_output=True,
        text=True,
    )
    if roadmap_result.returncode != 0:
        details = roadmap_result.stderr.strip() or roadmap_result.stdout.strip()
        failures.append(f"roadmap contract validation failed: {details}")

    layering_result = subprocess.run(
        [sys.executable, str(ROOT / "tools/check_layering.py"), str(ROOT)],
        check=False,
        capture_output=True,
        text=True,
    )
    if layering_result.returncode != 0:
        details = layering_result.stderr.strip() or layering_result.stdout.strip()
        failures.append(f"layering contract validation failed: {details}")

    maturity_result = subprocess.run(
        [sys.executable, str(ROOT / "tools/check_component_maturity.py"), str(ROOT)],
        check=False,
        capture_output=True,
        text=True,
    )
    if maturity_result.returncode != 0:
        details = maturity_result.stderr.strip() or maturity_result.stdout.strip()
        failures.append(f"component maturity validation failed: {details}")

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    print("repository checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
