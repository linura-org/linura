#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Callable

ALLOWED = {"experimental", "preview", "stable"}
KINDS = {"dbus-interface", "json-schema", "cli", "rust-sdk", "python-sdk"}
REGISTRY_PATH = "contracts/stability.toml"


def _safe_contract_path(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if "\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() == ".":
        return None
    return path.as_posix()


def _load_registry_text(text: str, source: str, failures: list[str]) -> dict[str, object] | None:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError) as error:
        failures.append(f"invalid contract registry {source}: {error}")
        return None
    if not isinstance(data, dict):
        failures.append(f"invalid contract registry {source}: root must be a table")
        return None
    return data


def _entry_map(registry: dict[str, object]) -> dict[str, dict[str, object]]:
    entries = registry.get("contract", [])
    if not isinstance(entries, list):
        return {}
    return {
        str(entry["id"]): entry
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    }


def _run_git(root: Path, *args: str) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None


def _resolve_commit(root: Path, ref: str) -> str | None:
    result = _run_git(root, "rev-parse", "--verify", f"{ref}^{{commit}}")
    if result is None or result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def _merge_base(root: Path, left: str, right: str) -> str | None:
    result = _run_git(root, "merge-base", left, right)
    if result is None or result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def _origin_default_branch(root: Path) -> str | None:
    result = _run_git(root, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD")
    if result is None or result.returncode != 0:
        return None
    value = result.stdout.strip()
    prefix = "refs/remotes/"
    return value[len(prefix) :] if value.startswith(prefix) else value or None


def discover_baseline_commit(root: Path, explicit_ref: str | None = None) -> tuple[str | None, str | None]:
    """Return the historical comparison commit and an error for explicit invalid refs.

    For feature branches we compare against the merge base of the protected/default branch.
    For main itself we compare against HEAD^ so a squash-merged compatibility regression cannot
    validate against its own new tree.
    """
    head = _resolve_commit(root, "HEAD")
    if head is None:
        return None, None

    configured = explicit_ref or os.environ.get("LINURA_CONTRACT_BASELINE_REF")
    if configured:
        target = _resolve_commit(root, configured)
        if target is None:
            return None, f"historical baseline ref could not be resolved: {configured}"
        base = _merge_base(root, head, target)
        return (base or target), None

    candidates: list[str] = []
    github_base = os.environ.get("GITHUB_BASE_REF", "").strip()
    if github_base:
        candidates.extend((f"origin/{github_base}", github_base))
    origin_default = _origin_default_branch(root)
    if origin_default:
        candidates.append(origin_default)
    candidates.extend(("origin/main", "main"))

    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        target = _resolve_commit(root, candidate)
        if target is None:
            continue
        base = _merge_base(root, head, target)
        if base is not None and base != head:
            return base, None

    parent = _resolve_commit(root, "HEAD^")
    return parent, None


def _git_reader(root: Path, commit: str) -> Callable[[str], str | None]:
    def read(path: str) -> str | None:
        result = _run_git(root, "show", f"{commit}:{path}")
        if result is None or result.returncode != 0:
            return None
        return result.stdout

    return read


def _root_reader(root: Path) -> Callable[[str], str | None]:
    def read(path: str) -> str | None:
        safe = _safe_contract_path(path)
        if safe is None:
            return None
        candidate = root / safe
        if not candidate.is_file():
            return None
        return candidate.read_text(encoding="utf-8")

    return read


def _annotations(element: ET.Element) -> tuple[tuple[str, str], ...] | None:
    values: dict[str, str] = {}
    for annotation in element.findall("annotation"):
        name = annotation.attrib.get("name")
        value = annotation.attrib.get("value")
        if name is None or value is None or name in values:
            return None
        values[name] = value
    return tuple(sorted(values.items()))


def _dbus_members(interface: ET.Element, tag: str) -> dict[str, object] | None:
    members: dict[str, object] = {}
    for element in interface.findall(tag):
        name = element.attrib.get("name")
        if not name or name in members:
            return None
        annotations = _annotations(element)
        if annotations is None:
            return None
        if tag in {"method", "signal"}:
            args = tuple(
                (
                    arg.attrib.get("name", ""),
                    arg.attrib.get("type", ""),
                    arg.attrib.get("direction", ""),
                )
                for arg in element.findall("arg")
            )
            members[name] = (args, annotations)
        elif tag == "property":
            members[name] = (
                element.attrib.get("type", ""),
                element.attrib.get("access", ""),
                annotations,
            )
    return members


def _dbus_compatible(baseline: str, current: str) -> bool:
    try:
        old_root = ET.fromstring(baseline)
        new_root = ET.fromstring(current)
    except ET.ParseError:
        return False
    old_interface = old_root.find("interface")
    new_interface = new_root.find("interface")
    if old_interface is None or new_interface is None:
        return False
    if old_interface.attrib.get("name") != new_interface.attrib.get("name"):
        return False
    old_annotations = _annotations(old_interface)
    new_annotations = _annotations(new_interface)
    if old_annotations is None or new_annotations is None:
        return False
    if not set(old_annotations).issubset(set(new_annotations)):
        return False
    for tag in ("method", "signal", "property"):
        old_members = _dbus_members(old_interface, tag)
        new_members = _dbus_members(new_interface, tag)
        if old_members is None or new_members is None:
            return False
        for name, shape in old_members.items():
            if new_members.get(name) != shape:
                return False
    return True


def _artifact_compatible(kind: object, baseline: str, current: str) -> bool:
    if kind == "dbus-interface":
        return _dbus_compatible(baseline, current)
    if kind == "json-schema":
        try:
            return json.loads(baseline) == json.loads(current)
        except json.JSONDecodeError:
            return False
    # CLI, Rust SDK and Python SDK stability are intentionally conservative until a typed
    # semantic compatibility checker is introduced: a Stable same-generation source contract is immutable.
    return baseline == current


def historical_failures(
    root: Path,
    current_registry: dict[str, object],
    *,
    baseline_root: Path | None = None,
    baseline_ref: str | None = None,
) -> list[str]:
    failures: list[str] = []
    current_by_id = _entry_map(current_registry)

    if baseline_root is not None:
        reader = _root_reader(baseline_root.resolve())
        baseline_source = str(baseline_root.resolve())
    else:
        commit, error = discover_baseline_commit(root, baseline_ref)
        if error:
            return [error]
        if commit is None:
            if any(entry.get("stability") == "stable" for entry in current_by_id.values()):
                return [
                    "Stable contracts require historical comparison, but no Git baseline is available; "
                    "provide --baseline-ref or --baseline-root"
                ]
            return []
        reader = _git_reader(root, commit)
        baseline_source = commit

    baseline_text = reader(REGISTRY_PATH)
    if baseline_text is None:
        if any(entry.get("stability") == "stable" for entry in current_by_id.values()):
            failures.append(
                f"Stable contracts require a prior {REGISTRY_PATH}, but baseline {baseline_source} has none"
            )
        return failures
    baseline_registry = _load_registry_text(baseline_text, baseline_source, failures)
    if baseline_registry is None:
        return failures

    for contract_id, old in _entry_map(baseline_registry).items():
        old_stability = old.get("stability")
        current = current_by_id.get(contract_id)
        if current is not None and old_stability == "stable":
            current_stability = current.get("stability")
            if current_stability != "stable":
                failures.append(
                    f"contract stability downgrade is forbidden: {contract_id}: "
                    f"stable -> {current_stability}"
                )

        if old_stability != "stable":
            continue
        if current is None:
            failures.append(f"Stable contract removed from registry: {contract_id}")
            continue
        if current.get("stability") != "stable":
            continue  # the monotonicity failure above is the actionable error

        for field in ("kind", "path", "version"):
            if current.get(field) != old.get(field):
                failures.append(
                    f"Stable contract identity changed in place: {contract_id}: {field} "
                    f"{old.get(field)!r} -> {current.get(field)!r}; publish a new major generation"
                )
        if any(current.get(field) != old.get(field) for field in ("kind", "path", "version")):
            continue

        path = _safe_contract_path(current.get("path"))
        if path is None:
            continue
        baseline_artifact = reader(path)
        current_path = root / path
        if baseline_artifact is None:
            failures.append(f"Stable baseline artifact is missing for {contract_id}: {path}")
            continue
        if not current_path.is_file():
            continue  # current-tree validation reports this separately
        current_artifact = current_path.read_text(encoding="utf-8")
        if not _artifact_compatible(current.get("kind"), baseline_artifact, current_artifact):
            failures.append(
                f"Stable {current.get('kind')} contract changed incompatibly within generation "
                f"{current.get('version')}: {contract_id} ({path})"
            )
    return failures


def validate(
    root: Path,
    *,
    baseline_root: Path | None = None,
    baseline_ref: str | None = None,
) -> list[str]:
    failures: list[str] = []
    registry_path = root / REGISTRY_PATH
    if not registry_path.is_file():
        return [f"missing {REGISTRY_PATH}"]
    registry = _load_registry_text(
        registry_path.read_text(encoding="utf-8"), str(registry_path), failures
    )
    if registry is None:
        return failures
    if registry.get("schema_version") != 1:
        failures.append("contract registry schema_version must equal 1")
    if registry.get("product_stability") not in ALLOWED:
        failures.append("invalid product_stability")
    if registry.get("default_contract_stability") != "experimental":
        failures.append("default contract stability must remain experimental; promotion is explicit")
    if registry.get("policy_document") != "docs/api-versioning.md":
        failures.append("policy_document must be docs/api-versioning.md")

    entries = registry.get("contract", [])
    if not isinstance(entries, list):
        return failures + ["registry contract entries must be [[contract]] tables"]

    ids: set[str] = set()
    paths: set[str] = set()
    by_path: dict[str, dict[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            failures.append("contract entry is not a table")
            continue
        contract_id = entry.get("id")
        raw_path = entry.get("path")
        kind = entry.get("kind")
        stability = entry.get("stability")
        version = entry.get("version")
        if not isinstance(contract_id, str) or not contract_id:
            failures.append("contract entry has invalid id")
            continue
        if contract_id in ids:
            failures.append(f"duplicate contract id: {contract_id}")
        ids.add(contract_id)
        path = _safe_contract_path(raw_path)
        if path is None:
            failures.append(f"contract {contract_id} has invalid or unsafe path")
            continue
        if path in paths:
            failures.append(f"duplicate contract path: {path}")
        paths.add(path)
        by_path[path] = entry
        if not (root / path).is_file():
            failures.append(f"contract path does not exist: {path}")
        if kind not in KINDS:
            failures.append(f"unsupported contract kind for {contract_id}: {kind}")
        if stability not in ALLOWED:
            failures.append(f"invalid stability for {contract_id}: {stability}")
        if not isinstance(version, str) or not version:
            failures.append(f"contract {contract_id} must declare a version string")
        if stability == "preview" and not entry.get("since"):
            failures.append(f"preview contract {contract_id} must declare since")
        if stability == "stable":
            if not entry.get("since"):
                failures.append(f"stable contract {contract_id} must declare since")
            if entry.get("compatibility") != "major-version-overlap":
                failures.append(
                    f"stable contract {contract_id} must declare compatibility = major-version-overlap"
                )

    schema_paths = {
        path.relative_to(root).as_posix()
        for path in (root / "schemas").glob("*.schema.json")
    }
    registered_schemas = {
        path for path, entry in by_path.items() if entry.get("kind") == "json-schema"
    }
    missing = sorted(schema_paths - registered_schemas)
    extra = sorted(registered_schemas - schema_paths)
    if missing:
        failures.append(f"unregistered JSON schemas: {missing}")
    if extra:
        failures.append(f"registered JSON schemas missing from disk: {extra}")

    interface_paths = {
        path.relative_to(root).as_posix()
        for path in (root / "interfaces/dbus").glob("*.xml")
    }
    registered_interfaces = {
        path for path, entry in by_path.items() if entry.get("kind") == "dbus-interface"
    }
    missing_interfaces = sorted(interface_paths - registered_interfaces)
    if missing_interfaces:
        failures.append(f"unregistered D-Bus interfaces: {missing_interfaces}")

    for path in sorted(schema_paths):
        entry = by_path.get(path)
        if entry is None:
            continue
        try:
            data = json.loads((root / path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            failures.append(f"invalid JSON schema {path}: {error}")
            continue
        if not isinstance(data, dict):
            failures.append(f"JSON schema root must be an object: {path}")
            continue
        if data.get("x-linura-contract-id") != entry.get("id"):
            failures.append(f"schema contract-id metadata mismatch: {path}")
        if data.get("x-linura-stability") != entry.get("stability"):
            failures.append(f"schema stability metadata mismatch: {path}")

    for path in sorted(interface_paths):
        entry = by_path.get(path)
        if entry is None:
            continue
        try:
            document = ET.parse(root / path).getroot()
        except ET.ParseError as error:
            failures.append(f"invalid D-Bus contract {path}: {error}")
            continue
        interface = document.find("interface")
        if interface is None:
            failures.append(f"D-Bus contract has no interface: {path}")
            continue
        annotation_items = _annotations(interface)
        if annotation_items is None:
            failures.append(f"D-Bus contract has invalid or duplicate annotations: {path}")
            continue
        annotations = dict(annotation_items)
        if annotations.get("org.linura.ContractId") != entry.get("id"):
            failures.append(f"D-Bus contract-id annotation mismatch: {path}")
        if annotations.get("org.linura.ContractVersion") != entry.get("version"):
            failures.append(f"D-Bus contract-version annotation mismatch: {path}")
        if annotations.get("org.linura.Stability") != entry.get("stability"):
            failures.append(f"D-Bus stability annotation mismatch: {path}")

    policy_path = root / "docs/api-versioning.md"
    if not policy_path.is_file():
        failures.append("missing docs/api-versioning.md")
    else:
        policy = policy_path.read_text(encoding="utf-8")
        required_policy = (
            "contract version", "contract stability", "Experimental", "Preview", "Stable",
            "Stability is never inferred", "Durable state is different",
        )
        for phrase in required_policy:
            if phrase not in policy:
                failures.append(f"API stability policy missing concept: {phrase}")

    failures.extend(
        historical_failures(
            root,
            registry,
            baseline_root=baseline_root,
            baseline_ref=baseline_ref,
        )
    )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    baseline = parser.add_mutually_exclusive_group()
    baseline.add_argument(
        "--baseline-ref",
        help="Git ref used to derive the historical merge-base contract baseline",
    )
    baseline.add_argument(
        "--baseline-root",
        type=Path,
        help="filesystem snapshot of the prior accepted tree (primarily for archives/tests)",
    )
    args = parser.parse_args()
    failures = validate(
        args.root.resolve(),
        baseline_root=args.baseline_root,
        baseline_ref=args.baseline_ref,
    )
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("contract stability checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
