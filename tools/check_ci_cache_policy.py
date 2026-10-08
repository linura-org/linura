#!/usr/bin/env python3
"""Fail-closed policy checks for reusable CI dependency-input caches."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CACHE_SHA = "55cc8345863c7cc4c66a329aec7e433d2d1c52a9"
CARGO_ACTION = ".github/actions/cargo-input-cache/action.yml"
APT_ACTION = ".github/actions/ubuntu-apt-input-cache/action.yml"
CI_WORKFLOW = ".github/workflows/ci.yml"
CONTRACT = ".github/actions/dependency-input-cache-policy.toml"

# Reviewed source identities, not cache identities. A shell command can be present
# as inert here-document text or unreachable code, so substring checks alone
# cannot authorize executable cache actions. Changing either action requires
# explicit adversarial review and a deliberate fingerprint update here.
REVIEWED_ACTION_SHA256 = {
    CARGO_ACTION: "87ff8a5e51554c1118e30467f11762c9e1a7cf2479f04124bd2e0773909d973b",
    APT_ACTION: "dcd0f4929a51b111d6d5c7263d7a4aba2f64e1b6865e848bdf17c55cb2d7e968",
}

CARGO_ALLOWED_PATHS = (
    "~/.cargo/registry/index",
    "~/.cargo/registry/cache",
    "~/.cargo/git/db",
)
FORBIDDEN_CACHE_FRAGMENTS = (
    "target/",
    "linura-shell-bridge-build",
    "linura-shell-bridge-install",
    "qualification-evidence",
    "evidence-cache",
    "runtime-binary-cache",
)


def _read(root: Path, relative: str) -> str:
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"missing or unsafe cache-policy file: {relative}")
    return path.read_text(encoding="utf-8")



def _canonical_composite_steps(source: str, label: str) -> list[dict[str, object]]:
    """Accept only unambiguous, canonical composite-action YAML step syntax.

    Other YAML key spellings, flow steps and aliases fail closed rather than
    letting GitHub execute a step the cache-policy checker did not inspect.
    """
    steps: list[dict[str, object]] = []
    in_runs = False
    in_steps = False
    block_indent: int | None = None
    runs_count = steps_count = using_count = 0
    seen_root: set[str] = set()
    for number, line in enumerate(source.splitlines(), 1):
        if not line.strip():
            continue
        indentation = line[: len(line) - len(line.lstrip())]
        if "\t" in indentation:
            raise ValueError(f"{label} action has tab indentation at line {number}")
        indent = len(indentation)
        stripped = line[indent:]
        if block_indent is not None:
            if indent > block_indent:
                if block_indent == 6 and steps:
                    steps[-1].setdefault("run_lines", []).append(stripped)
                continue
            block_indent = None
        if stripped.startswith("#"):
            continue
        if indent == 0:
            in_steps = False
            in_runs = False
            root_field = re.fullmatch(r"([a-z][a-z0-9-]*):(?:\s*(.*))?", stripped)
            if (
                root_field is None
                or root_field.group(1) not in {"name", "description", "inputs", "outputs", "runs"}
                or root_field.group(1) in seen_root
            ):
                raise ValueError(
                    f"{label} action has duplicate or noncanonical root key at line {number}"
                )
            root_key, root_value = root_field.group(1), (root_field.group(2) or "")
            seen_root.add(root_key)
            if root_key == "runs":
                if root_value:
                    raise ValueError(
                        f"{label} action must use a canonical runs mapping at line {number}"
                    )
                runs_count += 1
                in_runs = True
            continue
        if in_runs and indent == 2:
            in_steps = False
            if stripped == "using: composite":
                using_count += 1
            elif stripped == "steps:":
                steps_count += 1
                in_steps = True
            else:
                raise ValueError(
                    f"{label} action has noncanonical runs field at line {number}"
                )
            continue
        if in_steps and indent == 4:
            match = re.fullmatch(r"- (name|id):\s*(\S.*?)\s*", stripped)
            if not match:
                raise ValueError(
                    f"{label} action has noncanonical step at line {number}"
                )
            steps.append({match.group(1): match.group(2)})
            continue
        if in_steps and indent == 6:
            match = re.fullmatch(r"([a-z][a-z0-9-]*):(?:\s*(.*))?", stripped)
            if not match or not steps:
                raise ValueError(
                    f"{label} action has noncanonical step key at line {number}"
                )
            key, value = match.group(1), (match.group(2) or "")
            if (
                key not in {"name", "id", "uses", "run", "shell", "with", "env"}
                or key in steps[-1]
            ):
                raise ValueError(
                    f"{label} action has duplicate or noncanonical step key at line {number}"
                )
            if key == "run":
                if value != "|":
                    raise ValueError(
                        f"{label} action needs literal canonical shell at line {number}"
                    )
                steps[-1][key] = value
                steps[-1]["run_lines"] = []
                block_indent = 6
            elif key in {"env", "with"}:
                if value:
                    raise ValueError(
                        f"{label} action needs canonical nested mapping at line {number}"
                    )
                steps[-1][key] = value
            else:
                if not value:
                    raise ValueError(
                        f"{label} action has empty scalar at line {number}"
                    )
                steps[-1][key] = value.split(" #", 1)[0].strip()
            continue
        if in_steps and indent > 6:
            continue  # Children of env/with cannot authorize a step.
        if in_runs:
            raise ValueError(
                f"{label} action has unexpected YAML structure at line {number}"
            )
    if (runs_count, using_count, steps_count) != (1, 1, 1) or not steps:
        raise ValueError(
            f"{label} action requires exactly one canonical composite runs.steps mapping"
        )
    for step in steps:
        if ("run" in step) == ("uses" in step):
            raise ValueError(f"{label} action step must have exactly one run or uses")
    return steps


def _effective_shell_lines(steps: list[dict[str, object]]) -> list[str]:
    """Non-comment shell lines for diagnostics; reviewed hashes authorize semantics."""
    return [
        line.strip()
        for step in steps
        for line in step.get("run_lines", [])
        if line.strip() and not line.lstrip().startswith("#")
    ]



# The QML and bridge build recipe is reviewed independently of unrelated CI
# steps, which may evolve without changing this execution-critical script.
REVIEWED_QML_BUILD_SHA256 = (
    "724cd2b69e22bedd8531f48f2583a7d0ad2b6ac0fa4084ac52155e53f1d773a4"
)


def _canonical_ci_steps(source: str) -> list[dict[str, object]]:
    """Inspect the effective job/step structure, not raw text occurrences."""
    lines = source.splitlines()
    root_keys = [
        line.split(":", 1)[0]
        for line in lines
        if line and not line.startswith((" ", "\t", "#"))
    ]
    if root_keys != [
        "name", "run-name", "on", "permissions", "concurrency", "jobs"
    ]:
        raise ValueError("canonical CI has duplicate or noncanonical root mappings")
    job_lines = lines[lines.index("jobs:") + 1:]
    named_jobs = [
        line.strip()
        for line in job_lines
        if line.startswith("  ") and not line.startswith("   ")
        and line.strip() and not line.lstrip().startswith("#")
    ]
    if named_jobs != ["canonical-check:"]:
        raise ValueError("canonical CI must have one unambiguous canonical-check job")
    job_fields = [
        line.strip()
        for line in job_lines
        if line.startswith("    ") and not line.startswith("     ")
        and line.strip() and not line.lstrip().startswith("#")
    ]
    if job_fields != ["runs-on: ubuntu-24.04", "steps:"]:
        raise ValueError(
            "canonical CI job must run unconditionally with its reviewed runner and steps"
        )

    steps: list[dict[str, object]] = []
    mode: str | None = None
    allowed = {"name", "uses", "id", "run", "env", "with", "shell"}
    for number, line in enumerate(job_lines, 1):
        if not line.strip():
            if mode == "run" and steps:
                steps[-1]["run_lines"].append("")
            continue
        indent = len(line) - len(line.lstrip(" "))
        if "\t" in line[:indent]:
            raise ValueError("canonical CI step uses tab indentation")
        stripped = line[indent:]
        if stripped.startswith("#"):
            if mode == "run" and indent >= 10 and steps:
                steps[-1]["run_lines"].append(line[10:])
            continue
        if indent <= 4:
            mode = None
            continue
        if indent == 6:
            match = re.fullmatch(r"- (name|uses): (.+)", stripped)
            if not match:
                raise ValueError(
                    f"canonical CI has noncanonical step boundary at line {number}"
                )
            steps.append({
                "fields": {match.group(1): match.group(2)},
                "run_lines": [],
                "with_lines": [],
            })
            mode = None
        elif indent == 8:
            match = re.fullmatch(r"([a-z][a-z0-9-]*):(?:\s*(.*))?", stripped)
            if not match or not steps:
                raise ValueError(
                    f"canonical CI has noncanonical step key at line {number}"
                )
            key, value = match.group(1), (match.group(2) or "")
            fields = steps[-1]["fields"]
            if key not in allowed or key in fields:
                raise ValueError(
                    f"canonical CI has duplicate/unsafe step key {key!r} "
                    f"at line {number}"
                )
            if key in {"with", "env"} and value:
                raise ValueError("canonical CI requires literal nested step mappings")
            fields[key] = value
            mode = key if key in {"run", "with", "env"} else None
            if key == "run" and value != "|":
                mode = None
        elif indent >= 10 and steps:
            if mode == "run":
                steps[-1]["run_lines"].append(line[10:])
            elif mode == "with":
                steps[-1]["with_lines"].append(line[10:])
            elif mode != "env":
                raise ValueError("canonical CI has unexpected nested step structure")
        else:
            raise ValueError("canonical CI has noncanonical indentation")

    if not steps:
        raise ValueError("canonical CI has no checked steps")
    for step in steps:
        fields = step["fields"]
        if ("run" in fields) == ("uses" in fields):
            raise ValueError("canonical CI steps require one run or uses")
    return steps


def _verify_ci_execution_steps(source: str) -> None:
    steps = _canonical_ci_steps(source)
    named = {}
    for step in steps:
        name = step["fields"].get("name")
        if name is not None:
            if name in named:
                raise ValueError(f"canonical CI duplicate step name: {name}")
            named[name] = step

    # Changes to the effective shell, environment, or action identity must
    # be consciously reviewed; extra fields can change execution without
    # touching the reviewed command text.
    for name, expected in (
        ("Restore Cargo dependency inputs", {"name", "uses", "with"}),
        ("Install Linura Shell bridge build dependencies", {"name", "uses", "with"}),
        ("Build and install Linura Shell QML modules", {"name", "run"}),
        ("Run canonical Linura checks", {"name", "run"}),
        ("Validate CI dependency cache policy before builds", {"name", "run"}),
    ):
        item = named.get(name)
        if item is None or set(item["fields"]) != expected:
            raise ValueError(f"canonical CI critical step structure drifted: {name}")

    def required(name: str) -> dict[str, object]:
        if name not in named:
            raise ValueError(f"canonical CI missing executable step: {name}")
        return named[name]

    early_policy = required("Validate CI dependency cache policy before builds")
    if early_policy["fields"].get("run") != "python3 tools/check_ci_cache_policy.py":
        raise ValueError("canonical CI must validate cache policy before builds")
    cargo = required("Restore Cargo dependency inputs")
    if (
        cargo["fields"].get("uses") != "./.github/actions/cargo-input-cache"
        or cargo["with_lines"] != [
            "namespace: canonical-ci",
            "rust-version: ${{ env.RUST_VERSION }}",
        ]
    ):
        raise ValueError("canonical CI Cargo cache input step drifted")
    apt = required("Install Linura Shell bridge build dependencies")
    if (
        apt["fields"].get("uses")
        != "./.github/actions/ubuntu-apt-input-cache"
        or apt["with_lines"] != [
            "namespace: canonical-ci-shell",
            "packages: |",
            "  cmake",
            "  ninja-build",
            "  pkg-config",
            "  qt6-base-dev",
            "  qt6-declarative-dev",
        ]
    ):
        raise ValueError("canonical CI APT cache input step drifted")

    build = required("Build and install Linura Shell QML modules")
    if build["fields"].get("run") != "|":
        raise ValueError("canonical CI requires an executable literal QML build")
    build_source = "\n".join(build["run_lines"]) + "\n"
    if hashlib.sha256(build_source.encode("utf-8")).hexdigest() != REVIEWED_QML_BUILD_SHA256:
        raise ValueError(
            "canonical CI QML build differs from reviewed SHA-256; "
            "re-audit executable source-build commands before updating"
        )
    canonical = required("Run canonical Linura checks")
    if canonical["fields"].get("run") != "cargo xtask check":
        raise ValueError("canonical CI must execute the full cargo xtask check")


def check(root: Path = ROOT) -> list[str]:
    failures: list[str] = []
    try:
        cargo = _read(root, CARGO_ACTION)
        apt = _read(root, APT_ACTION)
        ci = _read(root, CI_WORKFLOW)
        contract = tomllib.loads(_read(root, CONTRACT))
    except (ValueError, tomllib.TOMLDecodeError) as exc:
        return [str(exc)]

    for action_path, source in ((CARGO_ACTION, cargo), (APT_ACTION, apt)):
        fingerprint = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if fingerprint != REVIEWED_ACTION_SHA256[action_path]:
            failures.append(
                f"{action_path} differs from its reviewed SHA-256 fingerprint; "
                "re-audit executable steps before updating the pinned identity"
            )

    expected_policy = {
        "cargo_registry_index": True,
        "cargo_registry_archives": True,
        "cargo_git_database": True,
        "ubuntu_package_payloads": True,
        "linura_source": False,
        "linura_build_outputs": False,
        "qml_cmake_build_outputs": False,
        "qualification_evidence": False,
        "runtime_binaries": False,
        "release_support_promotion": False,
    }
    expected_cargo_identity = [
        "runner.os",
        "runner.arch",
        "rust-version",
        "rust-toolchain.toml",
        "Cargo.lock",
        CARGO_ACTION,
    ]
    expected_apt_identity = [
        "runner.os",
        "runner.arch",
        "os-release.id",
        "os-release.version_id",
        "installed-package-universe-sha256",
        "requested-candidate-versions",
        "simulated-install-closure",
        APT_ACTION,
    ]
    if (
        contract.get("schema_version") != 1
        or contract.get("id") != "ci/dependency-input-cache"
        or contract.get("state") != "development-prerequisite"
        or contract.get("claim") != "non-authoritative-cacheable-inputs"
        or contract.get("cache_action_sha") != CACHE_SHA
        or contract.get("cargo_action") != CARGO_ACTION
        or contract.get("ubuntu_apt_action") != APT_ACTION
        or contract.get("cache_policy") != expected_policy
        or contract.get("identity", {}).get("cargo") != expected_cargo_identity
        or contract.get("identity", {}).get("ubuntu_apt") != expected_apt_identity
        or contract.get("storage") != {
            "ubuntu_apt_root": "runner.temp",
            "broad_restore_keys": False,
        }
        or contract.get("verification") != {
            "apt_signed_index_resolution": True,
            "apt_requested_candidate_match_after_install": True,
            "exact_source_builds_remain_required": True,
            "cache_hit_is_qualification_evidence": False,
        }
    ):
        failures.append("dependency-input cache contract drifted from reviewed authority boundary")

    try:
        cargo_steps = _canonical_composite_steps(cargo, "Cargo")
        apt_steps = _canonical_composite_steps(apt, "APT")
    except ValueError as exc:
        failures.append(str(exc))
        cargo_steps = []
        apt_steps = []

    expected_cache_use = f"actions/cache@{CACHE_SHA}"
    cargo_cache_refs = [step["uses"] for step in cargo_steps if "uses" in step]
    apt_cache_refs = [step["uses"] for step in apt_steps if "uses" in step]
    if cargo_cache_refs != [expected_cache_use]:
        failures.append(
            "Cargo input cache must use exactly one canonical pinned actions/cache step"
        )
    if apt_cache_refs != [expected_cache_use]:
        failures.append(
            "APT input cache must use exactly one canonical pinned actions/cache step"
        )
    if len(cargo_steps) != 2 or cargo_steps[1].get("id") != "cache":
        failures.append("Cargo cache action step structure is noncanonical")
    if (
        len(apt_steps) != 3
        or apt_steps[0].get("id") != "resolve"
        or apt_steps[1].get("id") != "cache"
        or apt_steps[2].get("name") != "Install and verify exact Ubuntu packages"
    ):
        failures.append("APT cache action step structure is noncanonical")
    for label, steps in (("Cargo", cargo_steps), ("APT", apt_steps)):
        for step in steps:
            if "run" in step:
                shell_lines = _effective_shell_lines([step])
                if not shell_lines or shell_lines[0] != "set -euo pipefail":
                    failures.append(
                        f"{label} cache run step must start with strict shell mode"
                    )

    if "restore-keys:" in cargo or "restore-keys:" in apt:
        failures.append("dependency-input caches must not use broad restore keys")

    cargo_paths = re.findall(r"(?m)^          (~/.cargo/[^\n]+)$", cargo)
    if tuple(cargo_paths) != CARGO_ALLOWED_PATHS:
        failures.append("Cargo cache path set must remain dependency-input-only")
    if "hashFiles('rust-toolchain.toml', 'Cargo.lock', '.github/actions/cargo-input-cache/action.yml')" not in cargo:
        failures.append("Cargo cache key must bind toolchain, lockfile, and cache implementation")
    if "${{ inputs.rust-version }}" not in cargo:
        failures.append("Cargo cache key must bind the reviewed Rust version")

    required_apt = (
        'cache_dir="$RUNNER_TEMP/linura-apt-inputs/$LINURA_APT_NAMESPACE/$digest"',
        "dpkg-query -W -f='${binary:Package}=${Version}\\n'",
        'installed_universe_sha256="$(',
        "printf 'installed_universe_sha256=%s\\n' \"$installed_universe_sha256\"",
        'action_sha256="$(sha256sum "$GITHUB_ACTION_PATH/action.yml"',
        "sudo apt-get update",
        "apt-get --simulate install --no-install-recommends",
        "APT::Keep-Downloaded-Packages=true",
        "Dir::Cache::archives=$LINURA_APT_CACHE_DIR",
        "installed=\"$(dpkg-query -W -f='${Version}' \"$package\")\"",
        'test "$installed" = "$candidate"',
    )
    apt_script_lines = _effective_shell_lines(apt_steps)
    for fragment in required_apt:
        if fragment in {"sudo apt-get update", 'test "$installed" = "$candidate"'}:
            present = fragment in apt_script_lines
        else:
            present = any(fragment in line for line in apt_script_lines)
        if not present:
            failures.append(f"APT cache missing fail-closed invariant: {fragment}")
    if (
        len(apt_steps) == 3
        and (
            "sudo apt-get update" not in _effective_shell_lines(apt_steps[:1])
            or 'test "$installed" = "$candidate"' not in _effective_shell_lines(
                apt_steps[2:3]
            )
        )
    ):
        failures.append("APT cache safety commands must execute in their expected steps")

    if "$HOME/.cache" in apt or "~/.cache" in apt:
        failures.append("APT cache must remain under runner.temp, never shared HOME cache state")

    for source, label in ((cargo, "Cargo"), (apt, "APT")):
        for fragment in FORBIDDEN_CACHE_FRAGMENTS:
            if fragment in source:
                failures.append(f"{label} cache policy contains forbidden cached output: {fragment}")

    try:
        _verify_ci_execution_steps(ci)
    except ValueError as exc:
        failures.append(str(exc))

    required_ci = (
        "uses: ./.github/actions/cargo-input-cache",
        "namespace: canonical-ci",
        "uses: ./.github/actions/ubuntu-apt-input-cache",
        "namespace: canonical-ci-shell",
        "cmake -S apps/linura-shell/bridge",
        'cmake --build "$build_dir" --parallel 2',
        "cmake -S apps/linura-shell/ui",
        'cmake --build "$ui_build_dir" --parallel 2',
        "run: cargo xtask check",
    )
    for fragment in required_ci:
        if fragment not in ci:
            failures.append(f"canonical CI cache integration missing invariant: {fragment}")
    if "uses: actions/cache@" in ci:
        failures.append("canonical CI must consume repository-owned cache primitives, not duplicate cache logic")
    if "sudo apt-get install --yes --no-install-recommends" in ci:
        failures.append("canonical CI must not duplicate inline APT cache/install logic")

    return failures


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else ROOT
    failures = check(root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("CI dependency-input cache policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
